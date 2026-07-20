# -*- coding: utf-8 -*-
"""Webhook 接收与二次转发"""
import json
import logging
import os
import time
from datetime import datetime

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import Response

from modules.core.config import config
from modules.data.cache import cache_manager
from modules.net.connections import (active_connections, forward_webhook,
                                     send_to_all)
from modules.util.privacy import PrivacyUtils
from modules.data.stats import stats_manager
from modules.data.appid import app_id_manager
from modules.util.helpers import generate_signature

router = APIRouter(tags=["webhook"])


@router.post("/webhook")
async def handle_webhook(request: Request,
                         user_agent: str = Header(None),
                         x_bot_appid: str = Header(None)):
    start_time = time.time()
    secret = request.query_params.get('secret')
    body = await request.body()

    if getattr(config, 'raw_content', {}).get('enabled'):
        _log_raw_message(request, body, secret, user_agent, x_bot_appid)

    stats_manager.increment_message_count()

    # 消息去重 (解析一次, 后续复用)
    msg_data = None
    try:
        msg_data = json.loads(body)
        msg_id = msg_data.get('id')
        if msg_id:
            if cache_manager.has_message_id(msg_id):
                return {"status": "success"}
            cache_manager.add_message_id(msg_id, config.deduplication_ttl)
    except:
        pass

    # 签名验证回调
    d = msg_data.get("d") if isinstance(msg_data, dict) else None
    if isinstance(d, dict) and "event_ts" in d and "plain_token" in d:
        try:
            result = generate_signature(secret, d["event_ts"], d["plain_token"])
            return result
        except Exception as e:
            logging.error(f"签名错误: {e}")
            return {"status": "error"}

    # Webhook 二次转发 (按AppID匹配) — 同步等待一次尝试, 失败进后台重发队列
    downstream_resp = None
    headers = dict(request.headers)
    if config.webhook_forward['enabled'] and config.webhook_forward['targets']:
        appid_for_forward = x_bot_appid or request.query_params.get('appid', '')
        if appid_for_forward:
            downstream_resp = await _forward_to_webhooks(appid_for_forward, body, headers)

    # WebSocket 转发
    enhanced_body = _add_http_context(body, request, msg_data, headers)
    skip_cache = secret in config.no_cache_secrets
    has_online = secret in active_connections and active_connections[secret]

    if not has_online and not skip_cache:
        await cache_manager.add_message(secret, enhanced_body)

    if has_online:
        try:
            await send_to_all(secret, enhanced_body)
        except Exception as e:
            logging.error(f"WebSocket转发异常: {e}")

    elapsed = time.time() - start_time
    if elapsed > 2:
        logging.warning(f"Webhook处理耗时: {elapsed:.2f}s | "
                        f"密钥:{PrivacyUtils.sanitize_secret(secret)}")

    if downstream_resp is not None:
        return Response(content=downstream_resp['body'],
                        status_code=downstream_resp['status'],
                        media_type=downstream_resp['content_type'])
    return {"status": "success"}


@router.post("/api/{appid}")
async def handle_appid_webhook(appid: str, request: Request,
                               user_agent: str = Header(None),
                               x_bot_appid: str = Header(None),
                               signature: str = Query(None),
                               timestamp: str = Query(None),
                               nonce: str = Query(None)):
    secret = app_id_manager.get_secret_by_appid(appid)
    if not secret:
        raise HTTPException(status_code=404, detail="无效的AppID")
    if (signature and timestamp and nonce
            and not app_id_manager.verify_signature(appid, signature, timestamp, nonce)):
        raise HTTPException(status_code=403, detail="签名验证失败")
    request.query_params._dict["secret"] = secret
    return await handle_webhook(request=request,
                                user_agent=user_agent, x_bot_appid=x_bot_appid)


# ========== 内部辅助 ==========

def _log_raw_message(request, body, secret, user_agent, x_bot_appid):
    try:
        log_dir = config.raw_content.get('path', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f'raw_messages_{datetime.now():%Y-%m-%d}.log')
        try:
            raw_body = json.loads(body.decode('utf-8', errors='ignore'))
        except:
            raw_body = body.decode('utf-8', errors='ignore')
        entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'client_ip': request.client.host if request.client else "unknown",
            'secret': secret, 'user_agent': user_agent, 'x_bot_appid': x_bot_appid,
            'content_length': len(body), 'raw_body': raw_body,
        }
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception as e:
        logging.error(f"记录原始消息失败: {e}")


async def _forward_to_webhooks(appid, body, headers):
    """返回首个成功目标的下游响应 (用于原样回复开放平台), 无成功则返回 None"""
    try:
        results = await forward_webhook(
            config.webhook_forward['targets'], body, headers,
            config.webhook_forward['timeout'], appid)
        success, fail = 0, 0
        for r in results:
            if r.get('skipped'):
                continue
            ts = time.strftime('%m-%d %H:%M:%S')
            if r['success']:
                success += 1
                retry = r.get('retry_count', 0)
                dur = r.get('duration', 0)
                if retry:
                    logging.debug(f"{ts} - Webhook转发成功 | AppID:{appid} | "
                                  f"耗时:{dur}s | 重试:{retry}次")
                else:
                    logging.debug(f"{ts} - Webhook转发成功 | AppID:{appid} | 耗时:{dur}s")
            else:
                fail += 1
                err = r.get('error', '未知')
                retry = r.get('retry_count', 0)
                if retry:
                    logging.error(f"{ts} - Webhook转发失败 | AppID:{appid} | "
                                  f"重试:{retry}次 | 错误:{err}")
                else:
                    logging.error(f"{ts} - Webhook转发失败 | AppID:{appid} | 错误:{err}")
        secret_for_stats = app_id_manager.get_secret_by_appid(appid) or appid
        stats_manager.batch_update_wh_stats(secret_for_stats, success, fail)
        for r in results:
            if r.get('success') and r.get('body') is not None:
                return r
    except Exception as e:
        logging.error(f"Webhook转发异常: {e}")
    return None


def _add_http_context(body, request, data=None, headers=None):
    try:
        if data is None:
            data = json.loads(body)
        if 'http_context' not in data:
            data = dict(data)
            data['http_context'] = {
                'headers': headers if headers is not None else dict(request.headers),
                'path': request.url.path,
                'method': request.method, 'url': str(request.url),
                'remote_addr': request.client.host if request.client else 'unknown',
            }
            return json.dumps(data, ensure_ascii=False).encode('utf-8')
    except:
        pass
    return body
