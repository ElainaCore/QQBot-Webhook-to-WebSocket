# -*- coding: utf-8 -*-
"""WebSocket 连接管理 + Webhook 转发 — 预编码静态负载、批量统计、单次加锁"""
import asyncio
import json
import logging
import time
from typing import Dict, List

import aiohttp
from fastapi import WebSocket

from modules.util.privacy import PrivacyUtils
from modules.data.cache import cache_manager
from modules.data.stats import stats_manager

# 全局状态
active_connections: Dict[str, Dict] = {}

service_health = {
    "last_successful_webhook": 0,
    "last_successful_ws_message": 0,
    "error_count": 0,
    "high_load_detected": False,
}

# 常量
PUSH_TIMEOUT = 10
RETRY_INTERVAL = 1
MAX_RETRY_TIME = 180
MAX_CONNECTIONS = 500

_http_session: aiohttp.ClientSession = None
_session_lock = asyncio.Lock()


async def get_http_session() -> aiohttp.ClientSession:
    """全局共享 ClientSession — 限制并发连接数，避免每次转发新建会话耗尽文件描述符"""
    global _http_session
    if _http_session is None or _http_session.closed:
        async with _session_lock:
            if _http_session is None or _http_session.closed:
                _http_session = aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(limit=MAX_CONNECTIONS, ttl_dns_cache=300))
    return _http_session


async def close_http_session():
    global _http_session
    if _http_session and not _http_session.closed:
        await _http_session.close()
    _http_session = None

# 预编码静态 JSON 负载 — 避免每次 json.dumps
HELLO_PAYLOAD = json.dumps({"op": 10, "d": {"heartbeat_interval": 30000}}).encode()
_HB_ACK = json.dumps({"op": 11}).encode()
_READY = json.dumps({"op": 0, "s": 1, "t": "READY",
                      "d": {"version": 1, "session_id": "open-connection",
                             "user": {"bot": True}, "shard": [0, 0]}}).encode()
_RESUMED = json.dumps({"op": 0, "s": 1, "t": "RESUMED", "d": {}}).encode()


# ==================== WebSocket 消息发送 ====================

async def send_to_all(secret: str, data: bytes) -> bool:
    conns = active_connections.get(secret)
    if not conns:
        return False
    items = list(conns.items())

    results = await asyncio.gather(
        *[_send_to_one(ws, data, info, secret) for ws, info in items],
        return_exceptions=True)

    ok = fail = sandbox_ok = 0
    for r in results:
        if isinstance(r, Exception) or r is None:
            continue
        sent, is_sb = r
        if sent:
            ok += 1
            if is_sb:
                sandbox_ok += 1
        else:
            fail += 1

    if ok or fail:
        stats_manager.batch_update_ws_stats(secret, ok, fail)

    sanitized = PrivacyUtils.sanitize_secret(secret)
    if ok:
        parts = [f"WS转发成功 | 密钥:{sanitized} | {ok}/{len(items)}"]
        if sandbox_ok:
            parts.append(f"沙盒:{sandbox_ok}")
        formal = ok - sandbox_ok
        if formal:
            parts.append(f"正式:{formal}")
        logging.info(" | ".join(parts))
    elif fail:
        logging.warning(f"WS转发失败 | 密钥:{sanitized} | 失败:{fail}/{len(items)}")

    return ok > 0


def _sandbox_filter(data: bytes, info: dict) -> bool:
    try:
        d = json.loads(data).get("d", {})
        if info["group"] and d.get("group_openid") != info["group"]:
            return False
        if info["member"] and d.get("author", {}).get("member_openid") != info["member"]:
            return False
        if info["content"] and info["content"] not in d.get("content", ""):
            return False
    except:
        pass
    return True


async def _send_to_one(ws: WebSocket, data: bytes, conn_info: dict, secret: str):
    is_sandbox = conn_info["is_sandbox"]
    if is_sandbox and not _sandbox_filter(data, conn_info):
        return None

    try:
        await ws.send_bytes(data)
        sent_ok = True
    except Exception:
        sent_ok = False

    lock = await cache_manager.get_lock_for_secret(secret)
    async with lock:
        conns = active_connections.get(secret)
        if not conns or ws not in conns:
            return (sent_ok, is_sandbox)
        if sent_ok:
            conns[ws]["failure_count"] = 0
            conns[ws]["last_activity"] = time.time()
        else:
            conns[ws]["failure_count"] += 1
            if conns[ws]["failure_count"] >= 5:
                try:
                    await ws.close()
                except:
                    pass
                del conns[ws]
                if not conns:
                    del active_connections[secret]
                logging.warning(f"连接重试过多关闭 | 密钥:{PrivacyUtils.sanitize_secret(secret)}")
    return (sent_ok, is_sandbox)


# ==================== 缓存补发 ====================

async def resend_token_cache(secret: str, token: str, websocket: WebSocket):
    try:
        await asyncio.sleep(3)
        msgs = await cache_manager.get_messages_for_token(secret, token)
        await _resend_cache(secret, websocket, msgs,
                            f"Token:{PrivacyUtils.sanitize_secret(token)}")
    except Exception as e:
        logging.error(f"Token缓存补发异常: {e}")


async def resend_public_cache(secret: str, websocket: WebSocket):
    try:
        await asyncio.sleep(3)
        msgs = await cache_manager.get_public_messages(secret)
        await _resend_cache(secret, websocket, msgs, "公共缓存")
    except Exception as e:
        logging.error(f"公共缓存补发异常: {e}")


async def _resend_cache(secret: str, ws: WebSocket, queue: list, desc: str):
    if not queue:
        return
    now = time.time()
    success = fail = valid = 0
    logging.info(f"开始补发{desc} | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 总量:{len(queue)}")
    for i in range(0, len(queue), 10):
        for expiry, msg in queue[i:i + 10]:
            if expiry <= now:
                continue
            valid += 1
            try:
                await ws.send_bytes(msg)
                success += 1
            except:
                fail += 1
        if i + 10 < len(queue):
            await asyncio.sleep(1)
    logging.info(f"{desc}补发完成 | 密钥:{PrivacyUtils.sanitize_secret(secret)} "
                 f"| 有效:{valid} 成功:{success} 失败:{fail}")


# ==================== 心跳 / 消息处理 ====================

async def send_heartbeat(websocket: WebSocket, secret: str):
    failures = 0
    try:
        while True:
            await asyncio.sleep(35)
            if websocket.client_state.name != 'CONNECTED':
                break
            try:
                await websocket.send_bytes(_HB_ACK)
                failures = 0
            except Exception as e:
                failures += 1
                logging.error(f"心跳发送失败 (第{failures}次): {e}")
                if failures >= 3:
                    break
                await asyncio.sleep(5)
    except asyncio.CancelledError:
        pass


async def handle_ws_message(message: str, websocket: WebSocket):
    try:
        op = json.loads(message).get("op")
        if op == 1:
            await websocket.send_bytes(_HB_ACK)
        elif op == 2:
            await websocket.send_bytes(_READY)
        elif op == 6:
            await websocket.send_bytes(_RESUMED)
    except Exception as e:
        logging.error(f"WS消息处理错误: {e}")
        service_health["error_count"] += 1


# ==================== Webhook 转发 ====================

async def forward_webhook(targets: List[dict], body: bytes, headers: dict,
                          timeout: int, current_appid: str) -> list:
    matched = [t for t in targets if t.get('appid') == current_appid]
    if not matched:
        return []

    async def _send_one(session: aiohttp.ClientSession, target: dict) -> dict:
        start = time.time()
        retries = 0
        last_err = None
        while time.time() - start < MAX_RETRY_TIME:
            try:
                async with session.post(target['url'], data=body, headers=headers,
                                        timeout=aiohttp.ClientTimeout(total=PUSH_TIMEOUT)) as resp:
                    if 200 <= resp.status < 300:
                        return {'url': target['url'], 'status': resp.status, 'success': True,
                                'retry_count': retries, 'duration': round(time.time() - start, 2)}
                    last_err = f"HTTP {resp.status}"
            except asyncio.TimeoutError:
                last_err = "超时"
            except Exception as e:
                last_err = str(e)
            retries += 1
            await asyncio.sleep(RETRY_INTERVAL)
        return {'url': target['url'], 'success': False, 'retry_count': retries,
                'error': last_err or '超时'}

    session = await get_http_session()
    return await asyncio.gather(*[_send_one(session, t) for t in matched])
