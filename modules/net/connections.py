# -*- coding: utf-8 -*-
"""WebSocket 连接管理 + Webhook 转发 — 预编码静态负载、批量统计、单次加锁"""
import asyncio
import json
import logging
import time
from collections import deque
from typing import Dict, List

import aiohttp
from fastapi import WebSocket

from modules.util.privacy import PrivacyUtils
from modules.data.cache import cache_manager
from modules.data.stats import stats_manager

# 全局状态
active_connections: Dict[str, Dict] = {}

# 常量
PUSH_TIMEOUT = 10
RETRY_INTERVAL = 1
MAX_RETRY_TIME = 300
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

    ok = fail = 0
    for r in results:
        if isinstance(r, Exception) or r is None:
            continue
        if r:
            ok += 1
        else:
            fail += 1

    if ok or fail:
        stats_manager.batch_update_ws_stats(secret, ok, fail)

    if ok:
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug(f"WS转发成功 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | {ok}/{len(items)}")
    elif fail:
        logging.warning(f"WS转发失败 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 失败:{fail}/{len(items)}")

    return ok > 0


async def _send_to_one(ws: WebSocket, data: bytes, conn_info: dict, secret: str):
    try:
        await ws.send_bytes(data)
        conn_info["failure_count"] = 0
        conn_info["last_activity"] = time.time()
        return True
    except Exception:
        pass

    lock = await cache_manager.get_lock_for_secret(secret)
    async with lock:
        conns = active_connections.get(secret)
        if not conns or ws not in conns:
            return False
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
    return False


# ==================== 缓存补发 ====================

async def resend_cache(secret: str, websocket: WebSocket):
    try:
        await asyncio.sleep(3)
        msgs = await cache_manager.get_messages(secret)
        await _resend_cache(secret, websocket, msgs, "缓存")
    except Exception as e:
        logging.error(f"缓存补发异常: {e}")


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


# ==================== Webhook 转发 ====================

_retry_queue: deque = deque()


async def _post_once(session: aiohttp.ClientSession, target: dict,
                     body: bytes, headers: dict) -> dict:
    """单次转发尝试, 返回下游响应内容"""
    start = time.time()
    try:
        async with session.post(target['url'], data=body, headers=headers,
                                timeout=aiohttp.ClientTimeout(total=PUSH_TIMEOUT)) as resp:
            resp_body = await resp.read()
            result = {'url': target['url'], 'status': resp.status,
                      'success': 200 <= resp.status < 300,
                      'body': resp_body,
                      'content_type': resp.headers.get('Content-Type', 'application/json'),
                      'duration': round(time.time() - start, 2)}
            if not result['success']:
                result['error'] = f"HTTP {resp.status}"
            return result
    except asyncio.TimeoutError:
        return {'url': target['url'], 'success': False, 'error': '超时'}
    except Exception as e:
        return {'url': target['url'], 'success': False, 'error': str(e)}


async def forward_webhook(targets: List[dict], body: bytes, headers: dict,
                          timeout: int, current_appid: str) -> list:
    """同步转发一次 (最多 PUSH_TIMEOUT 秒); 失败的目标进入后台重发队列"""
    matched = [t for t in targets if t.get('appid') == current_appid]
    if not matched:
        return []

    session = await get_http_session()
    results = await asyncio.gather(
        *[_post_once(session, t, body, headers) for t in matched])

    for target, r in zip(matched, results):
        if not r['success']:
            _retry_queue.append({'target': target, 'body': body, 'headers': headers,
                                 'deadline': time.time() + MAX_RETRY_TIME, 'retries': 0})
            r['queued'] = True
    return list(results)


async def retry_queue_worker():
    """失败重发队列 — 每秒轮询一轮, 逐条重试直至成功或超过 MAX_RETRY_TIME(5分钟)"""
    while True:
        try:
            await asyncio.sleep(RETRY_INTERVAL)
            if not _retry_queue:
                continue
            session = await get_http_session()
            for _ in range(len(_retry_queue)):
                item = _retry_queue.popleft()
                item['retries'] += 1
                r = await _post_once(session, item['target'], item['body'], item['headers'])
                url = PrivacyUtils.sanitize_url(item['target']['url'])
                if r['success']:
                    logging.info(f"重发成功 | {url} | 重试:{item['retries']}次")
                elif time.time() < item['deadline']:
                    _retry_queue.append(item)
                else:
                    logging.error(f"重发放弃(超过{MAX_RETRY_TIME}s) | {url} | "
                                  f"重试:{item['retries']}次 | 错误:{r.get('error', '未知')}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logging.error(f"重发队列异常: {e}")
