import asyncio
import hashlib
import json
import logging
import time
from collections import deque
from datetime import datetime
from typing import List, Dict, Any, Optional

import aiohttp
from fastapi import WebSocket, WebSocketDisconnect

from modules.privacy import PrivacyUtils
from modules.cache import cache_manager
from modules.stats import stats_manager

# 全局状态
active_connections: Dict[str, Dict] = {}
push_records: Dict[str, Any] = {}

service_health = {
    "last_successful_webhook": 0,
    "last_successful_ws_message": 0,
    "error_count": 0,
    "high_load_detected": False
}

# 常量
PUSH_TIMEOUT = 10
RETRY_INTERVAL = 1
MAX_RETRY_TIME = 180


class MessagePushRecord:
    def __init__(self, message_id: str, secret: str, data: bytes, target_count: int):
        self.message_id = message_id
        self.secret = secret
        self.data = data
        self.target_count = target_count
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.retry_count = 0
        self.success_count = 0
        self.status = "pending"


async def send_to_all(secret: str, data: bytes) -> bool:
    """向所有连接发送消息"""
    try:
        lock = await cache_manager.get_lock_for_secret(secret)
        async with lock:
            connections = active_connections.get(secret, {})
            websockets = list(connections.keys())
        
        if not websockets:
            return False

        tasks = [asyncio.create_task(_send_to_one(ws, data, connections[ws], secret)) for ws in websockets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success, fail = 0, 0
        sandbox_success, formal_success = 0, 0
        
        for result in results:
            if isinstance(result, Exception):
                fail += 1
                continue
            if result:
                success_type, is_sandbox = result
                if success_type:
                    success += 1
                    if is_sandbox:
                        sandbox_success += 1
                    else:
                        formal_success += 1
                else:
                    fail += 1
            else:
                fail += 1

        # 更新统计
        for _ in range(success):
            stats_manager.increment_ws_stats(secret, success=True)
        for _ in range(fail):
            stats_manager.increment_ws_stats(secret, success=False)

        current_time = time.strftime('%m-%d %H:%M:%S')
        if success > 0:
            log_parts = [f"{current_time} - WS转发成功 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | {success}/{len(websockets)}"]
            if sandbox_success:
                log_parts.append(f"沙盒:{sandbox_success}")
            if formal_success:
                log_parts.append(f"正式:{formal_success}")
            logging.info(" | ".join(log_parts))
        elif fail > 0:
            logging.warning(f"{current_time} - WS转发失败 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 失败:{fail}/{len(websockets)}")

        return success > 0
    except Exception as e:
        logging.error(f"发送消息异常: {e}")
        service_health["error_count"] += 1
        return False


async def _send_to_one(ws: WebSocket, data: bytes, conn_info: dict, secret: str):
    """向单个连接发送消息"""
    try:
        is_sandbox = conn_info["is_sandbox"]
        should_send = True
        
        if is_sandbox:
            try:
                msg = json.loads(data)
                d = msg.get("d", {})
                if conn_info["group"] and d.get("group_openid") != conn_info["group"]:
                    should_send = False
                if should_send and conn_info["member"] and d.get("author", {}).get("member_openid") != conn_info["member"]:
                    should_send = False
                if should_send and conn_info["content"] and conn_info["content"] not in d.get("content", ""):
                    should_send = False
            except:
                pass

        if not should_send:
            return None

        try:
            await ws.send_bytes(data)
            lock = await cache_manager.get_lock_for_secret(secret)
            async with lock:
                if secret in active_connections and ws in active_connections[secret]:
                    active_connections[secret][ws]["failure_count"] = 0
                    active_connections[secret][ws]["last_activity"] = time.time()
            return (True, is_sandbox)
        except Exception:
            lock = await cache_manager.get_lock_for_secret(secret)
            async with lock:
                if secret in active_connections and ws in active_connections[secret]:
                    active_connections[secret][ws]["failure_count"] += 1
                    if active_connections[secret][ws]["failure_count"] >= 5:
                        try:
                            await ws.close()
                        except:
                            pass
                        del active_connections[secret][ws]
                        if not active_connections[secret]:
                            del active_connections[secret]
                        logging.warning(f"连接重试过多关闭 | 密钥:{PrivacyUtils.sanitize_secret(secret)}")
            return False
    except Exception as e:
        logging.error(f"单消息发送异常: {e}")
        return False


async def resend_token_cache(secret: str, token: str, websocket: WebSocket):
    """补发token缓存"""
    try:
        await asyncio.sleep(3)
        messages = await cache_manager.get_messages_for_token(secret, token)
        await _resend_cache(secret, websocket, messages, f"Token:{PrivacyUtils.sanitize_secret(token)}")
    except Exception as e:
        logging.error(f"Token缓存补发异常: {e}")


async def resend_public_cache(secret: str, websocket: WebSocket):
    """补发公共缓存"""
    try:
        await asyncio.sleep(3)
        messages = await cache_manager.get_public_messages(secret)
        await _resend_cache(secret, websocket, messages, "公共缓存")
    except Exception as e:
        logging.error(f"公共缓存补发异常: {e}")


async def _resend_cache(secret: str, websocket: WebSocket, cache_queue: list, cache_desc: str):
    """通用缓存补发"""
    if not cache_queue:
        return
    
    now = datetime.now()
    success, fail, valid = 0, 0, 0
    
    logging.info(f"开始补发{cache_desc} | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 总量:{len(cache_queue)}")
    
    batch_size = 10
    for i in range(0, len(cache_queue), batch_size):
        batch = cache_queue[i:i + batch_size]
        for expiry, msg in batch:
            if expiry < now:
                continue
            valid += 1
            try:
                await websocket.send_bytes(msg)
                success += 1
            except:
                fail += 1
        
        if i + batch_size < len(cache_queue):
            await asyncio.sleep(1)
    
    logging.info(f"{cache_desc}补发完成 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 有效:{valid} 成功:{success} 失败:{fail}")


async def send_heartbeat(websocket: WebSocket, secret: str):
    """发送心跳"""
    heartbeat_failures = 0
    try:
        while True:
            await asyncio.sleep(35)
            if websocket.client_state.name != 'CONNECTED':
                break
            try:
                await websocket.send_bytes(json.dumps({"op": 11}))
                heartbeat_failures = 0
            except Exception as e:
                heartbeat_failures += 1
                logging.error(f"心跳发送失败 (第{heartbeat_failures}次): {e}")
                if heartbeat_failures >= 3:
                    break
                await asyncio.sleep(5)
    except asyncio.CancelledError:
        pass


async def handle_ws_message(message: str, websocket: WebSocket):
    """处理WebSocket消息"""
    try:
        data = json.loads(message)
        op = data.get("op")
        
        if op == 1:  # 心跳
            await websocket.send_bytes(json.dumps({"op": 11}))
        elif op == 2:  # 鉴权
            await websocket.send_bytes(json.dumps({
                "op": 0, "s": 1, "t": "READY",
                "d": {"version": 1, "session_id": "open-connection", "user": {"bot": True}, "shard": [0, 0]}
            }))
        elif op == 6:  # Resume
            await websocket.send_bytes(json.dumps({"op": 0, "s": 1, "t": "RESUMED", "d": {}}))
    except Exception as e:
        logging.error(f"WS消息处理错误: {e}")
        service_health["error_count"] += 1


async def forward_webhook(targets: List[dict], body: bytes, headers: dict, timeout: int, current_secret: str) -> list:
    """Webhook转发"""
    message_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
    webhook_targets = [t for t in targets if t['secret'] == current_secret]
    
    record = MessagePushRecord(message_id, current_secret, body, len(webhook_targets))
    record.status = "sending"
    push_records[message_id] = record
    
    async def send_with_retry(session: aiohttp.ClientSession, target: dict) -> dict:
        if target['secret'] != current_secret:
            return {'url': target['url'], 'success': True, 'skipped': True}

        start = time.time()
        retry_count = 0
        last_error = None
        
        while time.time() - start < MAX_RETRY_TIME:
            try:
                async with asyncio.timeout(PUSH_TIMEOUT):
                    async with session.post(target['url'], data=body, headers=headers,
                                           timeout=aiohttp.ClientTimeout(total=PUSH_TIMEOUT)) as resp:
                        if 200 <= resp.status < 300:
                            record.success_count += 1
                            return {'url': target['url'], 'status': resp.status, 'success': True, 
                                   'skipped': False, 'retry_count': retry_count, 'duration': round(time.time() - start, 2)}
                        last_error = f"HTTP {resp.status}"
            except asyncio.TimeoutError:
                last_error = "超时"
            except Exception as e:
                last_error = str(e)
            
            retry_count += 1
            record.retry_count = retry_count
            await asyncio.sleep(RETRY_INTERVAL)
        
        return {'url': target['url'], 'success': False, 'skipped': False, 'timeout': True, 
               'retry_count': retry_count, 'error': last_error or '超时'}

    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[send_with_retry(session, t) for t in targets])
        record.end_time = time.time()
        record.status = "success" if any(r.get('success') and not r.get('skipped') for r in results) else "failed"
        return results
