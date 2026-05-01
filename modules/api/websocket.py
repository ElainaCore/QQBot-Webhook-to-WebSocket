# -*- coding: utf-8 -*-
"""WebSocket 端点"""
import asyncio
import json
import logging
import time
from collections import deque

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from modules.core.config import config
from modules.data.cache import cache_manager
from modules.net.connections import (HELLO_PAYLOAD, active_connections, handle_ws_message,
                                     resend_public_cache, resend_token_cache,
                                     send_heartbeat, service_health)
from modules.util.privacy import PrivacyUtils
from modules.data.appid import app_id_manager

router = APIRouter(tags=["websocket"])


async def _handle_websocket(websocket: WebSocket, secret: str, token: str = None,
                            group: str = None, member: str = None, content: str = None):
    try:
        await websocket.accept()
        await websocket.send_bytes(HELLO_PAYLOAD)

        is_sandbox = any([group, member, content])
        lock = await cache_manager.get_lock_for_secret(secret)

        async with lock:
            active_connections.setdefault(secret, {})[websocket] = {
                "token": token, "failure_count": 0, "group": group,
                "member": member, "content": content,
                "is_sandbox": is_sandbox, "last_activity": time.time(),
            }
            count = len(active_connections[secret])
            if token and secret not in config.no_cache_secrets:
                cache_manager.message_cache.setdefault(
                    secret, {"public": deque(maxlen=config.cache["max_public_messages"]), "tokens": {}})
                cache_manager.message_cache[secret]["tokens"].setdefault(
                    token, deque(maxlen=config.cache["max_token_messages"]))

        logging.info(f"WS连接 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | "
                     f"Token:{PrivacyUtils.sanitize_secret(token) if token else '无'} | "
                     f"{'沙盒' if is_sandbox else '正式'} | 连接数:{count}")

        if token:
            asyncio.create_task(resend_token_cache(secret, token, websocket))
        asyncio.create_task(resend_public_cache(secret, websocket))
        heartbeat_task = asyncio.create_task(send_heartbeat(websocket, secret))

        try:
            while True:
                try:
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=60)
                    async with lock:
                        if secret in active_connections and websocket in active_connections[secret]:
                            active_connections[secret][websocket]["last_activity"] = time.time()
                    await handle_ws_message(data, websocket)
                    service_health["last_successful_ws_message"] = time.time()
                except asyncio.TimeoutError:
                    async with lock:
                        if secret in active_connections and websocket in active_connections[secret]:
                            if time.time() - active_connections[secret][websocket]["last_activity"] > 90:
                                break
                        else:
                            break
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logging.error(f"WS异常: {e}")
        finally:
            heartbeat_task.cancel()
            async with lock:
                if secret in active_connections and websocket in active_connections[secret]:
                    conn_token = active_connections[secret][websocket]["token"]
                    del active_connections[secret][websocket]
                    remaining = len(active_connections[secret])
                    if conn_token and secret not in config.no_cache_secrets:
                        cache_manager.message_cache.setdefault(
                            secret, {"public": deque(maxlen=config.cache["max_public_messages"]), "tokens": {}})
                        cache_manager.message_cache[secret]["tokens"].setdefault(
                            conn_token, deque(maxlen=config.cache["max_token_messages"]))
                    logging.info(f"WS断开 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 剩余:{remaining}")
                    if not active_connections[secret]:
                        del active_connections[secret]
    except Exception as e:
        logging.error(f"WS全局异常: {e}")
        try:
            await websocket.close()
        except:
            pass


@router.websocket("/ws/{secret}")
async def websocket_endpoint(websocket: WebSocket, secret: str, token: str = None,
                             group: str = None, member: str = None, content: str = None):
    await _handle_websocket(websocket, secret, token, group, member, content)


@router.websocket("/api/ws/{appid}")
async def appid_websocket_endpoint(websocket: WebSocket, appid: str, token: str = None,
                                   group: str = None, member: str = None, content: str = None,
                                   signature: str = None, timestamp: str = None, nonce: str = None):
    secret = app_id_manager.get_secret_by_appid(appid)
    if not secret:
        await websocket.accept()
        await websocket.close(code=1008, reason="无效的AppID")
        return
    if (signature and timestamp and nonce
            and not app_id_manager.verify_signature(appid, signature, timestamp, nonce)):
        await websocket.accept()
        await websocket.close(code=1008, reason="签名验证失败")
        return
    await _handle_websocket(websocket, secret, token, group, member, content)
