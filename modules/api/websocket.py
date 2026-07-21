# -*- coding: utf-8 -*-
"""WebSocket 端点"""
import asyncio
import logging
import time

from aiohttp import WSMsgType, web

from modules.data.cache import cache_manager
from modules.net.connections import (HELLO_PAYLOAD, active_connections, handle_ws_message,
                                     resend_cache, send_heartbeat)
from modules.util.privacy import PrivacyUtils
from modules.data.appid import app_id_manager


async def _handle_websocket(request: web.Request, secret: str) -> web.WebSocketResponse:
    websocket = web.WebSocketResponse()
    try:
        await websocket.prepare(request)
        await websocket.send_bytes(HELLO_PAYLOAD)

        lock = cache_manager.get_lock_for_secret(secret)

        conn_info = {"failure_count": 0, "last_activity": time.time()}
        async with lock:
            active_connections.setdefault(secret, {})[websocket] = conn_info
            count = len(active_connections[secret])

        logging.info(f"WS连接 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | "
                     f"连接数:{count}")

        resend_task = asyncio.create_task(resend_cache(secret, websocket))
        heartbeat_task = asyncio.create_task(send_heartbeat(websocket, secret))

        try:
            while True:
                try:
                    msg = await websocket.receive(timeout=60)
                    if msg.type in (WSMsgType.TEXT, WSMsgType.BINARY):
                        conn_info["last_activity"] = time.time()
                        data = msg.data.decode() if isinstance(msg.data, bytes) else msg.data
                        await handle_ws_message(data, websocket)
                    elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING,
                                      WSMsgType.CLOSED, WSMsgType.ERROR):
                        break
                except asyncio.TimeoutError:
                    if websocket not in active_connections.get(secret, {}):
                        break
                    if time.time() - conn_info["last_activity"] > 90:
                        break
        except Exception as e:
            logging.error(f"WS异常: {e}")
        finally:
            heartbeat_task.cancel()
            resend_task.cancel()
            try:
                await websocket.close()
            except Exception:
                pass
            async with lock:
                if secret in active_connections and websocket in active_connections[secret]:
                    del active_connections[secret][websocket]
                    remaining = len(active_connections[secret])
                    logging.info(f"WS断开 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 剩余:{remaining}")
                    if not active_connections[secret]:
                        del active_connections[secret]
    except Exception as e:
        logging.error(f"WS全局异常: {e}")
        try:
            await websocket.close()
        except:
            pass
    return websocket


async def websocket_endpoint(request: web.Request) -> web.WebSocketResponse:
    return await _handle_websocket(request, request.match_info["secret"])


async def appid_websocket_endpoint(request: web.Request) -> web.WebSocketResponse:
    appid = request.match_info["appid"]
    signature = request.query.get("signature")
    timestamp = request.query.get("timestamp")
    nonce = request.query.get("nonce")
    secret = app_id_manager.get_secret_by_appid(appid)
    if not secret:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.close(code=1008, message="无效的AppID".encode())
        return ws
    if (signature and timestamp and nonce
            and not app_id_manager.verify_signature(appid, signature, timestamp, nonce)):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.close(code=1008, message="签名验证失败".encode())
        return ws
    return await _handle_websocket(request, secret)
