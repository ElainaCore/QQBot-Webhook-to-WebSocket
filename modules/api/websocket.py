# -*- coding: utf-8 -*-
"""WebSocket 端点"""
import asyncio
import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from modules.data.cache import cache_manager
from modules.net.connections import (HELLO_PAYLOAD, active_connections, handle_ws_message,
                                     resend_cache, send_heartbeat)
from modules.util.privacy import PrivacyUtils
from modules.data.appid import app_id_manager

router = APIRouter(tags=["websocket"])


async def _handle_websocket(websocket: WebSocket, secret: str):
    try:
        await websocket.accept()
        await websocket.send_bytes(HELLO_PAYLOAD)

        lock = await cache_manager.get_lock_for_secret(secret)

        async with lock:
            active_connections.setdefault(secret, {})[websocket] = {
                "failure_count": 0,
                "last_activity": time.time(),
            }
            count = len(active_connections[secret])

        logging.info(f"WS连接 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | "
                     f"连接数:{count}")

        asyncio.create_task(resend_cache(secret, websocket))
        heartbeat_task = asyncio.create_task(send_heartbeat(websocket, secret))

        try:
            while True:
                try:
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=60)
                    async with lock:
                        if secret in active_connections and websocket in active_connections[secret]:
                            active_connections[secret][websocket]["last_activity"] = time.time()
                    await handle_ws_message(data, websocket)
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


@router.websocket("/ws/{secret}")
async def websocket_endpoint(websocket: WebSocket, secret: str):
    await _handle_websocket(websocket, secret)


@router.websocket("/api/ws/{appid}")
async def appid_websocket_endpoint(websocket: WebSocket, appid: str,
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
    await _handle_websocket(websocket, secret)
