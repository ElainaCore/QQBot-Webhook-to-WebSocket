# -*- coding: utf-8 -*-
"""aiohttp 应用工厂 — 实例创建、生命周期、SPA 路由"""
import asyncio
import logging
import os
from datetime import datetime

from aiohttp import web

from modules.core.config import config
from modules.data import database as db
from modules.data.cache import cache_manager
from modules.net.connections import active_connections, close_http_session, retry_queue_worker
from modules.core.session import valid_sessions, load_from_db as load_session_data
from modules.data.stats import stats_manager
from modules.data.appid import app_id_manager
from modules.util.helpers import setup_logger

logger = setup_logger()

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DIR = os.path.join(_BASE_DIR, "web")

MEMORY_CLEANUP_INTERVAL = 180
SESSION_MAX_AGE = 60 * 60 * 24 * 7


# ========== 后台任务 ==========

async def _stats_flush_loop():
    while True:
        await asyncio.sleep(2)
        try:
            stats_manager.flush_to_db()
        except Exception as e:
            logging.error(f"统计刷入异常: {e}")


async def _cleanup_memory():
    while True:
        try:
            await asyncio.sleep(MEMORY_CLEANUP_INTERVAL)
            now = datetime.now()
            counts = {"sessions": 0, "cache_locks": 0}

            for sid in [s for s, info in valid_sessions.items()
                        if info.get('created') and (now - info['created']).total_seconds() > SESSION_MAX_AGE]:
                valid_sessions.pop(sid, None)
                db.delete_session(sid)
                counts["sessions"] += 1

            for secret in [s for s in cache_manager.cache_locks
                           if s not in active_connections and s not in cache_manager.message_cache]:
                cache_manager.cache_locks.pop(secret, None)
                counts["cache_locks"] += 1

            total = sum(counts.values())
            if total:
                logging.info(f"内存清理完成 | Sessions:{counts['sessions']} 锁:{counts['cache_locks']}")
        except Exception as e:
            logging.error(f"内存清理异常: {e}")


# ========== 生命周期 ==========

async def _on_startup(application: web.Application):
    db.init_db()
    db.migrate_from_json()
    db.start_flush_thread()

    load_session_data()
    app_id_manager.load_from_db()
    stats_manager.start_write_thread()

    application['bg_tasks'] = [
        asyncio.create_task(_cleanup_memory()),
        asyncio.create_task(_stats_flush_loop()),
        asyncio.create_task(retry_queue_worker()),
    ]
    cache_manager.start_cleaning_thread()

    if config.admin.get("enabled") and config.admin.get("password") in ("", "admin", "123456", "password"):
        logger.warning("管理员密码为默认/弱密码，请尽快在 config.yaml 中修改 admin.password")

    ssl_cfg = config.ssl
    use_ssl = ssl_cfg.get("ssl_keyfile") and ssl_cfg.get("ssl_certfile")
    protocol = "https" if use_ssl else "http"
    logger.info("=" * 50)
    logger.info(f"服务已启动 - 端口:{config.port}")
    logger.info(f"面板地址: {protocol}://127.0.0.1:{config.port}/web")
    logger.info("=" * 50)


async def _on_cleanup(application: web.Application):
    stats_manager.stop_write_thread()
    tasks = application.get('bg_tasks', [])
    for t in tasks:
        t.cancel()
    cache_manager.stop_cleaning_thread()
    db.stop_flush_thread()
    await close_http_session()
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except:
        pass
    logger.info("服务已停止")


# ========== 中间件 ==========

@web.middleware
async def _cors_middleware(request: web.Request, handler):
    if request.method == "OPTIONS":
        response = web.Response()
    else:
        try:
            response = await handler(request)
        except web.HTTPException as exc:
            response = exc
    if isinstance(response, web.WebSocketResponse):
        return response
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    return response


# ========== 创建应用 ==========

def create_app() -> web.Application:
    application = web.Application(middlewares=[_cors_middleware],
                                  client_max_size=10 * 1024 ** 2)
    application.on_startup.append(_on_startup)
    application.on_cleanup.append(_on_cleanup)

    from modules.api import admin, auth, webhook, websocket

    async def serve_root(request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "message": "Webhook Bridge"})

    async def serve_spa(request: web.Request):
        index = os.path.join(WEB_DIR, "index.html")
        if os.path.isfile(index):
            return web.FileResponse(index)
        return web.json_response({"status": "ok", "message": "Webhook Bridge"})

    router = application.router
    router.add_get("/", serve_root)

    # 认证
    router.add_post("/api/admin/login", auth.admin_login)
    router.add_get("/api/admin/verify", auth.verify_admin)
    router.add_post("/api/admin/logout", auth.admin_logout)

    # 管理
    router.add_get("/api/admin/stats", admin.get_stats)
    router.add_get("/api/admin/appids", admin.get_appids)
    router.add_post("/api/admin/appids/create", admin.create_appid_post)
    router.add_get("/api/admin/create_appid", admin.create_appid_get)
    router.add_delete("/api/admin/appids/{appid}", admin.delete_appid)
    router.add_get("/api/admin/settings", admin.get_settings)
    router.add_post("/api/admin/settings/update", admin.update_settings)
    router.add_post("/api/admin/webhook/add", admin.add_webhook)
    router.add_post("/api/admin/webhook/remove", admin.remove_webhook)
    router.add_get("/api/admin/db/tables", admin.db_list_tables)
    router.add_get("/api/admin/db/table/{table_name}", admin.db_query_table)

    # Webhook / WebSocket
    router.add_post("/webhook", webhook.handle_webhook)
    router.add_get("/ws/{secret}", websocket.websocket_endpoint)
    router.add_get("/api/ws/{appid}", websocket.appid_websocket_endpoint)
    # 动态 AppID 路由最后注册, 避免遮蔽 /api/admin/* 与 /api/ws/*
    router.add_post("/api/{appid}", webhook.handle_appid_webhook)

    # 静态资源 + Vue SPA catch-all
    assets_dir = os.path.join(WEB_DIR, "assets")
    if os.path.isdir(assets_dir):
        router.add_static("/web/assets", assets_dir)
    router.add_get("/web", serve_spa)
    router.add_get("/web/{path:.*}", serve_spa)

    return application
