# -*- coding: utf-8 -*-
"""FastAPI 应用工厂 — 实例创建、生命周期、SPA 路由"""
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from modules.core.config import config
from modules.data import database as db
from modules.data.cache import cache_manager
from modules.net.connections import active_connections
from modules.core.session import valid_sessions, load_from_db as load_session_data
from modules.net.monitoring import monitor_service_health
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

@asynccontextmanager
async def lifespan(application: FastAPI):
    db.init_db()
    db.migrate_from_json()
    db.start_flush_thread()

    load_session_data()
    app_id_manager.load_from_db()
    stats_manager.start_write_thread()
    config.start_watcher()

    tasks = [
        asyncio.create_task(monitor_service_health()),
        asyncio.create_task(_cleanup_memory()),
        asyncio.create_task(_stats_flush_loop()),
    ]
    cache_manager.start_cleaning_thread()

    ssl_cfg = config.ssl
    use_ssl = ssl_cfg.get("ssl_keyfile") and ssl_cfg.get("ssl_certfile")
    protocol = "https" if use_ssl else "http"
    logger.info("=" * 50)
    logger.info(f"服务已启动 - 端口:{config.port}")
    logger.info(f"面板地址: {protocol}://127.0.0.1:{config.port}/web")
    logger.info("=" * 50)

    yield

    stats_manager.stop_write_thread()
    for t in tasks:
        t.cancel()
    cache_manager.stop_cleaning_thread()
    db.stop_flush_thread()
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except:
        pass
    logger.info("服务已停止")


# ========== 创建应用 ==========

def create_app() -> FastAPI:
    application = FastAPI(lifespan=lifespan, log_level="info")
    application.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                               allow_methods=["*"], allow_headers=["*"])

    # 注册路由
    from modules.api.auth import router as auth_router
    from modules.api.webhook import router as webhook_router
    from modules.api.websocket import router as ws_router
    from modules.api.admin import router as admin_router

    application.include_router(auth_router)
    application.include_router(webhook_router)
    application.include_router(ws_router)
    application.include_router(admin_router)

    # 根路径
    @application.get("/")
    async def serve_root():
        return {"status": "ok", "message": "Webhook Bridge"}

    # 静态资源 (必须在 SPA catch-all 之前注册)
    assets_dir = os.path.join(WEB_DIR, "assets")
    if os.path.isdir(assets_dir):
        application.mount("/web/assets", StaticFiles(directory=assets_dir), name="assets")

    # Vue SPA catch-all — /web 及 /web/... 均返回 index.html
    @application.get("/web")
    @application.get("/web/{path:path}")
    async def serve_spa(request: Request, path: str = ""):
        index = os.path.join(WEB_DIR, "index.html")
        if os.path.isfile(index):
            return FileResponse(index)
        return {"status": "ok", "message": "Webhook Bridge"}

    return application
