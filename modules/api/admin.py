# -*- coding: utf-8 -*-
"""管理 API — 统计、AppID CRUD、设置、Webhook 配置、数据库查看"""
import logging
import sqlite3
import time
from contextlib import closing

from aiohttp import web

from modules.core.config import config
from modules.data import database as db
from modules.net.connections import active_connections
from modules.core.session import require_admin
from modules.util.privacy import PrivacyUtils
from modules.data.stats import stats_manager
from modules.data.appid import app_id_manager


def _err(status: int, detail: str) -> web.Response:
    return web.json_response({"detail": detail}, status=status)


# ========== 统计 ==========

async def get_stats(request: web.Request) -> web.Response:
    require_admin(request)
    with stats_manager.stats_lock:
        stats_snap = {
            "ws": dict(stats_manager.stats.get("ws", {})),
            "wh": dict(stats_manager.stats.get("wh", {})),
            "total_messages": stats_manager.stats.get("total_messages", 0),
            "per_secret": {k: {"ws": dict(v.get("ws", {})), "wh": dict(v.get("wh", {}))}
                           for k, v in stats_manager.stats.get("per_secret", {}).items()},
        }

    webhook_counts = {}
    for t in (config.webhook_forward or {}).get("targets") or []:
        aid = t.get("appid", "")
        webhook_counts[aid] = webhook_counts.get(aid, 0) + 1

    secret_to_appid = {}
    for info in app_id_manager.get_all_appids():
        secret_to_appid[info["secret"]] = info["appid"]

    per_secret = {}
    for secret, data in stats_snap.get("per_secret", {}).items():
        per_secret[secret] = {
            "appid": secret_to_appid.get(secret, ""),
            "ws": data.get("ws", {}),
            "wh": data.get("wh", {}),
        }

    return web.json_response({
        "total_appids": len(app_id_manager.appids),
        "ws": stats_snap.get("ws", {}),
        "wh": stats_snap.get("wh", {}),
        "total_messages": stats_snap.get("total_messages", 0),
        "online": {s: len(c) for s, c in active_connections.items()},
        "forward_config": [{"appid": t.get("appid", ""), "url": t["url"]}
                           for t in (config.webhook_forward or {}).get("targets") or []],
        "webhook_enabled": (config.webhook_forward or {}).get("enabled", False),
        "per_secret": per_secret,
        "webhook_links_count": webhook_counts,
    })


# ========== AppID CRUD ==========

async def get_appids(request: web.Request) -> web.Response:
    require_admin(request)
    with stats_manager.stats_lock:
        ps = stats_manager.stats.get("per_secret", {})
    result = []
    for info in app_id_manager.get_all_appids():
        ss = ps.get(info["secret"], {})
        result.append({
            **info,
            "secret_masked": PrivacyUtils.sanitize_secret(info["secret"]),
            "ws": ss.get("ws", {"success": 0, "failure": 0}),
            "wh": ss.get("wh", {"success": 0, "failure": 0}),
        })
    return web.json_response(sorted(result, key=lambda x: x.get("create_time", 0), reverse=True))


async def create_appid_post(request: web.Request) -> web.Response:
    require_admin(request)
    try:
        data = await request.json()
    except:
        return _err(400, "无效的JSON数据")
    return _create_appid(data.get("appid", ""), data.get("secret", ""),
                         data.get("description", ""))


async def create_appid_get(request: web.Request) -> web.Response:
    require_admin(request)
    appid = request.query.get("appid")
    secret = request.query.get("secret")
    if appid is None or secret is None:
        return _err(400, "缺少appid或secret参数")
    return _create_appid(appid, secret, request.query.get("description", ""))


def _create_appid(appid, secret, description):
    if not appid or not appid.strip():
        return _err(400, "AppID不能为空")
    if not secret or len(secret) < 10:
        return _err(400, "密钥长度必须至少为10个字符")
    ok, msg = app_id_manager.create_appid(appid.strip(), secret.strip(), description.strip())
    if not ok:
        return _err(400, f"创建AppID失败: {msg}")
    return web.json_response({"appid": appid, "secret": secret, "description": description,
                              "create_time": time.time(), "status": msg})


async def delete_appid(request: web.Request) -> web.Response:
    require_admin(request)
    appid = request.match_info["appid"]
    if not app_id_manager.delete_appid(appid):
        return _err(404, "AppID不存在")
    return web.json_response({"status": "success", "appid": appid})


# ========== 设置 ==========

async def get_settings(request: web.Request) -> web.Response:
    require_admin(request)
    return web.json_response({
        "log_level": config.log_level,
        "deduplication_ttl": config.deduplication_ttl,
        "raw_content": getattr(config, 'raw_content', {"enabled": False, "path": "logs"}),
        "ssl": config.ssl,
    })


async def update_settings(request: web.Request) -> web.Response:
    require_admin(request)
    try:
        settings = await request.json()
    except:
        return _err(400, "无效的JSON数据")
    if "raw_content" in settings:
        rc = settings["raw_content"]
        rc.setdefault("enabled", False)
        rc.setdefault("path", "logs")
        if not isinstance(rc.get("enabled"), bool):
            return _err(400, "raw_content.enabled必须是布尔值")
        path = rc.get("path", "")
        if not path or ".." in path or path.startswith("/") or ":" in path:
            return _err(400, "raw_content.path路径格式不安全")
    if "log_level" in settings and settings["log_level"] not in (
            "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        return _err(400, "无效的日志级别")
    config.update_settings(settings)
    if "log_level" in settings:
        logging.getLogger().setLevel(settings["log_level"])
    logging.info("管理员更新了系统设置")
    return web.json_response({"status": "success", "message": "系统设置已更新"})


# ========== Webhook 转发配置 ==========

async def add_webhook(request: web.Request) -> web.Response:
    require_admin(request)
    try:
        target = await request.json()
    except:
        return _err(400, "无效的JSON数据")
    appid = target.get("appid", "").strip()
    url = target.get("url", "").strip()
    if not appid:
        return _err(400, "请选择AppID")
    if not url or not url.startswith(('http://', 'https://')):
        return _err(400, "URL必须以http://或https://开头")
    if any(t.get("appid") == appid and t["url"] == url
           for t in config.webhook_forward["targets"]):
        return _err(400, "该转发配置已存在")
    config.webhook_forward["targets"].append({"appid": appid, "url": url})
    try:
        config.save()
    except Exception as e:
        config.webhook_forward["targets"] = [
            t for t in config.webhook_forward["targets"]
            if not (t.get("appid") == appid and t["url"] == url)]
        return _err(500, f"保存配置失败: {e}")
    logging.info(f"添加Webhook转发: AppID:{appid} -> {url}")
    return web.json_response({"status": "success", "message": "Webhook转发配置已添加"})


async def remove_webhook(request: web.Request) -> web.Response:
    require_admin(request)
    try:
        target = await request.json()
    except:
        return _err(400, "无效的JSON数据")
    appid = target.get("appid", "")
    url = target.get("url", "")
    original = len(config.webhook_forward["targets"])
    config.webhook_forward["targets"] = [
        t for t in config.webhook_forward["targets"]
        if not (t.get("appid") == appid and t["url"] == url)]
    if len(config.webhook_forward["targets"]) == original:
        return _err(404, "未找到该转发配置")
    try:
        config.save()
    except Exception as e:
        return _err(500, f"保存配置失败: {e}")
    logging.info(f"删除Webhook转发: AppID:{appid} -> {url}")
    return web.json_response({"status": "success", "message": "Webhook转发配置已删除"})


# ========== 数据库查看 ==========

async def db_list_tables(request: web.Request) -> web.Response:
    require_admin(request)
    with closing(sqlite3.connect(db.DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]
        result = []
        for t in tables:
            count = conn.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
            cols = [c[1] for c in conn.execute(f"PRAGMA table_info([{t}])").fetchall()]
            result.append({"name": t, "count": count, "columns": cols})
    return web.json_response(result)


async def db_query_table(request: web.Request) -> web.Response:
    require_admin(request)
    table_name = request.match_info["table_name"]
    try:
        page = max(1, int(request.query.get("page", 1)))
        page_size = min(500, max(1, int(request.query.get("page_size", 50))))
    except ValueError:
        return _err(400, "无效的分页参数")
    with closing(sqlite3.connect(db.DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        valid = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)).fetchone()
        if not valid:
            return _err(404, "表不存在")
        total = conn.execute(f"SELECT COUNT(*) FROM [{table_name}]").fetchone()[0]
        cols = [c[1] for c in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()]
        offset = (page - 1) * page_size
        rows = conn.execute(f"SELECT * FROM [{table_name}] LIMIT ? OFFSET ?",
                            (page_size, offset)).fetchall()
    data = [dict(r) for r in rows]
    return web.json_response({"table": table_name, "columns": cols, "rows": data,
                              "total": total, "page": page, "page_size": page_size})
