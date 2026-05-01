# -*- coding: utf-8 -*-
"""管理 API — 统计、AppID CRUD、设置、Webhook 配置、数据库查看"""
import logging
import sqlite3
import time
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from modules.core.config import config
from modules.data import database as db
from modules.net.connections import active_connections
from modules.core.session import get_current_admin
from modules.util.privacy import PrivacyUtils
from modules.data.stats import stats_manager
from modules.data.appid import app_id_manager

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ========== 统计 ==========

@router.get("/stats")
async def get_stats(admin: str = Depends(get_current_admin)):
    with stats_manager.stats_lock:
        stats_snap = {
            "ws": dict(stats_manager.stats.get("ws", {})),
            "wh": dict(stats_manager.stats.get("wh", {})),
            "total_messages": stats_manager.stats.get("total_messages", 0),
            "per_secret": {k: {"ws": dict(v.get("ws", {})), "wh": dict(v.get("wh", {}))}
                           for k, v in stats_manager.stats.get("per_secret", {}).items()},
        }

    webhook_counts = {}
    for t in config.webhook_forward["targets"]:
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

    return {
        "total_appids": len(app_id_manager.appids),
        "ws": stats_snap.get("ws", {}),
        "wh": stats_snap.get("wh", {}),
        "total_messages": stats_snap.get("total_messages", 0),
        "online": {s: len(c) for s, c in active_connections.items()},
        "forward_config": [{"appid": t.get("appid", ""), "url": t["url"]}
                           for t in config.webhook_forward["targets"]],
        "webhook_enabled": config.webhook_forward["enabled"],
        "per_secret": per_secret,
        "webhook_links_count": webhook_counts,
    }


# ========== AppID CRUD ==========

@router.get("/appids")
async def get_appids(admin: str = Depends(get_current_admin)):
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
    return sorted(result, key=lambda x: x.get("create_time", 0), reverse=True)


@router.post("/appids/create")
async def create_appid_post(request: Request,
                            admin: str = Depends(get_current_admin)):
    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的JSON数据")
    return _create_appid(data.get("appid", ""), data.get("secret", ""),
                         data.get("description", ""))


@router.get("/create_appid")
async def create_appid_get(appid: str = Query(...), secret: str = Query(...),
                           description: str = Query(""),
                           admin: str = Depends(get_current_admin)):
    return _create_appid(appid, secret, description)


def _create_appid(appid, secret, description):
    if not appid or not appid.strip():
        raise HTTPException(status_code=400, detail="AppID不能为空")
    if not secret or len(secret) < 10:
        raise HTTPException(status_code=400, detail="密钥长度必须至少为10个字符")
    ok, msg = app_id_manager.create_appid(appid.strip(), secret.strip(), description.strip())
    if not ok:
        raise HTTPException(status_code=400, detail=f"创建AppID失败: {msg}")
    return {"appid": appid, "secret": secret, "description": description,
            "create_time": time.time(), "status": msg}


@router.delete("/appids/{appid}")
async def delete_appid(appid: str, admin: str = Depends(get_current_admin)):
    if not app_id_manager.delete_appid(appid):
        raise HTTPException(status_code=404, detail="AppID不存在")
    return {"status": "success", "appid": appid}


# ========== 设置 ==========

@router.get("/settings")
async def get_settings(admin: str = Depends(get_current_admin)):
    return {
        "log_level": config.log_level,
        "deduplication_ttl": config.deduplication_ttl,
        "raw_content": getattr(config, 'raw_content', {"enabled": False, "path": "logs"}),
        "ssl": config.ssl,
    }


@router.post("/settings/update")
async def update_settings(data: Dict[str, Any],
                          admin: str = Depends(get_current_admin)):
    settings = data
    if "raw_content" in settings:
        rc = settings["raw_content"]
        rc.setdefault("enabled", False)
        rc.setdefault("path", "logs")
        if not isinstance(rc.get("enabled"), bool):
            raise HTTPException(status_code=400, detail="raw_content.enabled必须是布尔值")
        path = rc.get("path", "")
        if not path or ".." in path or path.startswith("/") or ":" in path:
            raise HTTPException(status_code=400, detail="raw_content.path路径格式不安全")
    config.update_settings(settings)
    if "log_level" in settings:
        logging.getLogger().setLevel(settings["log_level"])
    logging.info("管理员更新了系统设置")
    return {"status": "success", "message": "系统设置已更新"}


# ========== Webhook 转发配置 ==========

@router.post("/webhook/add")
async def add_webhook(target: Dict[str, str],
                      admin: str = Depends(get_current_admin)):
    appid = target.get("appid", "").strip()
    url = target.get("url", "").strip()
    if not appid:
        raise HTTPException(status_code=400, detail="请选择AppID")
    if not url or not url.startswith(('http://', 'https://')):
        raise HTTPException(status_code=400, detail="URL必须以http://或https://开头")
    if any(t.get("appid") == appid and t["url"] == url
           for t in config.webhook_forward["targets"]):
        raise HTTPException(status_code=400, detail="该转发配置已存在")
    config.webhook_forward["targets"].append({"appid": appid, "url": url})
    try:
        config.save()
    except Exception as e:
        config.webhook_forward["targets"] = [
            t for t in config.webhook_forward["targets"]
            if not (t.get("appid") == appid and t["url"] == url)]
        raise HTTPException(status_code=500, detail=f"保存配置失败: {e}")
    logging.info(f"添加Webhook转发: AppID:{appid} -> {url}")
    return {"status": "success", "message": "Webhook转发配置已添加"}


@router.post("/webhook/remove")
async def remove_webhook(target: Dict[str, str],
                         admin: str = Depends(get_current_admin)):
    appid = target.get("appid", "")
    url = target.get("url", "")
    original = len(config.webhook_forward["targets"])
    config.webhook_forward["targets"] = [
        t for t in config.webhook_forward["targets"]
        if not (t.get("appid") == appid and t["url"] == url)]
    if len(config.webhook_forward["targets"]) == original:
        raise HTTPException(status_code=404, detail="未找到该转发配置")
    try:
        config.save()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"保存配置失败: {e}")
    logging.info(f"删除Webhook转发: AppID:{appid} -> {url}")
    return {"status": "success", "message": "Webhook转发配置已删除"}


# ========== 数据库查看 ==========

@router.get("/db/tables")
async def db_list_tables(admin: str = Depends(get_current_admin)):
    conn = sqlite3.connect(db.DB_PATH)
    conn.row_factory = sqlite3.Row
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]
    result = []
    for t in tables:
        count = conn.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
        cols = [c[1] for c in conn.execute(f"PRAGMA table_info([{t}])").fetchall()]
        result.append({"name": t, "count": count, "columns": cols})
    conn.close()
    return result


@router.get("/db/table/{table_name}")
async def db_query_table(table_name: str, page: int = Query(1, ge=1),
                         page_size: int = Query(50, ge=1, le=500),
                         admin: str = Depends(get_current_admin)):
    conn = sqlite3.connect(db.DB_PATH)
    conn.row_factory = sqlite3.Row
    valid = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)).fetchone()
    if not valid:
        conn.close()
        raise HTTPException(status_code=404, detail="表不存在")
    total = conn.execute(f"SELECT COUNT(*) FROM [{table_name}]").fetchone()[0]
    cols = [c[1] for c in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()]
    offset = (page - 1) * page_size
    rows = conn.execute(f"SELECT * FROM [{table_name}] LIMIT ? OFFSET ?",
                        (page_size, offset)).fetchall()
    conn.close()
    data = [dict(r) for r in rows]
    return {"table": table_name, "columns": cols, "rows": data,
            "total": total, "page": page, "page_size": page_size}
