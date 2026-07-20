# -*- coding: utf-8 -*-
"""认证 API — 登录 / 登出 / 验证"""
import hmac
import logging

from aiohttp import web

from modules.core.config import config
from modules.core.session import (
    COOKIE_MAX_AGE, COOKIE_NAME, IP_MAX_FAIL_COUNT,
    cleanup_expired_ip_bans, create_session, get_real_ip,
    ip_access_data, is_ip_banned, record_ip_access,
    remove_session, require_admin, sign_cookie,
)


def _err(status: int, detail: str) -> web.Response:
    return web.json_response({"detail": detail}, status=status)


async def admin_login(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:
        data = {}
    cleanup_expired_ip_bans()
    ip = get_real_ip(request)

    if is_ip_banned(ip):
        fail_count = len(ip_access_data.get(ip, {}).get('password_fail_times', []))
        return _err(418, f"IP已被封禁24小时（错误{fail_count}次）")

    if not config.admin.get("password"):
        return _err(403, "未设置管理员密码，登录已禁用")

    if not hmac.compare_digest(str(data.get("password") or ""),
                               str(config.admin.get("password") or "")):
        record_ip_access(ip, False)
        remaining = max(0, IP_MAX_FAIL_COUNT - len(
            ip_access_data.get(ip, {}).get('password_fail_times', [])))
        if remaining > 0:
            return _err(401, f"密码错误，剩余{remaining}次")
        return _err(418, "IP已被封禁24小时")

    record_ip_access(ip, True)
    token = create_session(request)
    response = web.json_response({"status": "success", "message": "登录成功"})
    response.set_cookie(COOKIE_NAME, sign_cookie(token),
                        httponly=True, max_age=COOKIE_MAX_AGE, samesite="Strict")
    logging.info(f"IP {ip} 管理员登录成功")
    return response


async def verify_admin(request: web.Request) -> web.Response:
    admin = require_admin(request)
    return web.json_response({"status": "success", "username": admin})


async def admin_logout(request: web.Request) -> web.Response:
    require_admin(request)
    remove_session(request)
    response = web.json_response({"status": "success", "message": "已退出登录"})
    response.del_cookie(COOKIE_NAME)
    return response
