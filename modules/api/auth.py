# -*- coding: utf-8 -*-
"""认证 API — 登录 / 登出 / 验证"""
import hmac
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from modules.core.config import config
from modules.core.session import (
    COOKIE_MAX_AGE, COOKIE_NAME, IP_MAX_FAIL_COUNT,
    cleanup_expired_ip_bans, create_session, get_current_admin,
    get_real_ip, ip_access_data, is_ip_banned,
    record_ip_access, remove_session, sign_cookie,
)

router = APIRouter(prefix="/api/admin", tags=["auth"])


@router.post("/login")
async def admin_login(request: Request, response: Response, data: Dict[str, Any]):
    cleanup_expired_ip_bans()
    ip = get_real_ip(request)

    if is_ip_banned(ip):
        fail_count = len(ip_access_data.get(ip, {}).get('password_fail_times', []))
        raise HTTPException(status_code=418,
                            detail=f"IP已被封禁24小时（错误{fail_count}次）")

    if not config.admin.get("password"):
        raise HTTPException(status_code=403, detail="未设置管理员密码，登录已禁用")

    if not hmac.compare_digest(str(data.get("password") or ""),
                               str(config.admin.get("password") or "")):
        record_ip_access(ip, False)
        remaining = max(0, IP_MAX_FAIL_COUNT - len(
            ip_access_data.get(ip, {}).get('password_fail_times', [])))
        if remaining > 0:
            raise HTTPException(status_code=401,
                                detail=f"密码错误，剩余{remaining}次")
        raise HTTPException(status_code=418, detail="IP已被封禁24小时")

    record_ip_access(ip, True)
    token = create_session(request)
    response.set_cookie(key=COOKIE_NAME, value=sign_cookie(token),
                        httponly=True, max_age=COOKIE_MAX_AGE, samesite="strict")
    logging.info(f"IP {ip} 管理员登录成功")
    return {"status": "success", "message": "登录成功"}


@router.get("/verify")
async def verify_admin(admin: str = Depends(get_current_admin)):
    return {"status": "success", "username": admin}


@router.post("/logout")
async def admin_logout(request: Request, response: Response,
                       admin: str = Depends(get_current_admin)):
    remove_session(request)
    response.delete_cookie(COOKIE_NAME)
    return {"status": "success", "message": "已退出登录"}
