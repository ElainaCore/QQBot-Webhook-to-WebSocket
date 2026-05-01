# -*- coding: utf-8 -*-
"""Session 管理、Cookie 签名、IP 访问控制"""
import hashlib
import hmac
import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import HTTPException, Request, status

from modules.data import database as db

COOKIE_NAME = "admin_session"
COOKIE_SECRET = os.environ.get("COOKIE_SECRET", "webhook_ws_cookie_secret_2024")
COOKIE_MAX_AGE = 60 * 60 * 24 * 7
SESSION_MAX_AGE = 60 * 60 * 24 * 7
IP_BAN_DURATION = 86400
IP_MAX_FAIL_COUNT = 5
MAX_SESSIONS = 10

# 内存状态
valid_sessions: Dict[str, Dict] = {}
ip_access_data: Dict[str, Dict] = {}
_last_ip_cleanup = 0


def load_from_db():
    global valid_sessions, ip_access_data
    valid_sessions = db.load_sessions()
    ip_access_data = db.load_ip_data()


# ========== IP 管理 ==========

def get_real_ip(request: Request) -> str:
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    real_ip = request.headers.get('X-Real-IP')
    return real_ip.strip() if real_ip else (request.client.host if request.client else 'unknown')


def record_ip_access(ip: str, success: bool = True):
    now = datetime.now()
    if ip not in ip_access_data:
        ip_access_data[ip] = {
            'last_access': now.isoformat(),
            'password_fail_times': [], 'is_banned': False, 'ban_time': None,
        }
    data = ip_access_data[ip]
    data['last_access'] = now.isoformat()
    if not success:
        data['password_fail_times'].append(now.isoformat())
        data['password_fail_times'] = [
            t for t in data['password_fail_times']
            if (now - datetime.fromisoformat(t)).total_seconds() < IP_BAN_DURATION]
        if len(data['password_fail_times']) >= IP_MAX_FAIL_COUNT:
            data['is_banned'] = True
            data['ban_time'] = now.isoformat()
            logging.warning(f"IP {ip} 因密码错误次数过多被封禁24小时")
    else:
        data['password_fail_times'] = []
    db.save_ip(ip, data)


def is_ip_banned(ip: str) -> bool:
    data = ip_access_data.get(ip)
    if not data or not data.get('is_banned'):
        return False
    ban_time = data.get('ban_time')
    if ban_time and (datetime.now() - datetime.fromisoformat(ban_time)).total_seconds() >= IP_BAN_DURATION:
        data.update({'is_banned': False, 'ban_time': None, 'password_fail_times': []})
        db.save_ip(ip, data)
        logging.info(f"IP {ip} 封禁期满，已解封")
        return False
    return True


def cleanup_expired_ip_bans():
    global _last_ip_cleanup
    if time.time() - _last_ip_cleanup < 3600:
        return
    _last_ip_cleanup = time.time()
    now = datetime.now()
    cleaned = 0
    for ip, data in ip_access_data.items():
        if 'password_fail_times' in data:
            data['password_fail_times'] = [
                t for t in data['password_fail_times']
                if (now - datetime.fromisoformat(t)).total_seconds() < IP_BAN_DURATION]
        if data.get('is_banned') and data.get('ban_time'):
            try:
                if (now - datetime.fromisoformat(data['ban_time'])).total_seconds() >= IP_BAN_DURATION:
                    data.update({'is_banned': False, 'ban_time': None, 'password_fail_times': []})
                    db.save_ip(ip, data)
                    cleaned += 1
            except:
                pass
    if cleaned:
        logging.info(f"清理了 {cleaned} 个过期的IP封禁")


# ========== Cookie 签名 ==========

def sign_cookie(value: str) -> str:
    sig = hmac.new(COOKIE_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"


def verify_cookie(signed: str) -> Optional[str]:
    try:
        value, sig = signed.rsplit('.', 1)
        expected = hmac.new(COOKIE_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
        return value if hmac.compare_digest(sig, expected) else None
    except:
        return None


# ========== Session 管理 ==========

def cleanup_sessions():
    now = datetime.now()
    expired = [t for t, info in valid_sessions.items() if now >= info['expires']]
    for t in expired:
        valid_sessions.pop(t, None)
        db.delete_session(t)


def limit_session_count():
    if len(valid_sessions) > MAX_SESSIONS:
        sorted_s = sorted(valid_sessions.items(), key=lambda x: x[1]['created'])
        for i in range(len(valid_sessions) - MAX_SESSIONS):
            token = sorted_s[i][0]
            valid_sessions.pop(token, None)
            db.delete_session(token)


def is_logged_in(request: Request) -> bool:
    cleanup_sessions()
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return False
    token = verify_cookie(cookie)
    if not token or token not in valid_sessions:
        return False
    info = valid_sessions[token]
    if datetime.now() >= info['expires']:
        valid_sessions.pop(token, None)
        db.delete_session(token)
        return False
    real_ip = get_real_ip(request)
    user_agent = request.headers.get('User-Agent', '')[:200]
    if info.get('ip') and info.get('ip') != real_ip:
        logging.warning(f"Session IP不匹配: {info.get('ip')} != {real_ip}")
        return False
    if info.get('user_agent') and info.get('user_agent')[:200] != user_agent:
        logging.warning("Session User-Agent不匹配")
        return False
    return True


def create_session(request: Request) -> str:
    cleanup_sessions()
    limit_session_count()
    token = secrets.token_hex(32)
    ip = get_real_ip(request)
    user_agent = request.headers.get('User-Agent', '')[:200]
    info = {
        'created': datetime.now(),
        'expires': datetime.now() + timedelta(days=7),
        'ip': ip, 'user_agent': user_agent,
    }
    valid_sessions[token] = info
    db.save_session(token, info)
    return token


def remove_session(request: Request):
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie:
        token = verify_cookie(cookie)
        if token and token in valid_sessions:
            valid_sessions.pop(token, None)
            db.delete_session(token)


async def get_current_admin(request: Request) -> str:
    if not is_logged_in(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="未登录或会话已过期")
    return "admin"
