import asyncio
import logging
import os
import time
import sys
import json
import secrets
import hmac
import hashlib
import re
import uvicorn
from collections import deque
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Header, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Response, Query
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import config
from modules.monitoring import watch_config, monitor_service_health
from modules.stats import stats_manager
from modules.user_manager import app_id_manager
from modules.privacy import PrivacyUtils
from modules.cache import cache_manager
from modules.utils import setup_logger, generate_signature
from modules.connections import (
    active_connections, send_to_all, handle_ws_message,
    forward_webhook, send_heartbeat, resend_token_cache, 
    resend_public_cache, service_health, push_records
)

# ==================== 配置常量 ====================
COOKIE_NAME = "admin_session"
COOKIE_SECRET = os.environ.get("COOKIE_SECRET", "webhook_ws_cookie_secret_2024")
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7天

MEMORY_CLEANUP_INTERVAL = 180  # 3分钟
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7天
IP_DATA_MAX_AGE = 60 * 60 * 24 * 30  # 30天
IP_BAN_DURATION = 86400  # 24小时
IP_MAX_FAIL_COUNT = 5
MAX_SESSIONS = 10  # 最大session数量

IP_DATA_FILE = "data/ip_access.json"
SESSION_DATA_FILE = "data/sessions.json"

# ==================== 全局状态 ====================
valid_sessions: Dict[str, Dict] = {}
ip_access_data: Dict[str, Dict] = {}
_last_ip_cleanup = 0

logger = setup_logger()

# ==================== Pydantic 模型 ====================
class Payload(BaseModel):
    d: dict

class SystemSettings(BaseModel):
    log_level: str = Field(..., pattern='^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$')
    deduplication_ttl: int = Field(..., ge=0, le=3600)
    raw_content: dict = Field(default_factory=dict)

class WebhookTarget(BaseModel):
    secret: str
    url: str

# ==================== IP 访问管理 ====================
def load_ip_data():
    global ip_access_data
    try:
        if os.path.exists(IP_DATA_FILE):
            with open(IP_DATA_FILE, 'r', encoding='utf-8') as f:
                ip_access_data = json.load(f)
    except Exception as e:
        logging.error(f"加载IP数据失败: {e}")
        ip_access_data = {}

def save_ip_data():
    try:
        os.makedirs(os.path.dirname(IP_DATA_FILE), exist_ok=True)
        with open(IP_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(ip_access_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error(f"保存IP数据失败: {e}")

def record_ip_access(ip: str, success: bool = True):
    now = datetime.now()
    if ip not in ip_access_data:
        ip_access_data[ip] = {'last_access': now.isoformat(), 'password_fail_times': [], 'is_banned': False, 'ban_time': None}
    
    data = ip_access_data[ip]
    data['last_access'] = now.isoformat()
    
    if not success:
        data['password_fail_times'].append(now.isoformat())
        # 只保留24小时内的失败记录
        data['password_fail_times'] = [t for t in data['password_fail_times'] 
                                        if (now - datetime.fromisoformat(t)).total_seconds() < IP_BAN_DURATION]
        if len(data['password_fail_times']) >= IP_MAX_FAIL_COUNT:
            data['is_banned'] = True
            data['ban_time'] = now.isoformat()
            logging.warning(f"IP {ip} 因密码错误次数过多被封禁24小时")
    else:
        data['password_fail_times'] = []
    
    save_ip_data()

def is_ip_banned(ip: str) -> bool:
    data = ip_access_data.get(ip)
    if not data or not data.get('is_banned'):
        return False
    
    ban_time = data.get('ban_time')
    if ban_time and (datetime.now() - datetime.fromisoformat(ban_time)).total_seconds() >= IP_BAN_DURATION:
        data.update({'is_banned': False, 'ban_time': None, 'password_fail_times': []})
        save_ip_data()
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
    for data in ip_access_data.values():
        if 'password_fail_times' in data:
            data['password_fail_times'] = [t for t in data['password_fail_times'] 
                                            if (now - datetime.fromisoformat(t)).total_seconds() < IP_BAN_DURATION]
        if data.get('is_banned') and data.get('ban_time'):
            try:
                if (now - datetime.fromisoformat(data['ban_time'])).total_seconds() >= IP_BAN_DURATION:
                    data.update({'is_banned': False, 'ban_time': None, 'password_fail_times': []})
                    cleaned += 1
            except:
                pass
    
    if cleaned:
        save_ip_data()
        logging.info(f"清理了 {cleaned} 个过期的IP封禁")

# ==================== Session 管理 ====================
def get_real_ip(request: Request) -> str:
    """获取真实IP地址（支持代理）"""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    real_ip = request.headers.get('X-Real-IP')
    return real_ip.strip() if real_ip else (request.client.host if request.client else 'unknown')

def load_session_data():
    """从文件加载session数据"""
    global valid_sessions
    try:
        if os.path.exists(SESSION_DATA_FILE):
            with open(SESSION_DATA_FILE, 'r', encoding='utf-8') as f:
                sessions = json.load(f)
            now = datetime.now()
            loaded = 0
            for token, info in sessions.items():
                try:
                    info['created'] = datetime.fromisoformat(info['created'])
                    info['expires'] = datetime.fromisoformat(info['expires'])
                    if now < info['expires']:
                        valid_sessions[token] = info
                        loaded += 1
                except:
                    pass
            if loaded:
                logging.info(f"已加载 {loaded} 个有效session")
    except Exception as e:
        logging.error(f"加载session数据失败: {e}")

def save_session_data():
    """保存session数据到文件"""
    try:
        os.makedirs(os.path.dirname(SESSION_DATA_FILE), exist_ok=True)
        data = {}
        for token, info in valid_sessions.items():
            data[token] = {
                'created': info['created'].isoformat() if isinstance(info['created'], datetime) else info['created'],
                'expires': info['expires'].isoformat() if isinstance(info['expires'], datetime) else info['expires'],
                'ip': info.get('ip', ''),
                'user_agent': info.get('user_agent', '')
            }
        with open(SESSION_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error(f"保存session数据失败: {e}")

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

def cleanup_sessions():
    now = datetime.now()
    expired = [t for t, info in valid_sessions.items() if now >= info['expires']]
    changed = len(expired) > 0
    for t in expired:
        valid_sessions.pop(t, None)
    if changed:
        save_session_data()

def limit_session_count():
    """限制session数量，删除最旧的"""
    if len(valid_sessions) > MAX_SESSIONS:
        sorted_sessions = sorted(valid_sessions.items(), key=lambda x: x[1]['created'])
        for i in range(len(valid_sessions) - MAX_SESSIONS):
            valid_sessions.pop(sorted_sessions[i][0], None)
        save_session_data()

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
        save_session_data()
        return False
    # 验证IP和User-Agent（防止session被盗用）
    real_ip = get_real_ip(request)
    user_agent = request.headers.get('User-Agent', '')[:200]
    if info.get('ip') and info.get('ip') != real_ip:
        logging.warning(f"Session IP不匹配: {info.get('ip')} != {real_ip}")
        return False
    if info.get('user_agent') and info.get('user_agent')[:200] != user_agent:
        logging.warning(f"Session User-Agent不匹配")
        return False
    return True

async def get_current_admin(request: Request) -> str:
    if not is_logged_in(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未登录或会话已过期")
    return "admin"

# ==================== 内存清理 ====================
async def cleanup_memory():
    while True:
        try:
            await asyncio.sleep(MEMORY_CLEANUP_INTERVAL)
            now = datetime.now()
            stats = {"sessions": 0, "ip_data": 0, "push_records": 0, "cache_locks": 0}
            
            # 清理过期session
            for sid in [s for s, info in valid_sessions.items() 
                       if info.get('created') and (now - info['created']).total_seconds() > SESSION_MAX_AGE]:
                valid_sessions.pop(sid, None)
                stats["sessions"] += 1
            
            # 清理过期IP数据
            for ip in [ip for ip, info in ip_access_data.items()
                      if (now - datetime.fromisoformat(info.get('last_access', now.isoformat()))).total_seconds() > IP_DATA_MAX_AGE]:
                ip_access_data.pop(ip, None)
                stats["ip_data"] += 1
            
            # 清理推送记录
            for msg_id in [mid for mid, rec in push_records.items() if rec.end_time and time.time() - rec.end_time > 300]:
                push_records.pop(msg_id, None)
                stats["push_records"] += 1
            
            # 清理未使用的缓存锁
            for secret in [s for s in cache_manager.cache_locks.keys()
                          if s not in active_connections and s not in cache_manager.message_cache]:
                cache_manager.cache_locks.pop(secret, None)
                stats["cache_locks"] += 1
            
            total = sum(stats.values())
            if total:
                logging.info(f"内存清理完成 | Sessions:{stats['sessions']} IP:{stats['ip_data']} 推送:{stats['push_records']} 锁:{stats['cache_locks']}")
        except Exception as e:
            logging.error(f"内存清理异常: {e}")

# ==================== 应用生命周期 ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    load_ip_data()
    load_session_data()
    tasks = [
        asyncio.create_task(watch_config()),
        asyncio.create_task(monitor_service_health()),
        asyncio.create_task(cleanup_memory())
    ]
    cache_manager.start_cleaning_thread()
    stats_manager.start_write_thread()
    
    # 显示启动信息和登录地址
    ssl_cfg = config.ssl
    use_ssl = ssl_cfg.get("ssl_keyfile") and ssl_cfg.get("ssl_certfile")
    protocol = "https" if use_ssl else "http"
    logger.info(f"=" * 50)
    logger.info(f"服务已启动 - 端口:{config.port}")
    logger.info(f"登录地址: {protocol}://127.0.0.1:{config.port}/login?token={config.access_token}")
    logger.info(f"=" * 50)
    
    yield
    
    # 停止前保存session
    save_session_data()
    
    for t in tasks:
        t.cancel()
    cache_manager.stop_cleaning_thread()
    stats_manager.stop_write_thread()
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except:
        pass
    logger.info("服务已停止")

app = FastAPI(lifespan=lifespan, log_level="info")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

os.makedirs("web/js", exist_ok=True)
os.makedirs("web/css", exist_ok=True)
app.mount("/static", StaticFiles(directory="web"), name="static")

# ==================== 页面路由 ====================
@app.get("/")
async def root():
    return {"status": "ok", "message": "Webhook"}

@app.get("/login")
async def login_page(request: Request, token: str = Query(None)):
    if token != config.access_token:
        return Response(status_code=403)
    if is_logged_in(request) and "/console" not in request.headers.get("referer", ""):
        return RedirectResponse(url="/console")
    return FileResponse("web/login.html")

@app.get("/console")
async def console_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse(url=f"/login?token={config.access_token}")
    return FileResponse("web/console.html")

@app.get("/admin")
async def admin_redirect(request: Request):
    if not config.admin.get("enabled", True):
        raise HTTPException(status_code=404, detail="管理员功能已禁用")
    return RedirectResponse(url="/console" if is_logged_in(request) else f"/login?token={config.access_token}")

# ==================== 认证 API ====================
@app.post("/api/admin/login")
async def admin_login(request: Request, response: Response, data: Dict[str, Any]):
    cleanup_expired_ip_bans()
    ip = get_real_ip(request)
    
    if is_ip_banned(ip):
        fail_count = len(ip_access_data.get(ip, {}).get('password_fail_times', []))
        raise HTTPException(status_code=418, detail=f"IP已被封禁24小时（错误{fail_count}次）")
    
    if data.get("password") != config.admin.get("password"):
        record_ip_access(ip, False)
        remaining = max(0, IP_MAX_FAIL_COUNT - len(ip_access_data.get(ip, {}).get('password_fail_times', [])))
        if remaining > 0:
            raise HTTPException(status_code=401, detail=f"密码错误，剩余{remaining}次")
        raise HTTPException(status_code=418, detail="IP已被封禁24小时")
    
    record_ip_access(ip, True)
    cleanup_sessions()
    limit_session_count()
    
    token = secrets.token_hex(32)
    user_agent = request.headers.get('User-Agent', '')[:200]
    valid_sessions[token] = {
        'created': datetime.now(),
        'expires': datetime.now() + timedelta(days=7),
        'ip': ip,
        'user_agent': user_agent
    }
    save_session_data()
    
    response.set_cookie(key=COOKIE_NAME, value=sign_cookie(token), httponly=True, max_age=COOKIE_MAX_AGE, samesite="lax")
    logging.info(f"IP {ip} 管理员登录成功")
    return {"status": "success", "message": "登录成功"}

@app.get("/api/admin/verify")
async def verify_admin(admin: str = Depends(get_current_admin)):
    return {"status": "success", "username": admin}

@app.post("/api/admin/logout")
async def admin_logout(request: Request, response: Response, admin: str = Depends(get_current_admin)):
    # 删除当前session
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie:
        token = verify_cookie(cookie)
        if token and token in valid_sessions:
            valid_sessions.pop(token, None)
            save_session_data()
    response.delete_cookie(COOKIE_NAME)
    return {"status": "success", "message": "已退出登录"}

# ==================== Webhook 处理 ====================
@app.post("/webhook")
async def handle_webhook(request: Request, payload: Payload, user_agent: str = Header(None), x_bot_appid: str = Header(None)):
    start_time = time.time()
    secret = request.query_params.get('secret')
    body = await request.body()
    
    # 原始消息记录
    if getattr(config, 'raw_content', {}).get('enabled'):
        _log_raw_message(request, body, secret, user_agent, x_bot_appid)
    
    stats_manager.increment_message_count()
    
    # 消息去重
    try:
        msg_data = json.loads(body)
        msg_id = msg_data.get('id')
        if msg_id:
            if cache_manager.has_message_id(msg_id):
                return {"status": "success"}
            cache_manager.add_message_id(msg_id, config.deduplication_ttl)
    except:
        pass
    
    # 签名验证回调
    if "event_ts" in payload.d and "plain_token" in payload.d:
        try:
            result = generate_signature(secret, payload.d["event_ts"], payload.d["plain_token"])
            service_health["last_successful_webhook"] = time.time()
            return result
        except Exception as e:
            logging.error(f"签名错误: {e}")
            return {"status": "error"}
    
    # Webhook 转发
    if config.webhook_forward['enabled'] and config.webhook_forward['targets']:
        await _forward_to_webhooks(secret, body, dict(request.headers))
    
    # WebSocket 转发
    enhanced_body = _add_http_context(body, request)
    skip_cache = secret in config.no_cache_secrets
    has_online = secret in active_connections and active_connections[secret]
    
    if not has_online and not skip_cache:
        await cache_manager.add_message(secret, enhanced_body)
    
    if has_online:
        try:
            await send_to_all(secret, enhanced_body)
        except Exception as e:
            logging.error(f"WebSocket转发异常: {e}")
    
    if time.time() - start_time > 2:
        logging.warning(f"Webhook处理耗时: {time.time()-start_time:.2f}s | 密钥:{PrivacyUtils.sanitize_secret(secret)}")
    
    service_health["last_successful_webhook"] = time.time()
    return {"status": "success"}

@app.post("/api/{appid}")
async def handle_appid_webhook(appid: str, request: Request, payload: Payload,
                               user_agent: str = Header(None), x_bot_appid: str = Header(None),
                               signature: str = Query(None), timestamp: str = Query(None), nonce: str = Query(None)):
    secret = app_id_manager.get_secret_by_appid(appid)
    if not secret:
        raise HTTPException(status_code=404, detail="无效的AppID")
    
    if signature and timestamp and nonce and not app_id_manager.verify_signature(appid, signature, timestamp, nonce):
        raise HTTPException(status_code=403, detail="签名验证失败")
    
    request.query_params._dict["secret"] = secret
    return await handle_webhook(request=request, payload=payload, user_agent=user_agent, x_bot_appid=x_bot_appid)

def _log_raw_message(request: Request, body: bytes, secret: str, user_agent: str, x_bot_appid: str):
    try:
        log_dir = config.raw_content.get('path', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f'raw_messages_{datetime.now():%Y-%m-%d}.log')
        
        try:
            raw_body = json.loads(body.decode('utf-8', errors='ignore'))
        except:
            raw_body = body.decode('utf-8', errors='ignore')
        
        entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'client_ip': request.client.host if request.client else "unknown",
            'secret': secret, 'user_agent': user_agent, 'x_bot_appid': x_bot_appid,
            'content_length': len(body), 'raw_body': raw_body
        }
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception as e:
        logging.error(f"记录原始消息失败: {e}")

async def _forward_to_webhooks(secret: str, body: bytes, headers: dict):
    try:
        results = await forward_webhook(config.webhook_forward['targets'], body, headers, config.webhook_forward['timeout'], secret)
        success, fail = 0, 0
        for r in results:
            if r.get('skipped'):
                continue
            current_time = time.strftime('%m-%d %H:%M:%S')
            if r['success']:
                success += 1
                if r.get('retry_count', 0) > 0:
                    logging.info(f"{current_time} - Webhook重试转发成功 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 耗时:{r.get('duration', 0)}秒 | 重试:{r.get('retry_count', 0)}次")
                else:
                    logging.info(f"{current_time} - Webhook转发成功 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 耗时:{r.get('duration', 0)}秒")
            else:
                fail += 1
                if r.get('retry_count', 0) > 0:
                    logging.error(f"{current_time} - Webhook重试转发失败 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 重试:{r.get('retry_count', 0)}次 | 错误:{r.get('error', '未知')}")
                else:
                    logging.error(f"{current_time} - Webhook转发失败 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 错误:{r.get('error', '未知')}")
        stats_manager.batch_update_wh_stats(secret, success, fail)
    except Exception as e:
        logging.error(f"Webhook转发异常: {e}")

def _add_http_context(body: bytes, request: Request) -> bytes:
    try:
        data = json.loads(body)
        if 'http_context' not in data:
            data['http_context'] = {
                'headers': dict(request.headers), 'path': request.url.path,
                'method': request.method, 'url': str(request.url),
                'remote_addr': request.client.host if request.client else 'unknown'
            }
            return json.dumps(data, ensure_ascii=False).encode('utf-8')
    except:
        pass
    return body

# ==================== WebSocket ====================
async def _handle_websocket(websocket: WebSocket, secret: str, token: str = None,
                            group: str = None, member: str = None, content: str = None):
    try:
        await websocket.accept()
        await websocket.send_bytes(json.dumps({"op": 10, "d": {"heartbeat_interval": 30000}}))
        
        is_sandbox = any([group, member, content])
        lock = await cache_manager.get_lock_for_secret(secret)
        
        async with lock:
            active_connections.setdefault(secret, {})[websocket] = {
                "token": token, "failure_count": 0, "group": group, "member": member,
                "content": content, "is_sandbox": is_sandbox, "last_activity": time.time()
            }
            count = len(active_connections[secret])
            
            if token and secret not in config.no_cache_secrets:
                cache_manager.message_cache.setdefault(secret, {"public": deque(maxlen=config.cache["max_public_messages"]), "tokens": {}})
                cache_manager.message_cache[secret]["tokens"].setdefault(token, deque(maxlen=config.cache["max_token_messages"]))
        
        logging.info(f"WS连接 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | Token:{PrivacyUtils.sanitize_secret(token) if token else '无'} | {'沙盒' if is_sandbox else '正式'} | 连接数:{count}")
        
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
                        cache_manager.message_cache.setdefault(secret, {"public": deque(maxlen=config.cache["max_public_messages"]), "tokens": {}})
                        cache_manager.message_cache[secret]["tokens"].setdefault(conn_token, deque(maxlen=config.cache["max_token_messages"]))
                    
                    logging.info(f"WS断开 | 密钥:{PrivacyUtils.sanitize_secret(secret)} | 剩余:{remaining}")
                    if not active_connections[secret]:
                        del active_connections[secret]
    except Exception as e:
        logging.error(f"WS全局异常: {e}")
        try:
            await websocket.close()
        except:
            pass

@app.websocket("/ws/{secret}")
async def websocket_endpoint(websocket: WebSocket, secret: str, token: str = None,
                             group: str = None, member: str = None, content: str = None):
    await _handle_websocket(websocket, secret, token, group, member, content)

@app.websocket("/api/ws/{appid}")
async def appid_websocket_endpoint(websocket: WebSocket, appid: str, token: str = None,
                                   group: str = None, member: str = None, content: str = None,
                                   signature: str = None, timestamp: str = None, nonce: str = None):
    secret = app_id_manager.get_secret_by_appid(appid)
    if not secret:
        await websocket.accept()
        await websocket.close(code=1008, reason="无效的AppID")
        return
    
    if signature and timestamp and nonce and not app_id_manager.verify_signature(appid, signature, timestamp, nonce):
        await websocket.accept()
        await websocket.close(code=1008, reason="签名验证失败")
        return
    
    await _handle_websocket(websocket, secret, token, group, member, content)

# ==================== 管理 API ====================
@app.get("/api/admin/stats")
async def get_stats(admin: str = Depends(get_current_admin)):
    with stats_manager.stats_lock:
        stats = {
            "ws": dict(stats_manager.stats.get("ws", {})),
            "wh": dict(stats_manager.stats.get("wh", {})),
            "total_messages": stats_manager.stats.get("total_messages", 0),
            "per_secret": {k: dict(v) for k, v in stats_manager.stats.get("per_secret", {}).items()}
        }
    
    webhook_counts = {}
    for t in config.webhook_forward["targets"]:
        webhook_counts[t["secret"]] = webhook_counts.get(t["secret"], 0) + 1
    
    per_secret = {}
    for secret, data in stats.get("per_secret", {}).items():
        if isinstance(data, dict):
            per_secret[secret] = {
                "ws": {"success": data.get("ws", {}).get("success", 0), "failure": data.get("ws", {}).get("failure", 0)},
                "wh": {"success": data.get("wh", {}).get("success", 0), "failure": data.get("wh", {}).get("failure", 0)},
                "webhook_links": webhook_counts.get(secret, 0)
            }
    
    return {
        "total_appids": len(getattr(app_id_manager, 'appids', {})),
        "ws": stats.get("ws", {}), "wh": stats.get("wh", {}),
        "total_messages": stats.get("total_messages", 0),
        "online": {s: len(c) for s, c in active_connections.items()},
        "forward_config": [{"url": t["url"], "secret": t["secret"]} for t in config.webhook_forward["targets"]],
        "webhook_enabled": config.webhook_forward["enabled"],
        "per_secret": per_secret, "webhook_links_count": webhook_counts
    }

@app.get("/api/admin/appids")
async def get_appids(admin: str = Depends(get_current_admin)):
    with stats_manager.stats_lock:
        stats = stats_manager.stats.copy()
    
    result = []
    for info in app_id_manager.get_all_appids():
        secret_stats = stats.get("per_secret", {}).get(info["secret"], {})
        result.append({
            **info,
            "secret_masked": PrivacyUtils.sanitize_secret(info["secret"]),
            "ws": secret_stats.get("ws", {"success": 0, "failure": 0}),
            "wh": secret_stats.get("wh", {"success": 0, "failure": 0})
        })
    return sorted(result, key=lambda x: x["create_time"], reverse=True)

@app.post("/api/admin/appids/create")
async def create_appid_post(request: Request, admin: str = Depends(get_current_admin)):
    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的JSON数据")
    return _create_appid(data.get("appid", ""), data.get("secret", ""), data.get("description", ""))

@app.get("/api/admin/create_appid")
async def create_appid_get(appid: str = Query(...), secret: str = Query(...), 
                           description: str = Query(""), admin: str = Depends(get_current_admin)):
    return _create_appid(appid, secret, description)

def _create_appid(appid: str, secret: str, description: str):
    if not appid or not appid.strip():
        raise HTTPException(status_code=400, detail="AppID不能为空")
    if not secret or len(secret) < 10:
        raise HTTPException(status_code=400, detail="密钥长度必须至少为10个字符")
    
    success, msg = app_id_manager.create_appid(appid.strip(), secret.strip(), description.strip())
    if not success:
        raise HTTPException(status_code=400, detail=f"创建AppID失败: {msg}")
    return {"appid": appid, "secret": secret, "description": description, "create_time": time.time(), "status": msg}

@app.delete("/api/admin/appids/{appid}")
async def delete_appid(appid: str, admin: str = Depends(get_current_admin)):
    if not app_id_manager.delete_appid(appid):
        raise HTTPException(status_code=404, detail="AppID不存在")
    return {"status": "success", "appid": appid}

@app.get("/api/admin/settings")
async def get_settings(admin: str = Depends(get_current_admin)):
    return {
        "log_level": config.log_level,
        "deduplication_ttl": config.deduplication_ttl,
        "raw_content": getattr(config, 'raw_content', {"enabled": False, "path": "logs"}),
        "ssl": config.ssl
    }

@app.post("/api/admin/settings/update")
async def update_settings(data: SystemSettings, admin: str = Depends(get_current_admin), request: Request = None):
    settings = data.dict()
    
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
    
    logging.info(f"管理员更新了系统设置")
    return {"status": "success", "message": "系统设置已更新"}

@app.post("/api/admin/webhook/add")
async def add_webhook(target: WebhookTarget, admin: str = Depends(get_current_admin)):
    if not target.url.startswith(('http://', 'https://')):
        raise HTTPException(status_code=400, detail="URL必须以http://或https://开头")
    
    if any(t["secret"] == target.secret and t["url"] == target.url for t in config.webhook_forward["targets"]):
        raise HTTPException(status_code=400, detail="该转发配置已存在")
    
    config.webhook_forward["targets"].append({"url": target.url, "secret": target.secret})
    try:
        _save_webhook_config()
    except Exception as e:
        config.webhook_forward["targets"] = [t for t in config.webhook_forward["targets"] 
                                              if not (t["secret"] == target.secret and t["url"] == target.url)]
        raise HTTPException(status_code=500, detail=f"保存配置失败: {e}")
    
    logging.info(f"添加Webhook转发: {target.secret[:8]}... -> {target.url}")
    return {"status": "success", "message": "Webhook转发配置已添加"}

@app.post("/api/admin/webhook/remove")
async def remove_webhook(target: WebhookTarget, admin: str = Depends(get_current_admin)):
    original = len(config.webhook_forward["targets"])
    config.webhook_forward["targets"] = [t for t in config.webhook_forward["targets"]
                                          if not (t["secret"] == target.secret and t["url"] == target.url)]
    
    if len(config.webhook_forward["targets"]) == original:
        raise HTTPException(status_code=404, detail="未找到该转发配置")
    
    try:
        _save_webhook_config()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"保存配置失败: {e}")
    
    logging.info(f"删除Webhook转发: {target.secret[:8]}... -> {target.url}")
    return {"status": "success", "message": "Webhook转发配置已删除"}

def _save_webhook_config():
    config_path = os.path.join(current_dir, "config.py")
    with open(config_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    targets = "[\n" + "".join(f'        {{"url": "{t["url"]}", "secret": "{t["secret"]}"}},\n' 
                               for t in config.webhook_forward["targets"]) + "    ]"
    content = re.sub(r'("targets"\s*:\s*\[)[^\]]*(\])', f'"targets": {targets}', content, flags=re.DOTALL)
    
    with open(config_path, 'w', encoding='utf-8') as f:
        f.write(content)

# ==================== 启动入口 ====================
if __name__ == "__main__":
    ssl_cfg = config.ssl
    use_ssl = ssl_cfg.get("ssl_keyfile") and ssl_cfg.get("ssl_certfile")
    
    uvicorn_cfg = uvicorn.Config(app, host="0.0.0.0", port=config.port, log_level="info", log_config=None, access_log=False)
    if use_ssl:
        uvicorn_cfg.ssl_keyfile = ssl_cfg["ssl_keyfile"]
        uvicorn_cfg.ssl_certfile = ssl_cfg["ssl_certfile"]
    
    logging.info(f"{'启用' if use_ssl else '未启用'}SSL，监听端口: {config.port}")
    asyncio.run(uvicorn.Server(uvicorn_cfg).serve())
