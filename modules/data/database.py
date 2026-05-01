# -*- coding: utf-8 -*-
"""SQLite 数据库模块 — WAL 模式 + 2秒批量写入 + DRY 迁移"""
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

DB_PATH = os.path.join('data', 'bridge.db')

_db_lock = threading.RLock()
_write_buffer: list = []
_buffer_lock = threading.Lock()
_flush_thread: Optional[threading.Thread] = None
_stop_flag = threading.Event()


# ==================== 初始化 ====================

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS appids (
                appid      TEXT PRIMARY KEY,
                secret     TEXT NOT NULL,
                description TEXT DEFAULT '',
                create_time REAL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS stats_global (
                key   TEXT PRIMARY KEY,
                value INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS stats_per_secret (
                secret      TEXT PRIMARY KEY,
                ws_success  INTEGER DEFAULT 0,
                ws_failure  INTEGER DEFAULT 0,
                wh_success  INTEGER DEFAULT 0,
                wh_failure  INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                created    TEXT,
                expires    TEXT,
                ip         TEXT DEFAULT '',
                user_agent TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS ip_access (
                ip                 TEXT PRIMARY KEY,
                last_access        TEXT,
                password_fail_times TEXT DEFAULT '[]',
                is_banned          INTEGER DEFAULT 0,
                ban_time           TEXT DEFAULT ''
            );
        """)
        for key in ('total_messages', 'ws_success', 'ws_failure', 'wh_success', 'wh_failure'):
            conn.execute("INSERT OR IGNORE INTO stats_global(key, value) VALUES(?, 0)", (key,))
        conn.commit()
        conn.close()
    logging.info("SQLite 数据库已初始化")


# ==================== 迁移 (JSON → SQLite) ====================

def _try_migrate(path: str, label: str, importer):
    if not os.path.isfile(path):
        return False
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        with _db_lock:
            conn = _get_conn()
            importer(conn, data)
            conn.commit()
            conn.close()
        os.rename(path, path + '.migrated')
        return True
    except Exception as e:
        logging.error(f"迁移 {label} 失败: {e}")
        return False


def migrate_from_json():
    migrated = []

    if _try_migrate('data/appids.json', 'appids', lambda c, d: [
        c.execute("INSERT OR REPLACE INTO appids VALUES(?,?,?,?)",
                  (aid, info.get('secret', ''), info.get('description', ''), info.get('create_time', 0)))
        for aid, info in d.items()]):
        migrated.append('appids')

    def _import_stats(conn, data):
        conn.execute("UPDATE stats_global SET value=? WHERE key='total_messages'",
                     (data.get('total_messages', 0),))
        for cat in ('ws', 'wh'):
            d = data.get(cat, {})
            conn.execute(f"UPDATE stats_global SET value=? WHERE key='{cat}_success'",
                         (d.get('total_success', 0),))
            conn.execute(f"UPDATE stats_global SET value=? WHERE key='{cat}_failure'",
                         (d.get('total_failure', 0),))
        for secret, sd in data.get('per_secret', {}).items():
            ws_s, wh_s = sd.get('ws', {}), sd.get('wh', {})
            conn.execute("INSERT OR REPLACE INTO stats_per_secret VALUES(?,?,?,?,?)",
                         (secret, ws_s.get('success', 0), ws_s.get('failure', 0),
                          wh_s.get('success', 0), wh_s.get('failure', 0)))

    if _try_migrate('data/stats.json', 'stats', _import_stats):
        migrated.append('stats')

    if _try_migrate('data/sessions.json', 'sessions', lambda c, d: [
        c.execute("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?,?)",
                  (tok, info.get('created', ''), info.get('expires', ''),
                   info.get('ip', ''), info.get('user_agent', '')))
        for tok, info in d.items()]):
        migrated.append('sessions')

    if _try_migrate('data/ip_access.json', 'ip_access', lambda c, d: [
        c.execute("INSERT OR REPLACE INTO ip_access VALUES(?,?,?,?,?)",
                  (ip, info.get('last_access', ''),
                   json.dumps(info.get('password_fail_times', [])),
                   1 if info.get('is_banned') else 0,
                   info.get('ban_time', '') or ''))
        for ip, info in d.items()]):
        migrated.append('ip_access')

    if migrated:
        logging.info(f"JSON → SQLite 迁移完成: {', '.join(migrated)}")


# ==================== 连接管理 ====================

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# ==================== 批量写入 ====================

def buffer_write(sql: str, params: tuple = ()):
    with _buffer_lock:
        _write_buffer.append((sql, params))


def _flush_buffer():
    with _buffer_lock:
        if not _write_buffer:
            return
        batch = list(_write_buffer)
        _write_buffer.clear()
    with _db_lock:
        try:
            conn = _get_conn()
            for sql, params in batch:
                conn.execute(sql, params)
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"批量写入失败 ({len(batch)} 条): {e}")


def start_flush_thread():
    global _flush_thread
    if _flush_thread and _flush_thread.is_alive():
        return
    _stop_flag.clear()
    _flush_thread = threading.Thread(target=_flush_loop, daemon=True)
    _flush_thread.start()
    logging.info("数据库批量写入线程已启动 (2s)")


def stop_flush_thread():
    _stop_flag.set()
    if _flush_thread and _flush_thread.is_alive():
        _flush_thread.join(timeout=5)
    _flush_buffer()
    logging.info("数据库批量写入线程已停止")


def _flush_loop():
    while not _stop_flag.wait(2):
        _flush_buffer()


# ==================== AppID CRUD ====================

def get_all_appids() -> List[Dict]:
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute("SELECT * FROM appids ORDER BY create_time DESC").fetchall()
        conn.close()
    return [dict(r) for r in rows]


def get_secret_by_appid(appid: str) -> Optional[str]:
    with _db_lock:
        conn = _get_conn()
        row = conn.execute("SELECT secret FROM appids WHERE appid=?", (appid,)).fetchone()
        conn.close()
    return row['secret'] if row else None


def create_appid(appid: str, secret: str, description: str = '') -> Tuple[bool, str]:
    with _db_lock:
        conn = _get_conn()
        existing = conn.execute("SELECT 1 FROM appids WHERE appid=?", (appid,)).fetchone()
        conn.execute("INSERT OR REPLACE INTO appids VALUES(?,?,?,?)",
                     (appid, secret, description, time.time()))
        conn.commit()
        conn.close()
    return (True, 'updated' if existing else 'success')


def delete_appid(appid: str) -> bool:
    with _db_lock:
        conn = _get_conn()
        cur = conn.execute("DELETE FROM appids WHERE appid=?", (appid,))
        conn.commit()
        conn.close()
    return cur.rowcount > 0


def verify_appid_signature(appid: str, signature: str, timestamp: str, nonce: str) -> bool:
    secret = get_secret_by_appid(appid)
    if not secret:
        return False
    return signature == hashlib.sha1((secret + timestamp + nonce).encode()).hexdigest()


# ==================== 统计 ====================

def load_stats() -> Dict:
    with _db_lock:
        conn = _get_conn()
        g_rows = conn.execute("SELECT key, value FROM stats_global").fetchall()
        p_rows = conn.execute("SELECT * FROM stats_per_secret").fetchall()
        conn.close()
    g = {r['key']: r['value'] for r in g_rows}
    ps = {r['secret']: {
        'ws': {'success': r['ws_success'], 'failure': r['ws_failure']},
        'wh': {'success': r['wh_success'], 'failure': r['wh_failure']},
    } for r in p_rows}
    return {
        'total_messages': g.get('total_messages', 0),
        'ws': {'total_success': g.get('ws_success', 0), 'total_failure': g.get('ws_failure', 0)},
        'wh': {'total_success': g.get('wh_success', 0), 'total_failure': g.get('wh_failure', 0)},
        'per_secret': ps,
    }


def save_stats_snapshot(stats: Dict):
    _bw = buffer_write
    _bw("UPDATE stats_global SET value=? WHERE key='total_messages'", (stats['total_messages'],))
    for cat in ('ws', 'wh'):
        d = stats[cat]
        _bw(f"UPDATE stats_global SET value=? WHERE key='{cat}_success'", (d['total_success'],))
        _bw(f"UPDATE stats_global SET value=? WHERE key='{cat}_failure'", (d['total_failure'],))
    for secret, sd in stats.get('per_secret', {}).items():
        ws, wh = sd.get('ws', {}), sd.get('wh', {})
        _bw("INSERT OR REPLACE INTO stats_per_secret VALUES(?,?,?,?,?)",
            (secret, ws.get('success', 0), ws.get('failure', 0),
             wh.get('success', 0), wh.get('failure', 0)))


# ==================== Session CRUD ====================

def load_sessions() -> Dict:
    now = datetime.now()
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute("SELECT * FROM sessions").fetchall()
        conn.close()
    result = {}
    for r in rows:
        try:
            expires = datetime.fromisoformat(r['expires'])
            if now < expires:
                result[r['token']] = {
                    'created': datetime.fromisoformat(r['created']),
                    'expires': expires,
                    'ip': r['ip'], 'user_agent': r['user_agent'],
                }
        except Exception:
            pass
    return result


def save_session(token: str, info: Dict):
    created = info['created'].isoformat() if isinstance(info['created'], datetime) else info['created']
    expires = info['expires'].isoformat() if isinstance(info['expires'], datetime) else info['expires']
    buffer_write("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?,?)",
                 (token, created, expires, info.get('ip', ''), info.get('user_agent', '')))


def delete_session(token: str):
    buffer_write("DELETE FROM sessions WHERE token=?", (token,))


def cleanup_expired_sessions():
    buffer_write("DELETE FROM sessions WHERE expires < ?", (datetime.now().isoformat(),))


# ==================== IP CRUD ====================

def load_ip_data() -> Dict:
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute("SELECT * FROM ip_access").fetchall()
        conn.close()
    return {r['ip']: {
        'last_access': r['last_access'],
        'password_fail_times': json.loads(r['password_fail_times'] or '[]'),
        'is_banned': bool(r['is_banned']),
        'ban_time': r['ban_time'] or None,
    } for r in rows}


def save_ip(ip: str, info: Dict):
    buffer_write("INSERT OR REPLACE INTO ip_access VALUES(?,?,?,?,?)",
                 (ip, info.get('last_access', ''),
                  json.dumps(info.get('password_fail_times', [])),
                  1 if info.get('is_banned') else 0,
                  info.get('ban_time', '') or ''))
