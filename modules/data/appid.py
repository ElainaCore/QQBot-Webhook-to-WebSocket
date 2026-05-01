# -*- coding: utf-8 -*-
"""AppID 管理器 — 内存缓存 + SQLite 持久化"""
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

from modules.data import database as db


class AppIdManager:
    __slots__ = ('appids', '_lock')

    def __init__(self):
        self.appids: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def load_from_db(self):
        with self._lock:
            rows = db.get_all_appids()
            self.appids = {r['appid']: {
                'secret': r['secret'], 'description': r['description'],
                'create_time': r['create_time'],
            } for r in rows}
            logging.info(f"已加载 {len(self.appids)} 个AppID映射")

    def create_appid(self, appid: str, secret: str,
                     description: str = "") -> Tuple[bool, str]:
        appid, secret = appid.strip(), secret.strip()
        description = description.strip()
        if not appid or not secret or len(secret) < 10:
            return False, "invalid"
        with self._lock:
            ok, msg = db.create_appid(appid, secret, description)
            if ok:
                self.appids[appid] = {
                    'secret': secret, 'description': description,
                    'create_time': self.appids.get(appid, {}).get('create_time', time.time()),
                }
            return ok, msg

    def get_secret_by_appid(self, appid: str) -> Optional[str]:
        info = self.appids.get(appid)
        return info['secret'] if info else None

    def get_all_appids(self) -> List[Dict]:
        with self._lock:
            return [{'appid': aid, **data} for aid, data in self.appids.items()]

    def delete_appid(self, appid: str) -> bool:
        with self._lock:
            if appid not in self.appids:
                return False
            db.delete_appid(appid)
            del self.appids[appid]
            return True

    def verify_signature(self, appid: str, signature: str,
                         timestamp: str, nonce: str) -> bool:
        return db.verify_appid_signature(appid, signature, timestamp, nonce)


app_id_manager = AppIdManager()
