# -*- coding: utf-8 -*-
"""消息缓存管理 — time.time() 浮点过期 + deque.popleft 清理"""
import asyncio
import logging
import threading
import time
from collections import deque

from modules.core.config import config

_ID_CACHE_LIMIT = 10000
_ID_CACHE_TRIM = 5000


class MessageCacheManager:
    __slots__ = ('message_cache', 'cache_locks', '_id_cache', '_clean_thread', '_stop')

    def __init__(self):
        self.message_cache = {}
        self.cache_locks = {}
        self._id_cache: dict[str, float] = {}
        self._clean_thread = None
        self._stop = threading.Event()

    # ---------- 锁 ----------

    async def get_lock_for_secret(self, secret: str) -> asyncio.Lock:
        lock = self.cache_locks.get(secret)
        if lock is None:
            lock = asyncio.Lock()
            self.cache_locks[secret] = lock
        return lock

    # ---------- 清理线程 ----------

    def start_cleaning_thread(self):
        if self._clean_thread and self._clean_thread.is_alive():
            return
        self._stop.clear()
        self._clean_thread = threading.Thread(target=self._clean_loop, daemon=True)
        self._clean_thread.start()
        logging.info("缓存清理线程已启动")

    def stop_cleaning_thread(self):
        if self._clean_thread and self._clean_thread.is_alive():
            self._stop.set()
            self._clean_thread.join(timeout=2)
            logging.info("缓存清理线程已停止")

    def _clean_loop(self):
        while not self._stop.is_set():
            try:
                self._do_clean()
            except Exception as e:
                logging.error(f"缓存清理异常: {e}")
            if self._stop.wait(config.cache["clean_interval"]):
                break

    def _do_clean(self):
        now = time.time()
        ic = self._id_cache
        expired = [k for k, exp in ic.items() if exp <= now]
        if expired:
            for k in expired:
                del ic[k]
        if len(ic) > _ID_CACHE_LIMIT:
            for k, _ in sorted(ic.items(), key=lambda x: x[1])[:len(ic) - _ID_CACHE_TRIM]:
                del ic[k]

        dead_secrets = []
        for secret, cache in self.message_cache.items():
            pub = cache.get("public")
            if pub:
                self._purge_deque(pub, now)
            tokens = cache.get("tokens")
            if tokens:
                dead_tokens = [t for t, q in tokens.items() if not self._purge_deque(q, now)]
                for t in dead_tokens:
                    del tokens[t]
            if (not pub or len(pub) == 0) and not tokens:
                dead_secrets.append(secret)
        for s in dead_secrets:
            del self.message_cache[s]
            self.cache_locks.pop(s, None)

    @staticmethod
    def _purge_deque(q: deque, now: float) -> int:
        while q and q[0][0] <= now:
            q.popleft()
        return len(q)

    # ---------- 消息缓存读写 ----------

    def _ensure_cache(self, secret: str) -> dict:
        c = self.message_cache.get(secret)
        if c is None:
            c = {"public": deque(maxlen=config.cache["max_public_messages"]), "tokens": {}}
            self.message_cache[secret] = c
        return c

    async def add_message(self, secret: str, data: bytes, token: str = None) -> bool:
        lock = await self.get_lock_for_secret(secret)
        async with lock:
            expiry = time.time() + config.cache["message_ttl"]
            c = self._ensure_cache(secret)
            if token is None:
                c["public"].append((expiry, data))
            else:
                tq = c["tokens"]
                if token not in tq:
                    tq[token] = deque(maxlen=config.cache["max_token_messages"])
                tq[token].append((expiry, data))
            return True

    async def get_messages_for_token(self, secret: str, token: str) -> list:
        lock = await self.get_lock_for_secret(secret)
        async with lock:
            c = self.message_cache.get(secret)
            if not c:
                return []
            q = c.get("tokens", {}).get(token)
            if not q:
                return []
            msgs = list(q)
            q.clear()
            return msgs

    async def get_public_messages(self, secret: str) -> list:
        lock = await self.get_lock_for_secret(secret)
        async with lock:
            c = self.message_cache.get(secret)
            if not c or not c.get("public"):
                return []
            msgs = list(c["public"])
            c["public"].clear()
            return msgs

    # ---------- 消息去重 ----------

    def add_message_id(self, message_id: str, ttl: int = None):
        self._id_cache[message_id] = time.time() + (ttl or config.cache["message_ttl"])

    def has_message_id(self, message_id: str) -> bool:
        exp = self._id_cache.get(message_id)
        if exp is None:
            return False
        if exp <= time.time():
            del self._id_cache[message_id]
            return False
        return True

    # ---------- 全量清除 ----------

    def clear_all(self):
        self.cache_locks.clear()
        self.message_cache.clear()
        self._id_cache.clear()


cache_manager = MessageCacheManager()
