# -*- coding: utf-8 -*-
"""统计管理器 — 内存计数 + SQLite 持久化 (通过 database 模块 2s 批量写入)"""
import logging
import threading
from collections import defaultdict

from modules.data import database as db


def _ps_factory():
    return {"ws": {"success": 0, "failure": 0}, "wh": {"success": 0, "failure": 0}}


class StatsManager:
    __slots__ = ('stats', 'stats_lock', '_dirty')

    def __init__(self):
        self.stats = {
            "total_messages": 0,
            "ws": {"total_success": 0, "total_failure": 0},
            "wh": {"total_success": 0, "total_failure": 0},
            "per_secret": defaultdict(_ps_factory),
        }
        self.stats_lock = threading.Lock()
        self._dirty = False

    def load_from_db(self):
        try:
            saved = db.load_stats()
            with self.stats_lock:
                self.stats["total_messages"] = saved.get("total_messages", 0)
                self.stats["ws"].update(saved.get("ws", {}))
                self.stats["wh"].update(saved.get("wh", {}))
                for secret, data in saved.get("per_secret", {}).items():
                    self.stats["per_secret"][secret] = data
            ws, wh = self.stats["ws"], self.stats["wh"]
            logging.info(f"已加载统计: 消息{self.stats['total_messages']}, "
                         f"WS {ws['total_success']}/{ws['total_failure']}, "
                         f"WH {wh['total_success']}/{wh['total_failure']}")
        except Exception as e:
            logging.warning(f"加载统计数据失败: {e}")

    def flush_to_db(self):
        if not self._dirty:
            return
        with self.stats_lock:
            snapshot = {
                "total_messages": self.stats["total_messages"],
                "ws": dict(self.stats["ws"]),
                "wh": dict(self.stats["wh"]),
                "per_secret": {
                    k: {"ws": dict(v["ws"]), "wh": dict(v["wh"])}
                    for k, v in self.stats["per_secret"].items()
                },
            }
            self._dirty = False
        db.save_stats_snapshot(snapshot)

    # ---- 向下兼容的旧接口 ----
    def start_write_thread(self):
        self.load_from_db()

    def stop_write_thread(self):
        self.flush_to_db()

    # ---- 计数 ----
    def increment_message_count(self):
        with self.stats_lock:
            self.stats["total_messages"] += 1
            self._dirty = True

    def increment_ws_stats(self, secret: str, success: bool = True):
        with self.stats_lock:
            key = "total_success" if success else "total_failure"
            self.stats["ws"][key] += 1
            self.stats["per_secret"][secret]["ws"]["success" if success else "failure"] += 1
            self._dirty = True

    def increment_wh_stats(self, secret: str, success: bool = True):
        with self.stats_lock:
            key = "total_success" if success else "total_failure"
            self.stats["wh"][key] += 1
            self.stats["per_secret"][secret]["wh"]["success" if success else "failure"] += 1
            self._dirty = True

    def batch_update_ws_stats(self, secret: str, success_count: int, failure_count: int):
        if not success_count and not failure_count:
            return
        with self.stats_lock:
            self.stats["ws"]["total_success"] += success_count
            self.stats["ws"]["total_failure"] += failure_count
            ps = self.stats["per_secret"][secret]["ws"]
            ps["success"] += success_count
            ps["failure"] += failure_count
            self._dirty = True

    def batch_update_wh_stats(self, secret: str, success_count: int, failure_count: int):
        if not success_count and not failure_count:
            return
        with self.stats_lock:
            self.stats["wh"]["total_success"] += success_count
            self.stats["wh"]["total_failure"] += failure_count
            ps = self.stats["per_secret"][secret]["wh"]
            ps["success"] += success_count
            ps["failure"] += failure_count
            self._dirty = True


stats_manager = StatsManager()
