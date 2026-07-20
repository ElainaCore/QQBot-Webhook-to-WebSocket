# -*- coding: utf-8 -*-
"""YAML 配置管理器 — 直接读写 config.yaml，属性访问 + 热加载"""
import os
import logging
import threading
import yaml

_DEFAULTS = {
    "admin": {"password": "", "enabled": True},
    "cache": {
        "default_max_messages": 1000, "message_ttl": 300, "clean_interval": 120,
    },
    "deduplication_ttl": 20, "log_level": "INFO", "log_maxlen": 2000,
    "no_cache_secrets": [], "port": 8000,
    "raw_content": {"enabled": False, "path": "logs"},
    "ssl": {"ssl_keyfile": "", "ssl_certfile": ""},
    "stats": {"write_interval": 5},
    "trust_proxy": False,
    "webhook_forward": {"enabled": False, "timeout": 5, "targets": []},
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = base.copy()
    for k, v in over.items():
        if v is None:
            continue
        bv = out.get(k)
        out[k] = _deep_merge(bv, v) if isinstance(bv, dict) and isinstance(v, dict) else v
    return out


class ConfigManager:
    """YAML 配置单例 — 读取无锁 (volatile snapshot)，写入加锁"""

    def __init__(self, path: str):
        self._file = path
        self._lock = threading.Lock()
        self._snap: dict = dict(_DEFAULTS)

    # ---------- 加载 / 保存 ----------

    def load(self):
        try:
            with open(self._file, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            merged = _deep_merge(_DEFAULTS, raw)
            with self._lock:
                self._snap = merged
            logging.info(f"配置已加载: {self._file}")
        except FileNotFoundError:
            logging.warning(f"配置文件不存在，使用默认值: {self._file}")
            self._snap = dict(_DEFAULTS)
        except Exception as e:
            logging.error(f"加载配置失败: {e}")

    def save(self):
        snap = self._snap
        try:
            with open(self._file, "w", encoding="utf-8") as f:
                yaml.dump(snap, f, default_flow_style=False,
                          allow_unicode=True, sort_keys=False)
            logging.info("配置已保存")
        except Exception as e:
            logging.error(f"保存配置失败: {e}")

    def update_settings(self, kv: dict) -> bool:
        try:
            with self._lock:
                d = dict(self._snap)
                d.update(kv)
                self._snap = d
            self.save()
            return True
        except Exception as e:
            logging.error(f"更新配置失败: {e}")
            return False

    # ---------- 属性访问 (无锁快速路径) ----------

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        snap = object.__getattribute__(self, '_snap')
        try:
            return snap[name]
        except KeyError:
            raise AttributeError(f"config 没有属性 '{name}'")


# ==================== 单例 ====================
_project_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
config = ConfigManager(os.path.join(_project_dir, "config.yaml"))
config.load()
