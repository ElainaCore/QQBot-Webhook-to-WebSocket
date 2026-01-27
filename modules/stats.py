import json
import logging
import os
import threading
import time
from collections import defaultdict

import config


class StatsManager:
    def __init__(self):
        self.stats = {
            "total_messages": 0,
            "ws": {"total_success": 0, "total_failure": 0},
            "wh": {"total_success": 0, "total_failure": 0},
            "per_secret": defaultdict(lambda: {"ws": {"success": 0, "failure": 0}, "wh": {"success": 0, "failure": 0}})
        }
        self.stats_lock = threading.Lock()
        self.write_thread = None
        self.stop_flag = threading.Event()
        
        try:
            self._load_stats()
        except Exception as e:
            logging.warning(f"加载统计数据失败: {e}")
    
    def _load_stats(self):
        stats_file = config.stats["stats_file"]
        if not os.path.exists(stats_file):
            return
        
        with open(stats_file, 'r', encoding='utf-8') as f:
            saved = json.load(f)
        
        self.stats["total_messages"] = saved.get("total_messages", 0)
        if "ws" in saved:
            self.stats["ws"].update(saved["ws"])
        if "wh" in saved:
            self.stats["wh"].update(saved["wh"])
        
        for secret, data in saved.get("per_secret", {}).items():
            if isinstance(data, dict):
                if secret not in self.stats["per_secret"]:
                    self.stats["per_secret"][secret] = {"ws": {"success": 0, "failure": 0}, "wh": {"success": 0, "failure": 0}}
                if "ws" in data:
                    self.stats["per_secret"][secret]["ws"].update(data["ws"])
                if "wh" in data:
                    self.stats["per_secret"][secret]["wh"].update(data["wh"])
        
        logging.info(f"已加载统计: 消息{self.stats['total_messages']}, WS {self.stats['ws']['total_success']}/{self.stats['ws']['total_failure']}, WH {self.stats['wh']['total_success']}/{self.stats['wh']['total_failure']}")
    
    def start_write_thread(self):
        if self.write_thread is None or not self.write_thread.is_alive():
            self.stop_flag.clear()
            self.write_thread = threading.Thread(target=self._write_stats, daemon=True)
            self.write_thread.start()
            logging.info("统计写入线程已启动")
    
    def stop_write_thread(self):
        if self.write_thread and self.write_thread.is_alive():
            self.stop_flag.set()
            self.write_thread.join(timeout=2)
            logging.info("统计写入线程已停止")
    
    def _write_stats(self):
        interval = config.stats["write_interval"]
        stats_file = config.stats["stats_file"]
        
        while not self.stop_flag.is_set():
            try:
                # 读取现有数据
                existing = {}
                if os.path.exists(stats_file):
                    try:
                        with open(stats_file, 'r', encoding='utf-8') as f:
                            existing = json.load(f)
                    except:
                        pass
                
                with self.stats_lock:
                    # 清理超限的per_secret
                    if len(self.stats["per_secret"]) > 1000:
                        activity = {s: sum(d["ws"].values()) + sum(d["wh"].values()) 
                                   for s, d in self.stats["per_secret"].items()}
                        keep = set(s for s, _ in sorted(activity.items(), key=lambda x: x[1], reverse=True)[:500])
                        for s in [s for s in self.stats["per_secret"] if s not in keep]:
                            del self.stats["per_secret"][s]
                        logging.warning(f"清理统计数据：保留500个最活跃的secret")
                    
                    current = {
                        "total_messages": self.stats["total_messages"],
                        "ws": dict(self.stats["ws"]),
                        "wh": dict(self.stats["wh"]),
                        "per_secret": {k: {"ws": dict(v["ws"]), "wh": dict(v["wh"])} for k, v in self.stats["per_secret"].items()}
                    }
                
                # 合并统计
                merged = self._merge_stats(existing, current)
                
                os.makedirs(os.path.dirname(stats_file), exist_ok=True)
                with open(stats_file, 'w', encoding='utf-8') as f:
                    json.dump(merged, f, indent=2, ensure_ascii=False)
                
                # 等待下次写入
                for _ in range(int(interval / 0.5)):
                    if self.stop_flag.is_set():
                        break
                    time.sleep(0.5)
                    
            except Exception as e:
                logging.error(f"写入统计异常: {e}")
                time.sleep(30)
    
    def _merge_stats(self, old: dict, new: dict) -> dict:
        if not old:
            return new
        
        result = {
            "total_messages": max(old.get("total_messages", 0), new["total_messages"]),
            "ws": {
                "total_success": max(old.get("ws", {}).get("total_success", 0), new["ws"]["total_success"]),
                "total_failure": max(old.get("ws", {}).get("total_failure", 0), new["ws"]["total_failure"])
            },
            "wh": {
                "total_success": max(old.get("wh", {}).get("total_success", 0), new["wh"]["total_success"]),
                "total_failure": max(old.get("wh", {}).get("total_failure", 0), new["wh"]["total_failure"])
            },
            "per_secret": {}
        }
        
        all_secrets = set(old.get("per_secret", {}).keys()) | set(new.get("per_secret", {}).keys())
        for secret in all_secrets:
            old_data = old.get("per_secret", {}).get(secret, {})
            new_data = new.get("per_secret", {}).get(secret, {})
            result["per_secret"][secret] = {
                "ws": {
                    "success": max(old_data.get("ws", {}).get("success", 0), new_data.get("ws", {}).get("success", 0)),
                    "failure": max(old_data.get("ws", {}).get("failure", 0), new_data.get("ws", {}).get("failure", 0))
                },
                "wh": {
                    "success": max(old_data.get("wh", {}).get("success", 0), new_data.get("wh", {}).get("success", 0)),
                    "failure": max(old_data.get("wh", {}).get("failure", 0), new_data.get("wh", {}).get("failure", 0))
                }
            }
        
        return result
    
    def increment_message_count(self):
        with self.stats_lock:
            self.stats["total_messages"] += 1
    
    def increment_ws_stats(self, secret: str, success: bool = True):
        with self.stats_lock:
            key = "total_success" if success else "total_failure"
            self.stats["ws"][key] += 1
            self.stats["per_secret"][secret]["ws"]["success" if success else "failure"] += 1
    
    def increment_wh_stats(self, secret: str, success: bool = True):
        with self.stats_lock:
            key = "total_success" if success else "total_failure"
            self.stats["wh"][key] += 1
            self.stats["per_secret"][secret]["wh"]["success" if success else "failure"] += 1
    
    def batch_update_wh_stats(self, secret: str, success_count: int, failure_count: int):
        with self.stats_lock:
            self.stats["wh"]["total_success"] += success_count
            self.stats["wh"]["total_failure"] += failure_count
            self.stats["per_secret"][secret]["wh"]["success"] += success_count
            self.stats["per_secret"][secret]["wh"]["failure"] += failure_count


stats_manager = StatsManager()
