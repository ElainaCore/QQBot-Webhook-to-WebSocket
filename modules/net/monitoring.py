# -*- coding: utf-8 -*-
"""服务健康监控 — 非阻塞 CPU 检测 + 自动恢复"""
import asyncio
import gc
import logging
import time

import psutil

from modules.core.config import config
from modules.net.connections import active_connections, service_health
from modules.data.cache import cache_manager
from modules.util.privacy import PrivacyUtils


def log_config_changes():
    c = config.cache
    logging.info(f"缓存配置: 默认={c['default_max_messages']}, "
                 f"公共={c['max_public_messages']}, Token={c['max_token_messages']}, "
                 f"TTL={c['message_ttl']}秒, 清理间隔={c['clean_interval']}秒")
    logging.info(f"统计配置: 间隔={config.stats['write_interval']}秒")
    logging.info(f"去重有效期: {config.deduplication_ttl}秒")
    if config.no_cache_secrets:
        sanitized = [PrivacyUtils.sanitize_secret(s) for s in config.no_cache_secrets]
        logging.info(f"不缓存密钥: {', '.join(sanitized)}")
    else:
        logging.info("不缓存密钥: 无")


async def monitor_service_health():
    loop = asyncio.get_event_loop()
    while True:
        try:
            now = time.time()

            if service_health["last_successful_webhook"] > 0:
                idle = now - service_health["last_successful_webhook"]
                if idle > 300:
                    logging.warning(f"Webhook处理异常，{idle:.1f}秒未成功处理")
                    total = sum(len(c) for c in active_connections.values())
                    if total == 0 and service_health["error_count"] > 10:
                        logging.warning("执行自动恢复: 清理缓存和锁")
                        cache_manager.clear_all()
                        service_health["error_count"] = 0

            cpu = await loop.run_in_executor(None, psutil.cpu_percent, 0.5)
            if cpu > 90:
                logging.warning(f"高CPU负载: {cpu}%")
                service_health["high_load_detected"] = True
            else:
                service_health["high_load_detected"] = False

            mem = psutil.Process().memory_percent()
            if mem > 85:
                logging.warning(f"高内存使用: {mem:.1f}%，执行垃圾回收")
                gc.collect()

            await asyncio.sleep(30)
        except Exception as e:
            logging.error(f"健康监控异常: {e}")
            await asyncio.sleep(60)
