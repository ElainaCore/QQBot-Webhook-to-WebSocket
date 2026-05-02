# -*- coding: utf-8 -*-
"""Webhook → WebSocket Bridge — 启动入口"""
import asyncio
import logging
import os
import sys

# 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from modules.core.config import config
from modules.core.app import create_app

app = create_app()

if __name__ == "__main__":
    import uvicorn
    logging.getLogger("uvicorn.error").setLevel(logging.ERROR)
    ssl_cfg = config.ssl
    use_ssl = ssl_cfg.get("ssl_keyfile") and ssl_cfg.get("ssl_certfile")
    uvicorn_cfg = uvicorn.Config(app, host="0.0.0.0", port=config.port,
                                 log_level="info", log_config=None, access_log=False)
    if use_ssl:
        uvicorn_cfg.ssl_keyfile = ssl_cfg["ssl_keyfile"]
        uvicorn_cfg.ssl_certfile = ssl_cfg["ssl_certfile"]
    logging.info(f"{'启用' if use_ssl else '未启用'}SSL，监听端口: {config.port}")
    asyncio.run(uvicorn.Server(uvicorn_cfg).serve())
