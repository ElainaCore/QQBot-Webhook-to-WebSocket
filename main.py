# -*- coding: utf-8 -*-
"""Webhook → WebSocket Bridge — 启动入口"""
import logging
import os
import ssl
import sys

# 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from aiohttp import web

from modules.core.config import config
from modules.core.app import create_app

app = create_app()

if __name__ == "__main__":
    try:
        import uvloop
        uvloop.install()
    except ImportError:
        pass
    ssl_cfg = config.ssl
    use_ssl = ssl_cfg.get("ssl_keyfile") and ssl_cfg.get("ssl_certfile")
    ssl_context = None
    if use_ssl:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(ssl_cfg["ssl_certfile"], ssl_cfg["ssl_keyfile"])
    logging.info(f"{'启用' if use_ssl else '未启用'}SSL，监听端口: {config.port}")
    web.run_app(app, host="0.0.0.0", port=config.port,
                ssl_context=ssl_context, access_log=None, print=None)
