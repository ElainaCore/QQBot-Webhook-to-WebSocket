# -*- coding: utf-8 -*-
"""日志配置 + Ed25519 签名工具"""
import logging
from aiohttp.http_exceptions import BadHttpMessage
from cryptography.hazmat.primitives.asymmetric import ed25519
from modules.core.config import config

_FILTER_STRINGS = frozenset({
    '{"op":1,"d":1}', "{'op': 1, 'd': 1}", "收到原始消息:", "b'{",
    "添加消息ID到缓存", "统计信息已写入文件:", "Webhook转发跳过", "转发消息内容:",
    "INFO::转发消息内容:", "收到WS消息:", "INFO::收到WS消息:",
    "解析WS消息:", "INFO::解析WS消息:", "connection rejected (403 Forbidden)",
})


def setup_logger():
    level = getattr(logging, config.log_level, logging.INFO)

    class _F(logging.Filter):
        def filter(self, rec):
            if rec.name == 'root':
                rec.name = ''
            msg = rec.getMessage()
            if any(s in msg for s in _FILTER_STRINGS):
                return False
            if "Webhook转发全部失败" in msg and "失败数：0/0" in msg:
                return False
            if "connection closed" in msg and rec.levelname == "INFO":
                return False
            if "WebSocket" in msg and "403" in msg:
                return False
            return True

    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', handlers=[logging.StreamHandler()])
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('aiohttp.access').setLevel(logging.WARNING)

    class _BadRequestFilter(logging.Filter):
        """屏蔽畸形请求噪音 (如对 HTTP 端口发 TLS 握手、端口扫描)"""
        def filter(self, rec):
            if rec.exc_info and isinstance(rec.exc_info[1], BadHttpMessage):
                return False
            return True

    logging.getLogger('aiohttp.server').addFilter(_BadRequestFilter())
    root = logging.getLogger()
    root.setLevel(level)
    f = _F()
    for h in root.handlers:
        h.addFilter(f)
    return root


def generate_signature(bot_secret, event_ts, plain_token):
    while len(bot_secret) < 32:
        bot_secret = (bot_secret + bot_secret)[:32]
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bot_secret.encode())
    sig = key.sign(f"{event_ts}{plain_token}".encode()).hex()
    return {"plain_token": plain_token, "signature": sig}
