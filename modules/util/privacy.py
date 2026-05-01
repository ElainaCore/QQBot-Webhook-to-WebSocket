# -*- coding: utf-8 -*-
"""隐私脱敏工具 — 预编译正则，零分配快速路径"""
import re
from urllib.parse import urlparse

_RE_SECRET = re.compile(r'(secret=)([^&]{0,2})([^&]*)')
_RE_SENSITIVE = re.compile(r'((?:token|key|password)=)[^&]*')
_LOG_PATTERNS = (
    (re.compile(r'sk-[a-zA-Z0-9]{30,}'), 'sk-***********'),
    (re.compile(r'Bearer\s+[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'), 'Bearer ********'),
)


class PrivacyUtils:

    @staticmethod
    def sanitize_ip(ip):
        if not ip or ip == "unknown":
            return "unknown"
        if '.' in ip:
            p = ip.split('.')
            if len(p) == 4:
                return f"{p[0]}.{p[1]}.*.{p[3]}"
        if ':' in ip:
            p = ip.split(':')
            if len(p) >= 3:
                return f"{p[0]}:{p[1]}:..:{p[-1]}"
        return ip

    @staticmethod
    def sanitize_path(path):
        if not path:
            return path
        path = _RE_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}***", path)
        return _RE_SENSITIVE.sub(r'\1***', path)

    @staticmethod
    def sanitize_url(url):
        if not url:
            return "unknown"
        try:
            p = urlparse(url)
            r = f"{p.scheme}://{p.netloc}{PrivacyUtils.sanitize_path(p.path)}"
            if p.query:
                r += f"?{PrivacyUtils.sanitize_path(p.query)}"
            return r
        except:
            return "invalid_url"

    @staticmethod
    def sanitize_secret(secret: str) -> str:
        return f"{secret[:2]}***" if secret and len(secret) > 2 else "******"

    @staticmethod
    def sanitize_logs(msg: str) -> str:
        for pat, repl in _LOG_PATTERNS:
            msg = pat.sub(repl, msg)
        return msg
