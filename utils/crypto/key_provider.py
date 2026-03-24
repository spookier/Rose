#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skin Key Provider
Fetches the skin decryption key from the Rose server and caches it in memory.
"""

import os
import urllib.request
import urllib.error
from typing import Optional

from utils.core.logging import get_logger

log = get_logger()

# Import worker URL from gitignored config, fall back to env var
try:
    from .skin_config import WORKER_URL as _CONFIGURED_URL
except ImportError:
    _CONFIGURED_URL = ""

_WORKER_URL = os.environ.get("ROSE_WORKER_URL", _CONFIGURED_URL)

# Module-level cache — fetched once per process lifetime
_cached_key: Optional[bytes] = None
_fetch_attempted: bool = False


def get_skin_key() -> Optional[bytes]:
    """Fetch the skin decryption key from the Rose server.

    Returns the 32-byte key on success, None on failure.
    The result is cached — only one HTTP request per process.
    """
    global _cached_key, _fetch_attempted

    if _cached_key is not None:
        return _cached_key

    if _fetch_attempted:
        return None

    _fetch_attempted = True

    if not _WORKER_URL:
        log.error("[CRYPTO] No worker URL configured — cannot fetch skin key")
        return None

    url = f"{_WORKER_URL.rstrip('/')}/skin-key"
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Rose")
        with urllib.request.urlopen(req, timeout=10) as resp:
            hex_key = resp.read().decode("utf-8").strip()
            key = bytes.fromhex(hex_key)
            if len(key) != 32:
                log.error(f"[CRYPTO] Invalid key length from server: {len(key)} bytes (expected 32)")
                return None
            _cached_key = key
            log.debug("[CRYPTO] Skin decryption key fetched successfully")
            return _cached_key
    except urllib.error.URLError as e:
        log.error(f"[CRYPTO] Failed to fetch skin key: {e}")
        return None
    except (ValueError, UnicodeDecodeError) as e:
        log.error(f"[CRYPTO] Invalid key format from server: {e}")
        return None
