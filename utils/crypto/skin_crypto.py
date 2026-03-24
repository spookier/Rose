#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skin File Encryption/Decryption

Uses HMAC-SHA256 in counter mode as a stream cipher.
The key is fetched from the Rose server at runtime — never stored locally.

File format (.rse):
  - Magic: b'RSE\\x01' (4 bytes)
  - Nonce: 16 bytes (random, unique per file)
  - Encrypted data: XOR with HMAC-SHA256 keystream
"""

import os
import hmac
import hashlib
import struct
from pathlib import Path
from typing import Optional

from utils.core.logging import get_logger

log = get_logger()

MAGIC = b'RSE\x01'
NONCE_SIZE = 16
HMAC_BLOCK = 32  # SHA-256 output size


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a keystream using HMAC-SHA256 in counter mode"""
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block_input = nonce + struct.pack('<Q', counter)
        block = hmac.new(key, block_input, hashlib.sha256).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def encrypt_file(src: Path, dst: Path, key: bytes) -> bool:
    """Encrypt a skin file (.zip/.fantome) to .rse format

    Args:
        src: Source file path (.zip or .fantome)
        dst: Destination file path (.rse)
        key: Encryption key (32 bytes)

    Returns:
        True if successful
    """
    try:
        plaintext = src.read_bytes()
        nonce = os.urandom(NONCE_SIZE)
        ks = _keystream(key, nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, ks))

        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(MAGIC + nonce + ciphertext)
        return True
    except Exception as e:
        log.error(f"Failed to encrypt {src}: {e}")
        return False


def decrypt_file(src: Path, dst: Path, key: bytes) -> bool:
    """Decrypt a .rse file back to its original format

    Args:
        src: Source file path (.rse)
        dst: Destination file path (.zip or .fantome)
        key: Decryption key (32 bytes)

    Returns:
        True if successful
    """
    try:
        data = src.read_bytes()
        if data[:4] != MAGIC:
            log.error(f"Invalid .rse file (bad magic): {src}")
            return False

        nonce = data[4:4 + NONCE_SIZE]
        ciphertext = data[4 + NONCE_SIZE:]
        ks = _keystream(key, nonce, len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, ks))

        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(plaintext)
        return True
    except Exception as e:
        log.error(f"Failed to decrypt {src}: {e}")
        return False


def decrypt_bytes(data: bytes, key: bytes) -> Optional[bytes]:
    """Decrypt .rse data in memory

    Args:
        data: Raw .rse file contents
        key: Decryption key (32 bytes)

    Returns:
        Decrypted bytes, or None on failure
    """
    if len(data) < 4 + NONCE_SIZE:
        return None
    if data[:4] != MAGIC:
        return None

    nonce = data[4:4 + NONCE_SIZE]
    ciphertext = data[4 + NONCE_SIZE:]
    ks = _keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, ks))
