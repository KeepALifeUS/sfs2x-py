"""SmartFoxServer 2X session encryption — AES key exchange and password hashing.

Key Exchange Flow:
1. Client connects TCP and completes SFS handshake → gets SessionToken
2. Client POSTs to https://{host}:{httpsPort}/BlueBox/CryptoManager
   with form field SessToken={SessionToken}
3. Server returns base64-encoded 32 bytes:
   - bytes[0:16]  = AES key
   - bytes[16:32] = IV
4. Both sides use this FIXED key+IV for all subsequent encrypted packets.

Encryption: AES-128-CBC with PKCS7 padding, fixed IV per session.
"""

from __future__ import annotations

import base64
import hashlib

import aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

__all__ = ["AESCipher", "KeyExchange", "make_password_hash"]

AES_BLOCK_SIZE = 16


class AESCipher:
    """AES-128-CBC encryption with fixed IV (per SFS2X session).

    Unlike typical implementations, this does NOT prepend the IV to ciphertext.
    Both sides share the same fixed IV from the key exchange.
    """

    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(key) != 16:
            raise ValueError(f"AES key must be 16 bytes, got {len(key)}")
        if len(iv) != 16:
            raise ValueError(f"AES IV must be 16 bytes, got {len(iv)}")
        self.key = key
        self.iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with AES-CBC. Output is raw ciphertext (no IV prefix)."""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(plaintext, AES_BLOCK_SIZE))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt AES-CBC ciphertext. Input is raw ciphertext (no IV prefix)."""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)


class KeyExchange:
    """Manages the AES key exchange via /BlueBox/CryptoManager.

    Usage::

        kx = KeyExchange()
        aes = await kx.fetch_crypto_key("game.example.com", 8443, session_token)
        encrypted = aes.encrypt(payload)
    """

    def __init__(self) -> None:
        self.aes: AESCipher | None = None

    async def fetch_crypto_key(self, host: str, port: int,
                               session_token: str,
                               use_https: bool = True) -> AESCipher:
        """Fetch AES key+IV from the CryptoManager endpoint."""
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{host}:{port}/BlueBox/CryptoManager"

        form_data = aiohttp.FormData()
        form_data.add_field("SessToken", session_token)

        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=form_data) as resp:
                if resp.status != 200:
                    raise ConnectionError(
                        f"CryptoManager returned HTTP {resp.status}"
                    )
                raw_text = await resp.text()

        data = base64.b64decode(raw_text)
        if len(data) != 32:
            raise ValueError(
                f"Expected 32 bytes from CryptoManager, got {len(data)}"
            )

        key = data[0:16]
        iv = data[16:32]
        self.aes = AESCipher(key, iv)
        return self.aes

    def set_from_bytes(self, data: bytes) -> AESCipher:
        """Set crypto key from raw 32 bytes (key + iv)."""
        if len(data) != 32:
            raise ValueError(f"Expected 32 bytes, got {len(data)}")
        self.aes = AESCipher(data[0:16], data[16:32])
        return self.aes

    def get_encrypt_fn(self):
        """Get encryption function, or None if key exchange hasn't happened."""
        if self.aes is None:
            return None
        return self.aes.encrypt

    def get_decrypt_fn(self):
        """Get decryption function, or None if key exchange hasn't happened."""
        if self.aes is None:
            return None
        return self.aes.decrypt


def make_password_hash(session_token: str, password: str) -> str:
    """Hash password for SFS2X login: MD5(session_token + password)."""
    raw = session_token + password
    return hashlib.md5(raw.encode("utf-8")).hexdigest()
