"""Tests for AES session encryption and password hashing."""

import base64
import os
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from sfs2x.crypto import AESCipher, KeyExchange, make_password_hash


class TestAESCipher:
    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(16)
        iv = os.urandom(16)
        cipher = AESCipher(key, iv)
        plaintext = b"Hello, SmartFoxServer 2X!"
        encrypted = cipher.encrypt(plaintext)
        assert encrypted != plaintext
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_empty_plaintext(self):
        key = os.urandom(16)
        iv = os.urandom(16)
        cipher = AESCipher(key, iv)
        # Empty plaintext gets PKCS7 padded to one full block
        encrypted = cipher.encrypt(b"")
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == b""

    def test_block_aligned(self):
        key = os.urandom(16)
        iv = os.urandom(16)
        cipher = AESCipher(key, iv)
        # Exactly 16 bytes — PKCS7 adds a full padding block
        plaintext = b"0123456789abcdef"
        encrypted = cipher.encrypt(plaintext)
        assert len(encrypted) == 32  # 16 data + 16 padding
        assert cipher.decrypt(encrypted) == plaintext

    def test_large_payload(self):
        key = os.urandom(16)
        iv = os.urandom(16)
        cipher = AESCipher(key, iv)
        plaintext = os.urandom(10000)
        assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext

    def test_invalid_key_length(self):
        with pytest.raises(ValueError, match="16 bytes"):
            AESCipher(b"short", os.urandom(16))

    def test_invalid_iv_length(self):
        with pytest.raises(ValueError, match="16 bytes"):
            AESCipher(os.urandom(16), b"short")

    def test_different_keys_produce_different_output(self):
        iv = os.urandom(16)
        c1 = AESCipher(os.urandom(16), iv)
        c2 = AESCipher(os.urandom(16), iv)
        plaintext = b"test data"
        assert c1.encrypt(plaintext) != c2.encrypt(plaintext)


class TestKeyExchange:
    def test_set_from_bytes(self):
        raw = os.urandom(32)
        kx = KeyExchange()
        aes = kx.set_from_bytes(raw)
        assert aes.key == raw[:16]
        assert aes.iv == raw[16:]
        assert kx.aes is aes

    def test_set_from_bytes_invalid(self):
        kx = KeyExchange()
        with pytest.raises(ValueError, match="32 bytes"):
            kx.set_from_bytes(b"too short")

    def test_encrypt_decrypt_via_exchange(self):
        raw = os.urandom(32)
        kx = KeyExchange()
        aes = kx.set_from_bytes(raw)
        plaintext = b"session data"
        assert aes.decrypt(aes.encrypt(plaintext)) == plaintext

    def test_get_encrypt_fn_none(self):
        kx = KeyExchange()
        assert kx.get_encrypt_fn() is None
        assert kx.get_decrypt_fn() is None

    def test_get_encrypt_fn(self):
        kx = KeyExchange()
        kx.set_from_bytes(os.urandom(32))
        enc = kx.get_encrypt_fn()
        dec = kx.get_decrypt_fn()
        assert callable(enc)
        assert callable(dec)
        assert dec(enc(b"test")) == b"test"

    @pytest.mark.asyncio
    async def test_fetch_crypto_key(self):
        """Test fetch_crypto_key with mocked HTTP response."""
        raw_key = os.urandom(32)
        b64_response = base64.b64encode(raw_key).decode()

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=b64_response)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("sfs2x.crypto.aiohttp.ClientSession", return_value=mock_session):
            kx = KeyExchange()
            aes = await kx.fetch_crypto_key("example.com", 8443, "test-token")

        assert aes.key == raw_key[:16]
        assert aes.iv == raw_key[16:]
        assert kx.aes is aes

    @pytest.mark.asyncio
    async def test_fetch_crypto_key_http_error(self):
        """Test fetch_crypto_key raises on non-200 response."""
        mock_resp = AsyncMock()
        mock_resp.status = 500
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("sfs2x.crypto.aiohttp.ClientSession", return_value=mock_session):
            kx = KeyExchange()
            with pytest.raises(ConnectionError, match="HTTP 500"):
                await kx.fetch_crypto_key("example.com", 8443, "test-token")

    @pytest.mark.asyncio
    async def test_fetch_crypto_key_bad_length(self):
        """Test fetch_crypto_key raises on wrong key length."""
        b64_response = base64.b64encode(b"too-short").decode()

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=b64_response)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("sfs2x.crypto.aiohttp.ClientSession", return_value=mock_session):
            kx = KeyExchange()
            with pytest.raises(ValueError, match="32 bytes"):
                await kx.fetch_crypto_key("example.com", 8443, "test-token")


class TestPasswordHash:
    def test_known_value(self):
        # MD5("token123" + "password") = MD5("token123password")
        import hashlib
        expected = hashlib.md5(b"token123password").hexdigest()
        assert make_password_hash("token123", "password") == expected

    def test_empty_password(self):
        import hashlib
        expected = hashlib.md5(b"session").hexdigest()
        assert make_password_hash("session", "") == expected

    def test_unicode_password(self):
        import hashlib
        expected = hashlib.md5("tokenпароль".encode("utf-8")).hexdigest()
        assert make_password_hash("token", "пароль") == expected

    def test_special_characters(self):
        import hashlib
        expected = hashlib.md5("tok<>&\"'!@#$%pass".encode("utf-8")).hexdigest()
        assert make_password_hash("tok<>&\"'!@#$%", "pass") == expected


class TestAESDecryptCorrupted:
    def test_corrupted_ciphertext(self):
        """Decrypting corrupted ciphertext should raise an error."""
        key = os.urandom(16)
        iv = os.urandom(16)
        cipher = AESCipher(key, iv)
        # Encrypt something valid, then corrupt
        encrypted = cipher.encrypt(b"valid data here!")
        corrupted = bytearray(encrypted)
        corrupted[0] ^= 0xFF
        corrupted[-1] ^= 0xFF
        with pytest.raises(Exception):  # ValueError from bad padding
            cipher.decrypt(bytes(corrupted))
