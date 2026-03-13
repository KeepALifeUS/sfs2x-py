# Changelog

## v0.1.1 (2026-03-13)

Quality improvements:

- Added PEP 561 `py.typed` marker for mypy/pyright support
- Added BOOL_ARRAY, FLOAT_ARRAY, DOUBLE_ARRAY encoding support
- Added `TypeAlias` for `SFSPacket`, return type for `iter_s2c_packets()`
- Added CI: Python 3.14, ruff linting, pip cache, PyPI auto-publish on tags
- Added 16 new tests (boundary values, nested arrays, C2S full roundtrip, etc.)
- Fixed `make_extension_request` room_id test assertion
- Added CONTRIBUTING.md

## v0.1.0 (2026-03-12)

Initial release.

- Full SFS2X type system: all 19 data types (NULL through SFS_OBJECT)
- C2S packet encoding with XOR obfuscation and optional zlib compression
- S2C packet decoding with zlib/zstd decompression and big-sized support
- Type-preserving decode (`decode_typed`) for MITM proxies
- AES-128-CBC session encryption with `/BlueBox/CryptoManager` key exchange
- Packet builders: `make_extension_request()`, `make_keepalive()`
- `parse_s2c_command()` and `iter_s2c_packets()` helpers
- MD5 password hashing (`make_password_hash`)
