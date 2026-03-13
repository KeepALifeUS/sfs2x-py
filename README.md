# sfs2x-py

[![CI](https://github.com/KeepALifeUS/sfs2x-py/actions/workflows/ci.yml/badge.svg)](https://github.com/KeepALifeUS/sfs2x-py/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sfs2x-py)](https://pypi.org/project/sfs2x-py/)
[![Python](https://img.shields.io/pypi/pyversions/sfs2x-py)](https://pypi.org/project/sfs2x-py/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pure Python implementation of the SmartFoxServer 2X binary protocol.

## Features

- **Full type system**: All 19 SFS2X data types (NULL, BOOL, BYTE, SHORT, INT, LONG, FLOAT, DOUBLE, UTF_STRING, arrays, SFS_ARRAY, SFS_OBJECT)
- **C2S/S2C packet framing**: Encode and decode client-to-server and server-to-client packets
- **XOR obfuscation**: Rotating 4-byte XOR key derived from packet size
- **Compression**: zlib and zstd support for large packets
- **AES session encryption**: Key exchange via `/BlueBox/CryptoManager`
- **Type-preserving decode**: `decode_typed()` wraps values in `TypedValue` to preserve wire types (BYTE vs INT) for MITM proxies
- **Packet builders**: `make_extension_request()`, `make_keepalive()`, `parse_s2c_command()`

## Install

```bash
pip install sfs2x-py
```

Or from source:

```bash
git clone https://github.com/KeepALifeUS/sfs2x-py.git
cd sfs2x-py
pip install -e ".[dev]"
```

## Quick Start

### Encode/decode SFSObject

```python
from sfs2x import SFSCodec, TypedValue, INT

# Encode
obj = {"username": "player1", "level": TypedValue(INT, 42)}
data = SFSCodec.encode(obj)

# Decode
decoded, consumed = SFSCodec.decode(data)
print(decoded)  # {'username': 'player1', 'level': 42}
```

### Build an extension request

```python
from sfs2x import make_extension_request, decode_c2s_packet, TypedValue, INT

# Create a C2S packet
packet = make_extension_request(
    cmd="chat.send",
    params={"msg": "Hello!", "channel": TypedValue(INT, 1)},
    server_id=1234,
)

# Decode it back
obj, _ = decode_c2s_packet(packet)
```

### Decode a captured S2C packet

```python
from sfs2x import decode_s2c_packet, parse_s2c_command

raw = bytes.fromhex("80001f...")  # paste captured hex
obj, _ = decode_s2c_packet(raw)
cmd, params = parse_s2c_command(obj)
print(f"Command: {cmd}, Params: {params}")
```

### Type-preserving decode for MITM

```python
from sfs2x import decode_c2s_packet_typed

obj, _ = decode_c2s_packet_typed(packet)
# Values are TypedValue instances — re-encoding preserves wire types
```

## Protocol Overview

### Wire Format

**S2C (server → client):**
```
[0x80] [size: 2B BE] [SFSObject payload]
```

**C2S (client → server):**
```
[0xC4] [server_id: 2B BE] [size: 2B BE] [XOR-obfuscated payload]
[0xE4] [server_id: 2B BE] [size: 2B BE] [XOR(zlib(payload))]  (compressed)
```

### SFSObject Structure

The payload is always a root SFSObject with:
- `"c"` → controller ID (BYTE: 0=system, 1=extension)
- `"a"` → action ID (SHORT)
- `"p"` → parameters (SFS_OBJECT)

Extension commands (c=1, a=13) nest further:
- `"p"."c"` → command name (UTF_STRING)
- `"p"."r"` → room ID (INT)
- `"p"."p"` → command parameters (SFS_OBJECT)

## API Reference

### `sfs2x.objects`
- `SFSCodec.encode(obj)` → `bytes` — Encode a dict as SFSObject
- `SFSCodec.decode(data)` → `(dict, int)` — Decode SFSObject, return (dict, bytes_consumed)
- `SFSCodec.decode_typed(data)` → `(dict, int)` — Decode preserving wire types as `TypedValue`
- `TypedValue(type_id, value)` — Force a specific wire type

### `sfs2x.protocol`
- `encode_c2s_packet(controller, action, params, server_id, compress)` → `bytes`
- `decode_c2s_packet(data)` → `(dict, int)`
- `decode_c2s_packet_typed(data)` → `(dict, int)`
- `encode_s2c_packet(obj, compress)` → `bytes`
- `decode_s2c_packet(data)` → `(dict, int)`
- `make_extension_request(cmd, params, room_id, server_id)` → `bytes`
- `make_keepalive(client_time, server_id)` → `bytes`
- `parse_s2c_command(obj)` → `(str | None, dict)`
- `iter_s2c_packets(data)` → iterator of `(dict, offset)`

### `sfs2x.crypto`
- `AESCipher(key, iv)` — AES-128-CBC with fixed IV
- `KeyExchange()` — Manages key exchange via CryptoManager endpoint
- `make_password_hash(session_token, password)` → `str` — MD5 password hash

## License

MIT
