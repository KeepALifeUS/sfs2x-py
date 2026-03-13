# sfs2x-py

[![CI](https://github.com/KeepALifeUS/sfs2x-py/actions/workflows/ci.yml/badge.svg)](https://github.com/KeepALifeUS/sfs2x-py/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sfs2x-py.svg)](https://pypi.org/project/sfs2x-py/)
[![Python](https://img.shields.io/pypi/pyversions/sfs2x-py.svg)](https://pypi.org/project/sfs2x-py/)
[![Downloads](https://img.shields.io/pypi/dm/sfs2x-py.svg)](https://pypi.org/project/sfs2x-py/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Pure Python implementation of the SmartFoxServer 2X binary protocol.**

Encode, decode, and manipulate SFS2X packets with full type fidelity — built for protocol analysis, MITM proxying, and game bot development.

## What is SmartFoxServer 2X?

[SmartFoxServer 2X](https://www.smartfoxserver.com/) (SFS2X) is a real-time multiplayer game server used by hundreds of mobile and web games. It communicates over TCP using a proprietary binary protocol featuring:

- A rich type system with 19 data types (SFSObject / SFSArray)
- XOR obfuscation on client-to-server packets
- Optional zlib/zstd compression
- AES-128-CBC session encryption

**sfs2x-py** is the first open-source Python library to fully implement this wire protocol. No official SDK or documentation for the binary format exists publicly — this was built entirely through reverse engineering.

## Features

| Feature | Description |
|---------|-------------|
| **Full type system** | All 19 SFS2X data types: NULL, BOOL, BYTE, SHORT, INT, LONG, FLOAT, DOUBLE, UTF_STRING, typed arrays, SFS_ARRAY, SFS_OBJECT |
| **Packet framing** | Encode and decode both C2S (client-to-server) and S2C (server-to-client) packets |
| **XOR obfuscation** | Rotating 4-byte key derived from packet size — automatic on encode/decode |
| **Compression** | zlib and zstd decompression for S2C; zlib compression for C2S |
| **AES encryption** | Session key exchange via `/BlueBox/CryptoManager` endpoint |
| **Type-preserving decode** | `decode_typed()` preserves wire types (BYTE vs INT vs LONG) — critical for MITM proxies that re-encode packets |
| **Packet builders** | High-level helpers: `make_extension_request()`, `make_keepalive()`, `parse_s2c_command()` |
| **Zero config** | No external dependencies beyond `pycryptodome`, `aiohttp`, `zstandard` |

## Installation

```bash
pip install sfs2x-py
```

From source:

```bash
git clone https://github.com/KeepALifeUS/sfs2x-py.git
cd sfs2x-py
pip install -e ".[dev]"
```

Requires Python 3.10+. Tested on 3.10 through 3.14.

## Quick Start

### Encode and decode an SFSObject

```python
from sfs2x import SFSCodec, TypedValue, INT, LONG

# Encode a dict to binary SFSObject
obj = {
    "username": "player1",
    "level": TypedValue(INT, 42),
    "score": TypedValue(LONG, 1_000_000),
}
data = SFSCodec.encode(obj)

# Decode it back
decoded, bytes_consumed = SFSCodec.decode(data)
print(decoded)
# {'username': 'player1', 'level': 42, 'score': 1000000}
```

### Build and send an extension request

```python
from sfs2x import make_extension_request, TypedValue, INT

# Build a ready-to-send C2S packet (with XOR obfuscation applied)
packet = make_extension_request(
    cmd="chat.send",
    params={"msg": "Hello!", "channel": TypedValue(INT, 1)},
    server_id=1234,
)

# Send over TCP
sock.sendall(packet)
```

### Decode captured S2C traffic

```python
from sfs2x import decode_s2c_packet, parse_s2c_command, iter_s2c_packets

# Single packet
raw = bytes.fromhex("80001f...")
obj, consumed = decode_s2c_packet(raw)
cmd, params = parse_s2c_command(obj)
print(f"{cmd}: {params}")

# Stream of packets (skips noise bytes between packets)
for obj, offset in iter_s2c_packets(tcp_stream):
    cmd, params = parse_s2c_command(obj)
    print(f"[{offset:#x}] {cmd}: {params}")
```

### Type-preserving decode for MITM proxies

When proxying traffic, you need to re-encode packets without altering wire types. A server may treat `BYTE(5)` and `INT(5)` differently even though both represent the number 5.

```python
from sfs2x import decode_c2s_packet_typed, encode_c2s_packet

# Decode preserving exact wire types
obj, consumed = decode_c2s_packet_typed(raw_packet)
# obj["p"]["level"] is TypedValue(INT, 5), not just 5

# Modify a field
obj["p"]["p"]["gold"] = TypedValue(INT, 9999)

# Re-encode — all other fields keep their original wire types
modified_packet = encode_c2s_packet(
    obj["c"].value, obj["a"].value, obj["p"],
    server_id=1234,
)
```

### AES session encryption

```python
from sfs2x import KeyExchange

kx = KeyExchange()

# Option 1: Fetch key from CryptoManager endpoint
aes = await kx.fetch_crypto_key("game.example.com", 8443, session_token)

# Option 2: Set key from raw bytes (if you captured the key exchange)
aes = kx.set_from_bytes(raw_32_bytes)  # first 16 = key, last 16 = IV

# Encrypt/decrypt packet payloads
encrypted = aes.encrypt(payload)
decrypted = aes.decrypt(encrypted)
```

## Wire Protocol Reference

### Packet Framing

**S2C (server to client):**
```
[0x80] [size: 2B BE] [SFSObject payload]
[0x88] [size: 4B BE] [SFSObject payload]         (big-sized, >64KB)
[0xA0] [size: 2B BE] [zlib/zstd compressed]       (compressed)
[0xB0] [dec_size: 4B] [zstd frame]                (zstd with size prefix)
```

**C2S (client to server):**
```
[0xC4] [server_id: 2B BE] [size: 2B BE] [XOR-obfuscated SFSObject]
[0xE4] [server_id: 2B BE] [size: 2B BE] [XOR(zlib(SFSObject))]
```

**XOR key derivation:**
```
key = [size & 0xFF, (size >> 8) & 0xFF, 0x00, 0x00]
```
Applied as a rotating 4-byte mask. Positions 2 and 3 are no-ops (key byte is 0).

### SFSObject Envelope

Every packet payload is a root SFSObject:

```
"c" -> controller (BYTE: 0 = system, 1 = extension)
"a" -> action     (SHORT: 0 = handshake, 1 = login, 13 = extension, 29 = keepalive)
"p" -> parameters (SFS_OBJECT)
```

Extension commands (c=1, a=13) have nested parameters:

```
"p"."c" -> command name  (UTF_STRING, e.g. "chat.send")
"p"."r" -> room ID       (INT, usually -1)
"p"."p" -> command params (SFS_OBJECT)
```

### SFS2X Type System

| ID | Type | Python | Wire Size |
|----|------|--------|-----------|
| 0 | NULL | `None` | 0 |
| 1 | BOOL | `bool` | 1 byte |
| 2 | BYTE | `int` | 1 byte (unsigned) |
| 3 | SHORT | `int` | 2 bytes (signed) |
| 4 | INT | `int` | 4 bytes (signed) |
| 5 | LONG | `int` | 8 bytes (signed) |
| 6 | FLOAT | `float` | 4 bytes |
| 7 | DOUBLE | `float` | 8 bytes |
| 8 | UTF_STRING | `str` | 2B length + UTF-8 |
| 9 | BOOL_ARRAY | `list[bool]` | 2B count + data |
| 10 | BYTE_ARRAY | `bytes` | 4B count + data |
| 11-16 | Typed arrays | `list` | 2B count + data |
| 17 | SFS_ARRAY | `list` | 2B count + typed elements |
| 18 | SFS_OBJECT | `dict` | 2B count + key-value pairs |

Auto-sizing: plain Python `int` values are automatically encoded as the smallest type that fits (BYTE -> SHORT -> INT -> LONG). Use `TypedValue` to force a specific wire type.

## API Reference

### `sfs2x.objects`

| Function | Returns | Description |
|----------|---------|-------------|
| `SFSCodec.encode(obj)` | `bytes` | Encode dict as SFSObject binary |
| `SFSCodec.decode(data)` | `(dict, int)` | Decode SFSObject, returns (dict, bytes_consumed) |
| `SFSCodec.decode_typed(data)` | `(dict, int)` | Decode preserving wire types as `TypedValue` |
| `TypedValue(type_id, value)` | — | Force a specific wire type on encode |

### `sfs2x.protocol`

| Function | Returns | Description |
|----------|---------|-------------|
| `encode_c2s_packet(ctrl, action, params, server_id, compress)` | `bytes` | Build a C2S packet with XOR obfuscation |
| `decode_c2s_packet(data)` | `(dict, int)` | Decode C2S packet |
| `decode_c2s_packet_typed(data)` | `(dict, int)` | Decode C2S preserving wire types |
| `encode_s2c_packet(obj, compress)` | `bytes` | Build an S2C packet |
| `decode_s2c_packet(data)` | `(dict, int)` | Decode S2C packet (handles compression) |
| `make_extension_request(cmd, params, room_id, server_id)` | `bytes` | Build extension request packet |
| `make_keepalive(client_time, server_id)` | `bytes` | Build keepalive packet |
| `parse_s2c_command(obj)` | `(str\|None, dict)` | Extract command name and params from S2C |
| `iter_s2c_packets(data)` | `Iterator` | Iterate packets in a byte stream |

### `sfs2x.crypto`

| Function | Returns | Description |
|----------|---------|-------------|
| `AESCipher(key, iv)` | — | AES-128-CBC with fixed IV per session |
| `KeyExchange()` | — | Manages key exchange via CryptoManager |
| `await kx.fetch_crypto_key(host, port, token)` | `AESCipher` | Fetch key from server |
| `kx.set_from_bytes(data)` | `AESCipher` | Set key from raw 32 bytes |
| `make_password_hash(token, password)` | `str` | MD5 login hash |

## Use Cases

- **Protocol analysis** — Decode captured traffic from tcpdump/Wireshark to understand game communication
- **MITM proxy** — Intercept, inspect, and modify packets in real time (see `examples/mitm_proxy.py`)
- **Game bots** — Build headless clients that communicate directly with SFS2X servers
- **Security research** — Audit game server implementations for vulnerabilities
- **Modding tools** — Build custom tools that interact with SFS2X-based games

## Examples

The `examples/` directory includes:

- **`decode_packet.py`** — Demonstrates encoding and decoding sample packets
- **`mitm_proxy.py`** — Transparent TCP proxy that logs all SFS2X commands bidirectionally

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and guidelines.

## License

[MIT](LICENSE) — use it for anything.
