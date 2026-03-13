"""SmartFoxServer 2X binary protocol — packet framing, XOR obfuscation, compression.

S2C (server → client) — PLAINTEXT:
    [0x80] [size: 2B BE] [SFSObject payload]

C2S (client → server) — XOR OBFUSCATED:
    [0xC4] [server_id: 2B BE] [size: 2B BE] [XOR payload]     (uncompressed)
    [0xE4] [server_id: 2B BE] [size: 2B BE] [XOR(zlib payload)]  (compressed)

    XOR key is 4-byte rotating: [size & 0xFF, (size >> 8) & 0xFF, 0, 0]
    Applied to every byte; positions 2,3 mod 4 are no-ops (key=0).

Payload root SFSObject:
    "c" -> controller id (BYTE: 0=system, 1=extension)
    "a" -> action id (SHORT)
    "p" -> parameters (SFS_OBJECT)

Extension commands (c=1, a=13):
    "p"."c" -> command name (UTF_STRING)
    "p"."r" -> room id (INT, usually -1)
    "p"."p" -> command parameters (SFS_OBJECT)
"""

from __future__ import annotations

import struct
import zlib
from typing import Any

from .objects import SFSCodec, TypedValue, BYTE, SHORT, INT, SFS_OBJECT, SFS_ARRAY

__all__ = [
    "encode_c2s_packet", "decode_c2s_packet", "decode_c2s_packet_typed",
    "encode_s2c_packet", "decode_s2c_packet",
    "make_extension_request", "make_keepalive", "parse_s2c_command",
    "iter_s2c_packets",
    "obfuscate_c2s", "deobfuscate_c2s",
    "FLAG_BINARY", "FLAG_ENCRYPTED", "FLAG_COMPRESSED", "FLAG_BIG_SIZED",
    "C2S_HEADER", "C2S_HEADER_COMPRESSED", "S2C_HEADER",
    "CTRL_SYSTEM", "CTRL_EXTENSION",
    "ACTION_HANDSHAKE", "ACTION_LOGIN", "ACTION_LOGOUT",
    "ACTION_KEEPALIVE", "ACTION_EXTENSION",
]

# Type alias for decoded SFS packets
SFSPacket = dict[str, Any]

# Header flags
FLAG_BINARY = 0x80
FLAG_ENCRYPTED = 0x40
FLAG_COMPRESSED = 0x20
FLAG_BIG_SIZED = 0x08

# C2S headers
C2S_HEADER = 0xC4             # uncompressed: 0x80 | 0x40 | 0x04
C2S_HEADER_COMPRESSED = 0xE4  # compressed:   0xC4 | 0x20
# S2C header
S2C_HEADER = 0x80

# Controllers
CTRL_SYSTEM = 0
CTRL_EXTENSION = 1

# System actions
ACTION_HANDSHAKE = 0
ACTION_LOGIN = 1
ACTION_LOGOUT = 2
ACTION_KEEPALIVE = 29

# Extension action
ACTION_EXTENSION = 13


def _xor_c2s(data: bytes, size: int) -> bytes:
    """Apply/remove XOR obfuscation using 4-byte rotating key [lo, hi, 0, 0]."""
    lo = size & 0xFF
    hi = (size >> 8) & 0xFF
    key = (lo, hi, 0, 0)
    result = bytearray(data)
    for i in range(len(result)):
        k = key[i & 3]
        if k:
            result[i] ^= k
    return bytes(result)


def obfuscate_c2s(payload: bytes) -> bytes:
    """Obfuscate C2S payload with rotating XOR key derived from payload size."""
    return _xor_c2s(payload, len(payload))


def deobfuscate_c2s(payload: bytes, size: int) -> bytes:
    """De-obfuscate C2S payload with rotating XOR key derived from size field."""
    return _xor_c2s(payload, size)


def encode_c2s_packet(controller: int, action: int,
                      params: dict[str, Any],
                      server_id: int = 0,
                      compress: bool = False) -> bytes:
    """Encode a C2S packet with XOR obfuscation and optional zlib compression.

    Args:
        controller: Controller ID (0=system, 1=extension).
        action: Action ID (e.g. 13 for extension requests).
        params: SFSObject parameters dict.
        server_id: Server ID embedded in the packet header.
        compress: Whether to zlib-compress the payload before obfuscation.

    Returns:
        Raw wire bytes ready to send over TCP.
    """
    envelope = {
        "c": TypedValue.byte(controller),
        "a": TypedValue.short(action),
        "p": params,
    }
    payload = SFSCodec.encode(envelope)

    if compress:
        payload = zlib.compress(payload, 9)
        header = C2S_HEADER_COMPRESSED
    else:
        header = C2S_HEADER

    obfuscated = obfuscate_c2s(payload)

    buf = bytearray()
    buf.append(header)
    buf.extend(struct.pack(">H", server_id))
    buf.extend(struct.pack(">H", len(payload)))
    buf.extend(obfuscated)
    return bytes(buf)


def decode_s2c_packet(data: bytes, offset: int = 0) -> tuple[dict[str, Any], int]:
    """Decode an S2C packet. Returns (decoded_dict, bytes_consumed).

    Handles FLAG_BIG_SIZED (4-byte size), FLAG_COMPRESSED (zlib/zstd),
    and 0x10 flag (4-byte decompressed size prefix).
    """
    header = data[offset]
    if not (header & FLAG_BINARY):
        raise ValueError(f"Expected S2C header with FLAG_BINARY, got 0x{header:02X}")

    big_sized = bool(header & FLAG_BIG_SIZED)
    compressed = bool(header & FLAG_COMPRESSED)

    if big_sized:
        size = struct.unpack_from(">I", data, offset + 1)[0]
        hdr_len = 5
    else:
        size = struct.unpack_from(">H", data, offset + 1)[0]
        hdr_len = 3

    has_dec_prefix = bool(header & 0x10) and compressed
    total = hdr_len + size + (4 if has_dec_prefix else 0)
    if offset + total > len(data):
        raise ValueError(f"Incomplete packet: need {total}, have {len(data) - offset}")

    payload = data[offset + hdr_len:offset + total]

    if compressed:
        payload = _decompress_s2c(payload)

    if payload and payload[0] == SFS_ARRAY:
        arr, _ = SFSCodec._decode_sfs_array(payload, 1)
        return {"_array": arr}, total

    sfs_obj, _ = SFSCodec.decode(payload)
    return sfs_obj, total


def _decompress_s2c(payload: bytes) -> bytes:
    """Decompress S2C payload — supports zlib, raw deflate, and zstd."""
    ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'

    # zstd with 4-byte prefix (expected decompressed size)
    if len(payload) > 8 and payload[4:8] == ZSTD_MAGIC:
        expected_size = struct.unpack_from(">I", payload, 0)[0]
        return _decompress_zstd(payload[4:], max_size=expected_size + 1024)

    # zstd without prefix
    if len(payload) > 4 and payload[:4] == ZSTD_MAGIC:
        return _decompress_zstd(payload)

    # Standard zlib
    try:
        return zlib.decompress(payload)
    except zlib.error:
        pass

    # Raw deflate (no zlib header)
    try:
        return zlib.decompress(payload, -15)
    except zlib.error:
        pass

    # Already raw SFS data
    if payload and payload[0] in (SFS_ARRAY, SFS_OBJECT):
        return payload

    raise ValueError(f"Cannot decompress ({len(payload)} bytes, first: {payload[:8].hex()})")


def _decompress_zstd(data: bytes, max_size: int = 4 * 1024 * 1024) -> bytes:
    """Decompress zstd data with fallback to streaming on error."""
    import zstandard
    dctx = zstandard.ZstdDecompressor()

    try:
        return dctx.decompress(data, max_output_size=max_size)
    except zstandard.ZstdError:
        pass

    dobj = dctx.decompressobj(write_size=max_size)
    chunks = []
    try:
        chunk = dobj.decompress(data)
        while chunk:
            chunks.append(chunk)
            chunk = dobj.decompress(b"")
    except zstandard.ZstdError:
        pass
    result = b''.join(chunks)
    if not result:
        raise ValueError(f"zstd produced no output ({len(data)} bytes)")
    return result


def decode_c2s_packet(data: bytes, offset: int = 0) -> tuple[dict[str, Any], int]:
    """Decode a C2S packet (deobfuscate + optional decompress + decode).

    Handles both 0xC4 (uncompressed) and 0xE4 (zlib compressed) headers.
    Returns (decoded_dict, bytes_consumed).
    """
    header = data[offset]
    if header not in (C2S_HEADER, C2S_HEADER_COMPRESSED):
        raise ValueError(f"Expected C2S header 0xC4/0xE4, got 0x{header:02X}")

    compressed = bool(header & FLAG_COMPRESSED)
    server_id = struct.unpack_from(">H", data, offset + 1)[0]
    size = struct.unpack_from(">H", data, offset + 3)[0]
    total = 5 + size

    if offset + total > len(data):
        raise ValueError(f"Incomplete packet: need {total}, have {len(data) - offset}")

    obfuscated = data[offset + 5:offset + total]
    payload = deobfuscate_c2s(obfuscated, size)

    if compressed:
        payload = zlib.decompress(payload)

    sfs_obj, _ = SFSCodec.decode(payload)
    return sfs_obj, total


def decode_c2s_packet_typed(data: bytes, offset: int = 0) -> tuple[dict[str, Any], int]:
    """Like decode_c2s_packet but preserves wire types as TypedValue."""
    header = data[offset]
    if header not in (C2S_HEADER, C2S_HEADER_COMPRESSED):
        raise ValueError(f"Expected C2S header 0xC4/0xE4, got 0x{header:02X}")
    compressed = bool(header & FLAG_COMPRESSED)
    server_id = struct.unpack_from(">H", data, offset + 1)[0]
    size = struct.unpack_from(">H", data, offset + 3)[0]
    total = 5 + size
    if offset + total > len(data):
        raise ValueError(f"Incomplete packet: need {total}, have {len(data) - offset}")
    obfuscated = data[offset + 5:offset + total]
    payload = deobfuscate_c2s(obfuscated, size)
    if compressed:
        payload = zlib.decompress(payload)
    sfs_obj, _ = SFSCodec.decode_typed(payload)
    return sfs_obj, total


# --- Packet builders ---

def encode_s2c_packet(sfs_obj: dict, compress: bool = False) -> bytes:
    """Encode an S2C packet from a decoded SFS object.

    Output: [0x80][size:2B BE][SFSObject payload]
    """
    payload = SFSCodec.encode(sfs_obj)
    if compress:
        payload = zlib.compress(payload, 9)
        header = S2C_HEADER | FLAG_COMPRESSED
    else:
        header = S2C_HEADER

    if len(payload) > 65535:
        buf = bytearray()
        buf.append(header | FLAG_BIG_SIZED)
        buf.extend(struct.pack(">I", len(payload)))
        buf.extend(payload)
    else:
        buf = bytearray()
        buf.append(header)
        buf.extend(struct.pack(">H", len(payload)))
        buf.extend(payload)
    return bytes(buf)


def make_keepalive(client_time: int, server_id: int = 0) -> bytes:
    """Build a keepalive C2S packet (c=0, a=29)."""
    params = {
        "p": {
            "clientTime": TypedValue.long(client_time),
        }
    }
    return encode_c2s_packet(CTRL_SYSTEM, ACTION_KEEPALIVE, params, server_id)


def make_extension_request(cmd: str, params: dict[str, Any] | None = None,
                           room_id: int = -1, server_id: int = 0) -> bytes:
    """Build an extension request C2S packet (c=1, a=13).

    Args:
        cmd: Extension command name.
        params: Command parameters as a dict.
        room_id: Room ID (default -1).
        server_id: Server ID for the packet header.

    Returns:
        Raw wire bytes ready to send over TCP.
    """
    p = {
        "c": cmd,
        "r": TypedValue(INT, room_id),
        "p": params or {},
    }
    return encode_c2s_packet(CTRL_EXTENSION, ACTION_EXTENSION, p, server_id)


def parse_s2c_command(sfs_obj: dict) -> tuple[str | None, dict]:
    """Extract command name and params from a decoded S2C packet.

    Returns (cmd_name, params). cmd_name is None for system packets.
    """
    controller = sfs_obj.get("c", 0)
    action = sfs_obj.get("a", 0)
    p = sfs_obj.get("p", {})

    if controller == CTRL_EXTENSION and action == ACTION_EXTENSION:
        cmd = p.get("c")
        params = p.get("p", {})
        return cmd, params

    return None, p


def iter_s2c_packets(data: bytes):
    """Iterate over S2C packets in a byte stream, yielding (decoded_dict, offset).

    Skips non-0x80 header bytes (noise between packets).
    """
    pos = 0
    while pos < len(data):
        if data[pos] != S2C_HEADER:
            pos += 1
            continue
        if pos + 3 > len(data):
            break
        size = struct.unpack_from(">H", data, pos + 1)[0]
        total = 3 + size
        if pos + total > len(data):
            break
        try:
            obj, _ = decode_s2c_packet(data, pos)
            yield obj, pos
        except Exception:
            pass
        pos += total
