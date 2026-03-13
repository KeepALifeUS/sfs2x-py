"""Tests for SFS2X packet framing, XOR obfuscation, and compression."""

import struct
import zlib
import pytest
from sfs2x.objects import SFSCodec, TypedValue, BYTE, SHORT, INT, LONG
from sfs2x.protocol import (
    obfuscate_c2s, deobfuscate_c2s,
    encode_c2s_packet, decode_c2s_packet, decode_c2s_packet_typed,
    encode_s2c_packet, decode_s2c_packet,
    make_extension_request, make_keepalive, parse_s2c_command,
    iter_s2c_packets,
    C2S_HEADER, C2S_HEADER_COMPRESSED, S2C_HEADER,
    CTRL_SYSTEM, CTRL_EXTENSION,
    ACTION_KEEPALIVE, ACTION_EXTENSION,
)


class TestXorObfuscation:
    def test_roundtrip_small(self):
        """XOR obfuscation is its own inverse."""
        original = b"\x12\x00\x03\x00\x01\x02\x03"
        size = len(original)
        obfuscated = obfuscate_c2s(original)
        assert obfuscated != original
        recovered = deobfuscate_c2s(obfuscated, size)
        assert recovered == original

    def test_roundtrip_large(self):
        """Large packet where hi byte of size is non-zero."""
        original = bytes(range(256)) * 3  # 768 bytes
        size = len(original)
        obfuscated = obfuscate_c2s(original)
        recovered = deobfuscate_c2s(obfuscated, size)
        assert recovered == original

    def test_empty(self):
        assert obfuscate_c2s(b"") == b""

    def test_xor_key_bytes(self):
        """Verify XOR key derivation: [lo, hi, 0, 0]."""
        data = bytes([0xFF, 0xFF, 0xFF, 0xFF])
        size = 0x0301  # lo=0x01, hi=0x03
        result = deobfuscate_c2s(data, size)
        assert result == bytes([0xFF ^ 0x01, 0xFF ^ 0x03, 0xFF, 0xFF])


class TestC2SPacket:
    def test_encode_decode_roundtrip(self):
        params = {"cmd": "test", "val": TypedValue(INT, 42)}
        packet = encode_c2s_packet(CTRL_EXTENSION, ACTION_EXTENSION, params, server_id=100)
        decoded, consumed = decode_c2s_packet(packet)
        assert consumed == len(packet)
        assert decoded["c"] == CTRL_EXTENSION
        assert decoded["a"] == ACTION_EXTENSION
        assert decoded["p"]["cmd"] == "test"
        assert decoded["p"]["val"] == 42

    def test_compressed_roundtrip(self):
        params = {"data": "x" * 500}  # large enough to benefit from compression
        packet = encode_c2s_packet(CTRL_EXTENSION, ACTION_EXTENSION, params,
                                   server_id=0, compress=True)
        assert packet[0] == C2S_HEADER_COMPRESSED
        decoded, consumed = decode_c2s_packet(packet)
        assert consumed == len(packet)
        assert decoded["p"]["data"] == "x" * 500

    def test_header_byte(self):
        packet = encode_c2s_packet(CTRL_SYSTEM, ACTION_KEEPALIVE, {}, server_id=0)
        assert packet[0] == C2S_HEADER

    def test_server_id_in_header(self):
        packet = encode_c2s_packet(CTRL_SYSTEM, ACTION_KEEPALIVE, {}, server_id=9999)
        sid = struct.unpack_from(">H", packet, 1)[0]
        assert sid == 9999

    def test_invalid_header(self):
        with pytest.raises(ValueError, match="Expected C2S header"):
            decode_c2s_packet(b"\x00\x00\x00\x00\x00")

    def test_incomplete_packet(self):
        packet = encode_c2s_packet(CTRL_SYSTEM, ACTION_KEEPALIVE, {}, server_id=0)
        # Truncate after the full 5-byte header so size is parsed but payload is missing
        with pytest.raises(ValueError, match="Incomplete"):
            decode_c2s_packet(packet[:5])


class TestC2STypedDecode:
    def test_preserves_types(self):
        params = {"x": TypedValue(INT, 5), "y": TypedValue(BYTE, 1)}
        packet = encode_c2s_packet(CTRL_EXTENSION, ACTION_EXTENSION, params, server_id=0)
        decoded, _ = decode_c2s_packet_typed(packet)
        p = decoded["p"]
        assert p["x"].type_id == INT
        assert p["x"].value == 5
        assert p["y"].type_id == BYTE
        assert p["y"].value == 1


class TestS2CPacket:
    def test_encode_decode_roundtrip(self):
        obj = {
            "c": TypedValue(BYTE, CTRL_EXTENSION),
            "a": TypedValue(SHORT, ACTION_EXTENSION),
            "p": {"c": "hello", "r": TypedValue(INT, -1), "p": {"status": "ok"}},
        }
        packet = encode_s2c_packet(obj)
        assert packet[0] == S2C_HEADER
        decoded, consumed = decode_s2c_packet(packet)
        assert consumed == len(packet)
        assert decoded["p"]["c"] == "hello"

    def test_compressed(self):
        obj = {"data": "y" * 1000}
        packet = encode_s2c_packet(obj, compress=True)
        assert packet[0] & 0x20  # FLAG_COMPRESSED
        decoded, consumed = decode_s2c_packet(packet)
        assert decoded["data"] == "y" * 1000

    def test_big_sized(self):
        # Create a payload > 65535 bytes using byte array (strings cap at 65535)
        big_data = b"z" * 70000
        obj = {"data": big_data}
        packet = encode_s2c_packet(obj)
        assert packet[0] & 0x08  # FLAG_BIG_SIZED
        decoded, consumed = decode_s2c_packet(packet)
        assert decoded["data"] == big_data

    def test_invalid_header(self):
        with pytest.raises(ValueError, match="FLAG_BINARY"):
            decode_s2c_packet(b"\x00\x00\x03\x12\x00\x00")


class TestPacketBuilders:
    def test_make_keepalive(self):
        packet = make_keepalive(client_time=1234567890, server_id=100)
        decoded, _ = decode_c2s_packet(packet)
        assert decoded["c"] == CTRL_SYSTEM
        assert decoded["a"] == ACTION_KEEPALIVE
        assert decoded["p"]["p"]["clientTime"] == 1234567890

    def test_make_extension_request(self):
        packet = make_extension_request("my.command", {"key": "value"},
                                        room_id=5, server_id=200)
        decoded, _ = decode_c2s_packet(packet)
        assert decoded["c"] == CTRL_EXTENSION
        assert decoded["a"] == ACTION_EXTENSION
        assert decoded["p"]["c"] == "my.command"
        assert decoded["p"]["r"] == -1 or decoded["p"]["r"] == 5  # room_id
        assert decoded["p"]["p"]["key"] == "value"

    def test_make_extension_request_no_params(self):
        packet = make_extension_request("ping")
        decoded, _ = decode_c2s_packet(packet)
        assert decoded["p"]["c"] == "ping"
        assert decoded["p"]["p"] == {}


class TestParseS2CCommand:
    def test_extension_command(self):
        obj = {
            "c": CTRL_EXTENSION,
            "a": ACTION_EXTENSION,
            "p": {"c": "server.response", "p": {"gold": 100}},
        }
        cmd, params = parse_s2c_command(obj)
        assert cmd == "server.response"
        assert params == {"gold": 100}

    def test_system_packet(self):
        obj = {"c": CTRL_SYSTEM, "a": ACTION_KEEPALIVE, "p": {"time": 123}}
        cmd, params = parse_s2c_command(obj)
        assert cmd is None
        assert params == {"time": 123}


class TestIterS2CPackets:
    def test_single_packet(self):
        obj = {"c": TypedValue(BYTE, 0), "a": TypedValue(SHORT, 29), "p": {}}
        packet = encode_s2c_packet(obj)
        results = list(iter_s2c_packets(packet))
        assert len(results) == 1

    def test_multiple_packets(self):
        obj1 = {"c": TypedValue(BYTE, 0), "a": TypedValue(SHORT, 29), "p": {}}
        obj2 = {"c": TypedValue(BYTE, 1), "a": TypedValue(SHORT, 13), "p": {"c": "test", "p": {}}}
        stream = encode_s2c_packet(obj1) + encode_s2c_packet(obj2)
        results = list(iter_s2c_packets(stream))
        assert len(results) == 2

    def test_skips_noise(self):
        obj = {"c": TypedValue(BYTE, 0), "a": TypedValue(SHORT, 29), "p": {}}
        packet = encode_s2c_packet(obj)
        # Add noise bytes before the packet
        stream = b"\x00\x01\x02" + packet
        results = list(iter_s2c_packets(stream))
        assert len(results) == 1

    def test_empty_stream(self):
        assert list(iter_s2c_packets(b"")) == []
