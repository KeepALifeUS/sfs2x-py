"""SmartFoxServer 2X SFSObject serialization and deserialization.

SFSObject is the core data container used by SmartFox 2X for all data exchange.
It supports typed key-value pairs with the following type system:

Type IDs:
    0  = NULL
    1  = BOOL
    2  = BYTE
    3  = SHORT
    4  = INT
    5  = LONG
    6  = FLOAT
    7  = DOUBLE
    8  = UTF_STRING
    9  = BOOL_ARRAY
    10 = BYTE_ARRAY
    11 = SHORT_ARRAY
    12 = INT_ARRAY
    13 = LONG_ARRAY
    14 = FLOAT_ARRAY
    15 = DOUBLE_ARRAY
    16 = UTF_STRING_ARRAY
    17 = SFS_ARRAY
    18 = SFS_OBJECT
"""

from __future__ import annotations

import struct
from typing import Any

__all__ = [
    "SFSCodec", "TypedValue",
    "NULL", "BOOL", "BYTE", "SHORT", "INT", "LONG",
    "FLOAT", "DOUBLE", "UTF_STRING",
    "BOOL_ARRAY", "BYTE_ARRAY", "SHORT_ARRAY", "INT_ARRAY",
    "LONG_ARRAY", "FLOAT_ARRAY", "DOUBLE_ARRAY", "UTF_STRING_ARRAY",
    "SFS_ARRAY", "SFS_OBJECT", "TEXT",
]

# Type IDs
NULL = 0
BOOL = 1
BYTE = 2
SHORT = 3
INT = 4
LONG = 5
FLOAT = 6
DOUBLE = 7
UTF_STRING = 8
BOOL_ARRAY = 9
BYTE_ARRAY = 10
SHORT_ARRAY = 11
INT_ARRAY = 12
LONG_ARRAY = 13
FLOAT_ARRAY = 14
DOUBLE_ARRAY = 15
UTF_STRING_ARRAY = 16
SFS_ARRAY = 17
SFS_OBJECT = 18
TEXT = 20


class TypedValue:
    """Wrapper for explicitly typed SFS values (when auto-detection isn't enough).

    SFS2X uses distinct wire types for BYTE, SHORT, INT, and LONG — all of which
    map to Python ``int``. Wrapping a value in ``TypedValue`` forces a specific
    wire type during encoding.

    Example::

        params = {
            "level": TypedValue(INT, 5),      # force 4-byte int
            "flags": TypedValue(BYTE, 0x01),  # force 1-byte
        }
    """

    __slots__ = ("type_id", "value")

    def __init__(self, type_id: int, value: Any) -> None:
        self.type_id = type_id
        self.value = value

    def __repr__(self) -> str:
        return f"TypedValue({self.type_id}, {self.value!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TypedValue):
            return self.type_id == other.type_id and self.value == other.value
        return NotImplemented

    @staticmethod
    def byte(value: int) -> TypedValue:
        return TypedValue(BYTE, value)

    @staticmethod
    def short(value: int) -> TypedValue:
        return TypedValue(SHORT, value)

    @staticmethod
    def int_(value: int) -> TypedValue:
        return TypedValue(INT, value)

    @staticmethod
    def long(value: int) -> TypedValue:
        return TypedValue(LONG, value)

    @staticmethod
    def float_(value: float) -> TypedValue:
        return TypedValue(FLOAT, value)

    @staticmethod
    def double(value: float) -> TypedValue:
        return TypedValue(DOUBLE, value)


class SFSCodec:
    """Encode/decode SFSObject binary format."""

    # --- Decoding ---

    @staticmethod
    def decode(data: bytes, offset: int = 0) -> tuple[dict[str, Any], int]:
        """Decode an SFSObject from binary data. Returns (dict, bytes_consumed)."""
        return SFSCodec._decode_object(data, offset)

    @staticmethod
    def decode_typed(data: bytes, offset: int = 0) -> tuple[dict[str, Any], int]:
        """Decode preserving wire types as TypedValue.

        Useful for MITM proxies that need to re-encode packets without
        losing type information (e.g. a BYTE 5 vs INT 5).
        """
        return SFSCodec._decode_object_typed(data, offset)

    @staticmethod
    def _decode_object(data: bytes, pos: int) -> tuple[dict[str, Any], int]:
        type_id = data[pos]
        pos += 1
        if type_id != SFS_OBJECT:
            raise ValueError(f"Expected SFS_OBJECT (18), got {type_id} at offset {pos - 1}")

        count = struct.unpack_from(">H", data, pos)[0]
        pos += 2

        obj: dict[str, Any] = {}
        for _ in range(count):
            key_len = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            key = data[pos:pos + key_len].decode("utf-8")
            pos += key_len

            value, pos = SFSCodec._decode_value(data, pos)
            obj[key] = value

        return obj, pos

    @staticmethod
    def _decode_object_typed(data: bytes, pos: int) -> tuple[dict[str, Any], int]:
        """Like _decode_object but wraps scalar values in TypedValue to preserve wire types."""
        type_id = data[pos]
        pos += 1
        if type_id != SFS_OBJECT:
            raise ValueError(f"Expected SFS_OBJECT (18), got {type_id}")
        count = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        obj: dict[str, Any] = {}
        for _ in range(count):
            key_len = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            key = data[pos:pos + key_len].decode("utf-8")
            pos += key_len
            value, pos = SFSCodec._decode_value_typed(data, pos)
            obj[key] = value
        return obj, pos

    @staticmethod
    def _decode_value_typed(data: bytes, pos: int) -> tuple[Any, int]:
        """Decode value wrapping scalars in TypedValue to preserve wire type."""
        type_id = data[pos]
        pos += 1
        if type_id == NULL:
            return None, pos
        elif type_id == BOOL:
            return TypedValue(BOOL, data[pos] != 0), pos + 1
        elif type_id == BYTE:
            return TypedValue(BYTE, data[pos]), pos + 1
        elif type_id == SHORT:
            val = struct.unpack_from(">h", data, pos)[0]
            return TypedValue(SHORT, val), pos + 2
        elif type_id == INT:
            val = struct.unpack_from(">i", data, pos)[0]
            return TypedValue(INT, val), pos + 4
        elif type_id == LONG:
            val = struct.unpack_from(">q", data, pos)[0]
            return TypedValue(LONG, val), pos + 8
        elif type_id == FLOAT:
            val = struct.unpack_from(">f", data, pos)[0]
            return TypedValue(FLOAT, val), pos + 4
        elif type_id == DOUBLE:
            val = struct.unpack_from(">d", data, pos)[0]
            return TypedValue(DOUBLE, val), pos + 8
        elif type_id == UTF_STRING:
            str_len = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            val = data[pos:pos + str_len].decode("utf-8")
            return TypedValue(UTF_STRING, val), pos + str_len
        elif type_id == SFS_OBJECT:
            pos -= 1
            nested, pos = SFSCodec._decode_object_typed(data, pos)
            return nested, pos
        elif type_id == SFS_ARRAY:
            count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            arr = []
            for _ in range(count):
                v, pos = SFSCodec._decode_value_typed(data, pos)
                arr.append(v)
            return arr, pos
        else:
            # For arrays and other types, fall back to plain decode
            pos -= 1
            val, pos = SFSCodec._decode_value(data, pos)
            return val, pos

    @staticmethod
    def _decode_value(data: bytes, pos: int) -> tuple[Any, int]:
        type_id = data[pos]
        pos += 1

        if type_id == NULL:
            return None, pos
        elif type_id == BOOL:
            return data[pos] != 0, pos + 1
        elif type_id == BYTE:
            return data[pos], pos + 1
        elif type_id == SHORT:
            val = struct.unpack_from(">h", data, pos)[0]
            return val, pos + 2
        elif type_id == INT:
            val = struct.unpack_from(">i", data, pos)[0]
            return val, pos + 4
        elif type_id == LONG:
            val = struct.unpack_from(">q", data, pos)[0]
            return val, pos + 8
        elif type_id == FLOAT:
            val = struct.unpack_from(">f", data, pos)[0]
            return val, pos + 4
        elif type_id == DOUBLE:
            val = struct.unpack_from(">d", data, pos)[0]
            return val, pos + 8
        elif type_id == UTF_STRING:
            str_len = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            val = data[pos:pos + str_len].decode("utf-8")
            return val, pos + str_len
        elif type_id == BOOL_ARRAY:
            count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            arr = [data[pos + i] != 0 for i in range(count)]
            return arr, pos + count
        elif type_id == BYTE_ARRAY:
            count = struct.unpack_from(">I", data, pos)[0]
            pos += 4
            arr = data[pos:pos + count]
            return bytes(arr), pos + count
        elif type_id == SHORT_ARRAY:
            count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            arr = [struct.unpack_from(">h", data, pos + i * 2)[0] for i in range(count)]
            return arr, pos + count * 2
        elif type_id == INT_ARRAY:
            count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            arr = [struct.unpack_from(">i", data, pos + i * 4)[0] for i in range(count)]
            return arr, pos + count * 4
        elif type_id == LONG_ARRAY:
            count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            arr = [struct.unpack_from(">q", data, pos + i * 8)[0] for i in range(count)]
            return arr, pos + count * 8
        elif type_id == FLOAT_ARRAY:
            count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            arr = [struct.unpack_from(">f", data, pos + i * 4)[0] for i in range(count)]
            return arr, pos + count * 4
        elif type_id == DOUBLE_ARRAY:
            count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            arr = [struct.unpack_from(">d", data, pos + i * 8)[0] for i in range(count)]
            return arr, pos + count * 8
        elif type_id == UTF_STRING_ARRAY:
            count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            arr = []
            for _ in range(count):
                str_len = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                arr.append(data[pos:pos + str_len].decode("utf-8"))
                pos += str_len
            return arr, pos
        elif type_id == SFS_ARRAY:
            return SFSCodec._decode_sfs_array(data, pos)
        elif type_id == SFS_OBJECT:
            count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            obj: dict[str, Any] = {}
            for _ in range(count):
                key_len = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                key = data[pos:pos + key_len].decode("utf-8")
                pos += key_len
                value, pos = SFSCodec._decode_value(data, pos)
                obj[key] = value
            return obj, pos
        else:
            raise ValueError(f"Unknown SFS type: {type_id} at offset {pos - 1}")

    @staticmethod
    def _decode_sfs_array(data: bytes, pos: int) -> tuple[list, int]:
        count = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        arr = []
        for _ in range(count):
            value, pos = SFSCodec._decode_value(data, pos)
            arr.append(value)
        return arr, pos

    # --- Encoding ---

    @staticmethod
    def encode(obj: dict[str, Any]) -> bytes:
        """Encode a Python dict as an SFSObject."""
        return SFSCodec._encode_object(obj)

    @staticmethod
    def _encode_object(obj: dict[str, Any]) -> bytes:
        buf = bytearray()
        buf.append(SFS_OBJECT)
        buf.extend(struct.pack(">H", len(obj)))

        for key, value in obj.items():
            key_bytes = key.encode("utf-8")
            buf.extend(struct.pack(">H", len(key_bytes)))
            buf.extend(key_bytes)
            buf.extend(SFSCodec._encode_value(value))

        return bytes(buf)

    @staticmethod
    def _encode_value(value: Any) -> bytes:
        buf = bytearray()

        if isinstance(value, TypedValue):
            return SFSCodec._encode_typed(value.type_id, value.value)
        elif value is None:
            buf.append(NULL)
        elif isinstance(value, bool):
            buf.append(BOOL)
            buf.append(1 if value else 0)
        elif isinstance(value, int):
            if -128 <= value <= 127:
                buf.append(BYTE)
                buf.append(value & 0xFF)
            elif -32768 <= value <= 32767:
                buf.append(SHORT)
                buf.extend(struct.pack(">h", value))
            elif -2147483648 <= value <= 2147483647:
                buf.append(INT)
                buf.extend(struct.pack(">i", value))
            else:
                buf.append(LONG)
                buf.extend(struct.pack(">q", value))
        elif isinstance(value, float):
            buf.append(DOUBLE)
            buf.extend(struct.pack(">d", value))
        elif isinstance(value, str):
            buf.append(UTF_STRING)
            encoded = value.encode("utf-8")
            buf.extend(struct.pack(">H", len(encoded)))
            buf.extend(encoded)
        elif isinstance(value, (bytes, bytearray)):
            buf.append(BYTE_ARRAY)
            buf.extend(struct.pack(">I", len(value)))
            buf.extend(value)
        elif isinstance(value, list):
            buf.extend(SFSCodec._encode_array(value))
        elif isinstance(value, dict):
            buf.extend(SFSCodec._encode_object(value))
        else:
            raise TypeError(f"Cannot encode type {type(value)} to SFS")

        return bytes(buf)

    @staticmethod
    def _encode_typed(type_id: int, value: Any) -> bytes:
        """Encode a value with an explicit type ID."""
        buf = bytearray()
        buf.append(type_id)
        if type_id == NULL:
            pass
        elif type_id == BOOL:
            buf.append(1 if value else 0)
        elif type_id == BYTE:
            buf.append(value & 0xFF)
        elif type_id == SHORT:
            buf.extend(struct.pack(">h", value))
        elif type_id == INT:
            buf.extend(struct.pack(">i", value))
        elif type_id == LONG:
            buf.extend(struct.pack(">q", value))
        elif type_id == FLOAT:
            buf.extend(struct.pack(">f", value))
        elif type_id == DOUBLE:
            buf.extend(struct.pack(">d", value))
        elif type_id == UTF_STRING:
            encoded = value.encode("utf-8")
            buf.extend(struct.pack(">H", len(encoded)))
            buf.extend(encoded)
        elif type_id == BYTE_ARRAY:
            buf.extend(struct.pack(">I", len(value)))
            buf.extend(value)
        elif type_id == SFS_OBJECT:
            inner = SFSCodec._encode_object(value)
            buf.extend(inner[1:])  # skip the type byte from _encode_object
        elif type_id == SFS_ARRAY:
            inner = SFSCodec._encode_array(value)
            buf.extend(inner[1:])  # skip the type byte
        elif type_id == SHORT_ARRAY:
            buf.extend(struct.pack(">H", len(value)))
            for v in value:
                buf.extend(struct.pack(">h", v))
        elif type_id == INT_ARRAY:
            buf.extend(struct.pack(">H", len(value)))
            for v in value:
                buf.extend(struct.pack(">i", v))
        elif type_id == LONG_ARRAY:
            buf.extend(struct.pack(">H", len(value)))
            for v in value:
                buf.extend(struct.pack(">q", v))
        elif type_id == UTF_STRING_ARRAY:
            buf.extend(struct.pack(">H", len(value)))
            for v in value:
                s = str(v).encode("utf-8")
                buf.extend(struct.pack(">H", len(s)))
                buf.extend(s)
        else:
            raise ValueError(f"Unsupported explicit type: {type_id}")
        return bytes(buf)

    @staticmethod
    def _encode_array(arr: list) -> bytes:
        buf = bytearray()
        buf.append(SFS_ARRAY)
        buf.extend(struct.pack(">H", len(arr)))
        for item in arr:
            buf.extend(SFSCodec._encode_value(item))
        return bytes(buf)
