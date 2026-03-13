"""Tests for SFSObject encode/decode roundtrips."""

import pytest
from sfs2x.objects import (
    SFSCodec, TypedValue,
    BOOL, BYTE, SHORT, INT, LONG, FLOAT, DOUBLE, UTF_STRING,
    BOOL_ARRAY, SHORT_ARRAY, INT_ARRAY,
    LONG_ARRAY, FLOAT_ARRAY, DOUBLE_ARRAY, UTF_STRING_ARRAY,
)


def roundtrip(obj):
    """Encode then decode, return result."""
    encoded = SFSCodec.encode(obj)
    decoded, consumed = SFSCodec.decode(encoded)
    assert consumed == len(encoded)
    return decoded


class TestScalarTypes:
    def test_null(self):
        assert roundtrip({"x": None}) == {"x": None}

    def test_bool_true(self):
        assert roundtrip({"x": True}) == {"x": True}

    def test_bool_false(self):
        assert roundtrip({"x": False}) == {"x": False}

    def test_byte(self):
        # Small ints auto-encode as BYTE
        result = roundtrip({"x": 42})
        assert result["x"] == 42

    def test_short(self):
        result = roundtrip({"x": 1000})
        assert result["x"] == 1000

    def test_int(self):
        result = roundtrip({"x": 100000})
        assert result["x"] == 100000

    def test_long(self):
        big = 2**40
        result = roundtrip({"x": big})
        assert result["x"] == big

    def test_negative_int(self):
        result = roundtrip({"x": TypedValue(INT, -12345)})
        assert result["x"] == -12345

    def test_max_int64(self):
        val = 2**63 - 1
        result = roundtrip({"x": val})
        assert result["x"] == val

    def test_min_int64(self):
        val = -(2**63)
        result = roundtrip({"x": val})
        assert result["x"] == val

    def test_float(self):
        result = roundtrip({"x": TypedValue(FLOAT, 3.14)})
        assert abs(result["x"] - 3.14) < 0.01  # float precision

    def test_double(self):
        result = roundtrip({"x": 3.14159265358979})
        assert abs(result["x"] - 3.14159265358979) < 1e-10

    def test_utf_string(self):
        assert roundtrip({"x": "hello"}) == {"x": "hello"}

    def test_utf_string_empty(self):
        assert roundtrip({"x": ""}) == {"x": ""}

    def test_utf_string_unicode(self):
        assert roundtrip({"x": "日本語"}) == {"x": "日本語"}


class TestArrayTypes:
    def test_byte_array(self):
        data = b"\x01\x02\x03\x04"
        result = roundtrip({"x": data})
        assert result["x"] == data

    def test_byte_array_empty(self):
        result = roundtrip({"x": b""})
        assert result["x"] == b""

    def test_sfs_array(self):
        result = roundtrip({"x": [1, "two", True]})
        assert result["x"] == [1, "two", True]

    def test_sfs_array_empty(self):
        result = roundtrip({"x": []})
        assert result["x"] == []

    def test_typed_short_array(self):
        arr = [1, 2, -3]
        obj = {"x": TypedValue(SHORT_ARRAY, arr)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode(encoded)
        assert decoded["x"] == arr

    def test_typed_int_array(self):
        arr = [100000, -200000]
        obj = {"x": TypedValue(INT_ARRAY, arr)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode(encoded)
        assert decoded["x"] == arr

    def test_typed_long_array(self):
        arr = [2**40, -(2**50)]
        obj = {"x": TypedValue(LONG_ARRAY, arr)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode(encoded)
        assert decoded["x"] == arr

    def test_typed_utf_string_array(self):
        arr = ["hello", "world"]
        obj = {"x": TypedValue(UTF_STRING_ARRAY, arr)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode(encoded)
        assert decoded["x"] == arr


class TestNestedObjects:
    def test_nested_object(self):
        obj = {"outer": {"inner": 42}}
        assert roundtrip(obj) == obj

    def test_deeply_nested(self):
        obj = {"a": {"b": {"c": {"d": 1}}}}
        assert roundtrip(obj) == obj

    def test_nested_array_with_objects(self):
        obj = {"items": [{"id": 1}, {"id": 2}]}
        result = roundtrip(obj)
        assert result["items"][0]["id"] == 1
        assert result["items"][1]["id"] == 2


class TestEmptyObjects:
    def test_empty_object(self):
        assert roundtrip({}) == {}

    def test_object_with_empty_nested(self):
        assert roundtrip({"x": {}}) == {"x": {}}


class TestTypedValue:
    def test_byte_vs_int(self):
        """TypedValue forces specific wire type even when value fits smaller."""
        obj_byte = {"x": TypedValue(BYTE, 5)}
        obj_int = {"x": TypedValue(INT, 5)}
        enc_byte = SFSCodec.encode(obj_byte)
        enc_int = SFSCodec.encode(obj_int)
        # INT encoding is larger than BYTE
        assert len(enc_int) > len(enc_byte)

    def test_typed_long(self):
        obj = {"x": TypedValue(LONG, 42)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode(encoded)
        assert decoded["x"] == 42

    def test_factory_methods(self):
        assert TypedValue.byte(5).type_id == BYTE
        assert TypedValue.short(5).type_id == SHORT
        assert TypedValue.int_(5).type_id == INT
        assert TypedValue.long(5).type_id == LONG
        assert TypedValue.float_(1.0).type_id == FLOAT
        assert TypedValue.double(1.0).type_id == DOUBLE

    def test_equality(self):
        assert TypedValue(INT, 5) == TypedValue(INT, 5)
        assert TypedValue(INT, 5) != TypedValue(LONG, 5)


class TestDecodeTyped:
    def test_preserves_byte(self):
        obj = {"x": TypedValue(BYTE, 5)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode_typed(encoded)
        assert isinstance(decoded["x"], TypedValue)
        assert decoded["x"].type_id == BYTE
        assert decoded["x"].value == 5

    def test_preserves_int(self):
        obj = {"x": TypedValue(INT, 5)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode_typed(encoded)
        assert decoded["x"].type_id == INT
        assert decoded["x"].value == 5

    def test_preserves_string(self):
        obj = {"x": "hello"}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode_typed(encoded)
        assert decoded["x"].type_id == UTF_STRING
        assert decoded["x"].value == "hello"

    def test_nested_object_typed(self):
        obj = {"outer": {"inner": TypedValue(INT, 42)}}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode_typed(encoded)
        assert isinstance(decoded["outer"], dict)
        assert decoded["outer"]["inner"].type_id == INT

    def test_null_not_wrapped(self):
        obj = {"x": None}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode_typed(encoded)
        assert decoded["x"] is None


class TestArrayTypesExtended:
    def test_bool_array_roundtrip(self):
        arr = [True, False, True, True, False]
        obj = {"x": TypedValue(BOOL_ARRAY, arr)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode(encoded)
        assert decoded["x"] == arr

    def test_float_array_roundtrip(self):
        arr = [1.5, -2.5, 0.0]
        obj = {"x": TypedValue(FLOAT_ARRAY, arr)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode(encoded)
        assert len(decoded["x"]) == 3
        for a, b in zip(decoded["x"], arr):
            assert abs(a - b) < 1e-6

    def test_double_array_roundtrip(self):
        arr = [1.23456789012345, -9.87654321098765]
        obj = {"x": TypedValue(DOUBLE_ARRAY, arr)}
        encoded = SFSCodec.encode(obj)
        decoded, _ = SFSCodec.decode(encoded)
        assert len(decoded["x"]) == 2
        for a, b in zip(decoded["x"], arr):
            assert abs(a - b) < 1e-10

    def test_nested_sfs_array(self):
        """SFS_ARRAY inside SFS_ARRAY."""
        inner = [1, "two", True]
        outer = [inner, 42, "top"]
        result = roundtrip({"x": outer})
        assert result["x"][0] == [1, "two", True]
        assert result["x"][1] == 42
        assert result["x"][2] == "top"


class TestBoundaryValues:
    def test_byte_boundaries(self):
        # BYTE in SFS2X is unsigned (0-255 on wire, stored as single byte)
        assert roundtrip({"x": 0})["x"] == 0
        assert roundtrip({"x": 127})["x"] == 127
        # Negative values in BYTE range auto-encode as BYTE but decode unsigned
        result = roundtrip({"x": TypedValue(SHORT, -128)})
        assert result["x"] == -128

    def test_short_boundaries(self):
        result = roundtrip({"x": TypedValue(SHORT, -32768)})
        assert result["x"] == -32768
        result = roundtrip({"x": TypedValue(SHORT, 32767)})
        assert result["x"] == 32767

    def test_int_boundaries(self):
        result = roundtrip({"x": TypedValue(INT, -2147483648)})
        assert result["x"] == -2147483648
        result = roundtrip({"x": TypedValue(INT, 2147483647)})
        assert result["x"] == 2147483647

    def test_long_boundaries(self):
        result = roundtrip({"x": TypedValue(LONG, -(2**63))})
        assert result["x"] == -(2**63)
        result = roundtrip({"x": TypedValue(LONG, 2**63 - 1)})
        assert result["x"] == 2**63 - 1


class TestNumericStringKeys:
    def test_numeric_string_key(self):
        obj = {"123": "value", "0": True}
        result = roundtrip(obj)
        assert result["123"] == "value"
        assert result["0"] is True

    def test_mixed_numeric_string_keys(self):
        obj = {"1": 1, "two": 2, "3": 3}
        result = roundtrip(obj)
        assert result == obj


class TestErrors:
    def test_decode_wrong_type_byte(self):
        # Start with BOOL type byte instead of SFS_OBJECT
        data = bytes([BOOL, 0x01])
        with pytest.raises(ValueError, match="Expected SFS_OBJECT"):
            SFSCodec.decode(data)

    def test_encode_unsupported_type(self):
        with pytest.raises(TypeError, match="Cannot encode type"):
            SFSCodec.encode({"x": object()})
