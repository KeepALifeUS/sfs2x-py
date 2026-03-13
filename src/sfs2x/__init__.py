"""sfs2x — Pure Python implementation of the SmartFoxServer 2X binary protocol."""

__version__ = "0.1.0"

from .objects import (
    SFSCodec, TypedValue,
    NULL, BOOL, BYTE, SHORT, INT, LONG, FLOAT, DOUBLE, UTF_STRING,
    BOOL_ARRAY, BYTE_ARRAY, SHORT_ARRAY, INT_ARRAY,
    LONG_ARRAY, FLOAT_ARRAY, DOUBLE_ARRAY, UTF_STRING_ARRAY,
    SFS_ARRAY, SFS_OBJECT, TEXT,
)
from .protocol import (
    encode_c2s_packet, decode_c2s_packet, decode_c2s_packet_typed,
    encode_s2c_packet, decode_s2c_packet,
    make_extension_request, make_keepalive, parse_s2c_command,
    iter_s2c_packets,
    obfuscate_c2s, deobfuscate_c2s,
    SFSPacket,
    FLAG_BINARY, FLAG_ENCRYPTED, FLAG_COMPRESSED, FLAG_BIG_SIZED,
    C2S_HEADER, C2S_HEADER_COMPRESSED, S2C_HEADER,
    CTRL_SYSTEM, CTRL_EXTENSION,
    ACTION_HANDSHAKE, ACTION_LOGIN, ACTION_LOGOUT,
    ACTION_KEEPALIVE, ACTION_EXTENSION,
)
from .crypto import AESCipher, KeyExchange, make_password_hash

__all__ = [
    # objects
    "SFSCodec", "TypedValue",
    "NULL", "BOOL", "BYTE", "SHORT", "INT", "LONG", "FLOAT", "DOUBLE",
    "UTF_STRING", "BOOL_ARRAY", "BYTE_ARRAY", "SHORT_ARRAY", "INT_ARRAY",
    "LONG_ARRAY", "FLOAT_ARRAY", "DOUBLE_ARRAY", "UTF_STRING_ARRAY",
    "SFS_ARRAY", "SFS_OBJECT", "TEXT",
    # protocol
    "encode_c2s_packet", "decode_c2s_packet", "decode_c2s_packet_typed",
    "encode_s2c_packet", "decode_s2c_packet",
    "make_extension_request", "make_keepalive", "parse_s2c_command",
    "iter_s2c_packets", "obfuscate_c2s", "deobfuscate_c2s",
    "SFSPacket",
    "FLAG_BINARY", "FLAG_ENCRYPTED", "FLAG_COMPRESSED", "FLAG_BIG_SIZED",
    "C2S_HEADER", "C2S_HEADER_COMPRESSED", "S2C_HEADER",
    "CTRL_SYSTEM", "CTRL_EXTENSION",
    "ACTION_HANDSHAKE", "ACTION_LOGIN", "ACTION_LOGOUT",
    "ACTION_KEEPALIVE", "ACTION_EXTENSION",
    # crypto
    "AESCipher", "KeyExchange", "make_password_hash",
]
