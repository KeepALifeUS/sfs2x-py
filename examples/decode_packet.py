"""Decode a captured SFS2X packet from hex dump.

Usage:
    python decode_packet.py

Replace the hex string below with your own captured packet data.
"""

from sfs2x import SFSCodec, decode_s2c_packet, parse_s2c_command, encode_s2c_packet

# Build a sample S2C packet to demonstrate decoding
sample_obj = {
    "c": 1,   # extension controller
    "a": 13,  # extension action
    "p": {
        "c": "server.hello",
        "p": {"message": "Welcome to the server!", "version": 42},
    },
}
raw = encode_s2c_packet(sample_obj)
print(f"Raw packet ({len(raw)} bytes): {raw.hex()}")
print()

# Decode it
obj, consumed = decode_s2c_packet(raw)
print(f"Decoded ({consumed} bytes consumed):")
print(f"  Controller: {obj.get('c')}")
print(f"  Action: {obj.get('a')}")

cmd, params = parse_s2c_command(obj)
print(f"  Command: {cmd}")
print(f"  Params: {params}")
