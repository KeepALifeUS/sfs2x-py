"""Minimal SFS2X transparent TCP proxy for protocol analysis.

Forwards traffic between client and server while decoding and logging
SFS2X commands in both directions.

Usage:
    python mitm_proxy.py --listen 9933 --remote game.example.com:9933
"""

import argparse
import asyncio
import sys

from sfs2x import (
    decode_c2s_packet, decode_s2c_packet, parse_s2c_command,
    C2S_HEADER, C2S_HEADER_COMPRESSED, S2C_HEADER,
)


async def pipe_c2s(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Forward client → server, decoding C2S packets."""
    while True:
        header = await reader.read(1)
        if not header:
            break
        # Read remaining header + size
        rest = await reader.readexactly(4)
        size = int.from_bytes(rest[2:4], "big")
        payload = await reader.readexactly(size)
        raw = header + rest + payload

        try:
            obj, _ = decode_c2s_packet(raw)
            p = obj.get("p", {})
            cmd = p.get("c", f"sys.{obj.get('a', '?')}")
            print(f"  C2S → {cmd}")
        except Exception as e:
            print(f"  C2S → [decode error: {e}]")

        writer.write(raw)
        await writer.drain()


async def pipe_s2c(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Forward server → client, decoding S2C packets."""
    while True:
        data = await reader.read(65536)
        if not data:
            break

        # Try to decode packets in the chunk
        pos = 0
        while pos < len(data):
            if data[pos] != S2C_HEADER:
                pos += 1
                continue
            try:
                obj, consumed = decode_s2c_packet(data, pos)
                cmd, params = parse_s2c_command(obj)
                label = cmd or f"sys.{obj.get('a', '?')}"
                print(f"  S2C ← {label}")
                pos += consumed
            except Exception:
                pos += 1

        writer.write(data)
        await writer.drain()


async def handle_client(local_reader, local_writer, remote_host, remote_port):
    remote_reader, remote_writer = await asyncio.open_connection(remote_host, remote_port)
    print(f"[+] Connected to {remote_host}:{remote_port}")

    try:
        await asyncio.gather(
            pipe_c2s(local_reader, remote_writer),
            pipe_s2c(remote_reader, local_writer),
        )
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        local_writer.close()
        remote_writer.close()
        print("[-] Connection closed")


async def main():
    parser = argparse.ArgumentParser(description="SFS2X MITM Proxy")
    parser.add_argument("--listen", type=int, default=9933, help="Local listen port")
    parser.add_argument("--remote", required=True, help="Remote host:port")
    args = parser.parse_args()

    host, port = args.remote.rsplit(":", 1)
    port = int(port)

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, host, port),
        "127.0.0.1", args.listen,
    )
    print(f"[*] Listening on 127.0.0.1:{args.listen} → {host}:{port}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
