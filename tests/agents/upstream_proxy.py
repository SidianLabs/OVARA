#!/usr/bin/env python3
"""A small HTTP CONNECT proxy: what a corporate forward proxy does for TLS
traffic. The agents battery puts it between Ovara and the internet
(UPSTREAM=1) to show Ovara's own outbound side going through it.

    upstream_proxy.py PORT LOGFILE

With PARENT=http://[user:pass@]host:port in the environment it chains every
CONNECT to that proxy instead of dialling the destination itself. LOGFILE
gets one line per CONNECT: "CONNECT host:port <outcome>".
"""
import asyncio
import base64
import os
import sys
import urllib.parse


async def pipe(r, w):
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


def note(log, line):
    log.write(line + "\n")
    log.flush()


async def handle(reader, writer, log):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
    except Exception:
        writer.close()
        return
    parts = head.split(b"\r\n", 1)[0].decode("latin-1").split()
    if len(parts) != 3 or parts[0] != "CONNECT":
        writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return
    target = parts[1]
    host, _, port = target.rpartition(":")
    parent = os.environ.get("PARENT")
    try:
        if parent:
            u = urllib.parse.urlsplit(parent)
            ur, uw = await asyncio.wait_for(asyncio.open_connection(u.hostname, u.port or 3128), 15)
            req = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n" % (target, target)
            if u.username:
                cred = "%s:%s" % (urllib.parse.unquote(u.username), urllib.parse.unquote(u.password or ""))
                req += "Proxy-Authorization: Basic %s\r\n" % base64.b64encode(cred.encode()).decode()
            uw.write((req + "\r\n").encode())
            await uw.drain()
            resp = await asyncio.wait_for(ur.readuntil(b"\r\n\r\n"), 15)
            status = resp.split(b" ", 2)[1].decode()
            if status != "200":
                note(log, "CONNECT %s parent-%s" % (target, status))
                writer.write(resp)
                await writer.drain()
                writer.close()
                return
        else:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(host.strip("[]"), int(port)), 15)
    except Exception:
        note(log, "CONNECT %s 502" % target)
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return
    note(log, "CONNECT %s 200" % target)
    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await writer.drain()
    await asyncio.gather(pipe(reader, uw), pipe(ur, writer))


async def main():
    port, logfile = int(sys.argv[1]), sys.argv[2]
    with open(logfile, "a") as log:
        server = await asyncio.start_server(lambda r, w: handle(r, w, log), "127.0.0.1", port)
        async with server:
            await server.serve_forever()


asyncio.run(main())
