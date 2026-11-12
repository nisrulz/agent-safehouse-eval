#!/usr/bin/env python3
"""Hostname-allowlisting CONNECT proxy for the allowlist eval stage.

Runs on the host, outside the sandbox. profiles/allowlist.sb permits egress to
127.0.0.1:18090 and nothing else, so the proxy is the only way out and it
decides which hostnames may be tunnelled.

Usage:
    proxy-allowlist.py --port 18090 --allow host1,host2

Only CONNECT is served. Anything else gets 405, an unlisted host gets 403, and
an unreachable upstream gets 502.
"""

import argparse
import select
import socket
import socketserver
import sys


def reply(conn, code, text):
    try:
        conn.sendall(f"HTTP/1.1 {code} {text}\r\n\r\n".encode())
    except OSError:
        pass


def relay(client, upstream):
    open_socks = [client, upstream]
    try:
        while True:
            readable, _, _ = select.select(open_socks, [], [], 30)
            if not readable:
                return
            for sock in readable:
                chunk = sock.recv(65536)
                if not chunk:
                    return
                (upstream if sock is client else client).sendall(chunk)
    except OSError:
        pass
    finally:
        for sock in open_socks:
            try:
                sock.close()
            except OSError:
                pass


class Handler(socketserver.BaseRequestHandler):
    allow = frozenset()

    def handle(self):
        client = self.request
        client.settimeout(20)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buf += chunk
        except OSError:
            return

        try:
            request_line = buf.split(b"\r\n", 1)[0].decode("latin-1")
            method, target, _ = request_line.split(" ", 2)
        except ValueError:
            reply(client, 400, "Bad Request")
            return

        if method != "CONNECT":
            reply(client, 405, "Method Not Allowed")
            return

        host, sep, port = target.rpartition(":")
        if not sep or not port.isdigit():
            reply(client, 400, "Bad Request")
            return
        if host not in self.allow:
            print(f"deny  {host}:{port}", flush=True)
            reply(client, 403, "Forbidden")
            return

        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            print(f"error {host}:{port}", flush=True)
            reply(client, 502, "Bad Gateway")
            return

        print(f"allow {host}:{port}", flush=True)
        reply(client, 200, "Connection Established")
        relay(client, upstream)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18090)
    parser.add_argument("--allow", default="")
    opts = parser.parse_args()

    Handler.allow = frozenset(h.strip() for h in opts.allow.split(",") if h.strip())
    if not Handler.allow:
        print("proxy-allowlist: --allow needs at least one hostname", file=sys.stderr)
        return 2

    with Server(("127.0.0.1", opts.port), Handler) as server:
        print(
            f"listening on 127.0.0.1:{opts.port} allow={','.join(sorted(Handler.allow))}",
            flush=True,
        )
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
