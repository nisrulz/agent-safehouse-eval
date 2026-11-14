#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Hostname-allowlisting CONNECT proxy.

The sandbox closes egress and reopens a single loopback port, so this proxy is
the only way out and it decides which hostnames may be tunnelled. Run it on the
host, outside the sandbox.

Usage:
    uv run tools/proxy-allowlist.py --port 18090 --allow-file allowlist.txt
    uv run tools/proxy-allowlist.py --port 18090 --allow host1,host2

An allowlist file holds one hostname per line. Blank lines and everything from
`#` to end of line are ignored. Matching is exact and case-insensitive:
`github.com` does not cover `gist.github.com`, and there are no wildcards. A
line that is not a bare hostname (scheme, path, port, wildcard) is an error,
because a typo there would otherwise silently allow nothing.

Only CONNECT is served. Anything else gets 405, an unlisted host gets 403, and
an unreachable upstream gets 502. One line per decision goes to stdout:
`allow github.com:443`, `deny opencode.ai:443`, `error github.com:443`.

An upstream that resolves to a loopback, private, or link-local address is
refused: DNS for an allowlisted name must not become a path to host-local
services. Pass --allow-private when you really do want that.
"""

import argparse
import ipaddress
import re
import select
import socket
import socketserver
import sys

IDLE_TIMEOUT = 300  # seconds a tunnel may sit silent before it is dropped
HOSTNAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
)


def reply(conn, code, text):
    try:
        conn.sendall(f"HTTP/1.1 {code} {text}\r\n\r\n".encode())
    except OSError:
        pass


def parse_allowlist(text, origin):
    """Return the hostnames in an allowlist body, rejecting anything else."""
    hosts = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        host = line.lower().rstrip(".")
        if not HOSTNAME.fullmatch(host):
            raise ValueError(
                f"{origin}:{lineno}: expected a bare hostname, got {line!r}"
            )
        hosts.add(host)
    return hosts


def read_allowlist(path):
    with open(path, encoding="utf-8") as file:
        return parse_allowlist(file.read(), path)


def resolve_upstream(host, port, allow_private):
    """Resolve the upstream, refusing non-public addresses unless allowed."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not allow_private:
        for *_, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
            if not ip.is_global:
                raise OSError(f"{host} resolves to non-public {ip}")
    return infos


def connect_upstream(host, port, allow_private):
    last = OSError(f"no address for {host}")
    for family, type_, proto, _, sockaddr in resolve_upstream(
        host, port, allow_private
    ):
        sock = socket.socket(family, type_, proto)
        sock.settimeout(10)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last = exc
            sock.close()
    raise last


def relay(client, upstream):
    peers = {client: upstream, upstream: client}
    socks = list(peers)
    try:
        while True:
            readable, _, _ = select.select(socks, [], [], IDLE_TIMEOUT)
            if not readable:
                return
            for sock in readable:
                chunk = sock.recv(65536)
                if not chunk:
                    return
                peers[sock].sendall(chunk)
    except OSError:
        pass
    finally:
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass


class Handler(socketserver.BaseRequestHandler):
    allow = frozenset()
    allow_private = False

    def handle(self):
        client = self.request
        client.settimeout(20)
        request = b""
        try:
            while b"\r\n\r\n" not in request:
                chunk = client.recv(4096)
                if not chunk:
                    return
                request += chunk
        except OSError:
            return

        try:
            method, target, _ = (
                request.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
            )
        except ValueError:
            reply(client, 400, "Bad Request")
            return

        if method != "CONNECT":
            print(f"deny  {method} {target}", flush=True)
            reply(client, 405, "Method Not Allowed")
            return

        host, sep, port = target.rpartition(":")
        if not sep or not port.isdigit() or not 0 < int(port) < 65536:
            reply(client, 400, "Bad Request")
            return
        host = host.strip("[]").lower().rstrip(".")

        if host not in self.allow:
            print(f"deny  {host}:{port}", flush=True)
            reply(client, 403, "Forbidden")
            return

        try:
            upstream = connect_upstream(host, int(port), self.allow_private)
        except OSError as exc:
            print(f"error {host}:{port} {exc}", flush=True)
            reply(client, 502, "Bad Gateway")
            return

        print(f"allow {host}:{port}", flush=True)
        reply(client, 200, "Connection Established")
        client.settimeout(None)
        upstream.settimeout(None)
        relay(client, upstream)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(
        prog="proxy-allowlist",
        description="CONNECT proxy that tunnels only to allowlisted hostnames.",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=18090, help="bind port (default: 18090)"
    )
    parser.add_argument(
        "--allow-file",
        action="append",
        metavar="PATH",
        help="allowlist file, one hostname per line; repeatable",
    )
    parser.add_argument(
        "--allow",
        default="",
        metavar="HOST[,HOST]",
        help="hostnames to allow in addition to --allow-file",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="allow upstreams that resolve to loopback, private, or link-local addresses",
    )
    opts = parser.parse_args()

    if not 0 < opts.port < 65536:
        parser.error(f"--port must be 1-65535, got {opts.port}")

    hosts = set()
    try:
        for path in opts.allow_file or []:
            hosts |= read_allowlist(path)
        hosts |= parse_allowlist(opts.allow.replace(",", "\n"), "--allow")
    except (OSError, ValueError) as exc:
        print(f"proxy-allowlist: {exc}", file=sys.stderr)
        return 2
    if not hosts:
        parser.error("no hostnames: pass --allow-file PATH or --allow HOST[,HOST]")

    Handler.allow = frozenset(hosts)
    Handler.allow_private = opts.allow_private
    try:
        server = Server((opts.host, opts.port), Handler)
    except OSError as exc:
        print(
            f"proxy-allowlist: cannot listen on {opts.host}:{opts.port}: {exc}",
            file=sys.stderr,
        )
        return 1

    with server:
        print(
            f"listening on {opts.host}:{opts.port} allow={','.join(sorted(hosts))}",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
