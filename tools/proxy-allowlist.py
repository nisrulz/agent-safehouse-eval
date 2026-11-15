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
an unreachable upstream gets 502. The log prints one line per decision, with the
time, an ASCII status tag, the host, the port, and a repeat count:

    == proxy-allowlist ==========================================================
       listening on  http://127.0.0.1:18090
       allowed       11 hostnames, exact match
       log           one line per request, Ctrl-C to stop

       api.github.com                 pypi.org
       codeload.github.com            raw.githubusercontent.com
       ...

    == ready ===================================================================

    [12:03:41] [ok] github.com:443
    [12:03:42] [no] opencode.ai:443   host not in allowlist
    [12:03:44] [ok] github.com:443   #3

    == done: 3 allowed, 1 denied, 0 failed in 0m03s

Colour and bold are used only when stdout is a terminal and NO_COLOR is not set.
The ASCII tags and the column layout carry the same meaning without colour.

An upstream that resolves to a loopback, private, or link-local address is
refused: DNS for an allowlisted name must not become a path to host-local
services. Pass --allow-private when you really do want that.
"""

import argparse
import ipaddress
import os
import re
import select
import signal
import socket
import socketserver
import sys
import threading
import time

IDLE_TIMEOUT = 300  # seconds a tunnel may sit silent before it is dropped
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
HOSTNAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
)


def reply(conn, code, text):
    try:
        conn.sendall(f"HTTP/1.1 {code} {text}\r\n\r\n".encode())
    except OSError:
        pass


def paint(text, code):
    """Return text in an ANSI style when the terminal wants colour."""
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


PORT_RE = re.compile(r":(\d+)(?=\D|$)")


def mark_port(text):
    """Highlight the port number inside a host:port or a URL."""
    return PORT_RE.sub(lambda match: ":" + paint(match.group(1), "36;1"), text)


class Log:
    """Aligned, timestamped decision log with per-host and total counts."""

    STATUS = {
        "allow": ("[ok]", "32"),
        "deny": ("[no]", "31"),
        "error": ("[!!]", "33"),
    }
    SUBJECT_WIDTH = 36  # minimum width of the host column
    WIDTH = 80  # longest rendered line

    def __init__(self, out=None):
        self.out = out or sys.stdout
        self.lock = threading.Lock()
        self.counts = {}
        self.totals = {"allow": 0, "deny": 0, "error": 0}
        self.started = time.monotonic()

    def write(self, text):
        with self.lock:
            self._emit(text)

    def _emit(self, text):
        self.out.write(text)
        self.out.flush()

    def header(self, title):
        bar = "=" * max(0, self.WIDTH - len(title) - 4)
        return f"== {title} {bar}"

    def banner(self, host, port, hosts):
        names = sorted(hosts)
        noun = "hostname" if len(names) == 1 else "hostnames"
        column = max(len(name) for name in names) + 3
        columns = max(1, self.WIDTH // column)
        rows = -(-len(names) // columns)
        facts = [
            ("listening on", paint(f"http://{host}:", "1") + paint(str(port), "36;1")),
            ("allowed", f"{len(names)} {noun}, exact match"),
            ("log", "one line per request, Ctrl-C to stop"),
        ]
        lines = [self.header("proxy-allowlist")]
        lines += [f"   {label:<12}  {value}" for label, value in facts]
        lines.append("")
        for row in range(rows):
            cells = names[row::rows]
            lines.append("   " + "".join(name.ljust(column) for name in cells).rstrip())
        lines.append("")
        lines.append(self.header("ready"))
        self.write("\n".join(lines) + "\n\n")

    def decision(self, outcome, subject, note=""):
        label, style = self.STATUS[outcome]
        with self.lock:
            self.totals[outcome] += 1
            count = self.counts[subject] = self.counts.get(subject, 0) + 1
            pad = " " * max(0, self.SUBJECT_WIDTH - len(subject))
            extra = f"  #{count}" if count > 1 else ""
            if note:
                extra += f"  {note}"
            line = (
                f"[{paint(time.strftime('%H:%M:%S'), '2')}] "
                f"{paint(label, style)} "
                f"{mark_port(subject)}{pad}{extra}"
            )
            self._emit(line.rstrip() + "\n")

    def summary(self):
        elapsed = int(time.monotonic() - self.started)
        allowed, denied, failed = (self.totals[key] for key in self.STATUS)
        gap = "\n" if any(self.totals.values()) else ""
        self.write(
            f"{gap}== done: {allowed} allowed, {denied} denied, {failed} failed "
            f"in {elapsed // 60}m{elapsed % 60:02d}s\n"
        )


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
    log = Log()

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
            self.log.decision("deny", f"{method} {target}", "only CONNECT is served")
            reply(client, 405, "Method Not Allowed")
            return

        host, sep, port = target.rpartition(":")
        if not sep or not port.isdigit() or not 0 < int(port) < 65536:
            self.log.decision("deny", target, "bad host:port")
            reply(client, 400, "Bad Request")
            return
        host = host.strip("[]").lower().rstrip(".")

        if host not in self.allow:
            self.log.decision("deny", f"{host}:{port}", "host not in allowlist")
            reply(client, 403, "Forbidden")
            return

        try:
            upstream = connect_upstream(host, int(port), self.allow_private)
        except OSError as exc:
            reason = exc.strerror or str(exc)
            self.log.decision("error", f"{host}:{port}", f"upstream: {reason}")
            reply(client, 502, "Bad Gateway")
            return

        self.log.decision("allow", f"{host}:{port}")
        reply(client, 200, "Connection Established")
        client.settimeout(None)
        upstream.settimeout(None)
        relay(client, upstream)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def stop_on_signal(signum, frame):
    """Turn SIGTERM into the same clean stop as Ctrl-C."""
    raise KeyboardInterrupt


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

    Handler.log.banner(opts.host, opts.port, hosts)
    signal.signal(signal.SIGTERM, stop_on_signal)
    with server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    Handler.log.summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
