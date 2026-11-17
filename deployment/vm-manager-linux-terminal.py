"""Connect a private VM Manager socket to the Linux guest's fixed Workspace Terminal."""

import argparse
import errno
import fcntl
import os
import pty
import selectors
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import termios
from pathlib import Path

HEADER = struct.Struct("!BH")
SIZE = struct.Struct("!HH")


def tls_context(directory, server):
    role = "guest" if server else "manager"
    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH,
        cafile=str(directory / ("manager.pem" if server else "guest.pem")),
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(directory / f"{role}.pem", directory / f"{role}.key")
    return context


def relay(client, endpoint, consume):
    with selectors.DefaultSelector() as selector:
        selector.register(client, selectors.EVENT_READ)
        selector.register(endpoint, selectors.EVENT_READ)
        while True:
            if isinstance(endpoint, ssl.SSLSocket) and endpoint.pending():
                ready = [endpoint]
            elif isinstance(client, ssl.SSLSocket) and client.pending():
                ready = [client]
            else:
                ready = [key.fileobj for key, _ in selector.select(timeout=45)]
            if not ready:
                # The browser relay sends authenticated keepalives during idle periods.
                break
            for source in ready:
                if source is client:
                    data = client.recv(16384)
                    if not data:
                        return
                    consume(data)
                elif not isinstance(endpoint, int):
                    data = endpoint.recv(16384)
                    if not data:
                        return
                    client.sendall(data)
                else:
                    try:
                        data = os.read(endpoint, 16384)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            return
                        raise
                    if not data:
                        return
                    client.sendall(data)


class GuestTerminal(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            with self.server.tls.wrap_socket(self.request, server_side=True) as client:
                self.terminal(client)
        except (OSError, ValueError):
            return

    def terminal(self, client):
        pid, master = pty.fork()
        if not pid:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            os.chdir("/")
            os.execve("/bin/encounter", ["encounter", "sourcery-workspace", self.server.origin],
                      {"PATH": "/bin", "HOME": "/", "TERM": "xterm-256color", "LANG": "C.UTF-8"})
        pending = bytearray()

        def consume(data):
            pending.extend(data)
            while len(pending) >= HEADER.size:
                kind, length = HEADER.unpack_from(pending)
                if length > 8192:
                    raise ValueError("Oversize terminal input")
                end = HEADER.size + length
                if len(pending) < end:
                    break
                body = pending[HEADER.size:end]
                del pending[:end]
                if kind == 0:
                    os.set_blocking(master, False)
                    if os.write(master, body) != length:
                        raise ValueError("Guest terminal input buffer is full")
                elif kind == 1 and length == SIZE.size:
                    rows, columns = SIZE.unpack(body)
                    if not (1 <= rows <= 240 and 1 <= columns <= 512):
                        raise ValueError("Invalid terminal dimensions")
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
                elif kind != 2 or length:
                    raise ValueError("Invalid terminal message")

        try:
            relay(client, master, consume)
        finally:
            os.close(master)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


class ManagerTerminal(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as upstream:
                with self.server.tls.wrap_socket(upstream, server_hostname="linux-dev") as guest:
                    self.request.sendall(b"\x01")
                    relay(self.request, guest, guest.sendall)
        except OSError:
            return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=["guest", "manager"])
    parser.add_argument("port", type=int)
    parser.add_argument("certificates", type=Path)
    parser.add_argument("origin_or_socket")
    args = parser.parse_args()
    guest = args.role == "guest"
    tls = tls_context(args.certificates, guest)
    if guest:
        with socketserver.TCPServer(("0.0.0.0", args.port), GuestTerminal) as server:
            server.tls = tls
            server.origin = args.origin_or_socket
            server.serve_forever()
        return
    path = Path(args.origin_or_socket)
    with socketserver.UnixStreamServer(str(path), ManagerTerminal) as server:
        server.tls = tls
        server.port = args.port
        path.chmod(0o660)
        try:
            server.serve_forever()
        finally:
            path.unlink()


if __name__ == "__main__":
    main()
