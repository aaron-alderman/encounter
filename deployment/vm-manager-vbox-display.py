"""Provide one configured VirtualBox guest's framebuffer, keyboard and mouse over a private Unix socket."""

import argparse
from pathlib import Path
import socketserver
import subprocess
import tempfile
import time
import uuid

KEYS = {}
for start, row in (
    (0x02, "Digit1 Digit2 Digit3 Digit4 Digit5 Digit6 Digit7 Digit8 Digit9 Digit0 Minus Equal Backspace"),
    (0x10, "KeyQ KeyW KeyE KeyR KeyT KeyY KeyU KeyI KeyO KeyP BracketLeft BracketRight Enter"),
    (0x1E, "KeyA KeyS KeyD KeyF KeyG KeyH KeyJ KeyK KeyL Semicolon Quote Backquote"),
    (0x2B, "Backslash KeyZ KeyX KeyC KeyV KeyB KeyN KeyM Comma Period Slash"),
    (0x3B, "F1 F2 F3 F4 F5 F6 F7 F8 F9 F10"),
    (0x57, "F11 F12"),
):
    for scan, key in enumerate(row.split(), start):
        KEYS[key] = (scan,)
KEYS.update(Escape=(1,), Space=(0x39,))
for key, scan in {"Home": 0x47, "ArrowUp": 0x48, "ArrowLeft": 0x4B,
                  "ArrowRight": 0x4D, "End": 0x4F, "ArrowDown": 0x50, "Delete": 0x53}.items():
    KEYS[key] = (0xE0, scan)


class GuestMouse:
    def __init__(self, guest):
        self.guest = guest
        self.manager = None
        self.vbox_error = RuntimeError
        self.position = None
        self.buttons = 0
        self.size = None

    def set_frame(self, image):
        if len(image) < 24 or not image.startswith(b"\x89PNG\r\n\x1a\n"):
            return False
        width = int.from_bytes(image[16:20], "big")
        height = int.from_bytes(image[20:24], "big")
        if not (0 < width <= 8192 and 0 < height <= 8192):
            return False
        size = (width, height)
        if size != self.size:
            self.reset()
            self.size = size
        return True

    def send(self, x, y, buttons):
        if self.size is None:
            return False
        width, height = self.size
        if not (0 <= x < width and 0 <= y < height and 0 <= buttons <= 7):
            return False
        if self.position == (x, y) and self.buttons == buttons:
            return True
        try:
            self.with_mouse(lambda mouse: self.move(mouse, x, y, buttons))
        except self.vbox_error:
            self.position = None
            return False
        return True

    def reset(self):
        if self.buttons:
            try:
                self.with_mouse(self.release_buttons)
            except self.vbox_error:
                return False
            self.buttons = 0
        self.position = None
        return True

    def release_buttons(self, mouse):
        if mouse.absoluteSupported and self.position is not None:
            x, y = self.position
            mouse.putMouseEventAbsolute(x + 1, y + 1, 0, 0, 0)
        else:
            mouse.putMouseEvent(0, 0, 0, 0, 0)

    def with_mouse(self, action):
        from vboxapi import VirtualBoxManager

        if self.manager is None:
            self.manager = VirtualBoxManager(None, None)
            from xpcom import Exception as VBoxError
            self.vbox_error = VBoxError
        machine = self.manager.getVirtualBox().findMachine(self.guest)
        session = self.manager.openMachineSession(machine)
        try:
            action(session.console.mouse)
        finally:
            self.manager.closeMachineSession(session)

    def move(self, mouse, x, y, buttons):
        absolute = mouse.absoluteSupported
        if absolute:
            self.position = (x, y)
            self.buttons = buttons
            mouse.putMouseEventAbsolute(x + 1, y + 1, 0, 0, buttons)
        else:
            if self.position is None:
                # PS/2 guests clamp at the screen edge. Establish the origin
                # before converting browser coordinates into relative packets.
                self.relative(mouse, -self.size[0], -self.size[1])
                self.position = (0, 0)
            self.relative(mouse, x - self.position[0], y - self.position[1])
            if buttons != self.buttons:
                self.buttons = buttons
                mouse.putMouseEvent(0, 0, 0, 0, buttons)
        self.position = (x, y)

    def relative(self, mouse, dx, dy):
        while dx or dy:
            step_x = max(-120, min(dx, 120))
            step_y = max(-120, min(dy, 120))
            mouse.putMouseEvent(step_x, step_y, 0, 0, self.buttons)
            dx -= step_x
            dy -= step_y
            # Keep PS/2 packets within range even when the browser jumps
            # across the display between two events.
            time.sleep(0.012)


class Display(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            request = self.rfile.read(64).decode("ascii")
            if request == "frame":
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "frame.png"
                    self.vbox("screenshotpng", str(output))
                    with output.open("rb") as image:
                        data = image.read(4 * 1024 * 1024 + 1)
                    if len(data) <= 4 * 1024 * 1024 and self.server.mouse.set_frame(data):
                        self.wfile.write(data)
            elif request.startswith("key "):
                key = request[4:]
                shifted = key.startswith("Shift+")
                scan = KEYS.get(key.removeprefix("Shift+"))
                if scan is None:
                    return
                release = (*scan[:-1], scan[-1] | 0x80)
                codes = (0x2A, *scan, *release, 0xAA) if shifted else (*scan, *release)
                self.vbox("keyboardputscancode", *(f"{code:02x}" for code in codes))
                self.wfile.write(b"ok")
            elif request == "mouse reset":
                if self.server.mouse.reset():
                    self.wfile.write(b"ok")
            elif request.startswith("mouse "):
                fields = request[6:].split(" ")
                if len(fields) == 3 and all(field.isdecimal() and len(field) <= 4 for field in fields):
                    if self.server.mouse.send(*map(int, fields)):
                        self.wfile.write(b"ok")
        except (OSError, UnicodeError, subprocess.SubprocessError):
            return

    def vbox(self, operation, *args):
        subprocess.run(
            ["/usr/bin/VBoxManage", "controlvm", self.server.guest, operation, *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True, timeout=2,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket", type=Path)
    parser.add_argument("guest", type=uuid.UUID)
    args = parser.parse_args()
    # The operator supplies a private parent directory and sets its group for AppDev.
    # Bind under the caller's umask and fail if the path already exists.
    with socketserver.UnixStreamServer(str(args.socket), Display) as server:
        server.guest = str(args.guest)
        server.mouse = GuestMouse(server.guest)
        args.socket.chmod(0o660)
        try:
            server.serve_forever()
        finally:
            args.socket.unlink()


if __name__ == "__main__":
    main()
