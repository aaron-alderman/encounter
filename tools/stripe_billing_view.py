"""Private operator transport for the Encounter sandbox billing view."""

from contextlib import closing
from datetime import datetime
import hashlib
import hmac
import http.client
import json
import re
import sqlite3
import subprocess
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

VIEW = "/stripe/sandbox/billing/"
RETRY_PATH = VIEW + "retry"
TEMPLE_COOKIE = "__Host-encounter_" + hashlib.sha256(b"/identity-management").hexdigest()


class BillingView:
    def __init__(self, csrf_key, origin, workspace_port, runtime, billing):
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", csrf_key):
            raise ValueError("Expected a private CSRF key for the sandbox billing view.")
        if not isinstance(origin, str) or not re.fullmatch(r"https://[a-z0-9.-]+(?::[0-9]{1,5})?", origin):
            raise ValueError("Expected the sandbox billing HTTPS origin.")
        if not isinstance(workspace_port, int) or not 1 <= workspace_port <= 65535:
            raise ValueError("Expected a loopback AppDev Workspace port.")
        self.key = csrf_key.encode()
        self.origin = origin
        self.authority = urlsplit(origin).netloc
        self.workspace_port = workspace_port
        self.render_args = [runtime, "run", "--stdin", billing.parents[2],
                            "applications/appdev-projects/billing/stripe-billing-view.rel"]

    def token(self, event_id, session):
        message = f"stripe-billing-retry/{self.origin}/{session}/{event_id}"
        return hmac.new(self.key, message.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def session(headers):
        values = []
        for header in headers.get_all("Cookie", []):
            for field in header.split(";"):
                key, _, value = field.strip().partition("=")
                if key == TEMPLE_COOKIE:
                    values.append(value)
        if len(values) == 1 and re.fullmatch(r"[A-Za-z0-9_-]{1,192}", values[0]):
            return values[0]
        return None

    def platform_allowed(self, session):
        with closing(http.client.HTTPConnection("127.0.0.1", self.workspace_port, timeout=7)) as client:
            client.request("GET", "/workspace/access", headers={
                "Host": self.authority, "Cookie": f"{TEMPLE_COOKIE}={session}"})
            response = client.getresponse()
            if response.status != 200:
                raise RuntimeError("AppDev Workspace access check unavailable.")
            return json.loads(response.read(4096)).get("platform") is True

    def render(self, model):
        result = subprocess.run(self.render_args, input=json.dumps(model), capture_output=True,
                                text=True, check=True, timeout=10)
        return result.stdout.encode()

    def handle(self, handler, receiver):
        target = urlsplit(handler.path)
        if target.path not in (VIEW, RETRY_PATH):
            return False
        preferred = "GET" if target.path == VIEW else "POST"
        if handler.command != preferred:
            self.send(handler, 405, headers={"Allow": preferred})
            return True
        try:
            session = self.session(handler.headers)
            if not session or not self.platform_allowed(session):
                status = 403 if session else 401
                body = self.render({"signIn": True, "hasSession": bool(session)}) if target.path == VIEW else b""
                self.send(handler, status, body)
            elif target.path == VIEW:
                self.show(handler, receiver, target.query, session)
            else:
                self.retry(handler, receiver, session)
        except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError, http.client.HTTPException):
            self.send(handler, 503)
        return True

    def show(self, handler, receiver, query, session):
        rows = receiver.inbox.rows()
        for row in rows:
            row["csrf"] = self.token(row["id"], session) if not row["done"] and row["attempts"] else ""
            row["receipt"] = json.loads(row["receipt"]) if row["receipt"] else None
            row["received"] = (
                datetime.fromtimestamp(row["received_at"], ZoneInfo("Australia/Perth")).strftime("%d %b %H:%M AWST")
                if row["received_at"] else ""
            )
        self.send(handler, 200, self.render({"events": rows, "query": query}))

    def retry(self, handler, receiver, session):
        if (handler.headers.get_all("Origin") != [self.origin]
                or handler.headers.get_content_type() != "application/x-www-form-urlencoded"
                or handler.headers.get("Transfer-Encoding")):
            self.send(handler, 403)
            return
        lengths = handler.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,4}", lengths[0]) or not 0 < int(lengths[0]) <= 512:
            self.send(handler, 400)
            return
        fields = parse_qs(handler.rfile.read(int(lengths[0])).decode("ascii"), strict_parsing=True, max_num_fields=2)
        event_id, = fields.get("event", [""])
        token, = fields.get("csrf", [""])
        if (not re.fullmatch(r"evt_[A-Za-z0-9]{1,128}", event_id)
                or not re.fullmatch(r"[a-f0-9]{64}", token) or not hmac.compare_digest(token, self.token(event_id, session))):
            self.send(handler, 403)
            return
        queued = receiver.inbox.retry(event_id)
        if queued:
            receiver.wakeup.set()
        self.send(handler, 303, headers={"Location": VIEW + ("?retry=queued" if queued else "?retry=unavailable")
                                       + "#" + event_id})

    @staticmethod
    def send(handler, status, body=b"", headers=None):
        handler.send_response(status)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Referrer-Policy", "same-origin")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("X-Robots-Tag", "noindex")
        handler.send_header("Content-Security-Policy",
                            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
                            "frame-ancestors 'none'; form-action 'self'")
        for key, value in (headers or {}).items():
            handler.send_header(key, value)
        handler.end_headers()
        if body:
            handler.wfile.write(body)
