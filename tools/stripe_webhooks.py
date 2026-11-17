"""Loopback Stripe sandbox ingress and durable reconciliation queue."""

from contextlib import closing
import fcntl
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import sqlite3
import threading
import time

EVENTS = frozenset({
    "checkout.session.completed", "checkout.session.expired", "payment_intent.succeeded",
    "refund.created", "refund.updated", "refund.failed",
    "charge.dispute.created", "charge.dispute.updated", "charge.dispute.closed",
    "charge.dispute.funds_withdrawn", "charge.dispute.funds_reinstated",
})
RETRY = frozenset({"payment-pending", "dispute-pending"})
MAX_BODY = 2_000_000


def verified_event(body, header, secret, now):
    fields = [part.strip().partition("=") for part in header.split(",")]
    times = [value for key, sep, value in fields if key == "t" and sep]
    signatures = [value for key, sep, value in fields if key == "v1" and sep
                  and re.fullmatch(r"[0-9a-f]{64}", value)]
    if len(times) != 1 or not re.fullmatch(r"[0-9]{1,12}", times[0]) or abs(now - int(times[0])) > 300:
        raise ValueError("Invalid Stripe signature timestamp.")
    expected = hmac.new(secret, times[0].encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, value) for value in signatures):
        raise ValueError("Invalid Stripe signature.")
    event = json.loads(body)
    if (not isinstance(event, dict) or event.get("livemode") is not False
            or event.get("account") is not None or event.get("context") is not None
            or event.get("object") != "event" or not isinstance(event.get("id"), str)
            or not re.fullmatch(r"evt_[A-Za-z0-9]{1,128}", event["id"])
            or not isinstance(event.get("type"), str)):
        raise ValueError("Expected a Stripe sandbox account event.")
    return event["id"], event["type"]


class Inbox:
    def __init__(self, path):
        self.path = path
        with closing(self.connect()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS stripe_webhooks (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                due REAL NOT NULL, done INTEGER NOT NULL DEFAULT 0, outcome TEXT)""")
            db.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in db.execute("PRAGMA table_info(stripe_webhooks)")}
            for column, definition in (("deliveries", "INTEGER"), ("manual_retries", "INTEGER NOT NULL DEFAULT 0"),
                                       ("received_at", "REAL"), ("receipt_key", "TEXT")):
                if column not in columns:
                    db.execute(f"ALTER TABLE stripe_webhooks ADD COLUMN {column} {definition}")
            db.execute("CREATE INDEX IF NOT EXISTS stripe_webhooks_due ON stripe_webhooks(done, due)")

    def connect(self):
        return sqlite3.connect(self.path, timeout=3)

    def enqueue(self, event_id, kind):
        with closing(self.connect()) as db, db:
            now = time.time()
            result = db.execute("""INSERT INTO stripe_webhooks(id, kind, due, deliveries, received_at)
                VALUES (?, ?, ?, 1, ?) ON CONFLICT(id) DO UPDATE SET
                  deliveries = coalesce(stripe_webhooks.deliveries, 0) + 1, received_at = excluded.received_at
                WHERE stripe_webhooks.kind = excluded.kind""", (event_id, kind, now, now))
            if result.rowcount != 1:
                raise ValueError("Stripe reused the event identifier with another type.")

    def retry(self, event_id):
        with closing(self.connect()) as db, db:
            return db.execute("""UPDATE stripe_webhooks SET due = ?, manual_retries = manual_retries + 1
                WHERE id = ? AND done = 0 AND attempts > 0 AND due > ?""",
                (time.time(), event_id, time.time())).rowcount == 1

    def rows(self):
        with closing(self.connect()) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("""SELECT w.*,
                CASE WHEN accepted.value = 'true' THEN relay.value END AS receipt
                FROM stripe_webhooks w LEFT JOIN adapter accepted ON accepted.key = 'accepted:' || w.receipt_key
                LEFT JOIN adapter relay ON relay.key = 'relay:' || w.receipt_key
                ORDER BY coalesce(received_at, due) DESC, w.rowid DESC LIMIT 100""")]

    def process(self, reconcile):
        with closing(self.connect()) as db:
            row = db.execute("""SELECT id, kind, attempts FROM stripe_webhooks
                WHERE done = 0 AND due <= ? ORDER BY due, rowid LIMIT 1""", (time.time(),)).fetchone()
            if row is None:
                return False
            event_id, kind, attempts = row
            receipt_key = None
            try:
                result = reconcile(event_id, kind)
                outcome = result["status"]
                receipt_key = result.get("receiptKey")
            except (ValueError, KeyError, TypeError, RuntimeError, OSError, sqlite3.Error) as error:
                # Store the exception class only. Provider objects and credentials stay out of the inbox.
                outcome = "retry-" + type(error).__name__
            retry = outcome in RETRY or outcome.startswith("retry-")
            delay = min(300, 2 ** min(attempts, 9)) if retry else 0
            with db:
                db.execute("""UPDATE stripe_webhooks SET attempts = ?, due = ?, done = ?, outcome = ?,
                    receipt_key = coalesce(?, receipt_key) WHERE id = ?""",
                    (attempts + 1, time.time() + delay, not retry, outcome, receipt_key, event_id))
            return True


class Receiver:
    def __init__(self, port, journal, signing_secret, reconcile, view=None):
        if not re.fullmatch(r"whsec_[A-Za-z0-9_]+", signing_secret):
            raise ValueError("Expected a Stripe webhook signing secret.")
        self.inbox = Inbox(journal)
        self.worker_lock = journal.with_suffix(journal.suffix + ".webhooks.lock")
        self.secret = signing_secret.encode("ascii")
        self.reconcile = reconcile
        self.view = view
        self.shutdown = threading.Event()
        self.wakeup = threading.Event()
        self.server = ThreadingHTTPServer(("127.0.0.1", port), self.handler())
        self.port = self.server.server_address[1]

    def handler(self):
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                self.request.settimeout(5)
                super().setup()

            def log_message(self, _format, *_args):
                pass

            def reply(self, status):
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                if not receiver.view or not receiver.view.handle(self, receiver):
                    self.reply(404)

            def do_POST(self):
                if receiver.view and receiver.view.handle(self, receiver):
                    return
                if self.path != "/stripe/webhook":
                    self.reply(404)
                    return
                lengths = self.headers.get_all("Content-Length", [])
                signatures = self.headers.get_all("Stripe-Signature", [])
                if (len(lengths) != 1 or len(signatures) != 1 or self.headers.get("Transfer-Encoding")
                        or not re.fullmatch(r"[0-9]{1,8}", lengths[0])):
                    self.reply(400)
                    return
                length = int(lengths[0])
                if not 0 < length <= MAX_BODY:
                    self.reply(413)
                    return
                try:
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("Incomplete delivery.")
                    event_id, kind = verified_event(body, signatures[0], receiver.secret, time.time())
                    if kind in EVENTS:
                        receiver.inbox.enqueue(event_id, kind)
                        receiver.wakeup.set()
                except (ValueError, TypeError, TimeoutError):
                    self.reply(400)
                    return
                except sqlite3.Error:
                    self.reply(503)
                    return
                self.reply(200)

        return Handler

    def work(self):
        while not self.shutdown.is_set():
            try:
                if self.inbox.process(self.reconcile):
                    continue
            except sqlite3.Error:
                # If the state update failed, retry the retained item after the provider/ledger operation.
                pass
            self.wakeup.wait(0.5)
            self.wakeup.clear()

    def __enter__(self):
        self.lock = self.worker_lock.open("a")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            self.server.server_close()
            raise RuntimeError("A Stripe receiver already owns this journal.") from None
        self.worker = threading.Thread(target=self.work, daemon=True)
        self.http = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.http.start()
        return self

    def wait(self):
        self.http.join()

    def __exit__(self, *_exc):
        self.shutdown.set()
        self.wakeup.set()
        self.server.shutdown()
        self.http.join()
        self.server.server_close()
        self.worker.join()
        self.lock.close()
