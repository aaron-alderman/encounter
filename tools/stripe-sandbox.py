"""Private I/O host for the Encounter Stripe sandbox declaration."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit

CORE = Path(__file__).resolve().parents[1]
BILLING = CORE.parent / "applications/appdev-projects/billing"
RUNTIME = CORE / "target/release/encounter"
STRIPE_API_VERSION = "2025-02-24.acacia"
KEY = re.compile(r"(?:sk_test|rk_test|rkcs_test)_[A-Za-z0-9]+")
COORDINATE = re.compile(r"[A-Za-z0-9_-]{1,64}")
ROUTE = re.compile(
    r"/v1/(?:checkout/sessions(?:/cs_test_[A-Za-z0-9]+)?"
    r"|payment_intents(?:/pi_[A-Za-z0-9]+)?|charges/ch_[A-Za-z0-9]+"
    r"|refunds(?:/re_[A-Za-z0-9]+)?|disputes/du_[A-Za-z0-9]+"
    r"|events/evt_[A-Za-z0-9]+)"
)


def digest(*values):
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_secret(path):
    with open(path, encoding="ascii") as stream:
        if os.fstat(stream.fileno()).st_mode & 0o077:
            raise ValueError("Use a private credential file with mode 0600.")
        return stream.read(1024).strip()


def exchange(connection, method, path, headers, params=None):
    try:
        body = None if params is None else urlencode(params)
        if body is not None:
            headers = {**headers, "Content-Type": "application/x-www-form-urlencoded"}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError("API response exceeded the adapter limit.")
        return response.status, response.getheader("Set-Cookie"), json.loads(data)
    finally:
        connection.close()


class Stripe:
    def __init__(self, key):
        if not KEY.fullmatch(key):
            raise ValueError("Only Stripe sandbox secret or restricted keys are accepted.")
        self.key = key

    def call(self, path, params=None, idempotency=None):
        if not ROUTE.fullmatch(path):
            raise ValueError("Stripe resource is outside the sandbox adapter routes.")
        headers = {"Authorization": "Bearer " + self.key, "Stripe-Version": STRIPE_API_VERSION}
        if params is not None:
            if not idempotency:
                raise ValueError("Stripe mutations require a durable idempotency key.")
            headers["Idempotency-Key"] = idempotency
        connection = http.client.HTTPSConnection("api.stripe.com", timeout=20, context=ssl.create_default_context())
        status, _, data = exchange(connection, "GET" if params is None else "POST", path, headers, params)
        if status == 402 and path == "/v1/payment_intents":
            data = data.get("error", {}).get("payment_intent") or {}
        elif not 200 <= status < 300:
            error = data.get("error", {}).get("code", "unknown")
            safe_code = error if isinstance(error, str) and re.fullmatch(r"[a-z0-9_]+", error) else "unknown"
            raise RuntimeError(f"Stripe request failed (HTTP {status}, {safe_code}).")
        if not isinstance(data, dict):
            raise ValueError("Stripe did not return a resource object.")
        refund_without_mode = (path.startswith("/v1/refunds") and data.get("object") == "refund"
                               and "livemode" not in data)
        if data.get("livemode") is not False and not refund_without_mode:
            raise ValueError("Stripe response did not identify a sandbox object.")
        return data


class Billing:
    def __init__(self, origin, token):
        parsed = urlsplit(origin)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
                or origin != f"http://127.0.0.1:{parsed.port}"):
            raise ValueError("Billing must be a private 127.0.0.1 listener.")
        self.port = parsed.port
        self.headers = {"Origin": origin, "Authorization": "Basic " + token}
        data, cookie = self.call("/session")
        self.csrf = data["csrf"]
        self.headers["Cookie"] = cookie.split(";", 1)[0]

    def call(self, route, params=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        status, cookie, data = exchange(connection, "GET" if params is None else "POST", route, self.headers, params)
        if status != 200 or isinstance(data, dict) and "error" in data:
            message = data.get("error", "request rejected") if isinstance(data, dict) else "request rejected"
            raise RuntimeError(f"Billing HTTP {status}: {message}")
        return data, cookie

    def read(self, route, account):
        return self.call(route + "?" + urlencode({"account": account}))[0]

    def send(self, command):
        encoded = encounter("encode", command=command)
        params = {"account": command["account"], "_csrf": self.csrf, "command": encoded}
        return self.call("/operations", params)[0]


def encounter(step, **data):
    result = subprocess.run([RUNTIME, "run", "--stdin", BILLING, "stripe-sandbox.rel"],
                            input=json.dumps({"step": step, **data}), capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)


class Journal:
    def __init__(self, path, scope):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS adapter (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        existing = self.get("scope")
        if existing is not None and existing != scope:
            raise ValueError("Use a separate journal for this sandbox key and billing store.")
        self.scope = scope
        self.put("scope", scope)

    def get(self, key):
        row = self.db.execute("SELECT value FROM adapter WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def find_binding(self, binding):
        if not isinstance(binding, str) or not re.fullmatch(r"[a-f0-9]{64}", binding):
            return None
        row = self.db.execute(
            "SELECT key, value FROM adapter WHERE key LIKE 'job:%' AND json_extract(value, '$.binding') = ?",
            (binding,)).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def put(self, key, value):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO adapter VALUES (?, ?)", (key, json.dumps(value)))


class Adapter:
    def __init__(self, stripe, billing, journal):
        self.stripe = stripe
        self.billing = billing
        self.journal = journal

    def post(self, key, request):
        record = self.journal.get("post:" + key)
        fingerprint = digest(request)
        if record:
            if record["fingerprint"] != fingerprint:
                raise ValueError("Stripe request changed for a retained operation.")
            if record.get("id"):
                return self.stripe.call(request["path"] + "/" + record["id"] if not key.startswith("evidence:")
                                        else request["path"])
            if time.time() - record["created"] >= 23 * 3600:
                raise ValueError("Stripe retry window elapsed. Reconcile this operation before attempting another.")
        else:
            record = {"fingerprint": fingerprint, "created": time.time()}
            self.journal.put("post:" + key, record)
        result = self.stripe.call(request["path"], request["params"], digest("stripe-sandbox", self.journal.scope, key))
        if not isinstance(result.get("id"), str):
            raise ValueError("Stripe did not return a resource ID. The operation remains pending.")
        self.journal.put("post:" + key, {**record, "id": result["id"]})
        return result

    def relay(self, key, account, action, fields):
        command = {"account": account, "operation": "stripe-" + digest(key)[:56], "action": action, "fields": fields}
        prior = self.journal.get("relay:" + key)
        if prior is not None and command != prior:
            raise ValueError("Attempted to change a retained Encounter command.")
        self.journal.put("relay:" + key, command)
        self.billing.send(command)
        self.journal.put("accepted:" + key, True)

    @staticmethod
    def job_key(account, intent):
        return "job:" + account + ":" + intent

    def run(self, args):
        key = self.job_key(args.account, args.intent)
        job = self.journal.get(key)
        if args.action != "sync":
            if job and job["method"] != args.action:
                raise ValueError("This intent is already assigned to a different Stripe operation.")
            if not job:
                job = self.create_job(args, key)
        if not job:
            raise ValueError("This intent has no Stripe sandbox job.")
        prior = self.journal.get("relay:" + key)
        if prior:
            self.billing.send(prior)
            self.journal.put("accepted:" + key, True)
            return {"status": prior["fields"]["outcome"], "reference": prior["fields"]["reference"]}
        if job["method"] == "refund" and not self.journal.get("post:" + key):
            if not any(item["intent"] == job["intent"] for item in self.billing.read("/settlement", args.account)):
                raise ValueError("Refund is no longer eligible for settlement.")
        obj = self.post(key, encounter("start", job=job))
        if getattr(args, "defer_to_webhooks", False):
            started = {"status": "awaiting-webhook", "reference": obj["id"]}
            if job["method"] == "checkout" and obj["status"] == "open":
                started["checkoutUrl"] = obj["url"]
            return started
        return self.reconcile(key, job, obj)

    def reconcile(self, key, job, obj):
        account = key.split(":")[1]
        method = job["method"]
        if method == "refund":
            charge = self.stripe.call("/v1/charges/" + job["originalCharge"])
            fields = encounter("refund", job=job, refund=obj, charge=charge)
        elif method == "checkout":
            if obj["status"] == "open":
                return {"status": "pending", "checkoutUrl": obj["url"], "session": obj["id"]}
            payment = self.stripe.call("/v1/payment_intents/" + obj["payment_intent"]) if obj.get("payment_intent") else None
            if obj["status"] == "expired":
                fields = encounter("expired", job=job, session=obj, payment=payment)
            elif obj["status"] == "complete" and obj["payment_status"] == "paid" and payment:
                fields = self.capture(job, payment)
            else:
                fields = None
        else:
            payment = obj
            fields = self.capture(job, payment) if payment["status"] == "succeeded" else None
        if fields is None:
            return {"status": "pending", "stripeStatus": obj["status"], "reference": obj["id"]}
        if fields["outcome"] == "confirmed" and method != "refund":
            if method == "checkout" and job.get("save"):
                self.journal.put("saved:" + key, {"customer": payment["customer"], "paymentMethod": payment["payment_method"]})
            self.journal.put("charge:" + fields["reference"], {"account": account, **fields})
        self.relay(key, account, "record-receipt", fields)
        return {"status": fields["outcome"], "reference": fields["reference"]}

    def capture(self, job, payment):
        charge = self.stripe.call("/v1/charges/" + payment["latest_charge"])
        return encounter("capture", job=job, payment=payment, charge=charge)

    def create_job(self, args, key):
        pending = self.billing.read("/settlement", args.account)
        intent = next((item["intent"] for item in pending if item["intent"]["id"] == args.intent), None)
        if intent is None:
            raise ValueError("No eligible pending settlement intent was found.")
        job = {"intent": intent, "method": args.action, "binding": digest("stripe-sandbox", self.journal.scope, key)}
        if args.action == "checkout":
            for url in (args.success_url, args.cancel_url):
                parsed = urlsplit(url)
                if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError("Stripe return URLs must be HTTPS without credentials.")
            job.update(successUrl=args.success_url, cancelUrl=args.cancel_url, save=args.save_for_subscription)
        elif args.action == "subscription":
            checkout = self.job_key(args.account, args.saved_checkout)
            payment = self.journal.get("relay:" + checkout)
            saved = self.journal.get("saved:" + checkout)
            if not saved or not payment or not self.journal.get("accepted:" + checkout):
                raise ValueError("A confirmed checkout with recorded off-session consent is required.")
            job.update(saved)
        else:
            original_key = self.job_key(args.account, intent.get("original") or "")
            original = self.journal.get("relay:" + original_key)
            if not original or not self.journal.get("accepted:" + original_key) or original["fields"]["outcome"] != "confirmed":
                raise ValueError("The original charge is missing from this Stripe journal.")
            job["originalCharge"] = original["fields"]["reference"]
        encounter("start", job=job)
        self.journal.put(key, job)
        return job

    def event(self, event_id, expected_type=None):
        key = "event:" + event_id
        prior = self.journal.get("relay:" + key)
        if prior:
            if not self.journal.get("accepted:" + key):
                self.billing.send(prior)
                self.journal.put("accepted:" + key, True)
            return {"status": "replayed", "event": prior["fields"]["event"], **({"receiptKey": key} if expected_type else {})}
        event = self.stripe.call("/v1/events/" + event_id)
        if event.get("id") != event_id or event.get("account") is not None:
            raise ValueError("Stripe event was not from the configured sandbox account.")
        kind = event.get("type", "")
        if expected_type is not None and kind != expected_type:
            raise ValueError("The signed event type differs from Stripe's Events API.")
        snapshot = event["data"]["object"]
        if not kind.startswith("charge.dispute."):
            return self.settlement_event(kind, snapshot)
        payment = self.journal.get("charge:" + snapshot["charge"])
        if not payment:
            charge = self.stripe.call("/v1/charges/" + snapshot["charge"])
            binding = charge.get("metadata", {}).get("encounter_binding")
            return {"status": "payment-pending" if self.journal.find_binding(binding) else "unmatched"}
        account = payment["account"]
        if not self.journal.get("accepted:" + self.job_key(account, payment["intent"])):
            return {"status": "payment-pending"}
        case = self.case(account, snapshot["id"])
        current = self.stripe.call("/v1/disputes/" + snapshot["id"])
        fields = encounter("dispute", event=event, dispute=current, payment=payment, case=case)
        if fields:
            self.relay(key, account, "record-dispute", fields)
            return {"status": "accepted", "event": fields["event"], **({"receiptKey": key} if expected_type else {})}
        if kind in ("charge.dispute.closed", "charge.dispute.funds_reinstated") and snapshot.get("status") in ("won", "lost"):
            if not case or case["status"] == "open":
                return {"status": "dispute-pending"}
        return {"status": "no-transition"}

    def settlement_event(self, kind, snapshot):
        jobs = {
            "checkout.session.completed": ("checkout", "/v1/checkout/sessions/"),
            "checkout.session.expired": ("checkout", "/v1/checkout/sessions/"),
            "payment_intent.succeeded": ("subscription", "/v1/payment_intents/"),
            "refund.created": ("refund", "/v1/refunds/"),
            "refund.updated": ("refund", "/v1/refunds/"),
            "refund.failed": ("refund", "/v1/refunds/"),
        }
        if kind not in jobs:
            return {"status": "ignored"}
        method, path = jobs[kind]
        if (method == "refund" and "livemode" in snapshot and snapshot["livemode"] is not False
                or method != "refund" and snapshot.get("livemode") is not False):
            raise ValueError("Stripe event resource is not a sandbox object.")
        match = self.journal.find_binding(snapshot.get("metadata", {}).get("encounter_binding"))
        if not match or match[1]["method"] != method:
            return {"status": "unmatched"}
        key, job = match
        record = self.journal.get("post:" + key)
        if not record:
            return {"status": "payment-pending"}
        resource = snapshot["id"]
        if record.get("id") and record["id"] != resource:
            raise ValueError("Stripe event refers to a different resource for the intent.")
        prior = self.journal.get("relay:" + key)
        if prior:
            if not self.journal.get("accepted:" + key):
                self.billing.send(prior)
                self.journal.put("accepted:" + key, True)
            return {"status": "replayed", "receiptKey": key}
        current = self.stripe.call(path + resource)
        if current.get("id") != resource or current.get("metadata", {}).get("encounter_binding") != job["binding"]:
            raise ValueError("Stripe resource no longer matches the active intent.")
        if not record.get("id"):
            self.journal.put("post:" + key, {**record, "id": resource})
        result = self.reconcile(key, job, current)
        # A later provider event advances a resource that is still legitimately pending.
        return {"status": "waiting-for-provider"} if result["status"] == "pending" else {**result, "receiptKey": key}

    def case(self, account, dispute_id):
        return next((item["dispute"] for item in self.billing.read("/disputes", account)
                     if item["dispute"]["id"] == dispute_id), None)

    def evidence(self, args):
        case = self.case(args.account, args.case)
        dispute = self.stripe.call("/v1/disputes/" + args.case)
        with args.text.open("rb") as stream:
            text = stream.read(20_001)
        if len(text) > 20_000:
            raise ValueError("The sandbox evidence text exceeds 20,000 bytes.")
        request = encounter("evidence", case=case, dispute=dispute, evidenceId=args.evidence_id,
                            text=text.decode("utf-8"), now=int(time.time()), submit=args.submit)
        key = "evidence:" + digest(args.account, args.case, args.evidence_id, args.submit)
        result = self.post(key, request)
        return {"case": result["id"], "status": result["status"],
                "submissionCount": result["evidence_details"]["submission_count"]}


@contextmanager
def journal_lock(path):
    with path.with_suffix(path.suffix + ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def coordinate(value):
    if not COORDINATE.fullmatch(value):
        raise argparse.ArgumentTypeError("Expected a billing coordinate.")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--billing-token-file", type=Path, required=True, help="Base64 private settlement credential")
    parser.add_argument("--ledger", required=True, help="Explicit identity of the disposable billing store")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--journal", type=Path, required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("checkout", "subscription", "refund", "sync"):
        command = commands.add_parser(name)
        command.add_argument("account", type=coordinate)
        command.add_argument("intent", type=coordinate)
        if name != "sync":
            command.add_argument("--defer-to-webhooks", action="store_true")
        if name == "checkout":
            command.add_argument("--success-url", required=True)
            command.add_argument("--cancel-url", required=True)
            command.add_argument("--save-for-subscription", action="store_true", help="Customer has authorized off-session billing")
        if name == "subscription":
            command.add_argument("--saved-checkout", type=coordinate, required=True)
    commands.add_parser("event").add_argument("event_id")
    evidence = commands.add_parser("evidence")
    evidence.add_argument("account", type=coordinate)
    evidence.add_argument("case")
    evidence.add_argument("evidence_id")
    evidence.add_argument("text", type=Path)
    evidence.add_argument("--submit", action="store_true", help="Approved sandbox submission, including staged fields")
    webhooks = commands.add_parser("serve-webhooks")
    webhooks.add_argument("--port", type=int, required=True)
    webhooks.add_argument("--signing-secret-file", type=Path, required=True)
    webhooks.add_argument("--billing-view-csrf-key-file", type=Path)
    webhooks.add_argument("--billing-view-origin")
    webhooks.add_argument("--billing-view-workspace-port", type=int)
    args = parser.parse_args()
    os.umask(0o077)
    stripe = Stripe(read_secret(args.key_file))
    token = read_secret(args.billing_token_file)
    scope = digest(stripe.key, args.ledger, args.origin)
    if args.action == "serve-webhooks":
        from stripe_webhooks import Receiver
        def reconcile(event_id, kind):
            with journal_lock(args.journal):
                journal = Journal(args.journal, scope)
                try:
                    return Adapter(stripe, Billing(args.origin, token), journal).event(event_id, kind)
                finally:
                    journal.db.close()
        with journal_lock(args.journal):
            Journal(args.journal, scope).db.close()
        view = None
        view_settings = (args.billing_view_csrf_key_file, args.billing_view_origin, args.billing_view_workspace_port)
        if any(value is not None for value in view_settings):
            if any(value is None for value in view_settings):
                raise ValueError("Billing view requires a CSRF key, origin and Workspace port.")
            from stripe_billing_view import BillingView
            view = BillingView(read_secret(args.billing_view_csrf_key_file), args.billing_view_origin,
                               args.billing_view_workspace_port, RUNTIME, BILLING)
        receiver = Receiver(args.port, args.journal, read_secret(args.signing_secret_file), reconcile, view=view)
        with receiver:
            receiver.wait()
        return
    billing = Billing(args.origin, token)
    with journal_lock(args.journal):
        journal = Journal(args.journal, scope)
        adapter = Adapter(stripe, billing, journal)
        if args.action == "event":
            result = adapter.event(args.event_id)
            result.pop("receiptKey", None)
        elif args.action == "evidence":
            result = adapter.evidence(args)
        else:
            result = adapter.run(args)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, sqlite3.Error, KeyError) as error:
        sys.exit(str(error))
