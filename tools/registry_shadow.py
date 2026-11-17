"""Import one finished Registry Demo console observation into sandbox billing."""

import argparse
import base64
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlencode

SPEC = importlib.util.spec_from_file_location("stripe_sandbox", Path(__file__).with_name("stripe-sandbox.py"))
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)
ROLE_FILES = ("identity", "catalog", "member", "scheduler", "meter", "settlement")


def plan(spool, session):
    if not re.fullmatch(r"vm-[a-f0-9]{48}", session):
        raise ValueError("Expected the Registry Demo console session ID.")
    root = spool.lstat()
    if not stat.S_ISDIR(root.st_mode) or root.st_mode & 0o077 or root.st_uid != os.geteuid():
        raise ValueError("Use the private spool owned by the Registry Demo host.")
    fd = os.open(spool / (session + ".rel"), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as observation:
        meta = os.fstat(observation.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_uid != root.st_uid:
            raise ValueError("The observation must be a private record from the Registry Demo host.")
        data = observation.read(4097)
        if len(data) > 4096:
            raise ValueError("Registry Demo observation exceeds its wire size.")
    result = subprocess.run([HOST.RUNTIME, "run", "--stdin", HOST.BILLING, "registry-shadow.rel"],
                            input=data, capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError(result.stderr.decode().strip())
    model = json.loads(result.stdout)
    if model["observation"]["id"] != session:
        raise ValueError("Observation ID does not match its durable session coordinate.")
    return model


class Journey:
    def __init__(self, model, origin, credentials):
        self.model = model
        self.account = model["account"]
        self.origin = origin
        tokens = {role: HOST.read_secret(credentials / (role + ".key")) for role in ROLE_FILES}
        member_id = base64.b64decode(tokens["member"], validate=True).decode().split(":", 1)[0]
        if member_id != model["principal"]:
            raise ValueError("The billing member must be the verified AppDev principal for this console.")
        self.roles = {role: HOST.Billing(origin, token) for role, token in tokens.items()}

    def send(self, command):
        role = command["role"]
        self.roles[role].send({"account": self.account, **{key: command[key] for key in ("operation", "action", "fields")}})

    def view(self):
        return self.roles["member"].read("/account", self.account)

    def entitlement(self):
        query = urlencode({"account": self.account, "subscription": self.model["subscription"]})
        return self.roles["member"].call("/entitlement?" + query)[0]

    def invoice(self):
        if time.time() < self.model["closeAt"]:
            return {"status": "waiting-for-period-end", "closeAt": self.model["closeAt"]}
        for command in self.model["commands"]:
            self.send(command)
        renewed = self.model["renewal"]
        self.send(renewed)
        view = self.view()
        session = self.model["observation"]
        return {"status": "invoiced", "account": self.account, "session": session["id"],
                "usage": view["usage"][session["id"]],
                "invoice": view["invoices"][self.model["invoice"]], "entitlement": self.entitlement()}

    def checkout(self, stripe, journal_path, ledger, success, cancel):
        invoice = self.view()["invoices"][self.model["invoice"]]
        self.send({"role": "member", "operation": self.model["intent"], "action": "request-payment",
                   "fields": {"intent": self.model["intent"], "invoice": self.model["invoice"],
                              "rail": "card", "amount": invoice["total"]}})
        return self.adapter(stripe, journal_path, ledger, "checkout", success_url=success, cancel_url=cancel,
                            save_for_subscription=False)

    def settle(self, stripe, journal_path, ledger):
        settled = self.adapter(stripe, journal_path, ledger, "sync")
        if settled["status"] != "confirmed":
            return settled
        view = self.view()
        return {**settled, "invoice": view["invoices"][self.model["invoice"]],
                "receipt": next(receipt for receipt in view["receipts"].values()
                                if receipt["intent"] == self.model["intent"]),
                "entitlement": self.entitlement()}

    def adapter(self, stripe, journal_path, ledger, action, **options):
        with HOST.journal_lock(journal_path):
            journal = HOST.Journal(journal_path, HOST.digest(stripe.key, ledger, self.origin))
            with closing(journal.db):
                adapter = HOST.Adapter(stripe, self.roles["settlement"], journal)
                return adapter.run(SimpleNamespace(action=action, account=self.account,
                                                   intent=self.model["intent"], **options))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--session", required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("preview")
    for name in ("invoice", "checkout", "settle"):
        command = commands.add_parser(name)
        command.add_argument("--origin", required=True)
        command.add_argument("--credentials", type=Path, required=True)
        if name != "invoice":
            command.add_argument("--stripe-key-file", type=Path, required=True)
            command.add_argument("--journal", type=Path, required=True)
            command.add_argument("--ledger", required=True)
        if name == "checkout":
            command.add_argument("--success-url", required=True)
            command.add_argument("--cancel-url", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    model = plan(args.spool, args.session)
    if args.action == "preview":
        result = {key: model[key] for key in ("account", "observation", "invoice", "closeAt")}
    else:
        journey = Journey(model, args.origin, args.credentials)
        if args.action == "invoice":
            result = journey.invoice()
        else:
            stripe = HOST.Stripe(HOST.read_secret(args.stripe_key_file))
            if args.action == "checkout":
                result = journey.checkout(stripe, args.journal, args.ledger, args.success_url, args.cancel_url)
            else:
                result = journey.settle(stripe, args.journal, args.ledger)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        sys.exit(str(error))
