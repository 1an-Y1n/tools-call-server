#!/usr/bin/env python3
"""End-to-end check of the email-identity account flow against a temp DB.

Starts a throwaway SMTP sink (so the invite mail can be captured), boots the
server on a spare port, and drives it with plain HTTP calls.
"""
import base64
import json
import os
import re
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DB = "/tmp/tcs-e2e.db"
PORT = 18765
SMTP_PORT = 2527
MESSAGES = []
FAILURES = []


class MailSink(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 sink\r\n")
        data_mode = False
        buf = []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if data_mode:
                if line.strip() == b".":
                    MESSAGES.append(b"".join(buf).decode("utf-8", "replace"))
                    buf, data_mode = [], False
                    self.wfile.write(b"250 ok\r\n")
                else:
                    buf.append(line)
                continue
            cmd = line.strip().upper()
            if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                self.wfile.write(b"250-sink\r\n250 8BITMIME\r\n")
            elif cmd.startswith(b"MAIL") or cmd.startswith(b"RCPT"):
                self.wfile.write(b"250 ok\r\n")
            elif cmd.startswith(b"DATA"):
                data_mode = True
                self.wfile.write(b"354 go\r\n")
            elif cmd.startswith(b"QUIT"):
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


class SinkServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def mail_html(message):
    """Decode the text/html part of a MIME message."""
    message = message.replace("\r\n", "\n")
    marker = 'Content-Type: text/html; charset="utf-8"'
    idx = message.find(marker)
    if idx < 0:
        return message
    rest = message[idx + len(marker):]
    head, sep, payload = rest.partition("\n\n")
    if not sep:
        return message
    if "base64" in head:
        payload = payload.split("\n--==")[0]
        return base64.b64decode("".join(payload.split())).decode("utf-8", "replace")
    return payload


def password_from(message):
    m = re.search(r"<code[^>]*>([^<]{8,})</code>", mail_html(message))
    return m.group(1).strip() if m else ""


def http(method, path, body=None, cookie=None, raw=None):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = raw.encode() if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/x-ndjson" if raw is not None else "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers.get("Set-Cookie")


def post_event(email, user="alice", n=1):
    lines = [json.dumps({
        "schema_version": 1, "type": "tool_call",
        "timestamp": f"2026-11-0{1 + i}T10:00:00Z",
        "client_id": "c1", "user": user, "name": "Alice", "email": email,
        "session_id": f"s{i}", "tool_name": "read_file", "status": "success",
    }) for i in range(n)]
    return http("POST", "/v1/events", raw="\n".join(lines))


def login(name, pw):
    st, body, cookie = http("POST", "/login", {"username": name, "password": pw})
    return st, body, (cookie or "").split(";")[0]


def wait_mail(count=1, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline and len(MESSAGES) < count:
        time.sleep(0.2)
    return list(MESSAGES)


def main():
    for p in (DB, DB + "-wal", DB + "-shm"):
        if os.path.exists(p):
            os.remove(p)
    global SMTP_PORT
    sink = SinkServer(("127.0.0.1", 0), MailSink)
    SMTP_PORT = sink.server_address[1]
    threading.Thread(target=sink.serve_forever, daemon=True).start()

    env = dict(os.environ, TOOL_CALL_SERVER_DB=DB, SESSION_SECRET="test-secret")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1",
         "--port", str(PORT), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(80):
            try:
                http("GET", "/health")
                break
            except Exception:
                time.sleep(0.25)
        else:
            print("server did not start")
            print(proc.stdout.read() if proc.stdout else "")
            return 1

        def check(label, cond, extra=""):
            print(("PASS " if cond else "FAIL ") + label +
                  ((" :: " + str(extra)[:300]) if extra and not cond else ""))
            if not cond:
                FAILURES.append(label)

        # --- admin login + SMTP config
        st, body, admin = login("SUPER_ADMIN", "SUPER_ADMIN")
        check("super admin login", st == 200, body)
        st, body, _ = http("POST", "/admin/smtp", {
            "host": "127.0.0.1", "port": SMTP_PORT, "user": "bot@corp.com",
            "password": "", "security": "none", "email_allowlist": ""}, admin)
        check("smtp saved", st == 200, body)

        # --- first record provisions an account and mails a password once
        st, body, _ = post_event("Alice@Corp.com", user="alice")
        check("ingest accepted", st == 200 and json.loads(body)["accepted"] == 1, body)
        msgs = wait_mail(1)
        check("invite mail sent", len(msgs) == 1, f"{len(msgs)} messages")
        mail = msgs[0] if msgs else ""
        check("mail addressed to lowercased email", "alice@corp.com" in mail, mail[:200])
        password = password_from(mail)
        check("password present in mail", bool(password), mail[:400])

        st, body, _ = http("GET", "/admin/users", None, admin)
        users = json.loads(body)["users"] if st == 200 else []
        alice = next((u for u in users if u["username"] == "alice@corp.com"), None)
        check("account created with email as name", alice is not None, users)
        if alice:
            check("role is user", alice["role"] == "user", alice)
            check("must change password", alice["must_change_password"] is True, alice)
            check("invite timestamp set", bool(alice["invite_sent_at"]), alice)
            check("event count attached", alice["event_count"] == 1, alice)

        # --- login with the mailed password, then the forced change
        st, body, alice_cookie = login("alice@corp.com", password)
        check("login with mailed password", st == 200, body)
        check("login reports must_change",
              json.loads(body).get("must_change_password") is True if st == 200 else False, body)

        st, body, _ = http("GET", "/dashboard", None, alice_cookie)
        check("dashboard redirects to change form", "f-change" in body, body[:160])

        st, body, _ = http("POST", "/me/password",
                           {"old_password": password, "new_password": "my-own-pass-1"}, alice_cookie)
        check("password change accepted", st == 200, body)
        st, body, _ = http("GET", "/dashboard", None, alice_cookie)
        check("dashboard reachable after change", "f-change" not in body, body[:160])
        check("manage tab hidden for regular user",
              'id="tab-manage" style="display:none"' in body, body[:200])

        # --- a second record with the same email never mails again
        MESSAGES.clear()
        post_event("alice@corp.com", n=2)
        time.sleep(2.0)
        check("no second invite for known address", len(MESSAGES) == 0, MESSAGES)

        # --- allowlist gates new accounts but not ingestion
        http("POST", "/admin/smtp", {"email_allowlist": "corp.com"}, admin)
        MESSAGES.clear()
        st, body, _ = post_event("bob@other.com", user="bob")
        check("blocked address still ingested", json.loads(body)["accepted"] == 1, body)
        time.sleep(1.5)
        check("blocked address gets no mail", len(MESSAGES) == 0, MESSAGES)
        st, body, _ = http("GET", "/admin/users", None, admin)
        names = [u["username"] for u in json.loads(body)["users"]]
        check("blocked address has no account", "bob@other.com" not in names, names)
        post_event("carol@corp.com", user="carol", n=1)
        check("allowlisted domain still provisions", len(wait_mail(1)) == 1, MESSAGES)
        http("POST", "/admin/smtp", {"email_allowlist": ""}, admin)

        # --- admin reset issues a new password by mail
        MESSAGES.clear()
        st, body, _ = http("POST", "/admin/users/alice%40corp.com/password", {}, admin)
        check("reset accepted", st == 200, body)
        msgs = wait_mail(1)
        check("reset mail sent", len(msgs) == 1, msgs)
        new_password = password_from(msgs[0]) if msgs else ""
        check("reset password differs", bool(new_password) and new_password != password, new_password)
        st, body, _ = login("alice@corp.com", "my-own-pass-1")
        check("old password rejected after reset", st == 401, body)
        st, body, alice_cookie = login("alice@corp.com", new_password)
        check("reset password works", st == 200, body)

        # --- roles: two tiers, and the last admin is never removable
        st, body, _ = http("POST", "/admin/users/alice%40corp.com/role", {"role": "admin"}, admin)
        check("promote to admin", st == 200, body)
        st, body, _ = http("POST", "/admin/users/alice%40corp.com/role",
                           {"role": "super_admin"}, admin)
        check("unknown role rejected", st == 400, body)
        st, body, _ = http("POST", "/admin/users/alice%40corp.com/role", {"role": "user"}, admin)
        check("demote works while another admin remains", st == 200, body)
        # SUPER_ADMIN is now the only admin, and it is the caller: every route
        # that could empty the admin list is refused (self-check first, the
        # last-admin guard is the second line of defence).
        for path, payload, label in (
            ("/admin/users/SUPER_ADMIN/role", {"role": "user"}, "cannot demote the last admin"),
            ("/admin/users/SUPER_ADMIN/delete", {}, "cannot delete the last admin"),
            ("/admin/users/SUPER_ADMIN/status", {"status": "disabled"},
             "cannot disable the last admin"),
        ):
            st, body, _ = http("POST", path, payload, admin)
            check(label, st == 400, body)
        st, body, _ = http("GET", "/admin/users", None, admin)
        admins_left = [u["username"] for u in json.loads(body)["users"] if u["role"] == "admin"]
        check("system still has an admin", "SUPER_ADMIN" in admins_left, admins_left)
        st, body, _ = http("POST", "/admin/users/alice%40corp.com/role", {"role": "admin"}, admin)
        check("re-promote to admin", st == 200, body)

        # --- disable / enable
        st, body, _ = http("POST", "/admin/users/alice%40corp.com/status",
                           {"status": "disabled"}, admin)
        check("disable accepted", st == 200, body)
        st, body, _ = login("alice@corp.com", new_password)
        check("disabled account cannot log in", st == 403, body)
        st, body, _ = http("POST", "/admin/users/alice%40corp.com/status", {"status": "active"}, admin)
        check("enable accepted", st == 200, body)
        st, body, alice_cookie = login("alice@corp.com", new_password)
        check("enabled account can log in again", st == 200, body)

        # --- admin-created alias account
        MESSAGES.clear()
        st, body, _ = http("POST", "/admin/users",
                           {"username": "ops", "role": "admin", "email": "ops@corp.com"}, admin)
        data = json.loads(body) if st == 200 else {}
        check("alias admin created", st == 200, body)
        check("generated password returned", bool(data.get("password")), data)
        check("alias mail sent", data.get("email_sent") is True, data)
        st, body, _ = http("POST", "/admin/users",
                           {"username": "nobody@corp.com", "role": "user",
                            "email": "nobody@corp.com"}, admin)
        check("regular accounts cannot be created by hand", st == 400, body)
        st, body, _ = http("POST", "/admin/users", {"username": "ops2", "role": "admin"}, admin)
        check("alias admin needs a mailbox", st == 400, body)
        st, body, _ = http("POST", "/admin/users",
                           {"username": "Lead@Corp.com", "role": "admin"}, admin)
        lead = json.loads(body) if st == 200 else {}
        check("email-named admin created", st == 200 and lead.get("username") == "lead@corp.com", body)
        check("email admin needs no separate mailbox", lead.get("email") == "lead@corp.com", lead)

        # --- the promoted admin sees every account
        st, body, _ = http("GET", "/admin/users", None, admin)
        all_users = [u["username"] for u in json.loads(body)["users"]]
        check("admin sees all accounts", len(all_users) >= 4, all_users)
        st, body, _ = http("GET", "/admin/users", None, alice_cookie)
        check("promoted admin can list users", st == 200, body)

        return 0 if not FAILURES else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        sink.shutdown()
        err = proc.stdout.read() if proc.stdout else ""
        bad = [l for l in err.splitlines() if "Traceback" in l or "ERROR" in l]
        if bad:
            print("--- server errors ---")
            print("\n".join(bad[:20]))


if __name__ == "__main__":
    sys.exit(main())
