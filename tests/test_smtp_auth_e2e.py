#!/usr/bin/env python3
"""End-to-end check of the SMTP sender: configuration, AUTH, and the From header.

Starts a throwaway SMTP sink that *requires* AUTH (so the password path is
exercised instead of the anonymous-relay path), boots the server on a spare
port against a temp DB, and drives the admin endpoints.

    python3 tests/test_smtp_auth_e2e.py
"""
import base64
import json
import os
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DB = "/tmp/tcs-smtp.db"
PORT = 18766

EXPECT_USER = "collector-bot@corp.com"
EXPECT_PASSWORD = "s3cret-app-password"

STATE = {"auth": [], "from": None, "to": None, "subjects": []}
FAILURES = []


class AuthSink(socketserver.StreamRequestHandler):
    """Minimal SMTP that advertises AUTH PLAIN/LOGIN and checks the password."""

    def handle(self):
        self.wfile.write(b"220 sink\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.strip()
            upper = cmd.upper()

            if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
                self.wfile.write(b"250-sink\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
            elif upper.startswith(b"AUTH PLAIN"):
                parts = cmd.split(None, 2)
                blob = parts[2] if len(parts) > 2 else self._read_b64()
                ok = self._check_plain(base64.b64decode(blob))
                self.wfile.write(b"235 ok\r\n" if ok else b"535 bad credentials\r\n")
            elif upper.startswith(b"AUTH LOGIN"):
                user = base64.b64decode(self._challenge(b"VXNlcm5hbWU6")).decode()
                password = base64.b64decode(self._challenge(b"UGFzc3dvcmQ6")).decode()
                ok = self._check(user, password)
                self.wfile.write(b"235 ok\r\n" if ok else b"535 bad credentials\r\n")
            elif upper.startswith(b"MAIL FROM"):
                STATE["from"] = self._addr(cmd)
                self.wfile.write(b"250 ok\r\n")
            elif upper.startswith(b"RCPT TO"):
                STATE["to"] = self._addr(cmd)
                self.wfile.write(b"250 ok\r\n")
            elif upper.startswith(b"DATA"):
                self.wfile.write(b"354 go\r\n")
                buf = []
                while True:
                    chunk = self.rfile.readline()
                    if not chunk or chunk.strip() == b".":
                        break
                    buf.append(chunk)
                body = b"".join(buf).decode("utf-8", "replace")
                for header in body.splitlines():
                    if header.lower().startswith("subject:"):
                        STATE["subjects"].append(header[8:].strip())
                self.wfile.write(b"250 ok\r\n")
            elif upper.startswith(b"QUIT"):
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")

    def _challenge(self, prompt):
        self.wfile.write(b"334 " + prompt + b"\r\n")
        return self.rfile.readline().strip()

    def _read_b64(self):
        return self._challenge(b"VXNlcm5hbWU6")

    def _check(self, user, password):
        STATE["auth"].append((user, password))
        return user == EXPECT_USER and password == EXPECT_PASSWORD

    def _check_plain(self, blob):
        try:
            _, user, password = blob.split(b"\x00")
        except ValueError:
            return False
        return self._check(user.decode(), password.decode())

    @staticmethod
    def _addr(line):
        text = line.decode("utf-8", "replace")
        if "<" in text and ">" in text:
            return text[text.index("<") + 1:text.index(">")]
        return text.split(":", 1)[-1].strip()


class SinkServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def http(method, path, body=None, cookie=None):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers.get("Set-Cookie")


def login(name, pw):
    st, body, cookie = http("POST", "/login", {"username": name, "password": pw})
    return st, body, (cookie or "").split(";")[0]


def main():
    for p in (DB, DB + "-wal", DB + "-shm"):
        if os.path.exists(p):
            os.remove(p)
    sink = SinkServer(("127.0.0.1", 0), AuthSink)
    smtp_port = sink.server_address[1]
    threading.Thread(target=sink.serve_forever, daemon=True).start()

    env = dict(os.environ, TOOL_CALL_SERVER_DB=DB, SESSION_SECRET="test-secret")
    for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_SECURITY"):
        env.pop(key, None)
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
                  ((" :: " + str(extra)[:400]) if extra and not cond else ""))
            if not cond:
                FAILURES.append(label)

        st, body, admin = login("SUPER_ADMIN", "SUPER_ADMIN")
        check("super admin login", st == 200, body)

        # --- a fresh deployment has no relay and no sender
        st, body, _ = http("GET", "/admin/smtp", None, admin)
        cfg = json.loads(body) if st == 200 else {}
        check("fresh server: no relay, no sender",
              cfg.get("host") == "" and cfg.get("sender") == "", cfg)
        st, body, _ = http("POST", "/admin/smtp/test", {"to": "someone@corp.com"}, admin)
        check("fresh server: sending is refused, not silently dropped",
              st == 502 and "SMTP 未配置" in body, (st, body))

        # --- the sender is SUPER_ADMIN's mailbox, so it must exist first
        st, body, _ = http("POST", "/admin/smtp", {
            "host": "127.0.0.1", "port": smtp_port, "password": EXPECT_PASSWORD,
            "security": "none"}, admin)
        check("smtp config saved", st == 200, body)
        st, body, _ = http("POST", "/admin/smtp/test", {"to": "someone@corp.com"}, admin)
        check("no SUPER_ADMIN mailbox: refused with a pointer",
              st == 502 and "SUPER_ADMIN" in body, (st, body))
        st, body, _ = http("POST", "/admin/users/SUPER_ADMIN/email",
                           {"email": EXPECT_USER}, admin)
        check("SUPER_ADMIN mailbox set", st == 200, body)
        st, body, _ = http("GET", "/admin/smtp", None, admin)
        cfg = json.loads(body) if st == 200 else {}
        check("sender follows SUPER_ADMIN", cfg.get("sender") == EXPECT_USER, cfg)
        check("password is write-only", "password" not in cfg and cfg.get("password_set") is True, cfg)

        # --- actually send
        st, body, _ = http("POST", "/admin/smtp/test", {"to": "someone@corp.com"}, admin)
        check("mail sent through AUTH", st == 200, (st, body))
        check("server authenticated once", len(STATE["auth"]) == 1, STATE["auth"])
        check("AUTH used the configured password",
              STATE["auth"] and STATE["auth"][0] == (EXPECT_USER, EXPECT_PASSWORD), STATE["auth"])
        check("From header is the SMTP account", STATE["from"] == EXPECT_USER, STATE["from"])

        # --- a wrong password must fail loudly
        STATE["auth"].clear()
        http("POST", "/admin/smtp", {"password": "wrong-password"}, admin)
        st, body, _ = http("POST", "/admin/smtp/test", {"to": "someone@corp.com"}, admin)
        check("wrong password is rejected", st == 502, (st, body))

        return 0 if not FAILURES else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        sink.shutdown()


if __name__ == "__main__":
    sys.exit(main())
