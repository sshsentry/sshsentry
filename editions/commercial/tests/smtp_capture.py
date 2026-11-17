"""Minimal stdlib SMTP capture server for sshsentry tests (no asyncore/smtpd, no aiosmtpd needed).

Speaks enough SMTP for smtplib: EHLO/HELO, AUTH PLAIN/LOGIN (accepts anything, records it),
MAIL, RCPT, DATA, RSET, NOOP, QUIT. No STARTTLS: test configs set email.starttls: false.
Captured messages: list of {"from", "to", "data", "auth"}.
Standalone: python3 smtp_capture.py PORT
"""
import base64, socketserver, sys, threading


class SMTPCapture:
    def __init__(self, port=0):
        self.messages, cap = [], self
        class H(socketserver.StreamRequestHandler):
            def reply(self, line):
                self.wfile.write((line + "\r\n").encode()); self.wfile.flush()
            def handle(self):
                self.reply("220 localhost sshsentry-test SMTP")
                mail, rcpt, auth = None, [], None
                while True:
                    raw = self.rfile.readline()
                    if not raw:
                        return
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    cmd = line.split(" ", 1)[0].upper()
                    arg = line[len(cmd):].strip()
                    if cmd == "EHLO":
                        self.wfile.write(b"250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"); self.wfile.flush()
                    elif cmd == "HELO":
                        self.reply("250 localhost")
                    elif cmd == "AUTH":
                        mech, _, initial = arg.partition(" ")
                        if mech.upper() == "PLAIN":
                            if not initial:
                                self.reply("334 "); initial = self.rfile.readline().decode().strip()
                            parts = base64.b64decode(initial).split(b"\0")
                            auth = {"user": parts[1].decode(), "password": parts[2].decode()}
                        else:   # LOGIN
                            self.reply("334 VXNlcm5hbWU6"); u = base64.b64decode(self.rfile.readline().strip()).decode()
                            self.reply("334 UGFzc3dvcmQ6"); p = base64.b64decode(self.rfile.readline().strip()).decode()
                            auth = {"user": u, "password": p}
                        self.reply("235 2.7.0 Authentication successful")
                    elif cmd == "MAIL":
                        mail, rcpt = arg, []; self.reply("250 OK")
                    elif cmd == "RCPT":
                        rcpt.append(arg); self.reply("250 OK")
                    elif cmd == "DATA":
                        self.reply("354 End data with <CR><LF>.<CR><LF>")
                        lines = []
                        while True:
                            l = self.rfile.readline()
                            if not l or l in (b".\r\n", b".\n"):
                                break
                            lines.append(l[1:] if l.startswith(b"..") else l)
                        cap.messages.append({"from": mail, "to": rcpt, "auth": auth,
                                             "data": b"".join(lines).decode("utf-8", "replace")})
                        self.reply("250 OK queued")
                    elif cmd in ("RSET", "NOOP"):
                        self.reply("250 OK")
                    elif cmd == "QUIT":
                        self.reply("221 Bye"); return
                    else:
                        self.reply("502 Command not implemented")
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", port), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown(); self.server.server_close()

    def clear(self):
        self.messages.clear()


if __name__ == "__main__":
    s = SMTPCapture(int(sys.argv[1]) if len(sys.argv) > 1 else 8025)
    print(f"SMTP capture on 127.0.0.1:{s.port}", flush=True)
    s.server.serve_forever()
