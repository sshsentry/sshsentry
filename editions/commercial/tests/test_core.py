"""Original rules, state, replay, --once, follow mode, approve, GeoIP-missing, new user / new key, email."""
import os, re, subprocess, time
from helpers import *


def readline_timeout(p, seconds):
    """Read one stdout line from a follow-mode process, or "" after `seconds` (never hang the suite)."""
    import queue, threading
    if not hasattr(p, "_lines"):
        p._lines = queue.Queue()
        threading.Thread(target=lambda: [p._lines.put(l) for l in p.stdout], daemon=True).start()
    try:
        return p._lines.get(timeout=seconds)
    except queue.Empty:
        return ""


def expected_year():
    return datetime.fromtimestamp(S.parse_ts("Oct 17 01:58:02")).year


class Replay(Base):
    def replay(self, *extra, cfg=DEFAULT_YAML):
        return self.sb.run(None, "-c", cfg, "--db", self.sb.path("r.db"), "--replay", SAMPLE, *extra, config=False)

    def test_golden_replay_default_config(self):
        r = self.replay()
        golden = open(os.path.join(TESTS, "golden", "replay_default.txt")).read()
        self.assertEqual(r.rc, 0, r)
        self.assertEqual(r.out, golden.replace("[2026-", f"[{expected_year()}-"))

    def test_golden_has_the_six_known_alerts(self):
        out = self.replay().out.splitlines()
        self.assertEqual([re.match(r"\[[^\]]+\] (\w+):", l).group(1) for l in out],
                         ["LOW", "MEDIUM", "MEDIUM", "HIGH", "LOW", "LOW"])
        frag = ["New IP login. User 'chris' logged in via publickey from 198.51.100.23",
                "Brute force. 5 failed SSH logins from 203.0.113.45 in 30 sec, trying user(s): admin, oracle, root, test.",
                "Brute force. 5 failed SSH logins from 192.0.2.77 in 49 sec, trying user(s): deploy.",
                "Login after failures. User 'deploy' logged in via password from 192.0.2.77 after 6 failed attempts",
                "New IP login. User 'deploy' logged in via password from 192.0.2.77",
                "New IP login. User 'chris' logged in via publickey from 100.64.12.9, an address never seen for this user. "]
        for l, f in zip(out, frag):
            self.assertIn(f, l)

    def test_geoip_missing_is_a_note_not_an_error(self):
        r = self.replay()
        self.assertEqual(r.rc, 0)
        self.assertIn("[sshsentry] note: country checks disabled", r.err)
        self.assertNotIn("Traceback", r.err)

    def test_replay_never_sends(self):
        self.sb.config("x", {"alerting": {"enabled": True, "webhook": {"enabled": True, "url": self.url + "/hook"}},
                             "sharing": {"enabled": True, "endpoint": self.url + "/share"},
                             "email": {"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": Base.smtp.port,
                                       "starttls": False, "from": "a@b", "to": ["c@d"]}})
        r = self.sb.run("x", "--replay", SAMPLE)
        self.assertEqual(len(r.out.splitlines()), 6, r)
        self.assertEqual(Base.http.requests, []); self.assertEqual(Base.smtp.messages, [])
        self.assertEqual(self.sb.one("x", "select count(*) from shared"), 0)

    def test_help_mentions_name_and_default_config(self):
        r = self.sb.run(None, "--help", config=False)
        self.assertEqual(r.rc, 0); self.assertIn("sshsentry: plain-English SSH intrusion alerts", r.out)
        self.assertIn('default="/etc/sshsentry/sshsentry.yaml"', open(SCRIPT).read())   # help text doesn't print defaults

    def test_missing_config_exits_with_message(self):
        r = self.sb.run(None, "-c", self.sb.path("nope.yaml"), "--once", config=False)
        self.assertNotEqual(r.rc, 0); self.assertIn("Config not found", r.err)

    def test_legacy_learning_days_maps_to_learn_mode(self):
        self.sb.config("lg", {"learning": {"days": 2}})
        r = self.sb.run("lg", "--replay", SAMPLE)
        self.assertIn("learning.days is deprecated", r.err)
        self.assertTrue(all(l.startswith("[learning: not sent]") for l in r.out.splitlines() if l.startswith("[")), r)


class Rules(Base):
    t0 = time.time() - 7200

    def rp(self, lines, cfg=None):
        self.sb.config("r", cfg or {}); self.sb.append("r", lines)
        return self.sb.run("r", "--replay", self.sb.log("r"))

    def test_brute_force_threshold(self):
        self.assertNotIn("Brute force", self.rp(burst(self.t0, "203.0.113.9", 4)).out)
        self.fresh()
        r = self.rp(burst(self.t0, "203.0.113.9", 5))
        self.assertIn("MEDIUM: Brute force. 5 failed SSH logins from 203.0.113.9", r.out)

    def test_brute_force_window(self):
        r = self.rp(burst(self.t0, "203.0.113.9", 5, step=180))   # 12 minutes > 10-minute window
        self.assertNotIn("Brute force", r.out)

    def test_invalid_user_counted_once(self):
        ip, t = "203.0.113.9", self.t0
        lines = []
        for i in range(4):
            lines += [invalid(t + i * 4, f"u{i}", ip), line(t + i * 4 + 1, f"Failed password for invalid user u{i} from {ip} port 1 ssh2")]
        self.assertNotIn("Brute force", self.rp(lines).out)   # 4 attempts, not 8
        self.fresh()
        r = self.rp(lines + [invalid(t + 30, "u9", ip)])
        self.assertIn("5 failed SSH logins", r.out)

    def test_login_after_failures(self):
        cfg = {"rules": {"brute_force": {"failures": 50}}}
        r = self.rp(burst(self.t0, "198.18.0.5", 5) + [ok(self.t0 + 60, "bob", "198.18.0.5")], cfg)
        self.assertIn("HIGH: Login after failures. User 'bob' logged in via password from 198.18.0.5 after 5 failed", r.out)
        self.fresh()
        r = self.rp(burst(self.t0, "198.18.0.5", 4) + [ok(self.t0 + 60, "bob", "198.18.0.5")], cfg)
        self.assertNotIn("Login after failures", r.out)

    def test_cooldown_suppresses_repeat(self):
        ip = "203.0.113.9"
        r = self.rp(burst(self.t0, ip, 5) + burst(self.t0 + 1200, ip, 5))   # 20 min later, within 60-min cooldown
        self.assertEqual(r.out.count("Brute force"), 1, r)
        self.fresh()
        r = self.rp(burst(self.t0, ip, 5) + burst(self.t0 + 3700, ip, 5))
        self.assertEqual(r.out.count("Brute force"), 2, r)

    def test_new_ip_rules(self):
        r = self.rp([ok(self.t0, "amy", "198.51.100.1", "publickey"), ok(self.t0 + 9, "amy", "198.51.100.1", "publickey"),
                     ok(self.t0 + 20, "amy", "198.51.100.2", "publickey")])
        self.assertEqual(r.out.count("New IP login"), 2, r)
        self.assertEqual(r.out.count("(first recorded login)"), 1)

    def test_new_ip_rule_can_be_disabled(self):
        r = self.rp([ok(self.t0, "amy", "198.51.100.1")], {"rules": {"new_ip": {"enabled": False}}})
        self.assertEqual(r.out, "")

    def test_iso_timestamps_and_sshd_session(self):
        ts = datetime.fromtimestamp(self.t0).astimezone().isoformat(timespec="milliseconds")
        lines = [f"{ts} web01 sshd-session[9]: Failed password for root from 203.0.113.7 port 1 ssh2"] * 5
        self.assertIn("Brute force. 5 failed SSH logins from 203.0.113.7", self.rp(lines).out)

    def test_non_sshd_lines_ignored(self):
        lines = [line(self.t0 + i, "Failed password for root from 203.0.113.7 port 1 ssh2", proc="CRON") for i in range(6)]
        lines += ["garbage line", "Feb 30 10:00:00 web01 sshd[1]: Accepted password for x from 198.51.100.4 port 1 ssh2"]
        self.assertEqual(self.rp(lines).out, "")

    def test_alert_log_json_lines(self):
        r = self.rp(burst(self.t0, "203.0.113.9", 5), {"alert_log": self.sb.path("alerts.jsonl")})
        rec = [json.loads(l) for l in open(self.sb.path("alerts.jsonl"))]
        self.assertEqual(rec[0]["rule"], "brute_force"); self.assertEqual(rec[0]["severity"], "MEDIUM")


class OnceAndFollow(Base):
    def test_first_run_learns_existing_log_silently(self):
        self.sb.config("o", {"learn_existing_log": True})
        self.sb.append("o", open(SAMPLE).read().splitlines())
        r = self.sb.once("o")
        self.assertEqual(r.out, "", r)
        self.assertEqual(self.sb.one("o", "select count(*) from seen_ips"), 3)
        self.sb.append("o", [ok(time.time() - 60, "chris", "198.51.100.23", "publickey")])
        self.assertEqual(self.sb.once("o").out, "")      # known IP: still quiet

    def test_first_run_without_learning_starts_at_end(self):
        self.sb.config("o"); self.sb.append("o", open(SAMPLE).read().splitlines())
        self.assertEqual(self.sb.once("o").out, "")
        self.assertEqual(self.sb.one("o", "select count(*) from failures"), 0)

    def test_once_resumes_from_offset_without_duplicates(self):
        self.sb.config("o"); self.sb.once("o")
        self.sb.append("o", burst(time.time() - 600, "203.0.113.9", 5))
        self.assertIn("Brute force", self.sb.once("o").out)
        self.assertEqual(self.sb.once("o").out, "")

    def test_once_handles_rotation(self):
        self.sb.config("o"); self.sb.once("o")
        self.sb.append("o", [ok(time.time() - 600, "amy", "198.51.100.1")]); self.sb.once("o")
        os.rename(self.sb.log("o"), self.sb.log("o") + ".1")
        self.sb.append("o", [ok(time.time() - 300, "amy", "198.51.100.2")])
        self.assertIn("198.51.100.2", self.sb.once("o").out)

    def test_follow_mode_tails_and_survives_rotation(self):
        self.sb.config("f", {"poll_seconds": 0.2})
        e = {k: v for k, v in os.environ.items() if not k.startswith("SSHSENTRY_")}; e["PYTHONUNBUFFERED"] = "1"
        p = subprocess.Popen([PY, SCRIPT, "-c", self.sb.path("f.yaml")], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, env=e)
        try:
            time.sleep(1.2)
            self.sb.append("f", burst(time.time() - 60, "203.0.113.9", 5))
            first = readline_timeout(p, 15)
            self.assertIn("Brute force", first)
            os.rename(self.sb.log("f"), self.sb.log("f") + ".1")
            self.sb.append("f", [ok(time.time() - 30, "amy", "198.51.100.77")])
            second = readline_timeout(p, 15)
            self.assertIn("198.51.100.77", second)
        finally:
            p.kill(); p.communicate()

    def test_approve_suppresses_new_ip(self):
        self.sb.config("a"); self.sb.once("a")
        r = self.sb.run("a", "--approve", "198.51.100.50")
        self.assertIn("Approved 198.51.100.50", r.out)
        self.sb.append("a", [ok(time.time() - 60, "amy", "198.51.100.50")])
        self.assertEqual(self.sb.once("a").out, "")

    def test_logins_not_stored_without_digest(self):
        self.sb.config("p"); self.sb.once("p")
        self.sb.append("p", [ok(time.time() - 60, "amy", "198.51.100.1")]); self.sb.once("p")
        self.assertEqual(self.sb.one("p", "select count(*) from logins"), 0)


class FileRules(Base):
    def setUp(self):
        super().setUp()
        os.makedirs(self.sb.path("home", "alice", ".ssh"))
        open(self.sb.path("passwd"), "w").write("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
        open(self.sb.path("home", "alice", ".ssh", "authorized_keys"), "w").write("ssh-ed25519 AAAAgood alice@laptop\n")
        self.sb.config("fr", {"rules": {"new_user": {"enabled": True, "passwd_file": self.sb.path("passwd")},
                                        "new_ssh_key": {"enabled": True, "paths": [self.sb.path("home", "*", ".ssh", "authorized_keys")]}}})

    def test_baseline_is_silent(self):
        self.assertEqual(self.sb.run("fr", "--replay", self.sb.log("fr")).out, "")

    def test_new_user_alert(self):
        self.sb.run("fr", "--replay", self.sb.log("fr"))
        open(self.sb.path("passwd"), "a").write("backdoor:x:0:0::/tmp:/bin/sh\n")
        r = self.sb.run("fr", "--replay", self.sb.log("fr"))
        self.assertIn("HIGH: New user account. 'backdoor' (uid 0, shell /bin/sh)", r.out)

    def test_new_key_alert(self):
        self.sb.run("fr", "--replay", self.sb.log("fr"))
        open(self.sb.path("home", "alice", ".ssh", "authorized_keys"), "a").write("ssh-rsa AAAAevil evil@attacker\n")
        r = self.sb.run("fr", "--replay", self.sb.log("fr"))
        self.assertIn("HIGH: New SSH key. A key (ssh-rsa, 'evil@attacker'", r.out)
        self.assertEqual(r.out.count("New SSH key"), 1)


class Email(Base):
    def cfg(self, **extra):
        e = {"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": Base.smtp.port, "starttls": False,
             "from": "sshsentry@example.com", "to": ["me@example.com"]}
        e.update(extra)
        self.sb.config("e", {"email": e}); self.sb.once("e")

    def test_legacy_email_sends_alert(self):
        self.cfg()
        self.sb.append("e", burst(time.time() - 600, "203.0.113.9", 5)); r = self.sb.once("e")
        self.assertIn("Brute force", r.out)
        self.assertEqual(len(Base.smtp.messages), 1, r)
        m = Base.smtp.messages[0]["data"]
        self.assertIn("Subject: [sshsentry] MEDIUM: Brute force", m)
        self.assertIn("me@example.com", Base.smtp.messages[0]["to"][0])

    def test_email_password_from_env(self):
        self.cfg(username="mailer")
        self.sb.append("e", burst(time.time() - 600, "203.0.113.9", 5))
        r = self.sb.once("e", env={"SSHSENTRY_SMTP_PASSWORD": "s3cret"})
        self.assertEqual(Base.smtp.messages[0]["auth"], {"user": "mailer", "password": "s3cret"}, r)
        self.assertNotIn("s3cret", r.out + r.err)

    def test_email_username_without_password_warns(self):
        self.sb.config("e", {"email": {"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": Base.smtp.port,
                                       "starttls": False, "username": "mailer", "to": ["me@example.com"]}})
        r = self.sb.once("e")
        self.assertIn("username is set but no password", r.err); self.assertEqual(r.rc, 0)

    def test_email_server_down_does_not_crash(self):
        self.sb.config("e", {"email": {"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": 1, "starttls": False,
                                       "from": "a@b", "to": ["c@d"]}})
        self.sb.once("e"); self.sb.append("e", burst(time.time() - 600, "203.0.113.9", 5))
        r = self.sb.once("e")
        self.assertEqual(r.rc, 0); self.assertIn("Brute force", r.out); self.assertIn("email alert failed", r.err)
