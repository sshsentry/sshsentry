"""Commercial Edition (exp2): connection_flood rule (reconnect flood with no login) and one-alert-per-spray."""
import json, os, signal, subprocess, time
from datetime import datetime
from helpers import *
from test_core import readline_timeout
import test_commercial
from test_commercial import InProc

ROUTER, ROUTER2, ADMIN = "192.0.2.41", "192.0.2.87", "198.51.100.23"


def iline(ts, msg, pid=20000, host="ops-ssh01", proc="sshd"):
    """ISO-8601 (rsyslog) line with microseconds, so sub-second floods keep their timing."""
    return f"{datetime.fromtimestamp(ts).astimezone().isoformat(timespec='microseconds')} {host} {proc}[{pid}]: {msg}"


def conns(t0, ip, n, rate=250.0, pid0=20000, port0=40000, close=True, noident=False, opened=True):
    """n pre-auth connections from ip at `rate`/sec. Each connection may log several lines."""
    out = []
    for i in range(n):
        t, pid, port = t0 + i / rate, pid0 + i, port0 + i
        if opened:
            out.append(iline(t, f'Connection from {ip} port {port} on 10.20.0.5 port 22 rdomain ""', pid))
        if close:
            out.append(iline(t + 0.01, f"Connection closed by {ip} port {port} [preauth]", pid))
        if noident:
            out.append(iline(t + 0.02, f"Did not receive identification string from {ip} port {port}", pid))
    return out


class Flood(InProc):
    def t0(self):
        return int(time.time()) - 300

    def test_fires_at_threshold_and_names_ip(self):
        a = self.agent()
        self.feed(a, conns(self.t0(), ROUTER, 100))
        o = self.out.getvalue()
        self.assertEqual(o.count("HIGH: Connection flood."), 1, o)
        self.assertIn(f"HIGH: Connection flood. 100 SSH connections from {ROUTER} in 0.40 sec (~250/sec), "
                      f"and none of them tried to log in (0 login attempts from {ROUTER} in the last 10 sec)", o)
        self.assertIn("(connection #100 from this IP)", o)
        self.assertIn(f"a device or script at {ROUTER} is opening and dropping SSH connections", o)
        self.assertEqual(a.q("SELECT key FROM alerts WHERE rule='connection_flood'")[0], ROUTER)

    def test_under_threshold_is_silent(self):
        a = self.agent()
        self.feed(a, conns(self.t0(), ROUTER, 99))
        self.assertNotIn("Connection flood", self.out.getvalue())

    def test_sliding_window(self):
        a = self.agent()
        self.feed(a, conns(self.t0(), ROUTER, 150, rate=9.0))   # 150 conns but only ~90 in any 10 s
        self.assertNotIn("Connection flood", self.out.getvalue())
        a = self.agent({"rules": {"connection_flood": {"connections": 50, "window_seconds": 30}}}, name="b")
        self.feed(a, conns(self.t0(), ROUTER, 60, rate=2.0))
        self.assertIn("HIGH: Connection flood. 50 SSH connections from", self.out.getvalue())

    def test_ip_with_login_attempts_is_excluded(self):
        for n, auth in enumerate([f"Failed password for root from {{ip}} port 1 ssh2",
                                  f"Invalid user admin from {{ip}} port 1",
                                  f"Accepted publickey for chris from {{ip}} port 1 ssh2",
                                  f"Connection closed by authenticating user root {{ip}} port 1 [preauth]",
                                  f"Disconnected from invalid user bob {{ip}} port 1 [preauth]"]):
            a = self.agent(name=f"x{n}")
            t0 = self.t0()
            self.feed(a, [iline(t0, auth.format(ip=ROUTER), pid=1)] + conns(t0 + 1, ROUTER, 200)
                      + conns(t0 + 1, ROUTER2, 120, pid0=60000))
            o = self.out.getvalue()
            self.assertNotIn(f"Connection flood. 100 SSH connections from {ROUTER} ", o, auth)
            self.assertIn(f"Connection flood. 100 SSH connections from {ROUTER2} ", o, auth)
            self.out.truncate(0); self.out.seek(0)

    def test_login_attempt_older_than_window_does_not_exclude(self):
        a = self.agent()
        t0 = self.t0()
        self.feed(a, [iline(t0, f"Failed password for root from {ROUTER} port 1 ssh2", pid=1)] + conns(t0 + 11, ROUTER, 100))
        self.assertIn(f"Connection flood. 100 SSH connections from {ROUTER}", self.out.getvalue())

    def test_open_and_close_lines_counted_once(self):
        a = self.agent()
        self.feed(a, conns(self.t0(), ROUTER, 60, noident=True))         # 180 lines, 60 connections
        self.assertNotIn("Connection flood", self.out.getvalue())
        self.assertEqual(a.cf_total[ROUTER], 60)
        a = self.agent(name="b")
        self.feed(a, conns(self.t0(), ROUTER, 100, noident=True))
        self.assertIn("Connection flood. 100 SSH connections", self.out.getvalue())

    def test_close_only_logs_and_port_reuse(self):
        a = self.agent()   # default LogLevel INFO: no "Connection from" lines, only the close lines
        self.feed(a, conns(self.t0(), ROUTER, 100, opened=False))
        self.assertIn("Connection flood. 100 SSH connections", self.out.getvalue())
        a = self.agent(name="b")   # same source port reused by new connections (new sshd pid each time)
        lines = []
        for i in range(100):
            t = self.t0() + i * 0.01
            lines += [iline(t, f"Connection from {ROUTER} port 40000 on 10.20.0.5 port 22", 30000 + i),
                      iline(t + 0.005, f"Connection closed by {ROUTER} port 40000 [preauth]", 30000 + i)]
        self.feed(a, lines)
        self.assertIn("Connection flood. 100 SSH connections", self.out.getvalue())

    def test_maxstartups_drops_and_other_preauth_lines(self):
        a = self.agent()
        t0, lines = self.t0(), []
        msgs = ["drop connection #12 from [{ip}]:{p} on [10.20.0.5]:22 past MaxStartups",
                "Connection reset by {ip} port {p} [preauth]",
                "Timeout before authentication for {ip} port {p}",
                "Received disconnect from {ip} port {p}:11: Bye Bye [preauth]",
                "Unable to negotiate with {ip} port {p}: no matching key exchange method found. [preauth]"]
        for i in range(100):
            lines.append(iline(t0 + i * 0.01, msgs[i % 5].format(ip=ROUTER, p=41000 + i),
                               pid=812 if i % 5 == 0 else 50000 + i))
        self.feed(a, lines)
        self.assertIn(f"Connection flood. 100 SSH connections from {ROUTER}", self.out.getvalue())

    def test_authenticated_session_close_not_counted(self):
        a = self.agent()
        t0 = self.t0()
        self.feed(a, [iline(t0, f"Accepted publickey for chris from {ADMIN} port 51422 ssh2", 1901),
                      iline(t0 + 60, f"Connection closed by {ADMIN} port 51422", 1901)])
        self.assertEqual(a.cf_total.get(ADMIN, 0), 0)

    def test_cooldown_per_ip(self):
        a = self.agent()
        t0 = self.t0()
        self.feed(a, conns(t0, ROUTER, 1000))                             # 4 sec of flood
        self.assertEqual(self.out.getvalue().count("Connection flood."), 1)
        self.feed(a, conns(t0 + 200, ROUTER, 200, pid0=70000))             # inside the 5-min cooldown
        self.assertEqual(self.out.getvalue().count("Connection flood."), 1)
        self.feed(a, conns(t0 + 301, ROUTER, 200, pid0=80000))             # after it
        self.assertEqual(self.out.getvalue().count("Connection flood."), 2)
        self.assertIn("(connection #1300 from this IP)", self.out.getvalue())
        a = self.agent({"rules": {"connection_flood": {"cooldown_minutes": 1}}}, name="b")
        self.feed(a, conns(t0, ROUTER, 200) + conns(t0 + 61, ROUTER, 200, pid0=70000))
        self.assertEqual(self.out.getvalue().count("Connection flood."), 2)

    def test_two_sources_each_alert_with_their_own_ip(self):
        a = self.agent()
        t0 = self.t0()
        self.feed(a, sorted(conns(t0, ROUTER, 300) + conns(t0 + 4, ROUTER2, 300, rate=200, pid0=40000)))
        o = self.out.getvalue()
        self.assertIn(f"100 SSH connections from {ROUTER} in 0.40 sec (~250/sec)", o)
        self.assertIn(f"100 SSH connections from {ROUTER2} in 0.49 sec (~200/sec)", o)
        self.assertEqual(o.count("Connection flood."), 2)

    def test_labels_exact_and_cidr(self):
        a = self.agent({"rules": {"connection_flood": {"labels": {
            ROUTER: "El Dorado radio-site router", "192.0.2.0/24": "Router network", "2001:db8::/32": "v6 lab",
            "bogus": "x"}}}})
        t0 = self.t0()
        self.feed(a, conns(t0, ROUTER, 100) + conns(t0, "192.0.2.87", 100, pid0=40000)
                  + conns(t0, "203.0.113.5", 100, pid0=50000) + conns(t0, "2001:db8::7", 100, pid0=60000))
        o = self.out.getvalue()
        self.assertIn(f"from {ROUTER} (El Dorado radio-site router) in", o)
        self.assertIn("from 192.0.2.87 (Router network) in", o)
        self.assertIn("from 203.0.113.5 (not in your inventory labels) in", o)
        self.assertIn("from 2001:db8::7 (v6 lab) in", o)
        self.assertIn("ignoring bad connection_flood.labels entry 'bogus'", self.err.getvalue())
        a = self.agent(name="b")
        self.feed(a, conns(t0, ROUTER, 100))
        self.assertIn(f"from {ROUTER} in 0.40 sec", self.out.getvalue())   # no labels configured: just the IP

    def test_ignore_and_disable(self):
        a = self.agent({"rules": {"connection_flood": {"ignore": ["192.0.2.0/28"]}}})
        self.feed(a, conns(self.t0(), "192.0.2.5", 200) + conns(self.t0(), ROUTER, 100, pid0=40000))
        o = self.out.getvalue()
        self.assertNotIn("from 192.0.2.5", o); self.assertIn(f"from {ROUTER}", o)
        a = self.agent({"rules": {"connection_flood": {"enabled": False}}}, name="b")
        self.feed(a, conns(self.t0(), ROUTER, 500))
        self.assertNotIn("Connection flood", self.out.getvalue())

    def test_classic_syslog_second_resolution(self):
        a = self.agent()
        t0 = int(self.t0())
        self.feed(a, [line(t0 + i // 50, f"Connection closed by {ROUTER} port {40000 + i} [preauth]", pid=9000 + i)
                      for i in range(100)])
        self.assertIn(f"HIGH: Connection flood. 100 SSH connections from {ROUTER} in 1.00 sec (~99/sec)",
                      self.out.getvalue())

    def test_existing_rules_unaffected(self):
        a = self.agent()
        self.feed(a, conns(self.t0(), ROUTER, 300))
        self.feed(a, burst(time.time() - 200, "203.0.113.9", 5))
        o = self.out.getvalue()
        self.assertIn("MEDIUM: Brute force. 5 failed SSH logins from 203.0.113.9", o)
        self.assertNotIn("Brute force. 5 failed SSH logins from " + ROUTER, o)

    def test_webhook_event_and_retry_queue(self):
        a = self.agent({"alerting": {"enabled": True, "webhook": {"enabled": True, "url": self.url + "/hook"}}})
        self.feed(a, conns(self.t0(), ROUTER, 100))
        got = [r["json"] for r in Base.http.requests if r["path"] == "/hook"]
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0]["rule"], got[0]["severity"], got[0]["ip"]), ("connection_flood", "HIGH", ROUTER))
        self.assertIn(f"Connection flood from {ROUTER}: 100 SSH connections", got[0]["message"])
        a = self.agent({"alerting": {"enabled": True, "webhook": {"enabled": True, "url": self.url + "/fail"}}}, name="b")
        self.feed(a, conns(self.t0(), ROUTER, 100))
        self.assertEqual(a.q("SELECT COUNT(*) FROM pending_alerts")[0], 1)
        self.assertIn("queued connection_flood alert for webhook", self.err.getvalue())
        self.assertEqual(a.q("SELECT COUNT(*) FROM shared")[0], 0)        # never shared to the community list

    def test_learning_existing_log_is_silent(self):
        a = self.agent()
        a.learning = True
        self.feed(a, conns(self.t0(), ROUTER, 200))
        self.assertNotIn("Connection flood", self.out.getvalue())

    def test_memory_is_pruned(self):
        a = self.agent()
        t0 = time.time() - 7200
        self.feed(a, conns(t0, ROUTER, 50))
        self.feed(a, conns(t0 + 3700, ROUTER2, 5000, pid0=100000, close=False))   # triggers a prune pass
        self.assertNotIn(ROUTER, a.cf_total)
        self.assertLess(len(a.cf_seen), 5001)


class FloodCli(Base):
    def flood_log(self, path, t0):
        with open(path, "w") as f:
            f.write("\n".join(sorted(conns(t0, ROUTER, 400) + conns(t0 + 4, ROUTER2, 400, rate=200, pid0=40000)
                                     + [iline(t0 - 4, f"Accepted publickey for chris from {ADMIN} port 51422 ssh2", 1901)]))
                    + "\n")

    def test_replay_and_json(self):
        self.sb.config("r", {"rules": {"connection_flood": {"labels": {ROUTER: "El Dorado router",
                                                                      ROUTER2: "Amarillo router"}}}})
        self.flood_log(self.sb.path("f.log"), int(time.time()) - 600)
        r = self.sb.run("r", "--replay", self.sb.path("f.log"))
        self.assertEqual(r.out.count("HIGH: Connection flood."), 2, r)
        self.assertIn(f"from {ROUTER} (El Dorado router) in 0.40 sec", r.out)
        self.assertIn(f"from {ROUTER2} (Amarillo router) in 0.49 sec", r.out)
        self.sb.config("j")   # fresh state DB (the first replay's alerts are still in their cooldown)
        j = self.sb.run("j", "--replay", self.sb.path("f.log"), "--format", "json").json()
        got = [(x["rule"], x["severity"]) for x in j["alerts"] if x["rule"] != "new_ip"]
        self.assertEqual(got, [("connection_flood", "HIGH")] * 2, j)
        self.assertIn(f"from {ROUTER} in 0.40 sec", j["alerts"][1]["message"])

    def test_live_follow(self):
        self.sb.config("w", {"poll_seconds": 0.2})
        e = {k: v for k, v in os.environ.items() if not k.startswith("SSHSENTRY_")}; e["PYTHONUNBUFFERED"] = "1"
        p = subprocess.Popen([PY, SCRIPT, "-c", self.sb.path("w.yaml")], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env=e)
        try:
            time.sleep(1.0)
            self.sb.append("w", conns(int(time.time()), ROUTER, 150))
            got = readline_timeout(p, 10)
            self.assertIn(f"HIGH: Connection flood. 100 SSH connections from {ROUTER}", got)
        finally:
            p.terminate(); p.communicate(timeout=10)

    def test_sample_config_documents_defaults(self):
        import yaml
        y = yaml.safe_load(open(DEFAULT_YAML))
        self.assertEqual(y["rules"]["connection_flood"], S.DEFAULTS["rules"]["connection_flood"])
        self.assertTrue(y["rules"]["distributed_spray"]["merge_user_alerts"])
        self.assertTrue(S.VERSION.endswith("exp2"))


class OneAlertPerSpray(InProc):
    spray = test_commercial.Spray.spray   # reuse the helper only (the Spray tests themselves run in test_commercial)

    def users4(self, i):
        return ("admin", "deploy", "oracle", "simvictim3")[i % 4]

    def oct25(self, a):
        """Shape of the Oct 25 live scenario A: 38 IPs x 2 failures over 4 usernames, ~2 per second."""
        out, t0, k = [], time.time() - 900, 0
        for j in range(2):
            for i in range(38):
                out.append(fail(t0 + k // 2, ("oracle", "admin", "simvictim3", "deploy")[(i + j) % 4],
                                f"127.0.0.{i + 2}")); k += 1
        self.feed(a, out)

    def test_spray_yields_one_alert_not_five(self):
        a = self.agent()
        self.oct25(a)
        o = self.out.getvalue()
        self.assertEqual(o.count("HIGH: Distributed password spray"), 1, o)   # whichever trips first
        self.assertEqual(o.count("HIGH: "), 1, o)

    def test_old_behaviour_with_merge_off(self):
        a = self.agent({"rules": {"distributed_spray": {"merge_user_alerts": False}}})
        self.oct25(a)
        o = self.out.getvalue()
        self.assertEqual(o.count("HIGH: Distributed password spray"), 5, o)
        self.assertEqual(o.count("spray on user"), 4)

    def test_window_alert_lists_targeted_usernames(self):
        a = self.agent()
        t0, lines = time.time() - 900, []
        lines += [fail(t0 + i, "alice", f"203.0.113.{i + 1}") for i in range(4)]            # alice from 4 IPs
        lines += [fail(t0 + 10 + i, f"b{i}", f"203.0.113.{i % 12 + 1}") for i in range(15)]  # 19 total, 12 IPs
        lines += [fail(t0 + 30, "alice", "203.0.113.13")]   # 20th failure = alice's 5th IP: both trip at once
        self.feed(a, lines + [fail(t0 + 40 + i, "alice", f"198.51.100.{i + 1}") for i in range(5)])
        o = self.out.getvalue()
        self.assertIn("HIGH: Distributed password spray. 20 failed SSH logins from 13 different IPs", o)
        self.assertIn("Targeted usernames (each from 5+ IPs): alice (5 failures from 5 IPs).", o)
        self.assertEqual(o.count("HIGH: "), 1, o)

    def test_per_user_first_then_window_is_still_one_alert(self):
        a = self.agent()
        self.feed(a, self.spray(12, 2, user=lambda i: "alice" if i < 6 else f"u{i}"))
        o = self.out.getvalue()
        self.assertIn("HIGH: Distributed password spray on user 'alice'. 5 failed SSH logins", o)
        self.assertEqual(o.count("HIGH: "), 1, o)

    def test_per_user_alone_still_fires(self):
        a = self.agent()
        self.feed(a, self.spray(5, 1, user=lambda i: "alice"))     # 5 IPs on one user, no window hit
        self.assertIn("Distributed password spray on user 'alice'", self.out.getvalue())

    def test_per_user_alert_returns_after_window_alert_expires(self):
        a = self.agent()
        t0 = time.time() - 3 * 3600
        self.feed(a, self.spray(10, 2, t0=t0, user=self.users4))
        self.feed(a, self.spray(5, 1, t0=t0 + 3700, user=lambda i: "carol"))   # > 60 min later, small
        o = self.out.getvalue()
        self.assertEqual(o.count("Distributed password spray. "), 1)
        self.assertIn("Distributed password spray on user 'carol'", o)
