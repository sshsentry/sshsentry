"""Commercial Edition additions: distributed spray, log tamper, heartbeat, retry queue, downtime, unusual hours."""
import contextlib, io, os, signal, socket, subprocess, time
from datetime import datetime, timedelta
from helpers import *
from test_core import readline_timeout


def at_hour(days_ago, hour, minute=0):
    d = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0) - timedelta(days=days_ago)
    return d.timestamp()


class InProc(Base):
    """Runs an Agent in this process (stdout/stderr captured) for fine-grained checks."""
    def agent(self, over=None, name="a"):
        cfg = S.merge(S.DEFAULTS, deep({"log_file": self.sb.log(name), "state_db": self.sb.db(name),
                                        "learn_existing_log": False,
                                        "rules": {"new_user": {"enabled": False}, "new_ssh_key": {"enabled": False},
                                                  "new_country": {"enabled": False}}}, over or {}))
        open(self.sb.log(name), "a").close()
        self.out, self.err = io.StringIO(), io.StringIO()
        with self.cap():
            a = S.Agent(cfg)
        return a

    @contextlib.contextmanager
    def cap(self):
        with contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.err):
            yield

    def feed(self, a, lines):
        with self.cap():
            for l in lines:
                a.handle_line(l)


class Spray(InProc):
    def spray(self, n_ips, per_ip, t0=None, user=lambda i: f"u{i}", step=3):
        t0 = t0 or time.time() - 900
        out, k = [], 0
        for j in range(per_ip):
            for i in range(n_ips):
                out.append(fail(t0 + k * step, user(i), f"203.0.113.{i + 1}")); k += 1
        return out

    def test_window_threshold_fires_high(self):
        a = self.agent()
        self.feed(a, self.spray(10, 2))            # 20 failures from 10 IPs, 2 each
        o = self.out.getvalue()
        self.assertIn("HIGH: Distributed password spray. 20 failed SSH logins from 10 different IPs", o)
        self.assertIn("at most 2 from any one of them", o)
        self.assertNotIn("Brute force", o)

    def test_below_failures_or_ips_is_silent(self):
        a = self.agent()
        self.feed(a, self.spray(10, 2)[:19])       # 19 < 20
        self.assertNotIn("Distributed password spray.", self.out.getvalue())
        a = self.agent(name="b")
        self.feed(a, self.spray(9, 3))             # 27 failures but only 9 IPs
        self.assertNotIn("Distributed password spray.", self.out.getvalue())

    def test_sliding_window(self):
        a = self.agent()
        self.feed(a, self.spray(10, 2, step=40))   # 20 failures over ~13 min, never 20 within 10 min
        self.assertNotIn("Distributed password spray.", self.out.getvalue())

    def test_per_username_variant(self):
        a = self.agent()
        self.feed(a, self.spray(4, 1, user=lambda i: "alice"))
        self.assertNotIn("spray on user", self.out.getvalue())
        self.feed(a, [fail(time.time() - 600, "alice", "198.51.100.9")])
        self.assertIn("HIGH: Distributed password spray on user 'alice'. 5 failed SSH logins for this username "
                      "from 5 different IPs", self.out.getvalue())

    def test_cooldown_applies(self):
        a = self.agent()
        self.feed(a, self.spray(12, 2, t0=time.time() - 1800))
        self.feed(a, self.spray(12, 2, t0=time.time() - 1200))
        self.assertEqual(self.out.getvalue().count("Distributed password spray. "), 1)

    def test_config_knobs_and_disable(self):
        a = self.agent({"rules": {"distributed_spray": {"failures": 6, "distinct_ips": 3}}})
        self.feed(a, self.spray(3, 2))
        self.assertIn("Distributed password spray. 6 failed", self.out.getvalue())
        a = self.agent({"rules": {"distributed_spray": {"enabled": False}}}, name="b")
        self.feed(a, self.spray(20, 2, user=lambda i: "bob"))
        self.assertNotIn("spray", self.out.getvalue())

    def test_brute_force_ip_not_counted_once_over_limit(self):
        a = self.agent()
        t0 = time.time() - 900
        self.feed(a, self.spray(8, 2, t0=t0) + burst(t0 + 60, "198.51.100.99", 8))   # 16 light + 8 heavy
        o = self.out.getvalue()
        self.assertIn("Brute force. 5 failed SSH logins from 198.51.100.99", o)
        self.assertNotIn("Distributed password spray. ", o)   # never 10 light IPs

    def test_digest_spray_line(self):
        self.sb.config("d")
        with open(self.sb.path("spray.log"), "w") as f:
            f.write("\n".join(self.spray(30, 2, step=60)) + "\n")   # slow spray: no real-time window hit
        r = self.sb.run("d", "--replay", self.sb.path("spray.log"), "--digest-now")
        self.assertIn("Possible distributed spray: 60 failures came from 30 IPs with at most 2 each", r.out, r)


class UnusualHours(InProc):
    def test_hour_near_wraps(self):
        self.assertTrue(S.hour_near(0, [23], 1)); self.assertTrue(S.hour_near(23, [0], 1))
        self.assertFalse(S.hour_near(2, [23], 1)); self.assertTrue(S.hour_near(5, [5], 0))
        self.assertFalse(S.hour_near(6, [5], 0))

    def baseline(self, a, n, hours=(9, 10, 11, 12, 13)):
        self.feed(a, [ok(at_hour(20 - i, hours[i % len(hours)]), "dana", "198.51.100.5") for i in range(n)])

    def test_min_samples_gate(self):
        a = self.agent()
        self.baseline(a, 9)
        self.feed(a, [ok(at_hour(0, 3), "dana", "198.51.100.5")])   # 10th login: only 9 samples before it
        self.assertNotIn("Unusual-hours", self.out.getvalue())

    def test_unusual_hour_alerts_medium(self):
        a = self.agent()
        self.baseline(a, 10)
        self.feed(a, [ok(at_hour(0, 3, 30), "dana", "198.51.100.5")])
        o = self.out.getvalue()
        self.assertIn("MEDIUM: Unusual-hours login. User 'dana' logged in via password from 198.51.100.5 at 03:30", o)
        self.assertIn("usual hours: 09:00, 10:00, 11:00, 12:00, 13:00", o)
        self.assertNotIn("New IP", o.split("Unusual-hours")[1])   # known IP: only the hours rule fires

    def test_tolerance(self):
        a = self.agent()
        self.baseline(a, 10)
        self.feed(a, [ok(at_hour(0, 14, 50), "dana", "198.51.100.5"), ok(at_hour(0, 8, 5), "dana", "198.51.100.5")])
        self.assertNotIn("Unusual-hours", self.out.getvalue())
        a = self.agent({"rules": {"unusual_hours": {"tolerance_hours": 0}}}, name="b")
        self.baseline(a, 10)
        self.feed(a, [ok(at_hour(0, 14, 50), "dana", "198.51.100.5")])
        self.assertIn("Unusual-hours", self.out.getvalue())

    def test_per_user_and_disabled(self):
        a = self.agent()
        self.baseline(a, 10)
        self.feed(a, [ok(at_hour(0, 3), "erin", "198.51.100.5")])   # erin has no history
        self.assertNotIn("Unusual-hours", self.out.getvalue())
        a = self.agent({"rules": {"unusual_hours": {"enabled": False}}}, name="b")
        self.baseline(a, 10)
        self.feed(a, [ok(at_hour(0, 3), "dana", "198.51.100.5")])
        self.assertNotIn("Unusual-hours", self.out.getvalue())


class Tamper(InProc):
    def start(self, over=None):
        a = self.agent(over)
        lf = S.LogFollower(a, self.sb.log("a"))
        with self.cap():
            lf.open_start()
        self.sb.append("a", [ok(time.time() - 60, "amy", "198.51.100.1")])
        with self.cap():
            lf.read(lf.f); lf.poll()
        return a, lf

    def step(self, lf):
        with self.cap():
            lf.poll(); lf.read(lf.f)

    def test_truncate_in_place_high(self):
        a, lf = self.start()
        open(self.sb.log("a"), "w").close()
        self.step(lf)
        self.assertIn("HIGH: Log tampering? ", self.out.getvalue())
        self.assertIn("was truncated in place", self.out.getvalue())
        self.sb.append("a", [ok(time.time() - 30, "amy", "198.51.100.2")])
        self.step(lf)
        self.assertIn("198.51.100.2", self.out.getvalue())      # detection continues

    def test_delete_and_recreate_high(self):
        a, lf = self.start()
        os.remove(self.sb.log("a")); self.sb.append("a", [ok(time.time() - 30, "amy", "198.51.100.3")])
        self.step(lf)
        o = self.out.getvalue()
        self.assertIn("was deleted and a new file created in its place", o)
        self.assertIn("HIGH: Log tampering?", o)
        self.assertIn("198.51.100.3", o)

    def test_rotation_soft_notice_and_no_lost_lines(self):
        a, lf = self.start({"tamper": {"rotation_notice": "alert"}})
        os.rename(self.sb.log("a"), self.sb.log("a") + ".1")
        with open(self.sb.log("a") + ".1", "a") as f:            # late line written to the old file
            f.write(ok(time.time() - 40, "amy", "198.51.100.4") + "\n")
        self.sb.append("a", [ok(time.time() - 30, "amy", "198.51.100.5")])
        self.step(lf)
        o = self.out.getvalue()
        self.assertIn("LOW: Log rotated: ", o); self.assertNotIn("HIGH", o)
        self.assertIn("198.51.100.4", o); self.assertIn("198.51.100.5", o)

    def test_rotation_default_is_stderr_note_only(self):
        a, lf = self.start()
        os.rename(self.sb.log("a"), self.sb.log("a") + ".1"); self.sb.append("a", [])
        self.step(lf)
        self.assertNotIn("Log rotated", self.out.getvalue())
        self.assertIn("note: Log rotated", self.err.getvalue())

    def test_missing_longer_than_threshold(self):
        a, lf = self.start({"tamper": {"missing_seconds": 0}})
        os.remove(self.sb.log("a"))
        with self.cap():
            lf.poll()
        self.assertIn("has been missing for", self.out.getvalue())
        with self.cap():
            lf.poll()
        self.assertEqual(self.out.getvalue().count("has been missing"), 1)   # once per outage

    def test_missing_short_is_silent(self):
        a, lf = self.start({"tamper": {"missing_seconds": 30}})
        os.remove(self.sb.log("a"))
        with self.cap():
            lf.poll()
        self.assertNotIn("missing", self.out.getvalue())

    def test_offline_truncate_replace_rotate(self):
        self.sb.config("o", {"tamper": {"rotation_notice": "alert"}})
        self.sb.once("o")
        self.sb.append("o", [ok(time.time() - 600, "amy", "198.51.100.1")]); self.sb.once("o")
        open(self.sb.log("o"), "w").close()
        self.assertIn("HIGH: Log tampering?", self.sb.once("o").out)
        self.sb.append("o", [ok(time.time() - 500, "amy", "198.51.100.2")]); self.sb.once("o")
        os.rename(self.sb.log("o"), self.sb.path("elsewhere.log")); self.sb.append("o", [])
        self.assertIn("was replaced while sshsentry was not running", self.sb.once("o").out)
        self.sb.append("o", [ok(time.time() - 400, "amy", "198.51.100.3")]); self.sb.once("o")
        self.sb.append("o", [ok(time.time() - 300, "amy", "198.51.100.6")])   # unread when rotated
        os.rename(self.sb.log("o"), self.sb.log("o") + ".1")
        self.sb.append("o", [ok(time.time() - 200, "amy", "198.51.100.7")])
        r = self.sb.once("o").out
        self.assertIn("LOW: Log rotated while sshsentry was not running", r)
        self.assertIn("198.51.100.6", r); self.assertIn("198.51.100.7", r)

    def test_tamper_disabled(self):
        a, lf = self.start({"tamper": {"enabled": False}})
        open(self.sb.log("a"), "w").close()
        self.step(lf)
        self.assertNotIn("tampering", self.out.getvalue())


class Heartbeat(InProc):
    def test_schedule(self):
        a = self.agent({"heartbeat": {"enabled": True, "interval_seconds": 300, "url": self.url + "/hb"}})
        t = 1_800_000_000
        with self.cap():
            self.assertTrue(a.maybe_heartbeat(t).startswith("sent"))
            self.assertIsNone(a.maybe_heartbeat(t + 299))
            self.assertTrue(a.maybe_heartbeat(t + 300).startswith("sent"))
        hb = Base.http.at("/hb") if hasattr(Base.http, "at") else [r for r in Base.http.requests if r["path"] == "/hb"]
        self.assertEqual(len(hb), 2)
        self.assertEqual(hb[0]["json"]["type"], "heartbeat")

    def test_off_by_default_and_use_webhook(self):
        a = self.agent()
        self.assertIsNone(a.maybe_heartbeat(1_800_000_000))
        a = self.agent({"heartbeat": {"enabled": True, "use_webhook": True},
                        "alerting": {"webhook": {"url": self.url + "/wh"}}}, name="b")
        with self.cap():
            a.maybe_heartbeat(1_800_000_000)
        self.assertEqual([r["path"] for r in Base.http.requests], ["/wh"])

    def test_failure_is_logged_not_raised(self):
        a = self.agent({"heartbeat": {"enabled": True, "url": self.url + "/fail"}})
        with self.cap():
            a.maybe_heartbeat(1_800_000_000)
        self.assertIn("heartbeat to localhost failed", self.err.getvalue())

    def test_sd_notify(self):
        path = self.sb.path("notify.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); srv.bind(path); srv.settimeout(2)
        old = os.environ.get("NOTIFY_SOCKET"); os.environ["NOTIFY_SOCKET"] = path
        try:
            self.assertTrue(S.sd_notify("WATCHDOG=1"))
            self.assertEqual(srv.recv(100), b"WATCHDOG=1")
        finally:
            srv.close()
            os.environ.pop("NOTIFY_SOCKET") if old is None else os.environ.__setitem__("NOTIFY_SOCKET", old)
        self.assertFalse(S.sd_notify("WATCHDOG=1")) if old is None else None


class Retry(InProc):
    def cfg(self, path="/fail", **retry):
        return {"alerting": {"enabled": True, "webhook": {"enabled": True, "url": self.url + path}},
                "retry": retry}

    def test_failed_send_is_queued_and_delivered_later(self):
        a = self.agent(self.cfg())
        self.feed(a, burst(time.time() - 600, "203.0.113.9", 5))
        self.assertEqual(a.q("SELECT COUNT(*) FROM pending_alerts")[0], 1)
        a.dests[0]["url"] = self.url + "/ok"           # destination comes back
        now = time.time()
        with self.cap():
            a.retry_pending(now)                       # not due yet (base 30 s)
        self.assertEqual(len([r for r in Base.http.requests if r["path"] == "/ok"]), 0)
        with self.cap():
            a.retry_pending(now + 31)
        got = [r for r in Base.http.requests if r["path"] == "/ok"]
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0]["json"]["delayed"]); self.assertEqual(got[0]["json"]["rule"], "brute_force")
        self.assertEqual(a.q("SELECT COUNT(*) FROM pending_alerts")[0], 0)
        self.assertIn("delivered queued brute_force alert to webhook", self.err.getvalue())

    def test_backoff_grows_and_caps(self):
        a = self.agent(self.cfg(base_seconds=10, max_backoff_seconds=35))
        self.feed(a, burst(time.time() - 600, "203.0.113.9", 5))
        now, waits = time.time(), []
        for _ in range(4):
            nt = a.q("SELECT next_try FROM pending_alerts")[0]
            with self.cap():
                a.retry_pending(nt + 0.01)
            waits.append(round(a.q("SELECT next_try FROM pending_alerts")[0] - nt - 0.01))
        self.assertEqual(waits, [20, 35, 35, 35])

    def test_max_age_drops(self):
        a = self.agent(self.cfg(max_age_hours=1))
        self.feed(a, burst(time.time() - 600, "203.0.113.9", 5))
        with self.cap():
            a.retry_pending(time.time() + 3601)
        self.assertEqual(a.q("SELECT COUNT(*) FROM pending_alerts")[0], 0)
        self.assertIn("gave up on queued brute_force alert", self.err.getvalue())

    def test_success_makes_queue_due_now_and_disable(self):
        a = self.agent(self.cfg())
        self.feed(a, burst(time.time() - 600, "203.0.113.9", 5))
        a.dests[0]["url"] = self.url + "/ok"
        self.feed(a, burst(time.time() - 500, "203.0.113.10", 5))
        self.assertEqual(a.q("SELECT next_try FROM pending_alerts")[0], 0)
        a = self.agent(self.cfg(enabled=False), name="b")
        self.feed(a, burst(time.time() - 600, "203.0.113.9", 5))
        self.assertEqual(a.q("SELECT COUNT(*) FROM pending_alerts")[0], 0)

    def test_test_alerts_never_queued(self):
        self.sb.config("t", self.cfg())
        self.sb.run("t", "--test-alerts")
        self.assertEqual(self.sb.one("t", "SELECT COUNT(*) FROM pending_alerts"), 0)


class Downtime(Base):
    def follow(self, name):
        e = {k: v for k, v in os.environ.items() if not k.startswith("SSHSENTRY_")}; e["PYTHONUNBUFFERED"] = "1"
        return subprocess.Popen([PY, SCRIPT, "-c", self.sb.path(f"{name}.yaml")], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=e)

    def test_kill9_then_restart_alerts_with_catchup(self):
        self.sb.config("k", {"poll_seconds": 0.2})
        p = self.follow("k"); time.sleep(1.5)
        p.send_signal(signal.SIGKILL); p.communicate()
        self.sb.append("k", burst(time.time() - 60, "203.0.113.9", 5))
        r = self.sb.once("k")
        self.assertIn("MEDIUM: sshsentry was not running from ", r.out)
        self.assertIn("caught up 5 log line(s)", r.out)
        self.assertIn("Brute force", r.out)
        self.assertNotIn("not running", self.sb.once("k").out)   # --once exits cleanly

    def test_sigterm_is_clean(self):
        self.sb.config("k", {"poll_seconds": 0.2})
        p = self.follow("k"); time.sleep(1.5)
        p.terminate(); p.communicate(timeout=10)
        self.assertNotIn("not running", self.sb.once("k").out)

    def test_disabled(self):
        self.sb.config("k", {"poll_seconds": 0.2, "downtime_alert": {"enabled": False}})
        p = self.follow("k"); time.sleep(1.5)
        p.send_signal(signal.SIGKILL); p.communicate()
        self.assertNotIn("not running", self.sb.once("k").out)

