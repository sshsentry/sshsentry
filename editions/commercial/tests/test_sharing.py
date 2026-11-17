"""Opt-in sharing: off by default, payload contents, filters, https enforcement, failures, show-shared, forget-me."""
import time
from helpers import *

ATTACK = "203.0.113.45"


class Sharing(Base):
    def setup_share(self, endpoint=None, extra=None):
        cfg = {"sharing": {"enabled": True, "endpoint": endpoint or self.url + "/report", "timeout": 2}}
        self.sb.config("s", deep(cfg, extra or {})); self.sb.once("s")

    def attack(self, ip=ATTACK, success=True):
        t = time.time() - 900
        lines = burst(t, ip, 6, users=("root", "admin"))
        if success:
            lines.append(ok(t + 60, "deploy", ip))
        self.sb.append("s", lines)
        return self.sb.once("s")

    def test_off_by_default_sends_nothing(self):
        self.sb.config("s"); self.sb.once("s"); self.attack()
        self.assertEqual(Base.http.requests, [])
        r = self.sb.run("s", "--show-shared")
        self.assertIn("Sharing is OFF", r.out); self.assertIn("Nothing has been shared yet", r.out)

    def test_shares_brute_force_and_login_after_failures_only(self):
        self.setup_share(); r = self.attack()
        rules = sorted(q["json"]["rule"] for q in Base.http.at("/report"))
        self.assertEqual(rules, ["brute_force", "login_after_failures"], r)   # new_ip is never shared

    def test_payload_has_exactly_the_documented_fields(self):
        self.setup_share(); self.attack()
        for q in Base.http.at("/report"):
            p = q["json"]
            self.assertEqual(set(p), {"ip", "rule", "timestamp", "sshsentry_version", "install_id"})
            self.assertEqual(p["ip"], ATTACK); self.assertRegex(p["timestamp"], r"T\d\d:\d\d:00Z$")
            for secret in ("root", "admin", "deploy", "web01"):
                self.assertNotIn(secret, q["body"])
        self.assertEqual(len({q["json"]["install_id"] for q in Base.http.at("/report")}), 1)

    def test_user_agent_header(self):
        self.setup_share(); self.attack()
        self.assertEqual(Base.http.at("/report")[0]["headers"]["User-Agent"], f"sshsentry/{S.VERSION}")

    def test_private_ip_never_shared(self):
        self.setup_share(); self.attack("10.1.2.3")
        self.assertEqual(Base.http.requests, [])

    def test_approved_ip_never_shared(self):
        self.setup_share(); self.sb.run("s", "--approve", ATTACK); self.attack()
        self.assertEqual(Base.http.requests, [])

    def test_plain_http_endpoint_refused(self):
        self.sb.config("s", {"sharing": {"enabled": True, "endpoint": "http://example.com/report"}})
        r = self.sb.once("s")
        self.assertIn("sharing DISABLED", r.err); self.assertIn("https://", r.err)
        self.sb.append("s", burst(time.time() - 900, ATTACK, 6)); self.sb.once("s")
        self.assertEqual(self.sb.one("s", "select count(*) from shared"), 0)

    def test_endpoint_rules(self):
        self.assertIsNone(S.endpoint_problem("https://intel.example.com/r"))
        self.assertIsNone(S.endpoint_problem("http://localhost:8080/r"))
        self.assertIsNone(S.endpoint_problem("http://127.0.0.1/r"))
        for bad in ("http://example.com/r", "ftp://example.com", "", "localhost"):
            self.assertIsNotNone(S.endpoint_problem(bad), bad)

    def test_failures_recorded(self):
        self.setup_share(self.url + "/fail"); r = self.attack()
        rows = self.sb.sql("s", "select status from shared")
        self.assertEqual(len(rows), 2); self.assertTrue(all(st == "failed (HTTP 500)" for (st,) in rows))
        self.assertIn("sharing report for 203.0.113.45 failed (HTTP 500)", r.err); self.assertEqual(r.rc, 0)

    def test_endpoint_down_recorded(self):
        self.setup_share("http://127.0.0.1:1/report"); r = self.attack()
        self.assertEqual(r.rc, 0)
        self.assertTrue(all(st.startswith("failed (") for (st,) in self.sb.sql("s", "select status from shared")))

    def test_show_shared_lists_reports(self):
        self.setup_share(); self.attack()
        r = self.sb.run("s", "--show-shared")
        self.assertIn(f"Sharing is ON -> {self.url}/report", r.out)
        self.assertIn("2 report(s) recorded", r.out); self.assertIn(ATTACK, r.out); self.assertIn("sent (HTTP 200)", r.out)

    def test_forget_me_deletes_and_requests_remote_deletion(self):
        self.setup_share(); self.attack()
        old = self.sb.one("s", "select v from meta where k='install_id'")
        Base.http.clear()
        r = self.sb.run("s", "--forget-me")
        self.assertIn("Deleted 2 shared-report record(s)", r.out); self.assertIn(f"Old install ID: {old}", r.out)
        req = Base.http.at("/report")[0]["json"]
        self.assertEqual(req["request"], "delete"); self.assertEqual(req["install_id"], old)
        self.assertEqual(self.sb.one("s", "select count(*) from shared"), 0)
        self.assertIn("sharing is still enabled", r.out)

    def test_forget_me_local_only_and_new_id(self):
        self.setup_share(); self.attack()
        old = self.sb.one("s", "select v from meta where k='install_id'")
        Base.http.clear(); self.sb.run("s", "--forget-me", "--local-only")
        self.assertEqual(Base.http.requests, [])
        self.sb.append("s", burst(time.time() - 300, "198.51.100.200", 6)); self.sb.once("s")
        new = self.sb.one("s", "select v from meta where k='install_id'")
        self.assertTrue(new and new != old)
