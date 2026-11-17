"""Alert destinations: Slack/webhook payloads, min_severity, escalation, misconfig, failures, escaping, --test-alerts."""
import time
from helpers import *

ATTACK = "203.0.113.45"


class Alerting(Base):
    def setup_alerts(self, alerting=None, extra=None, name="a"):
        al = {"enabled": True, "timeout": 2,
              "webhook": {"enabled": True, "url": self.url + "/hook"},
              "slack": {"enabled": True, "webhook_url": self.url + "/slack"}}
        self.sb.config(name, deep({"alerting": deep(al, alerting or {})}, extra or {}))
        self.sb.once(name)

    def attack(self, success=True, name="a", ip=ATTACK, users=("root", "admin", "oracle")):
        t = time.time() - 900
        lines = burst(t, ip, 6, users=users) + ([ok(t + 60, "deploy", ip)] if success else [])
        self.sb.append(name, lines)
        return self.sb.once(name)

    def hooks(self, rule=None):
        return [q["json"] for q in Base.http.at("/hook") if rule is None or q["json"]["rule"] == rule]

    def test_master_switch_off_sends_nothing(self):
        self.setup_alerts({"enabled": False}); r = self.attack()
        self.assertIn("Brute force", r.out); self.assertEqual(Base.http.requests, [])

    def test_webhook_payload_fields(self):
        self.setup_alerts(); self.attack(success=False)
        p = self.hooks("brute_force")[0]
        self.assertEqual(set(p), {"severity", "rule", "ip", "usernames", "success", "timestamp", "message"})
        self.assertEqual((p["severity"], p["ip"], p["success"]), ("MEDIUM", ATTACK, False))
        self.assertEqual(p["usernames"], ["admin", "oracle", "root"])
        self.assertIn("no successful login yet", p["message"]); self.assertRegex(p["timestamp"], r"Z$")

    def test_webhook_custom_headers_and_url_env(self):
        self.sb.config("a", {"alerting": {"enabled": True, "webhook": {"enabled": True, "url": "",
                              "headers": {"X-Token": "abc"}}}})
        env = {"SSHSENTRY_WEBHOOK_URL": self.url + "/hook"}
        self.sb.once("a", env=env); self.sb.append("a", burst(time.time() - 900, ATTACK, 5)); self.sb.once("a", env=env)
        self.assertEqual(Base.http.at("/hook")[0]["headers"]["X-Token"], "abc")

    def test_slack_payload_is_text_only(self):
        self.setup_alerts(); self.attack(success=False)
        p = Base.http.at("/slack")[0]["json"]
        self.assertEqual(set(p), {"text"}); self.assertTrue(p["text"].startswith("[sshsentry] MEDIUM: Brute force"))

    def test_min_severity_defaults(self):
        self.setup_alerts(); self.sb.append("a", [ok(time.time() - 60, "amy", "198.51.100.9")]); self.sb.once("a")
        self.assertEqual(len(self.hooks("new_ip")), 1)          # webhook default LOW
        self.assertEqual(Base.http.at("/slack"), [])            # slack default MEDIUM

    def test_min_severity_high_filters_medium(self):
        self.setup_alerts({"webhook": {"min_severity": "HIGH"}}); self.attack(success=False)
        self.assertEqual(self.hooks(), [])

    def test_unknown_min_severity_warns_and_uses_low(self):
        self.setup_alerts({"webhook": {"min_severity": "loud"}})
        r = self.sb.once("a"); self.assertIn("min_severity 'LOUD' unknown; using LOW", r.err)
        self.sb.append("a", [ok(time.time() - 60, "amy", "198.51.100.9")]); self.sb.once("a")
        self.assertEqual(len(self.hooks("new_ip")), 1)

    def test_escalation_replaces_high_alert(self):
        self.setup_alerts(); r = self.attack()
        self.assertIn("CRITICAL: ESCALATION: successful login from 203.0.113.45 after brute force", r.out)
        self.assertNotIn("HIGH: Login after failures", r.out)
        esc = self.hooks("brute_force_success")
        self.assertEqual(len(esc), 1); self.assertTrue(esc[0]["success"]); self.assertEqual(esc[0]["usernames"][0], "deploy")

    def test_escalation_once_across_once_runs(self):
        self.setup_alerts(); self.attack(success=False)
        t = time.time() - 300
        self.sb.append("a", [ok(t, "deploy", ATTACK)]); self.sb.once("a")
        self.sb.append("a", [ok(t + 30, "deploy", ATTACK), ok(t + 40, "web", ATTACK)]); r3 = self.sb.once("a")
        self.assertEqual(len(self.hooks("brute_force_success")), 1, r3)
        self.assertEqual(self.sb.one("a", "select escalated from alerted_ips where ip=?", ATTACK), 1)

    def test_no_escalation_when_alerting_disabled(self):
        self.setup_alerts({"enabled": False}); r = self.attack()
        self.assertIn("HIGH: Login after failures", r.out); self.assertNotIn("CRITICAL", r.out)

    def test_prior_success_mentioned_in_brute_force_payload(self):
        self.setup_alerts(); self.sb.append("a", [ok(time.time() - 3000, "deploy", ATTACK)]); self.sb.once("a")
        self.attack(success=False)
        self.assertIn("a successful login from this IP was seen earlier (user 'deploy')", self.hooks("brute_force")[0]["message"])

    def test_misconfigured_destinations_warn_and_continue(self):
        self.sb.config("a", {"alerting": {"enabled": True, "slack": {"enabled": True, "webhook_url": "http://example.com/x"},
                                          "webhook": {"enabled": True, "url": self.url + "/hook", "headers": {"X": 1}},
                                          "email": {"enabled": True}}})
        r = self.sb.once("a")
        self.assertEqual(r.rc, 0)
        self.assertIn("slack alert destination DISABLED: URL missing or not https://", r.err)
        self.assertIn("webhook alert destination DISABLED: headers must be a mapping", r.err)
        self.assertIn("email alert destination DISABLED: smtp_host is not set", r.err)

    def test_endpoint_down_logged_not_fatal(self):
        self.setup_alerts({"webhook": {"url": "http://127.0.0.1:1/hook"}, "slack": {"enabled": False}})
        r = self.attack(success=False)
        self.assertEqual(r.rc, 0); self.assertIn("Brute force", r.out); self.assertIn("webhook alert failed: failed (", r.err)

    def test_http_500_logged(self):
        self.setup_alerts({"webhook": {"url": self.url + "/fail"}, "slack": {"enabled": False}})
        r = self.attack(success=False); self.assertIn("webhook alert failed: failed (HTTP 500)", r.err)

    def test_timeout(self):
        self.setup_alerts({"timeout": 1, "webhook": {"url": self.url + "/slow"}, "slack": {"enabled": False}})
        t = time.time(); r = self.attack(success=False)
        self.assertIn("webhook alert failed: failed (", r.err); self.assertLess(time.time() - t, 6)

    def test_slack_escaping(self):
        self.setup_alerts(); self.attack(success=False, users=("<!channel>", "a&b"))
        text = Base.http.at("/slack")[0]["json"]["text"]
        self.assertIn("&lt;!channel&gt;", text); self.assertIn("a&amp;b", text); self.assertNotIn("<!channel>", text)

    def test_alerting_email_inherits_legacy_smtp(self):
        self.sb.config("a", {"email": {"smtp_host": "127.0.0.1", "smtp_port": Base.smtp.port, "starttls": False,
                                       "from": "s@x", "to": ["me@x"]},
                             "alerting": {"enabled": True, "email": {"enabled": True, "min_severity": "MEDIUM"}}})
        self.sb.once("a"); self.sb.append("a", [ok(time.time() - 3000, "amy", "198.51.100.9")]); self.sb.once("a")
        self.assertEqual(Base.smtp.messages, [])                  # LOW filtered
        self.attack(success=False); self.assertEqual(len(Base.smtp.messages), 1)


class TestAlerts(Base):
    def test_sends_to_each_destination(self):
        self.sb.config("t", {"alerting": {"webhook": {"enabled": True, "url": self.url + "/hook/secret-token"},
                                          "slack": {"enabled": True, "webhook_url": self.url + "/slack"}}})
        r = self.sb.run("t", "--test-alerts")
        self.assertEqual(r.rc, 0, r); self.assertIn("alerting.enabled is false", r.out)
        self.assertEqual(r.out.count("-> sent"), 2)
        self.assertNotIn("secret-token", r.out + r.err)            # only the host is printed
        self.assertEqual(Base.http.at("/hook/secret-token")[0]["json"]["rule"], "test")

    def test_failure_exit_code(self):
        self.sb.config("t", {"alerting": {"enabled": True, "webhook": {"enabled": True, "url": self.url + "/fail"}}})
        r = self.sb.run("t", "--test-alerts"); self.assertEqual(r.rc, 1); self.assertIn("failed (HTTP 500)", r.out)

    def test_no_destinations(self):
        self.sb.config("t"); r = self.sb.run("t", "--test-alerts")
        self.assertEqual(r.rc, 1); self.assertIn("No usable alert destinations", r.out)

    def test_email_test_alert(self):
        self.sb.config("t", {"email": {"smtp_host": "127.0.0.1", "smtp_port": Base.smtp.port, "starttls": False,
                                       "from": "s@x", "to": ["me@x"]}, "alerting": {"email": {"enabled": True}}})
        r = self.sb.run("t", "--test-alerts")
        self.assertEqual(r.rc, 0, r); self.assertIn("Test alert from sshsentry", Base.smtp.messages[0]["data"])
