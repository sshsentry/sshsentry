"""Learn mode: replay suggestion, no data, quiet sending, --accept-threshold, end-of-period announcement."""
import time
from helpers import *

BLOCK_YAML = """# my config
log_file: {log}
state_db: {db}
learn_existing_log: false
learn_mode:
  enabled: true
rules:
  new_country: {{enabled: false}}
  new_user: {{enabled: false}}
  new_ssh_key: {{enabled: false}}
  brute_force:
    failures: 5        # keep this comment
    window_minutes: 10
"""


class Learn(Base):
    def test_replay_marks_alerts_and_suggests(self):
        self.sb.config("l", {"learn_mode": {"enabled": True}})
        r = self.sb.run("l", "--replay", SAMPLE)
        alerts = [l for l in r.out.splitlines() if "] " in l and l.startswith("[")]
        self.assertTrue(alerts and all(l.startswith("[learning: not sent] ") for l in alerts), r)
        self.assertIn("suggested rules.brute_force.failures: 8", r.out)
        self.assertIn("data: 12 failed logins from 2 IP(s)", r.out)

    def test_no_data(self):
        self.sb.config("l", {"learn_mode": {"enabled": True}})
        r = self.sb.run("l", "--suggest-threshold")
        self.assertEqual(r.rc, 0); self.assertIn("No failed-login data has been recorded", r.out)

    def test_suggest_after_once_data(self):
        self.sb.config("l", {"learn_mode": {"enabled": True}}); self.sb.once("l")
        self.sb.append("l", open(SAMPLE).read().splitlines()); self.sb.once("l")
        r = self.sb.run("l", "--suggest-threshold")
        self.assertIn("suggested rules.brute_force.failures: 8", r.out); self.assertIn("current manual threshold: 5", r.out)

    def test_learning_sends_nothing(self):
        self.sb.config("l", {"learn_mode": {"enabled": True},
                             "alerting": {"enabled": True, "webhook": {"enabled": True, "url": self.url + "/hook"}}})
        self.sb.once("l"); self.sb.append("l", burst(time.time() - 900, "203.0.113.45", 6)); r = self.sb.once("l")
        self.assertIn("[learning: not sent]", r.out); self.assertEqual(Base.http.requests, [])

    def test_accept_threshold_edits_yaml_keeping_comments(self):
        cfgp = self.sb.config("l", raw=BLOCK_YAML.format(log=self.sb.log("l"), db=self.sb.db("l")))
        open(self.sb.log("l"), "w").close()
        self.sb.run("l", "--replay", SAMPLE)
        r = self.sb.run("l", "--accept-threshold")
        self.assertEqual(r.rc, 0, r); self.assertIn("rules.brute_force.failures = 8", r.out)
        new = open(cfgp).read()
        self.assertIn("failures: 8        # keep this comment", new); self.assertIn("# my config", new)
        self.assertEqual(open(cfgp + ".bak").read(), BLOCK_YAML.format(log=self.sb.log("l"), db=self.sb.db("l")))

    def test_accept_threshold_without_data_fails(self):
        cfgp = self.sb.config("l", raw=BLOCK_YAML.format(log=self.sb.log("l"), db=self.sb.db("l")))
        before = open(cfgp).read()
        r = self.sb.run("l", "--accept-threshold")
        self.assertEqual(r.rc, 1); self.assertEqual(open(cfgp).read(), before)

    def test_accept_threshold_refuses_flow_style(self):
        cfgp = self.sb.config("l", {"learn_mode": {"enabled": True}})
        self.sb.run("l", "--replay", SAMPLE); before = open(cfgp).read()
        r = self.sb.run("l", "--accept-threshold")
        self.assertIn("Could not safely edit", r.out); self.assertEqual(open(cfgp).read(), before)

    def test_end_of_period_announced_once_then_alerts_sent(self):
        self.sb.config("l", {"learn_mode": {"enabled": True, "days": 1},
                             "alerting": {"enabled": True, "webhook": {"enabled": True, "url": self.url + "/hook"}}})
        self.sb.once("l"); self.sb.append("l", burst(time.time() - 7200, "203.0.113.45", 6)); self.sb.once("l")
        self.sb.sql("l", "update meta set v=? where k='learn_start'", str(time.time() - 2 * 86400), commit=True)
        r = self.sb.once("l")
        self.assertIn("learn mode period finished", r.out); self.assertIn("Threshold suggestion", r.out)
        self.assertNotIn("learn mode period finished", self.sb.once("l").out)
        self.sb.append("l", burst(time.time() - 60, "198.51.100.200", 6)); self.sb.once("l")
        self.assertEqual(len(Base.http.at("/hook")), 1)
