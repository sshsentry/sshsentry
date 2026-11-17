"""Daily digest: content, scheduling, no duplicates, catch-up, send off/on, views, resend, quiet days, failures."""
import os, socket, time
from helpers import *

D0, D1, D2, D3 = day(0), day(1), day(2), day(3)


def yesterday_events(prefix_ip="203.0.113.45"):
    t = noon(1)
    return burst(t, prefix_ip, 6, users=("root", "admin")) + burst(t + 600, "192.0.2.77", 6, users=("deploy",)) + \
        [ok(t + 700, "deploy", "192.0.2.77"), ok(t + 800, "chris", "198.51.100.23", "publickey")]


class DigestContent(Base):
    def test_replay_digest_now_content(self):
        r = self.sb.run(None, "-c", DEFAULT_YAML, "--db", self.sb.path("r.db"), "--replay", SAMPLE, "--digest-now", config=False)
        self.assertIn("sshsentry daily digest, replayed log", r.out)
        self.assertIn("Failed logins: 12 from 2 IP address(es).", r.out)
        self.assertIn("Most active: 203.0.113.45, 6 attempts (usernames tried: admin, oracle, root, test).", r.out)
        self.assertIn("deploy from 192.0.2.77 [new IP]  << after 6 failed attempts from that IP. Check this.", r.out)
        self.assertIn("New IPs seen: 3 (198.51.100.23, 192.0.2.77, 100.64.12.9).", r.out)
        self.assertIn("Period: ", r.out)

    def test_replay_digest_private_and_not_stored(self):
        self.sb.config("r", {"alerting": {"enabled": True, "webhook": {"enabled": True, "url": self.url + "/hook"}},
                             "digest": {"enabled": True, "destination": "webhook"}})
        r = self.sb.run("r", "--replay", SAMPLE, "--digest-now")
        dg = r.out[r.out.index("sshsentry daily digest"):]
        for raw in ("sshd[", "Failed password", "port 4", socket.gethostname()):
            self.assertNotIn(raw, dg)
        self.assertEqual(Base.http.requests, []); self.assertEqual(self.sb.one("r", "select count(*) from daily_digests"), 0)

    def test_learn_suggestion_in_digest(self):
        self.sb.config("r", {"learn_mode": {"enabled": True}})
        r = self.sb.run("r", "--replay", SAMPLE, "--digest-now")
        self.assertIn("Learn mode suggests a brute-force threshold of 8 (currently 5)", r.out)

    def test_host_label_in_header(self):
        self.sb.config("r", {"digest": {"host_label": "web-prod"}})
        self.assertIn("sshsentry daily digest for web-prod, replayed log", self.sb.run("r", "--replay", SAMPLE, "--digest-now").out)


class Scheduled(Base):
    def cfg(self, name="d", digest=None, alerting=None):
        dg = deep({"enabled": True, "time": "00:00", "destination": "webhook"}, digest or {})
        al = deep({"webhook": {"url": self.url + "/hook"}, "slack": {"webhook_url": self.url + "/slack"}}, alerting or {})
        self.sb.config(name, {"digest": dg, "alerting": al})

    def scheduled(self, name="d", **kw):
        self.cfg(name, **kw)
        self.sb.once(name, days_ago=1)                 # first run: initializes the schedule only
        self.sb.append(name, yesterday_events())
        return self.sb.once(name)

    def test_disabled_records_nothing(self):
        self.sb.config("d", {"alerting": {"webhook": {"url": self.url + "/hook"}}})
        self.sb.once("d", days_ago=2); self.sb.append("d", yesterday_events()); r = self.sb.once("d")
        self.assertNotIn("daily digest", r.out); self.assertEqual(self.sb.one("d", "select count(*) from daily_digests"), 0)
        self.assertEqual(self.digests_received(), [])

    def test_first_run_only_initializes(self):
        self.cfg(); r = self.sb.once("d")
        self.assertNotIn("daily digest", r.out); self.assertEqual(self.sb.one("d", "select count(*) from daily_digests"), 0)

    def test_generated_stored_and_sent_once(self):
        r = self.scheduled()
        self.assertIn(f"sshsentry daily digest, {D0}", r.out)
        self.assertEqual(self.sb.sql("d", "select date, status, destination from daily_digests"), [(D0, "sent", "webhook")])
        self.assertEqual(len(self.digests_received("/hook")), 1)

    def test_no_duplicates(self):
        self.scheduled(); r = self.sb.once("d"); self.sb.once("d")
        self.assertNotIn("daily digest", r.out); self.assertEqual(len(self.digests_received()), 1)
        self.assertEqual(self.sb.one("d", "select count(*) from daily_digests"), 1)

    def test_stats_json_and_text_file(self):
        self.scheduled()
        st = json.loads(self.sb.one("d", "select stats from daily_digests"))
        self.assertEqual((st["failed_logins"], st["distinct_ips"], st["top_offender"]["ip"], st["flagged_logins"]),
                         (12, 2, "203.0.113.45", 1))
        txt = open(self.sb.path("d-digests", f"{D0}.txt")).read()
        self.assertIn("Failed logins: 12", txt); self.assertIn("Integrity chain: ", txt)

    def test_digest_records_logins(self):
        self.scheduled(); self.assertEqual(self.sb.one("d", "select count(*) from logins"), 2)

    def test_catch_up_only_newest_sent(self):
        self.cfg(); self.sb.once("d", days_ago=4); self.sb.once("d")
        rows = dict(self.sb.sql("d", "select date, status from daily_digests"))
        self.assertEqual(len(rows), 4)
        self.assertEqual(sorted(rows.values()), ["not sent (catch-up)"] * 3 + ["sent"])
        self.assertEqual(rows[D0], "sent"); self.assertEqual(len(self.digests_received()), 1)

    def test_catch_up_capped_at_seven_days(self):
        self.cfg(); self.sb.once("d", days_ago=10); self.sb.once("d")
        self.assertEqual(self.sb.one("d", "select count(*) from daily_digests"), 7)
        self.assertEqual(self.sb.one("d", "select min(date) from daily_digests"), day(6))

    def test_send_off_still_records(self):
        self.cfg(digest={"send": False}); self.sb.once("d", days_ago=3); self.sb.once("d", days_ago=2); self.sb.once("d", days_ago=1)
        self.assertEqual(self.sb.one("d", "select count(*) from daily_digests where status='not sent (digest.send: false)'"), 2)
        self.assertEqual(self.digests_received(), [])

    def test_reenable_sends_only_new_day(self):
        self.test_send_off_still_records()
        self.cfg(digest={"send": True}); self.sb.once("d")
        self.assertEqual(len(self.digests_received()), 1)
        self.assertEqual(self.sb.one("d", "select status from daily_digests where date=?", D0), "sent")
        self.assertEqual(self.sb.one("d", "select count(*) from daily_digests where status='not sent (digest.send: false)'"), 2)

    def test_digests_view(self):
        self.test_send_off_still_records(); self.cfg(); self.sb.once("d")
        r = self.sb.run("d", "--digests")
        self.assertIn("CHAIN", r.out); self.assertIn("DELIVERED", r.out)
        lines = {l.split()[0]: l for l in r.out.splitlines() if l[:4].isdigit()}
        self.assertTrue(lines[D0].endswith("yes")); self.assertIn("no: not sent (digest.send: false)", lines[D1])
        self.assertIn(D2, lines)
        self.assertEqual(len([l for l in self.sb.run("d", "--digests", "1").out.splitlines() if l[:4].isdigit()]), 1)

    def test_digests_view_empty(self):
        self.cfg(); self.assertIn("No daily digests recorded yet", self.sb.run("d", "--digests").out)

    def test_digest_date_view(self):
        self.scheduled(); r = self.sb.run("d", "--digest", D0)
        self.assertEqual(r.rc, 0); self.assertIn(f"sshsentry daily digest, {D0}", r.out)
        self.assertIn("delivery: sent via webhook", r.out); self.assertIn("Integrity chain:", r.out)
        r = self.sb.run("d", "--digest", "1999-01-01")
        self.assertEqual(r.rc, 1); self.assertIn("No digest recorded for 1999-01-01", r.out)

    def test_resend(self):
        self.cfg(digest={"send": False}); self.sb.once("d", days_ago=2); self.sb.once("d", days_ago=1)
        chain = self.sb.one("d", "select chain_hash from daily_digests where date=?", D1)
        self.cfg(); r = self.sb.run("d", "--resend", D1)
        self.assertEqual(r.rc, 0, r); self.assertIn(f"Resend of {D1} via webhook: sent", r.out)
        self.assertEqual(self.sb.one("d", "select status from daily_digests where date=?", D1), "sent")
        self.assertEqual(self.sb.one("d", "select chain_hash from daily_digests where date=?", D1), chain)
        self.assertIn(chain, self.digests_received()[0]["json"]["message"])
        self.assertEqual(self.sb.run("d", "--resend", "1999-01-01").rc, 1)

    def test_quiet_day_sent(self):
        self.cfg(digest={"destination": "slack"}); self.sb.once("d", days_ago=1); r = self.sb.once("d")
        self.assertIn("No incidents today.", r.out)
        self.assertIn("No incidents today.", self.digests_received("/slack")[0]["json"]["text"])
        self.assertEqual(self.sb.one("d", "select status from daily_digests"), "sent")

    def test_quiet_day_skipped_when_configured(self):
        self.cfg(digest={"destination": "slack", "send_when_quiet": False}); self.sb.once("d", days_ago=1); self.sb.once("d")
        self.assertEqual(self.digests_received(), [])
        self.assertTrue(self.sb.one("d", "select status from daily_digests").startswith("skipped (quiet day"))

    def test_destination_down(self):
        self.cfg(alerting={"timeout": 1, "webhook": {"url": "http://127.0.0.1:1/hook"}})
        self.sb.once("d", days_ago=1); r = self.sb.once("d"); r2 = self.sb.once("d")
        self.assertEqual(r.rc, 0); self.assertIn(f"digest for {D0} failed (webhook)", r.err)
        st, err = self.sb.sql("d", "select status, error from daily_digests")[0]
        self.assertEqual(st, "failed"); self.assertTrue(err.startswith("failed (URLError"))
        self.assertNotIn("daily digest", r2.out)   # not retried

    def test_unconfigured_email_and_unwritable_text_dir(self):
        self.cfg(digest={"destination": "email", "text_dir": "/proc/nope"}); self.sb.once("d", days_ago=1); r = self.sb.once("d")
        self.assertEqual(r.rc, 0); self.assertIn("email alert destination DISABLED", r.err)
        self.assertIn("could not write digest text file", r.err)
        self.assertEqual(self.sb.one("d", "select count(*) from daily_digests"), 1)

    def test_email_digest(self):
        self.sb.config("d", {"digest": {"enabled": True, "time": "00:00", "destination": "email"},
                             "email": {"smtp_host": "127.0.0.1", "smtp_port": Base.smtp.port, "starttls": False,
                                       "from": "s@x", "to": ["me@x"]}})
        self.sb.once("d", days_ago=1); self.sb.append("d", yesterday_events()); self.sb.once("d")
        import email, email.policy
        m = email.message_from_string(Base.smtp.messages[0]["data"], policy=email.policy.default)
        self.assertEqual(m["Subject"], "[sshsentry] Daily digest: 12 failed, 2 successful login(s), CHECK flagged login")
        body = m.get_content()
        chain = self.sb.one("d", "select chain_hash from daily_digests")
        self.assertIn(f"Integrity chain: {chain[:12]} (sha256 {chain})", body)

    def test_bad_digest_time(self):
        self.cfg(digest={"time": "8am"}); r = self.sb.once("d")
        self.assertEqual(r.rc, 0); self.assertIn("digest.time '8am' is not HH:MM", r.err)

    def test_digest_now_live_sent_not_stored(self):
        self.cfg(digest={"destination": "slack"}); r = self.sb.run("d", "--digest-now")
        self.assertIn("delivery: sent via slack", r.out); self.assertEqual(len(self.digests_received("/slack")), 1)
        self.assertEqual(self.sb.one("d", "select count(*) from daily_digests"), 0)

    def test_forget_me_keeps_digests(self):
        self.scheduled(); self.sb.run("d", "--forget-me", "--local-only")
        self.assertEqual(self.sb.one("d", "select count(*) from daily_digests"), 1)

    def test_include_chain_hash_false(self):
        self.scheduled(digest={"include_chain_hash": False})
        self.assertNotIn("Integrity chain", self.digests_received()[0]["body"])
        self.assertIn("Integrity chain", open(self.sb.path("d-digests", f"{D0}.txt")).read())
