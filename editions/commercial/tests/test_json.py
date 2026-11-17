"""--format json: every command emits parseable JSON with a versioned schema field."""
from helpers import *
from test_export_chain import four_days, D0, D3


class Json(Base):
    def test_replay_json(self):
        r = self.sb.run(None, "-c", DEFAULT_YAML, "--db", self.sb.path("r.db"), "--replay", SAMPLE, "--digest-now",
                        "--format", "json", config=False)
        d = r.json()
        self.assertEqual(d["schema"], "sshsentry.replay/1"); self.assertEqual(len(d["alerts"]), 6)
        self.assertEqual(set(d["alerts"][0]), {"time", "timestamp", "severity", "rule", "message", "learning"})
        st = d["digest"]["stats"]
        self.assertEqual((st["failed_logins"], st["distinct_ips"], st["top_offender"]["ip"]), (12, 2, "203.0.113.45"))

    def test_replay_json_with_learn_mode(self):
        self.sb.config("l", {"learn_mode": {"enabled": True}})
        d = self.sb.run("l", "--replay", SAMPLE, "--format", "json").json()
        self.assertEqual(d["threshold_suggestion"]["schema"], "sshsentry.threshold_suggestion/1")
        self.assertTrue(all(a["learning"] for a in d["alerts"]))

    def test_suggest_threshold_json(self):
        self.sb.config("l", {"learn_mode": {"enabled": True}})
        empty = self.sb.run("l", "--suggest-threshold", "--format", "json").json()
        self.assertIsNone(empty["suggested"])
        self.sb.run("l", "--replay", SAMPLE)
        d = self.sb.run("l", "--suggest-threshold", "--format", "json").json()
        self.assertEqual((d["schema"], d["suggested"], d["current"], d["stats"]["failed_logins"]),
                         ("sshsentry.threshold_suggestion/1", 8, 5, 12))

    def test_show_shared_json(self):
        self.sb.config("s")
        d = self.sb.run("s", "--show-shared", "--format", "json").json()
        self.assertEqual((d["schema"], d["sharing_enabled"], d["reports"]), ("sshsentry.shared/1", False, []))

    def test_digests_and_digest_json(self):
        head = four_days(self)
        d = self.sb.run("ch", "--digests", "--format", "json").json()
        self.assertEqual((d["schema"], d["count"]), ("sshsentry.digests/1", 4))
        self.assertTrue(all(len(x["chain_hash"]) == 64 and "text" not in x for x in d["digests"]))
        one = self.sb.run("ch", "--digest", D0, "--format", "json").json()
        self.assertEqual((one["schema"], one["found"], one["stored"], one["chain_hash"]), ("sshsentry.digest/1", True, True, head))
        self.assertIn(head, one["text"]); self.assertEqual(one["delivery"]["status"], "sent")
        r = self.sb.run("ch", "--digest", "1999-01-01", "--format", "json")
        self.assertEqual(r.rc, 1); self.assertFalse(r.json()["found"])

    def test_digest_now_json(self):
        self.sb.config("n", {"digest": {"send": False}})
        d = self.sb.run("n", "--digest-now", "--format", "json").json()
        self.assertEqual((d["schema"], d["stored"]), ("sshsentry.digest/1", False))
        self.assertTrue(d["delivery"]["status"].startswith("off"))

    def test_export_json(self):
        head = four_days(self)
        d = self.sb.run("ch", "--export-digests", D3, D0, "-o", self.sb.path("e.zip"), "--format", "json").json()
        self.assertEqual((d["schema"], d["ok"], d["exported_days"], d["chain_head"]), ("sshsentry.export/1", True, 4, head))
        bad = self.sb.run("ch", "--export-digests", "x", "y", "--format", "json")
        self.assertEqual(bad.rc, 2); self.assertFalse(bad.json()["ok"])

    def test_verify_json(self):
        head = four_days(self)
        v = self.sb.run("ch", "--verify-chain", "--format", "json").json()
        self.assertEqual((v["schema"], v["ok"], v["chain_head"], v["first_broken_date"]), ("sshsentry.verify/1", True, head, None))
        self.sb.run("ch", "--export-digests", D3, D0, "-o", self.sb.path("e.zip"))
        e = self.sb.run(None, "--verify-export", self.sb.path("e.zip"), "--format", "json", config=False).json()
        self.assertEqual((e["schema"], e["ok"], e["days"]), ("sshsentry.verify/1", True, 4))
        self.assertTrue(all({"check", "date", "ok", "detail"} <= set(c) for c in e["checks"]))
