"""--export-digests, sha256sum sidecar, hash chain, --verify-chain, --verify-export, upgrade backfill."""
import hashlib, os, shutil, sqlite3, subprocess, zipfile
from helpers import *
from test_digest import yesterday_events

D0, D1, D2, D3 = day(0), day(1), day(2), day(3)


def four_days(t, name="ch"):
    """Digests for D3..D0 (D1 holds the attack), delivered to the capture webhook."""
    t.sb.config(name, {"digest": {"enabled": True, "time": "00:00", "destination": "webhook"},
                       "alerting": {"webhook": {"url": t.url + "/hook"}}})
    t.sb.once(name, days_ago=4); t.sb.once(name, days_ago=3); t.sb.once(name, days_ago=2)
    t.sb.append(name, yesterday_events()); t.sb.once(name, days_ago=0.0001)   # today's digest covers yesterday
    return t.sb.one(name, "select chain_hash from daily_digests order by date desc limit 1")


def rezip(src, dst, edit):
    z = zipfile.ZipFile(src); files = {n: z.read(n) for n in z.namelist()}; z.close()
    edit(files)
    with zipfile.ZipFile(dst, "w") as o:
        for n, b in files.items():
            o.writestr(n, b)


class Export(Base):
    def setUp(self):
        super().setUp(); self.head = four_days(self)
        self.r = self.sb.run("ch", "--export-digests", D3, D0, "-o", self.sb.path("ex.zip"))
        self.zip = self.sb.path("ex.zip")

    def test_export_outputs(self):
        self.assertEqual(self.r.rc, 0, self.r)
        self.assertIn(f"Exported 4 digest(s) (0 missing day(s)) to {self.zip}", self.r.out)
        digest = hashlib.sha256(open(self.zip, "rb").read()).hexdigest()
        self.assertIn(f"SHA-256: {digest}", self.r.out); self.assertIn(f"Chain head: {self.head}", self.r.out)
        n = zipfile.ZipFile(self.zip).namelist()
        self.assertIn("manifest.json", n)
        self.assertEqual(sum(x.startswith("digests/") for x in n), 4); self.assertEqual(sum(x.startswith("records/") for x in n), 4)

    def test_sidecar_sha256sum_format(self):
        p = subprocess.run(["sha256sum", "-c", "ex.zip.sha256"], cwd=self.sb.dir, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_manifest_hashes_no_hostname(self):
        z = zipfile.ZipFile(self.zip); m = json.loads(z.read("manifest.json"))
        self.assertEqual(m["schema"], "sshsentry.export_manifest/2"); self.assertEqual(m["sshsentry_version"], S.VERSION)
        self.assertEqual(m["chain_head"], self.head); self.assertNotIn("host_label", m); self.assertEqual(m["missing_dates"], [])
        for d in m["days"]:
            for k in ("text", "record"):
                self.assertEqual(hashlib.sha256(z.read(d[k + "_file"])).hexdigest(), d[k + "_sha256"])
        host = socket_host()
        self.assertTrue(all(host.encode() not in z.read(n) for n in z.namelist()))

    def test_edit_detected_by_sha256sum(self):
        with open(self.zip, "ab") as f:
            f.write(b"x")
        p = subprocess.run(["sha256sum", "-c", "ex.zip.sha256"], cwd=self.sb.dir, capture_output=True)
        self.assertNotEqual(p.returncode, 0)

    def test_missing_days_and_host_label(self):
        self.sb.sql("ch", "delete from daily_digests where date=?", D2, commit=True)
        r = self.sb.run("ch", "--export-digests", D3, D0, "-o", self.sb.path("gap.zip"), "--host-label", "web-prod")
        self.assertIn("(1 missing day(s))", r.out)
        z = zipfile.ZipFile(self.sb.path("gap.zip")); m = json.loads(z.read("manifest.json"))
        self.assertEqual(m["missing_dates"], [D2]); self.assertEqual(m["host_label"], "web-prod")
        self.assertIn(D2.encode(), z.read("MISSING-DAYS.txt"))

    def test_empty_range(self):
        r = self.sb.run("ch", "--export-digests", "1999-01-01", "1999-01-31")
        self.assertEqual(r.rc, 1); self.assertIn("No daily digests are stored between", r.err)

    def test_bad_dates(self):
        self.assertEqual(self.sb.run("ch", "--export-digests", "2026-13-01", D0).rc, 2)
        self.assertEqual(self.sb.run("ch", "--export-digests", D0, D3).rc, 2)

    def test_default_output_name(self):
        r = self.sb.run("ch", "--export-digests", D3, D0)
        self.assertTrue(os.path.exists(self.sb.path(f"sshsentry-digests-{D3}_to_{D0}.zip")), r)

    # ---------- --verify-export ----------
    def verify(self, path, *extra):
        return self.sb.run(None, "--verify-export", path, *extra, config=False)

    def test_verify_export_pass_with_expected_head(self):
        r = self.verify(self.zip, "--expected-head", self.head)
        self.assertEqual(r.rc, 0, r); self.assertIn("RESULT: PASS", r.out)
        self.assertIn("PASS  sidecar", r.out); self.assertIn("PASS  expected", r.out); self.assertNotIn("FAIL", r.out)

    def test_expected_head_prefix_and_earlier_day(self):
        self.assertEqual(self.verify(self.zip, "--expected-head", self.head[:12]).rc, 0)
        mid = self.sb.one("ch", "select chain_hash from daily_digests where date=?", D2)
        r = self.verify(self.zip, "--expected-head", mid)
        self.assertEqual(r.rc, 0); self.assertIn(f"matches the chain at {D2} (not the head)", r.out)

    def test_expected_head_mismatch_and_too_short(self):
        r = self.verify(self.zip, "--expected-head", "0123456789abcdef")
        self.assertEqual(r.rc, 1); self.assertIn("FAIL  expected", r.out); self.assertIn("RESULT: FAIL", r.out)
        self.assertEqual(self.verify(self.zip, "--expected-head", self.head[:8]).rc, 1)

    def test_sidecar_mismatch(self):
        shutil.copy(self.zip, self.sb.path("sc.zip"))
        open(self.sb.path("sc.zip.sha256"), "w").write("0" * 64 + "  sc.zip\n")
        r = self.verify(self.sb.path("sc.zip")); self.assertEqual(r.rc, 1); self.assertIn("FAIL  sidecar", r.out)

    def test_no_sidecar_skipped(self):
        shutil.copy(self.zip, self.sb.path("ns.zip"))
        r = self.verify(self.sb.path("ns.zip")); self.assertEqual(r.rc, 0); self.assertIn("no .sha256 file", r.out)

    def forge(self, dst, recompute_chain=False):
        def edit(files):
            m = json.loads(files["manifest.json"])
            rec = json.loads(files[f"records/{D2}.json"]); rec["text"] = rec["text"].replace("Period", "Peri0d")
            files[f"records/{D2}.json"] = (json.dumps(rec, indent=2, sort_keys=True) + "\n").encode()
            files[f"digests/{D2}.txt"] = files[f"digests/{D2}.txt"].replace(b"Period", b"Peri0d")
            prev = m["days"][0]["prev_hash"]
            for d in m["days"]:
                r = json.loads(files[d["record_file"]])
                if recompute_chain:
                    ch = S.chain_next(prev, r)
                    r["prev_hash"] = d["prev_hash"] = prev; r["chain_hash"] = d["chain_hash"] = ch
                    files[d["record_file"]] = (json.dumps(r, indent=2, sort_keys=True) + "\n").encode()
                    files[d["text_file"]] = (S.with_chain(r["text"], ch) + "\n").encode()
                    prev = ch
                for k in ("text", "record"):
                    d[k + "_sha256"] = hashlib.sha256(files[d[k + "_file"]]).hexdigest()
            if recompute_chain:
                m["chain_head"] = prev
            files["manifest.json"] = json.dumps(m, indent=2).encode()
        rezip(self.zip, dst, edit)

    def test_edited_day_breaks_chain_at_that_day(self):
        self.forge(self.sb.path("forged.zip")); r = self.verify(self.sb.path("forged.zip"))
        self.assertEqual(r.rc, 1); self.assertIn(f"First broken day: {D2}", r.out)
        self.assertIn(f"FAIL  chain      {D2}", r.out); self.assertIn(f"PASS  chain      {D3}", r.out)

    def test_rewritten_chain_passes_alone_fails_with_expected_head(self):
        self.forge(self.sb.path("rw.zip"), recompute_chain=True)
        self.assertEqual(self.verify(self.sb.path("rw.zip")).rc, 0)                   # the documented limit
        r = self.verify(self.sb.path("rw.zip"), "--expected-head", self.head[:16])
        self.assertEqual(r.rc, 1); self.assertIn("FAIL  expected", r.out)

    def test_edited_text_file_only(self):
        rezip(self.zip, self.sb.path("t.zip"), lambda f: f.update({f"digests/{D1}.txt": f[f"digests/{D1}.txt"].replace(b"Period", b"Peri0d")}))
        r = self.verify(self.sb.path("t.zip")); self.assertEqual(r.rc, 1); self.assertIn(f"FAIL  text_sha   {D1}", r.out)

    def test_unlisted_file_fails(self):
        rezip(self.zip, self.sb.path("u.zip"), lambda f: f.update({"extra.txt": b"hi"}))
        r = self.verify(self.sb.path("u.zip")); self.assertEqual(r.rc, 1); self.assertIn("unlisted files: extra.txt", r.out)

    def test_not_a_zip(self):
        open(self.sb.path("bad.zip"), "w").write("hi")
        r = self.verify(self.sb.path("bad.zip"))
        self.assertEqual(r.rc, 1); self.assertIn("RESULT: FAIL", r.out); self.assertNotIn("Traceback", r.err)


def socket_host():
    import socket
    return socket.gethostname()


class Chain(Base):
    def setUp(self):
        super().setUp(); self.head = four_days(self)

    def test_genesis_and_links(self):
        rows = self.sb.sql("ch", "select prev_hash, chain_hash from daily_digests order by date")
        self.assertEqual(rows[0][0], hashlib.sha256(b"sshsentry-genesis-v1").hexdigest())
        self.assertTrue(all(rows[i][0] == rows[i - 1][1] for i in range(1, len(rows))))

    def test_chain_recomputes_from_stored_fields(self):
        prev = S.GENESIS
        for d, ps, pe, st, txt, ch in self.sb.sql("ch", "select date, period_start, period_end, stats, text, chain_hash from daily_digests order by date"):
            prev2 = S.chain_next(prev, {"date": d, "period_start": ps, "period_end": pe, "stats": json.loads(st), "text": txt})
            self.assertEqual(prev2, ch); prev = ch

    def test_delivered_and_text_copy_carry_chain(self):
        body = self.digests_received("/hook")[-1]["json"]["message"]
        self.assertIn(f"Integrity chain: {self.head[:12]} (sha256 {self.head})", body)
        self.assertIn(self.head, open(self.sb.path("ch-digests", f"{D0}.txt")).read())

    def test_verify_chain_passes(self):
        r = self.sb.run("ch", "--verify-chain")
        self.assertEqual(r.rc, 0, r); self.assertIn("RESULT: PASS (local database; 4 day(s)", r.out); self.assertNotIn("FAIL", r.out)

    def test_db_edit_breaks_chain_at_that_day(self):
        self.sb.sql("ch", "update daily_digests set text=replace(text,'Period','Peri0d') where date=?", D2, commit=True)
        r = self.sb.run("ch", "--verify-chain")
        self.assertEqual(r.rc, 1); self.assertIn(f"First broken day: {D2}", r.out)
        self.assertIn(f"FAIL  chain      {D2}  content changed after it was recorded", r.out)
        self.assertIn(f"PASS  chain      {D3}", r.out); self.assertIn(f"PASS  chain      {D1}", r.out)

    def test_deleted_day_breaks_link_at_next_day(self):
        self.sb.sql("ch", "delete from daily_digests where date=?", D2, commit=True)
        r = self.sb.run("ch", "--verify-chain")
        self.assertEqual(r.rc, 1); self.assertIn(f"First broken day: {D1}", r.out); self.assertIn("previous-hash link broken", r.out)

    def test_text_copy_tamper_detected(self):
        p = self.sb.path("ch-digests", f"{D1}.txt"); open(p, "a").write("extra\n")
        r = self.sb.run("ch", "--verify-chain")
        self.assertEqual(r.rc, 1); self.assertIn(f"FAIL  text_file  {D1}", r.out)

    def test_upgrade_backfill_from_old_schema(self):
        db = self.sb.db("ch")
        old = [(d, txt) for d, txt in self.sb.sql("ch", "select date, text from daily_digests")]
        c = sqlite3.connect(db)   # rebuild daily_digests exactly as the pre-chain version created it
        c.executescript("""
            CREATE TABLE old AS SELECT date, period_start, period_end, created_at, stats, text, status, destination, error FROM daily_digests;
            DROP TABLE daily_digests;
            CREATE TABLE daily_digests (date TEXT PRIMARY KEY, period_start REAL, period_end REAL, created_at REAL,
                stats TEXT, text TEXT, status TEXT, destination TEXT, error TEXT);
            INSERT INTO daily_digests SELECT * FROM old; DROP TABLE old;""")
        c.commit(); c.close()
        for d, txt in old:   # old text copies had no chain line
            open(self.sb.path("ch-digests", f"{d}.txt"), "w").write(txt + "\n")
        r = self.sb.run("ch", "--verify-chain")
        self.assertEqual(r.rc, 0, r)
        self.assertIn("added integrity chain hashes to 4 existing digest(s)", r.err)
        self.assertEqual(self.sb.one("ch", "select count(*) from daily_digests where chain_hash is not null"), 4)
        self.assertEqual(self.sb.one("ch", "select chain_hash from daily_digests where date=?", D0), self.head)
        self.assertIn("Integrity chain:", open(self.sb.path("ch-digests", f"{D0}.txt")).read())
        self.assertNotIn("added integrity", self.sb.run("ch", "--digests").err)          # only once
        self.sb.once("ch", days_ago=-1)                                                  # next day links on
        r = self.sb.run("ch", "--verify-chain")
        self.assertEqual(r.rc, 0, r); self.assertIn("RESULT: PASS (local database; 5 day(s)", r.out)
