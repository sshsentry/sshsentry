"""Shared helpers for the sshsentry test suite: sandboxes, config files, log-line fixtures, runners."""
import json, os, shutil, sqlite3, subprocess, sys, tempfile, time, unittest
from datetime import date, datetime, timedelta

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
SCRIPT = os.environ.get("SSHSENTRY_TEST_SCRIPT") or os.path.join(ROOT, "sshsentry.py")   # override to test another build
SAMPLE = os.path.join(ROOT, "sample-auth.log")
DEFAULT_YAML = os.path.join(ROOT, "sshsentry.yaml")
PY = sys.executable
sys.path.insert(0, ROOT)
import sshsentry as S   # imported only for pure helper functions; the program itself runs as a subprocess


def deep(base, over):
    out = dict(base)
    for k, v in over.items():
        out[k] = deep(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


# ---------- log-line fixtures (syslog format, local time) ----------
def line(ts, msg, proc="sshd", pid=2000, host="web01"):
    d = datetime.fromtimestamp(ts)
    return f"{d:%b} {d.day:>2} {d:%H:%M:%S} {host} {proc}[{pid}]: {msg}"

def fail(ts, user, ip, **kw):
    return line(ts, f"Failed password for {user} from {ip} port 40000 ssh2", **kw)

def invalid(ts, user, ip, **kw):
    return line(ts, f"Invalid user {user} from {ip} port 40000", **kw)

def ok(ts, user, ip, method="password", **kw):
    return line(ts, f"Accepted {method} for {user} from {ip} port 50000 ssh2", **kw)

def burst(t0, ip, n, users=("root",), step=5):
    return [fail(t0 + i * step, users[i % len(users)], ip) for i in range(n)]

def noon(days_ago):
    """Local noon `days_ago` days ago (inside that day's digest period for digest.time 00:00)."""
    d = date.today() - timedelta(days=days_ago)
    return datetime(d.year, d.month, d.day, 12, 0, 0).timestamp()

def day(days_ago):
    return (date.today() - timedelta(days=days_ago)).isoformat()


class Result:
    def __init__(self, p):
        self.rc, self.out, self.err = p.returncode, p.stdout, p.stderr
    def json(self):
        return json.loads(self.out)
    def __repr__(self):
        return f"rc={self.rc}\n--- stdout\n{self.out}\n--- stderr\n{self.err}"


class Sandbox:
    """A temp directory with named configs; each name gets its own log, DB and digest folder."""
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="sshsentry-test-")

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def path(self, *p):
        return os.path.join(self.dir, *p)

    def config(self, name="c", cfg=None, raw=None, log=True):
        """Write NAME.yaml (JSON is valid YAML) with safe test defaults merged under `cfg`."""
        base = {"log_file": self.path(f"{name}.log"), "state_db": self.path(f"{name}.db"),
                "learn_existing_log": False,
                "rules": {"new_user": {"enabled": False}, "new_ssh_key": {"enabled": False},
                          "new_country": {"enabled": False}},
                "digest": {"text_dir": self.path(f"{name}-digests")}}
        with open(self.path(f"{name}.yaml"), "w") as f:
            f.write(raw if raw is not None else json.dumps(deep(base, cfg or {}), indent=1))
        if log and not os.path.exists(self.path(f"{name}.log")):
            open(self.path(f"{name}.log"), "w").close()
        return self.path(f"{name}.yaml")

    def log(self, name):
        return self.path(f"{name}.log")

    def db(self, name):
        return self.path(f"{name}.db")

    def append(self, name, lines):
        with open(self.log(name), "a") as f:
            f.write("".join(l + "\n" for l in lines))

    def run(self, name, *args, days_ago=None, now=None, env=None, timeout=60, config=True):
        e = {k: v for k, v in os.environ.items() if not k.startswith("SSHSENTRY_")}
        e["PYTHONUNBUFFERED"] = "1"
        if days_ago is not None:
            now = time.time() - days_ago * 86400
        if now is not None:
            e["SSHSENTRY_TEST_NOW"] = str(now)
        e.update(env or {})
        cmd = [PY, SCRIPT] + (["-c", self.path(f"{name}.yaml")] if config and name else []) + list(args)
        return Result(subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=e, cwd=self.dir))

    def once(self, name, **kw):
        return self.run(name, "--once", **kw)

    def sql(self, name, q, *args, commit=False):
        c = sqlite3.connect(self.db(name))
        try:
            rows = c.execute(q, args).fetchall()
            if commit:
                c.commit()
            return rows
        finally:
            c.close()

    def one(self, name, q, *args):
        rows = self.sql(name, q, *args)
        return rows[0][0] if rows else None


class Base(unittest.TestCase):
    http = smtp = None   # set by the runner (shared capture servers)

    def setUp(self):
        self.sb = Sandbox()
        if Base.http:
            Base.http.clear()
        if Base.smtp:
            Base.smtp.clear()

    def tearDown(self):
        self.sb.cleanup()

    def fresh(self):
        """Start over with a new, empty sandbox inside the same test."""
        self.sb.cleanup(); self.sb = Sandbox()

    @property
    def url(self):
        return Base.http.url

    def digests_received(self, path=None):
        return [r for r in Base.http.requests if (path is None or r["path"] == path)
                and "sshsentry daily digest" in (r["body"] or "")]
