#!/usr/bin/env python3
"""SSH Sentry Commercial Edition (experimental; built on sshsentry 0.2.0): a detection-only intrusion watcher for Linux SSH servers.

Rules: brute force, login after failures, login from a new IP/country, and new
authorized_keys lines or /etc/passwd users. State lives in SQLite.
Requires Python 3.8+ and PyYAML; geoip2 + GeoLite2-Country.mmdb are optional.
The Commercial Edition adds: distributed-spray and unusual-hours rules, log tamper/rotation alerts, an
optional heartbeat + systemd watchdog, a downtime alert after an unclean stop, and a retry queue
for failed alert sends (see CHANGES.md).
exp2 adds: a connection-flood rule (one source IP opening and dropping many SSH connections with
no login attempt) and one-alert-per-spray (per-username spray alerts fold into the window alert).
Optional, off-by-default extras: alert destinations (email / Slack / webhook),
threshold learn mode, a daily digest, and community sharing of attacking IPs only (see README).
"""
import argparse, collections, glob, hashlib, ipaddress, json, math, os, re, signal, smtplib, socket, sqlite3, sys, time, uuid, zipfile
import urllib.error, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

VERSION = "0.2.0+commercial.exp2"

DEFAULTS = {
    "log_file": "auto",                 # auto = /var/log/auth.log or /var/log/secure
    "state_db": "/var/lib/sshsentry/state.db",
    "poll_seconds": 1.0,                # tail-follow polling interval
    "file_check_seconds": 60,           # how often to re-check passwd/authorized_keys
    "alert_log": "",                    # optional file to append alerts to (JSON lines)
    "cooldown_minutes": 60,             # do not repeat the same alert within this time
    "rules": {
        "brute_force": {"enabled": True, "failures": 5, "window_minutes": 10},
        "login_after_failures": {"enabled": True, "failures": 5, "lookback_minutes": 60},
        "new_ip": {"enabled": True}, "new_country": {"enabled": True},
        "new_user": {"enabled": True, "passwd_file": "/etc/passwd"},
        "new_ssh_key": {"enabled": True,
                        "paths": ["/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"]},
        # Many IPs, few failures each (slips under brute_force). Window rule: >= failures total from
        # >= distinct_ips IPs; per-username rule: one username failing from >= per_user_ips IPs.
        "distributed_spray": {"enabled": True, "window_minutes": 10, "failures": 20, "distinct_ips": 10,
                              "per_user_ips": 5,
                              # exp2: while the window-level spray alert is active, per-username spray
                              # alerts are folded into it (one spray = one alert). false = old behaviour.
                              "merge_user_alerts": True},
        # Login at an hour this user has never logged in (+/- tolerance_hours, server local time).
        # Silent until the user has min_samples recorded successful logins.
        "unusual_hours": {"enabled": True, "min_samples": 10, "tolerance_hours": 1},
        # exp2: reconnect flood. One source IP opens >= `connections` SSH connections within
        # `window_seconds` and none of them (and nothing else from that IP in the window) attempts a
        # login. HIGH, names the source IP (+ optional inventory label). Own per-IP cooldown.
        # labels: {"IP or CIDR": "name"} (most specific match wins); ignore: [IPs/CIDRs never flagged].
        "connection_flood": {"enabled": True, "connections": 100, "window_seconds": 10,
                             "cooldown_minutes": 5, "labels": {}, "ignore": []},
    },
    # Log tamper / rotation checks. Tamper = HIGH alert. Normal rotation: rotation_notice "log" (stderr
    # note, default), "alert" (a rotation_severity alert, LOW by default) or "off".
    "tamper": {"enabled": True, "missing_seconds": 30, "rotation_notice": "log",
               "rotation_severity": "LOW", "rotated_patterns": [".1", ".0", "-*", ".*"]},
    # Dead-man's switch: periodic "alive" POST. Off by default (it sends data). url / url_env, or
    # use_webhook: true to reuse alerting.webhook's URL. Receivers alert when pings stop.
    "heartbeat": {"enabled": False, "interval_seconds": 300, "url": "", "url_env": "SSHSENTRY_HEARTBEAT_URL",
                  "use_webhook": False, "timeout": 5},
    # Failed alert sends are queued in the state DB and retried with backoff on idle ticks.
    "retry": {"enabled": True, "max_age_hours": 24, "base_seconds": 30, "max_backoff_seconds": 1800},
    # MEDIUM alert on the next start after sshsentry stopped without a clean shutdown.
    "downtime_alert": {"enabled": True},
    "learn_existing_log": True,         # first start: read existing log silently to learn normal IPs
    # Opt-in learn mode: for `days`, alerts print to stdout marked "learning" but are never sent
    # anywhere, while per-IP failure counts per brute-force window are recorded to suggest a
    # threshold. The manual rules.brute_force.failures stays in force unless you accept it.
    "learn_mode": {"enabled": False, "days": 3, "percentile": 99, "margin": 2,
                   "min_threshold": 3, "max_threshold": 50},
    "geoip": {"database": "/usr/share/GeoIP/GeoLite2-Country.mmdb"},
    "email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "starttls": True, "username": "",
              "password_env": "SSHSENTRY_SMTP_PASSWORD", "password": "", "from": "", "to": [],
              "subject_prefix": "[sshsentry]"},
    "sharing": {"enabled": False, "endpoint": "", "timeout": 5},   # opt-in only
    # Alert destinations (stdout is always on). SMTP settings for alerting.email fall back to
    # the legacy top-level `email:` block, which keeps working on its own as before.
    # Daily summary at `time` (local) to one destination, reusing that destination's alerting settings.
    # Daily digest: generated + stored locally at `time` (local) every day when enabled; delivery
    # to one destination (reusing its alerting settings) is controlled separately by `send`.
    "digest": {"enabled": False, "time": "08:00", "send": True, "destination": "email",
               "send_when_quiet": True, "save_text": True, "text_dir": "", "host_label": "",
               "include_chain_hash": True},
    "alerting": {"enabled": False, "timeout": 5,
                 "email": {"enabled": False, "min_severity": "LOW"},
                 "slack": {"enabled": False, "min_severity": "MEDIUM", "webhook_url": "",
                           "webhook_url_env": "SSHSENTRY_SLACK_WEBHOOK"},
                 "webhook": {"enabled": False, "min_severity": "LOW", "url": "",
                             "url_env": "SSHSENTRY_WEBHOOK_URL", "headers": {}}},
}
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
# Only alerts about an *attacker* are ever shared: never new-IP/country logins of your
# own users, and never new-user/new-key alerts (they have no attacker IP).
SHARED_RULES = ("brute_force", "login_after_failures")
# Private / local source addresses are never shared (useless for a blocklist, and they
# reveal your internal network).
LOCAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
              "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]

SCHEMA = ["meta (k TEXT PRIMARY KEY, v TEXT)", "failures (ip TEXT, user TEXT, ts REAL)",
          "seen_ips (user TEXT, ip TEXT, first_seen REAL, PRIMARY KEY (user, ip))",
          "seen_countries (user TEXT, country TEXT, PRIMARY KEY (user, country))",
          "approved_ips (ip TEXT PRIMARY KEY)", "users (name TEXT PRIMARY KEY)",
          "keys (path TEXT, line_hash TEXT, PRIMARY KEY (path, line_hash))",
          "alerts (rule TEXT, key TEXT, ts REAL, PRIMARY KEY (rule, key))",
          "shared (id INTEGER PRIMARY KEY, ip TEXT, rule TEXT, event_minute TEXT, sent_at REAL, "
          "status TEXT, payload TEXT)",
          # IPs already alerted for brute force (drives the one-time success escalation)
          "alerted_ips (ip TEXT PRIMARY KEY, alerted_ts REAL, escalated INTEGER)",
          # learn mode: failed logins per IP per brute-force window
          "learn_windows (ip TEXT, window_start INTEGER, count INTEGER, PRIMARY KEY (ip, window_start))",
          # successful logins (for the daily digest) and digests already produced
          "logins (ts REAL, user TEXT, ip TEXT, method TEXT, failures_before INTEGER)",
          # commercial: queued alert sends (retry with backoff) and per-user login-hour histogram
          "pending_alerts (id INTEGER PRIMARY KEY, dest TEXT, event TEXT, created REAL, attempts INTEGER, "
          "next_try REAL, last_error TEXT)",
          "login_hours (user TEXT, hour INTEGER, n INTEGER, PRIMARY KEY (user, hour))",
          "daily_digests (date TEXT PRIMARY KEY, period_start REAL, period_end REAL, created_at REAL, "
          "stats TEXT, text TEXT, status TEXT, destination TEXT, error TEXT, prev_hash TEXT, chain_hash TEXT)"]

# Log line formats: classic syslog ("Oct 17 02:10:01 host sshd[123]: msg")
# and ISO-8601 rsyslog ("2026-10-17T02:10:01.123-04:00 host sshd[123]: msg").
LINE_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+)"
                     r" \S+ (?P<proc>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
IP = r"(?P<ip>[0-9a-fA-F:.]+)"
# FAIL_RE deliberately does not match "Failed password for invalid user x": the
# "Invalid user x" line before it is counted instead (catches key-only servers too).
FAIL_RE = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from " + IP)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from " + IP)
OK_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from " + IP)
# exp2 connection_flood: OpenSSH lines that show a connection from an IP *before* authentication.
# Several lines can belong to one connection (open + close); they are de-duplicated by
# (ip, sshd pid, source port). MaxStartups drops are logged by the listener (shared pid), so each
# drop line is its own connection (sshd never opened it, so no other line exists for it).
PORT = r"(?: port (?P<port>\d+))?"
CONN_RES = [
    re.compile(r"^Connection from " + IP + PORT + r"(?: on |$)"),                         # VERBOSE level
    re.compile(r"^Connection (?:closed|reset) by " + IP + PORT + r"(?: \[preauth\])?$"),
    re.compile(r"^Did not receive identification string from " + IP + PORT),
    re.compile(r"^Disconnected from " + IP + PORT + r" \[preauth\]$"),
    re.compile(r"^Received disconnect from " + IP + PORT + r":.*\[preauth\]$"),
    re.compile(r"^Timeout before authentication for " + IP + PORT),
    re.compile(r"^(?:Unable to negotiate with|banner exchange: Connection from|"
               r"ssh_dispatch_run_fatal: Connection from|kex_exchange_identification: .*? from) " + IP + PORT),
]
DROP_RE = re.compile(r"drop connection #\d+ from \[" + IP + r"\]:(?P<port>\d+)")   # MaxStartups (listener)
# Any sign of an authentication attempt from an IP (on top of FAIL_RE / INVALID_RE / OK_RE). Such an IP is
# not a reconnect flood: it is guessing or logging in, which the login rules cover.
AUTH_RES = [
    re.compile(r"(?:Connection (?:closed|reset) by|Disconnected from|Received disconnect from) "
               r"(?:authenticating|invalid) user \S*\s+" + IP),
    re.compile(r"(?:Failed|Postponed) \S+ for (?:invalid user )?\S+ from " + IP),
    re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?\S+ from " + IP),
]


def merge(base, over):
    """Recursively merge user config over defaults."""
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def parse_ts(raw):
    """Turn a log timestamp into epoch seconds (syslog lines carry no year)."""
    if raw[0].isdigit():
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    now = datetime.now()
    dt = datetime.strptime(f"{now.year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")
    if dt.timestamp() > now.timestamp() + 86400:   # e.g. December lines read in January
        dt = dt.replace(year=now.year - 1)
    return dt.timestamp()


def fmt(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def fmt_ms(ts):
    d = datetime.fromtimestamp(ts)
    return d.strftime("%Y-%m-%d %H:%M:%S") + f".{d.microsecond // 1000:03d}"


def valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def net_list(items, what):
    """Parse IPs / CIDRs into networks; bad entries are skipped with a note."""
    out = []
    for k in items or []:
        try:
            out.append(ipaddress.ip_network(str(k).strip(), strict=False))
        except ValueError:
            print(f"[sshsentry] note: ignoring bad {what} entry {k!r} (not an IP or CIDR)", file=sys.stderr)
    return out


def endpoint_problem(url):
    """Sharing endpoints must be https:// (plain http:// only to localhost, for testing)."""
    u = urllib.parse.urlparse(url or "")
    if u.hostname and (u.scheme == "https" or (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1"))):
        return None
    return f"endpoint must be https:// (http:// allowed only for localhost), got {url!r}"


def post_json(url, payload, timeout, headers=None):
    """POST a JSON payload with stdlib urllib. Returns a status string; never raises."""
    if endpoint_problem(url):
        return "refused: " + endpoint_problem(url)
    hdrs = {"Content-Type": "application/json", "User-Agent": f"sshsentry/{VERSION}", **(headers or {})}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=float(timeout)) as r:
            return f"sent (HTTP {r.status})"
    except urllib.error.HTTPError as e:
        return f"failed (HTTP {e.code})"
    except Exception as e:
        return f"failed ({type(e).__name__}: {getattr(e, 'reason', e)})"


def sd_notify(msg):
    """systemd notify protocol over $NOTIFY_SOCKET (no dependencies). Returns True if sent."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]   # abstract namespace socket
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sk:
            sk.connect(addr)
            sk.sendall(msg.encode())
        return True
    except OSError:
        return False


def hour_near(h, hours, tol):
    """True if hour h is within +/- tol hours (wrapping at midnight) of any hour in `hours`."""
    return any(min((h - x) % 24, (x - h) % 24) <= tol for x in hours)


def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError):
        return False


# ---------- digest integrity chain ----------
# chain_hash(day) = sha256(prev_chain_hash + canonical(day)); the first day uses GENESIS.
# GENESIS is a fixed public constant, so anyone can recompute a chain from an export.
GENESIS = hashlib.sha256(b"sshsentry-genesis-v1").hexdigest()


def canonical(rec):
    """Canonical bytes of one digest: sorted-key compact JSON of date, period, stats and text."""
    keep = {k: rec[k] for k in ("date", "period_start", "period_end", "stats", "text")}
    return json.dumps(keep, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_next(prev, rec):
    return hashlib.sha256((prev + canonical(rec)).encode()).hexdigest()


def with_chain(text, chain):
    """The digest text as delivered / saved: body plus a short and full chain hash."""
    return f"{text}\n\nIntegrity chain: {chain[:12]} (sha256 {chain})"


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def emit(obj):
    """Print one structured JSON document (for --format json)."""
    print(json.dumps(obj, indent=2, sort_keys=False))


def normalize(cfg, user_cfg):
    """Map legacy config keys onto the current ones (old configs keep working)."""
    old = user_cfg.get("learning") or {}
    if "learn_existing_log" in old and "learn_existing_log" not in user_cfg:
        cfg["learn_existing_log"] = old["learn_existing_log"]
    if float(old.get("days") or 0) > 0 and not (user_cfg.get("learn_mode") or {}).get("enabled"):
        print("[sshsentry] note: learning.days is deprecated; treating it as learn_mode "
              f"(enabled, days: {old['days']})", file=sys.stderr)
        cfg["learn_mode"].update(enabled=True, days=old["days"])
    return cfg


def host_of(url):
    """Webhook URLs are secrets: only ever log the host part."""
    return urllib.parse.urlparse(url or "").hostname or "(no URL)"


def slack_escape(text):
    """Escape Slack mrkdwn control characters (attacker-chosen usernames end up in messages)."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_destinations(cfg, ignore_master=False):
    """Validate configured alert destinations; warn about and drop broken ones. Never raises."""
    al, legacy, out = cfg["alerting"], cfg["email"], []
    on = al.get("enabled") or ignore_master
    def warn(name, why):
        print(f"[sshsentry] warning: {name} alert destination DISABLED: {why}", file=sys.stderr)
    def level(d, name):
        sev = str(d.get("min_severity") or "LOW").upper()
        if sev not in SEVERITIES:
            print(f"[sshsentry] warning: {name}.min_severity {sev!r} unknown; using LOW", file=sys.stderr)
            sev = "LOW"
        return SEVERITIES.index(sev)
    # Email: alerting.email inherits SMTP settings from the legacy top-level `email:` block.
    if (on and al["email"].get("enabled")) or legacy.get("enabled"):
        e = merge(legacy, {k: v for k, v in al["email"].items() if k != "enabled"})
        e["password_value"] = os.environ.get(e.get("password_env") or "", "") or e.get("password", "")
        to = e.get("to") or []
        if not e.get("smtp_host"):
            warn("email", "smtp_host is not set")
        elif not to or not (e.get("from") or e.get("username")):
            warn("email", "'to' and 'from' (or 'username') are required")
        elif e.get("username") and not e["password_value"]:
            warn("email", f"username is set but no password (set ${e.get('password_env')})")
        else:
            out.append({"name": "email", "kind": "email", "min": level(e, "email"), "cfg": e})
    for name, key, env_key in (("slack", "webhook_url", "webhook_url_env"), ("webhook", "url", "url_env")):
        d = al[name]
        if not (on and d.get("enabled")):
            continue
        url = os.environ.get(d.get(env_key) or "", "") or d.get(key, "")
        headers = d.get("headers") or {}
        if endpoint_problem(url):
            warn(name, "URL missing or not https:// (http:// allowed only for localhost); "
                       f"set {key} or ${d.get(env_key)}" if url else f"no URL (set {key} or ${d.get(env_key)})")
        elif not isinstance(headers, dict) or not all(isinstance(v, str) for v in headers.values()):
            warn(name, "headers must be a mapping of header name -> string value")
        else:
            out.append({"name": name, "kind": name, "min": level(d, name), "url": url,
                        "headers": {str(k): v for k, v in headers.items()}})
    return out


class Agent:
    def __init__(self, cfg, dry_run=False, admin=False):
        self.cfg, self.rules, self.dry_run = cfg, cfg["rules"], dry_run
        self.learning = False             # True = ingesting old history: record, stay silent
        os.makedirs(os.path.dirname(cfg["state_db"]) or ".", exist_ok=True)
        self.db = sqlite3.connect(cfg["state_db"])
        for ddl in SCHEMA:
            self.db.execute(f"CREATE TABLE IF NOT EXISTS {ddl}")
        self.collect = None               # list = collect alerts for --format json instead of printing
        self.upgrade_chain()
        self.db.execute("CREATE INDEX IF NOT EXISTS fail_ip ON failures (ip, ts)")
        if self.meta("first_run") is None:
            self.set_meta("first_run", time.time())
        self.geo = None if admin else self.open_geoip()   # admin commands need no GeoIP
        sh = cfg["sharing"]
        if sh.get("enabled") and endpoint_problem(sh.get("endpoint")):
            print(f"[sshsentry] sharing DISABLED: {endpoint_problem(sh.get('endpoint'))}", file=sys.stderr)
            sh["enabled"] = False
        self.dests = [] if admin else build_destinations(cfg)
        lm = cfg["learn_mode"]
        if lm.get("enabled") and self.meta("learn_start") is None:
            self.set_meta("learn_start", time.time())
        # exp2 connection_flood: in-memory sliding windows (a restart starts the windows empty).
        cf = self.rules.get("connection_flood") or {}
        self.cf_labels = []
        for k, v in (cf.get("labels") or {}).items():
            for n in net_list([k], "connection_flood.labels"):
                self.cf_labels.append((n, str(v)))
        self.cf_labels.sort(key=lambda x: -x[0].prefixlen)       # most specific first
        self.cf_ignore = net_list(cf.get("ignore"), "connection_flood.ignore")
        self.cf_win = {}         # ip -> deque of connection timestamps inside the window
        self.cf_total = {}       # ip -> connections seen from this IP since sshsentry started (attempt #)
        self.cf_last = {}        # ip -> ts of the latest connection (for pruning idle IPs)
        self.cf_auth = {}        # ip -> ts of the latest authentication attempt / login from this IP
        self.cf_seen = {}        # (ip, pid, port) -> ts: lines already counted for this connection
        self.cf_auth_conns = {}  # (ip, pid, port) -> ts: connections that authenticated (not pre-auth)
        self.cf_events = 0

    def upgrade_chain(self):
        """Upgrade older databases: add the chain columns and backfill hashes for old digests."""
        cols = [r[1] for r in self.db.execute("PRAGMA table_info(daily_digests)")]
        for c in ("prev_hash", "chain_hash"):
            if c not in cols:
                self.db.execute(f"ALTER TABLE daily_digests ADD COLUMN {c} TEXT")
        rows = self.db.execute("SELECT date, chain_hash FROM daily_digests ORDER BY date").fetchall()
        if not any(ch is None for _, ch in rows):
            return
        prev, n = GENESIS, 0
        for date, ch in rows:
            if ch is None:
                rec = self.digest_record(date)
                ch = chain_next(prev, rec)
                self.db.execute("UPDATE daily_digests SET prev_hash=?, chain_hash=? WHERE date=?", (prev, ch, date))
                n += 1
                path = os.path.join(self.digest_dir(), f"{date}.txt")
                try:   # add the chain line to an untouched pre-upgrade text copy
                    if os.path.exists(path) and open(path).read() == rec["text"] + "\n":
                        with open(path, "w") as f:
                            f.write(with_chain(rec["text"], ch) + "\n")
                except OSError:
                    pass
            prev = ch
        self.db.commit()
        print(f"[sshsentry] note: added integrity chain hashes to {n} existing digest(s). The chain protects "
              "them from now on; it can't vouch for changes made before this upgrade.", file=sys.stderr)

    def digest_record(self, date):
        """Stored digest as a dict (the canonical fields plus metadata), or None."""
        row = self.q("SELECT date, period_start, period_end, created_at, stats, text, status, destination, "
                     "error, prev_hash, chain_hash FROM daily_digests WHERE date=?", date)
        if not row:
            return None
        keys = ("date", "period_start", "period_end", "created_at", "stats", "text", "status", "destination",
                "error", "prev_hash", "chain_hash")
        rec = dict(zip(keys, row))
        rec["stats"] = json.loads(rec["stats"])
        return rec

    # ---------- small helpers ----------
    def q(self, sql, *args):
        """Return the first row of a query (or None)."""
        return self.db.execute(sql, args).fetchone()

    def meta(self, k):
        row = self.q("SELECT v FROM meta WHERE k=?", k)
        return row[0] if row else None

    def set_meta(self, k, v):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (k, str(v)))
        self.db.commit()

    def learn_active(self):
        """True while opt-in learn mode is running (alerts print but are never sent)."""
        lm = self.cfg["learn_mode"]
        if not lm.get("enabled") or self.meta("learn_start") is None:
            return False
        return time.time() < float(self.meta("learn_start")) + float(lm.get("days") or 0) * 86400

    def open_geoip(self):
        """Country lookups are optional: skip with a note if geoip2 or the database is missing."""
        if not self.rules["new_country"].get("enabled"):
            return None
        try:
            import geoip2.database
            return geoip2.database.Reader(self.cfg["geoip"]["database"])
        except Exception as e:
            print(f"[sshsentry] note: country checks disabled ({type(e).__name__}: {e})", file=sys.stderr)

    def country(self, ip):
        try:
            return self.geo.country(ip).country.iso_code if self.geo else None
        except Exception:
            return None   # private or unknown address

    # ---------- alerting ----------
    def alert(self, severity, rule, key, ts, text, attacker=None, notify=None, share_as=None, cooldown=None):
        """Print an alert and fan it out, respecting the per-rule cool-down. Returns True if raised.
        `notify` = (concise text, usernames, success) for destinations; defaults to the stdout text.
        `cooldown` (seconds) overrides the global cooldown_minutes for this rule."""
        if self.learning:
            return False
        row = self.q("SELECT ts FROM alerts WHERE rule=? AND key=?", rule, key)
        cd = self.cfg["cooldown_minutes"] * 60 if cooldown is None else float(cooldown)
        if row and abs(ts - row[0]) < cd:
            return False
        self.db.execute("INSERT OR REPLACE INTO alerts VALUES (?, ?, ?)", (rule, key, ts))
        self.db.commit()
        learning = self.learn_active()
        line = f"[{fmt(ts)}] {severity}: {text}"
        if self.collect is not None:
            self.collect.append({"time": fmt(ts), "timestamp": iso(ts), "severity": severity, "rule": rule,
                                 "message": text, "learning": learning})
        else:
            print(("[learning: not sent] " if learning else "") + line, flush=True)
        if self.cfg.get("alert_log"):
            with open(self.cfg["alert_log"], "a") as f:
                f.write(json.dumps({"time": fmt(ts), "severity": severity, "rule": rule, "message": text,
                                    "learning": learning}) + "\n")
        if learning:
            return True   # learn mode: nothing leaves the machine
        msg, users, success = notify or (text, [], None)
        self.dispatch({"severity": severity, "rule": rule, "ip": attacker, "usernames": users,
                       "success": success, "timestamp": datetime.fromtimestamp(ts, timezone.utc)
                       .strftime("%Y-%m-%dT%H:%M:%SZ"), "message": msg})
        if attacker and (share_as or rule) in SHARED_RULES:
            self.share(share_as or rule, attacker, ts)
        return True

    # ---------- alert destinations ----------
    def dispatch(self, event, dests=None, force=False):
        """Send one alert event to every destination at or above its min_severity. Never raises.
        --replay never sends; --test-alerts uses force=True to bypass severity filters."""
        if self.dry_run and not force:
            return []
        results = []
        for d in (self.dests if dests is None else dests):
            if not force and SEVERITIES.index(event["severity"]) < d["min"]:
                continue
            status = self.send_to(d, event)
            results.append((d["name"], status))
            if not status.startswith("sent"):
                print(f"[sshsentry] {d['name']} alert failed: {status}", file=sys.stderr)
                if not force and self.cfg["retry"].get("enabled"):
                    self.queue_alert(d["name"], event, status)
            elif not force:   # destination is back: retry anything queued for it on the next tick
                self.db.execute("UPDATE pending_alerts SET next_try=0 WHERE dest=?", (d["name"],))
                self.db.commit()
        return results

    # ---------- commercial: retry queue for failed sends ----------
    def queue_alert(self, dest, event, error, now=None):
        now = now or time.time()
        self.db.execute("INSERT INTO pending_alerts (dest, event, created, attempts, next_try, last_error) "
                        "VALUES (?, ?, ?, 1, ?, ?)", (dest, json.dumps(event), now,
                                                       now + float(self.cfg["retry"].get("base_seconds", 30)), error))
        self.db.commit()
        print(f"[sshsentry] queued {event['rule']} alert for {dest}; will retry with backoff", file=sys.stderr)

    def retry_pending(self, now=None):
        """Retry queued alert sends that are due. Drops ones older than retry.max_age_hours. Never raises."""
        r, now = self.cfg["retry"], now or time.time()
        if self.dry_run or not r.get("enabled"):
            return
        rows = self.db.execute("SELECT id, dest, event, created, attempts FROM pending_alerts WHERE next_try <= ? "
                               "ORDER BY id", (now,)).fetchall()
        failed_dests = set()
        for i, dest, ev, created, attempts in rows:
            event = json.loads(ev)
            d = next((x for x in self.dests if x["name"] == dest), None)
            if d is None or now - created > float(r.get("max_age_hours", 24)) * 3600:
                why = "destination no longer configured" if d is None else \
                    f"older than {r.get('max_age_hours', 24)} h"
                self.db.execute("DELETE FROM pending_alerts WHERE id=?", (i,))
                print(f"[sshsentry] gave up on queued {event['rule']} alert for {dest} after {attempts} "
                      f"attempt(s) ({why}); it was never delivered", file=sys.stderr)
                continue
            if dest in failed_dests:
                continue
            event = dict(event, delayed=True, queued_at=iso(created), attempts=attempts + 1)
            status = self.send_to(d, event)
            if status.startswith("sent"):
                self.db.execute("DELETE FROM pending_alerts WHERE id=?", (i,))
                print(f"[sshsentry] delivered queued {event['rule']} alert to {dest} (queued {fmt(created)}, "
                      f"attempt {attempts + 1}): {status}", file=sys.stderr, flush=True)
            else:
                failed_dests.add(dest)
                wait = min(float(r.get("max_backoff_seconds", 1800)),
                           float(r.get("base_seconds", 30)) * 2 ** attempts)
                self.db.execute("UPDATE pending_alerts SET attempts=?, next_try=?, last_error=? WHERE id=?",
                                (attempts + 1, now + wait, status, i))
                print(f"[sshsentry] retry {attempts + 1} of queued {event['rule']} alert for {dest} failed "
                      f"({status}); next try in {int(wait)} sec", file=sys.stderr)
        self.db.commit()

    # ---------- commercial: heartbeat ----------
    def heartbeat_url(self):
        hb = self.cfg["heartbeat"]
        if hb.get("use_webhook"):
            w = self.cfg["alerting"]["webhook"]
            return os.environ.get(w.get("url_env") or "", "") or w.get("url", "")
        return os.environ.get(hb.get("url_env") or "", "") or hb.get("url", "")

    def maybe_heartbeat(self, now=None):
        """Send the periodic alive ping when due. Returns the status string if one was sent."""
        hb, now = self.cfg["heartbeat"], now or time.time()
        if not hb.get("enabled") or self.dry_run:
            return None
        last = float(self.meta("heartbeat_last") or 0)
        if now - last < float(hb.get("interval_seconds", 300)):
            return None
        self.set_meta("heartbeat_last", now)
        url = self.heartbeat_url()
        payload = {"type": "heartbeat", "status": "alive", "rule": "heartbeat", "severity": "INFO",
                   "timestamp": iso(now), "interval_seconds": hb.get("interval_seconds", 300),
                   "pending_alerts": self.q("SELECT COUNT(*) FROM pending_alerts")[0],
                   "sshsentry_version": VERSION,
                   "message": "sshsentry heartbeat: still running. Alert if these stop arriving."}
        status = post_json(url, payload, hb.get("timeout", 5))
        if not status.startswith("sent"):
            print(f"[sshsentry] heartbeat to {host_of(url)} failed: {status}", file=sys.stderr)
        return status

    # ---------- commercial: run marker (downtime detection) ----------
    def mark_running(self):
        """Returns (was_unclean, last_alive_ts) from the previous run, then marks this run as running."""
        prev = self.meta("run_marker")
        unclean, last = False, None
        if prev:
            try:
                m = json.loads(prev)
                # A marker left behind means the last run never shut down cleanly (kill -9, crash,
                # power loss), unless that process is in fact still alive (a second instance).
                if m.get("pid") == os.getpid() or not pid_alive(m.get("pid")):
                    unclean, last = True, float(m.get("last_alive") or m.get("started"))
            except (ValueError, TypeError):
                pass
        self.touch_marker(started=time.time())
        return unclean, last

    def touch_marker(self, started=None):
        m = {"pid": os.getpid(), "started": started or json.loads(self.meta("run_marker") or "{}").get("started"),
             "last_alive": time.time()}
        self.set_meta("run_marker", json.dumps(m))

    def mark_clean(self):
        self.db.execute("DELETE FROM meta WHERE k='run_marker'")
        self.set_meta("clean_shutdown", time.time())

    def send_to(self, d, event):
        timeout = self.cfg["alerting"].get("timeout", 5)
        line = f"{event['severity']}: {event['message']}"
        if d["kind"] == "email":
            return self.send_email(d["cfg"], f"{event['severity']}: {event['message'].split('.')[0][:120]}",
                                   f"[{event['timestamp']}] {line}", timeout)
        if d["kind"] == "slack":
            return post_json(d["url"], {"text": slack_escape(f"[sshsentry] {line}")}, timeout)
        return post_json(d["url"], event, timeout, d["headers"])   # generic JSON webhook

    def test_alerts(self):
        """--test-alerts: send one sample alert to each enabled destination and report status."""
        dests = build_destinations(self.cfg, ignore_master=True)
        if not self.cfg["alerting"].get("enabled"):
            print("Note: alerting.enabled is false, so real alerts are not sent yet (testing anyway).")
        if not dests:
            print("No usable alert destinations are enabled (see warnings above, if any).")
            return False
        event = {"severity": "LOW", "rule": "test", "ip": None, "usernames": [], "success": None,
                 "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "message": "Test alert from sshsentry. If you can read this, this destination works."}
        ok = True
        for name, status in self.dispatch(event, dests, force=True):
            target = next((host_of(d.get("url")) for d in dests if d["name"] == name), "")
            print(f"  {name:<8} {target if name != 'email' else ''} -> {status}")
            ok = ok and status.startswith("sent")
        return ok

    # ---------- opt-in sharing ----------
    def install_id(self):
        """Random ID created locally the first time something is shared; links nothing to you."""
        if self.meta("install_id") is None:
            self.set_meta("install_id", uuid.uuid4())
        return self.meta("install_id")

    def share(self, rule, ip, ts):
        """Report an attacking IP if sharing is on. Records every attempt; never raises."""
        sh = self.cfg["sharing"]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if (not sh.get("enabled") or self.dry_run or any(addr in n for n in LOCAL_NETS)
                or self.q("SELECT 1 FROM approved_ips WHERE ip=?", ip)):
            return
        minute = datetime.fromtimestamp(ts - ts % 60, timezone.utc).strftime("%Y-%m-%dT%H:%M:00Z")
        # The complete payload. Nothing else (usernames, hostnames, log text, server IP) is sent.
        payload = {"ip": ip, "rule": rule, "timestamp": minute,
                   "sshsentry_version": VERSION, "install_id": self.install_id()}
        status = post_json(sh["endpoint"], payload, sh.get("timeout", 5))
        self.db.execute("INSERT INTO shared (ip, rule, event_minute, sent_at, status, payload) "
                        "VALUES (?, ?, ?, ?, ?, ?)", (ip, rule, minute, time.time(), status, json.dumps(payload)))
        self.db.commit()
        if not status.startswith("sent"):
            print(f"[sshsentry] sharing report for {ip} {status}", file=sys.stderr)

    def show_shared(self, as_json=False):
        sh = self.cfg["sharing"]
        if as_json:
            rows = self.db.execute("SELECT id, ip, rule, event_minute, sent_at, status, payload FROM shared "
                                   "ORDER BY id").fetchall()
            emit({"schema": "sshsentry.shared/1", "sharing_enabled": bool(sh.get("enabled")),
                  "endpoint": sh.get("endpoint") or None, "install_id": self.meta("install_id"),
                  "reports": [{"id": i, "ip": ip, "rule": r, "event_minute": m, "sent_at": iso(t),
                               "status": st, "payload": json.loads(pl)} for i, ip, r, m, t, st, pl in rows]})
            return
        state = f"ON -> {sh['endpoint']}" if sh.get("enabled") else "OFF"
        print(f"Sharing is {state}. Install ID: {self.meta('install_id') or '(none generated)'}")
        rows = self.db.execute("SELECT id, ip, rule, event_minute, sent_at, status FROM shared ORDER BY id").fetchall()
        if not rows:
            print("Nothing has been shared yet: no reports are recorded in this install's database.")
            return
        print(f"{len(rows)} report(s) recorded. Each report contains exactly: ip, rule, timestamp, sshsentry_version, install_id.")
        w = max(11, *(len(r[1]) for r in rows))
        print(f"{'#':>4}  {'ATTACKER IP':<{w}}  {'RULE':<20}  {'EVENT (UTC)':<20}  {'SENT AT (local)':<19}  STATUS")
        for i, ip, rule, minute, sent, status in rows:
            print(f"{i:>4}  {ip:<{w}}  {rule:<20}  {minute:<20}  {fmt(sent):<19}  {status}")

    def forget_me(self, local_only=False):
        """Delete local sharing history first; then (best effort) ask the endpoint to delete too."""
        n = self.db.execute("DELETE FROM shared").rowcount
        old_id = self.meta("install_id")
        self.db.execute("DELETE FROM meta WHERE k='install_id'")   # next share gets a fresh ID
        self.db.commit()
        print(f"Deleted {n} shared-report record(s) from the local database ({self.cfg['state_db']}).")
        sh = self.cfg["sharing"]
        if old_id and sh.get("endpoint") and not local_only:
            status = post_json(sh["endpoint"], {"request": "delete", "install_id": old_id,
                                                "sshsentry_version": VERSION}, sh.get("timeout", 5))
            print(f"Remote deletion request for install ID {old_id}: {status}")
        if old_id:
            print(f"Old install ID: {old_id} (keep it to request deletion by email if needed). "
                  "A new random ID will be created if you share again.")
        if sh.get("enabled"):
            print("Note: sharing is still enabled; set sharing.enabled: false to stop future reports.")

    def send_email(self, e, subject, body, timeout):
        msg = EmailMessage()
        msg["Subject"], msg["From"] = f"{e['subject_prefix']} {subject}", e["from"] or e["username"]
        msg["To"] = ", ".join(e["to"]) if isinstance(e["to"], list) else e["to"]
        msg.set_content(body + "\n\n-- sshsentry (detection only; review and respond manually)")
        try:
            with smtplib.SMTP(e["smtp_host"], int(e["smtp_port"]), timeout=float(timeout)) as s:
                if e.get("starttls", True):
                    s.starttls()
                if e.get("username"):
                    s.login(e["username"], e["password_value"])
                s.send_message(msg)
            return "sent"
        except Exception as ex:   # never let a mail problem stop monitoring
            return f"failed ({type(ex).__name__}: {ex})"

    # ---------- log rules ----------
    def handle_line(self, line):
        m = LINE_RE.match(line.strip())
        if not m or not m.group("proc").startswith("sshd"):   # sshd or sshd-session
            return
        try:
            msg, ts = m.group("msg"), parse_ts(m.group("ts"))
        except ValueError:   # malformed timestamp (e.g. Feb 29 guessed into a non-leap year)
            return
        if (f := INVALID_RE.search(msg) or FAIL_RE.search(msg)):
            self.on_failure(f.group("ip"), f.group("user") or "(empty)", ts)
        elif (ok := OK_RE.search(msg)):
            self.on_success(ok.group("ip"), ok.group("user"), ok.group("method"), ts)
        if (self.rules.get("connection_flood") or {}).get("enabled"):
            self.on_connection_line(msg, m.group("pid"), ts, auth=f or ok)

    # ---------- exp2: connection_flood ----------
    def cf_label(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return next((name for n, name in self.cf_labels if a.version == n.version and a in n), None)

    def on_connection_line(self, msg, pid, ts, auth=None):
        """Count pre-auth SSH connections per source IP; HIGH when one IP floods with no login attempt."""
        r = self.rules["connection_flood"]
        if not auth:
            auth = next((x for x in (rx.search(msg) for rx in AUTH_RES) if x), None)
        if auth:
            ip = auth.group("ip")
            self.cf_auth[ip] = ts
            port = re.search(r" port (\d+)", msg[auth.end("ip"):auth.end("ip") + 20])
            self.cf_auth_conns[(ip, pid, port.group(1) if port else None)] = ts
            return
        m = DROP_RE.search(msg)
        drop = bool(m)
        if not m:
            m = next((x for x in (rx.search(msg) for rx in CONN_RES) if x), None)
            if not m:
                return
        ip, port = m.group("ip"), m.group("port")
        if not valid_ip(ip):
            return
        key = (ip, pid, port)
        if not drop:
            if key in self.cf_seen or key in self.cf_auth_conns:
                return            # another line of a connection already counted (or one that logged in)
            self.cf_seen[key] = ts
        a = ipaddress.ip_address(ip)
        if any(a.version == n.version and a in n for n in self.cf_ignore):
            return
        self.cf_events += 1
        if self.cf_events % 5000 == 0:
            self.cf_prune(ts)
        w = float(r.get("window_seconds", 10))
        q = self.cf_win.setdefault(ip, collections.deque())
        q.append(ts)
        while q and q[0] < ts - w:
            q.popleft()
        self.cf_total[ip] = self.cf_total.get(ip, 0) + 1
        self.cf_last[ip] = ts
        if len(q) < int(r.get("connections", 100)):
            return
        if ip in self.cf_auth and ts - self.cf_auth[ip] <= w:
            return                # this IP also tried to log in: the login rules own it
        n, span = len(q), max(q[-1] - q[0], 0.0)
        rate = f" (~{(n - 1) / span:.0f}/sec)" if n > 1 and span > 0 else ""
        label = self.cf_label(ip)
        lab = f" ({label})" if label else (" (not in your inventory labels)" if self.cf_labels else "")
        took = f"{span:.2f} sec" if span < 120 else f"{round(span / 60)} min"
        total = self.cf_total[ip]
        text = (f"Connection flood. {n} SSH connections from {ip}{lab} in {took}{rate}, and none of them "
                f"tried to log in (0 login attempts from {ip} in the last {w:g} sec). First seen {fmt_ms(q[0])}, "
                f"last {fmt_ms(q[-1])} (connection #{total} from this IP). This is not password guessing: a device "
                f"or script at {ip} is opening and dropping SSH connections in a loop. Check that device; if it is "
                "not expected, rate-limit or block it at the firewall (sshd MaxStartups/PerSourcePenalties also help).")
        short = (f"Connection flood from {ip}{lab}: {n} SSH connections in {took}{rate}, 0 login "
                 f"attempts; first {fmt_ms(q[0])}, last {fmt_ms(q[-1])}, connection #{total} from this IP.")
        self.alert("HIGH", "connection_flood", ip, ts, text, attacker=ip, notify=(short, [], False),
                   cooldown=float(r.get("cooldown_minutes", 5)) * 60)

    def cf_prune(self, now):
        """Keep connection_flood memory bounded: forget old connection keys and idle IPs."""
        w = float(self.rules["connection_flood"].get("window_seconds", 10))
        keep = max(w, 600.0)      # a connection's last line can come LoginGraceTime (120 s default) later
        self.cf_seen = {k: t for k, t in self.cf_seen.items() if t >= now - keep}
        self.cf_auth_conns = {k: t for k, t in self.cf_auth_conns.items() if t >= now - keep}
        self.cf_auth = {k: t for k, t in self.cf_auth.items() if t >= now - keep}
        for ip in [ip for ip, t in self.cf_last.items() if t < now - 3600]:
            for d in (self.cf_win, self.cf_total, self.cf_last):
                d.pop(ip, None)

    def on_failure(self, ip, user, ts):
        self.db.execute("INSERT INTO failures VALUES (?, ?, ?)", (ip, user, ts))
        self.db.execute("DELETE FROM failures WHERE ts < ?", (ts - 8 * 86400,))   # 8 days (digest catch-up)
        r = self.rules["brute_force"]
        if self.learn_active():   # learn mode: count failures per IP per (tumbling) window
            w = int(r["window_minutes"] * 60)
            self.db.execute("INSERT INTO learn_windows VALUES (?, ?, 1) ON CONFLICT (ip, window_start) "
                            "DO UPDATE SET count = count + 1", (ip, int(ts // w * w)))
        self.check_spray(user, ts)
        if not r.get("enabled"):
            return
        rows = self.db.execute("SELECT user, ts FROM failures WHERE ip=? AND ts BETWEEN ? AND ?",
                               (ip, ts - r["window_minutes"] * 60, ts)).fetchall()
        if len(rows) >= r["failures"]:
            users = sorted({u for u, _ in rows})
            span = ts - min(t for _, t in rows)
            took = f"{int(span)} sec" if span < 120 else f"{round(span / 60)} min"
            tried = f"{', '.join(u[:64] for u in users[:8])}{' ...' if len(users) > 8 else ''}"
            prior = self.q("SELECT user FROM seen_ips WHERE ip=?", ip)
            status = f"a successful login from this IP was seen earlier (user '{prior[0]}')" if prior \
                else "no successful login yet"
            if self.alert("MEDIUM", "brute_force", ip, ts,
                          f"Brute force. {len(rows)} failed SSH logins from {ip} in {took}, trying "
                          f"user(s): {tried}. "
                          "Consider fail2ban, a firewall block, or disabling password logins.", attacker=ip,
                          notify=(f"Brute force from {ip}: {len(rows)} failed SSH logins in {took}; "
                                  f"users tried: {tried}; {status}.", users[:8], bool(prior))):
                # Remember the alert so a later success from this IP escalates exactly once.
                self.db.execute("INSERT OR REPLACE INTO alerted_ips VALUES (?, ?, 0)", (ip, ts))
                self.db.commit()

    def check_spray(self, user, ts):
        """commercial: distributed spray. Many IPs with few failures each, within a sliding window."""
        r = self.rules["distributed_spray"]
        if not r.get("enabled"):
            return
        lo = ts - float(r.get("window_minutes", 10)) * 60
        def took(rows):
            span = ts - min(t for _, _, t in rows)
            return f"{int(span)} sec" if span < 120 else f"{round(span / 60)} min"
        def names(xs):
            xs = sorted(xs)
            return f"{', '.join(x[:64] for x in xs[:8])}{' ...' if len(xs) > 8 else ''}"
        rows = self.db.execute("SELECT ip, user, ts FROM failures WHERE ts BETWEEN ? AND ?", (lo, ts)).fetchall()
        ips = {}
        for ip, _, _ in rows:
            ips[ip] = ips.get(ip, 0) + 1
        # Only "low and slow" IPs count: one that reached the brute-force limit is already covered by
        # brute_force (it would also make the "per-IP limits miss it" wording untrue).
        cap = int(self.rules["brute_force"].get("failures", 5)) if self.rules["brute_force"].get("enabled") else 10 ** 9
        ips = {k: v for k, v in ips.items() if v < cap}
        rows = [x for x in rows if x[0] in ips]
        if not rows:
            return
        per_user = int(r.get("per_user_ips", 5))
        window_hit = len(rows) >= int(r.get("failures", 20)) and len(ips) >= int(r.get("distinct_ips", 10))
        merge_users = r.get("merge_user_alerts", True)
        if window_hit:
            t = (f"Distributed password spray. {len(rows)} failed SSH logins from {len(ips)} different IPs in "
                 f"{took(rows)} (at most {max(ips.values())} from any one of them, so per-IP brute-force limits "
                 f"miss it), trying user(s): {names({u for _, u, _ in rows})}. Busiest IPs: "
                 f"{', '.join(sorted(ips, key=lambda k: -ips[k])[:5])}.")
            if merge_users:   # exp2: name the targeted accounts here instead of separate per-user alerts
                per = {}
                for ip, u, _ in rows:
                    per.setdefault(u, [0, set()]); per[u][0] += 1; per[u][1].add(ip)
                hot = sorted((u for u in per if len(per[u][1]) >= per_user), key=lambda u: (-len(per[u][1]), u))
                if hot:
                    t += (" Targeted usernames (each from " + str(per_user) + "+ IPs): " +
                          ", ".join(f"{u[:64]} ({per[u][0]} failures from {len(per[u][1])} IPs)" for u in hot[:8]) +
                          (" ..." if len(hot) > 8 else "") + ".")
            t += " Consider disabling password logins."
            self.alert("HIGH", "distributed_spray", "window", ts, t,
                       notify=(t, sorted({u for _, u, _ in rows})[:8], False))
        mine = [x for x in rows if x[1] == user]
        uips = {ip for ip, _, _ in mine}
        if len(uips) >= per_user:
            t = (f"Distributed password spray on user '{user[:64]}'. {len(mine)} failed SSH logins for this "
                 f"username from {len(uips)} different IPs in {took(mine)}. Someone may be targeting this "
                 "account; make sure it has a strong password or uses keys only.")
            if not merge_users:
                self.alert("HIGH", "distributed_spray", f"user:{user}", ts, t, notify=(t, [user], False))
            elif not window_hit:
                # exp2: one spray = one alert. A per-username hit raises the spray's single alert (same
                # "window" key and cooldown as the window-level alert), so whichever trips first is the only
                # one; later per-username or window hits for the same spray stay quiet for the cooldown.
                if len(ips) > len(uips):
                    t += (f" Spray so far: {len(rows)} failed SSH logins from {len(ips)} different IPs in "
                          f"{took(rows)}, trying user(s): {names({u for _, u, _ in rows})}.")
                self.alert("HIGH", "distributed_spray", "window", ts, t,
                           notify=(t, [user] + [u for u in sorted({u for _, u, _ in rows}) if u != user][:7], False))

    def check_unusual_hours(self, user, ip, method, ts):
        """commercial: login at an hour (server local time) this user has never logged in before."""
        r = self.rules["unusual_hours"]
        h = datetime.fromtimestamp(ts).hour
        hist = dict(self.db.execute("SELECT hour, n FROM login_hours WHERE user=?", (user,)).fetchall())
        total, tol = sum(hist.values()), int(r.get("tolerance_hours", 1))
        if r.get("enabled") and total >= int(r.get("min_samples", 10)) and not hour_near(h, hist, tol):
            usual = ", ".join(f"{x:02d}:00" for x in sorted(hist))
            t = (f"Unusual-hours login. User '{user}' logged in via {method} from {ip} at "
                 f"{datetime.fromtimestamp(ts):%H:%M} (server time), an hour with no logins in this user's "
                 f"{total} previous login(s) (usual hours: {usual}; tolerance +/-{tol} h). If this wasn't "
                 "them, the password or key may be stolen: lock the account and investigate.")
            self.alert("MEDIUM", "unusual_hours", f"{user}@{datetime.fromtimestamp(ts):%Y-%m-%d %H}", ts, t,
                       notify=(t, [user], True))
        self.db.execute("INSERT INTO login_hours VALUES (?, ?, 1) ON CONFLICT (user, hour) DO UPDATE SET n = n + 1",
                        (user, h))

    def on_success(self, ip, user, method, ts):
        r = self.rules["login_after_failures"]
        hit = self.q("SELECT alerted_ts FROM alerted_ips WHERE ip=? AND escalated=0", ip)
        if hit and self.cfg["alerting"].get("enabled"):
            # Escalation: an IP we already alerted on for brute force just got in. This replaces
            # the login_after_failures alert for this login, and fires once per brute-force alert.
            fails = self.db.execute("SELECT user FROM failures WHERE ip=? AND ts<=?", (ip, ts)).fetchall()
            tried = sorted({u for (u,) in fails})
            text = (f"ESCALATION: successful login from {ip} after brute force. User '{user}' logged in "
                    f"via {method} after {len(fails)} failed attempts from that IP (alerted at "
                    f"{fmt(hit[0])}; users tried: {', '.join(u[:64] for u in tried[:8])}). Treat this as a "
                    "likely compromise: lock the account, check ~/.ssh/authorized_keys, review processes.")
            if self.alert("CRITICAL", "brute_force_success", ip, ts, text, attacker=ip,
                          notify=(text, [user] + [u for u in tried[:8] if u != user], True),
                          share_as="login_after_failures"):
                self.db.execute("UPDATE alerted_ips SET escalated=1 WHERE ip=?", (ip,))
                # Start the login_after_failures cool-down too, so the same user's next logins
                # from this IP don't re-alert right after the escalation.
                self.db.execute("INSERT OR REPLACE INTO alerts VALUES ('login_after_failures', ?, ?)",
                                (f"{user}@{ip}", ts))
                r = {}   # already covered by the escalation
        if r.get("enabled"):
            n = self.q("SELECT COUNT(*) FROM failures WHERE ip=? AND ts BETWEEN ? AND ?",
                       ip, ts - r["lookback_minutes"] * 60, ts)[0]
            if n >= r["failures"]:
                self.alert("HIGH", "login_after_failures", f"{user}@{ip}", ts,
                           f"Login after failures. User '{user}' logged in via {method} from {ip} "
                           f"after {n} failed attempts from that IP. If this wasn't you, change the "
                           "password, check ~/.ssh/authorized_keys and review running processes.",
                           attacker=ip)
        approved = self.q("SELECT 1 FROM approved_ips WHERE ip=?", ip)
        cc = self.country(ip)
        first = "" if self.q("SELECT 1 FROM seen_ips WHERE user=?", user) else " (first recorded login)"
        src = f"logged in via {method} from {ip}{f' ({cc})' if cc else ''}"
        # A new country outranks a new IP, so at most one of the two fires per login.
        if (cc and not approved and self.rules["new_country"].get("enabled")
                and not self.q("SELECT 1 FROM seen_countries WHERE user=? AND country=?", user, cc)):
            t = (f"New-country login. User '{user}' {src}, a country never seen for this "
                 f"user{first}. If this wasn't you, lock the account and investigate.")
            self.alert("HIGH", "new_country", f"{user}@{cc}", ts, t, notify=(t, [user], True))
        elif (not approved and self.rules["new_ip"].get("enabled")
                and not self.q("SELECT 1 FROM seen_ips WHERE user=? AND ip=?", user, ip)):
            t = (f"New IP login. User '{user}' {src}, an address never seen for this "
                 f"user{first}. If expected, approve it with: sshsentry.py --approve {ip}")
            self.alert("LOW", "new_ip", f"{user}@{ip}", ts, t, notify=(t, [user], True))
        before = self.q("SELECT COUNT(*) FROM failures WHERE ip=? AND ts BETWEEN ? AND ?",
                        ip, ts - self.rules["login_after_failures"]["lookback_minutes"] * 60, ts)[0]
        self.check_unusual_hours(user, ip, method, ts)
        if self.cfg["digest"].get("enabled") or self.dry_run:   # login history only feeds the digest
            self.db.execute("INSERT INTO logins VALUES (?, ?, ?, ?, ?)", (ts, user, ip, method, before))
            self.db.execute("DELETE FROM logins WHERE ts < ?", (ts - 7 * 86400,))
        self.db.execute("INSERT OR IGNORE INTO seen_ips VALUES (?, ?, ?)", (user, ip, ts))
        if cc:
            self.db.execute("INSERT OR IGNORE INTO seen_countries VALUES (?, ?)", (user, cc))
        self.db.commit()

    # ---------- learn mode: threshold suggestion ----------
    def suggestion_data(self):
        """Structured learn-mode suggestion (schema sshsentry.threshold_suggestion/1)."""
        lm, cur = self.cfg["learn_mode"], self.rules["brute_force"]["failures"]
        counts = sorted(c for (c,) in self.db.execute("SELECT count FROM learn_windows"))
        out = {"schema": "sshsentry.threshold_suggestion/1", "suggested": None, "current": cur,
               "window_minutes": self.rules["brute_force"]["window_minutes"], "stats": None,
               "settings": {k: lm.get(k) for k in ("percentile", "margin", "min_threshold", "max_threshold")}}
        if counts:
            def pct(p):
                return counts[max(0, math.ceil(p / 100 * len(counts)) - 1)]
            p, margin = float(lm.get("percentile", 99)), float(lm.get("margin", 2))
            lo, hi = int(lm.get("min_threshold", 3)), int(lm.get("max_threshold", 50))
            out["suggested"] = min(hi, max(lo, math.ceil(pct(p) + margin)))
            out["stats"] = {"failed_logins": sum(counts), "ips": self.q("SELECT COUNT(DISTINCT ip) FROM learn_windows")[0],
                            "ip_windows": len(counts), "p50": pct(50), "p95": pct(95), "p99": pct(99),
                            "max": counts[-1], "chosen_percentile_value": pct(p)}
        return out

    def suggestion(self):
        """Return (suggested threshold or None, printable report) from recorded learn-mode data."""
        lm, cur = self.cfg["learn_mode"], self.rules["brute_force"]["failures"]
        win = self.rules["brute_force"]["window_minutes"]
        counts = sorted(c for (c,) in self.db.execute("SELECT count FROM learn_windows"))
        if not counts:
            return None, ("No failed-login data has been recorded by learn mode yet, so there is no "
                          f"suggestion. Keep the manual threshold (rules.brute_force.failures: {cur}).")
        def pct(p):   # nearest-rank percentile
            return counts[max(0, math.ceil(p / 100 * len(counts)) - 1)]
        p, margin = float(lm.get("percentile", 99)), float(lm.get("margin", 2))
        lo, hi = int(lm.get("min_threshold", 3)), int(lm.get("max_threshold", 50))
        sug = min(hi, max(lo, math.ceil(pct(p) + margin)))
        ips = self.q("SELECT COUNT(DISTINCT ip) FROM learn_windows")[0]
        report = [f"Threshold suggestion (learn mode; brute-force window = {win} min):",
                  f"  data: {sum(counts)} failed logins from {ips} IP(s) across {len(counts)} IP-window(s)",
                  f"  failures per IP per window: p50={pct(50)} p95={pct(95)} p99={pct(99)} max={counts[-1]}",
                  f"  suggested rules.brute_force.failures: {sug}  (p{p:g}={pct(p)} + margin {margin:g}; "
                  f"floor {lo}, cap {hi})",
                  f"  current manual threshold: {cur}" + ("  (unchanged until you run --accept-threshold)"
                                                          if sug != cur else "  (already matches)")]
        if sug > cur:
            report.append("  note: this data probably includes real attacks; a higher threshold "
                          "means fewer, later brute-force alerts.")
        return sug, "\n".join(report)

    # ---------- daily digest ----------
    def digest_stats(self, start, end):
        """Structured stats for [start, end): the source for both the stored JSON and the text."""
        fails = self.db.execute("SELECT ip, user FROM failures WHERE ts >= ? AND ts < ?", (start, end)).fetchall()
        rows = self.db.execute("SELECT user, ip, COUNT(*), MAX(failures_before) FROM logins WHERE ts >= ? "
                               "AND ts < ? GROUP BY user, ip ORDER BY MIN(ts)", (start, end)).fetchall()
        new_ips = [ip for (ip,) in self.db.execute("SELECT ip FROM seen_ips WHERE first_seen >= ? AND "
                                                   "first_seen < ? GROUP BY ip ORDER BY MIN(first_seen)", (start, end))]
        lim = self.rules["login_after_failures"]["failures"]
        logins = [{"user": u, "ip": ip, "count": n, "failures_before": fb, "after_failures": fb >= lim,
                   "new_ip": ip in new_ips} for u, ip, n, fb in rows]
        by_ip = {}
        for ip, user in fails:
            by_ip.setdefault(ip, []).append(user)
        top = None
        if by_ip:
            ip, users = max(by_ip.items(), key=lambda kv: len(kv[1]))
            top = {"ip": ip, "attempts": len(users), "usernames": sorted(set(u[:32] for u in users))[:6]}
        sug = self.suggestion()[0] if self.q("SELECT 1 FROM learn_windows") else None
        flagged = sum(1 for l in logins if l["after_failures"])
        sp = self.rules["distributed_spray"]
        spray = None
        light = {ip: len(u) for ip, u in by_ip.items() if len(u) < self.rules["brute_force"]["failures"]}
        if sp.get("enabled") and sum(light.values()) >= int(sp.get("failures", 20)) \
                and len(light) >= int(sp.get("distinct_ips", 10)):   # IPs that stayed under the per-IP limit
            spray = {"failed_logins": sum(light.values()), "ips": len(light), "max_per_ip": max(light.values())}
        return {"spray": spray, "failed_logins": len(fails), "distinct_ips": len(by_ip), "top_offender": top,
                "successful_logins": sum(l["count"] for l in logins), "logins": logins,
                "flagged_logins": flagged, "new_ips": new_ips, "suggestion": sug,
                "current_threshold": self.rules["brute_force"]["failures"],
                "quiet": not fails and not new_ips and not flagged}

    def digest_render(self, st, start, end, label):
        """One short screen of plain language. Returns (email subject, text)."""
        host = self.cfg["digest"].get("host_label")   # hostname is never added automatically
        head = f"sshsentry daily digest{f' for {host}' if host else ''}, {label}"
        span = f"{datetime.fromtimestamp(start):%a %b %d %H:%M} to {datetime.fromtimestamp(end):%a %b %d %H:%M}"
        if st["quiet"]:
            n = st["successful_logins"]
            extra = f" {n} routine login(s) from known addresses." if n else ""
            return "Daily digest: no incidents", f"{head}\nNo incidents today.{extra} Period: {span} (server time)."
        out = [head, f"Period: {span} (server time)", "",
               f"Failed logins: {st['failed_logins']} from {st['distinct_ips']} IP address(es)."]
        if st["top_offender"]:
            t = st["top_offender"]
            out.append(f"Most active: {t['ip']}, {t['attempts']} attempts (usernames tried: {', '.join(t['usernames'])}).")
        if st.get("spray"):
            sp = st["spray"]
            out.append(f"Possible distributed spray: {sp['failed_logins']} failures came from {sp['ips']} IPs with at "
                       f"most {sp['max_per_ip']} each, below the per-IP brute-force limit.")
        out.append(f"Successful logins: {st['successful_logins'] or 'none.'}")
        for l in st["logins"]:
            times = f" ({l['count']}x)" if l["count"] > 1 else ""
            new = " [new IP]" if l["new_ip"] else ""
            flag = f"  << after {l['failures_before']} failed attempts from that IP. Check this." \
                if l["after_failures"] else ""
            out.append(f"  - {l['user']} from {l['ip']}{times}{new}{flag}")
        if st["new_ips"]:
            ips = st["new_ips"]
            out.append(f"New IPs seen: {len(ips)} ({', '.join(ips[:5])}{' ...' if len(ips) > 5 else ''}).")
        if st["suggestion"] is not None:
            out.append(f"Learn mode suggests a brute-force threshold of {st['suggestion']} "
                       f"(currently {st['current_threshold']}); see --suggest-threshold.")
        subject = (f"Daily digest: {st['failed_logins']} failed, {st['successful_logins']} successful login(s)"
                   f"{', CHECK flagged login' if st['flagged_logins'] else ''}")
        return subject, "\n".join(out)

    def deliver_digest(self, subject, text, end, quiet=False):
        """Send a digest to digest.destination. Returns (status, destination, error); never raises."""
        if quiet and not self.cfg["digest"].get("send_when_quiet", True):
            return "skipped (quiet day, send_when_quiet: false)", "", ""
        kind = str(self.cfg["digest"].get("destination") or "email").lower()
        if kind not in ("email", "slack", "webhook"):
            return "failed", kind, f"unknown digest.destination {kind!r} (use email, slack or webhook)"
        c = merge(self.cfg, {"email": {"enabled": False}, "alerting": {"enabled": True}})
        for k in ("email", "slack", "webhook"):
            c["alerting"][k] = dict(c["alerting"][k], enabled=(k == kind))
        dests = build_destinations(c)   # reuses the alerting validation (prints warnings)
        if not dests:
            return "failed", kind, f"{kind} destination is not usable (see warning)"
        d = dests[0]
        event = {"severity": "LOW", "rule": "digest", "ip": None, "usernames": [], "success": None,
                 "timestamp": datetime.fromtimestamp(end, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "message": text}
        try:
            r = (self.send_email(d["cfg"], subject, text, self.cfg["alerting"].get("timeout", 5))
                 if kind == "email" else self.send_to(d, event))
        except Exception as e:   # a digest must never stop monitoring
            r = f"failed ({type(e).__name__}: {e})"
        return ("sent", kind, "") if r.startswith("sent") else ("failed", kind, r)

    def save_digest_text(self, date, text):
        dg = self.cfg["digest"]
        if not dg.get("save_text", True):
            return
        folder = self.digest_dir()
        try:
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, f"{date}.txt"), "w") as f:
                f.write(text + "\n")
        except OSError as e:
            print(f"[sshsentry] warning: could not write digest text file: {e}", file=sys.stderr)

    def digest_dir(self):
        return self.cfg["digest"].get("text_dir") or os.path.join(
            os.path.dirname(os.path.abspath(self.cfg["state_db"])), "digests")

    def make_digest(self, date, start, end, deliver):
        """Generate, chain, store (always), save text and optionally deliver one day's digest."""
        start, end = float(start), float(end)
        st = json.loads(json.dumps(self.digest_stats(start, end)))   # same form as stored/re-read
        subject, text = self.digest_render(st, start, end, date)
        prev = (self.q("SELECT chain_hash FROM daily_digests WHERE date < ? ORDER BY date DESC LIMIT 1", date)
                or (GENESIS,))[0]
        chain = chain_next(prev, {"date": date, "period_start": start, "period_end": end, "stats": st, "text": text})
        full = with_chain(text, chain)
        print(full, flush=True)
        self.db.execute("INSERT OR REPLACE INTO daily_digests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (date, start, end, time.time(), json.dumps(st), text, "pending", "", "", prev, chain))
        self.db.commit()
        self.save_digest_text(date, full)
        if deliver is True:
            body = full if self.cfg["digest"].get("include_chain_hash", True) else text
            status, dest, err = self.deliver_digest(subject, body, end, st["quiet"])
        else:
            status, dest, err = deliver or "not sent (digest.send: false)", "", ""
        if status == "failed":
            print(f"[sshsentry] digest for {date} failed ({dest}): {err}", file=sys.stderr)
        self.db.execute("UPDATE daily_digests SET status=?, destination=?, error=? WHERE date=?",
                        (status, dest, err, date))
        self.db.commit()

    def digest_slot(self, now):
        """Today's scheduled digest time (local) as a datetime, or None if digest.time is invalid."""
        try:
            hh, mm = (int(x) for x in str(self.cfg["digest"].get("time", "08:00")).split(":"))
            return datetime.fromtimestamp(now).replace(hour=hh, minute=mm, second=0, microsecond=0)
        except ValueError:
            print(f"[sshsentry] warning: digest.time {self.cfg['digest'].get('time')!r} is not HH:MM; "
                  "digest disabled", file=sys.stderr)
            self.cfg["digest"]["enabled"] = False
            return None

    def maybe_digest(self, now=None):
        """Generate every due daily digest (catching up missed days, up to 7). Each covers the
        24 h before its slot. Only the newest one is delivered, and only if digest.send is on."""
        dg = self.cfg["digest"]
        if not dg.get("enabled"):
            return
        # TEST-ONLY hook: SSHSENTRY_TEST_NOW (epoch seconds) simulates another day for the test
        # suite. It only shifts digest scheduling; never set it in production.
        now = now or float(os.environ.get("SSHSENTRY_TEST_NOW") or time.time())
        slot = self.digest_slot(now)
        if slot is None:
            return
        if slot.timestamp() > now:
            slot -= timedelta(days=1)          # most recent slot that has already passed
        if self.meta("digest_last_slot") is None:   # first time: start with the next slot
            self.set_meta("digest_last_slot", slot.timestamp())
            return
        last = datetime.fromtimestamp(float(self.meta("digest_last_slot")))
        due = []
        while last + timedelta(days=1) <= slot:
            last += timedelta(days=1)
            due.append(last)
        for i, sl in enumerate(due[-7:]):
            newest = i == len(due[-7:]) - 1
            deliver = (True if dg.get("send", True) else None) if newest else "not sent (catch-up)"
            self.set_meta("digest_last_slot", sl.timestamp())   # mark first: never twice
            if self.q("SELECT 1 FROM daily_digests WHERE date=?", f"{sl:%Y-%m-%d}"):
                continue
            self.make_digest(f"{sl:%Y-%m-%d}", (sl - timedelta(days=1)).timestamp(), sl.timestamp(), deliver)

    def digest_json(self, rec, include_text=True):
        out = {"date": rec["date"], "period_start": iso(rec["period_start"]), "period_end": iso(rec["period_end"]),
               "generated_at": iso(rec["created_at"]), "stats": rec["stats"],
               "delivery": {"status": rec["status"], "destination": rec["destination"] or None,
                            "error": rec["error"] or None},
               "prev_hash": rec["prev_hash"], "chain_hash": rec["chain_hash"]}
        if include_text:
            out["text"] = with_chain(rec["text"], rec["chain_hash"])
        return out

    def show_digests(self, n, as_json=False):
        dates = [d for (d,) in self.db.execute("SELECT date FROM daily_digests ORDER BY date DESC LIMIT ?", (n,))]
        if as_json:
            emit({"schema": "sshsentry.digests/1", "count": len(dates),
                  "digests": [self.digest_json(self.digest_record(d), include_text=False) for d in dates]})
            return
        if not dates:
            print("No daily digests recorded yet. Enable them with digest.enabled: true "
                  "(they're generated at digest.time each day).")
            return
        print(f"Last {len(dates)} daily digest(s). Details: sshsentry.py --digest YYYY-MM-DD")
        print(f"{'DATE':<10}  {'FAILED':>6}  {'IPS':>4}  {'TOP OFFENDER':<24}  {'LOGINS':>6}  {'NEW IPS':>7}  "
              f"{'CHAIN':<12}  DELIVERED")
        for d in dates:
            rec = self.digest_record(d)
            st, t = rec["stats"], rec["stats"]["top_offender"]
            top = f"{t['ip']} ({t['attempts']})" if t else "-"
            logins = f"{st['successful_logins']}{'!' if st['flagged_logins'] else ''}"
            yes = "yes" if rec["status"] == "sent" else f"no: {rec['status']}"
            print(f"{d:<10}  {st['failed_logins']:>6}  {st['distinct_ips']:>4}  {top:<24}  {logins:>6}  "
                  f"{len(st['new_ips']):>7}  {rec['chain_hash'][:12]:<12}  {yes}")
        print("(! = includes a successful login after failed attempts)")

    def show_digest(self, date, as_json=False):
        rec = self.digest_record(date)
        if not rec:
            if as_json:
                emit({"schema": "sshsentry.digest/1", "date": date, "found": False})
            else:
                print(f"No digest recorded for {date}. List recorded days with --digests.")
            return False
        if as_json:
            emit({"schema": "sshsentry.digest/1", "found": True, "stored": True, **self.digest_json(rec)})
            return True
        print(with_chain(rec["text"], rec["chain_hash"]))
        print(f"\n[generated {fmt(rec['created_at'])}; delivery: {rec['status']}"
              f"{' via ' + rec['destination'] if rec['destination'] else ''}"
              f"{'; error: ' + rec['error'] if rec['error'] else ''}]")
        return True

    def verify_chain(self, as_json=False):
        """Recompute the local digest chain; report the first day that doesn't match."""
        checks, prev, broken = [], GENESIS, None
        dates = [d for (d,) in self.db.execute("SELECT date FROM daily_digests ORDER BY date")]
        for d in dates:
            rec = self.digest_record(d)
            want = chain_next(prev, rec)
            ok = rec["prev_hash"] == prev and rec["chain_hash"] == want
            why = ("ok" if ok else "previous-hash link broken (a day was removed or reordered)"
                   if rec["prev_hash"] != prev else "content changed after it was recorded")
            checks.append({"check": "chain", "date": d, "ok": ok, "detail": why})
            path = os.path.join(self.digest_dir(), f"{d}.txt")
            if os.path.exists(path):
                same = open(path).read() == with_chain(rec["text"], rec["chain_hash"]) + "\n"
                checks.append({"check": "text_file", "date": d, "ok": same,
                               "detail": "matches" if same else f"{path} differs from the stored digest"})
            if not ok and broken is None:
                broken = d
            prev = rec["chain_hash"]   # continue from the stored value so later days are judged on their own
        result = {"schema": "sshsentry.verify/1", "target": "local database", "ok": all(c["ok"] for c in checks),
                  "days": len(dates), "chain_head": prev if dates else None, "first_broken_date": broken,
                  "checks": checks}
        report_verify(result, as_json)
        return result["ok"]

    def export_digests(self, start, end, out=None, host_label=None, as_json=False):
        """Zip stored digests for [start, end]: per-day text + JSON record, a manifest with per-file
        SHA-256 and chain hashes, and a `sha256sum -c` sidecar. Returns an exit code."""
        def fail(msg, code):
            if as_json:
                emit({"schema": "sshsentry.export/1", "ok": False, "error": msg})
            else:
                print(msg, file=sys.stderr)
            return code
        try:
            d0, d1 = (datetime.strptime(x, "%Y-%m-%d").date() for x in (start, end))
        except ValueError:
            return fail(f"Invalid date: use YYYY-MM-DD (got {start!r} {end!r}).", 2)
        if d0 > d1:
            return fail(f"START ({start}) is after END ({end}).", 2)
        dates = [d for (d,) in self.db.execute("SELECT date FROM daily_digests WHERE date BETWEEN ? AND ? "
                                                "ORDER BY date", (start, end))]
        if not dates:
            return fail(f"No daily digests are stored between {start} and {end}; nothing exported. "
                        "See --digests for recorded days.", 1)
        days = [(d0 + timedelta(days=i)).isoformat() for i in range((d1 - d0).days + 1)]
        missing = [d for d in days if d not in dates]
        out = out or f"sshsentry-digests-{start}_to_{end}.zip"
        files, entries = {}, []
        for d in dates:
            rec = self.digest_record(d)
            txt = (with_chain(rec["text"], rec["chain_hash"]) + "\n").encode()
            record = {k: rec[k] for k in ("date", "period_start", "period_end", "stats", "text")}
            rj = (json.dumps({"schema": "sshsentry.digest_record/1", **record, "prev_hash": rec["prev_hash"],
                              "chain_hash": rec["chain_hash"], "delivery": rec["status"]}, indent=2,
                             sort_keys=True, ensure_ascii=False) + "\n").encode()
            files[f"digests/{d}.txt"], files[f"records/{d}.json"] = txt, rj
            entries.append({"date": d, "text_file": f"digests/{d}.txt", "text_sha256": hashlib.sha256(txt).hexdigest(),
                            "record_file": f"records/{d}.json", "record_sha256": hashlib.sha256(rj).hexdigest(),
                            "prev_hash": rec["prev_hash"], "chain_hash": rec["chain_hash"], "delivery": rec["status"]})
        other = {}
        if missing:
            files["MISSING-DAYS.txt"] = ("No digest was recorded for these dates (digest disabled, sshsentry "
                                         "not running, or before the first digest):\n" + "\n".join(missing) + "\n").encode()
            other["MISSING-DAYS.txt"] = hashlib.sha256(files["MISSING-DAYS.txt"]).hexdigest()
        manifest = {"schema": "sshsentry.export_manifest/2", "tool": "sshsentry", "sshsentry_version": VERSION,
                    "range": {"start": start, "end": end},
                    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "genesis": GENESIS, "chain_head": entries[-1]["chain_hash"], "days": entries,
                    "other_files": other, "missing_dates": missing,
                    "chain_rule": "chain_hash = sha256(prev_hash + canonical(record)); canonical = compact "
                                  "sorted-key JSON of date, period_start, period_end, stats, text",
                    "note": "Hashes show these files are unchanged since export, and the chain shows days weren't "
                            "edited, removed or reordered relative to each other. Compare chain_head with a hash "
                            "that left the server earlier (e.g. an emailed digest) to detect a rewritten chain. "
                            "None of this proves the digests were accurate."}
        if host_label:
            manifest["host_label"] = host_label
        files["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
        try:
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
                for name in ["manifest.json"] + sorted(n for n in files if n != "manifest.json"):
                    z.writestr(name, files[name])
            digest = hashlib.sha256(open(out, "rb").read()).hexdigest()
            with open(out + ".sha256", "w") as f:
                f.write(f"{digest}  {os.path.basename(out)}\n")
        except OSError as e:
            return fail(f"Export failed: {e}", 1)
        path = os.path.abspath(out)
        if as_json:
            emit({"schema": "sshsentry.export/1", "ok": True, "path": path, "sha256": digest,
                  "sidecar": path + ".sha256", "exported_days": len(entries), "missing_dates": missing,
                  "chain_head": manifest["chain_head"]})
            return 0
        print(f"Exported {len(entries)} digest(s) ({len(missing)} missing day(s)) to {path}")
        print(f"SHA-256: {digest}")
        print(f"Chain head: {manifest['chain_head']}")
        print(f"Checksum file: {path}.sha256  (verify: cd {os.path.dirname(path)} && sha256sum -c "
              f"{os.path.basename(out)}.sha256, or sshsentry.py --verify-export {os.path.basename(out)})")
        print("Send the SHA-256 to the recipient separately (or store it elsewhere) now, so later changes can be detected.")
        return 0

    def resend_digest(self, date):
        rec = self.digest_record(date)
        if not rec:
            print(f"No digest recorded for {date}.")
            return False
        body = with_chain(rec["text"], rec["chain_hash"]) if self.cfg["digest"].get("include_chain_hash", True) \
            else rec["text"]
        status, dest, err = self.deliver_digest(f"Daily digest ({date}, resent)", body, rec["period_end"])
        self.db.execute("UPDATE daily_digests SET status=?, destination=?, error=? WHERE date=?",
                        (status, dest, err, date))
        self.db.commit()
        print(f"Resend of {date} via {dest or '?'}: {status}{f' ({err})' if err else ''}")
        return status == "sent"

    def maybe_report_learning(self):
        """Print the suggestion once when the learn-mode period ends."""
        if (self.cfg["learn_mode"].get("enabled") and self.meta("learn_start") and not self.learn_active()
                and self.meta("learn_reported") is None):
            print("[sshsentry] learn mode period finished; alerts are being sent again using the "
                  f"manual threshold ({self.rules['brute_force']['failures']}).", flush=True)
            print(self.suggestion()[1], flush=True)
            self.set_meta("learn_reported", time.time())

    # ---------- file rules ----------
    def unseen(self, flag, table, cols, found):
        """Yield entries of `found` ({key: info}) missing from `table`, recording them.
        The first pass only builds the baseline, so nothing is yielded then."""
        first, where = self.meta(flag) is None, " AND ".join(f"{c}=?" for c in cols)
        for key, info in found.items():
            if not self.q(f"SELECT 1 FROM {table} WHERE {where}", *key):
                self.db.execute(f"INSERT INTO {table} VALUES ({','.join('?' * len(key))})", key)
                if not first:
                    yield key, info
        self.set_meta(flag, 1)

    def check_files(self):
        """Compare /etc/passwd and authorized_keys files against the SQLite baseline."""
        now, r = time.time(), self.rules["new_user"]
        if r.get("enabled") and os.path.exists(r["passwd_file"]):
            with open(r["passwd_file"], errors="replace") as f:
                users = {(p[0],): p for p in (l.strip().split(":") for l in f) if len(p) >= 7}
            for (name,), p in self.unseen("users_baselined", "users", ["name"], users):
                self.alert("HIGH", "new_user", name, now,
                           f"New user account. '{name}' (uid {p[2]}, shell {p[6]}) appeared in "
                           f"{r['passwd_file']}. If you didn't create it, investigate immediately.")
        r, keys = self.rules["new_ssh_key"], {}
        if not r.get("enabled"):
            return
        for path in sorted({p for pat in r["paths"] for p in glob.glob(pat)}):
            try:
                with open(path, errors="replace") as f:
                    for l in (l.strip() for l in f):
                        if l and not l.startswith("#"):
                            keys[(path, hashlib.sha256(l.encode()).hexdigest())] = l.split()
            except OSError:
                continue   # unreadable: run as root to see every user's keys
        for (path, h), parts in self.unseen("keys_baselined", "keys", ["path", "line_hash"], keys):
            ktype = next((x for x in parts if x.startswith(("ssh-", "ecdsa-", "sk-"))), "unknown-type")
            comment = parts[-1] if len(parts) > 2 else "no comment"
            self.alert("HIGH", "new_ssh_key", f"{path}:{h[:16]}", now,
                       f"New SSH key. A key ({ktype}, '{comment}', line hash {h[:12]}) was added to "
                       f"{path}. Anyone holding it can log in. Remove it if you didn't add it.")


def report_verify(result, as_json):
    if as_json:
        emit(result)
        return
    for c in result["checks"]:
        print(f"{'PASS' if c['ok'] else 'FAIL'}  {c['check']:<10} {c.get('date') or '':<10}  {c['detail']}")
    if result.get("first_broken_date"):
        print(f"First broken day: {result['first_broken_date']}")
    print(f"RESULT: {'PASS' if result['ok'] else 'FAIL'} ({result['target']}; {result.get('days', 0)} day(s); "
          f"chain head {(result.get('chain_head') or '-')[:12]})")


def verify_export(path, expected_head=None, as_json=False):
    """Check an export zip: sidecar, every file vs manifest, the recomputed chain, and optionally
    that the chain head matches a hash that left the server earlier. Returns True if all pass."""
    checks, broken = [], None
    def add(check, ok, detail, date=None):
        nonlocal broken
        checks.append({"check": check, "date": date, "ok": bool(ok), "detail": detail})
        if not ok and date and broken is None:
            broken = date
    head = None
    side = path + ".sha256"
    try:
        actual = hashlib.sha256(open(path, "rb").read()).hexdigest()
    except OSError as e:
        add("zip", False, f"cannot read {path}: {e}")
        actual = None
    if actual and os.path.exists(side):
        parts = open(side).read().split()
        good = len(parts) >= 2 and parts[0] == actual and parts[1].lstrip("*") == os.path.basename(path)
        add("sidecar", good, "zip SHA-256 matches .sha256 file" if good else
            f"zip SHA-256 {actual[:12]} does not match {side}")
    elif actual:
        add("sidecar", True, "no .sha256 file next to the zip (skipped)")
    days = []
    try:
        z = zipfile.ZipFile(path)
        m = json.loads(z.read("manifest.json"))
        names = set(z.namelist()) - {"manifest.json"}
        days = m.get("days") or []
        listed = {d["text_file"] for d in days} | {d["record_file"] for d in days} | set(m.get("other_files", {}))
        extra = sorted(names - listed)
        add("files", not extra, "no unlisted files in zip" if not extra else f"unlisted files: {', '.join(extra)}")
        for name, sha in m.get("other_files", {}).items():
            data = z.read(name) if name in names else b""
            add("file", hashlib.sha256(data).hexdigest() == sha, f"{name} matches manifest")
        prev = days[0]["prev_hash"] if days else None
        for d in days:
            date = d["date"]
            try:
                txt, rj = z.read(d["text_file"]), z.read(d["record_file"])
            except KeyError as e:
                add("file", False, f"missing from zip: {e}", date)
                continue
            add("text_sha", hashlib.sha256(txt).hexdigest() == d["text_sha256"],
                "text file matches manifest" if hashlib.sha256(txt).hexdigest() == d["text_sha256"]
                else "text file differs from manifest (edited after export)", date)
            add("record_sha", hashlib.sha256(rj).hexdigest() == d["record_sha256"],
                "record matches manifest" if hashlib.sha256(rj).hexdigest() == d["record_sha256"]
                else "JSON record differs from manifest (edited after export)", date)
            rec = json.loads(rj)
            want = chain_next(prev, rec)
            link = d["prev_hash"] == prev and rec.get("prev_hash") == prev
            add("chain", link and want == d["chain_hash"] == rec.get("chain_hash"),
                "chain recomputes" if link and want == d["chain_hash"] == rec.get("chain_hash") else
                ("previous-hash link broken (day removed or reordered)" if not link
                 else "recomputed chain hash differs (digest content edited)"), date)
            same = txt.decode(errors="replace") == with_chain(rec["text"], d["chain_hash"]) + "\n"
            add("text_body", same, "text matches its record" if same else "text file doesn't match its record", date)
            prev = d["chain_hash"]
        head = prev
        add("head", head == m.get("chain_head"), f"chain head {(head or '-')[:12]} matches manifest"
            if head == m.get("chain_head") else "manifest chain_head doesn't match the last day")
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as e:
        add("manifest", False, f"cannot read export: {type(e).__name__}: {e}")
    if expected_head:
        exp = expected_head.strip().lower()
        hit = next((d["date"] for d in days if len(exp) >= 12 and d["chain_hash"].startswith(exp)), None)
        if head and len(exp) >= 12 and head.startswith(exp):
            add("expected", True, "chain head matches the expected hash")
        elif hit:
            add("expected", True, f"expected hash matches the chain at {hit} (not the head): days up to {hit} "
                                  "are the ones that left the server")
        else:
            add("expected", False, "expected hash not found in this export's chain (at least 12 hex chars needed)"
                if len(exp) < 12 else "expected hash not found: this export's chain differs from what left the server")
    result = {"schema": "sshsentry.verify/1", "target": os.path.basename(path), "ok": all(c["ok"] for c in checks),
              "days": len(days), "chain_head": head, "first_broken_date": broken, "checks": checks}
    report_verify(result, as_json)
    return result["ok"]


def accept_threshold(path, value):
    """Write rules.brute_force.failures into the YAML file, preserving comments and layout.
    Only edits a block-style `failures:` line under rules -> brute_force; returns False otherwise."""
    try:
        lines = open(path).read().splitlines(keepends=True)
    except OSError:
        return False
    indent = lambda l: len(l) - len(l.lstrip())
    def child(start, parent_indent, key):
        for i in range(start, len(lines)):
            l = lines[i]
            if not l.strip() or l.lstrip().startswith("#"):
                continue
            if indent(l) <= parent_indent:
                return None
            if re.match(rf"\s*{key}:\s*(#.*)?$", l):
                return i
        return None
    rules = next((i for i, l in enumerate(lines) if re.match(r"rules:\s*(#.*)?$", l)), None)
    bf = rules is not None and child(rules + 1, 0, "brute_force")
    if not bf:
        return False
    bf_indent = indent(lines[bf])
    for i in range(bf + 1, len(lines)):
        l = lines[i]
        if l.strip() and not l.lstrip().startswith("#") and indent(l) <= bf_indent:
            break
        m = re.match(r"(\s*failures:\s*)\d+(.*)$", l.rstrip("\n"))
        if m and indent(l) > bf_indent:
            lines[i] = f"{m.group(1)}{value}{m.group(2)}\n"
            break
    else:
        return False
    new = "".join(lines)
    try:   # never write a file that no longer parses to the intended value
        if yaml.safe_load(new)["rules"]["brute_force"]["failures"] != value:
            return False
    except Exception:
        return False
    with open(path + ".bak", "w") as f:
        f.write(open(path).read())
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(new)
    os.chmod(tmp, os.stat(path).st_mode)
    os.replace(tmp, path)
    return True


def find_log(cfg):
    if cfg["log_file"] != "auto":
        return cfg["log_file"]
    found = [p for p in ("/var/log/auth.log", "/var/log/secure") if os.path.exists(p)]
    return found[0] if found else sys.exit("No /var/log/auth.log or /var/log/secure; set log_file.")


class LogFollower:
    """commercial: follows the log with tamper detection. Truncation, replacement, deletion and a
    missing file raise HIGH `log_tamper` alerts; normal rotation (old file renamed next to it, e.g.
    auth.log.1) is a LOW notice. The old handle is always read to EOF before switching files."""

    def __init__(self, s, path):
        self.s, self.path, self.f, self.missing_since, self.missing_alerted = s, path, None, None, False
        self.lines = 0
        self.t = s.cfg["tamper"]

    def tamper(self, kind, text, high=True):
        if not self.t.get("enabled"):
            return
        if not high:
            mode = str(self.t.get("rotation_notice", "log")).lower()
            if mode in ("off", "false", "none"):
                return
            if mode != "alert" and mode != "true":   # default: a note on stderr only (routine event)
                print(f"[sshsentry] note: {text}", file=sys.stderr, flush=True)
                return
            sev = str(self.t.get("rotation_severity") or "LOW").upper()
            sev = sev if sev in SEVERITIES else "LOW"
            self.s.alert(sev, "log_rotated", f"{kind}:{time.time():.6f}", time.time(), text)
        else:   # every tamper event is its own alert (no cool-down)
            self.s.alert("HIGH", "log_tamper", f"{kind}:{time.time():.6f}", time.time(), text)

    def rotated_to(self, dev, ino):
        """Path of a sibling file (auth.log.1, auth.log-20261025, ...) that is the old inode, or None."""
        d, base = os.path.dirname(self.path) or ".", os.path.basename(self.path)
        for pat in self.t.get("rotated_patterns") or []:
            for c in glob.glob(os.path.join(glob.escape(d), glob.escape(base) + pat)):
                try:
                    st = os.stat(c)
                except OSError:
                    continue
                if (st.st_dev, st.st_ino) == (dev, ino) and os.path.abspath(c) != os.path.abspath(self.path):
                    return c
        return None

    def read(self, f):
        n = 0
        while True:
            line = f.readline()
            if not line:
                return n
            self.s.handle_line(line)
            n += 1

    def save(self):
        st = os.fstat(self.f.fileno())
        self.s.set_meta("log_offset", self.f.tell())
        self.s.set_meta("log_inode", st.st_ino)
        self.s.set_meta("log_dev", st.st_dev)

    def open_start(self):
        """Open at startup: resume, learn, or check what changed while sshsentry wasn't running."""
        s = self.s
        self.f = open(self.path, errors="replace")
        offset = s.meta("log_offset")
        st = os.fstat(self.f.fileno())
        if offset is None and s.cfg.get("learn_existing_log"):
            s.learning = True                  # first run: silently learn IPs from existing history
            for line in self.f:
                s.handle_line(line)
            s.learning = False
            return
        if offset is None:
            self.f.seek(0, os.SEEK_END)        # first run without learning: start at the end
            return
        offset, old_ino = int(offset), s.meta("log_inode")
        old_dev = s.meta("log_dev")
        same = old_ino == str(st.st_ino) and (old_dev is None or old_dev == str(st.st_dev))
        if same and offset <= st.st_size:
            self.f.seek(offset)                # same file as last time: resume where we stopped
            return
        if same:
            self.tamper("truncated_offline", f"Log tampering? {self.path} is smaller ({st.st_size} bytes) than "
                        f"where sshsentry stopped reading ({offset} bytes) while it was not running: it was "
                        "truncated or rewritten. Lines may have been removed; check the system journal.")
            return                             # read the (shorter) file from the start
        old = self.rotated_to(int(old_dev or st.st_dev), int(old_ino or -1)) if old_ino else None
        if old:
            try:   # catch up the tail of the rotated file first, so nothing is lost
                with open(old, errors="replace") as g:
                    g.seek(min(offset, os.path.getsize(old)))
                    self.lines += self.read(g)
            except OSError:
                pass
            self.tamper("rotated_offline", f"Log rotated while sshsentry was not running: {self.path} was "
                        f"renamed to {old} and a new file started. Read the rest of {old}, then the new file.",
                        high=False)
        else:
            self.tamper("replaced_offline", f"Log tampering? {self.path} was replaced while sshsentry was not "
                        "running (different file, and the old one was not found as a rotated copy next to it). "
                        "Lines may have been removed; check the system journal.")

    def poll(self):
        """Check the path once after reaching EOF; switch files if needed."""
        f = self.f
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self.lines += self.read(f)         # keep draining the old (deleted / renamed) handle
            now = time.time()
            self.missing_since = self.missing_since or now
            if now - self.missing_since >= float(self.t.get("missing_seconds", 30)) and not self.missing_alerted:
                self.missing_alerted = True
                self.tamper("missing", f"Log tampering? {self.path} has been missing for "
                            f"{int(now - self.missing_since)} sec (since {fmt(self.missing_since)}). sshsentry "
                            "cannot see SSH activity until it comes back.")
            return
        was_missing = self.missing_since
        self.missing_since, self.missing_alerted = None, False
        old = os.fstat(f.fileno())
        if (st.st_dev, st.st_ino) != (old.st_dev, old.st_ino):
            self.lines += self.read(f)         # drain the old file before switching
            gone = self.rotated_to(old.st_dev, old.st_ino) if old.st_nlink else None
            if gone:
                self.tamper("rotated", f"Log rotated: {self.path} was renamed to {gone} and a new file "
                            f"started ({st.st_size} bytes). Following the new file.", high=False)
            elif not old.st_nlink:
                self.tamper("deleted", f"Log tampering? {self.path} was deleted and a new file created in its "
                            f"place{f' (missing for {int(time.time() - was_missing)} sec)' if was_missing else ''}. "
                            "The old contents are gone; check the system journal. Following the new file.")
            else:
                self.tamper("replaced", f"Log tampering? {self.path} was replaced by a different file and the "
                            "old one was not found as a rotated copy next to it. Following the new file.")
            f.close()
            self.f = open(self.path, errors="replace")
        elif st.st_size < f.tell():
            self.tamper("truncated", f"Log tampering? {self.path} was truncated in place: it is now "
                        f"{st.st_size} bytes but sshsentry had already read {f.tell()} bytes. Lines may have "
                        "been removed (or a copytruncate rotation happened). Reading from the start.")
            f.seek(0)


def watch(s, path, follow):
    """Read new log lines from the saved offset; keep following (survives rotation) if asked.
    commercial: tamper alerts, heartbeat, retry queue, systemd watchdog and downtime detection."""
    lf = LogFollower(s, path)
    unclean, last_alive = s.mark_running()
    started = time.time()
    while True:
        try:
            lf.open_start()
            break
        except FileNotFoundError:
            if not follow:
                lf.tamper("missing", f"Log tampering? {path} does not exist, so sshsentry cannot see SSH activity.")
                s.mark_clean()
                return
            lf.missing_since = lf.missing_since or time.time()
            if time.time() - lf.missing_since >= float(lf.t.get("missing_seconds", 30)) and not lf.missing_alerted:
                lf.missing_alerted = True
                lf.tamper("missing", f"Log tampering? {path} has been missing for "
                          f"{int(time.time() - lf.missing_since)} sec since sshsentry started.")
            time.sleep(s.cfg["poll_seconds"])
    lf.missing_since, lf.missing_alerted = None, False
    sd_notify("READY=1")
    wd = float(os.environ.get("WATCHDOG_USEC") or 0) / 1e6
    last_check = last_wd = last_mark = 0
    caught_up = False
    while True:
        lf.lines += lf.read(lf.f)
        lf.save()
        now = time.time()
        if not caught_up:
            caught_up = True
            if unclean and s.cfg["downtime_alert"].get("enabled"):
                s.alert("MEDIUM", "downtime", f"{started:.6f}", now,
                        f"sshsentry was not running from {fmt(last_alive)} to {fmt(started)} (it stopped without a "
                        f"clean shutdown: killed, crashed or power loss); caught up {lf.lines} log line(s) written "
                        "in the meantime. Anything during that gap was only detected late.")
        if now - last_mark >= 5:
            s.touch_marker()
            last_mark = now
        if not follow or now - last_check >= s.cfg["file_check_seconds"]:
            s.check_files()
            s.maybe_report_learning()
            s.maybe_digest()
            last_check = now
        s.retry_pending()
        s.maybe_heartbeat()
        if wd and now - last_wd >= wd / 2:
            sd_notify("WATCHDOG=1")
            last_wd = now
        if not follow:
            s.mark_clean()
            return
        time.sleep(s.cfg["poll_seconds"])
        lf.poll()


def main():
    ap = argparse.ArgumentParser(description="sshsentry: plain-English SSH intrusion alerts (detection only).")
    ap.add_argument("-c", "--config", default="/etc/sshsentry/sshsentry.yaml", help="YAML config path")
    ap.add_argument("--log", help="override log file path")
    ap.add_argument("--db", help="override SQLite state path")
    ap.add_argument("--replay", "--dry-run", dest="replay", metavar="FILE",
                    help="process FILE from the start and print alerts; never sends anything")
    ap.add_argument("--once", action="store_true", help="process new log lines once, then exit (timers)")
    ap.add_argument("--approve", metavar="IP", help="mark an IP as known for all users, then exit")
    ap.add_argument("--show-shared", action="store_true", help="list everything this install has shared")
    ap.add_argument("--forget-me", action="store_true",
                    help="delete local sharing history (and ask the endpoint to delete it, if configured)")
    ap.add_argument("--local-only", action="store_true", help="with --forget-me: skip the remote request")
    ap.add_argument("--test-alerts", action="store_true", help="send a sample alert to each enabled destination")
    ap.add_argument("--suggest-threshold", action="store_true", help="print the learn-mode threshold suggestion")
    ap.add_argument("--digest-now", action="store_true",
                    help="print a digest of the last 24 h now and send it if digest.send is on "
                         "(with --replay: print only, for the replayed log); not stored")
    ap.add_argument("--digests", nargs="?", const=7, type=int, metavar="N",
                    help="list the last N stored daily digests (default 7)")
    ap.add_argument("--digest", metavar="DATE", help="show one stored daily digest (YYYY-MM-DD)")
    ap.add_argument("--resend", metavar="DATE", help="send a stored daily digest again")
    ap.add_argument("--export-digests", nargs=2, metavar=("START", "END"),
                    help="zip stored digests for an inclusive YYYY-MM-DD range, with manifest + SHA-256")
    ap.add_argument("-o", "--output", metavar="PATH", help="with --export-digests: zip path")
    ap.add_argument("--host-label", help="with --export-digests: label to include in the manifest")
    ap.add_argument("--accept-threshold", action="store_true",
                    help="write the suggested brute-force threshold into the config file")
    ap.add_argument("--verify-chain", action="store_true", help="recompute the local digest hash chain")
    ap.add_argument("--verify-export", metavar="ZIP", help="verify an --export-digests zip")
    ap.add_argument("--expected-head", metavar="HASH",
                    help="with --verify-export: chain hash that left the server earlier (e.g. from an emailed digest)")
    ap.add_argument("--format", choices=("text", "json"), default="text",
                    help="output format for --digests, --digest, --digest-now, --suggest-threshold, "
                         "--show-shared, --export-digests, --verify-*, and --replay")
    a = ap.parse_args()
    as_json = a.format == "json"
    if a.verify_export:   # needs no config or database
        sys.exit(0 if verify_export(a.verify_export, a.expected_head, as_json) else 1)

    if not os.path.exists(a.config) and a.config != ap.get_default("config"):
        sys.exit(f"Config not found: {a.config}")
    user_cfg = yaml.safe_load(open(a.config)) if os.path.exists(a.config) else {}
    cfg = normalize(merge(DEFAULTS, user_cfg), user_cfg)
    cfg["state_db"], cfg["log_file"] = a.db or cfg["state_db"], a.log or cfg["log_file"]

    admin = (a.approve or a.show_shared or a.forget_me or a.test_alerts or a.suggest_threshold
             or a.accept_threshold or (a.digest_now and not a.replay) or a.digests is not None
             or a.digest or a.resend or a.export_digests or a.verify_chain)
    s = Agent(cfg, dry_run=bool(a.replay), admin=bool(admin))
    if a.test_alerts:
        sys.exit(0 if s.test_alerts() else 1)
    elif a.verify_chain:
        sys.exit(0 if s.verify_chain(as_json) else 1)
    elif a.export_digests:
        sys.exit(s.export_digests(*a.export_digests, out=a.output, host_label=a.host_label, as_json=as_json))
    elif a.digests is not None:
        s.show_digests(max(1, a.digests), as_json)
    elif a.digest:
        sys.exit(0 if s.show_digest(a.digest, as_json) else 1)
    elif a.resend:
        sys.exit(0 if s.resend_digest(a.resend) else 1)
    elif a.digest_now and not a.replay:   # on demand preview: not stored, schedule untouched
        now = time.time()
        st = s.digest_stats(now - 86400, now)
        subject, text = s.digest_render(st, now - 86400, now, "last 24 hours (on demand)")
        if not as_json:
            print(text)
        status, dest, err = "off (digest.send: false)", "", ""
        if cfg["digest"].get("send", True):
            status, dest, err = s.deliver_digest(subject, text, now, st["quiet"])
        if as_json:
            emit({"schema": "sshsentry.digest/1", "found": True, "stored": False, "date": None,
                  "period_start": iso(now - 86400), "period_end": iso(now), "stats": st, "text": text,
                  "delivery": {"status": status, "destination": dest or None, "error": err or None}})
        else:
            print(f"[delivery: {status}{f' via {dest}' if dest else ''}{f'; {err}' if err else ''}]")
    elif a.suggest_threshold:
        emit(s.suggestion_data()) if as_json else print(s.suggestion()[1])
    elif a.accept_threshold:
        value, report = s.suggestion()
        print(report)
        if value is None:
            sys.exit(1)
        if os.path.exists(a.config) and accept_threshold(a.config, value):
            print(f"Updated {a.config}: rules.brute_force.failures = {value} (backup: {a.config}.bak). "
                  "Restart sshsentry to apply.")
        else:
            print(f"Could not safely edit {a.config}; add this to it yourself:\n"
                  f"rules:\n  brute_force:\n    failures: {value}")
    elif a.show_shared:
        s.show_shared(as_json)
    elif a.forget_me:
        s.forget_me(a.local_only)
    elif a.approve:
        s.db.execute("INSERT OR IGNORE INTO approved_ips VALUES (?)", (a.approve,))
        print(f"Approved {a.approve}; logins from it will no longer raise new-IP/country alerts.")
    elif a.replay:
        if as_json:
            s.collect = []
        with open(a.replay, errors="replace") as f:
            for line in f:
                s.handle_line(line)
        s.check_files()
        out = {"schema": "sshsentry.replay/1", "file": a.replay, "alerts": s.collect}
        if cfg["learn_mode"].get("enabled"):
            if as_json:
                out["threshold_suggestion"] = s.suggestion_data()
            else:
                print(s.suggestion()[1])
        if a.digest_now:   # digest of the replayed events only; never sent
            lo, hi = s.q("SELECT MIN(t), MAX(t) FROM (SELECT ts t FROM failures UNION ALL SELECT ts FROM logins)")
            lo, hi = lo or time.time(), (hi or time.time()) + 1
            st = s.digest_stats(lo, hi)
            text = s.digest_render(st, lo, hi - 1, "replayed log")[1]
            if as_json:
                out["digest"] = {"stored": False, "period_start": iso(lo), "period_end": iso(hi - 1),
                                 "stats": st, "text": text}
            else:
                print()
                print(text)
        if as_json:
            emit(out)
    else:
        def stop(signum, frame):   # systemctl stop / kill: shut down cleanly (no downtime alert next start)
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        try:
            watch(s, find_log(cfg), follow=not a.once)
        except KeyboardInterrupt:
            sd_notify("STOPPING=1")
            s.mark_clean()
    s.db.commit()


if __name__ == "__main__":
    main()
