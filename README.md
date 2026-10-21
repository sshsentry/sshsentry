# sshsentry

A free, open source, single-script intrusion **detection** agent for Linux servers. It watches your SSH auth log (plus `/etc/passwd` and `authorized_keys`) and prints plain-English alerts, optionally to email, Slack, or a webhook. It never blocks or attacks anything; pair it with fail2ban, a firewall, and key-only SSH.

## Why this exists

If you run one or a few Linux servers with SSH open, someone is probably guessing passwords on them right now, and nobody is reading the logs. Most SSH monitoring tools are enterprise suites: agents, dashboards, a database, and hours of setup. There's very little that's small and free and just watches the log and tells you when something matters.

sshsentry is one Python script. It reads your auth log, spots brute force, logins after failures, logins from new IPs or countries, and new users or SSH keys, then explains them in plain English on stdout, email, Slack, or a webhook.

It's for indie developers and small businesses. It's not for large fleets or compliance programs. It doesn't block anything (it's not a firewall or fail2ban), and it doesn't see web-app attacks. Optional learn mode can suggest a brute-force threshold from your own traffic.

## Try it in 30 seconds

No install or root needed, just Python 3.9+ and PyYAML. Replay the bundled sample log against a throwaway database:

```bash
pip install pyyaml
python3 sshsentry.py -c sshsentry.yaml --db /tmp/sshsentry-try.db --replay sample-auth.log --digest-now
```

You'll see the alerts (two brute-force attacks, a login after failures, and new-IP logins), followed by the daily digest for that log. Nothing is sent anywhere in `--replay` mode.

**Even quicker: the demo page.** Open `demo/index.html` in any browser (no Python, no install, nothing uploaded). It shows the same 6 alerts and digest for the bundled log, and you can paste your own log or change thresholds. It's a JavaScript *port* of the detection rules, escalation and digest, for demo purposes; the Python script is the real tool. GeoIP, the passwd/authorized_keys checks and delivery aren't in the demo. After the CRITICAL alert, the walkthrough plays a **simulated responder** (`sshsentry --respond`): it asks before each step (lock the account, block the IP, rotate the password, replace keys), runs read-only checks and ends with a verdict. Today sshsentry only detects and alerts. The responder is a planned feature, shown only as a simulation in the demo; it is **not yet in the Python tool** and is not included in this release. In the demo nothing runs on any real server. See the Disclaimer below before using --respond. It also has a **savings calculator** that puts admin time saved first and a clearly labeled breach-risk *estimate* second, with every assumption and source listed. Screenshots: `demo/screenshot.png`, `demo/responder.png` and `demo/calculator.png`. To check the demo against the Python tool and the published worked examples, run `python3 demo/verify_demo.py`, `verify_calculator.py`, `verify_walkthrough.py`, `verify_responder.py` and `verify_disclaimer.py` (they need google-chrome), or `python3 tests/run_all.py --demo`.

**Live demo:** <https://sshsentry.com>. The repo publishes `demo/` with a GitHub Actions workflow (`.github/workflows/pages.yml`); see `GITHUB_SETUP.md` for the Pages, custom-domain and DNS steps. It's one static file with no external scripts, so any static host works too.

## What it alerts on

| Rule | Default | Severity |
|---|---|---|
| Brute force | 5+ failed logins (incl. invalid usernames) from one IP in 10 min | MEDIUM |
| Login after failures | Successful login from an IP with 5+ failures in the last 60 min | HIGH |
| Escalation (alerting on) | Successful login from an IP already alerted for brute force (once per alert) | CRITICAL |
| New country | Successful login from a country never seen for that user (needs GeoLite2) | HIGH |
| New IP | Successful login from an IP never seen for that user | LOW |
| New user | A new account in `/etc/passwd` | HIGH |
| New SSH key | A new line in any watched `authorized_keys` file | HIGH |

All thresholds live in `sshsentry.yaml`. Repeat alerts are suppressed for `cooldown_minutes` (default 60).

**First run is quiet:** existing users and keys become the baseline, and with `learn_existing_log: true` the existing auth log is read silently to learn which IPs each user normally uses. Use `--approve IP` to whitelist an address.

**Brute-force threshold:** `rules.brute_force.failures` within `rules.brute_force.window_minutes` (default **5 failures from one IP within a sliding 10 minutes**). It's the same single threshold for stdout and every alert destination. Learn mode (below) can suggest a value; it never changes it on its own.

## Install

```bash
sudo mkdir -p /opt/sshsentry /etc/sshsentry /var/lib/sshsentry
sudo cp sshsentry.py /opt/sshsentry/
sudo cp sshsentry.yaml /etc/sshsentry/sshsentry.yaml
sudo pip install pyyaml          # or: sudo apt install python3-yaml / sudo dnf install python3-pyyaml
```

Python 3.9+ is required. On Debian/Ubuntu with "externally managed" Python, prefer the distro package `python3-yaml` (and `python3-geoip2`) or a venv.

### Optional: country detection

1. Create a free MaxMind account: <https://www.maxmind.com/en/geolite2/signup>
2. Download **GeoLite2-Country** (`.mmdb`), e.g. with `geoipupdate`, to `/usr/share/GeoIP/GeoLite2-Country.mmdb` (or set `geoip.database`).
3. `sudo pip install geoip2`

If either the library or the database is missing, sshsentry prints a one-line note and simply skips country checks.

## Run

```bash
sudo python3 /opt/sshsentry/sshsentry.py                 # tail-follow /var/log/auth.log or /var/log/secure
sudo python3 /opt/sshsentry/sshsentry.py --once          # process new lines since last run, then exit
sudo python3 /opt/sshsentry/sshsentry.py --approve 198.51.100.23
sudo python3 /opt/sshsentry/sshsentry.py --show-shared   # list everything this install has shared
sudo python3 /opt/sshsentry/sshsentry.py --forget-me     # delete sharing history (+ remote request)
sudo python3 /opt/sshsentry/sshsentry.py --test-alerts   # send a sample alert to each enabled destination
sudo python3 /opt/sshsentry/sshsentry.py --digests       # last 7 daily digests (the "main screen")
sudo python3 /opt/sshsentry/sshsentry.py --digest 2026-10-17   # one day in full
sudo python3 /opt/sshsentry/sshsentry.py --export-digests 2026-10-01 2026-10-31 -o oct.zip
sudo python3 /opt/sshsentry/sshsentry.py --digest-now    # preview the last 24 h now (sent if digest.send)
sudo python3 /opt/sshsentry/sshsentry.py --suggest-threshold   # learn-mode threshold suggestion
sudo python3 /opt/sshsentry/sshsentry.py --accept-threshold    # write the suggestion into the config
sudo python3 /opt/sshsentry/sshsentry.py --verify-chain        # check the local digest hash chain
python3 sshsentry.py --verify-export oct.zip [--expected-head HASH]   # check an export (no config needed)
python3 sshsentry.py -c ./sshsentry.yaml --log /path/to/auth.log --db /tmp/state.db   # overrides
```

**`--format json`** (default `text`) gives structured output for `--digests`, `--digest`, `--digest-now`, `--suggest-threshold`, `--show-shared`, `--export-digests`, `--verify-chain`, `--verify-export` and `--replay`. Every document has a `"schema"` field (for example `sshsentry.digests/1`, `sshsentry.digest/1`, `sshsentry.replay/1`, `sshsentry.threshold_suggestion/1`, `sshsentry.shared/1`, `sshsentry.export/1`, `sshsentry.verify/1`). The number goes up only when a field is removed or changes meaning; new fields can be added without a bump. Timestamps are UTC ISO-8601.

Run as root so it can read the auth log and every user's `authorized_keys`. Log rotation is handled automatically. Lines from both `sshd` and newer `sshd-session` processes are parsed, in classic syslog or ISO-8601 timestamp format.

Systems logging only to journald (no auth.log/secure): install rsyslog, or export with `journalctl -u ssh -o short > file` and use `--replay`.

## Alerting: email, Slack, webhook (off by default)

Every alert always goes to stdout (journald under systemd). To also send alerts elsewhere, set `alerting.enabled: true` and enable one or more destinations. Each destination has its own `enabled` flag and an optional `min_severity` (`LOW` < `MEDIUM` < `HIGH` < `CRITICAL`).

```yaml
alerting:
  enabled: true
  timeout: 5                      # seconds per send
  email:   {enabled: true,  min_severity: HIGH}     # SMTP settings: the `email:` block
  slack:   {enabled: true,  min_severity: MEDIUM, webhook_url_env: SSHSENTRY_SLACK_WEBHOOK}
  webhook: {enabled: false, min_severity: LOW, url: "https://example.org/hook",
            headers: {Authorization: "Bearer change-me"}}
```

**What gets sent:**
- **Brute force (MEDIUM):** one short message per IP per `cooldown_minutes`, for example: `Brute force from 203.0.113.45: 5 failed SSH logins in 30 sec; users tried: admin, oracle, root, test; no successful login yet.`
- **Escalation (CRITICAL):** if an IP that was already alerted for brute force later logs in successfully, sshsentry sends one more alert to all destinations naming the user, the method, and the failure count. It replaces the usual "login after failures" alert for that login. It fires once per brute-force alert, and that state lives in SQLite, so it also works across `--once` runs. For example: `ESCALATION: successful login from 192.0.2.77 after brute force. User 'deploy' logged in via password after 6 failed attempts from that IP ...`
- All other alerts (new IP or country, new user, new key, and so on) are sent as they appear on stdout, filtered by `min_severity`.

**Error handling:** destinations are checked at startup. A bad URL (anything other than `https://`, with `http://` allowed only for localhost), missing SMTP settings, or a username without a password gets a warning and disables *only that destination*. Send failures (timeouts, HTTP errors, SMTP errors) are logged to stderr and never stop monitoring. Webhook URLs are treated as secrets: logs show only the host.

**Testing:** `--replay` never sends anything. `sshsentry.py --test-alerts` sends one sample LOW alert to each enabled destination, ignoring `min_severity`, prints the result for each, and exits 1 if any fail.

### Email

The SMTP settings live in the `email:` block. For backward compatibility, an old config with `email.enabled: true` still sends email by itself. sshsentry uses `smtplib` with STARTTLS (port 587). Keep the password out of the YAML by putting it in the environment variable named by `email.password_env` (default `SSHSENTRY_SMTP_PASSWORD`):

```bash
sudo install -m 600 /dev/null /etc/sshsentry/env
echo 'SSHSENTRY_SMTP_PASSWORD=your-app-password' | sudo tee /etc/sshsentry/env >/dev/null
```

> **Tip:** Right after setup, add your sshsentry sender address (the `from` address in `sshsentry.yaml`) to your email contacts or safe-senders list so alerts don't land in spam or junk. Then run `--test-alerts` to confirm one arrives in your inbox.

### Slack setup

1. Go to <https://api.slack.com/apps>, click **Create New App** → **From scratch**, name it (for example "sshsentry"), and pick your workspace.
2. Under **Incoming Webhooks**, switch **Activate Incoming Webhooks** on, click **Add New Webhook to Workspace**, and choose the channel.
3. Copy the webhook URL (`https://hooks.slack.com/services/...`). It's a secret, so put it in the environment file rather than the YAML:
   `echo 'SSHSENTRY_SLACK_WEBHOOK=https://hooks.slack.com/services/...' | sudo tee -a /etc/sshsentry/env`
4. Set `alerting.enabled: true` and `alerting.slack.enabled: true`, restart, and run `--test-alerts`.

Slack receives `{"text": "[sshsentry] MEDIUM: Brute force from ..."}`. Characters Slack treats as markup (`<`, `>`, `&`) are escaped, so an attacker-chosen username such as `<!channel>` can't ping your channel.

### Generic webhook

sshsentry sends an HTTPS `POST` with `Content-Type: application/json` and any `headers` you configure. The URL can come from `$SSHSENTRY_WEBHOOK_URL` (`url_env`). Example payload:

```json
{"severity": "MEDIUM", "rule": "brute_force", "ip": "203.0.113.45", "usernames": ["admin", "oracle", "root", "test"],
 "success": false, "timestamp": "2026-10-17T06:10:31Z",
 "message": "Brute force from 203.0.113.45: 5 failed SSH logins in 30 sec; users tried: admin, oracle, root, test; no successful login yet."}
```

`ip` is `null` and `success` is `null` for alerts with no source IP (new user or key). `timestamp` is the event time in UTC. Note that alerts sent to *your own* destinations can include usernames and IPs; that's different from opt-in sharing (below), which never sends usernames.

## Daily digest (off by default)

```yaml
digest: {enabled: true, time: "08:00", send: true, destination: email, send_when_quiet: true}
```

**Recording (always, once enabled):** every day at `time` (server local time), sshsentry summarizes the previous 24 hours and stores the result in SQLite (`daily_digests`: date, structured stats as JSON, rendered text, delivery status, destination, and error). With `save_text: true` (the default) it also writes a plain-text copy to `<text_dir>/YYYY-MM-DD.txt` (default: a `digests/` folder next to the state DB, i.e. `/var/lib/sshsentry/digests/`). If the machine was off, the missed days (up to 7) are generated on the next run, and only the newest is sent.

**Delivery (`send`, optional):** the digest goes to one destination (`email`, `slack`, or `webhook`), reusing that destination's settings from `alerting`; neither its own `enabled` flag nor `alerting.enabled` is needed. With `send: false`, digests are still generated and stored. Turning `send` back on delivers new days only, with no backfill; use `--resend DATE` to send an old day. Quiet days send `No incidents today.` unless `send_when_quiet: false`. A failed send is logged to stderr, stored with its error, not retried, and never stops monitoring. Webhook digests use the alert JSON shape with `"rule": "digest"`.

**Content:** one short screen, no raw log lines. It shows failed logins and distinct IPs, the most active IP with its attempt count and usernames tried, and successful logins, flagging any that came after failures. It also lists new IPs and the learn-mode suggestion if there is one. The hostname is not included unless you set `host_label`. Sample (from the bundled log):

```
sshsentry daily digest, 2026-10-17
Period: Fri Oct 16 08:00 to Sat Oct 17 08:00 (server time)

Failed logins: 12 from 2 IP address(es).
Most active: 203.0.113.45, 6 attempts (usernames tried: admin, oracle, root, test).
Successful logins: 4
  - chris from 198.51.100.23 (2x) [new IP]
  - deploy from 192.0.2.77 [new IP]  << after 6 failed attempts from that IP. Check this.
  - chris from 100.64.12.9 [new IP]
New IPs seen: 3 (198.51.100.23, 192.0.2.77, 100.64.12.9).

Integrity chain: 9c41e07ab2d3 (sha256 9c41e07ab2d3…)
```

**The "main screen":** there's no GUI. `--digests [N]` lists the last N days (default 7):

```
DATE        FAILED   IPS  TOP OFFENDER              LOGINS  NEW IPS  CHAIN         DELIVERED
2026-10-17      12     2  203.0.113.45 (6)              4!        3  9c41e07ab2d3  yes
2026-10-16       0     0  -                              0        0  51d0a8f3c6e2  no: not sent (digest.send: false)
(! = includes a successful login after failed attempts)
```

`--digest YYYY-MM-DD` shows one day in full, with its delivery status. `--digest-now` previews the last 24 hours immediately and sends it if `send` is on; it isn't stored and doesn't affect the schedule. `--replay FILE --digest-now` only prints a digest for that file. `--forget-me` never deletes digests; it only removes shared-report history.

**Scheduling:** in follow mode the time is checked about every `file_check_seconds` (default 60). With `--once` from a systemd timer or cron, the digest is generated on the first run at or after `time`. Each date is recorded once, so digests are never duplicated. On the day you enable digests, the first one comes at the *next* `time`.

### Exporting digests (for records or an auditor)

```bash
sshsentry.py --export-digests 2026-10-01 2026-10-31 -o sshsentry-oct.zip [--host-label web-prod]
sha256sum -c sshsentry-oct.zip.sha256
```

This writes a zip containing, for each stored day, both its text (`digests/YYYY-MM-DD.txt`, ending with the chain line) **and** its JSON record (`records/YYYY-MM-DD.json`: date, period, stats, text, `prev_hash`, `chain_hash`). It also contains a `manifest.json` (schema `sshsentry.export_manifest/2`) with per-day SHA-256 of both files, each day's `prev_hash` and `chain_hash`, the final `chain_head`, delivery status, generation time, the sshsentry version, and a host label only if you pass `--host-label`. Dates in the range with no digest are listed in `MISSING-DAYS.txt`. It prints the path and the SHA-256 of the whole zip, and writes `PATH.sha256` in `sha256sum` format. Bad dates or START after END exit with code 2. A range with no digests prints a message and exits 1.

**What the hash does and doesn't prove:** it shows the zip hasn't changed *since it was exported*. It does **not** prove the digests are accurate, or that the database or log files weren't altered *before* export, by someone with root on the server for example. To make the hash useful, send it to the auditor separately from the zip (a different channel) or store it somewhere the server can't write to at export time.

### Hash chain and verification

Each stored digest gets `prev_hash` and `chain_hash = sha256(prev_hash + canonical digest)`. The canonical digest is the compact, sorted-key JSON of `date`, `period_start`, `period_end`, `stats` and `text` (the delivery status is excluded, so `--resend` doesn't change the chain). The first day's `prev_hash` is the genesis value `sha256("sshsentry-genesis-v1")`. That is a **fixed public constant**, not a per-install secret, so anyone can recompute a chain from an export with no access to the server. A secret salt wouldn't add tamper protection, because whoever can edit the database can also read the salt. Upgrading from an older version adds the columns and backfills the chain for existing digests once (a note is printed). The chain covers those days from then on; it can't vouch for anything changed before the upgrade.

Every delivered digest and every text copy ends with a line like `Integrity chain: 3f9a0c1d2b4e (sha256 3f9a0c1d…full 64 hex…)`. Turn it off for deliveries with `digest.include_chain_hash: false`; text copies and exports always keep it.

```bash
sshsentry.py --verify-chain                            # recompute the local DB chain (+ text copies)
sshsentry.py --verify-export oct.zip                   # sidecar, every file vs manifest, chain, head
sshsentry.py --verify-export oct.zip --expected-head 3f9a0c1d2b4e   # hash from an emailed digest
```

`--verify-export` checks the `.sha256` sidecar if one exists next to the zip. It then checks every file against the manifest and recomputes the chain day by day, so a removed, reordered or edited day is caught. It also checks the head, and it checks `--expected-head` (the full hash or at least 12 hex characters). If that hash belongs to an earlier day rather than the head, the check passes and says which day. Each check prints a `PASS` or `FAIL` line, a failure names the first day that broke, and any failure exits with code 1.

**Honest limits:** the chain is **tamper-evident, not tamper-proof**. Someone with root on the server can rewrite every digest *and* recompute the whole chain, and the result will verify on its own. What catches that is a chain hash that **already left the box**, such as the line in yesterday's emailed or Slack digest, an auditor's copy of an earlier export's head, or a hash you wrote down. If the head (or that day's hash) in the export doesn't match, the history was rewritten. So the protection is only as good as the copies stored off the server. Nothing proves the digests were accurate when they were created. Signing digests with a key kept off the server is possible future work; it's not implemented.

## Learn mode: threshold suggestion (off by default)

```yaml
learn_mode: {enabled: true, days: 3, percentile: 99, margin: 2, min_threshold: 3, max_threshold: 50}
```

For `days` after you enable it:
- alerts still print to stdout, prefixed `[learning: not sent]`, but nothing is sent to destinations or shared;
- sshsentry records how many failed logins each IP makes in each brute-force window (SQLite table `learn_windows`).

When the period ends, it prints a suggestion once, and alerting resumes with your **manual** `rules.brute_force.failures`. The suggestion is never applied automatically. Run `--suggest-threshold` anytime to see the current suggestion:

```
Threshold suggestion (learn mode; brute-force window = 10 min):
  data: 12 failed logins from 2 IP(s) across 2 IP-window(s)
  failures per IP per window: p50=6 p95=6 p99=6 max=6
  suggested rules.brute_force.failures: 8  (p99=6 + margin 2; floor 3, cap 50)
  current manual threshold: 5  (unchanged until you run --accept-threshold)
```

The suggestion is the chosen percentile of per-IP-per-window counts plus `margin`, clamped to `[min_threshold, max_threshold]`. With no data, it says so and suggests nothing. `--accept-threshold` rewrites only the `failures:` line under `rules: → brute_force:` in your config, keeping comments, and saves a `.bak` copy. If it can't edit safely (for example with a flow-style `{...}` mapping), it prints the exact YAML to paste instead. Restart afterwards.

**Caveat:** on an internet-facing server, the recorded failures are mostly real attackers, so a percentile-based number tends to be *higher* than 5. A higher threshold means fewer, later alerts. Treat the suggestion as information, not a target. `--replay FILE` with learn mode enabled prints a suggestion from that file, which is handy for experimenting. The old `learning.days` quiet period is deprecated and now maps onto learn mode.

## Opt-in threat sharing (off by default)

sshsentry can optionally report **attacking IPs** to a community blocklist endpoint. It is **off by default**; with `sharing.enabled: false` sshsentry never makes a network request for sharing, and behaves exactly as if the feature didn't exist.

**Enable:** in `sshsentry.yaml` set

```yaml
sharing:
  enabled: true
  endpoint: "https://example.org/api/report"   # must be https:// (http:// only for localhost testing)
  timeout: 5                                   # seconds
```

then restart (`sudo systemctl restart sshsentry`). **Disable:** set `enabled: false` and restart; nothing more is sent.

**What is shared:** only the `brute_force` and `login_after_failures` alerts. Never shared: new-IP/new-country logins (those are usually your own users), new-user and new-SSH-key alerts (no attacker IP), alerts for IPs you approved with `--approve`, private/local attacker addresses (10/8, 172.16/12, 192.168/16, 100.64/10, loopback, link-local, IPv6 ULA), and anything during `--replay`/`--dry-run`. A report is only sent when the alert itself fires, so the alert cool-down also limits reports.

**Exact payload** (one HTTPS `POST`, `Content-Type: application/json`, sent with Python's `urllib`):

```json
{"ip": "203.0.113.45", "rule": "brute_force", "timestamp": "2026-10-17T06:10:00Z", "sshsentry_version": "0.2.0", "install_id": "9e155cb8-6987-4d49-8a8f-ae0b6458db13"}
```

- `timestamp`: the attack time from the log, in UTC, rounded **down** to the minute.
- `install_id`: a random UUID generated on your machine the first time something is shared and stored in the local SQLite DB. It isn't derived from anything about you or your server.
- **Never sent:** usernames (including ones attackers tried), log lines, hostname, your server's IP, keys, or config. (Requests carry the header `User-Agent: sshsentry/0.2.0`. As with any HTTPS request, the endpoint can see the public IP your server connects from.)

Non-`https://` endpoints are refused at startup (sharing is disabled with a warning; monitoring continues). If a report fails (timeout, connection error, HTTP error), the failure is recorded locally and monitoring continues; failed reports are not retried.

**`--show-shared`** lists every report this install has recorded (sent or failed): attacker IP, rule, event minute (UTC), when it was sent (local time), and the status. If there are none it prints `Nothing has been shared yet`.

**`--forget-me`** deletes all shared-report records from the local DB and prints how many were deleted. It also discards the install ID, so any future reports use a new random one. If `sharing.endpoint` is set (even with sharing now disabled), it then makes a **best-effort** deletion request to the same endpoint:

```json
{"request": "delete", "install_id": "9e155cb8-6987-4d49-8a8f-ae0b6458db13", "sshsentry_version": "0.2.0"}
```

Local deletion always happens first and doesn't depend on the server. The old install ID is printed so you can ask for deletion by email if the request fails. Use `--forget-me --local-only` to skip the remote request. `--forget-me` doesn't turn sharing off; set `enabled: false` for that.

## systemd service

`/etc/systemd/system/sshsentry.service`:

```ini
[Unit]
Description=sshsentry SSH intrusion detection
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/sshsentry/sshsentry.py -c /etc/sshsentry/sshsentry.yaml
EnvironmentFile=-/etc/sshsentry/env
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now sshsentry
journalctl -u sshsentry -f          # alerts appear here (stdout)
```

Prefer a timer? Use `ExecStart=... --once` with `Type=oneshot` and a `sshsentry.timer` with `OnCalendar=minutely`; the saved log offset means no line is processed twice.

## Testing (dry run)

**Automated test suite:** `python3 tests/run_all.py` runs all the end-to-end tests (it needs PyYAML; add `--demo` to also check the demo page). See [`tests/README.md`](tests/README.md).

`--replay FILE` (alias `--dry-run FILE`) processes a log from the start, prints alerts, and never sends email. Use a throwaway state DB so your real baseline is untouched:

```bash
python3 sshsentry.py -c sshsentry.yaml --db /tmp/sshsentry-test.db --replay sample-auth.log
```

Expected: two brute-force alerts, one login-after-failures alert, and new-IP alerts. Replay never sends email, Slack/webhook alerts, or sharing reports.

**Test-only clock:** `SSHSENTRY_TEST_NOW=<epoch seconds>` makes digest scheduling act as if it were that time, so the test suite can simulate several days in a few seconds. It affects only digest scheduling (not log timestamps or alerts). Don't set it on a real server, because it can generate digests for the wrong dates. (Earlier builds called it `SSHSENTRY_NOW`; that name is no longer read.)

To test sharing without a real server, run a local endpoint that prints what it receives, and use `--once` (not `--replay`) on a copy of the sample log:

```bash
python3 -c '
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        print(self.rfile.read(int(self.headers["Content-Length"])).decode(), flush=True)
        self.send_response(200); self.end_headers()
HTTPServer(("127.0.0.1", 8765), H).serve_forever()' &
T=$(mktemp -d); : > $T/auth.log
printf "log_file: $T/auth.log\nlearning: {learn_existing_log: false}\nsharing: {enabled: true, endpoint: \"http://localhost:8765/report\"}\n" > $T/s.yaml
python3 sshsentry.py -c $T/s.yaml --db $T/s.db --once            # start at end of (empty) log
cat sample-auth.log >> $T/auth.log
python3 sshsentry.py -c $T/s.yaml --db $T/s.db --once            # alerts fire; 3 payloads printed
python3 sshsentry.py -c $T/s.yaml --db $T/s.db --show-shared
python3 sshsentry.py -c $T/s.yaml --db $T/s.db --forget-me
kill %1                                                         # stop the test endpoint
```

To test the user/key rules, point the config at temp files, run once to baseline, change them, and run again:

```bash
T=$(mktemp -d); mkdir -p $T/home/alice/.ssh
cp /etc/passwd $T/passwd; echo 'ssh-ed25519 AAAAexample alice@laptop' > $T/home/alice/.ssh/authorized_keys
cat > $T/test.yaml <<EOF2
rules:
  new_user: {passwd_file: $T/passwd}
  new_ssh_key: {paths: ["$T/home/*/.ssh/authorized_keys"]}
EOF2
: > $T/empty.log
python3 sshsentry.py -c $T/test.yaml --db $T/s.db --replay $T/empty.log      # baseline, no alerts
echo 'backdoor:x:0:0::/tmp:/bin/sh' >> $T/passwd
echo 'ssh-rsa AAAAexample evil@attacker' >> $T/home/alice/.ssh/authorized_keys
python3 sshsentry.py -c $T/test.yaml --db $T/s.db --replay $T/empty.log      # 2 HIGH alerts
```

## Community

Discussions happen on GitHub Discussions: <https://github.com/sshsentry/sshsentry/discussions>
- **Configs:** share your thresholds and learn-mode suggestions (form: `.github/DISCUSSION_TEMPLATE/share-config.yml`).
- **Attack patterns:** describe what you saw and what helped (form: `.github/DISCUSSION_TEMPLATE/attack-pattern.yml`).

**Privacy:** before you post, remove your server IPs, hostnames, usernames, email addresses, webhook URLs, passwords, and API tokens. Only share attacker IPs that are public and that you're comfortable publishing.

## Contact

Email: [sshsentry@gmail.com](mailto:sshsentry@gmail.com). Report security issues privately to sshsentry@gmail.com rather than in a public issue or Discussion.

## Limits

Detection only, SSH-focused. It won't see attacks that leave no login/account trace (e.g. memory-leak bugs, silent zero-days, kernel rootkits that tamper with logs). Ship logs off-box if tampering is a concern. See `sshsentry-design-v2.md`.

## Disclaimer

sshsentry helps you notice and respond to suspicious logins. It can't guarantee your server is secure or stop every break-in.

The responder runs real, destructive commands on your server: it locks accounts, blocks IPs, and rotates passwords and keys. You're responsible for every step you approve, so read each one before you say yes. When it says no unexplained changes were found, that doesn't prove your server is clean.

If an incident involves customer data, legal duties, or anything you can't explain, get a professional. If you have cyber insurance, call your insurer's hotline before you hire anyone.

sshsentry is provided as-is under the MIT license, with no warranty of any kind.

## License

MIT
