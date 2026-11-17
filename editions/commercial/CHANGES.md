# SSH Sentry Commercial Edition: changes from the base sshsentry.py 0.2.0 (experimental, not released)

> This file is the change log of the internal experimental build that was developed as `sshsentry2` (exp1, then exp2) and merged into this repo as the Commercial Edition on 2026-11-17. In this repo the program is `sshsentry_commercial.py` (`VERSION = "0.2.0+commercial.exp2"`), its new tests are `tests/test_commercial.py` (was `test_sshsentry2.py`) and `tests/test_commercial_exp2.py` (was `test_exp2.py`), and the example units are `systemd/sshsentry-commercial*.{service,timer}`. Historical names below are kept as they were written. Raw diffs, logs and captures referenced below are not published; sanitized results are in `results/`.

exp2 notes are at the end of this file.

`sshsentry2.py` (now `sshsentry_commercial.py`) is a copy of the base `sshsentry.py` 0.2.0 (md5 78b914af…, unchanged) with the edits below.
Diff: **+418 / -32 lines** (`live-test/captures/sshsentry2.diff`). It only detects. It never blocks anything.

## Module level
- Docstring updated. `VERSION = "0.2.0+sshsentry2.exp1"`. Added imports: `signal`, `socket`.
- `DEFAULTS`: new `rules.distributed_spray`, `rules.unusual_hours`, and new top-level `tamper`, `heartbeat` (off), `retry`, `downtime_alert`.
- `SCHEMA`: new tables `pending_alerts` (retry queue) and `login_hours` (per-user hour histogram). New meta keys: `log_dev`, `run_marker`, `clean_shutdown`, `heartbeat_last`.
- New helpers:
  - `sd_notify(msg)`: systemd notify protocol over `$NOTIFY_SOCKET`. Supports abstract sockets and needs no extra dependencies.
  - `hour_near(h, hours, tol)`: hour tolerance check that wraps at midnight.
  - `pid_alive(pid)`.

## Agent
- `dispatch()`: a failed send (not `force`/`--test-alerts`) is queued with `queue_alert()`. A successful send makes that destination's queued items due immediately.
- **New** `queue_alert()` and `retry_pending()`. Retries use exponential backoff (`base_seconds` doubling, capped at `max_backoff_seconds`). Items older than `max_age_hours` are dropped. Retries are marked `delayed: true, queued_at, attempts`. Each outcome is logged to stderr ("queued…", "retry N … next try in", "delivered queued…", "gave up…").
- **New** `heartbeat_url()` and `maybe_heartbeat()`. The ping is `{"type":"heartbeat","status":"alive",...}`, sent every `interval_seconds` to `heartbeat.url`/`url_env` (or the webhook if `use_webhook`). A failed ping is logged and never queued.
- **New** `mark_running()`, `touch_marker()` and `mark_clean()`. The run marker in the meta table holds the pid and last-alive time, refreshed every 5 s. If a marker is left over from a dead pid, the previous stop was unclean.
- `on_failure()` now calls **new** `check_spray()`:
  - HIGH `distributed_spray`, key `window`: at least `failures` failures from at least `distinct_ips` IPs in the sliding window.
  - Per-username variant, key `user:<name>`: one username failing from at least `per_user_ips` IPs.
  - Only IPs still under the brute_force limit are counted, because a heavier IP is already covered by `brute_force`. This fix was added after the first live run.
  - The normal cooldown applies.
- `on_success()` now calls **new** `check_unusual_hours()`. It raises MEDIUM `unusual_hours` (key `user@YYYY-MM-DD HH`) when the user has at least `min_samples` recorded logins and none within ±`tolerance_hours` of this hour, using server local time. It records the hour every time, including during silent learning.
- `digest_stats()`: new `spray` stat. It counts IPs below the brute-force limit, compared against the spray thresholds. `digest_render()` adds the "Possible distributed spray: …" line.

## Log following
- **New class `LogFollower`** (`tamper`, `rotated_to`, `read`, `save`, `open_start`, `poll`):
  - Startup (`open_start`) handles three cases:
    - Same inode and size below the saved offset: HIGH truncated while not running.
    - Different inode and the old inode found as a rotated sibling (`rotated_patterns`): the rest of the rotated file is read from the saved offset, then a rotation notice is raised.
    - Different inode and no sibling found: HIGH replaced while not running.
  - Live (`poll`) handles these cases:
    - Path missing: keep draining the old handle. After `missing_seconds`, raise HIGH "missing" (once per outage).
    - dev/inode changed: drain the old handle to EOF first. If the old inode is now a sibling `*.1`/`-*`/`.*`, raise the rotation notice. If its link count is 0, raise HIGH "deleted and a new file created". Otherwise raise HIGH "replaced".
    - Size below the read position: HIGH "truncated in place".
  - Tamper alerts use rule `log_tamper` with unique keys, so they have no cooldown. The rotation notice is controlled by `tamper.rotation_notice`: `log` (default, stderr note) / `alert` (rule `log_rotated` at `rotation_severity`, LOW) / `off`.
  - **Why `log` is the default:** the original follow-mode rotation test expects the next stdout line after a rotation to be the alert.
- `watch()` rewritten on top of `LogFollower`:
  - A missing log at startup is waited out with a tamper alert, or reported once in `--once` mode.
  - Sends `READY=1`. Sends `WATCHDOG=1` at half of `$WATCHDOG_USEC`.
  - Refreshes the run marker. Calls `retry_pending()` and `maybe_heartbeat()` every idle tick.
  - After the first catch-up after an unclean stop, raises MEDIUM `downtime` ("sshsentry was not running from X to Y …; caught up N log line(s)").
  - `--once` exits clean.
- `main()`: SIGTERM is turned into a clean shutdown (`STOPPING=1` and `mark_clean()`), so `systemctl stop` doesn't cause a downtime alert.

## Other files
- `sshsentry.yaml`: documented sections for all of the above. The heartbeat is off. Retry only re-sends to destinations you already enabled.
- `systemd/sshsentry2.service`: example unit (Type=notify, Restart=always, WatchdogSec=60, hardening). It is not installed. `sshsentry2-heartbeat-check.{service,timer}` is an optional local "ensure running" helper.
- `tests/`: copied. Only `helpers.py` changed (SCRIPT path to `sshsentry2.py`, `import sshsentry2 as S`). New `tests/test_sshsentry2.py` has 33 tests.

---

## exp2 (2026-11-17): connection_flood rule + one alert per spray

`VERSION = "0.2.0+sshsentry2.exp2"`. Diff vs exp1: **+180 / -11 lines** in `sshsentry2.py` (`exp2-results/sshsentry2-exp1-to-exp2.diff`). exp1 backup: kept locally. Still experimental. Merged into the repo as the Commercial Edition on 2026-11-17; not released to PyPI. Detection only.

### New rule: `connection_flood` (HIGH, enabled by default in this build)
- **What it catches:** one source IP opening and dropping many SSH connections with no login attempt (a device or script in a reconnect loop, or a scanner). The login rules never see this, because no username or password is ever sent. Ported from the standalone demo (not in this repo).
- **Lines counted** (pre-auth): `Connection from IP port P` (LogLevel VERBOSE), `Connection closed|reset by IP port P [preauth]` (also without `[preauth]`), `Did not receive identification string from IP`, `Disconnected from IP port P [preauth]`, `Received disconnect from IP port P:... [preauth]`, `Timeout before authentication for IP`, `Unable to negotiate with IP` / `banner exchange` / `ssh_dispatch_run_fatal` / `kex_exchange_identification ... from IP`, and MaxStartups `drop connection #N from [IP]:P`.
- **No double counting:** lines of one connection share a key of (IP, sshd pid, source port), so open + close + "did not receive identification" count once. A reused source port under a new sshd pid counts as a new connection. MaxStartups drop lines come from the listener (shared pid) and sshd never opened those connections, so each drop line is one connection.
- **Login attempts exclude the IP:** any `Failed ...`, `Invalid user`, `Accepted`, `Postponed`, `Connection closed/Disconnected ... by authenticating|invalid user`, or `maximum authentication attempts exceeded` from the IP within the window means it is guessing or logging in. The login rules own it. Lines from a connection that logged in are never counted.
- **Alert:** names the IP (and an inventory label if configured), the count, the time span, the rate, first and last seen (ms), and the connection number from that IP. Example from the demo log: `HIGH: Connection flood. 100 SSH connections from 192.0.2.41 (El Dorado, AR radio-site router (simulated)) in 0.40 sec (~250/sec), and none of them tried to log in ...`. Destinations get a shorter message with `"ip"` set. It goes through the normal alert path: stdout, alert_log, email/Slack/webhook by min_severity, retry queue on failed sends, `--format json`, learn-mode and learn-existing-log silence. It is **never shared** to the community list (not in `SHARED_RULES`).
- **Cooldown:** per source IP, `cooldown_minutes` (default 5), separate from the global cooldown. `alert()` gained an optional `cooldown` (seconds) argument for this.
- **Config** (`rules.connection_flood`): `enabled: true`, `connections: 100`, `window_seconds: 10`, `cooldown_minutes: 5`, `labels: {}` (IP or CIDR -> name, most specific wins, IPv6 OK, bad entries skipped with a note), `ignore: []` (IPs/CIDRs never flagged, e.g. load balancer health checks). Documented in `sshsentry.yaml`.
- **State:** in memory (per-IP sliding window deques). It works the same in `--replay`, `--once` and live follow (`LogFollower`), since all of them go through `handle_line`. Memory is pruned every 5,000 connections: connection keys older than 10 min and IPs idle for 1 h. **Limitation:** a restart starts the windows empty, so a flood split across a restart needs a full window again after the restart. The digest does not report floods.
- `LINE_RE` now captures the sshd pid (named group `pid`). New helpers: `fmt_ms`, `valid_ip`, `net_list`. New Agent methods: `cf_label`, `on_connection_line`, `cf_prune`.

### Alert-spam fix: one distributed spray = one alert
- **Before (exp1, live test Oct 25 scenario A):** one spray gave 5 HIGH alerts, the window alert plus 4 per-username alerts.
- **Now:** with `rules.distributed_spray.merge_user_alerts: true` (default), per-username spray hits raise the spray's single alert (same `window` key and cooldown). Whichever trips first is the only alert. If the window threshold trips, its text adds `Targeted usernames (each from 5+ IPs): oracle (8 failures from 5 IPs), ...`. If a per-username hit trips first, its text adds `Spray so far: N failed SSH logins from M IPs ..., trying user(s): ...`. Either way, later per-username or window hits for the same spray stay quiet for the cooldown.
- A per-username spray on its own (no window hit) still alerts. `merge_user_alerts: false` restores exp1 behaviour.

### Tests
- New `tests/test_exp2.py` with 27 tests:
  - Flood (19): threshold + IP named, under-threshold silent, sliding window, login-attempt exclusion (5 kinds), old login does not exclude, open/close de-dup, close-only logs + port reuse, MaxStartups and other pre-auth lines, authenticated-session close not counted, per-IP cooldown, two sources, labels (exact/CIDR/IPv6/bad), ignore + disable, classic syslog, existing rules unaffected, webhook payload + retry queue + not shared, learning silent, memory pruning.
  - CLI (3): replay text + `--format json`, live follow, sample config = defaults + version.
  - Spray (5): Oct 25 shape = 1 alert (was 5), merge off = 5, targeted usernames listed, per-user-first then window = 1, per-user alert returns after cooldown.
- **Full suite: 194 run, 194 passed, 0 failed** (was 167/167; 167 + 27 new).

### Replays (sanitized outputs in `results/exp2-replays/`)
- **Demo flood log** (simulated, not in this repo, 16,032 lines):
  - 192.0.2.41 (El Dorado, simulated): HIGH at connection #100, 0.40 s after its first connection (03:14:05.396 log time).
  - 192.0.2.87 (Amarillo, simulated): HIGH at connection #100, 0.49 s in (03:14:09.495).
  - One alert each for the whole 20 s flood (5,000 and 4,000 connections counted, including 1,976 MaxStartups drops). This matches the demo exactly.
  - exp1 on the same log: no flood alert (only the admin's LOW new-IP login).
- **Oct 25 scenario** (`oct25-reconstructed-auth.log`): rebuilt from `live-test/captures/attack.log` (the raw sshd log has no timestamps), replayed with the live-test config minus network sends.
  - exp1: spray at 21:29 = 5 HIGH.
  - exp2: 1 HIGH.
  - The 21:35:33 per-username repeats are gone too. Total HIGH lines went from 14 to 7. The remaining window repeats are the 1-minute test cooldown, as noted in RESULTS.md.
  - No connection_flood false positives.
