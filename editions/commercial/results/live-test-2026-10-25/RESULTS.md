# sshsentry2 live rerun: RESULTS

> **Published copy (sanitized).** This test ran against the internal experimental build, then called `sshsentry2` (exp1). It is now the SSH Sentry Commercial Edition (`editions/commercial/sshsentry_commercial.py`). All traffic was on loopback (127.0.0.0/8) with a throwaway sshd and a temporary test user; no real hosts or addresses are involved. Local paths were replaced with `<test-dir>`. Tests at the time: 167 (134 base + 33 new); the current Commercial Edition suite is 194 (adds 27 exp2 tests, see `../exp2-replays/`).


**Date:** 2026-10-25, 21:28 to 21:37 ET (America/Detroit, UTC-4). **Mode:** live follow, using the round-2 harness. That means a throwaway sshd on `127.0.0.1:2222` (round-2 keys), `log_bridge.py`, and the webhook listener on `127.0.0.1:8765`. Source IPs come from 127/8 with `ssh -b`. Everything stayed on loopback.
**Config:** `sshsentry2-live.yaml`, which is the round-2 config plus the new blocks. It uses a 1-minute cooldown, a 15 s heartbeat to `127.0.0.1:8765/heartbeat`, retry base 5 s / cap 20 s, `tamper.missing_seconds: 5` and `rotation_notice: alert`.
**sshd_config** adds `MaxStartups 200:30:400`, `PerSourcePenalties no` and `AllowUsers simvictim3`. This avoids the round-2 MaxStartups drops: 76 of 76 spray lines were logged and 0 were dropped.
**Original `sshsentry.py (base 0.2.0)`:** not modified. md5 `78b914af31d1e437f5d0971d58fe61e3` before and after (`captures/original_md5_after.txt`).

## Before / after

| # | Scenario | Round 2 (sshsentry.py) | sshsentry2 |
|---|----------|------------------------|------------|
| A | Spray: 38 IPs (127.0.0.2-.39), 2 failures each = 76, 21:28:59 to 21:29:33 | MISSED (digest gave a count only) | **CAUGHT.** HIGH `distributed_spray` at 21:29:10 (11 s after start), plus 4 per-username HIGHs. The digest flags the spray. |
| B1 | Stolen creds: clean login from known IP 127.0.0.80 at 21:29 (baseline 09-13 h) | MISSED (silent) | **CAUGHT.** MEDIUM `unusual_hours` and no new_ip. |
| B2 | Clean login from new IP 127.0.0.81 | LOW new_ip | LOW new_ip (unchanged) |
| C1 | Truncate to 0 while following | no tamper alert; detection continued | **HIGH** truncated in place. Detection continued (127.0.0.61 brute force at 21:30:18). |
| C2 | Delete, 8 s gap, recreate | no tamper alert | **HIGH** missing (after 5 s), then **HIGH** deleted and recreated. Detection continued (127.0.0.62). |
| C3 | Rotate (mv to .1, new empty file) | no alert | **LOW** "Log rotated". No HIGH. Detection continued (127.0.0.63). |
| D1 | kill -9, attack while down (127.0.0.64), restart | zero signal; restart caught up | **Heartbeats stopped** (last 21:32:41, kill about 21:32:53, next only after the restart at 21:33:54). Restart gave **MEDIUM downtime** "caught up 5 log line(s)" plus the 127.0.0.64 brute force. |
| D2 | Webhook down during an alert (127.0.0.66), back after about 16 s | alert lost | **Queued and delivered late.** Delivered on attempt 4 (21:34:59 and 21:35:11), `delayed: true`. Queue is empty at the end. |
| D3 | Heartbeat every 15 s | n/a | 24 pings received in total. Regular 15 s cadence. They stopped while the process was killed. Failures while the listener was down were logged to stderr. |
| R1 | Round-1 basic attack (8 failures from 127.0.0.90, then success) | MEDIUM, CRITICAL, LOW | Same MEDIUM, CRITICAL and LOW, with the same texts. **No regression.** See the note on extra spray noise below. |

## Exact alert texts (stdout, `captures/sshsentry2.stdout`)
```
[2026-10-25 21:29:10] HIGH: Distributed password spray. 20 failed SSH logins from 10 different IPs in 6 sec (at most 2 from any one IP, so per-IP brute-force limits miss it), trying user(s): admin, deploy, oracle, simvictim3. Busiest IPs: 127.0.0.5, 127.0.0.11, 127.0.0.3, 127.0.0.10, 127.0.0.7. Consider disabling password logins.
[2026-10-25 21:29:11] HIGH: Distributed password spray on user 'oracle'. 8 failed SSH logins for this username from 5 different IPs in 7 sec. Someone may be targeting this account; make sure it has a strong password or uses keys only.
   (same for 'admin' 21:29:11, 'deploy' 21:29:11, 'simvictim3' 21:29:14)
[2026-10-25 21:29:45] MEDIUM: Unusual-hours login. User 'simvictim3' logged in via password from 127.0.0.80 at 21:29 (server time), an hour with no logins in this user's 12 previous login(s) (usual hours: 09:00, 10:00, 11:00, 12:00, 13:00; tolerance +/-1 h). If this wasn't them, the password or key may be stolen: lock the account and investigate.
[2026-10-25 21:29:48] LOW: New IP login. User 'simvictim3' logged in via password from 127.0.0.81, an address never seen for this user. If expected, approve it with: sshsentry.py --approve 127.0.0.81
[2026-10-25 21:30:03] HIGH: Log tampering? <test-dir>/logs/auth-sim.log was truncated in place: it is now 0 bytes but sshsentry had already read 8966 bytes. Lines may have been removed (or a copytruncate rotation happened). Reading from the start.
[2026-10-25 21:30:18] MEDIUM: Brute force. 5 failed SSH logins from 127.0.0.61 in 13 sec, trying user(s): probeuser. ...
[2026-10-25 21:30:30] HIGH: Log tampering? <test-dir>/logs/auth-sim.log has been missing for 5 sec (since 2026-10-25 21:30:25). sshsentry cannot see SSH activity until it comes back.
[2026-10-25 21:30:33] HIGH: Log tampering? <test-dir>/logs/auth-sim.log was deleted and a new file created in its place (missing for 8 sec). The old contents are gone; check the system journal. Following the new file.
[2026-10-25 21:30:50] MEDIUM: Brute force. 5 failed SSH logins from 127.0.0.62 in 14 sec, ...
[2026-10-25 21:30:57] LOW: Log rotated: <test-dir>/logs/auth-sim.log was renamed to <test-dir>/logs/auth-sim.log.1 and a new file started (0 bytes). Following the new file.
[2026-10-25 21:31:13] MEDIUM: Brute force. 5 failed SSH logins from 127.0.0.63 in 13 sec, ...
[2026-10-25 21:33:12] MEDIUM: Brute force. 5 failed SSH logins from 127.0.0.64 in 15 sec, trying user(s): downuser. ...   (attack while killed; emitted on restart)
[2026-10-25 21:33:54] MEDIUM: sshsentry was not running from 2026-10-25 21:32:51 to 2026-10-25 21:33:54 (it stopped without a clean shutdown: killed, crashed or power loss); caught up 5 log line(s) written in the meantime. Anything during that gap was only detected late.
[2026-10-25 21:34:36] MEDIUM: Brute force. 5 failed SSH logins from 127.0.0.66 in 12 sec, trying user(s): hookdown. ...   (webhook down; queued)
[2026-10-25 21:35:51] MEDIUM: Brute force. 5 failed SSH logins from 127.0.0.90 in 18 sec, trying user(s): admin, oracle, simvictim3, test. ...
[2026-10-25 21:36:00] CRITICAL: ESCALATION: successful login from 127.0.0.90 after brute force. User 'simvictim3' logged in via password after 7 failed attempts from that IP (alerted at 2026-10-25 21:35:51; users tried: admin, oracle, simvictim3, test). Treat this as a likely compromise: ...
[2026-10-25 21:36:00] LOW: New IP login. User 'simvictim3' logged in via password from 127.0.0.90, an address never seen for this user. ...
```
Retry log (stderr):
```
[sshsentry] webhook alert failed: failed (URLError: [Errno 111] Connection refused)
[sshsentry] queued brute_force alert for webhook; will retry with backoff
[sshsentry] retry 2 of queued brute_force alert for webhook failed (...); next try in 10 sec
[sshsentry] retry 3 of queued brute_force alert for webhook failed (...); next try in 20 sec
[sshsentry] delivered queued brute_force alert to webhook (queued 2026-10-25 21:34:36, attempt 4): sent (HTTP 200)
```
Digest (`captures/digest_now.txt`): `Possible distributed spray: 76 failures came from 38 IPs with at most 2 each, below the per-IP brute-force limit.`

## False positives and noise noticed
1. **The spray alert re-fired** at 21:30:11, 21:31:13, 21:32:57, 21:34:24 and 21:35:33. The per-username spray alerts re-fired at 21:35:33 to 21:35:47.
   - **Cause:** the original 76-failure spray was still inside the 10-minute window, and the test cooldown is only 1 minute. Each later probe failure re-triggered it.
   - With the default 60-minute cooldown these repeats would not happen.
2. **First-pass bug, fixed during the run.** The 21:30:11 and 21:31:13 alerts counted the brute-force probe IPs. That made the text say "at most 5 from any one IP, so per-IP limits miss it", which was false.
   - **Fix:** `check_spray` now counts only IPs below the brute_force limit.
   - The sentry was restarted with the fix at 21:33:54. Later spray alerts show "at most 2 from any one of them".
   - The same filter was applied to the digest spray line after teardown and checked against the live DB.
   - Scenario A itself ran on the pre-fix code. Its alert would be identical either way, because no IP went over 2.
3. **Normal brute-force IPs still count toward spray** while they are under the limit (their first 1-4 failures). A single brute force alongside a real spray can therefore tip the window. One test documents this.
4. **One attack, five HIGH alerts** (window plus four usernames) in A. Consider suppressing the per-user alerts while the window alert is active.
5. **Unusual-hours learns right away.** The flagged 21:29 login is added to the histogram, so later 21:xx logins are treated as usual. The rule fires once per hour bucket, then accepts it.

## Known limitations
- **The heartbeat only helps if the receiver alerts on missing pings.** If the host dies, nothing local can report it. The systemd watchdog and Restart=always were not exercised live, because the box has no systemd service manager for this test. `sd_notify` is covered by a unit test with a real AF_UNIX socket.
- **The downtime "from" time can be up to about 5 s early**, because the marker is refreshed every 5 s. Downtime is only detected at the next start.
- **logrotate `copytruncate` shows up as HIGH truncation.** Use create mode, or accept that HIGH.
- **Deletion and rotation are told apart by finding the old inode as a sibling** matching `rotated_patterns`. If it is moved elsewhere, that is reported as HIGH "replaced". Compressed rotation done offline (`.1.gz`) shows as "replaced" on startup.
- **An attacker with root can still edit the log and the state DB.** These checks detect clumsy tampering, not careful tampering.
- **Retries are only attempted while sshsentry2 is running.** Queued items persist in the DB across restarts. Heartbeat failures are not queued.
- **The unusual-hours baseline was seeded** with 12 synthetic past "Accepted" lines (`captures/seed_lines.txt`), read silently via `learn_existing_log`. The time of day could not be varied live, so the tolerance and minimum-sample gate are covered by unit tests only.
- **`root` attempts don't count** under this sshd_config (they are not "Invalid user" lines). This matches round 1.

## Tests
167 run, 167 passed: 134 original plus 33 new (`tests/test_sshsentry2.py`, now `tests/test_commercial.py`).

## Evidence
Raw captures (stdout/stderr, webhook and alert logs, simulated auth logs, the state DB, sshd_config, pid files and helper scripts) are kept privately and are not published. The alert texts above are copied from them. The config used is in `live-test-config.yaml` (local paths replaced with `<test-dir>`).

## Cleanup (21:37 ET)
- Stopped: sshsentry2 (SIGTERM, clean shutdown marker written), the bridge, the listener and sshd.
- Ports 2222 and 8765 are free. Temp user `simvictim3` was removed.
- No commits, pushes or publishing. The website was not touched.
