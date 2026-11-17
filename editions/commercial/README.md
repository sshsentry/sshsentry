# SSH Sentry Commercial Edition (experimental)

**An expanded edition of sshsentry for larger institutions and critical-infrastructure operators.** It keeps everything the free base edition does and adds rules for the attacks and failure modes a single small server rarely worries about but a large estate must: distributed password sprays, logins at unusual hours, log tampering, silent downtime, lost alerts, and pre-authentication reconnect floods.

> **Status: experimental / alpha.** Version `0.2.0+commercial.exp2`. Not released on PyPI, not packaged, no support commitment yet. Detection only: like the base edition, it never blocks anything. Run it alongside your existing controls, not instead of them.

The **base edition** (`sshsentry.py` 0.2.0 at the repo root, `pip install sshsentry`) stays the small-business offering and is unchanged. This edition is a separate program in this folder; installing or testing it does not touch the base.

## Why this tier exists

On 2026-11-13 a router at an FAA air traffic control facility in El Dorado, Arkansas (installed by contractor L3Harris), with a second router in Amarillo, Texas, repeatedly tried to reach a server: roughly 1,000 attempts every 4 to 5 seconds. The root cause is still under investigation by the FAA and L3Harris.

**Be clear about what that event was and was not.** It was a router and network-layer problem, not an SSH attack. SSH Sentry reads SSH logs, so it would **not** have detected or prevented that incident, and nothing here claims otherwise.

The lesson we take from it is a monitoring gap, and the same gap exists in SSH monitoring at every scale: **a source that floods a service with connections but never attempts a login is invisible to tools that only count logins.** The base edition's rules all key on login attempts, so a reconnect loop or scanner that opens and drops thousands of SSH connections produces no alert at all. The Commercial Edition's `connection_flood` rule closes that gap for SSH: it counts pre-authentication connections per source IP and raises a HIGH alert naming the source address. Larger institutions have more devices, more automation and more places for a misbehaving client to hide, which is why this rule lives in the tier aimed at them.

## Feature comparison

| Capability | Base (Small Business, 0.2.0) | Commercial (exp2) |
|---|:---:|:---:|
| Brute force, login after failures, CRITICAL escalation | ✅ | ✅ |
| New IP / new country / new user / new SSH key | ✅ | ✅ |
| Email, Slack, webhook alerts; daily digest + hash chain; learn mode; JSON output | ✅ | ✅ |
| **Distributed password spray** (many IPs, few failures each; per-window and per-username) | — | ✅ HIGH |
| **One alert per spray** (per-username spray hits merged into the window alert; 5 alerts → 1 on the Oct 25 test) | — | ✅ |
| **Unusual-hours login** (per-user login-hour baseline) | — | ✅ MEDIUM |
| **Log tamper / rotation detection** (truncated, deleted, replaced, missing; rotation notice) | — | ✅ HIGH |
| **Downtime detection** (alert on restart after an unclean stop, with lines caught up) | — | ✅ MEDIUM |
| **Heartbeat / dead-man's switch** + systemd watchdog (`Type=notify`) | — | ✅ (heartbeat off by default) |
| **Retry queue** for failed alert sends (backoff, persists across restarts) | — | ✅ |
| **`connection_flood`**: N pre-auth connections from one IP in a window with no login attempt; names the IP and an optional inventory label | — | ✅ HIGH |
| Example systemd units with hardening | — | ✅ |

`connection_flood` defaults: 100 connections in 10 seconds, 5-minute per-IP cooldown, `labels` (IP/CIDR → device name) and `ignore` (e.g. load-balancer health checks). Any IP that attempts a login in the window is left to the login rules. Floods are never shared to the community list. See `CHANGES.md` for exact behavior and limits (for example, the flood window starts empty after a restart, and `LogLevel VERBOSE` in sshd gives the best coverage).

## Run it

Needs Python 3.9+ and PyYAML, same as the base.

```bash
cd editions/commercial
# dry run on the bundled sample: no root needed, nothing is sent
python3 sshsentry_commercial.py -c sshsentry.yaml --db /tmp/sshsentry-commercial-try.db --replay sample-auth.log
# live follow on a server (reads /var/log/auth.log or /var/log/secure; usually needs root)
sudo python3 sshsentry_commercial.py -c /etc/sshsentry/sshsentry.yaml
# add --format json for JSON alerts
```

`sshsentry.yaml` here documents every option, including the Commercial blocks (`rules.distributed_spray`, `rules.unusual_hours`, `rules.connection_flood`, `tamper`, `heartbeat`, `retry`, `downtime_alert`). The default state DB path is the same as the base (`/var/lib/sshsentry/state.db`); if you run both editions on one host, give each its own `state_db`.

Example units: `systemd/sshsentry-commercial.service` (expects the script at `/opt/sshsentry-commercial/`), plus an optional `sshsentry-commercial-heartbeat-check.{service,timer}`.

## Test it

```bash
python3 editions/commercial/tests/run_all.py      # 194 tests: the 134 base tests run against this edition, plus 60 new
python3 tests/run_all.py                          # base edition, 134 tests (unchanged)
```

New tests: `tests/test_commercial.py` (33: spray, unusual hours, tamper, heartbeat, retry, downtime) and `tests/test_commercial_exp2.py` (27: connection_flood and spray merging).

## Results

- `results/live-test-2026-10-25/`: live-attack rerun against a throwaway sshd on loopback (spray, unusual hours, tamper, kill -9 downtime, webhook outage + retry, heartbeat). Sanitized; raw captures and the state DB are not published.
- `results/exp2-replays/`: replays of the Oct 25 spray (5 HIGH alerts before the merge fix, 1 after) and of a **simulated** reconnect flood using documentation-only addresses (192.0.2.41, 192.0.2.87), where each source fired one HIGH alert at its 100th connection, 0.40 s and 0.49 s in.

## Licensing and commercial terms

**Placeholder: terms to be decided.** This code is currently in the same repository under the same **MIT license** as the base edition (see `../../LICENSE`), so as it stands anyone may use, modify and redistribute it under MIT. Commercial licensing, pricing, support and SLAs for this edition have not been defined yet. Contact: sshsentry@gmail.com.
