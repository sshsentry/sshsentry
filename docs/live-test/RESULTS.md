# Live attack test (2026-10-25)

**Date:** 2026-10-25 (America/Detroit, UTC-4)  
**Scope:** a single test machine only (`127.0.0.1:2222`). Detection only — sshsentry does not block.  
**Mode:** Live follow (NOT `--replay`).

## Pass / fail by rule

| Rule | Severity | Result | Notes |
|------|----------|--------|-------|
| `brute_force` | MEDIUM | **PASS** | Fired after 5 failed logins from 127.0.0.1 within ~15s |
| `brute_force_success` (escalation) | CRITICAL | **PASS** | Fired on successful `simvictim` login after prior brute_force alert (requires `alerting.enabled: true`) |
| `login_after_failures` | HIGH | **N/A (by design)** | Superseded by CRITICAL escalation when alerting is on; cool-down also written for `login_after_failures` |
| `new_ip` | LOW | **PASS** | Fired on first recorded login for `simvictim` from 127.0.0.1 |

## Exact alert texts (stdout)

```
[2026-10-25 21:03:14] MEDIUM: Brute force. 5 failed SSH logins from 127.0.0.1 in 15 sec, trying user(s): admin, oracle, root, simvictim, test. Consider fail2ban, a firewall block, or disabling password logins.
[2026-10-25 21:03:46] CRITICAL: ESCALATION: successful login from 127.0.0.1 after brute force. User 'simvictim' logged in via password after 7 failed attempts from that IP (alerted at 2026-10-25 21:03:14; users tried: admin, oracle, root, simvictim, test). Treat this as a likely compromise: lock the account, check ~/.ssh/authorized_keys, review processes.
[2026-10-25 21:03:46] LOW: New IP login. User 'simvictim' logged in via password from 127.0.0.1, an address never seen for this user (first recorded login). If expected, approve it with: sshsentry.py --approve 127.0.0.1
```

## How the attack was generated

1. Throwaway `sshd` on `127.0.0.1:2222` (`PasswordAuthentication yes`, dedicated host keys under `keys/`).
2. Temporary user `simvictim` with a password (removed at teardown).
3. `sshd -E` → raw log; a small log bridge reformatted lines to classic auth.log style (`Oct 25 HH:MM:SS host sshd[0]: …`) into `logs/auth-sim.log`.
4. Local webhook listener on `127.0.0.1:8765`; sshsentry follow with a test config.
5. an attack script via `sshpass` + `ssh` from localhost: failed attempts as `admin`, `root`, `oracle`, `test`, then 4× wrong password for `simvictim`; after OpenSSH per-source penalty cooled, successful login as `simvictim`.

## Timing (America/Detroit)

| Event | Time |
|-------|------|
| Attack start | 2026-10-25T21:02:59-04:00 |
| MEDIUM brute_force alert | 2026-10-25 21:03:14 |
| Attack brute phase done | 2026-10-25T21:03:20-04:00 |
| First success blocked by OpenSSH penalty | ~21:03:20–23 |
| Successful login retry | 2026-10-25T21:03:45-04:00 |
| CRITICAL + LOW alerts | 2026-10-25 21:03:46 |

## Log-format notes

- OpenSSH `-E` lines lack syslog timestamp/hostname; bridge prepends them. Message bodies (`Invalid user …`, `Failed password for …`, `Accepted password for …`) match sshsentry `INVALID_RE` / `FAIL_RE` / `OK_RE` unchanged.
- `Failed password for invalid user X` is intentionally **not** counted by sshsentry (duplicate of the preceding `Invalid user X` line) — bridge also skips emitting those as separate INTERESTING lines when the regex doesn’t match the `invalid user` token layout; counting still correct via `Invalid user`.
- OpenSSH 10.0 “penalty: failed authentication” dropped late spray connections from the same IP briefly; waiting ~20s allowed the success path. Not an sshsentry issue.

## Evidence in this folder

- `sshsentry.stdout`: sshsentry output during the run
- `webhook.jsonl`: JSON bodies received by the local webhook listener
- `auth-sim.log`: the auth log sshsentry followed (hostname replaced with `host`)

This was a manual one-off test that needs root and a throwaway sshd; it is not part of `tests/run_all.py`.
