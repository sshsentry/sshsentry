# sshsentry test suite

These are end-to-end tests of `sshsentry.py`. Each test runs the real script as a subprocess against throwaway sandboxes in a temp directory. They use only local capture servers, so nothing is sent off the machine.

## Setup (once)

```bash
python3 -m venv /tmp/sentvenv          # any path works
/tmp/sentvenv/bin/pip install pyyaml   # the only dependency (geoip2 is optional and not needed)
```

## Run

```bash
/tmp/sentvenv/bin/python tests/run_all.py          # all Python-program tests (~134, ~35 s)
/tmp/sentvenv/bin/python tests/run_all.py -q       # quiet: dots, failures, summary
/tmp/sentvenv/bin/python tests/run_all.py -k digest -k chain   # only matching test ids
/tmp/sentvenv/bin/python tests/run_all.py --list   # list test ids and the count
/tmp/sentvenv/bin/python tests/run_all.py --demo   # also run demo/verify_*.py (needs google-chrome or chromium)
SSHSENTRY_TEST_SCRIPT=/path/to/other/sshsentry.py tests/run_all.py   # test another build
```

The exit code is 0 only if everything passes.

## Files

| File | What it is |
|---|---|
| `run_all.py` | Runner (stdlib `unittest`). It starts the capture servers, discovers `test_*.py` and prints a summary. |
| `helpers.py` | `Sandbox` (per-test temp dir; named configs, each with its own log, DB and digest folder), log-line fixtures (`fail`, `ok`, `burst`, `noon`) and the `Base` test case. |
| `capture_server.py` | Local HTTP capture for webhook, Slack and sharing endpoints. `/fail` returns 500; `/slow` waits 3 s. It also runs standalone: `python3 capture_server.py 8765`. |
| `smtp_capture.py` | Minimal stdlib SMTP server: EHLO, AUTH PLAIN/LOGIN, MAIL, RCPT, DATA. No asyncore or aiosmtpd needed. Test configs set `email.starttls: false`. |
| `golden/replay_default.txt` | Expected stdout of `--replay sample-auth.log` with the shipped `sshsentry.yaml` (6 alerts). |
| `fixtures/sample-auth.log` | Copy of the bundled sample log. |
| `test_core.py` | Rules, cooldown, parsing, replay golden, `--once`/offsets/rotation, follow mode, `--approve`, missing GeoIP, new user/key, email. |
| `test_sharing.py` | Off by default, payload fields, private and approved IPs, https enforcement, failures, `--show-shared`, `--forget-me`. |
| `test_alerting.py` | Slack and webhook payloads, `min_severity`, escalation (once across runs), misconfiguration, down/500/timeout, Slack escaping, `--test-alerts`. |
| `test_learn.py` | Learn-mode suggestion, no data, no sending while learning, `--accept-threshold`, end-of-period announcement. |
| `test_digest.py` | Digest content, scheduling, no duplicates, catch-up (capped at 7), send off/on, `--digests`, `--digest`, `--resend`, quiet days, failures, email digest. |
| `test_export_chain.py` | Export, `sha256sum -c`, manifest, missing days, bad dates, `--verify-export` (sidecar, edits, rewritten chain vs `--expected-head`), `--verify-chain`, old-schema upgrade backfill. |
| `test_json.py` | `--format json` on every command that supports it; checks each `schema` field. |

## Notes

- **Time:** digest scheduling is simulated with the test-only `SSHSENTRY_TEST_NOW` environment variable (epoch seconds). Log events are written with real relative timestamps, such as noon yesterday.
- **Golden file:** the golden file holds the sample log's dates (`Oct 17`). Syslog lines carry no year, so the test substitutes the year the program would assign.
- **Regenerating the golden file:** only do this after an intentional output change. `python sshsentry.py -c sshsentry.yaml --db /tmp/g.db --replay sample-auth.log > tests/golden/replay_default.txt`
