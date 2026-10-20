# sshsentry Action List

**Legend:** [x] done · [ ] yours to do

## In progress or queued (I'm handling these)
1. [x] **Alerting:** email, Slack, and webhook destinations. A failed destination logs an error without crashing.
2. [x] **Escalation alert:** a second, higher-priority alert when an IP that only failed before later logs in successfully.
3. [x] **Learn mode:** watches quietly, then suggests a threshold. Off by default.
4. [x] **README "Why this exists" section:** under 150 words.
5. [x] **Community section and forms:** a README section, two GitHub Discussion forms (configs and attack patterns), and `SETUP-DISCUSSIONS.md`.
6. [x] **Full test suite rerun** and a rebuilt `sshsentry-mvp.zip`.

## Already done
7. [x] MVP script with four detection rules and plain-English alerts
8. [x] Opt-in sharing, `--show-shared`, and `--forget-me`
9. [x] Rename to sshsentry (all 18 tests passed)
10. [x] Design doc, business plan, Substack outline, privacy policy draft, and CrowdSec research

## Yours to do (in order)
11. [ ] **Claim the name:** the GitHub account or org `sshsentry`, the PyPI name `sshsentry`, and a domain (sshsentry.dev or .com, which looked free).
12. [ ] **Publish the GitHub repo:** push the project files and pick the MIT license.
13. [ ] **Enable Discussions:** follow `SETUP-DISCUSSIONS.md`, then replace `<owner>` in the README link.
14. [ ] **Pick a default threshold:** keep 5 failures in 10 minutes, or run learn mode for a few days and accept its suggestion.
15. [ ] **Choose alerting destinations:** email, Slack, or webhook, then add their settings in `sshsentry.yaml`. Run `--test-alerts` to confirm each one works.
16. [ ] **Test on a real server:** install it as a systemd service and watch for false alarms for a week.
17. [ ] **Legal review:** have a lawyer review the privacy policy before you turn on sharing or sell any data.
18. [ ] **Launch:** publish the Substack post, then post in r/selfhosted, r/sysadmin, and Show HN.

## Next build ideas
19. [x] **Try-it-without-installing demo:** `demo/index.html` is a self-contained page (a JS port of the rules, escalation and digest, with adjustable thresholds) that has been checked headlessly against the Python `--replay` output. The bundled sample log works with "Try it in 30 seconds".
20. [x] **Daily digest** with local records, `--digests`/`--digest`/`--resend`, and `--export-digests` zip + `.sha256` sidecar.
21. [x] **`--format json`** for the digest, threshold, sharing, export and verify commands (versioned `schema` field).
22. [x] **Digest hash chain** (`prev_hash`/`chain_hash`, upgrade backfill, hash in delivered digests) plus `--verify-chain` and `--verify-export [--expected-head]`.
23. [ ] **Publish the demo:** enable GitHub Pages (Settings → Pages → `main`, `/ (root)`) and link `https://<owner>.github.io/sshsentry/demo/` from the README and launch posts.
24. [ ] **Future:** optional digest signing with a key kept off the server (the chain is tamper-evident only).
