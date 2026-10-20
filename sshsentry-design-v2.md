# sshsentry: Design Doc for a Free, Open Source Server Intrusion Watcher

**Goal:** A lightweight agent that watches one Linux server and warns you, in plain language, about likely attempts to steal access or data.

## 1. What it monitors
- **Logins:** Failed and successful SSH and sudo attempts, with user and source IP, from `/var/log/auth.log`, `/var/log/secure`, or `journalctl`.
- **Login origin:** New IPs, countries, and odd hours per user, using a free offline GeoIP database (MaxMind GeoLite2 or DB-IP Lite).
- **Accounts:** New users, sudoers changes, and new SSH keys in `authorized_keys`, via file hashes and `/etc/passwd` diffs.
- **Processes:** New listening ports, shells spawned by web servers, and binaries running from `/tmp` or `/dev/shm`, via `/proc` scans (optionally `auditd`).
- **Sensitive files:** Reads and changes to `/etc/shadow`, SSH keys, `.env` files, and database dumps, via `auditd` or inotify.
- **Outbound network:** New destinations, large uploads, and unusual ports, via `/proc/net` or `ss` snapshots.

## 2. How it detects
Readable YAML rules with thresholds and severities. No machine learning in v1.

- **Brute force (Medium):** 5+ failed logins from one IP in 10 minutes.
- **Password spray (High):** 3+ different usernames failing from one IP in 10 minutes.
- **Success after failures (High):** A successful login from an IP that just failed 5+ times.
- **New country (High) / new IP (Low):** A successful login from a country or IP never seen before.
- **Odd hours (Low):** A login outside the user's usual hours, after 14 days of learning.
- **Account change (High):** New user, sudoers edit, or new SSH key.
- **Web shell (Critical):** `nginx`, `apache`, or `php-fpm` spawns `sh`, `bash`, `curl`, or `wget`.
- **Suspicious process (High):** An executable running from `/tmp`, `/dev/shm`, or a deleted file.
- **Sensitive read (High):** A non-allow-listed process reads `/etc/shadow` or private keys.
- **New listener (Medium):** A port opens that wasn't in the baseline.
- **Exfiltration hint (High):** Over 500 MB outbound to a new destination within an hour.

**Baseline:** The first run records "normal" (users, keys, IPs, countries, ports, processes) without alerting. You can approve new items so they stop alerting.

**Noise control:** Alerts are grouped in 15-minute windows, with per-rule cool-downs.

## 3. How it alerts
- **Local output:** Always to stdout/journald and a local alert log.
- **Email:** Optional, through your own SMTP server (STARTTLS, password from an environment variable).
- **Webhook:** Optional, to ntfy.sh, Matrix, or Discord.

Alerts say what happened and what to do, for example:
> **HIGH: Login after failures.** User `chris` logged in over SSH from 185.220.x.x (Romania) after 12 failed attempts from that IP. If this wasn't you, change the password and check `~/.ssh/authorized_keys`.

## 4. Tech stack (all free and open source)
- **Agent:** Python 3 for the MVP; Go later for a single static binary.
- **Storage:** SQLite for baselines, seen items, alert state, and approvals (30-day event retention).
- **Inputs:** Log files or journald, `/proc`, optional `auditd`, offline GeoIP.
- **Config:** YAML for rules and alert targets.
- **Packaging/license:** systemd service (later .deb/.rpm, Docker); MIT or Apache-2.0.
- **Privacy:** No paid services; nothing leaves the box except alerts you configure.

## 5. Scope limits (what it will NOT catch)
- **Memory-leak bugs like Heartbleed:** Stolen data leaves inside normal encrypted responses, with no login, process, or file trace.
- **Silent zero-days:** Exploits that create no processes, logins, files, or connections are invisible to the rules.
- **Kernel rootkits:** They can hide processes and alter logs; sshsentry trusts its host.
- **Insiders using valid access normally:** Normal-looking use looks normal.
- **Payload contents and app-logic abuse:** It sees metadata, not packets (it's not Suricata), and can't spot API scraping with valid tokens.
- **Prevention:** It only detects. Pair it with fail2ban, firewalls, updates, and key-only SSH.

Later mitigations: ship logs to a second machine so tampering is visible, and integrate with Suricata or Falco.

## 6. Weekend MVP
Build only this:
1. A single Python script, run as a systemd service (tail-follow) or via a timer with `--once`.
2. It parses `auth.log`/`secure` for SSH login events and keeps state in SQLite.
3. It implements four rules: brute force, success after failures, new IP or new country (using the GeoLite2 database), and new SSH key or new user (by hashing `authorized_keys` and `/etc/passwd`).
4. It prints plain-English alerts and optionally sends email through SMTP.
5. It has an `--approve <ip>` option to mark an IP as known, and a `--replay FILE` dry-run mode for testing.

**Why it's useful:** Most break-ins start with stolen or guessed SSH credentials; these rules cover that path in about two days of work.

**After the MVP:** Process and listener rules, auditd file watches, outbound tracking, a Go rewrite, and packaging.
