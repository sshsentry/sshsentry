# sshsentry Privacy Policy

> **Draft only.** This is not legal advice. Have a lawyer review it before you publish.

*Last updated: [DATE]* · *Contact: sshsentry@gmail.com*

## The Short Version
- **By default, nothing leaves your server.** sshsentry keeps what it learns in a small database on your own machine.
- **Sharing is off unless you turn it on.** If you opt in, sshsentry sends only basic facts about attacks: the attacker's IP address, which rule caught it, and when.
- **sshsentry never sends** your logs, passwords, usernames, hostname, or anything that identifies you or your server.
- **Shared data may be combined with other users' data and sold** as threat intelligence, such as lists of known attacking IPs. Your identity is never included.
- **You can stop sharing and ask us to delete your contributions at any time.**

## 1. Data Stored on Your Machine
sshsentry reads your server's login logs (for example `/var/log/auth.log` or `/var/log/secure`), plus `/etc/passwd` and `authorized_keys` files. It saves the following in a local SQLite file (`/var/lib/sshsentry/state.db` by default):
- IP addresses and countries that have logged in to each user account, so it can spot a "new" location
- Recent failed login attempts, used to detect brute force
- A baseline of system users and fingerprints of SSH keys
- Alert history and timestamps
- IP addresses you have approved
- If you opt in to sharing: a record of each report sent or attempted, and your random installation ID
- If you turn on learn mode: counts of failed logins per IP per time window
- If you turn on the daily digest: successful logins from the last 7 days (user, IP, time) and each day's digest, stored in the database and as text files

**This data stays on your machine.** We can't see it. You can delete it anytime by removing the database file. If you turn on email, Slack, or webhook alerts or the daily digest, the message text (which can include usernames and IP addresses) goes to the service you configure, under that service's own privacy terms.

## 2. What Optional Sharing Sends
Sharing is **off by default**. If you turn it on, each report includes only:
- **The attacking IP address** (the source of the suspicious activity, not your server's address)
- **The detection rule** that fired (for example, `brute_force`)
- **A timestamp** of the attack, in UTC, rounded down to the minute
- **The sshsentry version number**
- **A random installation ID**, generated locally the first time a report is sent and not tied to your name, email, or server, so you can ask us to delete your contributions later

**sshsentry never sends:** raw log lines, passwords, usernames (including the ones attackers guessed), your hostname, your server's IP, file contents, SSH keys, your email settings, or any other personal data.

Only two attack rules are shared: `brute_force` (repeated failed logins) and `login_after_failures` (a successful login from an IP that just failed repeatedly). **Never shared:** new-IP or new-country logins, new-user or new-SSH-key alerts, IP addresses you have approved, private or local network addresses, and test replays (`--replay`).

## 3. How Shared Data Is Kept Anonymous
- **Attacking IPs are shared as they are,** because a blocklist only works with real addresses.
- No user identity, hostname, server address, or account information is ever attached to a report.
- Reports are linked only to the random installation ID. We don't connect that ID to any other information about you.
- We don't log the address your server connects from beyond what our server needs to receive the report. Those connection logs are deleted within **[7] days**.
- Data that we sell or publish is combined first, for example "this IP was reported by 40 installations this week," and never includes installation IDs.

*Note: in some places, such as under the EU's GDPR, an IP address can count as personal data even when it belongs to an attacker. Ask your lawyer about this.*

## 4. Retention
- **Individual reports:** kept for **[90] days**, then deleted or folded into combined statistics.
- **Combined blocklist entries:** an IP stays listed while it's still being reported and drops off after **[30] days** without new reports.
- **Combined statistics** (counts and trends that can't be traced to any installation): may be kept indefinitely.
- **Server connection logs:** deleted within **[7] days**.

## 5. Your Choices
- **Opt in:** set `sharing.enabled: true` in `sshsentry.yaml` and restart sshsentry.
- **Opt out:** set it back to `false`. Sharing stops right away.
- **See what's sent:** run `sshsentry.py --show-shared` to list every report this installation has sent or tried to send: attacking IP, rule, timestamp, send time, and status. The exact report format is in the README.
- **Delete your contributions:** run `sshsentry.py --forget-me`. It deletes your sharing history from the local database right away, discards your installation ID, and, if a sharing endpoint is configured, sends us a deletion request with that ID. The request is best-effort; if it fails, email us at sshsentry@gmail.com with the installation ID it prints. `--forget-me` doesn't turn sharing off. We will delete your individual reports within **[30] days**. Data that has already been combined and stripped of installation IDs can't be separated back out.
- **Use it without sharing:** every detection feature works with sharing turned off.

## 6. Third Parties
**Who may buy combined data:**
- Security companies
- Hosting and cloud providers
- Firewall and content-delivery (CDN) vendors
- Researchers and organizations protecting their own networks

**What they receive:**
- Attacking IP addresses with threat scores
- Which detection rules fired
- First-seen and last-seen times, and report counts

**What they never receive:** installation IDs, data from any single installation, or anything that identifies sshsentry users.

**Our service providers:**
- We use hosting providers to run the collection server, under contracts that protect the data.
- We share data with law enforcement only when the law requires it.
- If the project or the sharing service changes owners, this policy applies until users are notified of any change.

**We never sell** information about sshsentry users. We sell only combined information about attackers.

## 7. Security
Reports are sent over HTTPS (encrypted in transit); sshsentry refuses non-HTTPS endpoints except `localhost` for testing. Access to the collection server is limited to the maintainers. Report security problems through `SECURITY.md` in the GitHub repo.

## 8. Changes
We will announce meaningful changes in the GitHub repo and the release notes at least **[30] days** before they take effect. A change that widens what gets shared will **never** switch on automatically; you'll have to opt in again.

## 9. Contact
Questions or deletion requests: **sshsentry@gmail.com** or open an issue on GitHub.
