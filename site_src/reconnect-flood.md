# A reconnect flood that never logs in is still a flood

Login-only detection stays silent. sshsentry 2 does not. Here is what is built, and what the released 0.2.0 base still misses.

## What the FAA reported

On November 13, 2026, the FAA issued a nationwide ground stop at about 3:30 p.m. ET and lifted it at 8:15 p.m. ET. The FAA reports that data flooded its FAA Telecommunications Infrastructure (FTI) network at about 1,000 connection attempts every 4 to 5 seconds. It traced the flood to a new router that contractor L3Harris had installed at a radio site in El Dorado, Arkansas, and to a radar-site router in Amarillo, Texas. Communications and radar became unstable at 17 of 22 en route centers. The FAA found no indication of a cyberattack.

Those figures are reported in [AeroTime, November 16, 2026](https://www.aerotime.aero/articles/faa-arkansas-router-upgrade-us-ground-stop) and [Axios, November 16, 2026](https://www.axios.com/2026/11/16/faa-flights-ground-stop-router-cause-reasons). The FAA also published a [questions-and-answers page](https://www.faa.gov/newsroom/nationwide-ground-stop-questions-and-answers) on November 15, 2026.

## The gap: if you only count logins, you will miss this

The November 13 event was flooding at the router and network layer. It did not involve SSH logins, and **sshsentry would not have detected or prevented it.** That is the starting point, not a footnote.

The lesson is the pattern. A single source opens connections over and over and drops them before anyone authenticates. If a detector only counts logins, that flood is invisible: no failed password, no invalid user, no accepted session, so the tool reports nothing while one address hammers a host hundreds of times a second. Silence, in that case, is the failure.

The released small-business base, sshsentry 0.2.0 (alpha, MIT licensed, one Python script), still has that gap. It is detection only: it watches the SSH authentication log and counts only `Failed`, `Invalid user`, and `Accepted` lines. Pre-auth drops are ignored, including `Connection closed by 192.0.2.41 [preauth]`, `Did not receive identification string`, and MaxStartups drops. The brute-force rule wants 5 failed logins from one IP in 10 minutes. A reconnect flood produces none, so the rule never trips.

sshsentry 2 (`0.2.0+sshsentry2.exp2`) closes this gap. It is built, tested, and merged into the main repository as the [Commercial Edition](https://github.com/sshsentry/sshsentry/tree/main/editions/commercial) for larger institutions and critical infrastructure, alongside the unchanged 0.2.0 base. It is not on PyPI, not a tagged release, and still experimental/alpha. It is not running in production anywhere.

On October 25, 2026, from 21:28 to 21:37 ET, an earlier sshsentry 2 build ran in live follow mode against a throwaway OpenSSH server on loopback. It caught a distributed password spray, an unusual-hours login, log tampering, and a downtime gap. That run also produced five HIGH alerts for one spray — a window-level alert plus four per-username alerts. The current build fixes that. `rules.distributed_spray.merge_user_alerts` is on by default, so an October 25-style spray now raises one HIGH alert that lists the targeted usernames, and the total HIGH count on that replay falls from 14 to 7. All 194 automated tests pass (167 from before, plus 27 new).

## The `connection_flood` rule

The rule is in the program and on by default. It raises a HIGH alert when 100 or more pre-auth connections come from one IP within 10 seconds, with no login attempts from that address in the same window. A `Failed`, `Invalid user`, `Accepted`, or authenticating-user line excludes the IP. Each connection is counted once, keyed on IP, process id, and port. MaxStartups drops count. The threshold and window are configurable. There is a five-minute cooldown per IP. You can attach optional inventory labels (an IP or CIDR mapped to a name) and an ignore list. Connection counts are kept in memory and reset on restart.

The rule works in replay, single-pass, and live follow. Alerts take the normal path: stdout, the alert log, and email, Slack, or a webhook if you have them enabled, plus the retry queue.

This rule is not in the released 0.2.0 base. A replay of the demo flood log through sshsentry 2 uses the FAA's reported rate as pre-auth SSH connections from two RFC 5737 placeholders: `192.0.2.41` (El Dorado, AR radio-site router) and `192.0.2.87` (Amarillo, TX radar-site router). The real router addresses are not public. The simulation clock (03:14:00 CT, November 13) is illustrative, not the 3:30 p.m. ET ground-stop time.

Each placeholder trips one HIGH alert at **connection #100**, in under half a second, with the source address named: 0.40 seconds for El Dorado, 0.49 seconds for Amarillo. The released 0.2.0 base stays silent on that traffic. The rule still only sees what reaches the SSH auth log on a host it watches, not the FTI flood itself.

## An example alert

The block below is an example from that replay, in the usual sshsentry alert style. It is not a real November 13 alert, and the addresses are placeholders, not the real routers.

```
[2026-11-13 03:14:05] HIGH: Connection flood. 100 SSH connections from 192.0.2.41 (El Dorado, AR radio-site router (simulated)) in 0.40 sec (~250/sec), all dropped before login; 0 login attempts. First seen 2026-11-13 03:14:05.000, last 2026-11-13 03:14:05.396 (attempt #100 from this source). This is not password guessing: a device or script is opening and dropping connections in a loop. Check the device at 192.0.2.41; if it is not expected, rate-limit or block it at the firewall.
```

The Amarillo placeholder, `192.0.2.87`, raises the same style of alert with its own address and label, at connection #100 after 0.49 seconds.

## Alerts and the retry queue

Alerts always print on stdout. Email, Slack, and webhook destinations are optional and off by default. Email (SMTP with STARTTLS) is the daily digest's default destination. In sshsentry 2, a failed send to any enabled destination is queued and retried with exponential backoff (first retry after 30 seconds, cap 30 minutes, drop after 24 hours). That queue is not in 0.2.0. The October 25 test exercised it on the webhook: queued while the listener was down, delivered on the fourth attempt, marked delayed. The same queue covers email if email is enabled.

## Watch the demo

A 77.5-second video walks through the rule: the flood starts, the El Dorado alert fires, the Amarillo alert fires, and a summary. It is a simulation with placeholder addresses, and its on-screen labels date from before the rule was built into sshsentry 2, so they call it "proposed."

The video is at the top of this page: [DEMO VIDEO LINK]. The four frames are in the [screenshots section](#screenshots) below. You can also run the [interactive version](/reconnect-flood-demo.html) in your browser; it makes no network requests.

The code is in the [sshsentry 2 Commercial Edition](https://github.com/sshsentry/sshsentry/tree/main/editions/commercial) on GitHub.
