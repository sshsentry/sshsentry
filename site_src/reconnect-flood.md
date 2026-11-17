<!-- Site copy of /workspace/sshsentry_flood_article/reconnect-flood-article-v2.md (title per request; 'coming soon' resolved to the embedded video). -->

# Catching a reconnect flood that never logs in

Login-only detection stays silent. A proposed rule does not. Here is the demo, and an honest account of the gap 0.2.0 still leaves open.

## What the FAA reported

On November 13, 2026, the FAA issued a nationwide ground stop at about 3:30 p.m. ET and lifted it at 8:15 p.m. ET. The FAA reports that data flooded its FAA Telecommunications Infrastructure (FTI) network at about 1,000 connection attempts every 4 to 5 seconds. It traced the flood to a new router that contractor L3Harris had installed at a radio site in El Dorado, Arkansas, and to a radar-site router in Amarillo, Texas. Communications and radar became unstable at 17 of 22 en route centers. The FAA found no indication of a cyberattack.

Those figures are reported in [AeroTime, November 16, 2026](https://www.aerotime.aero/articles/faa-arkansas-router-upgrade-us-ground-stop) and [Axios, November 16, 2026](https://www.axios.com/2026/11/16/faa-flights-ground-stop-router-cause-reasons). The FAA also published a [questions-and-answers page](https://www.faa.gov/newsroom/nationwide-ground-stop-questions-and-answers) on November 15, 2026.

## The gap: if you only count logins, you will miss this

The November 13 event was flooding at the router and network layer. It did not involve SSH logins, and **sshsentry would not have detected or prevented it.** That is the starting point, not a footnote.

The lesson is the pattern. A single source opens connections over and over and drops them before anyone authenticates. If a detector only counts logins, that flood is invisible: no failed password, no invalid user, no accepted session, so the tool reports nothing while one address hammers a host hundreds of times a second. Silence, in that case, is the failure.

sshsentry 0.2.0 (alpha, MIT licensed, one Python script) still has that gap. It is detection only: it watches the SSH authentication log and counts only `Failed`, `Invalid user`, and `Accepted` lines. Pre-auth drops are ignored, including `Connection closed by 192.0.2.41 [preauth]`, `Did not receive identification string`, and MaxStartups drops. The brute-force rule wants 5 failed logins from one IP in 10 minutes. A reconnect flood produces none, so the rule never trips.

An experimental follow-on, sshsentry2 (`0.2.0+sshsentry2.exp1`), closes other gaps. It is not released, not merged, and it does not close this one. On October 25, 2026, from 21:28 to 21:37 ET, it ran in live follow mode against a throwaway OpenSSH server on loopback. It caught a distributed password spray, an unusual-hours login, log tampering, and a downtime gap. All 167 automated tests passed (134 original, 33 new). Replayed on the flood demo log, both 0.2.0 and sshsentry2 stayed silent on the simulated routers and raised only a LOW new-IP alert for a normal admin login.

## The proposed `connection_flood` rule

The proposed rule fills that hole. It raises a HIGH alert when 100 or more pre-auth connections come from one source within 10 seconds, with zero authentication attempts from that source in the same window. Count and window are configurable. The alert names the source IP and an optional inventory label, so the person on call sees the device, not just an address.

This rule is not in released 0.2.0, not in sshsentry2, and not in the [live demo](/try.html) already on this site. It lives in a standalone simulation, which uses the FAA's reported rate as pre-auth SSH connections from two RFC 5737 TEST-NET placeholders: `192.0.2.41` (El Dorado, AR radio-site router) and `192.0.2.87` (Amarillo, TX radar-site router). The real router addresses are not public. The simulation clock (03:14:00 CT, November 13) is illustrative, not the 3:30 p.m. ET ground-stop time.

Each router trips the alert at **attempt #100**, in under half a second, with the source address named: 0.396 seconds for El Dorado, 0.495 seconds for Amarillo. The current login-based rules stay silent on that traffic. The rule would still only see what reaches the SSH auth log on a host it watches, not the FTI flood itself.

## An example alert

The block below is from the simulation. It is not a real November 13 alert, and the addresses are placeholders, not the real routers.

```
[2026-11-13 03:14:05] HIGH: Connection flood. 100 SSH connections from 192.0.2.41 (El Dorado, AR radio-site router (simulated)) in 0.40 sec (~250/sec), all dropped before login; 0 login attempts. First seen 2026-11-13 03:14:05.000, last 2026-11-13 03:14:05.396 (attempt #100 from this source). This is not password guessing: a device or script is opening and dropping connections in a loop. Check the device at 192.0.2.41; if it is not expected, rate-limit or block it at the firewall.
```

The Amarillo placeholder, `192.0.2.87`, raises the same style of alert with its own address and label, at attempt 100 after 0.49 seconds.

## What else is built, and what is still unmerged

Alerts always print on stdout. Email, Slack, and webhook destinations are optional and off by default. Email (SMTP with STARTTLS) is the daily digest's default destination. In sshsentry2, a failed send to any enabled destination is queued and retried with exponential backoff (first retry after 30 seconds, cap 30 minutes, drop after 24 hours). That queue is not in 0.2.0. The October 25 test exercised it on the webhook: the alert was queued while the listener was down and delivered on the fourth attempt, marked delayed. The same queue covers email if email is enabled.

The October 25 test also left a tweak unapplied. One spray produced five HIGH alerts (a window-level alert plus four per-username alerts). The results note suppressing the per-user alerts while the window alert is already active. That change is not in sshsentry2 yet. Exact repeats are already muted by the usual 60-minute cooldown.

## Watch the demo

A standalone visual demo has been built separately from 0.2.0, sshsentry2, and the existing live demo. It plays the two labeled sources at about 1,000 attempts every 4 to 5 seconds, shows the current rules staying quiet, then `connection_flood` firing in under half a second with the source IP named. The recording is 77.5 seconds.

The video is at the top of this page: [DEMO VIDEO LINK]. You can also run the [interactive version](/reconnect-flood-demo.html) in your browser; it makes no network requests.
