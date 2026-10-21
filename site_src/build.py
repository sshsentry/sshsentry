#!/usr/bin/env python3
"""Builds the static marketing/docs pages in demo/ from this file + site.css.
Run: python3 site_src/build.py   (no dependencies). demo/try.html (the live demo) is hand-maintained."""
import hashlib, html, os, re, shutil
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); OUT = os.path.join(ROOT, "demo")
SITE = "https://sshsentry.com"; GH = "https://github.com/sshsentry/sshsentry"
DISC = GH + "/discussions/categories/"
E = html.escape

SHIELD = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>'
ICONS = {
 "term": '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>',
 "lock": '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/></svg>',
 "shield": SHIELD.replace('width="20" height="20"', 'width="22" height="22"'),
 "key": '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3"/></svg>',
 "user": '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/></svg>',
 "globe": '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>',
 "hash": '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M5 9h14M5 15h14M10 3L8 21M16 3l-2 18"/></svg>',
}
FAVICON = "data:image/svg+xml," + re.sub(r"\s+", " ", '''<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect width='24' height='24' rx='5' fill='%2309090b'/><path d='M12 4l7 2.6v5.2c0 3.9-3 7.2-7 7.8-4-.6-7-3.9-7-7.8V6.6L12 4z' fill='none' stroke='%232dd4bf' stroke-width='1.8'/><path d='M9 12l2 2 4-4' fill='none' stroke='%232dd4bf' stroke-width='1.8'/></svg>''')

NAV = [("/features.html", "Features"), ("/docs/", "Docs"), ("/try.html", "Try it live"), (DISC + "configs", "Community")]
DOCS = [("/docs/", "Getting started"), ("/docs/configuration.html", "Configuration"), ("/docs/cli.html", "CLI reference"),
        ("/docs/replay.html", "Replaying logs"), ("/docs/fail2ban.html", "With fail2ban"), ("/docs/faq.html", "FAQ"),
        ("/docs/troubleshooting.html", "Troubleshooting")]

def nav_html(path):
    items = "".join(f'<li><a href="{h}"{" aria-current=page" if (h == path or (h == "/docs/" and path.startswith("/docs/"))) else ""}>{t}</a></li>' for h, t in NAV)
    return (f'<nav class="nav" aria-label="Main"><div class="wrap"><a class="brand" href="/">{SHIELD}sshsentry</a>'
            f'<ul>{items}<li><a class="gh" href="{GH}">GitHub</a></li></ul></div></nav>')

def footer_html(fp):
    return f'''<footer class="site"><div class="wrap"><div class="cols">
<div><a class="brand" href="/">{SHIELD}sshsentry</a><p style="max-width:340px;margin-top:10px">Plain-English SSH alerts for small Linux servers. Detection only. MIT licensed, free and open source.</p></div>
<div><h5>Project</h5><ul><li><a href="{GH}">GitHub</a></li><li><a href="https://pypi.org/project/sshsentry/">PyPI</a></li><li><a href="{GH}/issues">Issues</a></li><li><a href="{GH}/blob/main/LICENSE">MIT license</a></li></ul></div>
<div><h5>Community</h5><ul><li><a href="{DISC}configs">Discussions: Configs</a></li><li><a href="{DISC}attack-patterns">Discussions: Attack patterns</a></li><li><a href="{GH}/discussions">All discussions</a></li></ul></div>
<div><h5>More</h5><ul><li><a href="/docs/">Docs</a></li><li><a href="/privacy.html">Privacy policy</a></li><li><a href="mailto:sshsentry@gmail.com">sshsentry@gmail.com</a></li></ul></div>
</div><div class="fp">page sha256:{fp} &middot; static &middot; no trackers &middot; no third-party scripts</div></div></footer>'''

COPYJS = '''<script>document.querySelectorAll(".copy").forEach(function(b){b.addEventListener("click",function(){var t=b.getAttribute("data-copy");
(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent="copied"},function(){b.textContent="select + copy"});
setTimeout(function(){b.textContent="copy"},1600)})})</script>'''

def page(path, title, desc, body, out):
    url = SITE + path
    fp = hashlib.sha256(body.encode()).hexdigest()
    doc = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{E(title)}</title><meta name="description" content="{E(desc)}"><link rel="canonical" href="{url}">
<meta name="theme-color" content="#09090b"><link rel="icon" href="{FAVICON}">
<meta property="og:type" content="website"><meta property="og:site_name" content="sshsentry"><meta property="og:title" content="{E(title)}">
<meta property="og:description" content="{E(desc)}"><meta property="og:url" content="{url}"><meta property="og:image" content="{SITE}/assets/og.jpg">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="{SITE}/assets/og.jpg"><link rel="stylesheet" href="/assets/site.css"></head>
<body>{nav_html(path)}<main>{body}</main>{footer_html(fp[:40])}{COPYJS}</body></html>
'''
    p = os.path.join(OUT, out); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(doc)

def cmd(c):
    return f'<div class="cmd"><span class="p">$</span><code>{E(c)}</code><button class="copy" type="button" data-copy="{E(c)}" aria-label="Copy command">copy</button></div>'

def term(title, text, kind="alerts", ln=True):
    lines = []
    for l in text.strip("\n").split("\n"):
        h = E(l)
        if kind == "alerts":
            h = re.sub(r"^(\[[^\]]+\])", r'<span class="t-ts">\1</span>', h)
            h = re.sub(r"\b(LOW|MEDIUM|HIGH|CRITICAL):", r'<span class="s-\1">\1</span>:', h)
        elif kind == "yaml":
            m = re.match(r"^(\s*)(#.*)$", h)
            if m: h = f'{m.group(1)}<span class="y-c">{m.group(2)}</span>'
            else:
                h = re.sub(r"^(\s*-?\s*)([\w.]+):", r'\1<span class="y-k">\2</span>:', h)
                h = re.sub(r"(\s)(#.*)$", r'\1<span class="y-c">\2</span>', h)
                h = re.sub(r":\s(true|false|\d+(?:\.\d+)?|auto|LOW|MEDIUM|HIGH|CRITICAL)\b", r': <span class="y-v">\1</span>', h)
                h = re.sub(r"(&quot;[^&]*&quot;)", r'<span class="y-s">\1</span>', h)
        elif kind == "sh":
            if h.lstrip().startswith("#"): h = f'<span class="sh-c">{h}</span>'
            else: h = re.sub(r"(\s+)(#\s.*)$", r'\1<span class="sh-c">\2</span>', h)
        lines.append(f'<span class="l">{h or " "}</span>' if ln else h)
    s = hashlib.sha256(text.encode()).hexdigest()[:12]
    body = "".join(lines) if ln else "\n".join(lines)
    return (f'<div class="term"><div class="bar"><i></i><i></i><i></i><span>{E(title)}</span><span class="sum">sha256:{s}</span></div>'
            f'<pre class="{"ln" if ln else ""}">{body}</pre></div>')

REPLAY = """[2026-10-17 01:58:02] LOW: New IP login. User 'chris' logged in via publickey from 198.51.100.23, an address never seen for this user (first recorded login). If expected, approve it with: sshsentry.py --approve 198.51.100.23
[2026-10-17 02:10:31] MEDIUM: Brute force. 5 failed SSH logins from 203.0.113.45 in 30 sec, trying user(s): admin, oracle, root, test. Consider fail2ban, a firewall block, or disabling password logins.
[2026-10-17 02:15:41] MEDIUM: Brute force. 5 failed SSH logins from 192.0.2.77 in 49 sec, trying user(s): deploy. Consider fail2ban, a firewall block, or disabling password logins.
[2026-10-17 02:16:08] HIGH: Login after failures. User 'deploy' logged in via password from 192.0.2.77 after 6 failed attempts from that IP. If this wasn't you, change the password, check ~/.ssh/authorized_keys and review running processes.
[2026-10-17 02:16:08] LOW: New IP login. User 'deploy' logged in via password from 192.0.2.77, an address never seen for this user (first recorded login). If expected, approve it with: sshsentry.py --approve 192.0.2.77
[2026-10-17 02:47:33] LOW: New IP login. User 'chris' logged in via publickey from 100.64.12.9, an address never seen for this user. If expected, approve it with: sshsentry.py --approve 100.64.12.9"""
DIGEST = """sshsentry daily digest, 2026-10-17
Period: Fri Oct 16 08:00 to Sat Oct 17 08:00 (server time)

Failed logins: 12 from 2 IP address(es).
Most active: 203.0.113.45, 6 attempts (usernames tried: admin, oracle, root, test).
Successful logins: 4
  - chris from 198.51.100.23 (2x) [new IP]
  - deploy from 192.0.2.77 [new IP]  << after 6 failed attempts from that IP. Check this.
  - chris from 100.64.12.9 [new IP]
New IPs seen: 3 (198.51.100.23, 192.0.2.77, 100.64.12.9).

Integrity chain: 9c41e07ab2d3 (sha256 9c41e07ab2d3...)"""
REPLAY_DIGEST = """sshsentry daily digest, replayed log
Period: Sat Oct 17 01:58 to Sat Oct 17 02:47 (server time)

Failed logins: 12 from 2 IP address(es).
Most active: 203.0.113.45, 6 attempts (usernames tried: admin, oracle, root, test).
Successful logins: 4
  - chris from 198.51.100.23 (2x) [new IP]
  - deploy from 192.0.2.77 [new IP]  << after 6 failed attempts from that IP. Check this.
  - chris from 100.64.12.9 [new IP]
New IPs seen: 3 (198.51.100.23, 192.0.2.77, 100.64.12.9)."""
TRY = """pip install sshsentry
curl -sO https://raw.githubusercontent.com/sshsentry/sshsentry/main/sample-auth.log
sshsentry --db /tmp/sshsentry-try.db --replay sample-auth.log --digest-now   # prints alerts, sends nothing"""

def hexstrip(seed):
    rows = []
    for i in range(4):
        h = hashlib.sha256(f"{seed}{i}".encode()).hexdigest() + hashlib.sha256(f"{seed}{i}x".encode()).hexdigest()
        rows.append(f"{i*32:08x}  " + " ".join(h[j:j+2] for j in range(0, 64, 2)))
    return '<div class="hexstrip" aria-hidden="true">' + "\n".join(rows) + "</div>"

RULES = [  # verified against DEFAULTS and the alert texts in sshsentry.py
 ("brute_force", "Brute force", "MEDIUM", "lock", "5+ failed logins from one IP within a sliding 10 minutes. Invalid usernames count too, so key-only servers are covered.",
  "[2026-10-17 02:10:31] MEDIUM: Brute force. 5 failed SSH logins from 203.0.113.45 in 30 sec, trying user(s): admin, oracle, root, test. Consider fail2ban, a firewall block, or disabling password logins.",
  "rules.brute_force: failures 5, window_minutes 10"),
 ("login_after_failures", "Login after failures", "HIGH", "user", "A successful login from an IP that failed 5+ times in the last 60 minutes. This is the one you really want to hear about.",
  "[2026-10-17 02:16:08] HIGH: Login after failures. User 'deploy' logged in via password from 192.0.2.77 after 6 failed attempts from that IP. If this wasn't you, change the password, check ~/.ssh/authorized_keys and review running processes.",
  "rules.login_after_failures: failures 5, lookback_minutes 60"),
 ("escalation", "Escalation", "CRITICAL", "shield", "With alerting turned on, an IP already alerted for brute force that later logs in gets one CRITICAL alert to every destination. It replaces the login-after-failures alert for that login.",
  "ESCALATION: successful login from 192.0.2.77 after brute force. User 'deploy' logged in via password after 6 failed attempts from that IP ...",
  "needs alerting.enabled: true; once per brute-force alert"),
 ("new_country", "New country", "HIGH", "globe", "A successful login from a country never seen for that user. Needs the optional geoip2 library and a free MaxMind GeoLite2-Country database; skipped with a one-line note if missing.",
  None, "rules.new_country + geoip.database"),
 ("new_ip", "New IP", "LOW", "term", "A successful login from an IP never seen for that user. Approve your own addresses with --approve IP.",
  "[2026-10-17 02:47:33] LOW: New IP login. User 'chris' logged in via publickey from 100.64.12.9, an address never seen for this user. If expected, approve it with: sshsentry.py --approve 100.64.12.9",
  "rules.new_ip"),
 ("new_user", "New user", "HIGH", "user", "A new account appears in /etc/passwd. Existing accounts are recorded silently on the first run.", None, "rules.new_user.passwd_file"),
 ("new_ssh_key", "New SSH key", "HIGH", "key", "A new line in any watched authorized_keys file (root and /home/* by default, globs allowed). Existing keys are the silent baseline.", None, "rules.new_ssh_key.paths"),
]

def home():
    cards = "".join(f'<div class="card"><span class="ic">{ICONS[ic]}</span><h3>{t} <span class="sev s-{sv}">{sv}</span></h3><p>{d}</p><div class="meta">rule:{r}</div></div>' for r, t, sv, ic, d, *_ in RULES)
    b = f'''<section class="hero"><div class="wrap"><div class="grid"><div>
<div class="badges"><span class="badge"><span class="dot"></span>v0.2.0 on PyPI</span><span class="badge">detection only</span><span class="badge">one Python file</span><span class="badge">MIT</span></div>
<h1>Know when someone gets into your server.</h1>
<p class="lead">sshsentry watches your SSH auth log, <code>/etc/passwd</code> and <code>authorized_keys</code>, and tells you in plain English when something matters. Built for small businesses and homelabs, not enterprise fleets.</p>
<div style="margin-top:26px">{cmd("pip install sshsentry")}</div>
<div class="cta"><a class="btn primary" href="/docs/">Get started</a><a class="btn" href="/try.html">Try it live in your browser</a><a class="btn" href="{GH}">View on GitHub</a></div>
{hexstrip("hero")}
</div><div class="heroimg"><img src="/assets/banner.jpg" alt="sshsentry banner" width="1600" height="900" fetchpriority="high"></div></div></div></section>

<section class="block"><div class="wrap two"><div><span class="label">00 see it run</span><h2>Real output, no setup</h2>
<p class="muted">This is sshsentry replaying the sample log that ships in the repo. Every alert says what happened, who, from where, and what to check next. Replay never sends anything anywhere.</p>
{term("try it", TRY, "sh")}
<p class="dim" style="font-size:13px">The animation shows real tool output; the install lines in it are simulated.</p></div>
<div class="heroimg gifbox"><img src="/assets/demo.gif" alt="Terminal recording of sshsentry replaying a sample auth log and printing alerts" width="960" height="600" loading="lazy"></div></div></section>

<section class="block"><div class="wrap"><span class="label">01 detect</span><h2>What it notices</h2>
<p class="lead">Seven rules, all on by default, all tunable in <code>sshsentry.yaml</code>. Repeats are muted for <code>cooldown_minutes</code> (60).</p>
<div class="cards">{cards}</div><p style="margin-top:22px"><a href="/features.html">Every rule with sample alerts &rarr;</a></p></div></section>

<section class="block"><div class="wrap"><span class="label">02 how it works</span><h2>Three steps</h2><div class="steps">
<div class="step"><b>step_01</b><h3>Install one script</h3><p class="muted"><code>pip install sshsentry</code>, or copy <code>sshsentry.py</code> to the server. Python 3.9+ and PyYAML. No agent fleet, no database server, no dashboard.</p></div>
<div class="step"><b>step_02</b><h3>It learns what is normal</h3><p class="muted">The first run is quiet. Existing users and keys become the baseline, and the existing log teaches it which IPs each user normally uses.</p></div>
<div class="step"><b>step_03</b><h3>You get plain-English alerts</h3><p class="muted">On stdout (journald under systemd), and optionally by email, Slack or a webhook, plus an optional daily digest.</p></div>
</div></div></section>

<section class="block"><div class="wrap two"><div><span class="label">03 fits your stack</span><h2>Pairs with fail2ban</h2>
<p class="muted">sshsentry <strong>does not block anything</strong>. It reads logs and files and tells you what it saw. fail2ban (or your firewall) does the blocking. Together: fail2ban slows the guessing, sshsentry tells you when a guess worked, or when a new user or key appears that fail2ban was never designed to notice.</p>
<p><a href="/docs/fail2ban.html">How they fit together &rarr;</a></p></div>
<div class="callout"><strong>Does it change my server?</strong><br>No. It reads the auth log, <code>/etc/passwd</code> and <code>authorized_keys</code>, and writes only its own SQLite state file (and optional digest text files). Nothing leaves the machine unless you turn on alerts or opt-in sharing.</div></div></section>

<section class="block" id="community"><div class="wrap"><span class="label">04 community</span><h2>Share configs and attack patterns</h2>
<div class="cards">
<a class="card" href="{DISC}configs"><span class="ic">{ICONS["term"]}</span><h3>Configs</h3><p>Share your sshsentry.yaml thresholds and learn-mode suggestions, and compare with others.</p></a>
<a class="card" href="{DISC}attack-patterns"><span class="ic">{ICONS["hash"]}</span><h3>Attack patterns</h3><p>Post (redacted) log samples of what you saw and what helped.</p></a>
<a class="card" href="{GH}/issues"><span class="ic">{ICONS["key"]}</span><h3>Issues &amp; contributing</h3><p>Bugs, parser gaps, docs fixes. Security issues: email sshsentry@gmail.com privately.</p></a>
</div><p class="dim" style="margin-top:18px;font-size:14px">Before posting, remove your server IPs, hostnames, usernames, email addresses, webhook URLs and tokens.</p></div></section>'''
    page("/", "sshsentry: plain-English SSH intrusion alerts for small Linux servers",
         "A free, open source, single-script SSH intrusion detection tool for small businesses and homelabs. Detection only; pairs with fail2ban.", b, "index.html")

def features():
    secs = ""
    for r, t, sv, ic, d, sample, cfg in RULES:
        ex = term(f"{r}.alert", sample) if sample else ""
        secs += f'<section class="block" id="{r}" style="padding:56px 0"><div class="wrap"><span class="label">rule {r}</span><h2>{t} <span class="sev s-{sv}">{sv}</span></h2><p class="lead">{d}</p>{ex}<p class="dim" style="font:13px var(--mono)">config: {E(cfg)}</p></div></section>'
    b = f'''<section class="hero" style="padding-bottom:30px"><div class="wrap"><span class="label">features</span><h1>What sshsentry detects</h1>
<p class="lead">Each rule below is in the 0.2.0 release. Alerts are short, specific, and suggest the next thing to check.</p>
<div class="tablewrap" style="margin-top:30px"><table><tr><th>Severity</th><th>Meaning</th><th>Rules</th></tr>
<tr><td><span class="sev s-LOW">LOW</span></td><td>Worth knowing, usually you</td><td>New IP</td></tr>
<tr><td><span class="sev s-MEDIUM">MEDIUM</span></td><td>Someone is trying</td><td>Brute force</td></tr>
<tr><td><span class="sev s-HIGH">HIGH</span></td><td>Check this now</td><td>Login after failures, new country, new user, new SSH key</td></tr>
<tr><td><span class="sev s-CRITICAL">CRITICAL</span></td><td>An attacker may be in</td><td>Escalation (alerting on)</td></tr></table></div>
<p class="muted">Each destination can filter with <code>min_severity</code>.</p></div></section>
{secs}
<section class="block"><div class="wrap two"><div><span class="label">daily digest</span><h2>One short screen a day</h2><p class="muted">Optional (<code>digest.enabled</code>). Summarizes the last 24 hours, stores it locally, and can send it to one destination. Each day carries a hash chain line so a rewritten history can be spotted later: tamper-evident, not tamper-proof.</p></div>{term("digest-2026-10-17.txt", DIGEST, "plain")}</div></section>
<section class="block"><div class="wrap two"><div><span class="label">privacy</span><h2>Local by default</h2><p class="muted">State lives in a local SQLite file. Alerts go to stdout unless you enable email, Slack or a webhook (each off by default). Community sharing of attacker IPs is opt-in, sends no usernames or log lines, and can be reviewed with <code>--show-shared</code> and erased with <code>--forget-me</code>. See the <a href="/privacy.html">privacy policy</a>.</p></div>
<div><span class="label">detection only</span><h2>It watches. It does not block.</h2><p class="muted">sshsentry never changes firewall rules, accounts or keys. Use fail2ban, a firewall and key-only SSH for prevention. A responder that helps you act on an incident is planned and shown only as a simulation in the <a href="/try.html">live demo</a>; it is not in this release.</p></div></div></section>
<section class="block"><div class="wrap"><span class="label">limits</span><h2>Honest limits</h2><p class="muted" style="max-width:760px">SSH-focused. It won't see web-app attacks or anything that leaves no login or account trace (silent zero-days, rootkits that tamper with logs). Someone with root can edit local logs; ship logs off-box if that worries you.</p></div></section>'''
    page("/features.html", "Features: what sshsentry detects", "Brute force, login after failures, escalation, new country, new IP, new user and new SSH key alerts, in plain English.", b, "features.html")

def doc(path, out, title, desc, body):
    side = "".join(f'<li><a href="{h}"{" aria-current=page" if h == path else ""}>{t}</a></li>' for h, t in DOCS)
    i = [h for h, _ in DOCS].index(path)
    prev = f'<a href="{DOCS[i-1][0]}">&larr; {DOCS[i-1][1]}</a>' if i else "<span></span>"
    nxt = f'<a href="{DOCS[i+1][0]}">{DOCS[i+1][1]} &rarr;</a>' if i + 1 < len(DOCS) else "<span></span>"
    b = (f'<div class="wrap docs"><details class="side" open><summary>Docs menu</summary><div class="sidebody"><h4>Documentation</h4><ul>{side}</ul>'
         f'<h4>Elsewhere</h4><ul><li><a href="/try.html">Live demo</a></li><li><a href="{GH}#readme">README</a></li></ul></div></details>'
         f'<article class="doc"><span class="label">docs</span>{body}<div class="pager">{prev}{nxt}</div></article></div>')
    page(path, f"{title} | sshsentry docs", desc, b, out)

def docs():
    doc("/docs/", "docs/index.html", "Getting started", "Install sshsentry, try it on a sample log, and run it as a systemd service.", f'''
<h1>Getting started</h1><p class="lead">Five minutes from nothing to alerts. You need Linux, Python 3.9+ and PyYAML.</p>
<h2>1. Try it without touching your server</h2><p>Replay the sample log against a throwaway database. Nothing is sent anywhere in replay mode.</p>{term("shell", TRY, "sh")}
<p>Or skip Python entirely and use the <a href="/try.html">in-browser demo</a>.</p>
<h2>2. Install on a server</h2><p>Either from PyPI:</p>{cmd("sudo pip install sshsentry")}
<p>or as a single file from the repo:</p>{term("shell", """sudo mkdir -p /opt/sshsentry /etc/sshsentry /var/lib/sshsentry
sudo cp sshsentry.py /opt/sshsentry/
sudo cp sshsentry.yaml /etc/sshsentry/sshsentry.yaml
sudo apt install python3-yaml        # or: sudo dnf install python3-pyyaml / pip install pyyaml""", "sh")}
<p>On Debian/Ubuntu with "externally managed" Python, prefer the distro package <code>python3-yaml</code> or a venv.</p>
<h2>3. Run it</h2>{term("shell", """sudo python3 /opt/sshsentry/sshsentry.py            # follow /var/log/auth.log or /var/log/secure
sudo python3 /opt/sshsentry/sshsentry.py --once     # process new lines, then exit (for timers/cron)""", "sh")}
<p>Run as root so it can read the auth log and every user's <code>authorized_keys</code>. The first run is quiet: it records a baseline.</p>
<h2>4. Keep it running with systemd</h2>{term("/etc/systemd/system/sshsentry.service", """[Unit]
Description=sshsentry SSH intrusion detection
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/sshsentry/sshsentry.py -c /etc/sshsentry/sshsentry.yaml
EnvironmentFile=-/etc/sshsentry/env
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target""", "plain")}
{term("shell", """sudo systemctl daemon-reload && sudo systemctl enable --now sshsentry
journalctl -u sshsentry -f        # alerts appear here""", "sh")}
<h2>5. Optional: country checks</h2><p>Create a free MaxMind account, download <strong>GeoLite2-Country</strong> to <code>/usr/share/GeoIP/GeoLite2-Country.mmdb</code> (or set <code>geoip.database</code>), and <code>pip install geoip2</code>. If either is missing, sshsentry prints one note and skips country checks.</p>
<div class="callout"><strong>Next:</strong> tune thresholds and turn on email or Slack in <a href="/docs/configuration.html">Configuration</a>.</div>''')

    yaml_rules = """log_file: auto              # auto = /var/log/auth.log or /var/log/secure
state_db: /var/lib/sshsentry/state.db
poll_seconds: 1
file_check_seconds: 60      # how often to re-check passwd and authorized_keys
cooldown_minutes: 60        # don't repeat the same alert within this time
alert_log: ""               # optional JSON-lines alert file

rules:
  brute_force:          {enabled: true, failures: 5, window_minutes: 10}
  login_after_failures: {enabled: true, failures: 5, lookback_minutes: 60}
  new_ip:               {enabled: true}
  new_country:          {enabled: true}      # needs geoip2 + GeoLite2-Country
  new_user:             {enabled: true, passwd_file: /etc/passwd}
  new_ssh_key:
    enabled: true
    paths: [/root/.ssh/authorized_keys, "/home/*/.ssh/authorized_keys"]
learn_existing_log: true    # first run: learn normal IPs silently"""
    yaml_alert = """alerting:
  enabled: true
  timeout: 5
  email:   {enabled: true,  min_severity: HIGH}       # SMTP settings: the top-level email: block
  slack:   {enabled: true,  min_severity: MEDIUM, webhook_url_env: SSHSENTRY_SLACK_WEBHOOK}
  webhook: {enabled: false, min_severity: LOW, url_env: SSHSENTRY_WEBHOOK_URL}

email:
  smtp_host: smtp.example.com
  smtp_port: 587
  starttls: true
  username: alerts@example.com
  password_env: SSHSENTRY_SMTP_PASSWORD   # keep the password out of the YAML
  from: alerts@example.com
  to: [you@example.com]
  subject_prefix: "[sshsentry]\""""
    yaml_more = """digest:
  enabled: false
  time: "08:00"             # server local time
  send: true
  destination: email        # email | slack | webhook
  send_when_quiet: true
  save_text: true
  text_dir: ""              # "" = digests/ next to state_db
  host_label: ""
  include_chain_hash: true

learn_mode: {enabled: false, days: 3, percentile: 99, margin: 2, min_threshold: 3, max_threshold: 50}
geoip: {database: /usr/share/GeoIP/GeoLite2-Country.mmdb}
sharing: {enabled: false, endpoint: "", timeout: 5}   # opt-in, https only"""
    doc("/docs/configuration.html", "docs/configuration.html", "Configuration", "sshsentry.yaml reference: rules, alert destinations, digest, learn mode and sharing, with defaults from the code.", f'''
<h1>Configuration</h1><p class="lead">Everything lives in <code>/etc/sshsentry/sshsentry.yaml</code> (override with <code>-c</code>). Any key you leave out uses the default shown here, taken from the code in 0.2.0.</p>
<h2>Core and rules</h2>{term("sshsentry.yaml", yaml_rules, "yaml")}
<p>The brute-force threshold is one number for stdout and every destination. Learn mode can suggest a value; it never changes it unless you run <code>--accept-threshold</code>.</p>
<h2>Alert destinations</h2><p>Stdout is always on. Everything else is off until <code>alerting.enabled: true</code> plus the destination's own <code>enabled</code>. Severity order: <code>LOW &lt; MEDIUM &lt; HIGH &lt; CRITICAL</code>.</p>{term("sshsentry.yaml", yaml_alert, "yaml")}
<p>Put secrets in <code>/etc/sshsentry/env</code> (loaded by the systemd unit) rather than the YAML:</p>{term("shell", """sudo install -m 600 /dev/null /etc/sshsentry/env
echo 'SSHSENTRY_SMTP_PASSWORD=your-app-password' | sudo tee /etc/sshsentry/env >/dev/null
echo 'SSHSENTRY_SLACK_WEBHOOK=https://hooks.slack.com/services/...' | sudo tee -a /etc/sshsentry/env""", "sh")}
<ul><li>URLs must be <code>https://</code> (<code>http://</code> only for localhost). A bad destination is disabled with a warning; monitoring continues.</li>
<li>Slack markup characters in usernames are escaped, so an attacker-chosen <code>&lt;!channel&gt;</code> can't ping your channel.</li>
<li>Run <code>--test-alerts</code> after setup. Add the sender address to your contacts so alerts don't land in spam.</li></ul>
<h2>Digest, learn mode, GeoIP, sharing</h2>{term("sshsentry.yaml", yaml_more, "yaml")}
<p>All off by default. Learn mode records failures per IP per window for <code>days</code> and suggests a threshold; during it, alerts print with <code>[learning: not sent]</code> and nothing is sent. Sharing reports only attacker IPs for brute-force and login-after-failures alerts; see the <a href="/privacy.html">privacy policy</a>.</p>
<p>The fully commented config is <a href="{GH}/blob/main/sshsentry.yaml">sshsentry.yaml in the repo</a>.</p>''')

    cli = [("-c, --config PATH", "YAML config path (default /etc/sshsentry/sshsentry.yaml)"), ("--log PATH", "override the log file path"),
           ("--db PATH", "override the SQLite state path"), ("--replay FILE, --dry-run FILE", "process FILE from the start and print alerts; never sends anything"),
           ("--once", "process new log lines once, then exit (timers)"), ("--approve IP", "mark an IP as known for all users, then exit"),
           ("--test-alerts", "send a sample alert to each enabled destination"), ("--digest-now", "print a digest of the last 24 h now (sent if digest.send; print-only with --replay)"),
           ("--digests [N]", "list the last N stored daily digests (default 7)"), ("--digest DATE", "show one stored daily digest (YYYY-MM-DD)"),
           ("--resend DATE", "send a stored daily digest again"), ("--export-digests START END", "zip stored digests for a date range, with manifest + SHA-256"),
           ("-o, --output PATH", "with --export-digests: zip path"), ("--host-label LABEL", "with --export-digests: label in the manifest"),
           ("--verify-chain", "recompute the local digest hash chain"), ("--verify-export ZIP", "verify an exported zip (no config needed)"),
           ("--expected-head HASH", "with --verify-export: a chain hash that left the server earlier"),
           ("--suggest-threshold", "print the learn-mode threshold suggestion"), ("--accept-threshold", "write the suggested brute-force threshold into the config"),
           ("--show-shared", "list everything this install has shared"), ("--forget-me", "delete local sharing history (and ask the endpoint to delete it, if configured)"),
           ("--local-only", "with --forget-me: skip the remote request"), ("--format text|json", "output format for digests, replay, suggestions, sharing and verify commands")]
    rows = "".join(f"<tr><td><code>{E(a)}</code></td><td>{E(b)}</td></tr>" for a, b in cli)
    doc("/docs/cli.html", "docs/cli.html", "CLI reference", "Every sshsentry command-line option in 0.2.0.", f'''
<h1>CLI reference</h1><p class="lead">From <code>sshsentry --help</code> in 0.2.0. Installed from PyPI the command is <code>sshsentry</code>; from the repo it's <code>python3 sshsentry.py</code>.</p>
<div class="tablewrap"><table><tr><th>Option</th><th>What it does</th></tr>{rows}</table></div>
<h2>Common recipes</h2>{term("shell", """sudo sshsentry --approve 198.51.100.23            # stop new-IP alerts for your office IP
sudo sshsentry --test-alerts                      # check email/Slack/webhook
sudo sshsentry --digests                          # last 7 days at a glance
sudo sshsentry --export-digests 2026-10-01 2026-10-31 -o oct.zip
sshsentry --verify-export oct.zip --expected-head 3f9a0c1d2b4e""", "sh")}
<p>JSON documents carry a <code>"schema"</code> field (for example <code>sshsentry.replay/1</code>). Timestamps are UTC ISO-8601.</p>''')

    doc("/docs/replay.html", "docs/replay.html", "Replaying logs", "Use --replay to test sshsentry against any auth log without sending anything.", f'''
<h1>Replaying logs</h1><p class="lead"><code>--replay FILE</code> (alias <code>--dry-run</code>) reads a log from the start, prints alerts, and never sends email, Slack, webhook or sharing reports.</p>
<p>Always use a throwaway state database so your real baseline is untouched:</p>{term("shell", "sshsentry -c sshsentry.yaml --db /tmp/sshsentry-test.db --replay sample-auth.log", "sh")}
<p>Expected output for the bundled sample:</p>{term("replay", REPLAY)}
<h2>Add a digest</h2><p><code>--replay FILE --digest-now</code> also prints a digest for that file:</p>{term("digest", REPLAY_DIGEST, "plain")}
<h2>Your own logs</h2><ul><li>Debian/Ubuntu: <code>/var/log/auth.log</code>; RHEL/Fedora: <code>/var/log/secure</code>. Rotated files work too.</li>
<li>journald-only systems: <code>journalctl -u ssh -o short &gt; ssh.log</code> then replay that file.</li>
<li>Both classic syslog and ISO-8601 timestamps are parsed, from <code>sshd</code> and newer <code>sshd-session</code> processes.</li>
<li>Add <code>--format json</code> for machine-readable output.</li></ul>
<div class="callout">Prefer not to install anything? The <a href="/try.html">live demo</a> runs a JavaScript port of the rules in your browser; paste a log, nothing is uploaded.</div>''')

    doc("/docs/fail2ban.html", "docs/fail2ban.html", "Using sshsentry with fail2ban", "sshsentry detects and explains; fail2ban blocks. How to run both.", f'''
<h1>With fail2ban</h1><p class="lead">They do different jobs. Run both.</p>
<div class="tablewrap"><table><tr><th></th><th>fail2ban</th><th>sshsentry</th></tr>
<tr><td>Blocks IPs</td><td>Yes</td><td>No (detection only)</td></tr>
<tr><td>Tells you a login succeeded after failures</td><td>No</td><td>Yes (HIGH / CRITICAL)</td></tr>
<tr><td>New user, new SSH key, new IP/country</td><td>No</td><td>Yes</td></tr>
<tr><td>Plain-English alerts, daily digest</td><td>No</td><td>Yes</td></tr></table></div>
<p>A sensible small-server setup: key-only SSH (<code>PasswordAuthentication no</code>), fail2ban's <code>sshd</code> jail, a firewall, and sshsentry to tell you when something gets past them or changes underneath you.</p>
<p>Both read the same auth log and don't interfere with each other. fail2ban bans may mean you see fewer brute-force alerts, which is fine: the alerts that remain are the interesting ones.</p>''')

    faq = [("Does it change my server?", "No. It reads the auth log, /etc/passwd and authorized_keys, and writes only its own SQLite state file (plus optional digest text files and an optional alert log). It never edits firewall rules, accounts or keys."),
           ("Does it block attacks?", "No. sshsentry is detection only. Use fail2ban and a firewall for blocking. A responder is planned and appears only as a simulation in the live demo; it is not in this release."),
           ("Does anything leave my machine?", "Only if you turn it on: email, Slack or webhook alerts, the digest delivery, or opt-in sharing of attacker IPs. All are off by default."),
           ("How noisy is it?", "The first run is a silent baseline, repeats are muted for 60 minutes, and you can --approve your own IPs. Each destination can filter by min_severity."),
           ("What does it need?", "Linux, Python 3.9+ and PyYAML. geoip2 and a free GeoLite2 database are optional, for country checks."),
           ("Is it for big fleets or compliance?", "No. It's for one or a few servers: small businesses, indie developers and homelabs."),
           ("Can I see the code?", "Yes, it's one MIT-licensed Python file on GitHub.")]
    q = "".join(f'<details class="faq"><summary>{E(a)}</summary><p>{E(b)}</p></details>' for a, b in faq)
    doc("/docs/faq.html", "docs/faq.html", "FAQ", "Common questions about sshsentry.", f'<h1>FAQ</h1>{q}<p style="margin-top:28px">Still stuck? Ask in <a href="{GH}/discussions">Discussions</a>.</p>')

    ts = [("\"PyYAML is required: pip install pyyaml\"", "Install it for the Python you run sshsentry with: <code>sudo apt install python3-yaml</code>, <code>sudo dnf install python3-pyyaml</code>, or a venv."),
          ("\"note: country checks disabled\"", "geoip2 or the GeoLite2 database is missing. Harmless; install both to enable the new-country rule."),
          ("No alerts at all", "The first run is a silent baseline, so try <code>--replay</code> on the sample log. Check it is running as root and reading the right file (<code>--log</code> to override)."),
          ("No /var/log/auth.log or /var/log/secure", "Your system logs only to journald. Install rsyslog, or export with <code>journalctl -u ssh -o short &gt; file</code> and use <code>--replay</code>."),
          ("Email or Slack never arrives", "Run <code>--test-alerts</code>: it prints a result per destination and exits 1 on failure. Check the startup warnings (bad URL, missing SMTP settings, missing password env var). Add the sender to your contacts to avoid spam folders."),
          ("Too many LOW alerts for my own logins", "Approve your addresses: <code>sshsentry --approve IP</code>, or set <code>min_severity: MEDIUM</code> on a destination."),
          ("Brute-force threshold feels wrong", "Turn on learn mode for a few days and run <code>--suggest-threshold</code>. Treat the number as information; on internet-facing servers it tends to be higher than 5.")]
    t = "".join(f"<h2>{E(a)}</h2><p>{b}</p>" for a, b in ts)
    doc("/docs/troubleshooting.html", "docs/troubleshooting.html", "Troubleshooting", "Fixes for common sshsentry setup problems.", f'<h1>Troubleshooting</h1>{t}<p style="margin-top:28px">Found a parser gap? Open an <a href="{GH}/issues">issue</a> with a redacted log line.</p>')

def md(src):
    out, para, lst = [], [], False
    inl = lambda s: re.sub(r"\*([^*]+)\*", r"<em>\1</em>", re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", re.sub(r"`([^`]+)`", r"<code>\1</code>", E(s, quote=False))))
    def flush():
        nonlocal lst
        if para: out.append("<p>" + inl(" ".join(para)) + "</p>"); para.clear()
        if lst: out.append("</ul>"); lst = False
    for line in src.splitlines():
        m = re.match(r"^(#{1,3}) (.*)", line)
        if m: flush(); n = len(m.group(1)); out.append(f"<h{n}>{inl(m.group(2))}</h{n}>"); continue
        if re.match(r"^\s*[-*] ", line):
            if para: out.append("<p>" + inl(" ".join(para)) + "</p>"); para.clear()
            if not lst: out.append("<ul>"); lst = True
            out.append("<li>" + inl(re.sub(r"^\s*[-*] ", "", line)) + "</li>"); continue
        if not line.strip() or line.strip() == "---": flush(); continue
        para.append(line.strip())
    flush(); return "\n".join(out)

def privacy():
    body = md(open(os.path.join(ROOT, "sshsentry-privacy-policy.md"), encoding="utf-8").read())
    page("/privacy.html", "Privacy policy | sshsentry", "What sshsentry keeps on your machine and what opt-in sharing sends.",
         f'<div class="wrap" style="padding:48px 24px 80px"><article class="doc" style="margin:0 auto">{body}</article></div>', "privacy.html")

def notfound():
    page("/404.html", "Not found | sshsentry", "Page not found.", f'''<section class="hero"><div class="wrap"><span class="label">0x194 not found</span><h1>No such page.</h1>
<p class="lead">Checksum mismatch: the path you asked for isn't on this site.</p>{term("sshsentry", "$ sshsentry --verify-path\nFAIL  path not found\n      try / or /docs/", "plain", ln=False)}
<div class="cta"><a class="btn primary" href="/">Home</a><a class="btn" href="/docs/">Docs</a><a class="btn" href="/try.html">Live demo</a></div></div></section>''', "404.html")

def sitemap():
    urls = ["/", "/features.html", "/try.html", "/privacy.html"] + [h for h, _ in DOCS]
    open(os.path.join(OUT, "sitemap.xml"), "w").write('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "".join(f"  <url><loc>{SITE}{u}</loc></url>\n" for u in urls) + "</urlset>\n")
    open(os.path.join(OUT, "robots.txt"), "w").write(f"User-agent: *\nAllow: /\nSitemap: {SITE}/sitemap.xml\n")

if __name__ == "__main__":
    os.makedirs(os.path.join(OUT, "assets"), exist_ok=True)
    shutil.copy(os.path.join(ROOT, "site_src", "site.css"), os.path.join(OUT, "assets", "site.css"))
    home(); features(); docs(); privacy(); notfound(); sitemap(); print("built", OUT)
