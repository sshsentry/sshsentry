# Headless check (needs google-chrome + PyYAML): the JS demo must reproduce the Python --replay --digest-now output exactly.
# Run: python3 demo/verify_demo.py
import subprocess, json, re, html, sys, os, tempfile
D = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); PY = sys.executable; ok = True
def chrome(q=""):
    out = subprocess.run(["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", "--virtual-time-budget=3000",
                          "--dump-dom", f"file://{D}/demo/try.html{q}"], capture_output=True, text=True, timeout=90).stdout
    m = re.search(r'<pre id="result" hidden="">(.*?)</pre>', out, re.S)
    return json.loads(html.unescape(m.group(1)))
def python(extra_yaml=""):
    t = tempfile.mkdtemp(); cfg = os.path.join(t, "c.yaml")
    open(cfg, "w").write(open(f"{D}/sshsentry.yaml").read() + "\n" + extra_yaml)
    o = subprocess.run([PY, f"{D}/sshsentry.py", "-c", cfg, "--db", f"{t}/s.db", "--replay", f"{D}/sample-auth.log",
                        "--digest-now"], capture_output=True, text=True).stdout
    alerts = [l for l in o.splitlines() if re.match(r"^(\[learning: not sent\] )?\[\d{4}-", l)]
    return alerts, o[o.index("sshsentry daily digest"):].rstrip("\n")
for name, q, y in [("defaults", "", ""),
                   ("escalation on", "?escalation=1", "alerting: {enabled: true}"),
                   ("bf_failures=3, lookback=5", "?bf_failures=3&laf_lookback=5",
                    "rules: {brute_force: {failures: 3}, login_after_failures: {lookback_minutes: 5}}"),
                   ("learn mode", "?learn=1", "learn_mode: {enabled: true}"),
                   ("bf_failures=8, cooldown=0", "?bf_failures=8&cooldown=0", "cooldown_minutes: 0\nrules: {brute_force: {failures: 8}}"),
                   ("new_ip off, laf_failures=7", "?new_ip=0&laf_failures=7",
                    "rules: {new_ip: {enabled: false}, login_after_failures: {failures: 7}}")]:
    js = chrome(q); pa, pd = python(y)
    same = js["alert_lines"] == pa and js["digest"] == pd
    ok &= same
    print(f"{'PASS' if same else 'FAIL'}  demo == python ({name}): {js['alerts']} alerts, {js['failed_logins']} failed logins, "
          f"{js['distinct_ips']} IPs, top offender {js['top_offender']}")
    if not same:
        print(" js:", js["alert_lines"], js["digest"], "\n py:", pa, pd, sep="\n")
    if name == "escalation on":
        crit = any("CRITICAL: ESCALATION" in l for l in js["alert_lines"]); ok &= crit
        print(f"{'PASS' if crit else 'FAIL'}  escalation produces a CRITICAL alert in both")
    if name == "defaults":
        exp = js["alerts"] == 6 and js["failed_logins"] == 12 and js["distinct_ips"] == 2 and js["top_offender"] == "203.0.113.45"
        ok &= exp; print(f"{'PASS' if exp else 'FAIL'}  expected counts 6 / 12 / 2 / 203.0.113.45")
src = open(f"{D}/demo/try.html").read()
selfc = not re.search(r'(src|href)="(https?:)?//', src) and "fetch(" not in src and "XMLHttpRequest" not in src
ok &= selfc; print(f"{'PASS' if selfc else 'FAIL'}  self-contained (no external src/href, no fetch/XHR)")
sys.exit(0 if ok else 1)
