# Headless check (needs google-chrome): the live walkthrough in index.html, stepped to the end, must show the
# engine's alerts (MEDIUM brute force, then CRITICAL escalation) and the digest the engine produces, and must
# not autoplay under prefers-reduced-motion. Run: python3 demo/verify_walkthrough.py
import subprocess, json, re, html, os, sys
PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"); ok = True
def dom(q="", budget=3000, extra=()):
    return subprocess.run(["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", f"--virtual-time-budget={budget}",
                           *extra, "--dump-dom", f"file://{PAGE}{q}"], capture_output=True, text=True, timeout=90).stdout
def pre(out, i):
    return json.loads(html.unescape(re.search(rf'<pre id="{i}" hidden="">(.*?)</pre>', out, re.S).group(1)))
def check(name, cond, detail=""):
    global ok; ok &= bool(cond); print(f"{'PASS' if cond else 'FAIL'}  {name}{('  ' + detail) if detail else ''}")

# Reference: the page's own "try your own log" engine on the full sample log with escalation on.
ref = pre(dom("?escalation=1&walk=0"), "result")
end_out = dom("?walk=end"); end = pre(end_out, "walk-result")
sev = [a["severity"] for a in end["alerts"]]
check("stepped to end: all lines shown, not playing", end["step"] == end["total"] == 24 and not end["playing"]
      and end_out.count('class="logline') == 24)
check("MEDIUM brute-force alerts fire (2), then CRITICAL escalation after them",
      [a["rule"] for a in end["alerts"]].count("brute_force") == 2 and "CRITICAL" in sev
      and sev.index("CRITICAL") > max(i for i, a in enumerate(end["alerts"]) if a["rule"] == "brute_force")
      and end["alerts"][sev.index("CRITICAL")]["rule"] == "brute_force_success", str(sev))
check("walkthrough alerts == engine replay of the full log (escalation on)",
      [a["line"] for a in end["alerts"]] == ref["alert_lines"], f"{len(end['alerts'])} alerts")
check("daily digest shown at the end == engine digest", end["digest"] == ref["digest"] and
      'id="wt-digestbox" hidden' not in end_out and "Failed logins: 12 from 2 IP address(es)." in end["digest"])
check("every walkthrough alert has a 'What to do' line; alerts region is aria-live",
      end_out.count('<div class="todo"><b>What to do: </b>') == len(end["alerts"]) and
      re.search(r'id="wt-alerts" role="log" aria-live="polite"', end_out))
# Incremental: each prefix shows exactly the engine's alerts so far (the escalation appears on line 20, deploy's login).
steps = {n: pre(dom(f"?walk={n}"), "walk-result") for n in (12, 19, 20)}
check("brute force from 203.0.113.45 appears by line 12; no CRITICAL yet at line 19; CRITICAL at line 20",
      any(a["rule"] == "brute_force" and "203.0.113.45" in a["line"] for a in steps[12]["alerts"])
      and "CRITICAL" not in [a["severity"] for a in steps[19]["alerts"]]
      and "CRITICAL" in [a["severity"] for a in steps[20]["alerts"][len(steps[19]["alerts"]):]] and steps[20]["digest"] is None)
check("prefix alerts are a prefix of the final alerts (no hardcoding, stable)",
      all([a["line"] for a in steps[n]["alerts"]] == [a["line"] for a in end["alerts"]][:len(steps[n]["alerts"])] for n in steps))
# Autoplay and reduced motion
auto = pre(dom("", budget=8000), "walk-result")
check("autoplay (normal motion) advances on its own", auto["autoplay"] and auto["step"] > 0, f"step {auto['step']} after 8 s virtual")
rm = pre(dom("", budget=8000, extra=("--force-prefers-reduced-motion",)), "walk-result")
check("prefers-reduced-motion: no autoplay (still at line 0, not playing)", rm["reducedMotion"] and not rm["autoplay"]
      and rm["step"] == 0 and not rm["playing"])
src = open(PAGE).read()
check("controls are real <button>s with aria-pressed on Play", all(f'<button id="wt-{b}" type="button"' in src for b in ("play", "step", "restart"))
      and 'id="wt-play" type="button" aria-pressed=' in src)
sys.exit(0 if ok else 1)
