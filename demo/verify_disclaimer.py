# Checks the disclaimer in README.md and demo/try.html (exact text, placement) and the demo's
# "In real use" line before the simulated responder. Needs google-chrome for the rendered-page checks.
# Run: python3 demo/verify_disclaimer.py
import subprocess, json, re, html, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
PAGE = os.path.join(HERE, "try.html"); ok = True
DISCLAIMER = [
    "sshsentry helps you notice and respond to suspicious logins. It can't guarantee your server is secure or stop every break-in.",
    "The responder runs real, destructive commands on your server: it locks accounts, blocks IPs, and rotates passwords and keys. "
    "You're responsible for every step you approve, so read each one before you say yes. "
    "When it says no unexplained changes were found, that doesn't prove your server is clean.",
    "If an incident involves customer data, legal duties, or anything you can't explain, get a professional. "
    "If you have cyber insurance, call your insurer's hotline before you hire anyone.",
    "sshsentry is provided as-is under the MIT license, with no warranty of any kind."]
REAL = "In real use, these steps change your server. Read each one before approving."
POINTER = "See the Disclaimer below before using --respond."
def check(name, cond, detail=""):
    global ok; ok &= bool(cond); print(f"{'PASS' if cond else 'FAIL'}  {name}{('  ' + detail) if detail else ''}")
def dom(q=""):
    return subprocess.run(["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", "--virtual-time-budget=6000",
                           "--dump-dom", f"file://{PAGE}{q}"], capture_output=True, text=True, timeout=120).stdout
text = lambda frag: html.unescape(re.sub(r"<[^>]+>", "", frag)).strip()

readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
h2 = re.findall(r"^## (.+)$", readme, re.M)
check("README: '## Disclaimer' is directly above '## License', at the end", h2[-2:] == ["Disclaimer", "License"], str(h2[-3:]))
sec = readme.split("## Disclaimer\n", 1)[1].split("\n## License", 1)[0]
paras = [p.strip() for p in sec.strip().split("\n\n")]
check("README: disclaimer is exactly the four given paragraphs", paras == DISCLAIMER, f"{len(paras)} paragraphs")
lic = readme.split("## License", 1)[1]
check("README: License section says MIT (matches the disclaimer)", "MIT" in lic)
check("README: pointer 'See the Disclaimer below before using --respond.' appears before the Disclaimer section",
      readme.count(POINTER) == 1 and readme.index(POINTER) < readme.index("## Disclaimer"))
demo_par = next(l for l in readme.splitlines() if l.startswith("**Even quicker: the demo page.**"))
check("README: demo paragraph mentions the simulated responder, says it isn't in the Python tool yet, lists responder.png",
      "simulated responder" in demo_par and "not yet in the Python tool" in demo_par and "demo/responder.png" in demo_par
      and POINTER in demo_par)
src_py = open(os.path.join(ROOT, "sshsentry.py"), encoding="utf-8").read()
check("README does not claim --respond is implemented (sshsentry.py has no --respond)", "--respond" not in src_py)

src = open(PAGE, encoding="utf-8").read()
for name, s in (("README", sec), ("demo", src)):
    check(f"{name}: straight apostrophes only (no curly quotes)", not re.search("[\u2018\u2019\u201c\u201d]", s))

o = dom("?autoplay=0")
m = re.search(r'<section id="disclaimer"[^>]*>(.*?)</section>', o, re.S)
got = [text(p) for p in re.findall(r"<p>(.*?)</p>", m.group(1), re.S)] if m else []
check("demo: disclaimer section with the same four paragraphs as the README", got == DISCLAIMER and got == paras)
check("demo: disclaimer has a heading and is labeled", m and '<h2 id="disc-title">Disclaimer</h2>' in m.group(1)
      and 'aria-labelledby="disc-title"' in o)
i_d, i_s = o.find('<section id="disclaimer"'), o.find('<section id="savings-foot"')
i_f = o.find('id="features"'); i_t = o.find('id="try"')
check("demo: disclaimer sits in the footer area, directly above the collapsed savings calculator",
      0 < i_f < i_t < i_d < i_s and re.fullmatch(r"\s*", o[o.find("</section>", i_d) + 10:i_s]) is not None
      and re.search(r'<details class="foot" id="savings">', o[i_s:]) and "<details" not in o[i_d:i_s])
check("demo: disclaimer is not hidden or collapsed", 'hidden' not in o[i_d:o.find(">", i_d)])

r = re.search(r'<div id="responder"[^>]*>(.*?)<pre id="rs-term"', o, re.S).group(1)
check("demo: 'In real use' line inside the responder, after the simulation labels and before the terminal",
      REAL in text(r) and r.find("Simulation: the responder is specified but not yet in the Python tool.") < r.find(REAL)
      and "nothing runs on any real server" in r[:r.find(REAL)])
o = dom("?walk=20")
d = json.loads(html.unescape(re.search(r'<pre id="resp-result" hidden="">(.*?)</pre>', o, re.S).group(1)))
blk = o[o.find('<div id="responder"'):o.find('<pre id="rs-term"')]
check("demo: line is shown when the responder starts (prompt 1 waiting)",
      d["visible"] and d["state"] == "prompt" and 'id="rs-real"' in blk and "hidden" not in blk[blk.find('id="rs-real"') - 40:blk.find(REAL)])
sys.exit(0 if ok else 1)
