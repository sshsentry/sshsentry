# Headless check (needs google-chrome): the simulated responder that follows the walkthrough's CRITICAL escalation.
# Answers are given through the page's own handlers (real keydown events for y/n/Enter, button clicks for yes/no).
# Run: python3 demo/verify_responder.py
import subprocess, json, re, html, os, sys
PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "try.html"); ok = True
def dom(q="", budget=6000, extra=()):
    return subprocess.run(["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", f"--virtual-time-budget={budget}",
                           *extra, "--dump-dom", f"file://{PAGE}{q}"], capture_output=True, text=True, timeout=120).stdout
def res(out, i="resp-result"):
    return json.loads(html.unescape(re.search(rf'<pre id="{i}" hidden="">(.*?)</pre>', out, re.S).group(1)))
def check(name, cond, detail=""):
    global ok; ok &= bool(cond); print(f"{'PASS' if cond else 'FAIL'}  {name}{('  ' + detail) if detail else ''}")
outcomes = lambda d: [s["outcome"] for s in d["steps"]]
PROMPTS = ["Lock the account? [y/N]", "Block the IP? [y/N]", "Rotate the password? [y/N]", "Replace keys? [y/N]"]

src = open(PAGE).read()
check("labeled as a simulation; nothing runs on a real server",
      "Simulation: the responder is specified but not yet in the Python tool." in src and "nothing runs on any real server" in src)
d = res(dom("?walk=19"))
check("responder hidden before the CRITICAL escalation", d["state"] == "idle" and not d["visible"])
o = dom("?walk=20"); d = res(o)
check("after CRITICAL: snapshot runs automatically, then pauses at the first prompt with focus on No",
      d["visible"] and d["state"] == "prompt" and d["prompts"] == PROMPTS[:1] and outcomes(d) == ["done"]
      and d["focus"] == "rs-no" and d["promptShown"] and d["ip"] == "192.0.2.77" and d["user"] == "deploy" and "mkdir -m 700 /root/sshsentry-evidence-" in d["terminal"])
check("prompt region is labeled; terminal and report are aria-live",
      'id="rs-prompt" class="rs-prompt" role="group" aria-labelledby="rs-q"' in src
      and 'id="rs-term" class="term" role="log" aria-live="polite"' in src and 'id="rs-report" aria-live="polite"' in src)
d = res(dom("?walk=20&resp=y,y,y,y"))
check("keyboard y x4: prompts asked one at a time, in order; all steps done; prompt hidden afterwards",
      d["state"] == "done" and not d["promptShown"] and d["prompts"] == PROMPTS and outcomes(d) == ["done"] * 5, str(outcomes(d)))
cmds = ["usermod -L -e 1 deploy", "pkill -KILL -u deploy", "ufw insert 1 deny from 192.0.2.77", "passwd deploy",
        "authorized_keys.sshsentry-bak", ": > ~deploy/.ssh/authorized_keys"]
check("each step shows the commands it would run", all(c in d["terminal"] for c in cmds))
d = res(dom("?walk=20&resp=n,n,Enter,n"))
check("keyboard n/Enter: all skipped (Enter = No)", outcomes(d) == ["done"] + ["skipped"] * 4 and "usermod" not in d["terminal"])
d = res(dom("?walk=20&resp=yes,no,yes,no"))
check("button clicks: yes/no map to done/skipped", outcomes(d) == ["done", "done", "skipped", "done", "skipped"], str(outcomes(d)))
d = res(dom("?walk=20&resp=y,y,n,n&preblocked=1"))
check("pre-blocked scenario: Block -> 'already done' and ufw not re-run",
      outcomes(d) == ["done", "done", "already done", "skipped", "skipped"] and "ufw insert" not in d["terminal"])
d = res(dom("?walk=20&resp=y,y,y,n&again=1", budget=9000))
check("Run again with the same answers: completed steps are 'already done', skipped stay skipped",
      d["runs"] == 2 and outcomes(d) == ["done", "already done", "already done", "already done", "skipped"], str(outcomes(d)))
d = res(dom("?walk=20&resp=n,n,n,n"))
lg = d["findings"][0]["detail"]
check("logins check derived from the engine/sample log (6 failures, success 02:16:08 as deploy)",
      "6 failed attempts (" in lg and "02:14:52 to " in lg and "02:15:55)" in lg and "02:16:08" in lg and "'deploy'" in lg and any("cat /etc/shadow" in f["detail"] for f in d["findings"]))
check("every finding labeled expected / unexplained / can't tell",
      all(f["label"] in ("expected", "unexplained", "cant") for f in d["findings"]) and len(d["findings"]) >= 6)
for sc, title, lesson, extra in (("unexplained", "Recommend rebuild", "lessons/lesson-4.html", "Rebuild it from a known-good image"),
                                 ("data", "Call a professional", "lessons/lesson-5.html", "insurer first"),
                                 ("clean", "No unexplained changes found", None, "does not prove the server is clean")):
    o = dom(f"?walk=20&resp=n,n,n,n&scenario={sc}"); d = res(o)
    link_ok = (f'<a href="{lesson}" id="rs-lesson">' in o) if lesson else ('id="rs-lesson"' not in o)
    check(f"scenario '{sc}': verdict '{title}'{' + ' + lesson if lesson else ' + caveat'}",
          d["verdict"]["title"] == title and link_ok and extra in d["verdict"]["text"] and "Response report" in o
          and '<table class="rs">' in o)
d = res(dom("?resp=y,y,y,y&scenario=clean", budget=60000))
w = res(dom("?resp=y,y,y,y&scenario=clean", budget=60000), "walk-result")
check("playback pauses while responding, then resumes to the digest", d["state"] == "done" and w["step"] == 24 and w["digest"])
o = dom("?autoplay=0&walk=20&resp=y,n,y,n&then=restart"); d = res(o); w = res(o, "walk-result")
check("Restart resets the responder", d["state"] == "idle" and not d["visible"] and d["steps"] == [] and d["terminal"] == ""
      and w["step"] == 0)
d = res(dom("?walk=20", extra=("--force-prefers-reduced-motion",)))
check("reduced motion: no typing delay (instant), still waits at the prompt", d["instant"] and d["state"] == "prompt")
sys.exit(0 if ok else 1)
