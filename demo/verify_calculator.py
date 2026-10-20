# Headless check (needs google-chrome): the savings calculator in index.html must reproduce the worked
# examples in sshsentry-financial-analysis.md (section 3) with its default inputs, and handle "no manual review".
# Run: python3 demo/verify_calculator.py
import subprocess, json, re, html, os, sys
PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"); ok = True
def page(q=""):
    out = subprocess.run(["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", "--virtual-time-budget=3000",
                          "--dump-dom", f"file://{PAGE}{q}"], capture_output=True, text=True, timeout=90).stdout
    cell = lambda i: html.unescape(re.search(rf'<td id="{i}"[^>]*>(.*?)</td>', out, re.S).group(1))
    cell.deemph = lambda i: bool(re.search(rf'<td id="{i}" class="deemph">', out))
    data = json.loads(html.unescape(re.search(r'<pre id="calc-result" hidden="">(.*?)</pre>', out, re.S).group(1)))
    note_hidden = bool(re.search(r'<div id="c_noreview" class="note" hidden="">', out))
    return cell, data, note_hidden
def out_head(q):
    out = subprocess.run(["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", "--virtual-time-budget=3000",
                          "--dump-dom", f"file://{PAGE}{q}"], capture_output=True, text=True, timeout=90).stdout
    return re.search(r'<th id="c_agg_head">(.*?)</th>', out).group(1)
def check(name, cond, detail=""):
    global ok; ok &= bool(cond); print(f"{'PASS' if cond else 'FAIL'}  {name}{('  ' + detail) if detail else ''}")
# Analysis table: (servers, attempts/day) -> scenario -> (hours, labor, EAB, total, subscription/yr, payback as published)
TABLE = {(1, 500):    {"c": ("9.3", "$631", "~$1", "$633", "$36", "0.7 months"),
                       "a": ("20.3", "$1,381", "~$4,686", "$6,067", "$36", "<0.1 months")},
         (5, 2000):   {"c": ("49.0", "$3,334", "~$1", "$3,336", "$180", "0.6 months"),
                       "a": ("106.6", "$7,259", "~$4,686", "$11,945", "$180", "0.2 months")},
         (20, 5000):  {"c": ("202.8", "$13,807", "~$1", "$13,808", "$720", "0.6 months"),
                       "a": ("440.2", "$29,974", "~$4,686", "$34,660", "$720", "0.3 months")}}
for (n, a), rows in TABLE.items():
    q = "" if (n, a) == (1, 500) else f"?servers={n}&attempts={a}"   # (1, 500) = the page's own defaults
    cell, data, _ = page(q)
    for k, sc in (("c", "cautious"), ("a", "aggressive")):
        got = tuple(cell(f"c_{x}_{k}") for x in "hletsp")
        exp = rows[k]
        same = got[:5] == exp[:5]
        check(f"{n} server(s), {a}/day, {sc}: hours/labor/EAB/total/subscription match analysis", same, f"got {got[:5]}")
        if got[5] == exp[5]:
            check(f"{n} server(s), {a}/day, {sc}: payback matches analysis", True, got[5])
        else:
            m = data["conservative" if k == "c" else "aggressive"]["paybackMonths"]
            print(f"NOTE  {n} server(s), {a}/day, {sc}: payback {got[5]} (exact {m:.3f} mo) vs analysis '{exp[5]}' "
                  "(analysis rounding; formula followed)")
cell, data, hidden = page("?review=no")
check("no manual review: hours 0.0 and time value $0 in both scenarios",
      [cell(f"c_{x}_{k}") for x in "hl" for k in "ca"] == ["0.0", "0.0", "$0", "$0"])
check("no manual review: total = breach estimate only (~$1 / ~$4,686); note shown",
      cell("c_t_c") == "$1" and cell("c_t_a") == "$4,686" and not hidden)
check("no manual review: payback uses breach estimate only; aggressive breach/total/payback de-emphasized",
      cell("c_p_c") == "289 months (~24 years)" and cell("c_p_a") == "<0.1 months"
      and all(cell.deemph(i) for i in ("c_e_a", "c_t_a", "c_p_a")) and not any(cell.deemph(i) for i in ("c_e_c", "c_t_c", "c_p_c"))
      and "not meaningful" in out_head("?review=no"), f"{cell('c_p_c')} / {cell('c_p_a')}")
cell, data, hidden = page("?rate=68&ratetype=loaded&price=0")
check("loaded/MSP rate used as is; price 0 -> immediate payback; review=yes -> nothing de-emphasized",
      abs(data["conservative"]["rate"] - 68) < 1e-9 and cell("c_s_c") == "$0" and cell("c_p_c").startswith("immediate") and hidden
      and not any(cell.deemph(i) for i in ("c_e_a", "c_t_a", "c_p_a")))
sys.exit(0 if ok else 1)
