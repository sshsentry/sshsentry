#!/usr/bin/env python3
"""Run the whole sshsentry test suite (stdlib unittest; no pytest needed).

  python3 tests/run_all.py            # all Python-program tests
  python3 tests/run_all.py -k digest  # only tests whose id contains "digest"
  python3 tests/run_all.py --demo     # also run the demo checkers (needs google-chrome or chromium)
  python3 tests/run_all.py --list     # list test ids
The interpreter must have PyYAML (see tests/README.md).
"""
import argparse, os, shutil, subprocess, sys, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def iter_tests(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from iter_tests(t)
        else:
            yield t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", action="append", default=[], help="only run tests whose id contains this (repeatable)")
    ap.add_argument("--demo", action="store_true", help="also run demo/verify_*.py (needs google-chrome/chromium)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-q", action="store_true", help="quiet: only failures and the summary")
    a = ap.parse_args()
    try:
        import yaml  # noqa: F401
    except ImportError:
        sys.exit("PyYAML is missing for this interpreter. See tests/README.md (python3 -m venv ... && pip install pyyaml).")
    from helpers import Base
    from capture_server import CaptureServer
    from smtp_capture import SMTPCapture
    loaded = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)
    tests = [t for t in iter_tests(loaded) if not a.k or any(k in t.id() for k in a.k)]
    if a.list:
        print("\n".join(t.id() for t in tests)); print(f"{len(tests)} tests"); return 0
    Base.http, Base.smtp = CaptureServer().start(), SMTPCapture().start()
    t0 = time.time()
    res = unittest.TextTestRunner(verbosity=1 if a.q else 2, stream=sys.stdout).run(unittest.TestSuite(tests))
    failed = len(res.failures) + len(res.errors)
    print(f"\nPYTHON SUITE: {res.testsRun - failed - len(res.skipped)} passed, {failed} failed, "
          f"{len(res.skipped)} skipped, {res.testsRun} run in {time.time() - t0:.0f}s")
    demo_ok = True
    if a.demo:
        chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
        if not chrome:
            print("DEMO CHECKS: skipped (no google-chrome/chromium on PATH)")
        else:
            for f in ("verify_demo.py", "verify_calculator.py", "verify_walkthrough.py", "verify_responder.py", "verify_disclaimer.py"):
                p = subprocess.run([sys.executable, os.path.join(HERE, "..", "demo", f)], capture_output=True, text=True)
                n_pass, n_fail = p.stdout.count("\nPASS") + p.stdout.startswith("PASS"), p.stdout.count("FAIL  ")
                print(f"DEMO {f}: {'OK' if p.returncode == 0 else 'FAILED'} ({n_pass} PASS, {n_fail} FAIL)")
                if p.returncode:
                    print(p.stdout[-3000:], p.stderr[-2000:]); demo_ok = False
    return 0 if res.wasSuccessful() and demo_ok else 1


if __name__ == "__main__":
    sys.exit(main())
