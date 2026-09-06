#!/usr/bin/env python3
"""Reproducible eval harness for cryptojack_detect.

Spawns a labeled set of processes -- miners that each trip a STRONG signal
(miner signature or mining-pool connection) plus corroboration, and benign
look-alikes that trip only weak signals -- runs scan(), and asserts
precision == recall == 1.0. Exit code 0 on pass, 1 on failure (CI-friendly).
"""
import os, sys, time, socket, shutil, threading, subprocess
import cryptojack_detect as cj

POOL_PORT = 4444
BURN = "x=0" + chr(10) + "while True: x=(x*x+7)%2147483647"
IDLE = "import time" + chr(10) + "while True: time.sleep(0.5)"
CONNECT = ("import socket,time" + chr(10) +
           "s=socket.socket(); s.connect(('127.0.0.1', " + str(POOL_PORT) + "))" + chr(10) +
           "while True: time.sleep(0.5)")

def listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", POOL_PORT)); srv.listen(16)
    held = []
    while True:
        try:
            c, _ = srv.accept(); held.append(c)
        except OSError:
            break

def cp(name):
    dst = os.path.join("/tmp", name)
    shutil.copy(sys.executable, dst); os.chmod(dst, 0o755)
    return dst

def spawn(path, code, extra=None):
    return subprocess.Popen([path, "-c", code] + (extra or []),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    threading.Thread(target=listener, daemon=True).start()
    time.sleep(0.3)
    made = []
    procs = {}
    def mk(name):
        p = cp(name); made.append(p); return p
    procs["M1"] = spawn(mk("xmrig"),   IDLE)                    # signature + suspicious path
    procs["M2"] = spawn(mk("worker"),  CONNECT)                # pool + suspicious path
    procs["M3"] = spawn(mk("minerd"),  CONNECT)                # signature + pool
    procs["B1"] = spawn(sys.executable, BURN)                  # legit sustained CPU (weak only)
    procs["B2"] = spawn(sys.executable, IDLE)                  # idle
    procs["B3"] = spawn(mk("mybuild"), BURN)                   # build in /tmp: path+cpu (both weak)
    procs["B4"] = spawn(sys.executable, IDLE, ["xmrig-note"])  # 'xmrig' only in an arg
    time.sleep(1.0)
    rows = cj.scan()
    high = set(pid for is_high, _, pid, _, _, _, _, _ in rows if is_high)
    expect = {"M1": True, "M2": True, "M3": True,
              "B1": False, "B2": False, "B3": False, "B4": False}
    tp = fp = fn = tn = 0
    print("LABEL  EXPECT  VERDICT")
    for lbl, pr in procs.items():
        got = pr.pid in high
        exp = expect[lbl]
        if exp and got: tp += 1
        elif exp and not got: fn += 1
        elif (not exp) and got: fp += 1
        else: tn += 1
        print("%-5s  %-6s  %s" % (lbl, "MINER" if exp else "benign", "HIGH" if got else "-"))
    for pr in procs.values(): pr.terminate()
    for pr in procs.values():
        try: pr.wait(timeout=3)
        except Exception: pr.kill()
    for f in made:
        try: os.remove(f)
        except OSError: pass
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    print("TP=%d FP=%d FN=%d TN=%d  Precision=%.2f Recall=%.2f F1=%.2f"
          % (tp, fp, fn, tn, prec, rec, f1))
    ok = (prec == 1.0 and rec == 1.0)
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

def _run_browser_suite():
    # Keep CI's single `python test_detector.py` command covering the
    # browser detector too: run its suite and propagate a failure.
    here = os.path.dirname(os.path.abspath(__file__))
    bt = os.path.join(here, "test_browser_detector.py")
    if not os.path.exists(bt):
        return 0
    print("\n=== browser detector suite ===")
    return subprocess.run([sys.executable, bt], cwd=here).returncode


if __name__ == "__main__":
    rc = main()
    if rc == 0:
        rc = _run_browser_suite()
    sys.exit(rc)
