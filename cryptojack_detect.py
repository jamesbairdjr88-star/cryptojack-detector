#!/usr/bin/env python3
"""cryptojack_detect.py - host-based cryptojacking detector (Phase 2 + adaptive CPU + allowlist).
Read-only. HIGH requires >=2 independent signals."""
import psutil, os, time, subprocess

MINER_NAMES = ["xmrig","minerd","cpuminer","cgminer","bfgminer","ethminer",
    "nbminer","phoenixminer","lolminer","t-rex","gminer","nanominer","xmr-stak"]
MINER_ARGS = ["stratum+tcp","stratum+ssl","--donate-level","--randomx","--coin=",
    "-o pool.","--rig-id","nicehash.com","--cpu-priority"]
MINING_POOL_PORTS = {3333,4444,5555,14444,45700,3357}  # trimmed 7777/8888/9999 - too commonly legit
SUSPICIOUS_DIRS = ("/tmp/","/dev/shm/","/var/tmp/","/private/tmp/")

# --- adaptive sustained-CPU parameters (replaces the fixed CPU_HIGH) ---
FLOOR_MAX   = 70.0   # cap: on an idle box a miner nearly maxes one core
FLOOR_FRAC  = 0.75   # a miner sits near its fair share; flag at 75% of it
ACTIVE_MIN  = 20.0   # a process counts as "active" (competing for CPU) above this
WINDOWS = 4; WINDOW_S = 1.0; REQUIRED_HIGH = 3

# --- Phase 4 allowlist: trusted heavy apps, only when in a trusted install dir ---
ALLOWLIST_NAMES = {"ffmpeg","ffmpeg.exe","x264","x265","handbrakecli","blender",
    "gcc","cc1","cc1plus","clang","clang++","make","cargo","rustc","node","java",
    "dockerd","containerd","obs"}
TRUSTED_DIRS = ("/usr/bin/","/usr/local/bin/","/bin/","/opt/","/usr/lib/")

def _self_tree():
    me = psutil.Process(); ignore = {me.pid}
    for parent in me.parents(): ignore.add(parent.pid)
    return ignore

def is_allowlisted(info):
    name = (info.get('name') or "").lower()
    exe  = info.get('exe') or ""
    return name in ALLOWLIST_NAMES and any(exe.startswith(d) for d in TRUSTED_DIRS)

def adaptive_floor(n_active, cores):
    """Per-process fair share of the cores, scaled. Shrinks as contention rises."""
    fair_share = cores * 100.0 / max(1, n_active)   # % of one core each active proc can get
    return min(FLOOR_MAX, FLOOR_FRAC * fair_share)

def multi_sample(ignore):
    cores = os.cpu_count() or 1
    procs = {}
    for p in psutil.process_iter(['pid','name','cmdline','exe']):
        if p.pid in ignore: continue
        try:
            proc = psutil.Process(p.pid); proc.cpu_percent(None)
            procs[p.pid] = {'proc':proc,'info':p.info,'high':0,'last':0.0}
        except (psutil.NoSuchProcess, psutil.AccessDenied): pass
    floors = []
    for _ in range(WINDOWS):
        time.sleep(WINDOW_S)
        reads = {}
        for pid, rec in procs.items():
            try:
                c = rec['proc'].cpu_percent(None); rec['last'] = c; reads[pid] = c
            except (psutil.NoSuchProcess, psutil.AccessDenied): reads[pid] = 0.0
        n_active = sum(1 for c in reads.values() if c >= ACTIVE_MIN)
        floor = adaptive_floor(n_active, cores); floors.append(floor)
        for pid, c in reads.items():
            if c >= floor: procs[pid]['high'] += 1
    return procs, (floors[-1] if floors else FLOOR_MAX), cores

def name_hits(info):
    name = (info.get('name') or "").lower()
    exe  = os.path.basename(info.get('exe') or "").lower()
    return [kw for kw in MINER_NAMES if kw in name or kw in exe]
def arg_hits(info):
    cmd = " ".join(info.get('cmdline') or []).lower()
    return [a for a in MINER_ARGS if a in cmd]
def path_suspicious(info):
    exe = info.get('exe') or ""
    if any(exe.startswith(d) for d in SUSPICIOUS_DIRS): return exe
    if exe and os.path.basename(exe).startswith('.'): return exe
    return None
def pool_connections(proc):
    hits=[]
    try:
        for c in proc.net_connections(kind='inet'):
            if c.raddr and c.raddr.port in MINING_POOL_PORTS:
                hits.append(f"{c.raddr.ip}:{c.raddr.port}")
    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
    return hits

STRONG_SIGNALS = {"signature", "pool"}   # specific to miners
WEAK_SIGNALS   = {"cpu", "path", "gpu"}  # ambiguous - ML/games/transcode also use GPU

def classify(fired):
    """HIGH needs a strong signal, not just two weak ones."""
    strong = len(fired & STRONG_SIGNALS); total = len(fired)
    if strong >= 2 or (strong >= 1 and total >= 2):
        return "HIGH"
    return "MED"

GPU_SM_HIGH = 30   # per-process GPU compute utilization % considered "busy"

def gpu_busy_pids(sm_threshold=GPU_SM_HIGH):
    """Parse `nvidia-smi pmon -c 1` for per-process GPU compute %. Empty if no GPU."""
    try:
        binary = os.environ.get("CRYPTOJACK_NVIDIA_SMI", "nvidia-smi")
        out = subprocess.run([binary,"pmon","-c","1"],
                             capture_output=True, text=True, timeout=5).stdout
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return {}   # no GPU / no nvidia-smi -> signal simply doesn't fire
    busy = {}
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith("#"): continue
        parts = s.split()                 # gpu pid type sm mem enc dec command
        if len(parts) < 8: continue
        try: pid = int(parts[1]); sm = int(parts[3]) if parts[3].isdigit() else 0
        except ValueError: continue
        if sm >= sm_threshold: busy[pid] = sm
    return busy

def scan():
    ignore = _self_tree()
    procs, floor, cores = multi_sample(ignore)
    gpu_pids = gpu_busy_pids()
    findings = []
    for pid, rec in procs.items():
        info = rec["info"]; score = 0; reasons = []; fired = set()
        allow = is_allowlisted(info)
        if rec["high"] >= REQUIRED_HIGH and not allow:
            fired.add("cpu"); score += 40
            reasons.append(f"sustained CPU {rec['last']:.0f}% ({rec['high']}/{WINDOWS} win, floor {floor:.0f}%)")
        nh, ah = name_hits(info), arg_hits(info)
        if nh or ah:
            fired.add("signature"); score += 50; reasons.append("miner signature: " + ",".join(nh+ah))
        sp = path_suspicious(info)
        if sp:
            fired.add("path"); score += 30; reasons.append(f"suspicious path: {sp}")
        pc = pool_connections(rec["proc"])
        if pc:
            fired.add("pool"); score += 50; reasons.append("mining-pool port: " + ",".join(pc))
        if pid in gpu_pids:
            fired.add("gpu"); score += 40; reasons.append(f"GPU compute {gpu_pids[pid]}%")
        if not fired: continue
        band = classify(fired)
        findings.append((band=="HIGH", score, pid, info.get("name"), info.get("exe"), rec["last"], band, reasons))
    findings.sort(reverse=True)
    return findings


# ---------------- Phase 4: structured output + alerting ----------------
import json, socket as _socket, datetime, urllib.request

def finding_to_dict(f):
    is_high, score, pid, name, exe, cpu, band, reasons = f
    return {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "host": _socket.gethostname(),
        "band": band, "risk": score, "pid": pid,
        "process": name, "exe": exe, "cpu_pct": round(cpu),
        "reasons": reasons,
    }

def emit_json(rows):
    """Machine-readable: one JSON object per finding (JSON Lines) for a SIEM."""
    return "\n".join(json.dumps(finding_to_dict(f)) for f in rows)

def emit_log(rows):
    """Human/syslog-style single line per finding."""
    out = []
    for f in rows:
        d = finding_to_dict(f)
        out.append(f"{d['ts']} cryptojack-detect {d['band']} risk={d['risk']} "
                   f"pid={d['pid']} proc={d['process']} :: {'; '.join(d['reasons'])}")
    return "\n".join(out)

def post_webhook(rows, url, min_band="HIGH", timeout=5):
    """POST qualifying findings to a webhook (Slack/PagerDuty/generic). Returns count sent."""
    rank = {"MED": 1, "HIGH": 2}
    sent = 0
    for f in rows:
        d = finding_to_dict(f)
        if rank.get(d["band"], 0) < rank.get(min_band, 2):
            continue
        payload = json.dumps({
            "text": f"[{d['band']}] cryptojacking suspect on {d['host']}: "
                    f"{d['process']} (pid {d['pid']}) - {'; '.join(d['reasons'])}",
            "finding": d,
        }).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=timeout).read()
            sent += 1
        except Exception as e:
            print(f"webhook error: {e}")
    return sent

def print_report(rows):
    print(f"{'BAND':>4} {'RISK':>4} {'PID':>7}  {'PROCESS':<15} {'CPU%':>5}  REASONS")
    print("-"*90)
    for is_high, score, pid, name, exe, cpu, band, reasons in rows:
        print(f"{band:>4} {score:>4} {pid:>7}  {str(name)[:15]:<15} {cpu:>5.0f}  " + "; ".join(reasons))
    if not rows: print("No suspicious processes.")


# ---------------- Phase 3: persistence enumeration ----------------
def _persist_entries(extra_files=None):
    """Collect autostart entries from cron, systemd, desktop autostart, shell rc."""
    import glob
    entries = []
    try:
        out = subprocess.run(["crontab","-l"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            t = line.strip()
            if t and not t.startswith("#"):
                entries.append(("user crontab", t))
    except Exception:
        pass
    files = (["/etc/crontab"] + glob.glob("/etc/cron.d/*")
             + glob.glob("/etc/systemd/system/*.service")
             + glob.glob(os.path.expanduser("~/.config/systemd/user/*.service"))
             + glob.glob(os.path.expanduser("~/.config/autostart/*.desktop"))
             + [os.path.expanduser("~/.bashrc"), os.path.expanduser("~/.profile")]
             + list(extra_files or []))
    for fp in files:
        try:
            for line in open(fp):
                t = line.strip()
                is_exec = t.startswith("ExecStart=") or t.startswith("Exec=")
                is_cronline = ("cron" in fp) and t and not t.startswith("#")
                is_rc = fp.endswith((".bashrc", ".profile")) and t and not t.startswith("#")
                if is_exec or is_cronline or is_rc:
                    entries.append((fp, t))
        except Exception:
            pass
    return entries

def scan_persistence(extra_files=None):
    """Flag autostart entries that reference a miner name or a suspicious path."""
    findings = []
    for src, text in _persist_entries(extra_files):
        low = text.lower()
        sig = [kw for kw in MINER_NAMES if kw in low]
        susp = [d for d in SUSPICIOUS_DIRS if d in text]
        if sig or susp:
            band = "HIGH" if sig else "MED"
            why = []
            if sig: why.append("miner name: " + ",".join(sig))
            if susp: why.append("suspicious launch path")
            findings.append((band, src, text, "; ".join(why)))
    return findings


# ---------------- Optional daemon: continuous scan with rate-limited alerts ----------------
def run_daemon(interval=60, cooldown=3600, webhook_url=None, iterations=None,
               include_persistence=True, persistence_extra=None, verbose=False):
    """Scan on a loop. Each distinct finding alerts at most once per `cooldown` seconds."""
    seen = {}   # dedup key -> last-alert timestamp
    n = 0
    try:
        while True:
            n += 1
            now = time.time()
            fired, suppressed = [], []
            for f in [r for r in scan() if r[0]]:            # HIGH process findings
                key = ("proc", f[4] or f[3])                 # dedup on exe (survives PID change)
                if now - seen.get(key, -1e18) >= cooldown:
                    seen[key] = now; fired.append(f[3])
                    if webhook_url: post_webhook([f], webhook_url)
                    print("ALERT " + emit_log([f]))
                else:
                    suppressed.append(f[3])
            if include_persistence:
                for band, src, text, why in scan_persistence(persistence_extra):
                    if not (band == "HIGH"): continue
                    key = ("persist", src)
                    if now - seen.get(key, -1e18) >= cooldown:
                        seen[key] = now; fired.append(os.path.basename(src))
                        print("ALERT persistence " + os.path.basename(src) + " :: " + why)
            if verbose:
                print("  scan %d  fired=%s  suppressed=%s" % (n, fired, suppressed))
            if iterations and n >= iterations: break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("daemon stopped")


__version__ = "1.0.0"


# ---------------- Command-line interface ----------------
def _print_findings(rows, fmt):
    if fmt == "json":
        print(emit_json(rows))
    elif fmt == "log":
        print(emit_log(rows))
    else:
        print_report(rows)


def _print_persistence(pf, as_json=False):
    if as_json:
        print(json.dumps([{"band": b, "source": s, "entry": t, "reasons": w}
                          for b, s, t, w in pf]))
        return
    if not pf:
        print("No suspicious persistence entries.")
        return
    for band, src, text, why in pf:
        print("%-4s %s :: %s" % (band, os.path.basename(src), why))
        print("      -> " + text)


def cli(argv=None):
    import argparse
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--nvidia-smi", metavar="PATH", dest="nvidia_smi",
                        help="path to nvidia-smi (also settable via CRYPTOJACK_NVIDIA_SMI)")
    common.add_argument("--windows", type=int, default=WINDOWS,
                        help="CPU sampling windows (default %(default)s)")
    common.add_argument("--window-seconds", type=float, default=WINDOW_S,
                        dest="window_seconds",
                        help="seconds per CPU sampling window (default %(default)s)")

    ap = argparse.ArgumentParser(
        prog="cryptojack-detect",
        description=("Host-based cryptojacking detector (read-only). Scores running "
                     "processes and autostart entries on multiple signals and reports "
                     "them; it never terminates or changes anything."))
    ap.add_argument("--version", action="version",
                    version="cryptojack-detect " + __version__)
    sub = ap.add_subparsers(dest="command")

    def add_format(p):
        g = p.add_mutually_exclusive_group()
        g.add_argument("--json", action="store_const", const="json", dest="fmt",
                       help="emit findings as JSON Lines (for a SIEM)")
        g.add_argument("--log", action="store_const", const="log", dest="fmt",
                       help="emit findings as syslog-style lines")

    def add_webhook(p):
        p.add_argument("--webhook", metavar="URL",
                       help="POST qualifying findings to this webhook")
        p.add_argument("--min-band", choices=["MED", "HIGH"], default="HIGH",
                       dest="min_band",
                       help="minimum band to send to the webhook (default %(default)s)")

    p_scan = sub.add_parser("scan", parents=[common],
                            help="run one scan of live processes (default)")
    add_format(p_scan); add_webhook(p_scan)
    p_scan.add_argument("--persistence", action="store_true",
                        help="also enumerate autostart persistence entries")
    p_scan.add_argument("--exit-zero", action="store_true", dest="exit_zero",
                        help="always exit 0 (default: exit 1 when a HIGH finding is present)")

    p_watch = sub.add_parser("watch", parents=[common],
                             help="run continuously as a rate-limited daemon")
    add_webhook(p_watch)
    p_watch.add_argument("--interval", type=float, default=60.0,
                         help="seconds between scans (default %(default)s)")
    p_watch.add_argument("--cooldown", type=float, default=3600.0,
                         help="min seconds between repeat alerts for one finding (default %(default)s)")
    p_watch.add_argument("--no-persistence", action="store_true", dest="no_persistence",
                         help="skip persistence enumeration each cycle")
    p_watch.add_argument("--quiet", action="store_true",
                         help="print only alerts, not per-scan summaries")

    p_persist = sub.add_parser("persistence", help="scan autostart vectors only")
    add_format(p_persist)

    args = ap.parse_args(argv)

    globals()["WINDOWS"] = getattr(args, "windows", WINDOWS)
    globals()["WINDOW_S"] = getattr(args, "window_seconds", WINDOW_S)
    if getattr(args, "nvidia_smi", None):
        os.environ["CRYPTOJACK_NVIDIA_SMI"] = args.nvidia_smi

    command = args.command or "scan"

    if command == "scan":
        rows = scan()
        _print_findings(rows, getattr(args, "fmt", None) or "table")
        if getattr(args, "persistence", False):
            print()
            print("PERSISTENCE")
            _print_persistence(scan_persistence())
        wh = getattr(args, "webhook", None)
        if wh:
            n = post_webhook(rows, wh, min_band=getattr(args, "min_band", "HIGH"))
            print("(posted %d finding(s) to webhook)" % n)
        if getattr(args, "exit_zero", False):
            return 0
        return 1 if any(r[0] for r in rows) else 0

    if command == "persistence":
        pf = scan_persistence()
        _print_persistence(pf, as_json=(getattr(args, "fmt", None) == "json"))
        return 1 if any(b == "HIGH" for b, _, _, _ in pf) else 0

    if command == "watch":
        run_daemon(interval=args.interval, cooldown=args.cooldown,
                   webhook_url=getattr(args, "webhook", None),
                   include_persistence=not getattr(args, "no_persistence", False),
                   verbose=not getattr(args, "quiet", False))
        return 0

    return 0


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(cli())
