#!/usr/bin/env python3
"""Run one GhostLock QEMU mode over and over, one fresh boot per round.

Each round starts build_and_run.sh with GLMODE=<mode> (so the mode is baked
into that boot's initramfs) and watches the kernel log.  A round ends when the
wrapper's independent marker shows up -- "init: ghostlock_exe[<mode>] exited
status=0x..." -- or when the guest wedges: the log stops growing and every
vCPU sits in queued_spin_lock_slowpath's __cmpwait loop on the same lock word,
i.e. the clobbered walk oopsed and left a spinlock held (README "第二种失败
模式").  A wedged guest is killed and the next round starts by itself, which is
the whole point: one clobbered attempt must cost one boot, not a whole
campaign, and no longer needs a human watching for it.

Run it with the same escalation as build_and_run.sh (QEMU needs its QMP unix
socket, and the driver kills the guest it started).

  run_rounds.py --mode "--bench 30" --rounds 10
  run_rounds.py --mode "--verify-all" --rounds 5 --stall 120
  run_rounds.py --mode "--bench 10" --rounds 3 --out /tmp/gl-campaign

Modes that never exit (--su-server, --hold, --detach) have no wrapper marker:
give them --timeout and --stall 0 so the round ends on the timeout instead of
being mistaken for a wedge.
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import glqemu  # noqa: E402  (path set up above)

HERE = os.path.dirname(os.path.abspath(__file__))
MARKER = re.compile(r"init: ghostlock_exe\[([^\]]*)\] exited status=0x([0-9a-f]+)")

# Lines worth quoting in the summary (the wrapper marker only says the mode
# returned 0; these say what it measured).
HIGHLIGHTS = (
    r"bench: \d+/\d+ single-attempt writes succeeded \(\d+%\)",
    r"slide verify all (?:PASSED|FAILED)",
    r"slide [a-z0-9-]+ test (?:PASSED|FAILED)",
    r"su selftest (?:PASSED|FAILED)",
    r"selinux relax (?:PASSED|FAILED)",
    r"harden: [^\n]*",
    r"Unable to handle[^\n]*",
    r"Internal error[^\n]*",
)


def highlights(text):
    found = []
    for pat in HIGHLIGHTS:
        m = re.search(pat, text)
        if m and m.group(0) not in found:
            found.append(m.group(0))
    return "; ".join(found)


def stop(proc):
    """Kill the guest build_and_run.sh exec'd (it is qemu by then)."""
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def run_round(args, index):
    sock = os.path.join(args.out, "qmp.sock")
    if os.path.exists(sock):
        os.unlink(sock)          # a stale socket makes QEMU refuse to bind
    env = dict(os.environ, GLMODE=args.mode, GDB="0", OUT=args.out)
    guest_log = open(os.path.join(args.out, "round-%02d.console" % index), "w")
    proc = subprocess.Popen([os.path.join(HERE, "build_and_run.sh")], cwd=HERE,
                            env=env, stdout=guest_log, stderr=guest_log)
    guest = glqemu.Guest(sock)
    started = time.time()
    deadline = started + args.timeout
    text, last_change, verdict, detail = "", time.time(), "TIMEOUT", ""
    while time.time() < deadline and proc.poll() is None:
        time.sleep(args.poll)
        try:
            fresh = guest.log_text()
        except Exception:
            fresh = text
        if fresh.strip() and fresh != text:
            text, last_change = fresh, time.time()
        m = MARKER.search(text)
        if m:
            verdict = "PASS" if int(m.group(2), 16) == 0 else "FAIL"
            detail = m.group(0)
            break
        if args.stall and time.time() - last_change >= args.stall:
            wedged, why = guest.wedge()
            if wedged:
                verdict, detail = "WEDGED", why
                break
    if proc.poll() is not None and verdict == "TIMEOUT":
        verdict, detail = "DIED", "qemu exited rc=%s" % proc.returncode
    try:                          # keep the raw buffer for post-mortems
        raw = guest.log_buffer()[1]
    except Exception:
        raw = b""                 # the guest may already be gone
    stop(proc)
    guest_log.close()
    with open(os.path.join(args.out, "round-%02d.log" % index), "w") as fh:
        fh.write(text)
    with open(os.path.join(args.out, "round-%02d.raw" % index), "wb") as fh:
        fh.write(raw)
    return {"round": index, "verdict": verdict, "detail": detail,
            "highlights": highlights(text), "seconds": round(time.time() - started)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True,
                    help="GLMODE string, e.g. \"--bench 30\"")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--out", default=os.environ.get("OUT", "/tmp/ghostlock-qemu"),
                    help="artifacts + QMP socket directory (default %(default)s)")
    ap.add_argument("--timeout", type=float, default=900.0,
                    help="wall clock per round before giving up (default 900)")
    ap.add_argument("--stall", type=float, default=90.0,
                    help="seconds without new log lines before probing for the "
                         "__cmpwait wedge; 0 disables (default 90)")
    ap.add_argument("--poll", type=float, default=10.0,
                    help="seconds between log reads (default 10)")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    rows = []
    counts = {}
    for i in range(1, args.rounds + 1):
        print("== round %d/%d: %s" % (i, args.rounds, args.mode), flush=True)
        row = run_round(args, i)
        rows.append(row)
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
        print("   %-7s %5ds  %s" % (row["verdict"], row["seconds"],
                                    row["detail"] or row["highlights"]),
              flush=True)

    summary = os.path.join(args.out, "report-%s.txt"
                           % re.sub(r"[^A-Za-z0-9]+", "_", args.mode).strip("_"))
    with open(summary, "w") as fh:
        fh.write("mode: %s\nrounds: %d\n\n" % (args.mode, args.rounds))
        for r in rows:
            fh.write("round %02d  %-7s %4ds  %s\n    %s\n"
                     % (r["round"], r["verdict"], r["seconds"],
                        r["detail"], r["highlights"]))
        fh.write("\ntotals: %s\n" % ", ".join(
            "%s=%d" % kv for kv in sorted(counts.items())))
    print("== totals: %s" % ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
    print("== report: %s" % summary)
    return 0 if counts.get("PASS", 0) == args.rounds else 1


if __name__ == "__main__":
    sys.exit(main())
