#!/usr/bin/env python3
# sshwatch.py — stream Linux journal for sshd and flag suspicious logins
# Adds: --bootstrap window (auto-used on first run to backfill and alert)

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import time
from collections import defaultdict, deque

STATE_DEFAULT_PATHS = [
    "/var/lib/sshwatch/state.json",
    os.path.expanduser("~/.local/share/sshwatch/state.json"),
]

ACCEPT_RE = re.compile(
    r"(Accepted|Accepted password|Accepted publickey|Accepted keyboard-interactive)"
    r".* for (?P<user>\S+) from (?P<ip>\S+)"
)
FAIL_RE = re.compile(r"(Failed|Invalid user).* from (?P<ip>\S+)")
ROOT_RE = re.compile(r"Accepted.* for root from (?P<ip>\S+)")

DEFAULT_SUSPICION_SCORES = {
    "new_user": 5,
    "new_ip_global": 4,
    "new_ip_for_user": 3,
    "root_login": 6,
    "odd_hour": 2,
    "burst_fail_then_success": 4,
}

def now_utc():
    return dt.datetime.now(dt.timezone.utc)

def parse_journal_timestamp(ts_str: str) -> dt.datetime:
    try:
        micros = int(ts_str)
        if micros > 10**16:  # ns
            return dt.datetime.fromtimestamp(micros/1e9, tz=dt.timezone.utc)
        return dt.datetime.fromtimestamp(micros/1e6, tz=dt.timezone.utc)
    except Exception:
        return now_utc()

def load_state(path: str):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "known_users": [],
        "known_ips": [],
        "user_ips": {},
        "hour_hist": {},
        "allow_users": [],
        "allow_ips": [],
        "created_at": now_utc().isoformat(),
        "last_seen": None,
    }

def save_state(path: str, state: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, path)

def ip_in_allowlist(ip: str, allow_ips):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for item in allow_ips or []:
        try:
            net = ipaddress.ip_network(item, strict=False)
            if ip_obj in net:
                return True
        except Exception:
            if item == ip:
                return True
    return False

def human(ts: dt.datetime):
    return ts.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

class BurstDetector:
    def __init__(self, window_sec=300, thresh=5):
        self.window = window_sec
        self.thresh = thresh
        self.failures = defaultdict(deque)

    def record_fail(self, ip, t):
        dq = self.failures[ip]
        dq.append(t.timestamp())
        cutoff = t.timestamp() - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def consumed_by_success(self, ip, t) -> bool:
        dq = self.failures.get(ip)
        if not dq:
            return False
        cutoff = t.timestamp() - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        recent = len(dq)
        self.failures[ip].clear()
        return recent >= self.thresh

def print_alert(title, details, score, ts):
    print("")
    print("="*80)
    print(f"[ALERT score={score}] {title}")
    print(f"Time: {human(ts)}")
    for k, v in details.items():
        print(f"- {k}: {v}")
    print("="*80)
    print("", flush=True)

def run_journal(unit="sshd.service", since=None):
    cmd = ["journalctl", "-o", "json", "-u", unit]
    if since:
        cmd += [f"--since={since}"]
    else:
        cmd += ["-f"]  # follow
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)

def evaluate_event(state, scores, burst, msg, tstamp, verbose=False):
    changed = False
    message = msg or ""

    m_fail = FAIL_RE.search(message)
    if m_fail:
        ip = m_fail.group("ip").split()[0]
        burst.record_fail(ip, tstamp)
        if verbose:
            print(f"[fail] {ip} @ {human(tstamp)}")
        return changed

    m_acc = ACCEPT_RE.search(message)
    if not m_acc:
        return changed

    user = m_acc.group("user")
    ip = m_acc.group("ip").split()[0]
    suspicious = []
    score = 0

    is_allowed_user = user in state.get("allow_users", [])
    is_allowed_ip = ip_in_allowlist(ip, state.get("allow_ips", []))

    if ROOT_RE.search(message) and not is_allowed_ip:
        suspicious.append(("root_login", f"root login from {ip}"))
        score += scores["root_login"]

    if user not in state["known_users"] and not is_allowed_user:
        suspicious.append(("new_user", f"first time seeing user '{user}'"))
        score += scores["new_user"]
        state["known_users"].append(user)
        changed = True

    if ip not in state["known_ips"] and not is_allowed_ip:
        suspicious.append(("new_ip_global", f"new source IP {ip}"))
        score += scores["new_ip_global"]
        state["known_ips"].append(ip)
        changed = True

    user_ips = state["user_ips"].setdefault(user, [])
    if ip not in user_ips and not is_allowed_ip:
        suspicious.append(("new_ip_for_user", f"new IP {ip} for user {user}"))
        score += scores["new_ip_for_user"]
        user_ips.append(ip)
        changed = True

    hour = tstamp.astimezone().hour
    hist = state["hour_hist"].setdefault(user, [0]*24)
    total = sum(hist)
    if total >= 5 and hist[hour] == 0 and not is_allowed_user and not is_allowed_ip:
        suspicious.append(("odd_hour", f"login at hour {hour:02d} is unusual for {user}"))
        score += scores["odd_hour"]
    hist[hour] += 1
    changed = True

    if burst.consumed_by_success(ip, tstamp) and not is_allowed_ip:
        suspicious.append(("burst_fail_then_success", f"success after multiple recent failures from {ip}"))
        score += scores["burst_fail_then_success"]

    if suspicious:
        title = f"SSH login accepted: user={user} ip={ip}"
        details = {
            "user": user,
            "ip": ip,
            "hour": f"{hour:02d}",
            "flags": ", ".join([k for k, _ in suspicious]),
            "notes": "; ".join([v for _, v in suspicious]),
        }
        print_alert(title, details, score, tstamp)
    elif verbose:
        print(f"[ok] {user} from {ip} @ {human(tstamp)}")

    return changed

def parse_bootstrap(s: str) -> str:
    """Accept shorthand like 7d, 1w, 12h and return a journalctl --since string."""
    s = s.strip().lower()
    if s.endswith("w"):
        n = int(s[:-1]); return f"{n*7} days ago"
    if s.endswith("d"):
        n = int(s[:-1]); return f"{n} days ago"
    if s.endswith("h"):
        n = int(s[:-1]); return f"{n} hours ago"
    if s.endswith("m") and s[:-1].isdigit():
        # minutes
        n = int(s[:-1]); return f"{n} minutes ago"
    # fallback: pass through (could be "2025-09-01 00:00")
    return s

def main():
    ap = argparse.ArgumentParser(description="Watch journal for sshd and alert on suspicious logins.")
    ap.add_argument("--state", default=None, help="Path to state.json (default tries common locations).")
    ap.add_argument("--unit", default="sshd.service", help="Systemd unit (default: sshd.service).")
    ap.add_argument("--since", default=None, help="Manual backfill window (e.g., '12h' or '2025-09-01 00:00'). One-shot mode.")
    ap.add_argument("--bootstrap", default="7d", help="Initial backfill window used automatically on first run (default: 7d).")
    ap.add_argument("--verbose", action="store_true", help="Print normal logins too.")
    ap.add_argument("--allow-user", action="append", default=[], help="Allowlist users.")
    ap.add_argument("--allow-ip", action="append", default=[], help="Allowlist CIDRs/IPs.")
    ap.add_argument("--score", action="append", default=[], help="Override scores, e.g. new_user=8,new_ip_global=2")
    args = ap.parse_args()

    # resolve state path
    state_path = args.state or next((p for p in STATE_DEFAULT_PATHS if os.path.isdir(os.path.dirname(p)) or not os.path.exists(p)), STATE_DEFAULT_PATHS[-1])
    state_exists = os.path.exists(state_path)
    state = load_state(state_path)

    # apply allowlists
    if args.allow_user:
        for u in args.allow_user:
            if u not in state.get("allow_users", []):
                state.setdefault("allow_users", []).append(u)
    if args.allow_ip:
        for ipmask in args.allow_ip:
            if ipmask not in state.get("allow_ips", []):
                state.setdefault("allow_ips", []).append(ipmask)

    # scores
    scores = DEFAULT_SUSPICION_SCORES.copy()
    for override in args.score:
        for kv in override.split(","):
            if not kv.strip():
                continue
            k, v = kv.split("=", 1)
            if k in scores:
                scores[k] = int(v)

    burst = BurstDetector(window_sec=300, thresh=5)

    # One-shot manual backfill
    if args.since:
        p = run_journal(unit=args.unit, since=args.since)
        changed = False
        try:
            for line in p.stdout:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = entry.get("MESSAGE") or ""
                tstamp = parse_journal_timestamp(entry.get("__REALTIME_TIMESTAMP", "0"))
                if evaluate_event(state, scores, burst, msg, tstamp, verbose=args.verbose):
                    changed = True
        finally:
            try: p.terminate()
            except Exception: pass
        if changed:
            state["last_seen"] = now_utc().isoformat()
            save_state(state_path, state)
        return

    # Auto-bootstrap backfill on first run (no state yet)
    if not state_exists:
        since_str = parse_bootstrap(args.bootstrap)
        print(f"[*] First run detected. Backfilling since: {since_str}")
        p = run_journal(unit=args.unit, since=since_str)
        changed = False
        try:
            for line in p.stdout:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = entry.get("MESSAGE") or ""
                tstamp = parse_journal_timestamp(entry.get("__REALTIME_TIMESTAMP", "0"))
                if evaluate_event(state, scores, burst, msg, tstamp, verbose=args.verbose):
                    changed = True
        finally:
            try: p.terminate()
            except Exception: pass
        if changed:
            state["last_seen"] = now_utc().isoformat()
            save_state(state_path, state)

    # Follow live
    p = run_journal(unit=args.unit)
    print(f"[*] sshwatch: following journal for {args.unit}; state={state_path}")
    print("[*] Alerts include historical backfill (first run) and live events. Ctrl-C to stop.")
    changed = False
    try:
        for line in p.stdout:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = entry.get("MESSAGE") or ""
            tstamp = parse_journal_timestamp(entry.get("__REALTIME_TIMESTAMP", "0"))
            if evaluate_event(state, scores, burst, msg, tstamp, verbose=args.verbose):
                changed = True
                # periodic save
                if time.time() % 30 < 1:
                    state["last_seen"] = now_utc().isoformat()
                    save_state(state_path, state)
    except KeyboardInterrupt:
        print("\n[*] Stopping…")
    finally:
        try: p.terminate()
        except Exception: pass
        if changed:
            state["last_seen"] = now_utc().isoformat()
            save_state(state_path, state)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("WARNING: Not running as root; journalctl may not return sshd logs. Consider sudo.", file=sys.stderr)
    main()

