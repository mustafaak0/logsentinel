#!/usr/bin/env python3
"""
LogSentinel — SSH/auth log anomaly detector (pure stdlib).

Parses classic sshd auth logs (Debian/Ubuntu auth.log, RHEL secure),
aggregates activity per source IP and per user, then applies explainable
weighted rules + z-score statistics to surface:

  - brute force        (many failures from one IP)
  - user spraying      (many usernames probed from one IP)
  - password spraying  (one username probed from many IPs)
  - possible compromise(failures followed by a SUCCESS — highest severity)
  - night logins       (00:00-05:59 local-hours)
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

LINE_RE = re.compile(
    r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>sshd)\[?\d*\]?:?\s+(?P<msg>.*)")

FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)")
ACCEPT_RE = re.compile(
    r"Accepted (?:\S+) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")


@dataclass
class Event:
    ts: datetime
    host: str
    kind: str        # failed | accepted | invalid-user
    user: str
    ip: str


@dataclass
class IPStats:
    fails: int = 0
    accepts: int = 0
    invalid_users: int = 0
    users: set = field(default_factory=set)
    night_events: int = 0
    failed_then_ok: bool = False

    @property
    def total(self) -> int:
        return self.fails + self.accepts + self.invalid_users


# ----------------------------------------------------------------------------
# parsing
# ----------------------------------------------------------------------------

def parse_ts(mon: str, day: str, time: str) -> datetime:
    return datetime(2026, MONTHS.get(mon, 1), int(day),
                    *(int(x) for x in time.split(":")))


def parse_log(path: Path) -> list[Event]:
    events = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE_RE.match(raw)
        if not m:
            continue
        msg = m.group("msg")
        ts = parse_ts(m.group("mon"), m.group("day"), m.group("time"))
        hit = (FAILED_RE.search(msg) or ACCEPT_RE.search(msg)
               or INVALID_RE.search(msg))
        if not hit:
            continue
        kind = ("failed" if "Failed" in msg
                else "accepted" if "Accepted" in msg else "invalid-user")
        events.append(Event(ts, m.group("host"), kind, hit.group("user"), hit.group("ip")))
    return events


# ----------------------------------------------------------------------------
# aggregation & scoring
# ----------------------------------------------------------------------------

def zscore(value: float, mean: float, std: float) -> float:
    return (value - mean) / std if std > 0 else 0.0


def mean_std(xs: list[float]) -> tuple[float, float]:
    if not xs:
        return 0.0, 0.0
    mu = sum(xs) / len(xs)
    var = sum((x - mu) ** 2 for x in xs) / len(xs)
    return mu, math.sqrt(var)


def aggregate(events: list[Event]):
    ips: dict[str, IPStats] = defaultdict(IPStats)
    users: dict = defaultdict(lambda: {"fails": 0, "accepts": 0, "ips": set()})
    pair_fails: dict[tuple[str, str], int] = defaultdict(int)
    COMPROMISE_MIN_FAILS = 3   # same (ip,user) must fail this much before a success counts

    for e in events:
        st = ips[e.ip]
        st.users.add(e.user)
        if e.ts.hour < 6:
            st.night_events += 1
        if e.kind == "failed":
            st.fails += 1
            users[e.user]["fails"] += 1
            users[e.user]["ips"].add(e.ip)
            pair_fails[(e.ip, e.user)] += 1
        elif e.kind == "invalid-user":
            st.invalid_users += 1
        else:
            st.accepts += 1
            users[e.user]["accepts"] += 1
            users[e.user]["ips"].add(e.ip)
            if pair_fails.get((e.ip, e.user), 0) >= COMPROMISE_MIN_FAILS:
                st.failed_then_ok = True
    return dict(ips), dict(users), dict(pair_fails)


def detect(ips: dict[str, IPStats], users: dict, pair_fails: dict,
           min_failed: int, spray_users: int, spray_ips: int) -> list[dict]:
    findings: list[dict] = []
    f_mu, f_std = mean_std([float(x.fails) for x in ips.values()])

    for ip, s in ips.items():
        score, reasons = 0, []
        if s.fails >= min_failed:
            z = zscore(s.fails, f_mu, f_std)
            score += min(45, s.fails)
            reasons.append(f"brute force: {s.fails} failed logins (z={z:+.1f})")
        if len(s.users) >= spray_users and s.fails:
            score += min(25, len(s.users))
            reasons.append(f"user spraying: {len(s.users)} distinct usernames probed")
        if s.night_events >= 5 and s.accepts:
            score += 10
            reasons.append(f"night activity: {s.night_events} events between 00:00-05:59")
        if s.failed_then_ok:
            score += 40
            reasons.append("⚠ FAILURES THEN SUCCESS from this IP — possible compromise")
        if score >= 20:
            sev = ("CRITICAL" if score >= 75 else
                   "HIGH" if score >= 50 else "MEDIUM")
            findings.append({"ip": ip, "score": min(100, score),
                             "severity": sev, "reasons": reasons,
                             "fails": s.fails, "accepts": s.accepts,
                             "users": len(s.users)})

    # IPs with at least one successful login anywhere are "known-good";
    # spraying comes from throwaway IPs that never succeed.
    benign = {ip for ip, s in ips.items() if s.accepts > 0}
    for user, u in users.items():
        per_ip = {ip: pair_fails.get((user, ip), 0)
                  for ip in u["ips"] if ip not in benign}
        top = max(per_ip.values(), default=0)
        distributed = (u["fails"] - top) >= 0.4 * u["fails"]
        if u["fails"] >= 3 and len(per_ip) >= spray_ips and distributed:
            findings.append({"user": user, "score": min(100, 10 * len(per_ip)),
                             "severity": "MEDIUM" if len(per_ip) < 10 else "HIGH",
                             "reasons": [f"password spraying: '{user}' probed from "
                                         f"{len(per_ip)} never-successful IPs ({u['fails']} fails, "
                                         f"distributed)"],
                             "fails": u["fails"], "accepts": u["accepts"],
                             "users": len(per_ip)})
    return sorted(findings, key=lambda f: -f["score"])


# ----------------------------------------------------------------------------
# report
# ----------------------------------------------------------------------------

def report(events: list[Event], findings: list[dict], top: int) -> None:
    n_fail = sum(1 for e in events if e.kind == "failed")
    n_ok = sum(1 for e in events if e.kind == "accepted")
    n_inv = sum(1 for e in events if e.kind == "invalid-user")
    print("╭─ LogSentinel report " + "─" * 42)
    print(f"│ events parsed : {len(events)}  (failed={n_fail}, accepted={n_ok}, invalid-user={n_inv})")
    print(f"│ unique IPs    : {len({e.ip for e in events})}")
    print(f"│ unique users  : {len({e.user for e in events})}")
    print(f"│ findings      : {len(findings)}")
    print("╰" + "─" * 62)
    if not findings:
        print("\n✔ no anomalies above threshold — quiet log (or is it?)")
        return
    for f in findings[:top]:
        label = f.get("ip", f.get("user", "?"))
        print(f"\n  ● {label}  →  {f['score']}/100  [{f['severity']}]")
        for r in f["reasons"]:
            print(f"      - {r}")
        print(f"      (fails={f['fails']}  accepts={f['accepts']}  identities={f['users']})")


def main() -> None:
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="LogSentinel — SSH/auth log anomaly detector")
    p.add_argument("log", help="auth log file (sshd format)")
    p.add_argument("--min-failed", type=int, default=10, help="brute-force threshold (default 10)")
    p.add_argument("--spray-users", type=int, default=8, help="user-spray threshold (default 8)")
    p.add_argument("--spray-ips", type=int, default=5, help="password-spray threshold (default 5)")
    p.add_argument("--top", type=int, default=10, help="show top N findings")
    p.add_argument("--json", dest="json_out", help="export findings as JSON")
    args = p.parse_args()

    path = Path(args.log)
    if not path.exists():
        sys.exit(f"[!] log file not found: {path}")

    events = parse_log(path)
    if not events:
        sys.exit("[!] no parseable sshd events found — is this an auth.log?")
    ips, users, pair_fails = aggregate(events)
    findings = detect(ips, users, pair_fails, args.min_failed, args.spray_users, args.spray_ips)
    report(events, findings, args.top)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(findings, indent=2), encoding="utf-8")
        print(f"\n[+] JSON export → {args.json_out}")


if __name__ == "__main__":
    main()
