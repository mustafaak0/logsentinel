#!/usr/bin/env python3
"""
demo_gen — synthetic SSH auth.log generator with planted attacks.

Scenarios seeded into the output (so LogSentinel has something to find):
  1. normal office noise      (legit logins from 10.0.0.x)
  2. brute force              (one IP hammering root/admin)
  3. user enumeration         (one IP probing many invalid usernames)
  4. password spraying        ('admin' probed from a botnet of IPs)
  5. successful compromise    (failures → SUCCESS at 02:13 — the crown jewel)
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

NAMES = ["ahmet", "ayse", "mehmet", "zeynep", "emre", "elif", "burak", "selin",
         "can", "deniz", "kaan", "mina", "operator", "deploy", "backup"]
INVALID = ["oracle", "test2", "postgres", "git", "pi", "ubuntu", "vagrant",
           "support", "service", "weather", "nagios", "jenkins", "gitlab",
           "zabbix", "elastic", "kafka"]
BOTNET = [f"45.155.{a}.{b}" for a in (204, 205) for b in (11, 23, 57, 88, 99)]


def sshd(ts: datetime, msg: str) -> str:
    return (f"{ts.strftime('%b')} {ts.day:>2} {ts.strftime('%H:%M:%S')} "
            f"srv01 sshd[{random.randint(1000, 99999)}]: {msg}")


def failed(ts, user, ip):
    return sshd(ts, f"Failed password for {'invalid user ' if user in INVALID else ''}"
                    f"{user} from {ip} port {random.randint(1024, 64000)} ssh2")


def accepted(ts, user, ip):
    return sshd(ts, f"Accepted publickey for {user} from {ip} "
                    f"port {random.randint(1024, 64000)} ssh2")


def main() -> None:
    p = argparse.ArgumentParser(description="synthetic auth.log generator")
    p.add_argument("--out", default="sample_auth.log")
    p.add_argument("--seed", type=int, default=7)
    a = p.parse_args()
    rng = random.Random(a.seed)

    lines: list[tuple[datetime, str]] = []
    t = datetime(2026, 11, 8, 6, 12, 0)

    # 1) office noise: ~140 normal logins over ~2 days
    for _ in range(140):
        t += timedelta(minutes=rng.randint(2, 18))
        stamp = t.replace(hour=min(23, max(7, int(rng.gauss(14, 3)))))
        lines.append((stamp, accepted(stamp, rng.choice(NAMES),
                                      f"10.0.0.{rng.randint(2, 20)}")))
        if rng.random() < 0.08:  # typo noise
            lines.append((stamp + timedelta(seconds=rng.randint(1, 40)),
                          failed(stamp, rng.choice(NAMES), f"10.0.0.{rng.randint(2, 20)}")))

    # 2) brute force: 185.234.219.11 hammering
    bt = datetime(2026, 11, 9, 3, 4, 0)
    for i in range(64):
        lines.append((bt + timedelta(seconds=i * 4),
                      failed(bt, rng.choice(["root", "admin", "toor"]),
                             "185.234.219.11")))

    # 3) user enumeration: 198.51.100.9 probing 25 invalid users
    et = datetime(2026, 11, 9, 21, 40, 0)
    for i, u in enumerate(INVALID + INVALID[:10]):
        lines.append((et + timedelta(seconds=i * 9), failed(et, u, "198.51.100.9")))

    # 4) password spraying: 'admin' from a botnet
    st = datetime(2026, 11, 10, 16, 2, 0)
    for i, ip in enumerate(BOTNET):
        lines.append((st + timedelta(seconds=i * 31), failed(st, "admin", ip)))

    # 5) the compromise: 12 failures then SUCCESS at night
    ct = datetime(2026, 11, 10, 2, 1, 0)
    for i in range(12):
        lines.append((ct + timedelta(seconds=i * 26), failed(ct, "deploy", "203.0.113.66")))
    ok = ct + timedelta(minutes=7)
    lines.append((ok, accepted(ok, "deploy", "203.0.113.66")))

    lines.sort(key=lambda x: x[0])
    Path(a.out).write_text("\n".join(l for _, l in lines) + "\n", encoding="utf-8")
    print(f"[+] wrote {len(lines)} events → {a.out}")
    print("    planted: brute-force, user-enum, password-spray, night compromise")


if __name__ == "__main__":
    main()
