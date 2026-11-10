# 📜 LogSentinel

> SSH auth-log anomaly detector — catch brute force, spraying and the one login that *succeeded* after the storm. Zero dependencies, pure Python stdlib.

[![Python](https://img.shields.io/badge/Python-3.9%2B-0D1117?style=for-the-badge&logo=python&logoColor=3776AB)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-00E676?style=for-the-badge&labelColor=0D1117)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-0D1117?style=for-the-badge&labelColor=00E676)](LICENSE)
[![Author](https://img.shields.io/badge/Author-mustafaak0-0D1117?style=for-the-badge&logo=github&logoColor=00E676)](https://github.com/mustafaak0)

## 🎯 Detections

| Finding | Logic | Severity |
|---------|-------|----------|
| ⚠ **possible compromise** | same `(IP, user)` fails **≥3 times**, then **succeeds** | up to CRITICAL |
| 🔨 **brute force** | many failures from one IP (z-scored against population) | MEDIUM–HIGH |
| 👥 **user spraying** | one IP probing many distinct usernames | MEDIUM |
| 🌐 **password spraying** | one username probed from many **never-successful** IPs, distributed | MEDIUM–HIGH |
| 🌙 **night activity** | events between 00:00–05:59 | adds weight |

The **never-successful IP** signal is the key anti-false-positive trick: office
users typo their passwords too, but their IPs also have *successful* logins.
Throwaway attack IPs never succeed at anything — that asymmetry separates
noise from campaigns.

## 🚀 Usage

```bash
# try it instantly on the bundled demo log
python logsentinel.py sample_auth.log

# your own server's log
python logsentinel.py /var/log/auth.log --top 20

# generate a fresh synthetic log with planted attacks
python demo_gen.py --out sample_auth.log --seed 42

# thresholds are tunable, export for your SIEM
python logsentinel.py auth.log --min-failed 20 --spray-ips 8 --json alerts.json
```

```
╭─ LogSentinel report ──────────────────────────────────────────
│ events parsed : 262  (failed=121, accepted=141, invalid-user=0)
│ unique IPs    : 32
│ findings      : 4
╰──────────────────────────────────────────────────────────────

  ● admin  →  100/100  [HIGH]
      - password spraying: 'admin' probed from 11 never-successful IPs
  ● 203.0.113.66  →  62/100  [HIGH]
      - brute force: 12 failed logins (z=+0.7)
      - night activity: 13 events between 00:00-05:59
      - ⚠ FAILURES THEN SUCCESS from this IP — possible compromise
```

## 🧪 Verified on Synthetic Attacks

`demo_gen.py` plants five scenarios into a realistic log: office noise,
brute force, user enumeration, botnet password spraying and a **night-time
compromise** (12 failures → success at 02:08). LogSentinel catches **4/4
attack patterns with zero false positives** on the office population.

## 🧠 Design Notes

- **Explainable scoring** — every finding lists its reasons; no black-box
  mystery score. Weights are simple and in the code.
- **z-scores, not magic** — an IP's failure count is compared against the
  population mean/std of that log, so "many" adapts to the log's baseline.
- **Parsed formats**: classic Debian/Ubuntu `auth.log` and RHEL `secure`
  sshd lines (`Failed password`, `Accepted *`, `Invalid user`).
- Pure stdlib: runs on a stock Python 3.9+ — no pip, no ML framework,
  perfect for air-gapped jump hosts.

## 🔭 Roadmap

- [ ] `--follow` live tail mode
- [ ] geoip enrichment (offline MMDB)
- [ ] systemd journal JSON input
- [ ] fail2ban config export from findings

## ⚖️ Disclaimer

For analyzing logs of systems **you are authorized to monitor**.
Blue-team tooling — be the defender.

---

<div align="center">

*The quietest line in your log may be the loudest warning.*

</div>
