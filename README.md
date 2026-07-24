# SOC Auth Log Analyzer

Parses common SSH-style authentication log lines and surfaces failed logins, repeated failures from one source, and multi-user spray patterns.

## What it does

| Rule | Meaning |
|------|---------|
| `failed_login` | Single failed authentication line |
| `brute_force_burst` | Many failures from the same source IP |
| `password_spray_hint` | Many usernames failing from one source IP |

## Usage

```bash
python3 analyzer.py --log samples/auth_sample.log --threshold 5 --out findings.json
python3 analyzer.py --log samples/auth_sample.log --csv findings.csv
```

## Layout

```
analyzer.py
samples/auth_sample.log
```

## Notes

Sample log is synthetic lab data (RFC 5737 documentation IPs). Adapt parsers for your real log format before production use.
