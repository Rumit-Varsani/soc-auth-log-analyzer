#!/usr/bin/env python3
"""Authentication log analyzer for failed-login patterns."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

FAILED_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)
ACCEPTED_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


@dataclass
class Finding:
    severity: str
    rule: str
    source_ip: str
    username: str | None
    count: int
    evidence: str


def parse_events(path: Path) -> list[dict]:
    events: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = FAILED_RE.search(line)
        if m:
            events.append(
                {
                    "type": "failed",
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "raw": line.strip(),
                }
            )
            continue
        m = ACCEPTED_RE.search(line)
        if m:
            events.append(
                {
                    "type": "accepted",
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "raw": line.strip(),
                }
            )
    return events


def detect(events: list[dict], threshold: int) -> list[Finding]:
    findings: list[Finding] = []
    fails_by_ip: dict[str, list[dict]] = defaultdict(list)

    for e in events:
        if e["type"] != "failed":
            continue
        fails_by_ip[e["ip"]].append(e)
        findings.append(
            Finding(
                severity="low",
                rule="failed_login",
                source_ip=e["ip"],
                username=e["user"],
                count=1,
                evidence=e["raw"][:160],
            )
        )

    for ip, items in fails_by_ip.items():
        if len(items) >= threshold:
            findings.append(
                Finding(
                    severity="high",
                    rule="brute_force_burst",
                    source_ip=ip,
                    username=None,
                    count=len(items),
                    evidence=f"{len(items)} failed logins from {ip}",
                )
            )
        users = {i["user"] for i in items}
        if len(users) >= max(3, threshold // 2) and len(items) >= threshold:
            findings.append(
                Finding(
                    severity="medium",
                    rule="password_spray_hint",
                    source_ip=ip,
                    username=None,
                    count=len(users),
                    evidence=f"{len(users)} distinct users failing from {ip}",
                )
            )

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order.get(f.severity, 9), -f.count))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze auth logs for failure patterns")
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--out", type=Path, default=Path("findings.json"))
    parser.add_argument("--csv", type=Path, default=None)
    args = parser.parse_args()

    events = parse_events(args.log)
    findings = detect(events, args.threshold)

    # Prefer higher-severity rules first; cap raw failed_login noise in JSON
    ranked = [f for f in findings if f.rule != "failed_login"]
    low = [f for f in findings if f.rule == "failed_login"][:20]

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "soc-auth-log-analyzer",
        "events_parsed": len(events),
        "findings_count": len(findings),
        "findings": [asdict(f) for f in ranked + low],
    }
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[+] Parsed events: {len(events)}")
    print("[+] Findings:")
    for f in findings:
        if f.rule == "failed_login":
            continue
        print(f"    [{f.severity.upper()}] {f.rule} ip={f.source_ip} count={f.count}")
    print(f"[*] JSON → {args.out}")

    if args.csv:
        with args.csv.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=["severity", "rule", "source_ip", "username", "count", "evidence"],
            )
            writer.writeheader()
            for f in findings:
                writer.writerow(asdict(f))
        print(f"[*] CSV  → {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
