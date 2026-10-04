#!/usr/bin/env python3
"""Summarize TestLocalPerformance logs; reject incomplete/duplicate matrices."""
import collections
import re
import statistics
import sys

rows = collections.defaultdict(list)
lines = open(sys.argv[1], encoding="utf-8").readlines()
if not any(line.strip() == "PASS" for line in lines) or any(line.startswith("FAIL") for line in lines):
    raise SystemExit("performance test run did not pass")
for line in lines:
    if "PERF protocol=" not in line:
        continue
    fields = dict(re.findall(r"(\w+)=([^\s]+)", line))
    rows[fields["protocol"], fields["network"]].append(fields)
if len(rows) != 130 or any(len(v) != 3 or {x["round"] for x in v} != {"1", "2", "3"} for v in rows.values()):
    raise SystemExit("expected 65 protocols × TCP/UDP × 3 unique rounds")
if any(x["pool"] != "1" for v in rows.values() for x in v):
    raise SystemExit("expected Pool=1")
print("# 完整性能矩阵\n")
print("Apple M4 / macOS arm64 / Go 1.27.0 / GOMAXPROCS=10；loopback，非 race。")
print("65个合法外层配置 × TCP/UDP × 3轮 = 390条测量。每列分别取三轮中位数；非置信区间。")
print("TCP：内层TLS1.3、64MiB；UDP：1200B×16384、窗口16；均排除握手与预热。")
print("吞吐分子为单份payload（不是收发相加）；RTT为200次64B回显的p50/p95，单位µs。")
print("Vision配置下UDP仍走加密XUDP，不发生直拷；0rtt/1rtt为配置标签，不是握手性能。\n")
print("| 外层配置 | TCP MiB/s | TCP RTT p50/p95 µs | UDP MiB/s | UDP RTT p50/p95 µs |")
print("|---|---:|---:|---:|---:|")
for name in dict.fromkeys(k[0] for k in rows):
    values = []
    for network in ("tcp", "udp"):
        def median(field):
            return statistics.median(float(x[field]) for x in rows[name, network])
        values += [f'{median("MiBps"):.2f}', f'{median("p50_us"):.1f}/{median("p95_us"):.1f}']
    print("| " + name + " | " + " | ".join(values) + " |")
