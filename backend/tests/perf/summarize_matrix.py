#!/usr/bin/env python3
"""Validate extended performance logs and export measured rows as JSON."""
import argparse
import collections
import json
import math
import re
import statistics
from pathlib import Path


def summarize(paths, expected_cases=None, expected_rounds=None):
    expected = {}
    measured = {}
    environments = []
    for path in paths:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        if "PASS" not in lines or any(line.startswith("FAIL") for line in lines):
            raise ValueError(f"test run did not pass: {path}")
        for line in lines:
            if "PERF_MATRIX " in line:
                environments.append(dict(re.findall(r"(\w+)=([^\s]+)", line)))
            if "PERF_EXPECT " not in line and "PERF protocol=" not in line:
                continue
            row = dict(re.findall(r"(\w+)=([^\s]+)", line))
            key = tuple(row[field] for field in ("protocol", "network", "mux", "pool", "round"))
            dest = expected if "PERF_EXPECT " in line else measured
            if key in dest:
                raise ValueError(f"duplicate measurement or expectation: {key}")
            dest[key] = row
    if not expected or expected.keys() != measured.keys():
        raise ValueError(f"incomplete matrix: expected={len(expected)}, measured={len(measured)}")
    groups = collections.defaultdict(list)
    for key, row in measured.items():
        if row["bytes"] != expected[key]["bytes"]:
            raise ValueError(f"payload size mismatch: {key}")
        for field in ("seconds", "MiBps", "p50_us", "p95_us"):
            value = float(row[field])
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"invalid {field}: {key}")
        if float(row["p95_us"]) < float(row["p50_us"]):
            raise ValueError(f"invalid latency percentiles: {key}")
        for field in ("pool", "round", "bytes"):
            row[field] = int(row[field])
        for field in ("seconds", "MiBps", "p50_us", "p95_us"):
            row[field] = float(row[field])
        groups[key[:-1]].append(row)
    if expected_cases is not None:
        cases = {key[0] for key in groups}
        if len(cases) != expected_cases or len(groups) != expected_cases * 5:
            raise ValueError(f"expected {expected_cases} cases with all five paths")
        for name in cases:
            paths_seen = {(key[1], key[2]) for key in groups if key[0] == name}
            if paths_seen != {("tcp", kind) for kind in ("off", "smux", "yamux", "h2mux")} | {("udp", "udp")}:
                raise ValueError(f"missing path: {name}")
    if expected_rounds is not None:
        for key, rows in groups.items():
            if {row["round"] for row in rows} != set(range(1, expected_rounds + 1)):
                raise ValueError(f"missing round: {key}")
    medians = []
    for key, rows in groups.items():
        item = dict(zip(("protocol", "network", "mux", "pool"), key))
        item["rounds"] = len(rows)
        for field in ("MiBps", "p50_us", "p95_us"):
            item[field] = statistics.median(row[field] for row in rows)
        medians.append(item)
    return {"environments": environments, "measurements": list(measured.values()), "medians": medians}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+")
    parser.add_argument("--cases", type=int)
    parser.add_argument("--rounds", type=int)
    args = parser.parse_args()
    try:
        print(json.dumps(summarize(args.logs, args.cases, args.rounds), indent=2))
    except ValueError as exc:
        parser.exit(1, f"{exc}\n")
