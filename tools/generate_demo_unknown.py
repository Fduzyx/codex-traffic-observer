"""Add reproducible, fictional Unknown detail fixtures to the bundled demo.

Only the bundled synthetic demo may be changed. No actual observations are read.
"""
from __future__ import annotations

import csv
import datetime as dt
import json
from collections import defaultdict
from pathlib import Path

DEMO = Path(__file__).resolve().parent.parent / "traffic_observer" / "demo"


def read(name):
    with (DEMO / name).open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        return reader.fieldnames, list(reader)


def write(name, fields, rows):
    with (DEMO / name).open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    assert json.loads((DEMO / "demo_manifest.json").read_text())["synthetic"] is True
    fields, samples = read("sample_summary.csv")
    proc_fields, processes = read("process_snapshots.csv")
    assert all(r["run_id"] == "demo-current" and r["started_utc"].startswith("2000-01-01") for r in samples)
    processes = [r for r in processes if int(r["pid"]) < 7100]
    detail = []
    cumulative = defaultdict(lambda: [0, 0])
    for sample in samples:
        sid = int(sample["sample_id"])
        counts = json.loads(sample["process_counts"])
        counts.pop("CampusMainWSL", None)
        counts.pop("CampusInsights", None)
        for enabled, workload, platform, pid, parent, start, category in (
            (20 <= sid <= 40 or 63 <= sid <= 80, "CampusMainWSL", "wsl", 7100, 7090,
             "2000-01-01T12:02:50+00:00", "codex_dedicated_campus_linux_runtime"),
            (35 <= sid <= 50, "CampusInsights", "windows", 7200, 7190,
             "2000-01-01T12:05:20+00:00", "codex_generic_windows_runtime"),
        ):
            if enabled:
                counts[workload] = 1
                processes.append(dict(zip(proc_fields, [sample["run_id"], sid, sample["started_utc"],
                    platform, pid, parent, start, category, workload, "synthetic_demo_only", "codex",
                    f"demo:{pid}", "python3" if platform == "wsl" else "python.exe",
                    "linux_python_runtime" if platform == "wsl" else "python_runtime", "[]",
                    sample["started_utc"], False, 0])))
        sample["process_counts"] = json.dumps(counts)
        totals = json.loads(sample["logical_totals"])
        down = totals.get("unknown_download_delta")
        if totals.get("delta_valid") is not True or down is None:
            continue
        up = down // 80
        totals.setdefault("process_deltas", {})["Unknown"] = {"upload_delta": up, "download_delta": down}
        sample["logical_totals"] = json.dumps(totals)
        stamp = dt.datetime.fromisoformat(totals["delta_interval_end_utc"])
        bucket = int(stamp.timestamp() * 1000) // 300000 * 300000
        distributions = [
            ("chatgpt_exact", "node_demo_proxy", down * 85 // 100, up * 85 // 100),
            ("chatgpt_subdomain", "node_demo_proxy", down * 10 // 100, up * 10 // 100),
        ]
        distributions.append(("other", "DIRECT", down - sum(x[2] for x in distributions), up - sum(x[3] for x in distributions)))
        for target, route, received, sent in distributions:
            key = (bucket, target, route)
            cumulative[key][0] += sent
            cumulative[key][1] += received
            detail.append({"run_id": sample["run_id"], "sample_id": sid,
                "observed_utc": sample["traffic_capture_utc"], "resolution_ms": 300000,
                "bucket_ms": bucket, "bucket_start_utc": dt.datetime.fromtimestamp(bucket / 1000, dt.timezone.utc).isoformat(),
                "process_class": "Unknown", "target_category": target, "outbound_alias": route,
                "upload_bytes": cumulative[key][0], "download_bytes": cumulative[key][1], "samples": sid,
                "upload_delta_bytes": sent, "download_delta_bytes": received, "samples_delta": 1,
                "delta_status": "DELTA", "delta_valid": True, "pre_observation_bucket": False,
                "closed_bucket_write": False, "semantics": "SYNTHETIC_RECORDED_INCREMENT"})
    processes.sort(key=lambda r: (int(r["sample_id"]), int(r["pid"])))
    write("sample_summary.csv", fields, samples)
    write("process_snapshots.csv", proc_fields, processes)
    write("logical_traffic.csv", list(detail[0]), detail)
    print(f"Updated synthetic demo only: {len(detail)} logical detail rows.")


if __name__ == "__main__":
    main()
