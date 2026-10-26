"""Unknown process ledger increments, with explicitly non-causal co-observation.

Only metadata supplied by AuditStore is used. No filesystem, network, process
inspection, or application content is accessed here. Cumulative bucket values
are deliberately never consumed.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
from collections import defaultdict
from typing import Any

SERVICES = frozenset({"chatgpt_exact", "chatgpt_subdomain", "openai", "google_drive",
    "google", "microsoft_update", "microsoft", "github", "tencent", "other",
    "other_domain", "ip_target", "invalid_or_nonhost", "empty_target"})
WORKLOADS = {
    "CodexDesktop": "CodexDesktop", "CampusMainWSL": "CampusRadarWSL",
    "CampusRadarWSL": "CampusRadarWSL", "CampusInsights": "CampusInsights",
    "VSCode": "VSCode", "CodexVSCode": "VSCode", "CodexCLI": "CodexCLI",
    "InteractiveCLI": "CodexCLI", "Unknown": "UnclassifiedCodex",
}
LABELS = {"CodexDesktop": "Desktop", "CampusRadarWSL": "Campus WSL",
    "CampusInsights": "Campus Insights", "VSCode": "VS Code",
    "CodexCLI": "CLI", "UnclassifiedCodex": "未分类 Codex"}
EXE_CATEGORIES = frozenset({"codex_desktop_package_process", "codex_desktop_engine_path",
    "codex_dedicated_campus_linux_runtime", "codex_pinned_windows_runtime",
    "codex_executable_path_unavailable", "codex_cli", "codex_cli_executable",
    "codex_vscode_extension", "codex_other_path", "codex_path_unavailable",
    "codex_other_windows", "codex_other_wsl_runtime", "executable_path_unavailable"})
CONFIDENCES = frozenset({"high_path_and_ancestry", "medium_parent_name",
    "medium_dedicated_path_and_python_ancestor", "high_ancestor_path", "synthetic_demo_only", "unclassified"})


def _time(value: Any) -> float | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        number = parsed.timestamp() if parsed.tzinfo else None
        return number if number is not None and math.isfinite(number) else None
    except (ValueError, TypeError, OSError, OverflowError):
        return None


def _iso(value: float) -> str:
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat()


def _int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    text = str(value)
    return int(text) if re.fullmatch(r"[0-9]{1,24}", text) else None


def _true(value: Any) -> bool:
    return value is True or isinstance(value, str) and value.casefold() == "true"


def _false(value: Any) -> bool:
    return value is False or isinstance(value, str) and value.casefold() == "false"


def _uncached_age(value: Any) -> bool:
    if value in (None, ""):
        return True  # Older records still require their source time inside cycle.
    try:
        return not isinstance(value, bool) and float(value) == 0
    except (ValueError, TypeError, OverflowError):
        return False


def _obj(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    try:
        result = json.loads(value) if isinstance(value, str) and len(value) <= 65536 else None
        return result if isinstance(result, dict) else {}
    except (ValueError, RecursionError):
        return {}


def _route(value: Any) -> str:
    text = str(value or "")
    if text == "DIRECT":
        return text
    if re.fullmatch(r"node_[a-fA-F0-9]{8,64}", text):
        return text.lower()
    if not text:
        return "route_unavailable"
    # A future collector must not accidentally expose node names or locations.
    return "route_" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _incomplete(source: dict) -> bool:
    return source.get("status") != "readable" or any(source.get(k) for k in (
        "tail_truncated", "cache_dropped_rows", "invalid_rows", "backlog", "pending_record"))


def _candidates(rows: list[dict], cycle: tuple[float | None, float | None],
                interval: tuple[float, float]) -> tuple[list[dict], int]:
    result = {}; rejected = 0
    cycle_start, cycle_end = cycle
    for row in rows:
        observed = _time(row.get("source_observed_utc"))
        began = _time(row.get("start_utc"))
        pid = _int(row.get("pid"))
        if (not _false(row.get("is_cached")) or not _uncached_age(row.get("cache_age_seconds"))
                or pid is None or pid == 0
                or cycle_start is None or cycle_end is None or observed is None or began is None
                or not cycle_start <= observed <= cycle_end or began > observed
                or max(began, interval[0]) >= min(observed, interval[1])):
            rejected += 1
            continue
        workload = WORKLOADS.get(row.get("workload"), "UnclassifiedCodex")
        raw_platform = row.get("platform", "")
        platform = raw_platform if raw_platform in ("windows", "wsl", "wsl_ubuntu", "linux") else "other"
        category = row.get("exe_category")
        confidence = row.get("confidence")
        candidate = {"pid":pid, "parent_pid":_int(row.get("parent_pid")),
            "platform":platform, "workload":workload,
            "exe_category":category if category in EXE_CATEGORIES else "unclassified",
            "confidence":confidence if confidence in CONFIDENCES else "unclassified",
            "start_utc":_iso(began), "source_observed_utc":_iso(observed)}
        result[(platform, pid, began, workload)] = candidate
    return list(result.values()), rejected


def build_unknown_breakdown(summaries: list[dict], details: list[dict], processes: list[dict],
                            *, start: float | None, end: float | None,
                            source_coverage: dict) -> dict:
    """Partition validated Unknown increments once, without assigning a PID owner.

    A sample's detail sum exceeding its summary is quarantined rather than
    arbitrarily trimming rows. Equal duplicate keys are ignored; conflicting
    duplicates are excluded. Missing detail remains a separate residual.
    """
    notes = ["Unknown 仍表示原进程身份未确认；同期实例仅为落库区间共同观察到的候选，不是流量归属。",
        "桌面单独出现也不能证明流量属于桌面；未采到或过期进程不能证明空闲或任务不存在。",
        "逻辑增量可能含延迟写入的旧桶，不能据落库时刻证明请求或传输发生时刻。",
        "只使用单一 5 分钟分辨率的有效增量字段，不使用累计桶值或不同分辨率之和。"]
    coverage = {"complete":False, "summary_samples":0, "detail_samples":0,
        "matched_samples":0, "missing_samples":0, "invalid_rows":0,
        "duplicate_rows":0, "conflicting_rows":0, "summary_conflicts":0,
        "excluded_summary_samples":0, "out_of_window_rows":0,
        "unsupported_resolution_rows":0, "overshoot_samples":0,
        "stale_or_invalid_process_rows":0, "process_missing_samples":0,
        "closed_bucket_write_rows":0, "pre_observation_bucket_rows":0,
        "sources":{name:dict(source_coverage.get(name, {})) for name in (
            "sample_summary.csv", "logical_traffic.csv", "process_snapshots.csv")}}
    unique_summary = {}; conflicts = set()
    for row in summaries:
        sample = _int(row.get("sample_id"))
        if sample is None:
            continue
        if sample in unique_summary:
            if row != unique_summary[sample]:
                conflicts.add(sample)
        else:
            unique_summary[sample] = row
    coverage["summary_conflicts"] = len(conflicts)
    valid = {}; totals_down = []; totals_up = []
    for sample, row in unique_summary.items():
        obj = _obj(row.get("logical_totals"))
        a, b = _time(obj.get("delta_interval_start_utc")), _time(obj.get("delta_interval_end_utc"))
        is_valid = (_true(obj.get("delta_valid")) and not _true(obj.get("counter_discontinuity"))
            and sample not in conflicts and a is not None and b is not None and b > a
            and _int(obj.get("resolution_ms", 300000)) == 300000)
        if not is_valid:
            # Baseline/invalid source rows are not traffic or zero measurements.
            coverage["excluded_summary_samples"] += 1
            continue
        if start is not None and a < start or end is not None and b > end + .001:
            coverage["out_of_window_rows"] += 1
            continue
        down = _int(obj.get("unknown_download_delta"))
        unknown = _obj(_obj(obj.get("process_deltas")).get("Unknown"))
        up = _int(obj.get("unknown_upload_delta"))
        if up is None:
            up = _int(unknown.get("upload_delta"))
        if down is None:
            coverage["excluded_summary_samples"] += 1
            continue
        valid[sample] = {"down":down, "up":up, "a":a, "b":b,
            "cycle":(_time(row.get("started_utc")), _time(row.get("ended_utc")))}
        totals_down.append(down)
        if up is not None:
            totals_up.append(up)
    coverage["summary_samples"] = len(valid)
    total_down = sum(totals_down) if valid else None
    total_up = sum(totals_up) if valid and len(totals_up) == len(valid) else None
    unique = {}; bad_keys = set()
    for row in details:
        if str(row.get("process_class", "")).casefold() != "unknown":
            continue
        sample = _int(row.get("sample_id"))
        if sample not in valid:
            continue
        if _int(row.get("resolution_ms")) != 300000:
            coverage["unsupported_resolution_rows"] += 1
            continue
        key = (sample, row.get("bucket_ms"), row.get("target_category"),
               row.get("service_category", row.get("service")), row.get("outbound_alias"))
        if key in unique:
            # Only relevant fields decide identity: cumulative values are not read.
            fields = ("upload_delta_bytes", "download_delta_bytes", "samples_delta", "delta_status", "delta_valid")
            if any(row.get(k) != unique[key].get(k) for k in fields):
                bad_keys.add(key)
            else:
                coverage["duplicate_rows"] += 1
        else:
            unique[key] = row
    coverage["conflicting_rows"] = len(bad_keys)
    by_sample = defaultdict(list)
    for key, row in unique.items():
        down = _int(row.get("download_delta_bytes")); up = _int(row.get("upload_delta_bytes"))
        bucket = _int(row.get("bucket_ms"))
        if (key in bad_keys or not _true(row.get("delta_valid"))
                or row.get("delta_status") not in ("DELTA", "NEW_KEY_FULL_LOGICAL_VALUE")
                or down is None or up is None or bucket is None or bucket % 300000 != 0):
            coverage["invalid_rows"] += 1
            continue
        by_sample[key[0]].append((row, up, down))
    proc_by_sample = defaultdict(list)
    for row in processes:
        proc_by_sample[_int(row.get("sample_id"))].append(row)
    groups = {}; detail_down = detail_up = 0
    for sample, meta in valid.items():
        sample_rows = by_sample.get(sample, [])
        down = sum(item[2] for item in sample_rows); up = sum(item[1] for item in sample_rows)
        if down > meta["down"] or meta["up"] is not None and up > meta["up"]:
            coverage["overshoot_samples"] += 1
            coverage["missing_samples"] += 1
            continue
        if sample_rows:
            coverage["detail_samples"] += 1
        if down == meta["down"] and (meta["up"] is None or up == meta["up"]):
            coverage["matched_samples"] += 1
        else:
            coverage["missing_samples"] += 1
        candidates, rejected = _candidates(proc_by_sample.get(sample, []), meta["cycle"], (meta["a"], meta["b"]))
        coverage["stale_or_invalid_process_rows"] += rejected
        if not candidates:
            coverage["process_missing_samples"] += 1
        kinds = sorted({r["workload"] for r in candidates})
        workload_key = "+".join(kinds) if kinds else "process_observation_missing"
        label = " + ".join(LABELS[k] for k in kinds) if kinds else "无有效同期进程观测"
        if kinds == ["CodexDesktop"]:
            label = "仅新鲜观测到 Desktop（非独占归属）"
        for row, up, down in sample_rows:
            if not up and not down:
                continue
            service = row.get("service_category", row.get("service", row.get("target_category")))
            service = service if service in SERVICES else "other"
            route = _route(row.get("outbound_alias"))
            key = (service, route, workload_key)
            if key not in groups:
                groups[key] = {"group_id":"unknown_" + hashlib.sha256("|".join(key).encode()).hexdigest()[:16],
                    "service_category":service, "route_alias":route, "workload_key":workload_key,
                    "workload_label":label, "download_bytes":0, "upload_bytes":0,
                    "first_utc":_iso(meta["a"]), "last_utc":_iso(meta["b"]),
                    "evidence_level":"coobserved_only" if candidates else "process_observation_missing",
                    "evidence":["logical_traffic.csv: upload_delta_bytes/download_delta_bytes; delta_valid=True; resolution_ms=300000",
                        "sample_summary.csv: logical_totals.delta_interval_start_utc/delta_interval_end_utc; unknown_download_delta",
                        "process_snapshots.csv: same run_id/sample_id; is_cached=False; source_observed_utc inside cycle; process lifetime overlaps interval"],
                    "limitations":["未取得连接 PID；不能把这些字节归属到候选实例。", "同期仅表示账本落库观察区间，非网络请求活动证明。"],
                    "_samples":set(), "_candidates":{}, "ledger_samples_delta":0,
                    "closed_bucket_write_rows":0, "pre_observation_bucket_rows":0}
            group = groups[key]
            group["download_bytes"] += down; group["upload_bytes"] += up
            group["first_utc"] = min(group["first_utc"], _iso(meta["a"]))
            group["last_utc"] = max(group["last_utc"], _iso(meta["b"]))
            group["_samples"].add(sample)
            group["ledger_samples_delta"] += _int(row.get("samples_delta")) or 0
            for flag in ("closed_bucket_write", "pre_observation_bucket"):
                if _true(row.get(flag)):
                    group[flag + "_rows"] += 1; coverage[flag + "_rows"] += 1
            for candidate in candidates:
                ident = (candidate["platform"], candidate["pid"], candidate["start_utc"], candidate["workload"])
                group["_candidates"][ident] = candidate
            detail_down += down; detail_up += up
    output = []
    for group in groups.values():
        samples = group.pop("_samples"); candidates = group.pop("_candidates")
        group.update(sample_count=len(samples), first_sample_id=min(samples), last_sample_id=max(samples),
            candidates=list(candidates.values())[:128], candidate_count=len(candidates),
            candidates_truncated=len(candidates)>128,
            download_share=group["download_bytes"] / total_down if total_down else None)
        group["evidence"].append(f"sample_id range={min(samples)}..{max(samples)}; distinct samples={len(samples)}")
        output.append(group)
    output.sort(key=lambda r:(-r["download_bytes"], -r["upload_bytes"], r["group_id"]))
    detail_source = coverage["sources"]["logical_traffic.csv"]
    summary_source = coverage["sources"]["sample_summary.csv"]
    summary_complete = not _incomplete(summary_source) and not coverage["summary_conflicts"]
    details_complete = not _incomplete(detail_source) and not any(coverage[k] for k in (
        "missing_samples", "invalid_rows", "conflicting_rows", "unsupported_resolution_rows", "overshoot_samples"))
    coverage["complete"] = bool(valid) and summary_complete and details_complete
    coverage["process_observations_complete"] = (not _incomplete(coverage["sources"]["process_snapshots.csv"])
        and coverage["process_missing_samples"] == 0 and coverage["stale_or_invalid_process_rows"] == 0)
    if not coverage["complete"]:
        notes.append("明细覆盖不完整；缺额只表示未匹配到有效明细，不推定服务、出口或进程。")
    if coverage["overshoot_samples"]:
        notes.append("有样本的明细超过同样本摘要，已整样本隔离；未裁剪或强行配平。")
    if not summary_complete:
        notes.append("摘要来源有截断、缺失或冲突，总量本身也只代表当前可验证区间。")
    if not coverage["process_observations_complete"]:
        notes.append("进程观测存在缺失、缓存、过期或截断；仅列出通过新鲜度检验的候选，不能排除其他实例。")
    if total_up is None:
        notes.append("摘要缺少可验证的 Unknown 上行总量；不把部分上行明细补作总量。")
    return {"status":"available" if valid and coverage["complete"] else "partial" if valid else "unavailable",
        "total_down":total_down, "total_up":total_up,
        "detail_down":detail_down if valid else None, "detail_up":detail_up if valid else None,
        "residual_down":total_down-detail_down if total_down is not None else None,
        "residual_up":total_up-detail_up if total_up is not None else None,
        "groups":output, "coverage":coverage, "limitations":notes,
        "semantics":"monitor_delta_cooccurrence",
        "window":{"start_utc":_iso(start) if start is not None else None,
                  "end_utc":_iso(end) if end is not None else None}}
