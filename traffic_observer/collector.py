"""Optional Windows collector. Explicit start only; never launched by the viewer.

Sources are local counters and metadata. This module has no HTTP clients, socket
connections, model clients, service controls, or network configuration writes.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import csv
import ctypes
from ctypes import wintypes
import datetime as dt
import json
import math
import os
from pathlib import Path
import time
import uuid

from .probes.common import local_path
from .probes.physical import PhysicalProbe
from .probes.processes import collect_processes
from .probes.traffic import TrafficProbe

FORMAT = "codex-traffic-observer-v1"
CONNECTION_STATUS = "UNAVAILABLE_NOT_COLLECTED"
FIELDS = {
    "physical_network.csv": "sample_id observed_utc adapter if_index link_status received_bytes sent_bytes interval_start_utc interval_seconds rx_delta tx_delta rx_bytes_per_second tx_bytes_per_second counter_status".split(),
    "process_snapshots.csv": "sample_id observed_utc platform pid parent_pid start_utc exe_category workload confidence name instance_key parent_name parent_exe_category ancestry_categories source_observed_utc is_cached cache_age_seconds".split(),
    "codex_activity.csv": "sample_id observed_utc event_utc platform workload event_type status count evidence confidence context_safe".split(),
    "live_connections.csv": "sample_id observed_utc source connection_id pid instance_key process_class target_domain started_utc proxy_chain_alias upload_total download_total upload_delta download_delta counter_status".split(),
    "monitor_health.csv": "sample_id observed_utc source code duration_seconds".split(),
    "sample_summary.csv": "sample_id started_utc ended_utc physical_rx_delta physical_tx_delta physical_valid_adapters traffic_capture_utc logical_totals process_counts activity_event_count cycle_duration_seconds".split(),
    "logical_traffic.csv": "sample_id observed_utc resolution_ms bucket_ms bucket_start_utc process_class target_category outbound_alias upload_bytes download_bytes samples upload_delta_bytes download_delta_bytes samples_delta delta_status delta_valid pre_observation_bucket closed_bucket_write semantics".split(),
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _process_start_ticks(pid: int) -> int | None:
    """Read process identity without signals, full command lines, or credentials."""
    if os.name != "nt" or pid <= 0:
        return None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        created, exited, kernel_time, user_time = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel_time), ctypes.byref(user_time)):
            return None
        return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
    finally:
        kernel.CloseHandle(handle)


def _json_write(path: Path, value: dict):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, path)


def _prepare_output(value: str | Path) -> Path:
    output = local_path(value)
    package_root = Path(__file__).resolve().parent.parent
    if output == package_root or package_root in output.parents:
        raise ValueError("Keep collected data outside the application/repository directory")
    if output.exists():
        marker = output / ".observer-output.json"
        if any(output.iterdir()) and not marker.is_file():
            raise ValueError("Output must be empty or belong to this collector; existing audit directories are read-only")
        if marker.exists() and json.loads(marker.read_text(encoding="utf-8")).get("format") != FORMAT:
            raise ValueError("Unrecognized output directory format")
        # Do not follow an output file symlink into an existing data source.
        for item in output.iterdir():
            if item.is_symlink() or getattr(item.lstat(), "st_file_attributes", 0) & 0x400:
                raise ValueError("Output directory must not contain reparse points")
    output.mkdir(parents=True, exist_ok=True)
    return output


class _Lock:
    def __init__(self, path: Path):
        self.path = path
        self.file = None

    def __enter__(self):
        import msvcrt
        self.file = self.path.open("a+b")
        if self.file.seek(0, 2) == 0:
            self.file.write(b"0")
            self.file.flush()
        self.file.seek(0)
        try:
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.file.close()
            self.file = None
            raise RuntimeError("This output directory already has a collector") from None
        return self

    def __exit__(self, *args):
        import msvcrt
        if self.file is not None:
            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            self.file.close()


class _Csv:
    def __init__(self, path: Path, fields: list[str]):
        self.fields = ["run_id", *fields]
        empty = not path.exists() or path.stat().st_size == 0
        if not empty:
            with path.open(encoding="utf-8-sig", newline="") as existing:
                if next(csv.reader(existing), None) != self.fields:
                    raise ValueError("Existing collector CSV schema does not match")
        self.file = path.open("a", encoding="utf-8-sig" if empty else "utf-8", newline="")
        self.writer = csv.DictWriter(self.file, fieldnames=self.fields)
        if empty:
            self.writer.writeheader()
            self.file.flush()

    def append(self, run: str, rows: list[dict]):
        for row in rows:
            result = {key: row.get(key) for key in self.fields}
            result["run_id"] = run
            for key, value in result.items():
                if isinstance(value, (dict, list, tuple)):
                    result[key] = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
                elif isinstance(value, str) and value[:1] in ("=", "+", "-", "@"):
                    result[key] = "'" + value
            self.writer.writerow(result)
        self.file.flush()

    def close(self):
        self.file.close()


def _stopped_by_flag(output: Path, state: dict) -> bool:
    try:
        flag = json.loads((output / "stop.request.json").read_text(encoding="utf-8-sig"))
        return (flag.get("run_id") == state["run_id"]
                and flag.get("monitor_pid") == state["monitor_pid"]
                and flag.get("monitor_process_start_ticks") == state["monitor_process_start_ticks"])
    except (OSError, ValueError, TypeError):
        return False


def request_stop(output_dir: str | Path) -> dict:
    """Write a run-scoped flag only after verifying the collector's live identity."""
    output = local_path(output_dir, must_exist=True)
    marker = output / ".observer-output.json"
    if not marker.is_file() or json.loads(marker.read_text(encoding="utf-8")).get("format") != FORMAT:
        raise ValueError("This is not an output directory owned by the portable collector")
    state = json.loads((output / "monitor_state.json").read_text(encoding="utf-8"))
    if state.get("status") == "stopped":
        return {"status": "already_stopped", "processes_terminated": 0}
    actual = _process_start_ticks(int(state["monitor_pid"]))
    if actual is None or actual != state.get("monitor_process_start_ticks"):
        return {"status": "identity_unavailable_or_changed", "stop_flag_written": False, "processes_terminated": 0}
    _json_write(output / "stop.request.json", {
        "run_id": state["run_id"], "monitor_pid": state["monitor_pid"],
        "monitor_process_start_ticks": actual, "requested_utc": utc_now(),
    })
    return {"status": "stop_requested", "run_id": state["run_id"], "processes_terminated": 0}


def run_collector(output_dir: str | Path, interval: float = 10, duration: float = 0,
                  mihomo_db: str | Path | None = None) -> int:
    """Collect until Ctrl+C, a matching stop flag, or an optional duration limit.

    A Mihomo path must be explicitly supplied; it is never discovered by scanning
    user files. WSL, task log bodies, control APIs and socket content are omitted.
    """
    if os.name != "nt":
        raise RuntimeError("The optional collector currently supports Windows only")
    if not math.isfinite(interval) or not 5 <= interval <= 15:
        raise ValueError("interval must be between 5 and 15 seconds")
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("duration must be zero or a positive number")
    source = local_path(mihomo_db, must_exist=True) if mihomo_db is not None else None
    output = _prepare_output(output_dir)
    if source is not None and (source == output or output in source.parents):
        raise ValueError("The source database must be outside the output directory")
    with _Lock(output / "monitor.lock"):
        _json_write(output / ".observer-output.json", {"format": FORMAT})
        run = str(uuid.uuid4())
        started = utc_now()
        state = {
            "run_id": run, "monitor_pid": os.getpid(), "monitor_process_start_ticks": _process_start_ticks(os.getpid()),
            "started_utc": started, "status": "starting", "interval_seconds": interval, "samples": 0,
            "physical_rx_total": 0, "physical_tx_total": 0, "logical_totals": {},
            "connection_source": CONNECTION_STATUS, "last_processes": [],
            "last_limitations": ["TASK_ACTIVITY_NOT_COLLECTED", "WSL_NOT_COLLECTED"],
            "network_calls_by_monitor": 0,
        }
        outputs = {}
        reason = "stopped"
        _json_write(output / "monitor_state.json", state)
        try:
            for name, fields in FIELDS.items():
                outputs[name] = _Csv(output / name, fields)
            physical = PhysicalProbe()
            traffic = TrafficProbe(source) if source is not None else None
            last_health = {}
            began = next_tick = time.monotonic()
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="local_metadata") as pool:
                while True:
                    if _stopped_by_flag(output, state):
                        reason = "local_run_scoped_stop_request"
                        break
                    if duration and time.monotonic() - began >= duration:
                        reason = "requested_duration_complete"
                        break
                    sample = state["samples"] + 1
                    stamp, cycle = utc_now(), time.monotonic()
                    jobs = {"physical": pool.submit(physical.poll, sample, stamp),
                            "process": pool.submit(collect_processes)}
                    if traffic is not None:
                        jobs["logical"] = pool.submit(traffic.poll, sample, stamp)
                    results, health = {}, []
                    for name, future in jobs.items():
                        try:
                            results[name] = future.result()
                        except Exception as exc:
                            results[name] = {}
                            health.append((name, "PROBE_FAILED_" + type(exc).__name__))
                    physical_rows = results.get("physical", {}).get("rows", [])
                    processes = results.get("process", {}).get("rows", [])
                    logical = results.get("logical", {})
                    totals = logical.get("totals", {"delta_valid": False, "read_status": "NOT_CONFIGURED", "all_download_delta": None, "all_upload_delta": None, "codex_download_delta": None, "unknown_download_delta": None})
                    for row in processes:
                        row.update(sample_id=sample, observed_utc=stamp)
                    outputs["physical_network.csv"].append(run, physical_rows)
                    outputs["process_snapshots.csv"].append(run, processes)
                    buckets = [row for row in logical.get("bucket_rows", []) if row.get("delta_status") != "DELTA" or any(row.get(key) not in (None, 0) for key in ("upload_delta_bytes", "download_delta_bytes", "samples_delta"))]
                    outputs["logical_traffic.csv"].append(run, buckets)
                    good = [row for row in physical_rows if row.get("counter_status") == "valid_delta"]
                    rx, tx = sum(row["rx_delta"] for row in good), sum(row["tx_delta"] for row in good)
                    state["physical_rx_total"] += rx
                    state["physical_tx_total"] += tx
                    if totals.get("delta_valid"):
                        for key, value in totals.items():
                            if key.endswith("_delta") and isinstance(value, (int, float)) and not isinstance(value, bool):
                                state["logical_totals"][key] = state["logical_totals"].get(key, 0) + value
                    process_counts = {}
                    for row in processes:
                        process_counts[row["workload"]] = process_counts.get(row["workload"], 0) + 1
                    elapsed, ended = time.monotonic() - cycle, utc_now()
                    outputs["sample_summary.csv"].append(run, [{
                        "sample_id": sample, "started_utc": stamp, "ended_utc": ended,
                        "physical_rx_delta": rx if good else None, "physical_tx_delta": tx if good else None,
                        "physical_valid_adapters": len(good), "traffic_capture_utc": totals.get("read_ended_utc"),
                        "logical_totals": totals, "process_counts": process_counts, "activity_event_count": 0,
                        "cycle_duration_seconds": elapsed,
                    }])
                    for name, result in results.items():
                        for code in result.get("health", []):
                            health.append((name, code if isinstance(code, str) else code.get("code", "SOURCE_STATUS")))
                    health += [("connections", CONNECTION_STATUS), ("activity", "TASK_ACTIVITY_NOT_COLLECTED")]
                    if traffic is None:
                        health.append(("logical", "MIHOMO_DATABASE_NOT_CONFIGURED"))
                    if elapsed > interval:
                        health.append(("collector", "SAMPLING_OVERRUN"))
                    for key in health:
                        if key not in last_health or sample - last_health[key] >= 60:
                            outputs["monitor_health.csv"].append(run, [{"sample_id": sample, "observed_utc": ended, "source": key[0], "code": key[1], "duration_seconds": elapsed}])
                            last_health[key] = sample
                    state.update(samples=sample, last_sample_utc=ended, status="running", last_cycle_seconds=elapsed,
                                 last_processes=processes, last_process_counts=process_counts, last_logical_totals=totals,
                                 last_limitations=sorted({code for _, code in health}))
                    _json_write(output / "monitor_state.json", state)
                    next_tick = max(next_tick + interval, time.monotonic())
                    while time.monotonic() < next_tick:
                        if _stopped_by_flag(output, state) or (duration and time.monotonic() - began >= duration):
                            break
                        time.sleep(min(0.25, max(0, next_tick - time.monotonic())))
        except KeyboardInterrupt:
            reason = "foreground_keyboard_interrupt"
        except Exception as exc:
            reason = "collector_error_" + type(exc).__name__
            raise
        finally:
            for stream in outputs.values():
                stream.close()
            state.update(status="stopped", stop_reason=reason, stopped_utc=utc_now())
            _json_write(output / "monitor_state.json", state)
    return 0
