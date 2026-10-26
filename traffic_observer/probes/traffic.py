"""Local, read-only Mihomo rollup probe. No sockets, control API, or credentials.

All deltas are *recorded logical increments*, never unique physical traffic.
The first successful poll is a baseline. State and HMAC aliases last one run.
"""
from __future__ import annotations

import datetime as dt
import hmac
import ntpath
import os
from pathlib import Path
import sqlite3
import time
from typing import Any

from .common import local_path

RESOLUTION_MS = 300_000
PROCESS_CLASSES = ("codex.exe", "ChatGPT.exe", "Unknown", "Other")


def _process_class(value: Any) -> str:
    name = ntpath.basename(str(value or "")).casefold()
    if name in {"codex.exe", "codex"}:
        return "codex.exe"
    if name in {"chatgpt.exe", "chatgpt"}:
        return "ChatGPT.exe"
    if name in {"", "unknown"}:
        return "Unknown"
    return "Other"


def _target_class(value: Any) -> str:
    host = str(value or "").casefold().rstrip(".")
    if any(ch.isspace() or ch in "/:@?\\" for ch in host):
        return "other"
    if host == "chatgpt.com":
        return "chatgpt_exact"
    if host.endswith(".chatgpt.com") and host != ".chatgpt.com":
        return "chatgpt_subdomain"
    return "other"


def _utc(value: Any) -> dt.datetime:
    if isinstance(value, dt.datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("observed_utc must be an ISO timestamp or datetime")
    if parsed.tzinfo is None:
        raise ValueError("observed_utc must have an explicit UTC offset")
    return parsed.astimezone(dt.timezone.utc)


class TrafficProbe:
    def __init__(self, db_path: str | Path, *, lookback_minutes: int = 20,
                 completed_cache_minutes: int = 120, hmac_key: bytes | None = None,
                 timeout_seconds: float = 0.25, max_keys: int = 50_000,
                 query_deadline_seconds: float = 1.0):
        self.db_path = local_path(db_path, must_exist=True)
        self.lookback_ms = max(20, int(lookback_minutes)) * 60_000
        self.cache_ms = max(20, int(completed_cache_minutes)) * 60_000
        self.timeout = max(0.0, min(float(timeout_seconds), 2.0))
        self.max_keys = max(100, int(max_keys))
        self.query_deadline_seconds = max(0.05, min(float(query_deadline_seconds), 2.0))
        self._secret = hmac_key if hmac_key is not None else os.urandom(32)
        if not self._secret:
            raise ValueError("hmac_key cannot be empty")
        self._start_ms: int | None = None
        self._last_success_ms: int | None = None
        self._last_success_read_end: str | None = None
        self._last: dict[tuple, tuple[int, int, int]] = {}
        self._present: set[tuple] = set()
        self._initialized = False
        self._generation = 0

    def _alias(self, value: Any) -> str:
        text = str(value or "")
        if text.casefold() == "direct":
            return "DIRECT"
        return "node_" + hmac.new(self._secret, text.encode("utf-8", "replace"), "sha256").hexdigest()[:20]

    def _read_snapshot(self, lower: int, upper: int) -> dict[tuple, tuple[int, int, int]]:
        # Do not create a missing DB or missing WAL index beside the live source.
        if str(self.db_path).startswith(("\\\\", "//")):
            raise RuntimeError("NONLOCAL_DB_PATH_REJECTED")
        if not self.db_path.is_file():
            raise FileNotFoundError()
        wal = Path(str(self.db_path) + "-wal")
        shm = Path(str(self.db_path) + "-shm")
        with self.db_path.open("rb") as source:
            header = source.read(20)  # SQLite journal-format metadata only.
        wal_format = (header.startswith(b"SQLite format 3\x00") and len(header) == 20
                      and (header[18] == 2 or header[19] == 2))
        if (wal_format or (wal.is_file() and wal.stat().st_size)) and not shm.is_file():
            raise RuntimeError("WAL_SIDECAR_UNAVAILABLE")
        conn = None
        try:
            uri = self.db_path.absolute().as_uri() + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=self.timeout)
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA temp_store=MEMORY")
            deadline = time.perf_counter() + self.query_deadline_seconds
            conn.set_progress_handler(lambda: int(time.perf_counter() >= deadline), 1000)
            conn.create_function("audit_process_class", 1, _process_class, deterministic=True)
            conn.create_function("audit_target_class", 1, _target_class, deterministic=True)
            conn.execute("BEGIN")
            cursor = conn.execute(
                "SELECT bucket, audit_process_class(process), audit_target_class(host), outbound, "
                "SUM(upload), SUM(download), SUM(samples) FROM traffic_usage "
                "WHERE resolution=? AND bucket>=? AND bucket<? "
                "GROUP BY bucket, audit_process_class(process), audit_target_class(host), outbound",
                (RESOLUTION_MS, lower, upper),
            )
            rows = cursor.fetchmany(self.max_keys + 1)
            if len(rows) > self.max_keys:
                raise RuntimeError("QUERY_KEY_LIMIT")
            result: dict[tuple, tuple[int, int, int]] = {}
            for bucket, process, target, outbound, upload, download, samples in rows:
                if time.perf_counter() >= deadline:
                    raise RuntimeError("QUERY_DEADLINE_EXCEEDED")
                key = (int(bucket), process, target, self._alias(outbound))
                values = (int(upload or 0), int(download or 0), int(samples or 0))
                # Alias collisions are exceedingly unlikely; summing also handles
                # differently cased reserved DIRECT labels without overwriting.
                previous = result.get(key, (0, 0, 0))
                result[key] = tuple(previous[i] + values[i] for i in range(3))
            return result
        finally:
            if conn is not None:
                try:
                    conn.set_progress_handler(None, 0)
                    conn.rollback()
                finally:
                    conn.close()

    @staticmethod
    def _health(sample_id: Any, observed: str, code: str, status: str = "INFO", **extra: Any) -> dict:
        return {"sample_id": sample_id, "observed_utc": observed, "component": "traffic_probe",
                "status": status, "code": code, **extra}

    def poll(self, sample_id: Any, observed_utc: Any) -> dict:
        health = []
        result = {"bucket_rows": [], "connections": [], "health": health, "totals": {}}
        try:
            observed_dt = _utc(observed_utc)
        except (ValueError, TypeError, OverflowError):
            health.append(self._health(sample_id, "", "INVALID_OBSERVED_UTC", "ERROR"))
            result["totals"] = {"delta_valid": False, "counter_discontinuity": True,
                                "all_download_delta": None, "all_upload_delta": None,
                                "delta_interval_start_utc": None, "delta_interval_end_utc": None}
            return result
        observed = observed_dt.isoformat()
        now_ms = int(observed_dt.timestamp() * 1000)
        bucket = now_ms // RESOLUTION_MS * RESOLUTION_MS
        if self._start_ms is None:
            self._start_ms = now_ms
        start_bucket = self._start_ms // RESOLUTION_MS * RESOLUTION_MS
        fixed_lower = start_bucket - 2 * RESOLUTION_MS
        lower = max(fixed_lower, (now_ms - self.lookback_ms) // RESOLUTION_MS * RESOLUTION_MS)
        upper = bucket + RESOLUTION_MS
        totals = {"sample_id": sample_id, "observed_utc": observed, "resolution_ms": RESOLUTION_MS,
                  "semantics": "RECORDED_LOGICAL_INCREMENT_NOT_PHYSICAL",
                  "connections_status": "UNAVAILABLE_NOT_COLLECTED", "alias_scope": "probe_lifetime",
                  "initial_fixed_lower_bucket_ms": fixed_lower, "query_lower_bucket_ms": lower,
                  "query_upper_exclusive_bucket_ms": upper, "current_bucket_ms": bucket,
                  "observation_start_bucket_ms": start_bucket, "baseline": not self._initialized,
                  "delta_valid": False, "counter_discontinuity": False,
                  "counter_discontinuity_detection_scope": "COARSE_AGGREGATES_ONLY_RAW_RESETS_MAY_BE_MASKED",
                  "late_write_coverage": "QUERIED_BUCKETS_ONLY_BEFORE_QUERY_LOWER_UNAVAILABLE",
                  "delta_interval_start_utc": None, "delta_interval_end_utc": None,
                  "all_download_delta": None, "all_upload_delta": None,
                  "codex_download_delta": None, "codex_upload_delta": None,
                  "codex_chatgpt_download_delta": None, "codex_chatgpt_upload_delta": None,
                  "codex_exact_chatgpt_download_delta": None, "unknown_download_delta": None,
                  "chatgpt_process_download_delta": None,
                  "process_deltas": {}, "bucket_coverage": [], "read_status": "NOT_READ"}
        result["totals"] = totals
        health.append(self._health(sample_id, observed, "UNAVAILABLE_NOT_COLLECTED", "UNAVAILABLE",
                                   detail="No control API, authentication, connection IDs, or connection counters read."))
        health.append(self._health(sample_id, observed, "LOGICAL_PARTIAL_BUCKET_BOUNDARIES",
                                   detail="Flush delay and initial partial bucket are unresolved; DIRECT is a label."))
        if self._last_success_ms is not None and now_ms < self._last_success_ms:
            totals.update(counter_discontinuity=True, read_status="SKIPPED_CLOCK_ROLLBACK")
            health.append(self._health(sample_id, observed, "CLOCK_ROLLBACK", "ERROR"))
            return result
        began = dt.datetime.now(dt.timezone.utc).isoformat()
        timer = time.perf_counter()
        try:
            snapshot = self._read_snapshot(lower, upper)
        except (OSError, sqlite3.Error, RuntimeError, ValueError, OverflowError) as exc:
            # Exception text is deliberately excluded: it can contain raw paths.
            code = "DATABASE_READ_UNAVAILABLE"
            if isinstance(exc, RuntimeError) and exc.args and exc.args[0] in {"WAL_SIDECAR_UNAVAILABLE", "QUERY_KEY_LIMIT", "NONLOCAL_DB_PATH_REJECTED", "QUERY_DEADLINE_EXCEEDED"}:
                code = str(exc.args[0])
            elif isinstance(exc, sqlite3.Error) and getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_INTERRUPT:
                code = "QUERY_DEADLINE_EXCEEDED"
            totals.update(read_status=code, read_started_utc=began,
                          read_ended_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                          read_elapsed_ms=round((time.perf_counter() - timer) * 1000, 3))
            health.append(self._health(sample_id, observed, code, "UNAVAILABLE", error_type=type(exc).__name__))
            return result
        totals.update(read_status="OK", read_started_utc=began,
                      read_ended_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                      read_elapsed_ms=round((time.perf_counter() - timer) * 1000, 3))
        totals["delta_interval_start_utc"] = self._last_success_read_end
        totals["delta_interval_end_utc"] = totals["read_ended_utc"]
        self._apply_snapshot(result, snapshot, now_ms, lower, upper)
        return result

    def _apply_snapshot(self, result: dict, snapshot: dict, now_ms: int, lower: int, upper: int) -> None:
        totals = result["totals"]
        sample_id, observed = totals["sample_id"], totals["observed_utc"]
        start_bucket, current_bucket = totals["observation_start_bucket_ms"], totals["current_bucket_ms"]
        first = not self._initialized
        gap = self._last_success_ms is not None and now_ms - self._last_success_ms > self.lookback_ms
        missing = {key for key in self._present if lower <= key[0] < upper} - set(snapshot)
        discontinuity = bool(missing or gap)
        process = {name: {"upload_delta": 0, "download_delta": 0} for name in PROCESS_CLASSES}
        exact_down = domain_down = domain_up = 0
        old_up = old_down = 0
        valid_up = valid_down = 0
        decreases = reappearances = 0
        for key, current in sorted(snapshot.items()):
            bb, proc, target, outbound = key
            previous = self._last.get(key)
            signed = None if first else tuple(current[i] - previous[i] for i in range(3)) if previous is not None else current
            reappeared = previous is not None and key not in self._present and not first
            reappearances += int(reappeared)
            bad = any(value < 0 for value in current) or (signed is not None and any(value < 0 for value in signed))
            decreases += int(bad)
            discontinuity |= bad or reappeared
            status = "BASELINE_ONLY" if first else "COUNTER_DECREASE" if bad else "REAPPEARED_BASELINE_RETAINED" if reappeared else "NEW_KEY_FULL_LOGICAL_VALUE" if previous is None else "DELTA"
            row = {"sample_id": sample_id, "observed_utc": observed, "resolution_ms": RESOLUTION_MS,
                   "bucket_ms": bb, "bucket_start_utc": dt.datetime.fromtimestamp(bb / 1000, dt.timezone.utc).isoformat(),
                   "process_class": proc, "target_category": target, "outbound_alias": outbound,
                   "upload_bytes": current[0], "download_bytes": current[1], "samples": current[2],
                   "upload_delta_bytes": signed[0] if signed is not None else None,
                   "download_delta_bytes": signed[1] if signed is not None else None,
                   "samples_delta": signed[2] if signed is not None else None,
                   "delta_status": status, "delta_valid": not first and not bad and not gap and not reappeared,
                   "pre_observation_bucket": bb < start_bucket,
                   "closed_bucket_write": bool(signed is not None and (signed[0] or signed[1]) and bb < current_bucket),
                   "semantics": "RECORDED_LOGICAL_NOT_PHYSICAL"}
            result["bucket_rows"].append(row)
            if signed is not None and not bad and not reappeared:
                up, down = signed[:2]
                valid_up += up; valid_down += down
                process[proc]["upload_delta"] += up; process[proc]["download_delta"] += down
                if bb < start_bucket:
                    old_up += up; old_down += down
                if proc == "codex.exe" and target == "chatgpt_exact":
                    exact_down += down
                if proc == "codex.exe" and target in {"chatgpt_exact", "chatgpt_subdomain"}:
                    domain_down += down; domain_up += up
            self._last[key] = current
        if missing or gap or decreases or reappearances:
            result["health"].append(self._health(sample_id, observed, "COUNTER_DISCONTINUITY", "WARNING",
                                                 missing_keys=len(missing), decreased_keys=decreases,
                                                 reappeared_keys=reappearances,
                                                 poll_gap_exceeds_lookback=bool(gap)))
        if reappearances:
            result["health"].append(self._health(sample_id, observed, "REAPPEARED_KEYS_BASELINE_RETAINED", "INFO", keys=reappearances))
        if old_up or old_down:
            result["health"].append(self._health(sample_id, observed, "PRE_START_BUCKET_LATE_WRITE", "WARNING",
                                                 upload_delta=old_up, download_delta=old_down))
        valid = not first and not discontinuity
        totals.update(delta_valid=valid, counter_discontinuity=discontinuity,
                      missing_key_count=len(missing), decreased_key_count=decreases,
                      reappeared_key_count=reappearances, poll_gap_exceeds_lookback=bool(gap),
                      snapshot_upload_bytes=sum(v[0] for v in snapshot.values()),
                      snapshot_download_bytes=sum(v[1] for v in snapshot.values()),
                      bucket_coverage=sorted({key[0] for key in snapshot}), snapshot_keys=len(snapshot),
                      known_valid_upload_delta=valid_up if not first else None,
                      known_valid_download_delta=valid_down if not first else None,
                      pre_start_bucket_late_upload_delta=old_up if not first else None,
                      pre_start_bucket_late_download_delta=old_down if not first else None,
                      all_upload_delta=valid_up if valid else None, all_download_delta=valid_down if valid else None,
                      codex_upload_delta=process["codex.exe"]["upload_delta"] if valid else None,
                      codex_download_delta=process["codex.exe"]["download_delta"] if valid else None,
                      unknown_download_delta=process["Unknown"]["download_delta"] if valid else None,
                      chatgpt_process_download_delta=process["ChatGPT.exe"]["download_delta"] if valid else None,
                      codex_chatgpt_download_delta=domain_down if valid else None,
                      codex_chatgpt_upload_delta=domain_up if valid else None,
                      codex_exact_chatgpt_download_delta=exact_down if valid else None,
                      process_deltas=process if valid else {name: {"upload_delta": None, "download_delta": None} for name in PROCESS_CLASSES},
                      partial_start_bucket_unresolved=True)
        self._present = set(snapshot)
        # Keep completed baselines after leaving the query window, but bounded.
        cutoff = lower - self.cache_ms
        self._last = {key: value for key, value in self._last.items() if key[0] >= cutoff}
        self._initialized = True
        self._last_success_ms = now_ms
        self._last_success_read_end = totals["read_ended_utc"]
        self._generation += 1
        totals["cached_baseline_keys"] = len(self._last)
