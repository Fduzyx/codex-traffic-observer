"""Optional Unknown-service detail from retained, complete Mihomo 5-minute buckets.

This is an independent ledger view, never a decomposition of the monitor's
observed deltas. No HTTP, DNS, controller API, credentials, or workload control.
Only anonymous source/route/target identities leave the SQL adapter.
"""
from __future__ import annotations

from copy import deepcopy
import datetime as dt
import hmac
import ipaddress
import json
import math
import ntpath
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Any

from .probes.common import local_path

RESOLUTION_MS = 300_000
_BUCKET_US = RESOLUTION_MS * 1000
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_SERVICE_SUFFIXES = (
    ("openai", ("openai.com", "oaistatic.com", "oaiusercontent.com")),
    ("google_drive", ("drive.google.com", "drive.usercontent.google.com", "drive.googleusercontent.com", "googledrive.com")),
    ("google", ("google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "googlevideo.com", "youtube.com", "ytimg.com")),
    ("microsoft_update", ("windowsupdate.com", "microsoftupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com")),
    ("microsoft", ("microsoft.com", "windows.com", "live.com", "office.com", "office365.com", "microsoftonline.com", "msedge.net", "azure.com", "azureedge.net", "onedrive.com", "1drv.com")),
    ("github", ("github.com", "githubusercontent.com", "githubassets.com", "github.io")),
    ("tencent", ("qq.com", "tencent.com", "qcloud.com", "myqcloud.com")),
)
_LIMITATIONS = [
    "Independent complete-bucket ledger totals; never add to or apportion monitored delta totals.",
    "Service labels identify public domain namespaces, not an application, payload type, PID or account.",
    "Retained bucket rows do not prove continuous capture or complete traffic coverage.",
    "Unknown remains Unknown; source and route aliases do not identify a workload.",
    "Aliases are stable only for this adapter instance and are not persisted as an identity map.",
    "Closed time buckets can still receive late writes; results reflect a single read snapshot.",
]


class _Unavailable(Exception):
    """Internal safe reason code only; never expose underlying exception text."""


def _utc(value: Any) -> dt.datetime:
    if isinstance(value, str):
        value = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, dt.datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("A timezone-aware datetime is required")
    return value.astimezone(dt.timezone.utc)


def _microseconds(value: dt.datetime) -> int:
    distance = value - _EPOCH
    return (distance.days * 86_400 + distance.seconds) * 1_000_000 + distance.microseconds


def _iso_ms(value: int) -> str:
    return (_EPOCH + dt.timedelta(milliseconds=value)).isoformat()


def _is_unknown(value: Any) -> int:
    # Match the basename only, not a substring in a parent path or executable.
    name = ntpath.basename(str(value or "")).strip().casefold()
    return int(name in {"", "unknown"})


def _has_suffix(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def _ip_scope(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if address.is_unspecified:
        return "unspecified"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.version == 4 and address in ipaddress.ip_network("198.18.0.0/15"):
        return "benchmark_range"
    if address.is_reserved:
        return "reserved"
    return "private_or_non_global" if not address.is_global else "public"


class UnknownLedgerDetails:
    """Read an explicitly selected local database with bounded read-only queries.

    ``snapshot(start_utc, end_utc)`` returns complete 5-minute buckets fully inside
    the requested half-open interval. Availability failures are returned as
    ``status='unavailable'`` with null totals, never as zero traffic. Construction
    does not open a database; file availability is checked on each uncached read.
    """

    def __init__(self, path: str | Path, *, cache_seconds: float = 10.0,
                 max_keys: int = 50_000):
        self._path_input = path
        self._key = os.urandom(32)
        self.cache_seconds = min(10.0, max(0.0, float(cache_seconds)))
        if not math.isfinite(self.cache_seconds):
            self.cache_seconds = 0.0
        self.max_keys = max(1, min(50_000, int(max_keys)))
        self._cache_key: tuple[int, int] | None = None
        self._cached_at = 0.0
        self._cached: dict | None = None
        self._lock = threading.Lock()

    def _alias(self, kind: str, value: Any) -> str:
        text = str(value or "")
        if not text:
            return kind + "_unreported"
        message = (kind + "\x00" + text).encode("utf-8", "replace")
        return kind + "_" + hmac.new(self._key, message, "sha256").hexdigest()[:20]

    def _target(self, value: Any) -> tuple[str, str, str, str]:
        raw = str(value or "")
        if not raw:
            return "empty_target", "empty", "not_applicable", "target_unreported"
        host = raw.casefold()
        ip_candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            address = ipaddress.ip_address(ip_candidate)
        except ValueError:
            pass
        else:
            return "ip_target", f"ipv{address.version}", _ip_scope(address), self._alias("target", str(address))
        # Do not parse URLs, userinfo, paths, query strings, ports or arbitrary
        # Unicode into public domains. Only syntactically plain hosts qualify.
        host = host[:-1] if host.endswith(".") else host
        if not _DOMAIN.fullmatch(host):
            return "invalid_or_nonhost", "nonhost", "not_applicable", self._alias("target", raw)
        if host == "chatgpt.com":
            return "chatgpt_exact", "domain", "not_applicable", "service_chatgpt_exact"
        if host.endswith(".chatgpt.com"):
            return "chatgpt_subdomain", "domain", "not_applicable", "service_chatgpt_subdomain"
        for category, suffixes in _SERVICE_SUFFIXES:
            if any(_has_suffix(host, suffix) for suffix in suffixes):
                # Aggregate known namespace targets by public service category;
                # arbitrary subdomain labels (including tenant names) never exit.
                return category, "domain", "not_applicable", "service_" + category
        return "other_domain", "domain", "not_applicable", self._alias("target", host)

    def _source(self, value: Any) -> tuple[str, str, str]:
        raw = str(value or "")
        if not raw:
            return "source_unreported", "empty", "not_applicable"
        candidate = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return self._alias("source", raw), "non_ip", "not_applicable"
        return self._alias("source", str(address)), f"ipv{address.version}", _ip_scope(address)

    def _group_key(self, host: Any, source: Any, outbound: Any) -> str:
        route = str(outbound or "")
        route_alias = "DIRECT" if route.casefold() == "direct" else self._alias("route", route)
        source_alias, source_kind, source_scope = self._source(source)
        values = (*self._target(host), source_alias, route_alias, source_kind, source_scope)
        return json.dumps(values, separators=(",", ":"))

    @staticmethod
    def _empty_result() -> dict:
        return {
            "status": "unavailable", "reason": "not_read",
            "semantics": "INDEPENDENT_FULL_BUCKET_TOTALS_NOT_OBSERVED_DELTAS",
            "requested_start_utc": None, "requested_end_utc": None,
            "start_utc": None, "end_utc": None, "resolution_ms": RESOLUTION_MS,
            "actual_coverage": {
                "start_utc": None, "end_utc": None, "bucket_count": None,
                "expected_bucket_count": None, "unknown_bucket_count": None,
                "complete_range": None,
                "coverage_basis": "retained_ledger_bucket_rows_not_continuous_capture",
            },
            "total_up": None, "total_down": None, "rows": [],
            "cached": False, "cache_age_seconds": 0.0,
            "read_started_utc": None, "read_ended_utc": None,
            "limitations": list(_LIMITATIONS),
        }

    def snapshot(self, start_utc: Any, end_utc: Any) -> dict:
        result = self._empty_result()
        try:
            start, end = _utc(start_utc), _utc(end_utc)
            if end <= start:
                raise ValueError("Invalid range")
            start_us, end_us = _microseconds(start), _microseconds(end)
            lower = ((start_us + _BUCKET_US - 1) // _BUCKET_US) * RESOLUTION_MS
            upper = (end_us // _BUCKET_US) * RESOLUTION_MS
            result.update(requested_start_utc=start.isoformat(), requested_end_utc=end.isoformat(),
                          start_utc=_iso_ms(lower), end_utc=_iso_ms(upper))
            result["actual_coverage"]["expected_bucket_count"] = max(0, (upper - lower) // RESOLUTION_MS)
        except (ValueError, TypeError, OverflowError, OSError):
            result["reason"] = "invalid_range"
            return result
        if upper <= lower:
            result.update(status="insufficient_range", reason="no_complete_five_minute_bucket")
            return result
        key = (lower, upper)
        with self._lock:
            age = time.monotonic() - self._cached_at
            if self._cache_key == key and self._cached is not None and 0 <= age < self.cache_seconds:
                cached = deepcopy(self._cached)
                cached.update(cached=True, cache_age_seconds=age,
                              requested_start_utc=start.isoformat(), requested_end_utc=end.isoformat())
                return cached
            result["read_started_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
            try:
                self._read(result, lower, upper)
            except _Unavailable as exc:
                result.update(status="unavailable", reason=str(exc), total_up=None, total_down=None, rows=[])
            except (OSError, ValueError, TypeError, sqlite3.Error, OverflowError) as exc:
                reason = "query_deadline_exceeded" if isinstance(exc, sqlite3.Error) and getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_INTERRUPT else "database_read_unavailable"
                result.update(status="unavailable", reason=reason, total_up=None, total_down=None, rows=[])
            result["read_ended_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
            self._cache_key, self._cached_at, self._cached = key, time.monotonic(), deepcopy(result)
            return result

    def _read(self, result: dict, lower: int, upper: int):
        try:
            path = local_path(self._path_input, must_exist=True)
        except (OSError, ValueError, TypeError):
            raise _Unavailable("local_database_unavailable") from None
        if not path.is_file():
            raise _Unavailable("local_database_unavailable")
        wal, shm = Path(str(path) + "-wal"), Path(str(path) + "-shm")
        with path.open("rb") as handle:
            header = handle.read(20)
        wal_format = (header.startswith(b"SQLite format 3\x00") and len(header) == 20
                      and (header[18] == 2 or header[19] == 2))
        if (wal_format or (wal.is_file() and wal.stat().st_size)) and not shm.is_file():
            raise _Unavailable("wal_sidecar_unavailable")
        connection = None
        deadline = time.perf_counter() + 1.0
        try:
            connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.25)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.set_progress_handler(lambda: int(time.perf_counter() >= deadline), 1000)
            connection.create_function("observer_unknown", 1, _is_unknown, deterministic=True)
            connection.create_function("observer_safe_group", 3, self._group_key, deterministic=True)
            connection.execute("BEGIN")
            coverage = connection.execute(
                "SELECT bucket,MAX(observer_unknown(process)) FROM traffic_usage "
                "WHERE resolution=? AND bucket>=? AND bucket<? GROUP BY bucket ORDER BY bucket",
                (RESOLUTION_MS, lower, upper),
            ).fetchmany(self.max_keys + 1)
            if len(coverage) > self.max_keys:
                raise _Unavailable("query_key_limit")
            if time.perf_counter() >= deadline:
                raise _Unavailable("query_deadline_exceeded")
            if any(not isinstance(bucket, int) or bucket % RESOLUTION_MS for bucket, _ in coverage):
                raise _Unavailable("invalid_bucket_alignment")
            observed = result["actual_coverage"]
            observed.update(bucket_count=len(coverage), unknown_bucket_count=sum(bool(flag) for _, flag in coverage),
                            complete_range=len(coverage) == observed["expected_bucket_count"])
            if not coverage:
                raise _Unavailable("no_retained_buckets")
            observed.update(start_utc=_iso_ms(coverage[0][0]), end_utc=_iso_ms(coverage[-1][0] + RESOLUTION_MS))
            grouped = connection.execute(
                "SELECT observer_safe_group(host,source_ip,outbound) AS safe_group,"
                "SUM(upload),SUM(download),COUNT(DISTINCT bucket),"
                "SUM(CASE WHEN typeof(upload)!='integer' OR typeof(download)!='integer' "
                "OR upload<0 OR download<0 THEN 1 ELSE 0 END) "
                "FROM traffic_usage WHERE resolution=? AND bucket>=? AND bucket<? "
                "AND observer_unknown(process)=1 GROUP BY safe_group",
                (RESOLUTION_MS, lower, upper),
            ).fetchmany(self.max_keys + 1)
            if len(grouped) > self.max_keys:
                raise _Unavailable("query_key_limit")
            rows = []
            for safe_group, upload, download, bucket_count, invalid_values in grouped:
                if time.perf_counter() >= deadline:
                    raise _Unavailable("query_deadline_exceeded")
                if invalid_values or not isinstance(upload, int) or not isinstance(download, int):
                    raise _Unavailable("invalid_byte_counters")
                category, kind, scope, target, source, route, source_kind, source_scope = json.loads(safe_group)
                rows.append({
                    "service_category": category, "target_kind": kind, "target_scope": scope,
                    "target_alias": target, "source_alias": source, "route_alias": route,
                    "upload_bytes": upload, "download_bytes": download, "bucket_count": bucket_count,
                    "source_kind": source_kind, "source_scope": source_scope,
                })
            rows.sort(key=lambda row: (-row["download_bytes"], -row["upload_bytes"], row["service_category"], row["source_alias"], row["route_alias"], row["target_alias"]))
            result.update(status="ok", reason="retained_unknown_bucket_rows" if rows else "no_unknown_rows_in_retained_buckets",
                          rows=rows, total_up=sum(row["upload_bytes"] for row in rows),
                          total_down=sum(row["download_bytes"] for row in rows))
        finally:
            if connection is not None:
                try:
                    connection.set_progress_handler(None, 0)
                    connection.rollback()
                finally:
                    connection.close()
