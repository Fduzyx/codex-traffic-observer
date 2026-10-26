"""Read-only, bounded views over the observer's metadata CSV files.

This module does not collect traffic, open network connections, or modify its
input directory. Rates from a logical ledger describe recorded increments,
not packet timing. Missing or invalid measurements remain ``None``.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import math
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from .probes.common import local_path
from .unknown import build_unknown_breakdown

UTC = dt.timezone.utc
FILES = (
    "physical_network.csv", "sample_summary.csv", "process_snapshots.csv",
    "codex_activity.csv", "anomaly_windows.csv", "live_connections.csv", "monitor_health.csv",
    "logical_traffic.csv",
)
_ROW_START = re.compile(rb"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127},[0-9]+,")


def _timestamp(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        # A timestamp without its timezone is not safe to join across sources.
        if parsed.tzinfo is None:
            return None
        result = parsed.timestamp()
        return result if math.isfinite(result) else None
    except (ValueError, OverflowError, OSError):
        return None


def _iso(value: float | None) -> str | None:
    return dt.datetime.fromtimestamp(value, UTC).isoformat() if value is not None else None


def _number(value: Any, *, nonnegative: bool = True) -> float | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (ValueError, TypeError, OverflowError):
        return None
    return result if math.isfinite(result) and (not nonnegative or result >= 0) else None


def _integer(value: Any) -> int | None:
    n = _number(value)
    return int(n) if n is not None and n.is_integer() else None


def _true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def _object(value: Any, maximum: int = 65536) -> dict:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or len(value) > maximum:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, RecursionError):
        return {}


def _clean_row(row: dict) -> dict:
    """Keep only bounded CSV cells; this is a local view, never a publish export."""
    return {str(k): str(v)[:4096] for k, v in row.items()
            if k is not None and not str(k).startswith("_") and v is not None}


class _CsvTail:
    """Incremental CSV reader with bounded record/cache sizes and rotation checks.

    Complete quoted multiline records work across polls. The audit format's
    first two fields (run_id, sample_id) allow recovery when starting at a tail
    boundary in a large file. That truncated coverage is always reported.
    """
    def __init__(self, path: Path, *, max_rows: int = 12000,
                 startup_bytes: int = 8 * 1024 * 1024,
                 poll_bytes: int = 2 * 1024 * 1024):
        self.path = path
        self.max_rows = max(2, max_rows)
        self.startup_bytes = max(256, startup_bytes)
        self.poll_bytes = max(256, poll_bytes)
        self.rows: deque[dict] = deque(maxlen=self.max_rows)
        self.identity = None
        self.offset = 0
        self.mtime_ns = None
        self.header: list[str] | None = None
        self.buffer = b""
        self.record = bytearray()
        self.quote_open = False
        self.recover_boundary = False
        self.truncated = False
        self.dropped = 0
        self.invalid = 0
        self.rotations = 0
        self.backlog = False
        self.status = "missing"

    def _reset(self):
        self.offset = 0; self.header = None; self.buffer = b""
        self.record.clear(); self.quote_open = False; self.rows.clear()
        self.recover_boundary = False; self.truncated = False
        self.dropped = 0; self.invalid = 0

    def _consume(self, data: bytes):
        pieces = (self.buffer + data).split(b"\n")
        self.buffer = pieces.pop()
        for piece in pieces:
            line = piece + b"\n"
            if self.recover_boundary:
                if not _ROW_START.match(line):
                    continue
                self.recover_boundary = False
            self.record.extend(line)
            self.quote_open ^= bool(line.count(b'"') % 2)
            if len(self.record) > 512 * 1024:
                self.record.clear(); self.quote_open = False
                self.recover_boundary = True; self.invalid += 1
                continue
            if self.quote_open:
                continue
            try:
                parsed = list(csv.reader(io.StringIO(self.record.decode("utf-8-sig"), newline=""), strict=True))
                if len(parsed) != 1 or len(parsed[0]) != len(self.header or []):
                    raise ValueError("invalid_columns")
                row = dict(zip(self.header or [], parsed[0]))
                if not row.get("run_id") or _integer(row.get("sample_id")) is None:
                    raise ValueError("invalid_identity")
                if len(self.rows) == self.max_rows:
                    self.dropped += 1
                self.rows.append(row)
            except (ValueError, UnicodeError, csv.Error):
                self.invalid += 1
            self.record.clear()
        if len(self.buffer) > 512 * 1024:
            self.buffer = b""; self.record.clear(); self.quote_open = False
            self.recover_boundary = True; self.invalid += 1

    def update(self):
        try:
            entry=self.path.lstat()
            if self.path.is_symlink() or getattr(entry,"st_file_attributes",0) & 0x400:
                self.status="reparse_point_skipped";return
            stat = self.path.stat()
            identity = (stat.st_dev, stat.st_ino)
            changed = self.identity is not None and (identity != self.identity or stat.st_size < self.offset
                       or (stat.st_size == self.offset and self.mtime_ns != stat.st_mtime_ns))
            if changed:
                self.rotations += 1; self._reset()
            self.identity = identity
            with self.path.open("rb") as handle:
                initial = self.header is None
                if initial:
                    raw_header = handle.readline(65537)
                    if not raw_header.endswith(b"\n") or len(raw_header) > 65536:
                        self.status = "incomplete_header"; return
                    parsed = next(csv.reader([raw_header.decode("utf-8-sig").rstrip("\r\n")], strict=True))
                    if len(set(parsed)) != len(parsed) or parsed[:2] != ["run_id", "sample_id"]:
                        self.status = "unsupported_schema"; return
                    self.header = parsed
                    self.offset = handle.tell()
                    if stat.st_size - self.offset > self.startup_bytes:
                        handle.seek(stat.st_size - self.startup_bytes)
                        handle.readline(512 * 1024)  # Drop the first possibly partial line.
                        self.offset = handle.tell(); self.truncated = True
                        self.recover_boundary = True
                handle.seek(self.offset)
                chunk = handle.read(self.startup_bytes if initial else self.poll_bytes)
                self.offset += len(chunk)
            self._consume(chunk)
            self.backlog = self.offset < stat.st_size
            self.mtime_ns = stat.st_mtime_ns
            self.status = "readable"
        except FileNotFoundError:
            self.status = "missing"
            self.rows.clear(); self._reset(); self.identity = None
        except PermissionError:
            self.status = "permission_denied"
        except (OSError, ValueError, UnicodeError, csv.Error):
            self.status = "read_error"


class AuditStore:
    """One worker owns this object; snapshot() is safe for a GUI worker thread.

    A reader can run on any OS. It only reads the chosen directory. At most
    12,000 rows per source are retained, and partial coverage is explicit.
    ``minutes=None`` or ``minutes=0`` means all retained data for that run.
    """
    def __init__(self, directory: str | Path, mihomo_db: str | Path | None = None):
        self.directory = local_path(directory)
        self._readers = {name: _CsvTail(self.directory / name) for name in FILES}
        self._last_clock = None
        self._mihomo_db = mihomo_db
        self._ledger_details = None

    def _read_json(self, name: str, maximum: int = 2 * 1024 * 1024) -> dict:
        try:
            path=self.directory/name
            entry=path.lstat()
            if path.is_symlink() or getattr(entry,"st_file_attributes",0) & 0x400:
                return {}
            with path.open("rb") as f:
                data = f.read(maximum + 1)
            if len(data) > maximum:
                return {}
            value = json.loads(data.decode("utf-8-sig"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, UnicodeError, RecursionError):
            return {}

    def snapshot(self, run_id: str | None = None, minutes: int | float | None = 60) -> dict:
        if minutes is not None and (not isinstance(minutes, (int, float)) or not math.isfinite(minutes) or minutes < 0):
            raise ValueError("minutes must be nonnegative or None")
        for reader in self._readers.values():
            reader.update()
        state = self._read_json("monitor_state.json")
        demo = self._read_json("demo_manifest.json", 4096).get("synthetic") is True
        limitations = ["逻辑曲线表示账本落库增量，不能当作逐包速率；物理网卡包含所有应用。"]
        coverage = {}
        for name, reader in self._readers.items():
            coverage[name] = {"status":reader.status,"retained_rows":len(reader.rows),
                "tail_truncated":reader.truncated,"cache_dropped_rows":reader.dropped,
                "invalid_rows":reader.invalid,"backlog":reader.backlog,
                "pending_record":bool(reader.buffer or reader.record),"rotations":reader.rotations}
            if reader.status not in ("readable", "missing"):
                limitations.append(f"{name}：{reader.status}，未干预数据源。")
            if reader.truncated or reader.dropped:
                limitations.append(f"{name} 只保留最近数据；所选窗口可能不完整。")
            if reader.backlog:
                limitations.append(f"{name} 尚有待读取数据，下次刷新继续。")
            if reader.invalid:
                limitations.append(f"{name} 跳过 {reader.invalid} 条无效记录。")
        rows = {k:list(v.rows) for k,v in self._readers.items() if v.status == "readable"}
        for name in FILES:
            rows.setdefault(name, [])
        discovered: dict[str, dict] = {}
        for name in ("sample_summary.csv", "physical_network.csv"):
            for r in rows[name]:
                ident = r["run_id"]
                end = _timestamp(r.get("ended_utc") or r.get("observed_utc"))
                start = _timestamp(r.get("started_utc") or r.get("interval_start_utc")) or end
                if end is None:
                    continue
                entry = discovered.setdefault(ident, {"run_id":ident,"_start":start,"_end":end,"_samples":set()})
                entry["_start"] = min(entry["_start"],start)
                entry["_end"] = max(entry["_end"],end)
                entry["_samples"].add(_integer(r.get("sample_id")))
        state_id = state.get("run_id") if isinstance(state.get("run_id"), str) else None
        state_last = _timestamp(state.get("last_sample_utc"))
        state_start = _timestamp(state.get("started_utc"))
        if state_id and (state_last is not None or state_start is not None):
            last = state_last if state_last is not None else state_start
            entry = discovered.setdefault(state_id,{"run_id":state_id,"_start":state_start or last,"_end":last,"_samples":set()})
            entry["_end"] = max(entry["_end"],last)
            if state_start is not None:
                entry["_start"] = min(entry["_start"],state_start)
        ordered = sorted(discovered.values(),key=lambda r:r["_end"],reverse=True)
        runs = [{"run_id":r["run_id"],"start_utc":_iso(r["_start"]),"last_utc":_iso(r["_end"]),
                 "samples":len(r["_samples"])} for r in ordered]
        selected = run_id if run_id in discovered else (state_id if state_id in discovered else (runs[0]["run_id"] if runs else None))
        if run_id and selected != run_id:
            limitations.append("指定运行段不在当前保留数据中，已选择可用运行段。")
        end = discovered[selected]["_end"] if selected else None
        start = (end - float(minutes)*60) if end is not None and minutes else None
        def selected_rows(name):
            return [r for r in rows[name] if r.get("run_id")==selected]
        def inside_interval(a,b):
            return a is not None and b is not None and b>a and (start is None or a>=start) and (end is None or b<=end+0.001)
        def inside_point(value):
            return value is not None and (start is None or value>=start) and (end is None or value<=end+0.001)

        physical_points=defaultdict(list)
        totals_lists={k:[] for k in ("physical_rx","physical_tx","logical_down","codex_down","unknown_down")}
        partial_boundary = False
        physical_gaps=logical_gaps=0
        # Distinct adapters contribute bytes, never counts from cumulative counters.
        seen_physical=set()
        for r in selected_rows("physical_network.csv"):
            sample=_integer(r.get("sample_id")); key=(sample,r.get("adapter"),r.get("observed_utc"))
            if key in seen_physical:
                continue
            seen_physical.add(key)
            b=_timestamp(r.get("observed_utc")); a=_timestamp(r.get("interval_start_utc"))
            point={"timestamp":r.get("observed_utc"),"sample_id":sample,"physical_rx_rate":None,"physical_tx_rate":None}
            rx=_number(r.get("rx_delta"));tx=_number(r.get("tx_delta"))
            if inside_interval(a,b) and r.get("counter_status")=="valid_delta":
                if rx is not None:totals_lists["physical_rx"].append(rx);point["physical_rx_rate"]=rx/(b-a)
                if tx is not None:totals_lists["physical_tx"].append(tx);point["physical_tx_rate"]=tx/(b-a)
            elif start is not None and a is not None and b is not None and a<start<b:
                partial_boundary=True
            if inside_point(b) and (sample or 0)>1 and (r.get("counter_status")!="valid_delta" or rx is None or tx is None):
                physical_gaps+=1
            if inside_point(b):physical_points[sample].append(point)
        points={}
        for sample,items in physical_points.items():
            def rate(k):
                values=[i[k] for i in items if i[k] is not None]
                return sum(values) if len(values)==len(items) and values else None
            latest=max(items,key=lambda x:_timestamp(x["timestamp"]) or 0)
            points[sample]={"timestamp":latest["timestamp"],"sample_id":sample,
                "physical_rx_rate":rate("physical_rx_rate"),"physical_tx_rate":rate("physical_tx_rate"),
                "logical_down_rate":None,"codex_down_rate":None,"unknown_down_rate":None}
        seen_summary=set(); logical_valid_samples=0
        for r in selected_rows("sample_summary.csv"):
            sample=_integer(r.get("sample_id"))
            if sample in seen_summary:continue
            seen_summary.add(sample)
            obj=_object(r.get("logical_totals"))
            b=_timestamp(obj.get("delta_interval_end_utc"));a=_timestamp(obj.get("delta_interval_start_utc"))
            at=b or _timestamp(r.get("ended_utc"))
            if inside_point(at):
                point=points.setdefault(sample,{"timestamp":_iso(at),"sample_id":sample,"physical_rx_rate":None,
                    "physical_tx_rate":None,"logical_down_rate":None,"codex_down_rate":None,"unknown_down_rate":None})
                point["logical_timestamp"]=_iso(b)
                point["logical_interval_start_utc"]=_iso(a)
                point["logical_interval_end_utc"]=_iso(b)
            else:
                point=None
            valid=_true(obj.get("delta_valid")) and not _true(obj.get("counter_discontinuity"))
            if valid and inside_interval(a,b):
                logical_valid_samples+=1
                for field,key in (("logical_down","all_download_delta"),("codex_down","codex_download_delta"),("unknown_down","unknown_download_delta")):
                    val=_number(obj.get(key))
                    if val is not None:
                        totals_lists[field].append(val)
                        if point is not None:point[field+"_rate"]=val/(b-a)
            elif start is not None and a is not None and b is not None and a<start<b:
                partial_boundary=True
            if inside_point(at) and (sample or 0)>1 and (not valid or a is None or b is None):
                logical_gaps+=1
        if partial_boundary:
            limitations.append("窗口边界穿过采样区间，该区间未按比例拆分，合计只含完整区间。")
        if selected and not logical_valid_samples:
            limitations.append("没有带完整源区间的有效逻辑增量；不以累计量或固定10秒补算。")
        totals={key:int(sum(values)) if values else None for key,values in totals_lists.items()}
        totals_partial=partial_boundary or bool(physical_gaps or logical_gaps) or any(
            coverage[name]["status"]!="readable" or coverage[name]["tail_truncated"]
            or coverage[name]["cache_dropped_rows"] or coverage[name]["invalid_rows"] or coverage[name]["backlog"]
            for name in ("physical_network.csv","sample_summary.csv"))
        if totals_partial:
            limitations.append("合计仅为当前已保留、有效且完整的采样区间，不代表所选时间范围的无遗漏总量。")
        series=sorted(points.values(),key=lambda r:_timestamp(r["timestamp"]) or 0)

        proc=selected_rows("process_snapshots.csv")
        latest_sample=max((_integer(r.get("sample_id")) or 0 for r in proc),default=0)
        process_rows=[r for r in proc if (_integer(r.get("sample_id")) or 0)==latest_sample]
        state_sample=_integer(state.get("samples")) or 0
        if selected==state_id and state_sample>=latest_sample and isinstance(state.get("last_processes"),list):
            allowed={"platform","pid","parent_pid","start_utc","exe_category","workload","confidence","name","instance_key","parent_name","parent_exe_category","ancestry_categories","source_observed_utc","is_cached","cache_age_seconds","observed_utc","sample_id"}
            process_rows=[{k:v for k,v in r.items() if k in allowed} for r in state["last_processes"] if isinstance(r,dict)]
        processes=[]
        for r in process_rows:
            out=_clean_row(r)
            out["is_cached"]=_true(r.get("is_cached"))
            out["cache_age_seconds"]=_number(r.get("cache_age_seconds"))
            processes.append(out)
        events=[]
        for r in selected_rows("codex_activity.csv"):
            if inside_point(_timestamp(r.get("event_utc"))):
                out=_clean_row(r);out["context"]=_object(r.get("context_safe"),16384)
                events.append(out)
        events.sort(key=lambda r:_timestamp(r.get("event_utc")) or 0,reverse=True)
        markers=[]
        for r in selected_rows("anomaly_windows.csv"):
            if inside_point(_timestamp(r.get("query_ended_utc") or r.get("ended_utc"))):
                out=_clean_row(r);out["logical"]=_object(r.get("logical_totals"))
                markers.append(out)
        connections=selected_rows("live_connections.csv")
        conn_sample=max((_integer(r.get("sample_id")) or 0 for r in connections),default=0)
        connections=[_clean_row(r) for r in connections if (_integer(r.get("sample_id")) or 0)==conn_sample]
        connection_status=str(state.get("connection_source") or "UNAVAILABLE_NO_CONNECTION_DATA")[:160]
        if not connections:
            limitations.append("逐连接计数不可用，无法据此确定最大连接或把字节分配给单个PID。")
        if connections:
            connection_status="available_metadata_only"
            limitations.append("连接表为最后一次有记录的快照，不保证这些连接现在仍活动。")
        historical=bool(selected and selected!=state_id)
        status="historical" if historical else str(state.get("status") or ("unknown" if selected else "missing"))[:40]
        now=time.time();age=max(0,now-end) if end is not None else None
        interval=_number(state.get("interval_seconds")) or 10
        stale=(age is None or age>max(30,interval*3) or status in ("stopped","missing","unknown"))
        if end is not None and end>now+60:
            stale=True
            limitations.append("数据时间晚于当前系统时间，不能确认实时状态。")
        if self._last_clock is not None and now<self._last_clock-2:
            limitations.append("系统时间回退，数据新鲜度可能不可靠。")
        self._last_clock=now
        if demo:
            status="demo";stale=False;age=None
            limitations.insert(0,"模拟数据：完全虚构，不代表本机或任何真实用户的网络活动。")
        if historical:
            limitations.append("当前选择的是历史运行段；实例列表表示该段最后一次观察，不代表现在存活。")
        unknown = build_unknown_breakdown(selected_rows("sample_summary.csv"),
            selected_rows("logical_traffic.csv"), selected_rows("process_snapshots.csv"),
            start=start, end=end, source_coverage=coverage)
        ledger = {"status":"not_configured", "reason":"synthetic_demo_ignores_external_database" if demo
            else "no_database_selected", "rows":[], "total_up":None, "total_down":None,
            "limitations":["原账本完整桶视角与监测增量口径独立，不能相加。"]}
        if self._mihomo_db is not None and not demo and selected and end is not None:
            from .ledger_details import UnknownLedgerDetails
            if self._ledger_details is None:
                self._ledger_details = UnknownLedgerDetails(self._mihomo_db)
            # All-retained mode still needs a real lower bound for independent
            # bucket inspection. Do not infer it from cumulative state totals.
            ledger_start = start
            if ledger_start is None:
                starts = [_timestamp(_object(r.get("logical_totals")).get("delta_interval_start_utc"))
                    for r in selected_rows("sample_summary.csv")]
                ledger_start = min((value for value in starts if value is not None),
                                   default=discovered[selected]["_start"])
            ledger = self._ledger_details.snapshot(_iso(ledger_start), _iso(end))
        return {"runs":runs,"selected_run":selected,"source_status":{"monitor":status,"connections":connection_status,"data_directory":str(self.directory)},
            "freshness":{"age_seconds":age,"stale":stale,"demo":demo,"historical":historical},
            "totals":totals,"series":series,"processes":processes,"events":events[:2000],
            "markers":markers[-500:],"connections":connections,"limitations":list(dict.fromkeys(limitations)),
            "window":{"start_utc":_iso(start),"end_utc":_iso(end),"minutes":minutes,"complete":not totals_partial},"coverage":coverage,
            "totals_partial":totals_partial,
            "unknown_breakdown":unknown,"unknown_ledger_details":ledger,
            "measurement_coverage":{"physical_valid_intervals":len(totals_lists["physical_rx"]),
                "logical_valid_intervals":logical_valid_samples,"physical_gap_rows":physical_gaps,"logical_gap_rows":logical_gaps},
            "demo":demo,"updated_utc":dt.datetime.now(UTC).isoformat()}
