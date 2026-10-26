"""Synthetic collector tests. Never sample, change, or stop real workloads."""
import csv
from contextlib import closing
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from traffic_observer import collector
from traffic_observer.probes.common import local_path
from traffic_observer.probes.physical import PhysicalProbe
from traffic_observer.probes.processes import collect_processes
from traffic_observer.probes.traffic import TrafficProbe


class CollectorSafetyTests(unittest.TestCase):
    def test_network_paths_are_rejected_before_access(self):
        for path in (r"\\server\share\data", "//server/share/data", "https://example.invalid/data"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                local_path(path)

    @unittest.skipUnless(os.name == "nt", "Windows drive types")
    def test_mapped_network_drive_rejected_before_resolve_or_stat(self):
        with patch("traffic_observer.probes.common.ctypes.windll.kernel32.GetDriveTypeW", return_value=4), \
             patch.object(Path, "resolve") as resolve, patch.object(Path, "stat") as stat:
            with self.assertRaises(ValueError):
                local_path("Z:/synthetic/data", must_exist=True)
            resolve.assert_not_called()
            stat.assert_not_called()

    def test_existing_unowned_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            marker = directory / "existing.txt"
            marker.write_text("preserve", encoding="utf-8")
            with self.assertRaises(ValueError):
                collector._prepare_output(directory)
            self.assertEqual(marker.read_text(), "preserve")
            self.assertEqual([p.name for p in directory.iterdir()], ["existing.txt"])

    def test_output_cannot_be_inside_project(self):
        project = Path(collector.__file__).resolve().parent.parent
        with self.assertRaises(ValueError):
            collector._prepare_output(project / "test-no-write")
        self.assertFalse((project / "test-no-write").exists())

    def test_stop_requires_run_and_process_start_identity(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            collector._json_write(output / ".observer-output.json", {"format": collector.FORMAT})
            state = {"run_id": "synthetic-run", "monitor_pid": 123, "monitor_process_start_ticks": 456, "status": "running"}
            collector._json_write(output / "monitor_state.json", state)
            with patch.object(collector, "_process_start_ticks", return_value=789):
                result = collector.request_stop(output)
            self.assertFalse(result["stop_flag_written"])
            self.assertFalse((output / "stop.request.json").exists())
            with patch.object(collector, "_process_start_ticks", return_value=456):
                result = collector.request_stop(output)
            self.assertEqual(result["processes_terminated"], 0)
            self.assertTrue(collector._stopped_by_flag(output, state))
            changed = dict(state, run_id="different-run")
            self.assertFalse(collector._stopped_by_flag(output, changed))

    @unittest.skipUnless(os.name == "nt", "Windows file locking")
    def test_second_collector_cannot_take_existing_lock(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "monitor.lock"
            with collector._Lock(path):
                with self.assertRaises(RuntimeError):
                    with collector._Lock(path):
                        pass

    @unittest.skipUnless(os.name == "nt", "Windows-only collector")
    def test_short_run_uses_only_mocked_probes_and_keeps_missing_data_blank(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "data"
            with patch.object(collector.PhysicalProbe, "poll", return_value={"rows": [], "health": ["SYNTHETIC_UNAVAILABLE"]}), \
                 patch.object(collector, "collect_processes", return_value={"rows": [], "health": []}):
                self.assertEqual(collector.run_collector(output, interval=5, duration=0.01), 0)
            state = json.loads((output / "monitor_state.json").read_text())
            self.assertEqual(state["status"], "stopped")
            self.assertEqual(state["stop_reason"], "requested_duration_complete")
            with (output / "sample_summary.csv").open(encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(rows[0]["physical_rx_delta"], "")
            self.assertIsNone(json.loads(rows[0]["logical_totals"])["all_download_delta"])
            with (output / "live_connections.csv").open(encoding="utf-8-sig", newline="") as f:
                self.assertEqual(list(csv.DictReader(f)), [])


class ProbeSemanticsTests(unittest.TestCase):
    def test_physical_baseline_reset_and_recovery(self):
        def row(seconds, received, sent):
            return {"adapter_key": "synthetic-adapter", "if_index": 1, "status": "Up", "received_bytes": received,
                    "sent_bytes": sent, "observed_utc": f"2020-01-01T00:00:{seconds:02d}Z"}
        probe = PhysicalProbe()
        values = [[row(0, 100, 50)], [row(10, 180, 80)], [row(20, 10, 5)], [row(30, 30, 10)]]
        with patch("traffic_observer.probes.physical.local_powershell", side_effect=values):
            first, second, reset, fourth = [probe.poll(i, "2020-01-01T00:00:00Z")["rows"][0] for i in range(4)]
        self.assertIsNone(first["rx_delta"])
        self.assertEqual(second["rx_delta"], 80)
        self.assertIsNone(reset["rx_delta"])
        self.assertEqual(reset["counter_status"], "counter_decrease_new_baseline")
        self.assertEqual(fourth["rx_delta"], 20)

    def test_process_path_alone_does_not_prove_desktop_workload(self):
        records = [
            {"Name": "cmd.exe", "pid": 1, "parent_pid": 0, "ExecutablePath": r"C:\Windows\System32\cmd.exe", "start_utc": "2020-01-01T00:00:00Z"},
            {"Name": "codex.exe", "pid": 2, "parent_pid": 1, "ExecutablePath": r"X:\OpenAI\Codex\bin\example\codex.exe", "start_utc": "2020-01-01T00:01:00Z"},
        ]
        with patch("traffic_observer.probes.processes.local_powershell", return_value=records):
            row = collect_processes()["rows"][0]
        self.assertEqual(row["workload"], "Unknown")
        self.assertNotIn("ExecutablePath", row)
        self.assertNotIn("CommandLine", row)

    def test_parent_pid_reuse_does_not_assign_vscode(self):
        records = [
            {"Name": "Code.exe", "pid": 1, "parent_pid": 0, "ExecutablePath": r"X:\apps\Code.exe", "start_utc": "2020-01-01T01:00:00Z"},
            {"Name": "codex.exe", "pid": 2, "parent_pid": 1, "ExecutablePath": r"X:\tools\codex.exe", "start_utc": "2020-01-01T00:01:00Z"},
        ]
        with patch("traffic_observer.probes.processes.local_powershell", return_value=records):
            result = collect_processes()
        self.assertEqual(result["rows"][0]["workload"], "Unknown")
        self.assertIn("PARENT_PID_REUSE_OR_INCONSISTENT_SNAPSHOT", result["health"])

    def test_logical_probe_reads_one_resolution_and_does_not_modify_database(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "synthetic.db"
            bucket = 1577836800000
            with closing(sqlite3.connect(source)) as connection, connection:
                connection.execute("CREATE TABLE traffic_usage (resolution INTEGER,bucket INTEGER,process TEXT,host TEXT,outbound TEXT,upload INTEGER,download INTEGER,samples INTEGER)")
                connection.executemany("INSERT INTO traffic_usage VALUES (?,?,?,?,?,?,?,?)", [
                    (300000, bucket, "codex.exe", "chatgpt.com", "Example node", 10, 100, 1),
                    (3600000, bucket, "codex.exe", "chatgpt.com", "Example node", 10, 100, 1),
                ])
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            probe = TrafficProbe(source)
            first = probe.poll(1, "2020-01-01T00:00:05Z")
            self.assertIsNone(first["totals"]["all_download_delta"])
            self.assertEqual(first["totals"]["snapshot_download_bytes"], 100)
            self.assertNotIn("Example node", json.dumps(first))
            self.assertEqual(before, hashlib.sha256(source.read_bytes()).hexdigest())
            with closing(sqlite3.connect(source)) as connection, connection:
                connection.execute("UPDATE traffic_usage SET download=download+25 WHERE resolution=300000")
            second = probe.poll(2, "2020-01-01T00:00:15Z")
            self.assertEqual(second["totals"]["all_download_delta"], 25)
            self.assertEqual(second["totals"]["delta_interval_start_utc"], first["totals"]["read_ended_utc"])
            self.assertEqual(second["connections"], [])
            with closing(sqlite3.connect(source)) as connection, connection:
                connection.execute("UPDATE traffic_usage SET download=1 WHERE resolution=300000")
            reset = probe.poll(3, "2020-01-01T00:00:25Z")
            self.assertIsNone(reset["totals"]["all_download_delta"])
            self.assertEqual(reset["bucket_rows"][0]["download_delta_bytes"], -124)
            self.assertTrue(reset["totals"]["counter_discontinuity"])

    def test_missing_wal_index_is_not_created(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "synthetic.db"
            source.write_bytes(b"synthetic")
            Path(str(source) + "-wal").write_bytes(b"nonempty")
            probe = TrafficProbe(source)
            with patch("traffic_observer.probes.traffic.sqlite3.connect") as connect:
                result = probe.poll(1, "2020-01-01T00:00:00Z")
            connect.assert_not_called()
            self.assertEqual(result["totals"]["read_status"], "WAL_SIDECAR_UNAVAILABLE")

    def test_wal_database_without_any_sidecars_is_not_opened(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "synthetic.db"
            source.write_bytes(b"SQLite format 3\x00" + bytes([16, 0, 2, 2]))
            probe = TrafficProbe(source)
            with patch("traffic_observer.probes.traffic.sqlite3.connect") as connect:
                result = probe.poll(1, "2020-01-01T00:00:00Z")
            connect.assert_not_called()
            self.assertEqual(result["totals"]["read_status"], "WAL_SIDECAR_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
