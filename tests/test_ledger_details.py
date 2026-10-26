"""Synthetic complete-bucket tests; no real audit data or network requests."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from traffic_observer.ledger_details import UnknownLedgerDetails, RESOLUTION_MS

BASE = 1577836800000  # Fictional fixture: 2020-01-01 UTC.
SCHEMA = """
CREATE TABLE traffic_usage (
 resolution INTEGER,bucket INTEGER,source_ip TEXT,host TEXT,outbound TEXT,
 process TEXT,upload INTEGER,download INTEGER,samples INTEGER,
 PRIMARY KEY(resolution,bucket,source_ip,host,outbound,process)
) WITHOUT ROWID, STRICT
"""


class LedgerDetailsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.path = self.directory / "synthetic-ledger.db"
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(SCHEMA)

    def tearDown(self):
        self.temp.cleanup()

    def add(self, *, minute=0, process="Unknown", host="chatgpt.com", source="192.0.2.10",
            route="Example route", upload=10, download=100, resolution=300000):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("INSERT INTO traffic_usage VALUES (?,?,?,?,?,?,?,?,?)",
                               (resolution, BASE + minute * 60000, source, host, route, process, upload, download, 1))

    def snapshot(self, start="2020-01-01T00:00:00Z", end="2020-01-01T00:10:00Z", **kwargs):
        return UnknownLedgerDetails(self.path, **kwargs).snapshot(start, end)

    def test_read_only_single_resolution_and_unknown_basename(self):
        self.add(process="Unknown", download=100)
        self.add(process="uNkNoWn", host="api.openai.com", download=200)
        self.add(process="", host="drive.google.com", download=300)
        self.add(process=r"X:\runtime\UNKNOWN", host="github.com", download=400)
        self.add(process="/opt/example/Unknown", host="qq.com", download=500)
        self.add(process="unknown.exe", host="other.example", download=10000)
        self.add(process="codex.exe", host="chatgpt.com", download=10000)
        self.add(resolution=3600000, download=90000)
        self.add(resolution=86400000, download=90000)
        before = {p.name: (p.stat().st_size, p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
                  for p in self.directory.iterdir()}
        result = self.snapshot()
        after = {p.name: (p.stat().st_size, p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
                 for p in self.directory.iterdir()}
        self.assertEqual(before, after)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["total_down"], 1500)
        self.assertEqual(result["total_up"], 50)
        self.assertEqual(result["resolution_ms"], RESOLUTION_MS)
        self.assertEqual(result["actual_coverage"]["bucket_count"], 1)
        self.assertFalse(result["actual_coverage"]["complete_range"])
        self.assertEqual(result["semantics"], "INDEPENDENT_FULL_BUCKET_TOTALS_NOT_OBSERVED_DELTAS")

    def test_inward_alignment_half_open_range_and_microseconds(self):
        for minute in (0, 5, 10, 15):
            self.add(minute=minute)
        result = self.snapshot("2020-01-01T00:00:00.000001Z", "2020-01-01T00:15:00Z")
        self.assertEqual(result["start_utc"], "2020-01-01T00:05:00+00:00")
        self.assertEqual(result["end_utc"], "2020-01-01T00:15:00+00:00")
        self.assertEqual(result["total_down"], 200)
        self.assertEqual(result["actual_coverage"]["bucket_count"], 2)
        self.assertTrue(result["actual_coverage"]["complete_range"])
        before_boundary = self.snapshot("2020-01-01T08:00:00+08:00", "2020-01-01T08:09:59.999999+08:00")
        self.assertEqual(before_boundary["total_down"], 100)
        self.assertEqual(before_boundary["end_utc"], "2020-01-01T00:05:00+00:00")

    def test_no_complete_bucket_does_not_read_database_or_report_zero(self):
        detail = UnknownLedgerDetails(self.path)
        with patch.object(detail, "_read") as read:
            result = detail.snapshot("2020-01-01T00:01:00Z", "2020-01-01T00:09:59Z")
        read.assert_not_called()
        self.assertEqual(result["status"], "insufficient_range")
        self.assertIsNone(result["total_down"])
        self.assertEqual(result["rows"], [])

    def test_missing_retention_is_distinct_from_recorded_no_unknown(self):
        missing = self.snapshot()
        self.assertEqual(missing["status"], "unavailable")
        self.assertEqual(missing["reason"], "no_retained_buckets")
        self.assertIsNone(missing["total_down"])
        self.add(process="codex.exe")
        recorded = self.snapshot()
        self.assertEqual(recorded["status"], "ok")
        self.assertEqual(recorded["reason"], "no_unknown_rows_in_retained_buckets")
        self.assertEqual(recorded["total_down"], 0)
        self.assertEqual(recorded["actual_coverage"]["unknown_bucket_count"], 0)

    def test_public_service_suffixes_use_exact_label_boundaries(self):
        detail = UnknownLedgerDetails(self.path)
        good = {
            "CHATGPT.COM.": "chatgpt_exact", "tenant.chatgpt.com": "chatgpt_subdomain",
            "api.openai.com": "openai", "drive.google.com": "google_drive",
            "files.drive.googleusercontent.com": "google_drive", "storage.googleapis.com": "google",
            "download.windowsupdate.com": "microsoft_update", "login.microsoftonline.com": "microsoft",
            "raw.githubusercontent.com": "github", "object.myqcloud.com": "tencent",
        }
        for host, category in good.items():
            with self.subTest(host=host):
                self.assertEqual(detail._target(host)[0], category)
        for host in ("evilchatgpt.com", "chatgpt.com.example", "notopenai.com", "github.com.evil.example", "notqq.com"):
            with self.subTest(host=host):
                self.assertEqual(detail._target(host)[0], "other_domain")
        for host in ("https://chatgpt.com/private?token=example", "user@chatgpt.com", "chatgpt.com:443", "chatgpt.com.."):
            with self.subTest(host=host):
                self.assertEqual(detail._target(host)[0], "invalid_or_nonhost")

    def test_private_host_source_route_and_ip_never_leave_adapter(self):
        private_values = ["secret-tenant.chatgpt.com", "private-school.example", "https://private.example/path?token=EXAMPLE_ONLY",
                          "198.51.100.22", "2001:db8::55", "Private location subscription name", "192.0.2.222"]
        for host in private_values[:5]:
            self.add(host=host, source=private_values[-1], route=private_values[-2])
        result = self.snapshot()
        encoded = json.dumps(result)
        for raw in private_values:
            self.assertNotIn(raw, encoded)
        rows = result["rows"]
        ip_rows = [row for row in rows if row["service_category"] == "ip_target"]
        self.assertEqual({row["target_kind"] for row in ip_rows}, {"ipv4", "ipv6"})
        self.assertTrue(all(row["source_alias"].startswith("source_") for row in rows))
        self.assertTrue(all(row["route_alias"].startswith("route_") for row in rows))

    def test_known_service_aggregates_without_exposing_subdomain(self):
        self.add(host="private-one.chatgpt.com")
        self.add(host="private-two.chatgpt.com")
        result = self.snapshot()
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["download_bytes"], 200)
        self.assertEqual(result["rows"][0]["service_category"], "chatgpt_subdomain")

    def test_aliases_stable_for_instance_and_change_for_new_instance(self):
        self.add(host="private.example")
        detail = UnknownLedgerDetails(self.path, cache_seconds=0)
        first = detail.snapshot("2020-01-01T00:00:00Z", "2020-01-01T00:10:00Z")
        second = detail.snapshot("2020-01-01T00:00:00Z", "2020-01-01T00:15:00Z")
        third = self.snapshot()
        for key in ("source_alias", "route_alias", "target_alias"):
            self.assertEqual(first["rows"][0][key], second["rows"][0][key])
            self.assertNotEqual(first["rows"][0][key], third["rows"][0][key])

    def test_cache_is_bounded_copied_and_invalidated_by_effective_bucket_range(self):
        self.add()
        detail = UnknownLedgerDetails(self.path, cache_seconds=100)
        self.assertEqual(detail.cache_seconds, 10)
        with patch("traffic_observer.ledger_details.time.monotonic", return_value=100):
            first = detail.snapshot("2020-01-01T00:00:00Z", "2020-01-01T00:10:00Z")
        first["rows"][0]["download_bytes"] = 999
        with patch("traffic_observer.ledger_details.time.monotonic", return_value=109), patch.object(detail, "_read", wraps=detail._read) as read:
            cached = detail.snapshot("2020-01-01T00:00:00Z", "2020-01-01T00:10:00Z")
            read.assert_not_called()
        self.assertTrue(cached["cached"])
        self.assertEqual(cached["rows"][0]["download_bytes"], 100)
        with patch("traffic_observer.ledger_details.time.monotonic", return_value=110), patch.object(detail, "_read", wraps=detail._read) as read:
            expired = detail.snapshot("2020-01-01T00:00:00Z", "2020-01-01T00:10:00Z")
            self.assertEqual(read.call_count, 1)
        self.assertFalse(expired["cached"])
        with patch("traffic_observer.ledger_details.time.monotonic", return_value=111), patch.object(detail, "_read", wraps=detail._read) as read:
            # Same complete buckets are cached; requested labels still update.
            adjusted = detail.snapshot("2019-12-31T23:59:59Z", "2020-01-01T00:10:01Z")
            read.assert_not_called()
        self.assertTrue(adjusted["cached"])
        self.assertEqual(adjusted["requested_start_utc"], "2019-12-31T23:59:59+00:00")
        self.assertEqual(adjusted["requested_end_utc"], "2020-01-01T00:10:01+00:00")
        with patch("traffic_observer.ledger_details.time.monotonic", return_value=112), patch.object(detail, "_read", wraps=detail._read) as read:
            detail.snapshot("2020-01-01T00:00:00Z", "2020-01-01T00:15:00Z")
            self.assertEqual(read.call_count, 1)

    def test_source_ip_alias_normalizes_equivalent_spellings(self):
        self.add(source="2001:0DB8:0000:0000:0000:0000:0000:0055")
        self.add(source="2001:db8::55")
        result = self.snapshot()
        self.assertEqual(len(result["rows"]), 1)
        row = result["rows"][0]
        self.assertEqual(row["source_kind"], "ipv6")
        self.assertEqual(row["download_bytes"], 200)
        self.assertNotIn("2001:", json.dumps(result))
        detail = UnknownLedgerDetails(self.path)
        self.assertEqual(detail._source("")[1:], ("empty", "not_applicable"))
        self.assertEqual(detail._source("synthetic-label")[1:], ("non_ip", "not_applicable"))
        self.assertEqual(detail._source("127.0.0.1")[1:], ("ipv4", "loopback"))

    def test_missing_sidecars_fail_before_sqlite_connect(self):
        self.path.write_bytes(b"SQLite format 3\x00" + bytes([16, 0, 2, 2]))
        with patch("traffic_observer.ledger_details.sqlite3.connect") as connect:
            result = self.snapshot()
        connect.assert_not_called()
        self.assertEqual(result["reason"], "wal_sidecar_unavailable")
        self.assertIsNone(result["total_down"])
        self.assertFalse(Path(str(self.path) + "-shm").exists())

    def test_nonempty_wal_without_shm_also_fails_closed(self):
        Path(str(self.path) + "-wal").write_bytes(b"synthetic")
        with patch("traffic_observer.ledger_details.sqlite3.connect") as connect:
            result = self.snapshot()
        connect.assert_not_called()
        self.assertEqual(result["reason"], "wal_sidecar_unavailable")

    def test_missing_database_schema_and_invalid_range_are_not_zero(self):
        missing = UnknownLedgerDetails(self.directory / "does-not-exist.db").snapshot("2020-01-01T00:00:00Z", "2020-01-01T00:10:00Z")
        self.assertEqual(missing["status"], "unavailable")
        self.assertIsNone(missing["total_down"])
        self.assertFalse((self.directory / "does-not-exist.db").exists())
        for start, end in (("2020-01-01T00:00:00", "2020-01-01T00:10:00Z"), ("2020-01-02T00:00:00Z", "2020-01-01T00:00:00Z")):
            result = self.snapshot(start, end)
            self.assertEqual(result["reason"], "invalid_range")
            self.assertIsNone(result["total_down"])
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TABLE traffic_usage")
        result = self.snapshot()
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["total_down"])

    def test_group_limit_and_invalid_byte_counters_are_unavailable(self):
        self.add(host="one.example")
        self.add(host="two.example")
        limited = self.snapshot(max_keys=1)
        self.assertEqual(limited["reason"], "query_key_limit")
        self.assertIsNone(limited["total_down"])
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE traffic_usage SET download=-1 WHERE host='one.example'")
        invalid = self.snapshot()
        self.assertEqual(invalid["reason"], "invalid_byte_counters")
        self.assertIsNone(invalid["total_down"])

    def test_deadline_exceeded_closes_read_connection(self):
        self.add()
        with patch("traffic_observer.ledger_details.time.perf_counter", side_effect=[0, 2]):
            result = self.snapshot()
        self.assertEqual(result["reason"], "query_deadline_exceeded")
        self.assertIsNone(result["total_down"])
        # An exclusive transaction succeeds after the failed read; no reader held.
        with closing(sqlite3.connect(self.path, timeout=0)) as connection:
            connection.execute("BEGIN EXCLUSIVE")
            connection.rollback()

    def test_direct_label_is_safe_but_node_names_are_not_exposed(self):
        self.add(route="dIrEcT")
        result = self.snapshot()
        self.assertEqual(result["rows"][0]["route_alias"], "DIRECT")

    def test_misaligned_bucket_is_rejected(self):
        self.add(minute=1)
        result = self.snapshot()
        self.assertEqual(result["reason"], "invalid_bucket_alignment")
        self.assertIsNone(result["total_down"])


if __name__ == "__main__":
    unittest.main()
