"""UI presentation semantics and local window smoke tests (no network or collectors)."""
import math
from pathlib import Path
import unittest
from unittest.mock import patch

try:
    import tkinter as tk
    from traffic_observer.ui import ObserverApp, format_bytes, local_time, layout_scale
except ImportError as error:
    raise unittest.SkipTest("Optional Tk GUI runtime is unavailable") from error


class FormattingTests(unittest.TestCase):
    def test_missing_is_not_zero(self):
        for value in (None, "", "bad", -1, math.inf, math.nan):
            self.assertEqual(format_bytes(value), "—")
        self.assertEqual(format_bytes(0), "0 B")

    def test_iec_units_and_rates(self):
        self.assertEqual(format_bytes(1024), "1.00 KiB")
        self.assertEqual(format_bytes(1024 * 1024, True), "1.00 MiB/s")

    def test_missing_time_is_explicit(self):
        self.assertEqual(local_time(None), "—")
        self.assertEqual(local_time("not-a-timestamp"), "—")

    def test_scale_matches_window_and_high_dpi(self):
        self.assertEqual(layout_scale(1050, 700, 2), 1)
        self.assertEqual(layout_scale(1440, 920, 2), 1)
        self.assertEqual(layout_scale(3120, 1939, 2), 2.1)


class WindowTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
            self.root.withdraw()
        except tk.TclError as exc:
            self.skipTest("A graphical display is unavailable: " + type(exc).__name__)
        self.app = ObserverApp(self.root, None)

    def tearDown(self):
        if hasattr(self, "app"):
            self.app.close()

    def test_empty_start_does_not_start_collection(self):
        self.app.refresh_now()
        self.assertIsNone(self.app.store)
        self.assertEqual(self.app.status_badge.cget("text"), "选择数据目录")

    def test_demo_is_visibly_distinct(self):
        self.app.apply_snapshot({
            "demo": True, "selected_run": "synthetic-run", "runs": [],
            "freshness": {"demo": True, "stale": False}, "source_status": {"monitor": "demo"},
            "totals": {"physical_rx": 0, "logical_down": None}, "series": [],
        })
        self.assertEqual(self.app.status_badge.cget("text"), "模拟数据")
        self.assertIn("虚构", self.app.notice.cget("text"))
        self.assertEqual(self.app.metric_values["physical_rx"].cget("text"), "0 B")
        self.assertEqual(self.app.metric_values["logical_down"].cget("text"), "—")

    def test_stale_snapshot_does_not_claim_current_activity(self):
        self.app.apply_snapshot({"selected_run": "old-run", "runs": [],
            "freshness": {"age_seconds": 600, "stale": True},
            "source_status": {"monitor": "running", "connections": "UNAVAILABLE"}})
        self.assertEqual(self.app.status_badge.cget("text"), "数据未更新")
        self.assertIn("不代表进程当前仍在运行", self.app.notice.cget("text"))
        self.assertEqual(len(self.app.connection_tree.get_children()), 0)

    def test_process_cache_is_labelled(self):
        self.app.apply_snapshot({"processes": [{"name": "codex", "pid": 101, "parent_pid": 100,
            "is_cached": True, "cache_age_seconds": 12, "workload": "Unknown"}]})
        item = self.app.process_tree.get_children()[0]
        self.assertEqual(self.app.process_tree.set(item, "freshness"), "缓存 12s")

    def test_partial_totals_are_labelled(self):
        self.app.apply_snapshot({"totals_partial": True, "selected_run": "partial",
            "totals": {"logical_down": 2048}, "freshness": {"stale": False}})
        self.assertIn("仅合计已验证区间", self.app.notice.cget("text"))
        self.assertIn("覆盖不完整", self.app.metric_subtitles["logical_down"].cget("text"))

    def test_rejected_directory_preserves_current_source(self):
        previous = object()
        self.app.store = previous
        with patch("traffic_observer.ui.filedialog.askdirectory", return_value="invalid-source"), \
             patch("traffic_observer.ui.AuditStore", side_effect=ValueError("unsupported source")):
            self.app.choose_directory()
        self.assertIs(self.app.store, previous)
        self.assertIn("请选择可读取的本地监测目录", self.app.notice.cget("text"))

    def test_typography_and_geometry_scale_together_without_drift(self):
        self.app._dpi_scale = 2
        sidebar = self.root.winfo_children()[0]
        with patch.object(self.root, "winfo_width", return_value=3120), \
             patch.object(self.root, "winfo_height", return_value=1939):
            self.app._apply_layout_scale()
        self.assertEqual(self.app._ui_scale, 2.1)
        self.assertEqual(int(sidebar.cget("width")), round(207 * 2.1))
        self.assertEqual(int(self.app.ttk_style.lookup("Audit.Treeview", "rowheight")), round(35 * 2.1))
        with patch.object(self.root, "winfo_width", return_value=1050), \
             patch.object(self.root, "winfo_height", return_value=700):
            self.app._apply_layout_scale()
        self.assertEqual(self.app._ui_scale, 1)
        self.assertEqual(int(sidebar.cget("width")), 207)
        self.assertEqual(int(self.app.ttk_style.lookup("Audit.Treeview", "rowheight")), 35)
        self.assertTrue(self.app._compact)

    def test_all_views_and_resize_are_available(self):
        for view in ("overview", "processes", "events", "connections", "unknown"):
            self.app.show_page(view)
            self.root.geometry("1050x700")
            self.root.update_idletasks()
            self.assertEqual(self.app._view, view)

    @staticmethod
    def unknown_payload():
        return {"selected_run": "synthetic-run", "freshness": {"stale": False},
            "window": {"start_utc": "2026-01-01T00:00:00Z", "end_utc": "2026-01-01T01:00:00Z"},
            "totals": {"unknown_down": 1000},
            "unknown_breakdown": {"status": "ok", "total_down": 1000, "total_up": None,
                "detail_down": 750, "residual_down": 250, "residual_up": None,
                "coverage": {"matched_samples": 2, "summary_samples": 3},
                "groups": [{"group_id": "synthetic-group", "service_category": "chatgpt", "route_alias": "DIRECT",
                    "workload_label": "Campus Insights", "download_bytes": 750, "upload_bytes": 10,
                    "download_share": .75, "sample_count": 2, "evidence_level": "coobserved_only",
                    "first_utc": "2026-01-01T00:05:00Z", "last_utc": "2026-01-01T00:05:20Z",
                    "candidates": [{"pid": 101, "platform": "WSL", "workload": "CampusInsights",
                                    "exe_category": "codex-engine", "confidence": "high_path"}],
                    "evidence": ["synthetic-safe-source: sample 1"], "limitations": ["没有连接到 PID 的映射。"]}]},
            "unknown_ledger_details": {"status": "ok", "total_down": 8192, "total_up": 2048,
                "start_utc": "2026-01-01T00:05:00Z", "end_utc": "2026-01-01T00:55:00Z",
                "actual_coverage": {"bucket_count": 10, "expected_bucket_count": 10},
                "rows": [{"service_category": "chatgpt", "target_alias": "service-01", "target_kind": "domain",
                          "source_alias": "source-01", "route_alias": "node-01", "download_bytes": 8192,
                          "upload_bytes": 2048, "bucket_count": 10}]}}

    def test_unknown_candidate_is_never_confirmed_attribution(self):
        self.app.apply_snapshot(self.unknown_payload())
        tree = self.app.unknown_trees["monitor"]
        first = tree.get_children()[0]
        self.assertIn("候选", tree.set(first, "context"))
        self.assertEqual(tree.set(first, "confidence"), "同期观察 · 未归属")
        details = self.app.unknown_evidence["monitor"].get("1.0", "end")
        self.assertIn("PID 101", details)
        self.assertIn("不是流量归属置信度", details)
        self.assertIn("不是已确认的字节来源", details)
        self.assertEqual(self.app.unknown_evidence["monitor"].cget("state"), "disabled")

    def test_unknown_missing_detail_is_residual_not_workload(self):
        self.app.apply_snapshot(self.unknown_payload())
        tree = self.app.unknown_trees["monitor"]
        self.assertEqual(len(tree.get_children()), 2)
        row = tree.get_children()[1]
        self.assertEqual(tree.set(row, "service"), "目标未细分 / 明细缺失")
        self.assertEqual(tree.set(row, "down"), "250 B")
        self.assertEqual(tree.set(row, "up"), "—")
        self.assertEqual(tree.set(row, "share"), "25.0%")
        self.assertEqual(tree.set(row, "confidence"), "明细缺失")

    def test_unknown_ledger_totals_are_independent(self):
        self.app.apply_snapshot(self.unknown_payload())
        self.assertEqual(self.app.unknown_metrics["down"].cget("text"), "1,000 B")
        self.app._show_unknown_mode("ledger")
        self.assertEqual(self.app.unknown_metrics["down"].cget("text"), "8.00 KiB")
        self.assertIn("不能细分、替代或叠加", self.app.unknown_scope.cget("text"))
        details = self.app.unknown_evidence["ledger"].get("1.0", "end")
        self.assertIn("匿名来源标识不是 PID", details)
        self.app._show_unknown_mode("monitor")
        self.assertEqual(self.app.unknown_metrics["down"].cget("text"), "1,000 B")

    def test_unknown_absent_ledger_is_not_zero(self):
        self.app.apply_snapshot({"totals": {"unknown_down": 2048}})
        self.app._show_unknown_mode("ledger")
        self.assertEqual(self.app.unknown_metrics["down"].cget("text"), "—")
        self.assertIn("尚未启用", self.app.unknown_scope.cget("text"))

    def test_unknown_evidence_can_expand_without_changing_data(self):
        self.app.apply_snapshot(self.unknown_payload())
        before = self.app.unknown_metrics["down"].cget("text")
        self.app._toggle_unknown_evidence("monitor")
        self.assertTrue(self.app._unknown_expanded["monitor"])
        self.assertEqual(self.app.unknown_table_holders["monitor"].winfo_manager(), "")
        self.assertEqual(self.app.unknown_metrics["down"].cget("text"), before)
        self.app._toggle_unknown_evidence("monitor")
        self.assertEqual(self.app.unknown_table_holders["monitor"].winfo_manager(), "grid")

    def test_ledger_labels_are_readable_and_full_alias_stays_in_evidence(self):
        payload = self.unknown_payload()
        row = payload["unknown_ledger_details"]["rows"][0]
        row.update(target_alias="service_chatgpt_exact", service_category="chatgpt_exact",
                   source_alias="source_abcdef123456", route_alias="node_fedcba987654",
                   source_kind="ipv6", source_scope="private")
        self.app.apply_snapshot(payload)
        tree = self.app.unknown_trees["ledger"]
        item = tree.get_children()[0]
        self.assertEqual(tree.set(item, "service"), "ChatGPT 主域")
        self.assertEqual(tree.set(item, "context"), "来源 #abcdef")
        self.assertEqual(tree.set(item, "route"), "非DIRECT #fedcba")
        details = self.app.unknown_evidence["ledger"].get("1.0", "end")
        self.assertIn("source_abcdef123456", details)
        self.assertIn("IPv6", details)
        self.assertIn("这些类别不等于 WSL、TUN 或某个 PID", details)
        self.assertIn("两个视角的匿名标识独立", details)

    def test_unknown_selection_survives_refresh(self):
        payload = self.unknown_payload()
        self.app.apply_snapshot(payload)
        tree = self.app.unknown_trees["monitor"]
        tree.selection_set(tree.get_children()[1])
        self.app.apply_snapshot(payload)
        selected = tree.selection()[0]
        self.assertEqual(tree.set(selected, "service"), "目标未细分 / 明细缺失")

    def test_demo_never_opens_ledger_picker(self):
        self.app.apply_snapshot({"demo": True})
        with patch("traffic_observer.ui.filedialog.askopenfilename") as picker:
            self.app.choose_ledger()
        picker.assert_not_called()
        self.assertEqual(self.app.ledger_button.cget("state"), "disabled")

    def test_changing_monitor_directory_unbinds_existing_ledger(self):
        self.app.mihomo_db = Path("previous.db")
        replacement = object()
        with patch("traffic_observer.ui.filedialog.askdirectory", return_value="replacement"), \
             patch("traffic_observer.ui.AuditStore", return_value=replacement), \
             patch.object(self.app, "refresh_now"):
            self.app.choose_directory()
        self.assertIsNone(self.app.mihomo_db)
        self.assertIs(self.app.store, replacement)


if __name__ == "__main__":
    unittest.main()
