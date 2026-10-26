"""UI presentation semantics and local window smoke tests (no network or collectors)."""
import math
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
        for view in ("overview", "processes", "events", "connections"):
            self.app.show_page(view)
            self.root.geometry("1050x700")
            self.root.update_idletasks()
            self.assertEqual(self.app._view, view)


if __name__ == "__main__":
    unittest.main()
