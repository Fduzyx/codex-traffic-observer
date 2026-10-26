"""Offline, read-only desktop dashboard for traffic audit metadata.

The UI opens no sockets, starts no collectors and never controls a workload.
All disk reads run in a daemon worker; closing this window only closes the UI.
"""
from __future__ import annotations

import datetime as dt
import json
import math
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk
from tkinter import font as tkfont
from typing import Any

from .data import AuditStore

BG = "#f2f5f5"
SURFACE = "#ffffff"
INK = "#172b36"
MUTED = "#617780"
LINE = "#e3ebec"
ACCENT = "#007f80"
SIDEBAR = "#142a35"
FONT = "Microsoft YaHei UI"
MONO = "Consolas"

SERIES = (
    ("physical_rx_rate", "物理 WLAN 接收", "#007f80"),
    ("logical_down_rate", "Mihomo 逻辑下行", "#4e82bb"),
    ("codex_down_rate", "Codex 逻辑下行", "#8660b8"),
    ("unknown_down_rate", "未识别进程下行", "#c59035"),
)
WINDOWS = {"最近 15 分钟": 15, "最近 1 小时": 60, "最近 4 小时": 240, "整个运行段": None}


def display_environment(root: tk.Tk) -> tuple[float, tuple[int, int, int, int]]:
    """Read the current display's DPI/work area without changing Windows settings."""
    work = (0, 0, root.winfo_screenwidth(), root.winfo_screenheight())
    factor = 1.0
    try:
        import ctypes
        from ctypes import wintypes
        user = ctypes.windll.user32
        user.GetDpiForWindow.argtypes = [wintypes.HWND]
        user.GetDpiForWindow.restype = wintypes.UINT
        factor = max(1.0, user.GetDpiForWindow(root.winfo_id()) / 96)
        rect = wintypes.RECT()
        if user.SystemParametersInfoW(48, 0, ctypes.byref(rect), 0):
            work = (rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top)
    except (AttributeError, OSError):
        pass
    return factor, work


def layout_scale(width: int, height: int, dpi_scale: float = 1.0) -> float:
    """One scale for text and geometry; small windows retain the compact baseline."""
    fitting = min(width / 1440, height / 920)
    maximum = max(1.0, min(2.5, dpi_scale * 1.1))
    return max(1.0, min(maximum, round(fitting * 20) / 20))


def _number(value: Any) -> float | None:
    try:
        result = float(value)
        return result if math.isfinite(result) and result >= 0 else None
    except (TypeError, ValueError, OverflowError):
        return None


def format_bytes(value: Any, rate: bool = False) -> str:
    amount = _number(value)
    if amount is None:
        return "—"
    unit = "B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if amount < 1024 or unit == "PiB":
            break
        amount /= 1024
    precision = 0 if unit == "B" else 2 if amount < 10 else 1
    return f"{amount:,.{precision}f} {unit}" + ("/s" if rate else "")


def _datetime(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=dt.timezone.utc) if parsed.tzinfo is None else parsed
    except (ValueError, OverflowError):
        return None


def local_time(value: Any, full: bool = False) -> str:
    parsed = _datetime(value)
    if parsed is None:
        return "—"
    return parsed.astimezone().strftime("%m-%d %H:%M:%S" if full else "%H:%M:%S")


def _text(value: Any, limit: int = 240) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value).replace("\x00", "").replace("\r", " ").replace("\n", " ")[:limit]


def _truth(value: Any) -> bool:
    return value is True or str(value).lower() in ("true", "1", "yes")


def workload_name(value: Any) -> str:
    return {
        "CodexDesktop": "Codex Desktop",
        "CampusMainWSL": "Campus · WSL",
        "CampusRadarWSL": "CampusRadar · WSL",
        "CampusInsights": "Campus Insights",
        "CodexCLI": "Codex CLI",
        "UnclassifiedCodex": "未分类 Codex",
        "VSCode": "VS Code",
        "Unknown": "未分类实例",
        "desktop_app_server": "Desktop / app-server",
        "backend_log_modules": "Codex 日志模块",
        "main_evaluator": "Campus 评估器",
        "codex_calls_ledger": "Insights 调用账本",
    }.get(str(value), _text(value))


class RateChart(tk.Canvas):
    """Canvas plot with explicit missing values and a metadata-only hover cursor."""

    def __init__(self, master: tk.Misc, **kwargs: Any):
        super().__init__(master, background=SURFACE, highlightthickness=0, **kwargs)
        self.series: list[dict[str, Any]] = []
        self.visible = {key: True for key, _, _ in SERIES}
        self._points: list[tuple[float, dict[str, Any]]] = []
        self._plot_box = (66, 20, 600, 250)
        self.ui_scale = 1.0
        self.bind("<Configure>", lambda _: self.draw())
        self.bind("<Motion>", self._hover)
        self.bind("<Leave>", lambda _: self.delete("hover"))

    def set_data(self, values: list[dict[str, Any]]) -> None:
        self.series = values
        self.draw()

    def draw(self) -> None:
        self.delete("all")
        self._points = []
        scale = self.ui_scale
        px = lambda value: max(1, round(value * scale))
        width = max(px(200), self.winfo_width())
        height = max(px(160), self.winfo_height())
        left, top, right, bottom = px(76), px(28), width - px(22), height - px(34)
        self._plot_box = (left, top, right, bottom)
        parsed = []
        for row in self.series:
            stamp = _datetime(row.get("timestamp"))
            if stamp is not None:
                parsed.append((stamp.timestamp(), row))
        parsed.sort(key=lambda item: item[0])
        usable = [(_number(row.get(key)) or 0) for _, row in parsed for key, _, _ in SERIES if self.visible[key]]
        maximum = max(usable, default=0)
        maximum = max(maximum * 1.15, 1024.0)
        for index in range(5):
            y = top + (bottom - top) * index / 4
            self.create_line(left, y, right, y, fill=LINE, dash=(px(2), px(4)))
            self.create_text(left - px(12), y, anchor="e", text=format_bytes(maximum * (4 - index) / 4, True),
                             font=(FONT, px(8)), fill=MUTED)
        self.create_line(left, bottom, right, bottom, fill=LINE)
        if not parsed:
            self.create_text((left + right) / 2, (top + bottom) / 2 - px(13), text="等待可用的增量数据",
                             font=(FONT, px(14), "bold"), fill=INK)
            self.create_text((left + right) / 2, (top + bottom) / 2 + px(18),
                             text="首个累计计数是基线；没有增量时不会画成零流量。", font=(FONT, px(10)), fill=MUTED)
            return
        source_times = [stamp for stamp, _ in parsed]
        for _, row in parsed:
            logical = _datetime(row.get("logical_timestamp"))
            if logical is not None:
                source_times.append(logical.timestamp())
        start, end = min(source_times), max(source_times)
        span = max(end - start, 1)
        for index in range(5):
            x = left + (right - left) * index / 4
            stamp = dt.datetime.fromtimestamp(start + span * index / 4).strftime("%H:%M:%S")
            self.create_text(x, bottom + px(17), text=stamp, font=(FONT, px(8)), fill=MUTED)
        self._points = [(left + (stamp - start) / span * (right - left), row) for stamp, row in parsed]
        for key, _, color in SERIES:
            if not self.visible[key]:
                continue
            segment: list[float] = []
            entries = []
            for stamp, row in parsed:
                logical = _datetime(row.get("logical_timestamp")) if key != "physical_rx_rate" else None
                entries.append((logical.timestamp() if logical is not None else stamp, row))
            for stamp, row in sorted(entries, key=lambda item: item[0]):
                x = left + (stamp - start) / span * (right - left)
                value = _number(row.get(key))
                if value is None:
                    if len(segment) >= 4:
                        self.create_line(*segment, fill=color, width=px(2), joinstyle="round")
                    segment = []
                    continue
                y = bottom - value / maximum * (bottom - top)
                segment.extend((x, y))
            if len(segment) >= 4:
                self.create_line(*segment, fill=color, width=px(2), joinstyle="round")
            elif len(segment) == 2:
                x, y = segment
                self.create_oval(x - px(2), y - px(2), x + px(2), y + px(2), fill=color, outline="")

    def _hover(self, event: tk.Event) -> None:
        self.delete("hover")
        if not self._points:
            return
        left, top, right, bottom = self._plot_box
        if not (left <= event.x <= right and top <= event.y <= bottom):
            return
        x, row = min(self._points, key=lambda item: abs(item[0] - event.x))
        px = lambda value: max(1, round(value * self.ui_scale))
        self.create_line(x, top, x, bottom, fill="#b5c6ca", dash=(px(3), px(3)), tags="hover")
        lines = ["物理取样  " + local_time(row.get("timestamp"), True)]
        if row.get("logical_timestamp"):
            lines.append("逻辑读取  " + local_time(row.get("logical_timestamp")))
        for key, name, _ in SERIES:
            if self.visible[key]:
                lines.append(f"{name}   {format_bytes(row.get(key), True)}")
        box_width = px(250)
        box_height = px(24 + len(lines) * 19)
        bx = min(max(x + px(14), left), max(left, right - box_width))
        by = top + px(7)
        self.create_rectangle(bx, by, bx + box_width, by + box_height, fill=SIDEBAR, outline="", tags="hover")
        self.create_text(bx + px(13), by + px(12), anchor="nw", text="\n".join(lines), fill="#edf6f8",
                         font=(FONT, px(9)), width=box_width - px(26), tags="hover")


class ObserverApp:
    """Read-only window. ``refresh_now`` and ``apply_snapshot`` assist local UI tests."""

    def __init__(self, root: tk.Tk, directory: Path | None, demo: bool = False,
                 mihomo_db: Path | None = None):
        self.root = root
        # Use a known font baseline, then scale fonts AND pixel layout together.
        # These are process-local Tk settings, not Windows display configuration.
        self.root.tk.call("tk", "scaling", 96 / 72)
        self._dpi_scale, work_area = display_environment(root)
        self._ui_scale = 1.0
        self._design_geometry: list[dict[str, Any]] = []
        self._tree_geometry: list[tuple[ttk.Treeview, dict[str, dict[str, int]]]] = []
        self.directory = Path(directory) if directory is not None else None
        self.demo = demo
        self.mihomo_db = None if demo or mihomo_db is None else Path(mihomo_db)
        self.store = AuditStore(self.directory, mihomo_db=self.mihomo_db) if self.directory is not None else None
        self.snapshot: dict[str, Any] = {}
        self._queue: queue.Queue = queue.Queue()
        self._pending = False
        self._closed = False
        self._generation = 0
        self._run_id: str | None = None
        self._run_labels: dict[str, str | None] = {"最新运行段": None}
        self._view = "overview"
        self._compact = False
        self._event_rows: dict[str, dict[str, Any]] = {}
        self._unknown_rows: dict[str, dict[str, dict[str, Any]]] = {"monitor": {}, "ledger": {}}
        self._unknown_mode = "monitor"
        self._legend_vars: dict[str, tk.BooleanVar] = {}
        self._after_ids: dict[str, str] = {}
        self._last_refresh = 0.0
        self.root.title("Codex Traffic Observer · 本地流量观察台")
        self.root.configure(background=BG)
        work_x, work_y, screen_w, screen_h = work_area
        initial_scale = min(self._dpi_scale, 2.5)
        width = max(1050, min(round(1440 * initial_scale), screen_w - round(64 * initial_scale)))
        height = max(700, min(round(920 * initial_scale), screen_h - round(72 * initial_scale)))
        x, y = work_x + max(0, (screen_w - width) // 2), work_y + max(0, (screen_h - height) // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.minsize(1050, 700)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self._style()
        self._build()
        self._capture_design_geometry()
        self.root.bind("<F5>", lambda _: self.refresh_now())
        self.root.bind("<Control-o>", lambda _: self.choose_directory())
        for key, page in enumerate(("overview", "processes", "events", "connections", "unknown"), 1):
            self.root.bind(f"<Alt-Key-{key}>", lambda _, page=page: self.show_page(page))
        self._after_ids["queue"] = root.after(100, self._drain_queue)
        self._after_ids["initial"] = root.after(50, self.refresh_now)
        self._after_ids["refresh"] = root.after(5000, self._refresh_tick)
        self._after_ids["layout"] = root.after(10, self._apply_layout_scale)

    def _style(self) -> None:
        style = ttk.Style(self.root)
        self.ttk_style = style
        style.theme_use("clam")
        style.configure("TCombobox", padding=(10, 7), font=(FONT, 10), fieldbackground=SURFACE,
                        background=SURFACE, bordercolor=LINE, arrowcolor=MUTED)
        style.map("TCombobox", fieldbackground=[("readonly", SURFACE)], selectbackground=[("readonly", SURFACE)],
                  selectforeground=[("readonly", INK)])
        style.configure("Audit.Treeview", background=SURFACE, foreground=INK, fieldbackground=SURFACE,
                        rowheight=35, borderwidth=0, font=(FONT, 9))
        style.configure("Audit.Treeview.Heading", background="#edf3f4", foreground=MUTED,
                        relief="flat", padding=(9, 10), font=(FONT, 9, "bold"))
        style.map("Audit.Treeview", background=[("selected", "#d9eeed")], foreground=[("selected", INK)])
        style.map("Audit.Treeview.Heading", background=[("active", "#e3eeee")])
        style.configure("Vertical.TScrollbar", background="#cbd9dc", bordercolor=SURFACE,
                        troughcolor=SURFACE, arrowcolor=MUTED, relief="flat")

    @staticmethod
    def label(parent: tk.Misc, text: str = "", *, size: int = 10, color: str = INK,
              bold: bool = False, bg: str = SURFACE, **kwargs: Any) -> tk.Label:
        return tk.Label(parent, text=text, font=(FONT, size, "bold" if bold else "normal"),
                        foreground=color, background=bg, **kwargs)

    @staticmethod
    def button(parent: tk.Misc, text: str, command: Any, *, primary: bool = False) -> tk.Button:
        return tk.Button(parent, text=text, command=command, font=(FONT, 10),
                         background=ACCENT if primary else SURFACE,
                         foreground="white" if primary else INK,
                         activebackground="#006c6e" if primary else "#eaf1f2",
                         activeforeground="white" if primary else INK, relief="flat",
                         borderwidth=0, padx=14, pady=8, cursor="hand2", takefocus=True)

    def _build(self) -> None:
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        sidebar = tk.Frame(self.root, background=SIDEBAR, width=207)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(8, weight=1)
        logo = tk.Canvas(sidebar, width=42, height=42, background=SIDEBAR, highlightthickness=0)
        self.logo = logo
        logo.grid(row=0, column=0, sticky="w", padx=23, pady=(27, 8))
        for x, h, c in [(5, 12, "#55969b"), (16, 27, "#8bd6cd"), (27, 20, "#b8ebe5")]:
            logo.create_rectangle(x, 35 - h, x + 6, 35, fill=c, outline="")
        self.label(sidebar, "流量观察台", size=19, bold=True, bg=SIDEBAR, color="white").grid(row=1, column=0, sticky="w", padx=24)
        self.label(sidebar, "CODEX TRAFFIC OBSERVER", size=7, bg=SIDEBAR, color="#91adb8").grid(row=2, column=0, sticky="w", padx=25, pady=(5, 33))
        self._nav_buttons = {}
        for row, (key, text, icon) in enumerate((("overview", "流量总览", "◫"), ("processes", "进程实例", "▤"),
                                                ("events", "活动时间线", "≡"), ("connections", "连接证据", "⇄"),
                                                ("unknown", "未识别流量", "◇")), 3):
            button = tk.Button(sidebar, text=f"{icon}   {text}", font=(FONT, 11), anchor="w", padx=21, pady=13,
                               background=SIDEBAR, foreground="#aec2ca", activebackground="#23424f",
                               activeforeground="white", relief="flat", borderwidth=0, cursor="hand2",
                               command=lambda page=key: self.show_page(page))
            button.grid(row=row, column=0, sticky="ew", padx=12, pady=3)
            self._nav_buttons[key] = button
        foot = tk.Frame(sidebar, bg=SIDEBAR)
        foot.grid(row=9, column=0, sticky="sew", padx=23, pady=25)
        self.label(foot, "●  完全本地 · 只读观察", color="#a2d8ce", bg=SIDEBAR, size=9).pack(anchor="w")
        self.label(foot, "无模型调用 · 无网络服务", color="#8eabb7", bg=SIDEBAR, size=8).pack(anchor="w", pady=(7, 0))
        self.label(foot, "关闭界面不会停止采集", color="#8eabb7", bg=SIDEBAR, size=8).pack(anchor="w", pady=(4, 0))

        main = tk.Frame(self.root, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)
        header = tk.Frame(main, bg=BG)
        self.header = header
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(25, 16))
        header.grid_columnconfigure(0, weight=1)
        self.title_label = self.label(header, "流量总览", size=22, bold=True, bg=BG)
        self.title_label.grid(row=0, column=0, sticky="w")
        self.subtitle_label = self.label(header, "将实际接收、代理账本与工作负载放在同一时间轴上。", size=9, color=MUTED, bg=BG)
        self.subtitle_label.grid(row=1, column=0, sticky="w", pady=(5, 0))
        self.status_badge = self.label(header, "正在读取", size=9, color=ACCENT, bg="#e3efed", padx=12, pady=7)
        self.status_badge.grid(row=0, column=1, sticky="e", padx=(10, 13))
        self.refresh_button = self.button(header, "刷新  ↻", self.refresh_now)
        self.refresh_button.grid(row=0, column=2, sticky="e")
        self.timestamp_label = self.label(header, "每 5 秒刷新界面", size=8, color=MUTED, bg=BG)
        self.timestamp_label.grid(row=1, column=1, columnspan=2, sticky="e", pady=(4, 0))

        toolbar = tk.Frame(main, bg=SURFACE, highlightbackground=LINE, highlightthickness=1)
        self.toolbar = toolbar
        toolbar.grid(row=1, column=0, sticky="ew", padx=28, pady=(0, 14))
        toolbar.grid_columnconfigure(1, weight=1)
        self.button(toolbar, "选择数据目录", self.choose_directory).grid(row=0, column=0, padx=(8, 8), pady=7)
        self.directory_label = self.label(toolbar, "内置模拟数据" if self.demo else str(self.directory) if self.directory else "尚未选择数据目录", color=MUTED, size=8, anchor="w")
        self.directory_label.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.run_var = tk.StringVar(value="最新运行段")
        self.run_combo = ttk.Combobox(toolbar, textvariable=self.run_var, values=["最新运行段"], width=21, state="readonly")
        self.run_combo.grid(row=0, column=2, padx=(0, 10), pady=9)
        self.run_combo.bind("<<ComboboxSelected>>", self._select_run)
        self.window_var = tk.StringVar(value="最近 1 小时")
        window_combo = ttk.Combobox(toolbar, textvariable=self.window_var, values=list(WINDOWS), width=13, state="readonly")
        window_combo.grid(row=0, column=3, padx=(0, 12), pady=9)
        window_combo.bind("<<ComboboxSelected>>", self._filter_changed)

        self.notice = self.label(main, "正在读取现有采集文件…", color=MUTED, bg=BG, size=9, anchor="w")
        self.notice.grid(row=2, column=0, sticky="ew", padx=29, pady=(0, 10))
        self.pages = tk.Frame(main, bg=BG)
        self.pages.grid(row=3, column=0, sticky="nsew", padx=28)
        self.pages.grid_rowconfigure(0, weight=1)
        self.pages.grid_columnconfigure(0, weight=1)
        self.page_frames = {name: tk.Frame(self.pages, bg=BG) for name in ("overview", "processes", "events", "connections", "unknown")}
        for frame in self.page_frames.values():
            frame.grid(row=0, column=0, sticky="nsew")
        self._build_overview(self.page_frames["overview"])
        self._build_processes(self.page_frames["processes"])
        self._build_events(self.page_frames["events"])
        self._build_connections(self.page_frames["connections"])
        self._build_unknown(self.page_frames["unknown"])
        footer = tk.Frame(main, bg=BG)
        self.footer = footer
        footer.grid(row=4, column=0, sticky="ew", padx=29, pady=(12, 15))
        self.label(footer, "UTC 时间戳按本地时区显示 · 数值使用 IEC 字节单位", size=8, color=MUTED, bg=BG).pack(side="left")
        self.label(footer, "F5 刷新   Ctrl+O 选择目录   Alt+1…5 切换视图", size=8, color=MUTED, bg=BG).pack(side="right")
        self.show_page("overview")
        main.bind("<Configure>", self._adaptive_layout)

    def _build_overview(self, parent: tk.Frame) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        cards = tk.Frame(parent, bg=BG)
        self.cards = cards
        cards.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        self.metric_values, self.metric_subtitles, self.metric_titles = {}, {}, {}
        for column, (key, name, color) in enumerate((("physical_rx", "物理 WLAN 接收", "#007f80"),
                ("logical_down", "Mihomo 逻辑下行", "#4e82bb"), ("codex_down", "Codex 逻辑下行", "#8660b8"),
                ("unknown_down", "未识别进程流量", "#c59035"))):
            cards.grid_columnconfigure(column, weight=1, uniform="metric")
            card = tk.Frame(cards, bg=SURFACE, highlightbackground=LINE, highlightthickness=1)
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 6, 0 if column == 3 else 6))
            tk.Frame(card, bg=color, height=3).pack(fill="x")
            title = self.label(card, name, color=MUTED, size=9)
            title.pack(anchor="w", padx=16, pady=(14, 7))
            value = self.label(card, "—", size=23, bold=True)
            value.pack(anchor="w", padx=15)
            detail = self.label(card, "所选时间范围", size=8, color=MUTED)
            detail.pack(anchor="w", padx=16, pady=(7, 15))
            self.metric_values[key], self.metric_subtitles[key] = value, detail
            self.metric_titles[key] = title
            card.bind("<Configure>", lambda event, label=value: self._fit_metric(label, event.width - round(32 * self._ui_scale)))
            if key == "unknown_down":
                for target in (card, title, value, detail):
                    target.configure(cursor="hand2")
                    target.bind("<Button-1>", lambda _: self.show_page("unknown"))
                card.configure(takefocus=True)
                card.bind("<Return>", lambda _: self.show_page("unknown"))
                card.bind("<space>", lambda _: self.show_page("unknown"))
        chart_panel = tk.Frame(parent, bg=SURFACE, highlightbackground=LINE, highlightthickness=1)
        chart_panel.grid(row=1, column=0, sticky="nsew")
        chart_panel.grid_columnconfigure(0, weight=1)
        chart_panel.grid_rowconfigure(2, weight=1)
        heading = tk.Frame(chart_panel, bg=SURFACE)
        heading.grid(row=0, column=0, sticky="ew", padx=20, pady=(17, 4))
        self.label(heading, "接收速率与账本增量", size=13, bold=True).pack(side="left")
        self.chart_range = self.label(heading, "等待数据", size=8, color=MUTED)
        self.chart_range.pack(side="right")
        legend = tk.Frame(chart_panel, bg=SURFACE)
        legend.grid(row=1, column=0, sticky="w", padx=17, pady=(3, 0))
        for key, name, color in SERIES:
            variable = tk.BooleanVar(value=True)
            self._legend_vars[key] = variable
            check = tk.Checkbutton(legend, text=name, variable=variable, command=self._legend_changed,
                                   font=(FONT, 8), fg=color, bg=SURFACE, activebackground=SURFACE,
                                   activeforeground=color, selectcolor=SURFACE, relief="flat", padx=4)
            check.pack(side="left", padx=(0, 12))
        self.chart = RateChart(chart_panel, height=250)
        self.chart.grid(row=2, column=0, sticky="nsew", padx=10, pady=(3, 3))
        self.label(chart_panel, "逻辑曲线按落库增量折算，可能滞后于网卡；Codex 与未识别进程属于逻辑总量的子集，不应相加。",
                   size=8, color=MUTED, anchor="w").grid(row=3, column=0, sticky="ew", padx=20, pady=(1, 14))
        lower = tk.Frame(parent, bg=BG)
        self.overview_lower = lower
        lower.grid(row=2, column=0, sticky="ew", pady=(14, 0))
        lower.grid_columnconfigure(0, weight=3)
        lower.grid_columnconfigure(1, weight=2)
        left = tk.Frame(lower, bg="#e6f0ef", padx=17, pady=14)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.label(left, "观察结论", size=10, bold=True, bg="#e6f0ef", color=ACCENT).pack(anchor="w")
        self.insight_label = self.label(left, "接收量说明发生了传输；实例同时存在并不证明它产生了这些字节。", size=9,
                                         color="#365b62", bg="#e6f0ef", anchor="w", justify="left", wraplength=620)
        self.insight_label.pack(fill="x", pady=(7, 0))
        right = tk.Frame(lower, bg=SURFACE, padx=17, pady=14, highlightbackground=LINE, highlightthickness=1)
        right.grid(row=0, column=1, sticky="nsew")
        self.label(right, "证据覆盖", size=10, bold=True).pack(anchor="w")
        self.coverage_label = self.label(right, "正在检查采样与连接证据", color=MUTED, size=9, anchor="w", justify="left", wraplength=380)
        self.coverage_label.pack(fill="x", pady=(7, 0))

    def _fit_metric(self, label: tk.Label, available: int) -> None:
        size = round(23 * self._ui_scale)
        face = tkfont.Font(family=FONT, size=size, weight="bold")
        while size > round(14 * self._ui_scale) and face.measure(label.cget("text")) > max(70, available - round(4 * self._ui_scale)):
            size -= 1
            face.configure(size=size)
        label.configure(font=(FONT, size, "bold"))

    def _adaptive_layout(self, event: tk.Event) -> None:
        if self._closed:
            return
        previous = self._after_ids.get("layout")
        if previous:
            try:
                self.root.after_cancel(previous)
            except tk.TclError:
                pass
        self._after_ids["layout"] = self.root.after(90, self._apply_layout_scale)

    def _capture_design_geometry(self) -> None:
        """Capture design pixels once; later resizing never compounds old scaling."""
        def visit(widget: tk.Misc) -> None:
            record: dict[str, Any] = {"widget": widget, "options": {}, "manager": widget.winfo_manager()}
            options = widget.configure()
            for name in ("padx", "pady", "borderwidth", "highlightthickness", "wraplength"):
                if name in options:
                    try:
                        record["options"][name] = float(widget.cget(name))
                    except (TypeError, ValueError, tk.TclError):
                        pass
            if isinstance(widget, (tk.Frame, tk.Canvas)):
                for name in ("width", "height"):
                    record["options"][name] = float(widget.cget(name))
            if "font" in options:
                try:
                    face = tkfont.Font(font=widget.cget("font")).actual()
                    record["font"] = (face["family"], abs(int(face["size"])), face["weight"], face["slant"])
                except tk.TclError:
                    pass
            if isinstance(widget, ttk.Combobox):
                record["font"] = (FONT, 10, "normal", "roman")
            manager = record["manager"]
            info = widget.grid_info() if manager == "grid" else widget.pack_info() if manager == "pack" else {}
            record["padding"] = {key: info[key] for key in ("padx", "pady", "ipadx", "ipady") if key in info}
            self._design_geometry.append(record)
            if isinstance(widget, ttk.Treeview):
                self._tree_geometry.append((widget, {key: {name: int(widget.column(key, name)) for name in ("width", "minwidth")}
                    for key in widget.cget("columns")}))
            for child in widget.winfo_children():
                visit(child)
        for child in self.root.winfo_children():
            visit(child)

    def _scaled_padding(self, value: Any, scale: float) -> Any:
        parts = value if isinstance(value, (tuple, list)) else self.root.tk.splitlist(str(value))
        result = tuple(round(float(part) * scale) for part in parts)
        return result[0] if len(result) == 1 else result

    def _apply_layout_scale(self) -> None:
        if self._closed or not self._design_geometry:
            return
        width, height = self.root.winfo_width(), self.root.winfo_height()
        scale = layout_scale(width, height, self._dpi_scale)
        compact = height / scale < 830
        changed = abs(scale - self._ui_scale) > .01
        mode_changed = compact != self._compact
        if changed:
            old_scale = self._ui_scale
            self._ui_scale = scale
            for record in self._design_geometry:
                widget = record["widget"]
                values = {key: round(value * scale) for key, value in record["options"].items()}
                if record.get("font"):
                    family, size, weight, slant = record["font"]
                    values["font"] = (family, max(7, round(size * scale)), weight, slant)
                if values:
                    widget.configure(**values)
                padding = {key: self._scaled_padding(value, scale) for key, value in record["padding"].items()}
                if padding and record["manager"] == "grid":
                    widget.grid_configure(**padding)
                elif padding and record["manager"] == "pack":
                    widget.pack_configure(**padding)
            for tree, columns in self._tree_geometry:
                for key, values in columns.items():
                    tree.column(key, **{name: round(value * scale) for name, value in values.items()})
            self.logo.scale("all", 0, 0, scale / old_scale, scale / old_scale)
            self.ttk_style.configure("TCombobox", padding=(round(10 * scale), round(7 * scale)), font=(FONT, round(10 * scale)))
            self.ttk_style.configure("Audit.Treeview", rowheight=round(35 * scale), font=(FONT, round(9 * scale)))
            self.ttk_style.configure("Audit.Treeview.Heading", padding=(round(9 * scale), round(10 * scale)), font=(FONT, round(9 * scale), "bold"))
            for name in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
                self.ttk_style.configure(name, arrowsize=round(12 * scale))
            self.root.option_add("*TCombobox*Listbox.font", (FONT, round(10 * scale)))
            self.chart.ui_scale = scale
            self.chart.draw()
        self.notice.configure(wraplength=max(300, width - round((207 + 58) * scale)), justify="left")
        for mode, expanded in self._unknown_expanded.items():
            if expanded:
                self.unknown_table_holders[mode].grid_remove()
        if not changed and not mode_changed:
            return
        self._compact = compact
        if compact:
            self.overview_lower.grid_remove()
            self.footer.grid_remove()
        else:
            self.overview_lower.grid()
            self.footer.grid()
        self.header.grid_configure(pady=self._scaled_padding((16, 10) if compact else (25, 16), scale))
        self.toolbar.grid_configure(pady=self._scaled_padding((0, 10) if compact else (0, 14), scale))
        self.notice.grid_configure(pady=self._scaled_padding((0, 5) if compact else (0, 10), scale))
        self.cards.grid_configure(pady=self._scaled_padding((0, 10) if compact else (0, 16), scale))
        for title in self.metric_titles.values():
            title.pack_configure(pady=self._scaled_padding((10, 4) if compact else (14, 7), scale))
        for subtitle in self.metric_subtitles.values():
            subtitle.pack_configure(pady=self._scaled_padding((4, 8) if compact else (7, 15), scale))
        for label in self.metric_values.values():
            self._fit_metric(label, label.master.winfo_width() - round(32 * scale))

    def _table(self, parent: tk.Frame, columns: list[tuple[str, str, int]], *, height: int = 12) -> ttk.Treeview:
        frame = tk.Frame(parent, bg=SURFACE, highlightbackground=LINE, highlightthickness=1)
        frame.pack(fill="both", expand=True)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", style="Audit.Treeview", height=height)
        tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        for key, title, width in columns:
            tree.heading(key, text=title, anchor="w", command=lambda k=key, tr=tree: self._sort_tree(tr, k))
            tree.column(key, width=width, minwidth=max(55, int(width * .65)), anchor="w", stretch=True)
        tree.tag_configure("muted", foreground=MUTED)
        tree.tag_configure("warning", foreground="#9b681c")
        tree.tag_configure("alternate", background="#f7fafa")
        return tree

    def _build_processes(self, parent: tk.Frame) -> None:
        bar = tk.Frame(parent, bg=BG)
        bar.pack(fill="x", pady=(0, 11))
        self.process_summary = self.label(bar, "等待实例元数据", size=10, color=MUTED, bg=BG)
        self.process_summary.pack(side="left")
        self.engines_only = tk.BooleanVar(value=True)
        tk.Checkbutton(bar, text="仅看 Codex 引擎", variable=self.engines_only, command=self._render_processes,
                       font=(FONT, 9), bg=BG, activebackground=BG, fg=INK, selectcolor=SURFACE).pack(side="right")
        self.process_tree = self._table(parent, [("workload", "工作负载", 165), ("pid", "PID / 父 PID", 125),
            ("platform", "平台", 90), ("started", "启动时间", 140), ("category", "程序类别", 210),
            ("freshness", "取样状态", 110), ("confidence", "归类依据", 160)])
        self.label(parent, "进程存在不是任务正在生成的证明。WSL 缓存行按来源时间标注；未知归属始终保留未知。", color=MUTED,
                   size=9, bg=BG, anchor="w").pack(fill="x", pady=(13, 2))

    def _build_events(self, parent: tk.Frame) -> None:
        bar = tk.Frame(parent, bg=BG)
        bar.pack(fill="x", pady=(0, 11))
        self.event_summary = self.label(bar, "等待活动记录", size=10, color=MUTED, bg=BG)
        self.event_summary.pack(side="left")
        self.event_filter = tk.StringVar(value="重要事件")
        chooser = ttk.Combobox(bar, textvariable=self.event_filter, values=["重要事件", "全部元数据"], state="readonly", width=15)
        chooser.pack(side="right")
        chooser.bind("<<ComboboxSelected>>", lambda _: self._render_events())
        self.event_tree = self._table(parent, [("time", "发生时间", 145), ("workload", "工作负载", 160),
            ("event", "事件", 280), ("status", "状态", 210), ("count", "记录数", 75)], height=11)
        self.event_tree.bind("<<TreeviewSelect>>", self._show_event_evidence)
        details = tk.Frame(parent, bg="#eaf1f2", padx=16, pady=13)
        details.pack(fill="x", pady=(13, 0))
        self.label(details, "证据位置", size=9, bold=True, bg="#eaf1f2").pack(anchor="w")
        self.event_evidence = self.label(details, "选择一条记录查看其来源。日志记录数不等于模型调用数，未记录事件也不等于空闲。",
                                         color=MUTED, size=8, bg="#eaf1f2", wraplength=1000, justify="left", anchor="w")
        self.event_evidence.pack(fill="x", pady=(6, 0))

    def _build_connections(self, parent: tk.Frame) -> None:
        banner = tk.Frame(parent, bg="#fff2dd", padx=19, pady=16)
        banner.pack(fill="x", pady=(0, 15))
        self.connection_title = self.label(banner, "连接级证据暂缺", color="#8f631e", bg="#fff2dd", size=12, bold=True)
        self.connection_title.pack(anchor="w")
        self.connection_note = self.label(banner, "现有账本不能把流量分到单条连接；这里不会用历史统计桶代造连接记录。",
                                          color="#8f7549", bg="#fff2dd", size=9, wraplength=1000, justify="left", anchor="w")
        self.connection_note.pack(fill="x", pady=(7, 0))
        self.connection_tree = self._table(parent, [("id", "连接 ID", 135), ("process", "进程 / PID", 150),
            ("target", "目标类别 / 域名", 180), ("down", "累计下行", 115), ("delta", "下行增量", 115),
            ("up", "累计上行", 115), ("started", "连接开始", 135)])
        self.label(parent, "同一连接的累计计数才可差分；连接重建本身不是重复下载证据。界面不会调用或开启控制接口。",
                   color=MUTED, size=9, bg=BG, anchor="w").pack(fill="x", pady=(13, 2))

    def _build_unknown(self, parent: tk.Frame) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(3, weight=1)
        summary = tk.Frame(parent, bg=SURFACE, highlightbackground=LINE, highlightthickness=1)
        summary.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.unknown_metrics = {}
        for column, (key, title) in enumerate((("down", "未识别进程下行"), ("up", "未识别进程上行"), ("rows", "可查看的分组"))):
            summary.grid_columnconfigure(column, weight=1, uniform="unknown_metric")
            cell = tk.Frame(summary, bg=SURFACE, padx=16, pady=10)
            cell.grid(row=0, column=column, sticky="nsew")
            self.label(cell, title, color=MUTED, size=8).pack(anchor="w")
            value = self.label(cell, "—", size=18, bold=True, color="#9b681c" if key == "down" else INK)
            value.pack(anchor="w", pady=(3, 0))
            self.unknown_metrics[key] = value
        controls = tk.Frame(parent, bg=BG)
        controls.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.unknown_mode_buttons = {}
        for mode, text in (("monitor", "监测增量 · 活动关联"), ("ledger", "原账本 · 服务 / 来源细分")):
            button = self.button(controls, text, lambda mode=mode: self._show_unknown_mode(mode))
            button.pack(side="left", padx=(0, 8))
            self.unknown_mode_buttons[mode] = button
        self.ledger_button = self.button(controls, "选择已有账本", self.choose_ledger)
        self.ledger_button.pack(side="right")
        if self.demo:
            self.ledger_button.configure(state="disabled")
        self.unknown_scope = self.label(parent, "等待未识别流量明细。", color=MUTED, size=8, bg=BG,
                                        anchor="w", justify="left", wraplength=1000)
        self.unknown_scope.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        self.unknown_scope.bind("<Configure>", lambda event: self.unknown_scope.configure(wraplength=max(250, event.width)))
        self.unknown_views, self.unknown_trees, self.unknown_evidence = {}, {}, {}
        self.unknown_table_holders, self.unknown_expand_buttons = {}, {}
        self._unknown_expanded = {"monitor": False, "ledger": False}
        for mode in ("monitor", "ledger"):
            frame = tk.Frame(parent, bg=BG)
            frame.grid(row=3, column=0, sticky="nsew")
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_rowconfigure(0, weight=3)
            frame.grid_rowconfigure(1, weight=2)
            self.unknown_views[mode] = frame
            holder = tk.Frame(frame, bg=BG)
            holder.grid(row=0, column=0, sticky="nsew")
            self.unknown_table_holders[mode] = holder
            columns = [("service", "目标服务", 175), ("route", "出口", 110)]
            columns.append(("context", "同期活跃 · 仅候选" if mode == "monitor" else "匿名来源", 205 if mode == "monitor" else 145))
            columns += [("down", "下行", 100), ("up", "上行", 100), ("share", "下行占比", 85), ("confidence", "证据等级", 135)]
            tree = self._table(holder, columns, height=4)
            tree.bind("<<TreeviewSelect>>", lambda _, mode=mode: self._show_unknown_evidence(mode))
            self.unknown_trees[mode] = tree
            details = tk.Frame(frame, bg="#eaf1f2", padx=13, pady=9)
            details.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
            details.grid_columnconfigure(0, weight=1)
            details.grid_rowconfigure(1, weight=1)
            heading = tk.Frame(details, bg="#eaf1f2")
            heading.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 5))
            self.label(heading, "安全证据与归因边界", size=9, bold=True, bg="#eaf1f2").pack(side="left")
            expand = tk.Button(heading, text="展开证据 ↗", command=lambda mode=mode: self._toggle_unknown_evidence(mode),
                               font=(FONT, 8), fg=ACCENT, bg="#eaf1f2", relief="flat", borderwidth=0, padx=4, pady=0,
                               cursor="hand2", takefocus=True)
            expand.pack(side="right")
            self.unknown_expand_buttons[mode] = expand
            text = tk.Text(details, wrap="word", height=5, width=20, font=(FONT, 9), bg="#eaf1f2", fg="#365b62",
                           relief="flat", borderwidth=0, highlightthickness=0, padx=0, pady=0,
                           cursor="arrow", state="disabled", takefocus=True)
            text.grid(row=1, column=0, sticky="nsew")
            scrollbar = ttk.Scrollbar(details, orient="vertical", command=text.yview)
            scrollbar.grid(row=1, column=1, sticky="ns")
            text.configure(yscrollcommand=scrollbar.set)
            self.unknown_evidence[mode] = text
            self._set_unknown_evidence(mode, "选择一行查看安全证据、候选 PID、未确认原因及统计覆盖。\n服务或出口已识别，也不等于产生流量的进程已识别。")
        self._show_unknown_mode("monitor")

    def _set_unknown_evidence(self, mode: str, text: str) -> None:
        widget = self.unknown_evidence[mode]
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _toggle_unknown_evidence(self, mode: str) -> None:
        expanded = not self._unknown_expanded[mode]
        self._unknown_expanded[mode] = expanded
        holder = self.unknown_table_holders[mode]
        holder.grid_remove() if expanded else holder.grid()
        self.unknown_views[mode].grid_rowconfigure(0, weight=0 if expanded else 3)
        self.unknown_expand_buttons[mode].configure(text="返回列表 ↙" if expanded else "展开证据 ↗")

    def _show_unknown_mode(self, mode: str) -> None:
        self._unknown_mode = mode
        self.unknown_views[mode].tkraise()
        for key, button in self.unknown_mode_buttons.items():
            button.configure(background=ACCENT if key == mode else SURFACE, foreground="white" if key == mode else INK)
        self._update_unknown_summary()

    def show_page(self, name: str) -> None:
        self._view = name
        self.page_frames[name].tkraise()
        titles = {
            "overview": ("流量总览", "将实际接收、代理账本与工作负载放在同一时间轴上。"),
            "processes": ("进程实例", "查看进程身份与来源时间；保留归属判断的边界。"),
            "events": ("活动时间线", "只展示允许的活动元数据，不读取提示词或响应正文。"),
            "connections": ("连接证据", "逐连接归因依赖真实连接元数据；缺失时明确留白。"),
            "unknown": ("未识别流量", "按服务、出口与安全元数据拆分；同期活跃任务仍只是候选。"),
        }
        title, subtitle = titles[name]
        self.title_label.configure(text=title)
        self.subtitle_label.configure(text=subtitle)
        for key, button in self._nav_buttons.items():
            button.configure(background="#254753" if key == name else SIDEBAR,
                             foreground="#ffffff" if key == name else "#aec2ca")

    def _legend_changed(self) -> None:
        self.chart.visible = {key: var.get() for key, var in self._legend_vars.items()}
        self.chart.draw()

    def _select_run(self, _: tk.Event | None = None) -> None:
        self._run_id = self._run_labels.get(self.run_var.get())
        self._filter_changed()

    def _filter_changed(self, _: tk.Event | None = None) -> None:
        self._generation += 1
        self.refresh_now()

    def choose_directory(self) -> None:
        options = {"initialdir": str(self.directory)} if self.directory is not None else {}
        chosen = filedialog.askdirectory(parent=self.root, title="选择已有监测数据目录", **options)
        if not chosen:
            return
        candidate = Path(chosen)
        try:
            store = AuditStore(candidate)
        except (OSError, ValueError):
            self.notice.configure(text="无法打开该目录。请选择可读取的本地监测目录；远程目录不受支持。", foreground="#9b681c")
            return
        self.directory = candidate
        self.demo = False
        self.mihomo_db = None
        self.store = store
        self._generation += 1
        self._run_id = None
        self.run_var.set("最新运行段")
        self.directory_label.configure(text=str(self.directory))
        self.snapshot = {}
        self.refresh_now()

    def choose_ledger(self) -> None:
        if self.demo or _truth(self.snapshot.get("demo")) or _truth((self.snapshot.get("freshness") or {}).get("demo")):
            return
        if self.directory is None:
            self.notice.configure(text="请先选择已有监测数据目录，再选择与它对应的本地账本。", foreground="#9b681c")
            return
        chosen = filedialog.askopenfilename(parent=self.root, title="只读打开与当前监测对应的已有流量账本",
            filetypes=[("SQLite 流量账本", "*.db"), ("所有文件", "*.*")])
        if not chosen:
            return
        candidate = Path(chosen)
        try:
            store = AuditStore(self.directory, mihomo_db=candidate)
        except (OSError, ValueError):
            self.notice.configure(text="无法打开该账本。请选择可读取的本地数据库；原数据源未改变。", foreground="#9b681c")
            return
        self.mihomo_db, self.store = candidate, store
        self._generation += 1
        self._show_unknown_mode("ledger")
        self.refresh_now()

    def refresh_now(self) -> None:
        if self._closed or self._pending:
            return
        if self.store is None:
            self.status_badge.configure(text="选择数据目录", foreground=MUTED, background="#e8edef")
            self.notice.configure(text="点击“选择数据目录”打开已有的监测结果。界面不会自动启动采集器。", foreground=MUTED)
            return
        self._pending = True
        self._last_refresh = time.monotonic()
        self.refresh_button.configure(text="读取中…", state="disabled")
        generation, store = self._generation, self.store
        run_id = self._run_id
        minutes = WINDOWS[self.window_var.get()]

        def read() -> None:
            try:
                payload = store.snapshot(run_id=run_id, minutes=minutes)
                self._queue.put((generation, payload, None))
            except Exception as error:
                # Free-form exception text may contain a local file path or data.
                self._queue.put((generation, None, type(error).__name__))

        threading.Thread(target=read, name="audit-ui-reader", daemon=True).start()

    def _refresh_tick(self) -> None:
        if self._closed:
            return
        self.refresh_now()
        self._after_ids["refresh"] = self.root.after(5000, self._refresh_tick)

    def _drain_queue(self) -> None:
        if self._closed:
            return
        try:
            while True:
                generation, payload, error = self._queue.get_nowait()
                self._pending = False
                self.refresh_button.configure(text="刷新  ↻", state="normal")
                if generation != self._generation:
                    self.root.after(0, self.refresh_now)
                    continue
                if error:
                    self.status_badge.configure(text="读取受限", background="#fff0da", foreground="#9b681c")
                    self.notice.configure(text=f"暂时无法读取数据（{error}）。原数据未修改；请确认目录可读，稍后将自动重试。", foreground="#9b681c")
                    self.timestamp_label.configure(text="读取失败 · 保留最后成功显示")
                else:
                    self.apply_snapshot(payload)
        except queue.Empty:
            pass
        self._after_ids["queue"] = self.root.after(150, self._drain_queue)

    def apply_snapshot(self, payload: dict[str, Any]) -> None:
        self.snapshot = payload
        runs = payload.get("runs") or []
        labels: dict[str, str | None] = {"最新运行段": None}
        for run in runs:
            run_id = str(run.get("run_id") or "")
            label = f"{local_time(run.get('start_utc'), True)} · {run_id[:6]}"
            labels[label] = run_id
        self._run_labels = labels
        self.run_combo.configure(values=list(labels))
        if self._run_id is None:
            self.run_var.set("最新运行段")
        else:
            match = next((label for label, value in labels.items() if value == self._run_id), None)
            if match:
                self.run_var.set(match)
        freshness = payload.get("freshness") or {}
        source = payload.get("source_status") or {}
        if isinstance(source, str):
            source = {"monitor": source}
        is_demo = self.demo or _truth(payload.get("demo")) or _truth(freshness.get("demo"))
        is_stale = _truth(freshness.get("stale"))
        selected = payload.get("selected_run")
        monitor = str(source.get("monitor") or "unknown").lower()
        if is_demo:
            badge, color, background = "模拟数据", "#9b681c", "#fff0da"
            notice = "模拟数据演示：所有数字与实例均为虚构，不代表任何设备的实际流量。"
            self.directory_label.configure(text="内置模拟数据 · 未读取本机监测目录")
        elif not selected:
            badge, color, background = "等待数据", MUTED, "#e8edef"
            notice = "此目录尚无可展示的运行段。请选择已有监测输出目录；界面不会自动启动采集器。"
        elif is_stale:
            badge, color, background = "数据未更新", "#9b681c", "#fff0da"
            age = _number(freshness.get("age_seconds"))
            gap = f"约 {int(age // 60)} 分钟" if age is not None and age >= 60 else "一段时间"
            notice = f"最新记录已 {gap}未更新。这里显示最后一次留存数据，不代表进程当前仍在运行。"
        elif monitor == "stopped":
            badge, color, background = "采集已结束", MUTED, "#e8edef"
            notice = "正在查看已结束采集的记录。切换到“最新运行段”可查看更新的数据。"
        else:
            badge, color, background = "持续更新", ACCENT, "#e1efeb"
            notice = "只读显示已有采集结果。物理总量与代理账本口径不同；时间重合不等于因果归属。"
        partial = _truth(payload.get("totals_partial")) or (payload.get("window") or {}).get("complete") is False
        if partial:
            notice += "  当前范围有缺口，数字仅合计已验证区间。"
        self.status_badge.configure(text=badge, foreground=color, background=background)
        self.notice.configure(text=notice, foreground=color if is_demo or is_stale else MUTED)
        window = payload.get("window") or {}
        ending = window.get("end_utc") or payload.get("updated_utc")
        if not ending and runs:
            ending = next((r.get("last_utc") for r in runs if r.get("run_id") == selected), None)
        self.timestamp_label.configure(text=f"记录截至 {local_time(ending)} · 界面每 5 秒刷新")
        totals = payload.get("totals") or {}
        for key, label in self.metric_values.items():
            label.configure(text=format_bytes(totals.get(key)))
            self._fit_metric(label, label.master.winfo_width() - round(32 * self._ui_scale))
        self.metric_subtitles["physical_rx"].configure(text=f"已验证区间发送 {format_bytes(totals.get('physical_tx'))}" if partial else f"同期发送 {format_bytes(totals.get('physical_tx'))}")
        self.metric_subtitles["logical_down"].configure(text="已验证区间增量 · 覆盖不完整" if partial else "账本记录增量 · 非物理总量")
        self.metric_subtitles["codex_down"].configure(text="按进程名聚合 · 未分到 PID")
        self.metric_subtitles["unknown_down"].configure(text="下行 · 点击查看拆分 →")
        self.chart.set_data(payload.get("series") or [])
        start, end = window.get("start_utc"), window.get("end_utc")
        self.chart_range.configure(text=f"{local_time(start)} — {local_time(end)}" if end else "等待有效时间范围")
        connection_status = str(source.get("connections") or "unavailable")
        connection_rows = payload.get("connections") or []
        missing = not connection_rows
        self.coverage_label.configure(text=("范围有缺口 · 仅合计已验证区间\n" if partial else "")
                                      + f"{len(payload.get('series') or [])} 个速率采样点  ·  {len(payload.get('markers') or [])} 个复核标记\n"
                                      + ("连接级字节缺失，无法定位最大连接。" if missing else "已读取连接元数据；仍需保留归因边界。"))
        logical, unknown = _number(totals.get("logical_down")), _number(totals.get("unknown_down"))
        if logical and unknown is not None:
            message = f"未识别进程占逻辑下行约 {unknown / logical * 100:.1f}%。可查看服务与同期活动拆分；时间重合不证明流量归属。"
        else:
            message = "接收量说明发生了传输；实例同时存在并不证明它产生了这些字节。"
        self.insight_label.configure(text=message)
        self._render_processes()
        self._render_events()
        self._render_connections(connection_status)
        self.ledger_button.configure(state="disabled" if is_demo else "normal")
        self._render_unknown()

    @staticmethod
    def _unknown_service(value: Any) -> str:
        return {"chatgpt": "ChatGPT / Codex 服务", "chatgpt.com": "ChatGPT / Codex 服务",
                "chatgpt_exact": "ChatGPT 主域", "chatgpt_subdomain": "ChatGPT 子域",
                "openai": "OpenAI 服务", "google": "Google 服务", "google_drive": "Google Drive",
                "microsoft": "Microsoft 服务", "microsoft_update": "Microsoft 更新", "github": "GitHub 服务",
                "tencent": "腾讯服务", "other": "目标未细分", "other_domain": "其他域名 / 服务未细分",
                "ip_target": "IP 目标 / 服务未细分", "invalid_or_nonhost": "目标格式无法分类",
                "empty_target": "目标未记录",
                "unknown": "目标未细分", "missing": "目标未细分 / 明细缺失"}.get(str(value), _text(value))

    @staticmethod
    def _unknown_level(value: Any) -> str:
        return {"coobserved_only": "同期观察 · 未归属", "process_observation_missing": "缺少进程观察",
                "ledger_aggregate": "账本聚合 · 未归属", "missing_detail": "明细缺失"}.get(str(value), "尚未确认归属")

    @staticmethod
    def _unknown_alias(value: Any) -> str:
        text = _text(value)
        if text == "route_unavailable":
            return "出口未记录"
        for prefix, label in (("route_", "非DIRECT"), ("node_", "非DIRECT"), ("source_", "来源"), ("target_", "目标")):
            if text.startswith(prefix):
                return label + " #" + text[len(prefix):len(prefix) + 6]
        return text

    @staticmethod
    def _address_kind(value: Any) -> str:
        return {"ipv4": "IPv4", "ipv6": "IPv6", "empty": "未记录", "non_ip": "非 IP 字段",
                "domain": "域名", "not_applicable": "不适用", "unspecified": "未指定",
                "loopback": "回环", "private": "私有", "global": "公共", "link_local": "链路本地",
                "multicast": "多播", "reserved": "保留"}.get(str(value), _text(value))

    @staticmethod
    def _unknown_note(value: Any) -> str:
        return {
            "Independent complete-bucket ledger totals; never add to or apportion monitored delta totals.": "原账本完整桶是独立总量，不能与监测增量相加或按它分摊。",
            "Service labels identify public domain namespaces, not an application, payload type, PID or account.": "服务分类仅识别公共域名类别，不能证明应用、传输内容类型、PID 或账号。",
            "Retained bucket rows do not prove continuous capture or complete traffic coverage.": "留存统计桶不能证明连续采集或完整流量覆盖。",
            "Unknown remains Unknown; source and route aliases do not identify a workload.": "未识别身份保持未知；匿名来源与出口别名不能识别工作负载。",
            "Aliases are stable only for this adapter instance and are not persisted as an identity map.": "匿名别名仅在当前查看器的数据源实例中稳定，不跨启动跟踪身份。",
            "Closed time buckets can still receive late writes; results reflect a single read snapshot.": "已结束的桶仍可能收到延迟落库；这里只反映本次只读快照。",
            "not_read": "尚未读取原账本。", "invalid_range": "未获得有效的统计时间范围。",
            "no_complete_five_minute_bucket": "所选范围不足一个完整 5 分钟桶。",
            "synthetic_demo_ignores_external_database": "模拟演示不会连接真实账本。",
            "local_database_unavailable": "所选本地账本不存在或不可读。",
            "wal_sidecar_unavailable": "缺少安全只读所需的 WAL 辅助文件；未创建文件或干预数据库。",
            "database_read_unavailable": "账本当前无法安全只读查询；未修复或干预数据库。",
            "query_deadline_exceeded": "只读查询达到时间预算，已停止本次查询。",
            "query_key_limit": "查询分组过多，达到安全读取上限。", "no_retained_buckets": "此范围没有留存的完整统计桶。",
            "invalid_bucket_alignment": "统计桶时间没有对齐，未将其作为有效明细。",
            "invalid_byte_counters": "账本包含无效字节计数，未生成合计。",
        }.get(str(value), _text(value, 1200))

    def _update_unknown_summary(self) -> None:
        mode = self._unknown_mode
        block = self.snapshot.get("unknown_breakdown" if mode == "monitor" else "unknown_ledger_details") or {}
        down = block.get("total_down")
        if mode == "monitor" and not block:
            down = (self.snapshot.get("totals") or {}).get("unknown_down")
        self.unknown_metrics["down"].configure(text=format_bytes(down))
        self.unknown_metrics["up"].configure(text=format_bytes(block.get("total_up")))
        group_count = len(self._unknown_rows.get(mode) or {})
        self.unknown_metrics["rows"].configure(text=str(group_count) if block.get("status") not in (None, "not_configured", "unavailable", "insufficient_range") else "—")
        if mode == "monitor":
            window = self.snapshot.get("window") or {}
            scope = f"监测增量  {local_time(window.get('start_utc'), True)} — {local_time(window.get('end_utc'), True)}"
            coverage = block.get("coverage") or {}
            scope += f"  ·  可匹配明细 {_text(coverage.get('matched_samples'))} / {_text(coverage.get('summary_samples'))} 个采样区间"
            if coverage.get("complete") is False:
                scope += "  ·  明细覆盖不完整"
            if not block:
                scope += "\n现有记录没有可用拆分。未识别进程流量不等于异常流量，也不能直接归给同期任务。"
            else:
                scope += "\n仅合计已验证监测增量；活动与流量同窗出现，不代表属于该任务。明细缺额单列，不推测服务。"
        else:
            status = block.get("status")
            if status in (None, "not_configured"):
                scope = "原账本尚未启用。选择已有本地账本后，可只读查看完整 5 分钟桶的服务与匿名来源。"
                if self.demo or _truth(self.snapshot.get("demo")):
                    scope = "模拟演示未连接真实账本。此处未启用，不代表未识别流量为零。"
            else:
                coverage = block.get("actual_coverage") or {}
                scope = f"原账本完整桶  {local_time(block.get('start_utc'), True)} — {local_time(block.get('end_utc'), True)}"
                scope += f"  ·  已保留 {_text(coverage.get('bucket_count'))} / {_text(coverage.get('expected_bucket_count'))} 个 5 分钟桶"
                if coverage.get("complete_range") is False:
                    scope += "  ·  桶覆盖有缺口"
                if status != "ok":
                    scope += "  ·  该范围暂无可用明细"
            scope += "\n这是独立完整桶总量，不能细分、替代或叠加另一视角的监测增量。"
        self.unknown_scope.configure(text=scope)

    def _render_unknown(self) -> None:
        breakdown = self.snapshot.get("unknown_breakdown") or {}
        groups = [dict(row) for row in (breakdown.get("groups") or []) if isinstance(row, dict)]
        residual_down, residual_up = _number(breakdown.get("residual_down")), _number(breakdown.get("residual_up"))
        if (residual_down or 0) > 0 or (residual_up or 0) > 0:
            total = _number(breakdown.get("total_down"))
            groups.append({"group_id": "__missing_detail__", "service_category": "missing", "route_alias": "出口未细分",
                           "workload_label": "活动关联明细缺失", "download_bytes": residual_down, "upload_bytes": residual_up,
                           "download_share": residual_down / total if total and residual_down is not None else None,
                           "evidence_level": "missing_detail", "candidates": [],
                           "evidence": ["来自有效监测汇总与可匹配明细之间的差额，未伪造服务、连接或 PID。"],
                           "limitations": ["缺少能够与该增量一一匹配的明细，不能分配到目标服务或工作负载。"]})
        ledger = self.snapshot.get("unknown_ledger_details") or {}
        for mode, rows in (("monitor", groups), ("ledger", ledger.get("rows") or [])):
            tree = self.unknown_trees[mode]
            selection = tree.selection()
            old = self._unknown_rows[mode].get(selection[0]) if selection else None
            old_identity = old.get("_ui_identity") if old else None
            tree.delete(*tree.get_children())
            self._unknown_rows[mode] = {}
            preferred = None
            for index, source_row in enumerate(rows):
                if not isinstance(source_row, dict):
                    continue
                row = dict(source_row)
                service = self._unknown_service(row.get("service_category"))
                route = self._unknown_alias(row.get("route_alias"))
                if mode == "monitor":
                    activity = _text(row.get("workload_label"))
                    activity = activity.replace("仅新鲜观测到 Desktop（非独占归属）", "Desktop")
                    context = activity + " · 候选" if row.get("candidates") else activity
                    share = _number(row.get("download_share"))
                    confidence = self._unknown_level(row.get("evidence_level"))
                    identity = str(row.get("group_id") or index)
                else:
                    target = _text(row.get("target_alias"))
                    if target != "—" and not target.startswith("service_") and target not in service:
                        service += " · " + self._unknown_alias(target)
                    context = self._unknown_alias(row.get("source_alias"))
                    total, amount = _number(ledger.get("total_down")), _number(row.get("download_bytes"))
                    share = amount / total if total and amount is not None else None
                    confidence = self._unknown_level("ledger_aggregate")
                    identity = "|".join(str(row.get(key) or "") for key in ("service_category", "target_alias", "source_alias", "route_alias"))
                row["_ui_identity"] = identity
                item = tree.insert("", "end", values=(service, route, context, format_bytes(row.get("download_bytes")),
                    format_bytes(row.get("upload_bytes")), f"{share * 100:.1f}%" if share is not None else "—", confidence),
                    tags=("warning",) if row.get("evidence_level") == "missing_detail" else (("alternate",) if index % 2 else ()))
                self._unknown_rows[mode][item] = row
                if identity == old_identity:
                    preferred = item
            children = tree.get_children()
            if children:
                tree.selection_set(preferred or children[0])
                self._show_unknown_evidence(mode)
            else:
                limitation = "\n".join(self._unknown_note(item) for item in (breakdown if mode == "monitor" else ledger).get("limitations", [])[:12])
                reason = self._unknown_note((breakdown if mode == "monitor" else ledger).get("reason"))
                text = "当前没有可展示的拆分行。没有明细不等于没有流量。\n"
                if mode == "ledger":
                    text += "需要已保留且完整的 5 分钟桶；未选择账本或范围不足时保留未知值。\n"
                if reason != "—":
                    text += "来源状态：" + reason + "\n"
                self._set_unknown_evidence(mode, text + limitation)
        self._update_unknown_summary()

    def _show_unknown_evidence(self, mode: str) -> None:
        selected = self.unknown_trees[mode].selection()
        row = self._unknown_rows[mode].get(selected[0]) if selected else None
        if not row:
            return
        block = self.snapshot.get("unknown_breakdown" if mode == "monitor" else "unknown_ledger_details") or {}
        lines = []
        target_reason = {"other": "已有记录未提供进一步可验证的目标服务分类。",
            "other_domain": "目标未匹配已识别服务类别；不反推匿名目标。",
            "ip_target": "仅有 IP 类目标，未进行外网查询或反向解析。",
            "invalid_or_nonhost": "记录中的目标不是可分类的有效主机字段。",
            "empty_target": "已有记录的目标字段为空。", "unknown": "已有记录未提供可验证的目标分类。",
            "missing": "汇总增量没有可匹配明细，无法知道其目标、出口或同期进程。"}.get(str(row.get("service_category")))
        if target_reason:
            lines.append("目标未细分原因：" + target_reason)
        if mode == "monitor":
            lines.append("归因边界：仅在同一观察区间出现；候选 PID / 任务不是已确认的字节来源。")
            lines.append(f"所选分组：{self._unknown_service(row.get('service_category'))}；出口 {_text(row.get('route_alias'))}；同期组合 {_text(row.get('workload_label'))}。")
            lines.append(f"统计覆盖：{local_time(row.get('first_utc'), True)} — {local_time(row.get('last_utc'), True)}；匹配区间 {_text(row.get('sample_count'))} 个。")
            candidates = row.get("candidates") or []
            if not candidates:
                lines.append("候选 PID：没有可匹配的安全进程元数据，保持未知。")
            for candidate in candidates[:30]:
                if not isinstance(candidate, dict):
                    continue
                lines.append(f"同期候选：{workload_name(candidate.get('workload'))} · PID {_text(candidate.get('pid'))} / 父 PID {_text(candidate.get('parent_pid'))} · {_text(candidate.get('platform'))} · 程序类别 {_text(candidate.get('exe_category'))}")
                lines.append(f"  进程取样 {local_time(candidate.get('source_observed_utc'), True)}；启动 {local_time(candidate.get('start_utc'), True)}；类别依据 {_text(candidate.get('confidence'))}（不是流量归属置信度）。")
            if len(candidates) > 30:
                lines.append(f"共 {len(candidates)} 个同期候选，界面展示前 30 个；未将字节分配给它们。")
            for evidence in (row.get("evidence") or [])[:16]:
                lines.append("安全证据：" + _text(evidence, 1200))
            lines.append("为何未确认：历史明细不含可核验的连接到 PID 字节映射，时间重合本身不足以确认产生流量的实例。")
        else:
            coverage = block.get("actual_coverage") or {}
            lines.append("证据类型：原账本中未识别进程的完整 5 分钟桶聚合；此处不关联或分摊给同期任务。")
            lines.append(f"服务：{self._unknown_service(row.get('service_category'))}；目标类别 {_text(row.get('target_kind'))} / 别名 {_text(row.get('target_alias'))}；匿名来源 {_text(row.get('source_alias'))}；出口 {_text(row.get('route_alias'))}。")
            lines.append(f"来源类型 {self._address_kind(row.get('source_kind'))}；来源地址范围 {self._address_kind(row.get('source_scope'))}；目标地址范围 {self._address_kind(row.get('target_scope'))}。这些类别不等于 WSL、TUN 或某个 PID。")
            lines.append("完整匿名标识见上行；短标签仅用于阅读。两个视角的匿名标识独立，不能据此认定是同一来源或节点。")
            lines.append(f"完整桶请求范围：{local_time(block.get('start_utc'), True)} — {local_time(block.get('end_utc'), True)}（结束不包含）。")
            lines.append(f"实际留存：{local_time(coverage.get('start_utc'), True)} — {local_time(coverage.get('end_utc'), True)}；本组 {_text(row.get('bucket_count'))} 个桶；全范围 {_text(coverage.get('bucket_count'))} / {_text(coverage.get('expected_bucket_count'))} 个桶。")
            lines.append("为何未确认：匿名来源标识不是 PID，目标服务与出口也不能证明哪个任务产生了流量。该表总量不能与监测增量相加。")
            if _truth(block.get("cached")):
                age = _number(block.get("cache_age_seconds"))
                lines.append("查询缓存：" + (f"{age:.0f} 秒前读取。" if age is not None else "非本次即时读取。"))
        for limitation in [*(row.get("limitations") or []), *(block.get("limitations") or [])][:20]:
            lines.append("限制：" + self._unknown_note(limitation))
        self._set_unknown_evidence(mode, "\n".join(lines))

    def _render_processes(self) -> None:
        rows = self.snapshot.get("processes") or []
        native = [r for r in rows if str(r.get("name", "")).lower() in ("codex", "codex.exe")]
        shown = native if self.engines_only.get() else rows
        self.process_summary.configure(text=f"{len(native)} 个 Codex 引擎 · {len(rows)} 条相关进程记录 · 均为最近留存快照")
        self.process_tree.delete(*self.process_tree.get_children())
        for index, row in enumerate(shown):
            cached = _truth(row.get("is_cached"))
            age = _number(row.get("cache_age_seconds"))
            fresh = f"缓存 {age:.0f}s" if cached and age is not None else "缓存" if cached else local_time(row.get("source_observed_utc") or row.get("observed_utc"))
            confidence = _text(row.get("confidence"))
            if confidence.startswith("high"):
                confidence = "高 · 路径 / 祖先"
            elif confidence.startswith("medium"):
                confidence = "中 · 有限身份依据"
            elif confidence in ("unclassified", "unknown", "—"):
                confidence = "未知"
            self.process_tree.insert("", "end", values=(workload_name(row.get("workload")),
                f"{_text(row.get('pid'))} / {_text(row.get('parent_pid'))}", _text(row.get("platform")),
                local_time(row.get("start_utc"), True), _text(row.get("exe_category")), fresh, confidence),
                tags=("muted",) if cached else (("alternate",) if index % 2 else ()))

    def _render_events(self) -> None:
        rows = self.snapshot.get("events") or []
        if self.event_filter.get() == "重要事件":
            rows = [r for r in rows if r.get("event_type") not in ("codex_module_log_activity", "activity_source_state")]
        rows = sorted(rows, key=lambda r: str(r.get("event_utc") or r.get("observed_utc") or ""), reverse=True)[:500]
        self.event_summary.configure(text=f"{len(rows)} 条显示记录 · 只含允许的事件与状态元数据")
        selection = self.event_tree.selection()
        old_key = self._event_rows.get(selection[0], {}).get("evidence") if selection else None
        self.event_tree.delete(*self.event_tree.get_children())
        self._event_rows = {}
        for index, row in enumerate(rows):
            values = (local_time(row.get("event_utc") or row.get("observed_utc"), True),
                      workload_name(row.get("workload") or row.get("platform")), _text(row.get("event_type")),
                      _text(row.get("status")), _text(row.get("count", 1)))
            tag = "warning" if any(k in str(row.get("event_type", "")).lower() for k in ("failed", "error", "retry", "reconnect")) else ("alternate" if index % 2 else "")
            item = self.event_tree.insert("", "end", values=values, tags=(tag,) if tag else ())
            self._event_rows[item] = row
            if old_key and row.get("evidence") == old_key:
                self.event_tree.selection_set(item)

    def _show_event_evidence(self, _: tk.Event | None = None) -> None:
        selected = self.event_tree.selection()
        row = self._event_rows.get(selected[0]) if selected else None
        if not row:
            return
        self.event_evidence.configure(text=_text(row.get("evidence"), 700) + "\n" + _text(row.get("context_safe") or row.get("confidence"), 600))

    def _render_connections(self, status: str) -> None:
        rows = self.snapshot.get("connections") or []
        self.connection_tree.delete(*self.connection_tree.get_children())
        if not rows:
            self.connection_title.configure(text="连接级证据暂缺")
            if "LOOPBACK" in status:
                detail = "尚无可核验的回环控制数据源。现有账本不能定位最大连接；界面不会开启新接口或访问其它通道。"
            elif "AUTH" in status:
                detail = "连接数据源尚未获准使用。这里保留缺口，现有账本不能把流量分配到单条连接。"
            else:
                detail = "当前没有可用的逐连接记录。没有记录不等于没有连接；这里不会用历史统计桶代造连接。"
            self.connection_note.configure(text=detail)
            return
        self.connection_title.configure(text=f"已读取 {len(rows)} 条连接元数据")
        self.connection_note.configure(text="这里展示原采集器已保存的连接数据。连接重建不证明重复下载；目标域名也不证明响应内容类型。")
        for index, row in enumerate(rows[:500]):
            self.connection_tree.insert("", "end", values=(_text(row.get("connection_id"), 20),
                f"{_text(row.get('process_class') or row.get('process_name'))} / {_text(row.get('pid'))}",
                _text(row.get("target_domain") or row.get("target_category")), format_bytes(row.get("download_total")),
                format_bytes(row.get("download_delta")), format_bytes(row.get("upload_total")),
                local_time(row.get("started_utc"), True)), tags=("alternate",) if index % 2 else ())

    @staticmethod
    def _sort_tree(tree: ttk.Treeview, column: str) -> None:
        values = [(tree.set(item, column), item) for item in tree.get_children("")]
        reverse = getattr(tree, "_sort_column", None) == column and not getattr(tree, "_sort_reverse", False)
        values.sort(key=lambda item: item[0].casefold(), reverse=reverse)
        for index, (_, item) in enumerate(values):
            tree.move(item, "", index)
        tree._sort_column = column  # type: ignore[attr-defined]
        tree._sort_reverse = reverse  # type: ignore[attr-defined]

    def close(self) -> None:
        self._closed = True
        for after_id in self._after_ids.values():
            try:
                self.root.after_cancel(after_id)
            except tk.TclError:
                pass
        self.root.destroy()


def launch(directory: Path | None = None, *, demo: bool = False,
           mihomo_db: Path | None = None, view: str = "overview") -> None:
    # Process-local display scaling only; it does not change any system setting.
    try:
        import ctypes
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    app = ObserverApp(root, directory, demo=demo, mihomo_db=mihomo_db)
    app.show_page(view if view in app.page_frames else "overview")
    root.mainloop()
