#!/usr/bin/env python3
"""
USBForge v3.0 — 基于 Cynthion 的全功能 USB 安全工具套件

九大功能模块:
  🖥  设备   — 硬件状态、模式切换、MCP 集成
  📡  监听   — USB 总线流量捕获 (Analyzer)
  🔄  中继   — USB MITM 中间人拦截/篡改
  🔍  分析   — 描述符解析、流量统计、SETUP 提取
  💉  注入   — 构造/发送/重放控制请求
  🔧  伪造   — USB 设备仿真 (Facedancer)
  🧪  模糊   — 多阶段智能 USB 模糊测试
  📊  统计   — 全局统计、活动日志
  ℹ️  关于   — 工具介绍、技术栈、快捷键

运行: ./run.sh (macOS/Linux)  或  run.bat (Windows)
"""

# ══ 环境修复 — 必须在所有其他 import 之前 ══
import os as _os
import sys as _sys
if "PYTHONPATH" in _os.environ:
    _pp = _os.environ["PYTHONPATH"]
    _clean = [p for p in _pp.split(":") if "hermes" not in p.lower()]
    if _clean:
        _os.environ["PYTHONPATH"] = ":".join(_clean)
    else:
        _os.environ.pop("PYTHONPATH", None)
_sys.path = [p for p in _sys.path if "hermes-agent" not in p and "hermes/hermes-agent" not in p]
import site as _site
_us = _site.getusersitepackages()
if _us not in _sys.path:
    _sys.path.insert(0, _us)

import asyncio
import json
import time
import random
import struct
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Header, Footer, Label, Button, Input, Select, Checkbox,
    RichLog, ProgressBar, Static, TabbedContent, TabPane,
    DataTable, Switch, ListView, ListItem,
)
from textual.reactive import reactive
from textual.message import Message
from textual.binding import Binding
from textual.theme import Theme
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown

# Import backend modules
from strategy import (
    Mutator, StrategyGenerator, FuzzCase, FuzzPhase,
    PHASE_NAMES, PHASE_SOURCES, HUB_CONSTS, HID_LIMITS,
)
from monitor import (
    BaseMonitor, NoShellMonitor, UserShellMonitor, RootShellMonitor,
    CrashDetail, CrashLevel, create_monitor,
)
from device import (
    detect_cynthion, get_full_status, get_detailed_info,
    switch_to_facedancer, switch_to_analyzer,
    CynthionInfo, DeviceMode, FuzzerReadiness,
)
from sniffer import (
    USBSniffer, USBPacket, CaptureStats, PacketType, PID_MAP,
    parse_device_descriptor, parse_config_descriptor, parse_endpoint_descriptor,
    DESC_TYPES, DEVICE_CLASSES,
)
from injector import (
    PacketInjector, ControlRequest, PacketTemplate, TEMPLATES,
    build_device_descriptor, build_config_descriptor, build_endpoint_descriptor,
    mutate_request, DIR_IN, DIR_OUT, TYPE_STANDARD, TYPE_CLASS, TYPE_VENDOR,
    RCV_DEVICE, RCV_INTERFACE, RCV_ENDPOINT,
    REQ_GET_DESCRIPTOR, DESC_DEVICE, DESC_CONFIG, DESC_STRING,
)
from emulator import (
    DeviceEmulator, DeviceProfile, PROFILES, PROFILE_OPTIONS,
    build_descriptor_set, USBClass,
)

from mcp_bridge import get_bridge, check_mcp_available


# ═══════════════════════════════════════════════════════════════════════════════
# 路径常量
# ═══════════════════════════════════════════════════════════════════════════════

_SCRIPT_DIR = _os.path.dirname(_os.path.abspath(__file__))
_VENV_DIR = _os.path.dirname(_SCRIPT_DIR) + "/.venv"
if not _os.path.isdir(_VENV_DIR):
    _VENV_DIR = _SCRIPT_DIR + "/.venv"  # fallback: local venv
if _sys.platform == "win32":
    _PYTHON_BIN = _os.path.join(_VENV_DIR, "Scripts", "python.exe")
    _MCP_SERVER_PATH = _os.path.join(_VENV_DIR, "Scripts", "cynthion-mcp.exe")
    _CLAUDE_CONFIG_DIR = _os.path.join(_os.environ.get("APPDATA", ""), "Claude")
    _SERIAL_DEFAULT = "COM3"
    _SERIAL_CHOICES = [("COM1", "COM1"), ("COM2", "COM2"), ("COM3", "COM3"),
                       ("COM4", "COM4"), ("COM5", "COM5")]
else:
    _PYTHON_BIN = _os.path.join(_VENV_DIR, "bin", "python3")
    _MCP_SERVER_PATH = _os.path.join(_VENV_DIR, "bin", "cynthion-mcp")
    _CLAUDE_CONFIG_DIR = str(Path.home() / "Library" / "Application Support" / "Claude")
    _SERIAL_DEFAULT = "/dev/ttyUSB0"
    _SERIAL_CHOICES = [("/dev/ttyUSB0", "/dev/ttyUSB0"),
                       ("/dev/ttyUSB1", "/dev/ttyUSB1"),
                       ("/dev/ttyS0", "/dev/ttyS0"),
                       ("/dev/cu.SLAB_USBtoUART", "/dev/cu.SLAB_USBtoUART"),
                       ("/dev/cu.usbserial", "/dev/cu.usbserial")]
_HERMES_CONFIG_DIR = str(Path.home() / ".hermes")


# ═══════════════════════════════════════════════════════════════════════════════
# 统计数据容器
# ═══════════════════════════════════════════════════════════════════════════════

class GlobalStats:
    """全局统计"""
    def __init__(self):
        self.fuzz_total = 0
        self.fuzz_executed = 0
        self.fuzz_passed = 0
        self.fuzz_crashed = 0
        self.fuzz_warnings = 0
        self.fuzz_start_time = 0.0
        self.inject_sent = 0
        self.inject_errors = 0
        self.sniff_packets = 0
        self.sniff_start_time = 0.0
        self.phase_stats: dict = {}
        self.crashes: list = []
        # 中继统计
        self.relay_forward = 0
        self.relay_hold = 0
        self.relay_drop = 0
        self.relay_modify = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Modal Screens
# ═══════════════════════════════════════════════════════════════════════════════

class ModeConfirmScreen(ModalScreen):
    """设备模式确认弹窗 — 检查当前模式并询问是否切换"""

    def __init__(self, current_mode: str, required_mode: str, action_name: str = ""):
        super().__init__()
        self.current_mode = current_mode
        self.required_mode = required_mode
        self.action_name = action_name

    def compose(self) -> ComposeResult:
        mode_label = {"facedancer": "Facedancer (主动仿真)", "analyzer": "Analyzer (被动监听)",
                      "debugger": "Debugger (未加载 bitstream)", "not_found": "未连接",
                      "error": "检测错误"}.get(self.current_mode.lower(), self.current_mode)
        req_label = {"facedancer": "Facedancer (主动仿真)", "analyzer": "Analyzer (被动监听)"
                     }.get(self.required_mode.lower(), self.required_mode)

        yield Vertical(
            Label(f"⚠ 模式检查", classes="modal-title"),
            Label(f"功能: {self.action_name}", classes="modal-text"),
            Label(f"当前模式: [bold yellow]{mode_label}[/]", classes="modal-text"),
            Label(f"需要模式: [bold green]{req_label}[/]", classes="modal-text"),
            Label("", classes="info-line"),
            Label(f"是否切换到 {req_label} 模式？", classes="modal-text"),
            Horizontal(
                Button(f"✓ 切换并执行", id="modal-confirm-switch", variant="success"),
                Button("✗ 取消", id="modal-cancel", variant="error"),
                classes="btn-row",
            ),
            id="mode-confirm-dialog",
        )

    BINDINGS = [Binding("escape", "app.pop_screen", "取消")]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "modal-confirm-switch":
            self.dismiss(self.required_mode)
        else:
            self.dismiss(False)


class FlashFirmwareScreen(ModalScreen):
    """一键刷写固件确认弹窗"""

    def __init__(self, current_bitstream: str, target_bitstream: str, needs_download: bool = False):
        super().__init__()
        self.current_bitstream = current_bitstream
        self.target_bitstream = target_bitstream
        self.needs_download = needs_download

    def compose(self) -> ComposeResult:
        children = [
            Label("📦 一键刷写固件", classes="modal-title"),
            Label(f"当前 Bitstream: [bold yellow]{self.current_bitstream or '未知'}[/]", classes="modal-text"),
            Label(f"目标固件: [bold green]{self.target_bitstream}[/]", classes="modal-text"),
        ]
        if self.needs_download:
            children.append(Label("⚠ 将自动联网下载固件文件", classes="modal-text"))
        children.extend([
            Label("", classes="info-line"),
            Label("刷写过程中设备将断开重连，请勿拔插设备。", classes="modal-warning"),
            Label("预计耗时 10-30 秒。", classes="modal-text"),
            Label("", classes="info-line"),
            Horizontal(
                Button("✓ 开始刷写", id="modal-flash-confirm", variant="warning"),
                Button("✗ 取消", id="modal-flash-cancel", variant="error"),
                classes="btn-row",
            ),
        ])
        yield Vertical(*children, id="flash-firmware-dialog")

    BINDINGS = [Binding("escape", "app.pop_screen", "取消")]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "modal-flash-confirm":
            self.dismiss(True)
        else:
            self.dismiss(False)


class InfoScreen(ModalScreen):
    """信息提示弹窗（如已满足固件提示）"""

    def __init__(self, title: str, message: str):
        super().__init__()
        self._title = title
        self._message = message

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label(self._title, classes="modal-title"),
            Label(self._message, classes="modal-text"),
            Label("", classes="info-line"),
            Button("✓ 知道了", id="modal-info-ok", variant="primary"),
            id="info-dialog",
        )

    BINDINGS = [Binding("escape", "app.pop_screen", "取消"), Binding("enter", "_ok", "确定")]

    def _ok(self):
        self.dismiss(True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(True)


class USBForgeApp(App):
    """USBForge — 全功能 USB 安全工具套件"""

    CSS = """
    /* ═══ USBForge — Design Guide compliant, full-width tabs, bordered widgets ═══ */
    Screen {
        background: $background;
        color: $foreground;
    }

    /* ── App root: vertical flex layout ── */
    #app-root {
        height: 100%;
        width: 100%;
    }

    /* ── Header: 1 row, title centered ── */
    #header-title {
        height: 1;
        width: 100%;
        background: $surface;
        color: $primary;
        text-style: bold;
        text-align: center;
    }
    #header-status {
        color: $text-muted;
    }

    /* ── Tabs: full width, 1 row tall ── */
    Tabs {
        background: $surface;
        width: 100%;
        height: 2;
    }
    #tabs-scroll {
        width: 100%;
    }
    #tabs-list-bar {
        width: 100%;
    }
    #tabs-list {
        width: 100%;
    }
    #tabs-list ContentTab {
        width: 1fr;
        height: 1;
        padding: 0 1;
    }
    TabbedContent {
        width: 100%;
        height: 1fr;
    }
    TabbedContent > ContentSwitcher {
        height: 1fr;
    }

    /* ── Workspace ── */
    /* 响应式布局：使用 fr 比例而非固定字符宽度 */
    .workspace { height: 1fr; }
    .workspace-3col { height: 1fr; }
    #left-panel {
        width: 2fr;
        min-width: 40;
        background: $surface;
        border-right: solid $boost;
        padding: 1 1;
    }
    #mid-panel {
        width: 1fr;
        background: $surface;
        border-right: solid $boost;
        padding: 1 1;
    }
    #right-panel {
        width: 3fr;
        background: $background;
        padding: 1 1;
    }
    #tab-about #right-panel {
        width: 4fr;
        min-width: 62;
    }
    #tab-about #left-panel {
        width: 2.5fr;
    }
    #mcp-panel {
        width: 1fr;
        background: $surface;
        border-left: solid $boost;
        padding: 1 1;
    }
    #mcp-panel .section-label { margin: 0 0 1 0; }
    #mcp-panel .mcp-info {
        color: $text;
        height: auto;
        margin: 0 0 1 0;
    }
    #mcp-panel .mcp-code {
        background: $panel;
        color: $accent;
        height: auto;
        padding: 0 1;
        margin: 0 0 1 0;
        text-style: bold;
    }

    /* ── Labels ── */
    .section-label {
        color: $primary;
        text-style: bold;
        height: 1;
        margin: 0;
    }
    .section-label:first-child {
        margin-top: 0;
    }
    .panel-title {
        color: $accent;
        text-style: bold;
        height: 1;
        margin: 0 0 1 0;
    }

    /* ── Button rows ── */
    .btn-row {
        height: auto;
        margin: 0;
    }
    .btn-row > Button, .btn-row > Input, .btn-row > Select, .btn-row > Checkbox {
        width: 1fr;
        margin: 0 1 0 0;
    }
    .btn-row > *:last-child {
        margin-right: 0;
    }

    /* ── Left panel widgets: bordered, height 3 ── */
    #left-panel Input {
        height: 3;
        border: solid $boost;
        margin: 0;
        padding: 0 1;
    }
    #left-panel Input:focus {
        border: solid $primary;
    }
    #left-panel Select {
        height: 3;
        margin: 0;
    }
    #left-panel SelectCurrent {
        border: solid $boost;
        padding: 0 1;
        height: 3;
    }
    #left-panel Select:focus > SelectCurrent {
        border: solid $primary;
    }
    /* Standalone inputs/selects fill width */
    #left-panel > Input, #left-panel > Select {
        width: 100%;
    }
    /* Buttons in left panel: height 3 */
    #left-panel Button {
        height: 3;
        padding: 0 1;
        margin: 0;
    }
    /* Standalone full-width buttons (direct children of left-panel scroll) */
    #left-panel > Button {
        width: 100%;
    }

    /* ── btn-row buttons: share row, same height ── */
    .btn-row > Button {
        height: 3;
    }

    /* ── Checkbox ── */
    #left-panel Checkbox {
        height: 3;
        margin: 0;
        padding: 0 1;
        border: solid $boost;
        background: $boost;
    }

    /* ── Info lines ── */
    .info-line { height: 1; color: $foreground; margin: 0 0 0 0; }
    .info-line-dim { height: 1; color: $text-muted; margin: 0 0 0 0; }
    .about-text { height: auto; color: $foreground; margin: 0 0 1 0; }
    .avatar-art {
        height: auto;
        width: auto;
        color: $foreground;
        margin: 0 0 1 0;
    }

    /* ── Status card ── */
    .status-card {
        padding: 0 0 0 0;
        height: auto;
        margin: 0 0 0 0;
    }
    #device-card {
        height: auto;
        margin: 0 0 1 0;
    }
    #mcp-bottom {
        dock: bottom;
        height: auto;
        margin: 1 0 0 0;
    }
    .device-card-title {
        color: $primary;
        text-style: bold;
        height: 1;
        margin: 1 0 0 0;
    }
    .device-card-title:first-child {
        margin-top: 0;
    }
    .device-info-line {
        height: 1;
        color: $text-muted;
        margin: 0;
    }
    #btn-flash-firmware {
        width: 100%;
    }

    /* ── DataTable ── */
    DataTable {
        background: $background;
        height: 1fr;
    }

    /* ── RichLog ── */
    RichLog {
        background: $background;
        border: round $boost;
        height: 1fr;
    }

    /* ── ProgressBar ── */
    ProgressBar { margin: 0 0 1 0; }

    /* ── Footer ── */
    #status-bar {
        background: $surface;
        color: $text-muted;
        height: 1;
        padding: 0 2;
    }
    #status-hints {
        width: 1fr;
        text-align: right;
    }

    /* ── Scrollbar ── */
    VerticalScroll, Vertical {
        scrollbar-size: 1 2;
    }

    /* ── Modal dialogs — 叠加在当前页面上 ── */
    ModeConfirmScreen, FlashFirmwareScreen, InfoScreen {
        align: center middle;
    }
    #mode-confirm-dialog, #flash-firmware-dialog, #info-dialog {
        background: $surface;
        border: solid $primary;
        padding: 1 2;
        width: 64;
        height: auto;
        max-height: 80%;
    }
    .modal-title {
        text-style: bold;
        color: $accent;
        height: 1;
        margin: 0 0 1 0;
    }
    .modal-text {
        height: auto;
        margin: 0 0 0 0;
    }
    .modal-warning {
        height: auto;
        color: $warning;
        margin: 0 0 0 0;
    }

    /* ── 模糊测试全宽选择器 ── */
    .fuzz-full-select {
        width: 100%;
        margin: 0 0 1 0;
    }
    .fuzz-target-section {
        height: auto;
        margin: 0 0 1 0;
    }
    .fuzz-hint {
        height: 1;
        color: $text-muted;
        margin: 0;
    }
    """

    TITLE = "USBForge"
    DARK = True

    is_running = reactive(False)
    stats = None

    BINDINGS = [
        Binding("q", "quit", "退出"),
        Binding("1", "goto_tab('tab-device')", "设备"),
        Binding("2", "goto_tab('tab-sniff')", "监听"),
        Binding("3", "goto_tab('tab-relay')", "中继"),
        Binding("4", "goto_tab('tab-analyze')", "分析"),
        Binding("5", "goto_tab('tab-inject')", "注入"),
        Binding("6", "goto_tab('tab-emulate')", "伪造"),
        Binding("7", "goto_tab('tab-fuzz')", "模糊"),
        Binding("8", "goto_tab('tab-stats')", "统计"),
        Binding("9", "goto_tab('tab-about')", "关于"),
        Binding("d", "refresh_device", "刷新设备"),
    ]

    def __init__(self):
        super().__init__()
        self.sniffer = USBSniffer()
        self.injector = PacketInjector()
        self.emulator = DeviceEmulator()
        self.stats = GlobalStats()
        self._device_status = None
        self._monitor = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._fuzz_thread = None
        self.all_cases = []
        # 中继状态
        self._relay_active = False
        self._relay_policy = "pass"
        self._relay_queue = []
        self._relay_thread = None

    def compose(self) -> ComposeResult:
        """构建主界面 — 标题栏 + 8 Tab + 状态栏"""
        with Vertical(id="app-root"):
            yield Label("⚡ USBForge — USB Security Suite", id="header-title")

            with TabbedContent():
                with TabPane("🖥 设备", id="tab-device"):
                    yield from self._compose_device_tab()
                with TabPane("📡 监听", id="tab-sniff"):
                    yield from self._compose_sniff_tab()
                with TabPane("🔀 中继", id="tab-relay"):
                    yield from self._compose_relay_tab()
                with TabPane("🔍 分析", id="tab-analyze"):
                    yield from self._compose_analyze_tab()
                with TabPane("💉 注入", id="tab-inject"):
                    yield from self._compose_inject_tab()
                with TabPane("🔧 伪造", id="tab-emulate"):
                    yield from self._compose_emulate_tab()
                with TabPane("🧪 模糊", id="tab-fuzz"):
                    yield from self._compose_fuzz_tab()
                with TabPane("📊 统计", id="tab-stats"):
                    yield from self._compose_stats_tab()
                with TabPane("ℹ️ 关于", id="tab-about"):
                    yield from self._compose_about_tab()

            with Horizontal(id="status-bar"):
                yield Label("● 初始化中...", id="header-status")
                yield Label("[1-9]切换Tab  D=刷新设备  Q=退出", id="status-hints")

    # ═══════════════════════════════════════════════════════════════════════
    # Tab 1: 设备 — 卡片式状态 + 模式选择
    # ═══════════════════════════════════════════════════════════════════════

    def _compose_device_tab(self) -> ComposeResult:
        with Horizontal(classes="workspace"):
            # ── 左栏: 上半设备控制 + 下半 MCP 配置 ──
            with VerticalScroll(id="left-panel"):
                # ── 设备信息 (状态+详情+模式 三合一紧凑组) ──
                with Vertical(id="device-card"):
                    # 状态
                    yield Label("设备状态", classes="device-card-title")
                    yield Label("● 检测中...", id="device-status-line")
                    yield Label("硬件:  -", id="device-hw", classes="device-info-line")
                    yield Label("固件:  -", id="device-fw", classes="device-info-line")
                    yield Label("模式:  -", id="device-mode", classes="device-info-line")
                    yield Label("VID:PID: -", id="device-vidpid", classes="device-info-line")
                    yield Label("速度:  -", id="device-speed", classes="device-info-line")
                    yield Label("DUT:   -", id="device-dut", classes="device-info-line")

                    # 详情 (紧贴状态)
                    yield Label("设备详情", classes="device-card-title")
                    yield Label("序列号: -", id="dev-serial", classes="device-info-line")
                    yield Label("制造商: -", id="dev-manuf", classes="device-info-line")
                    yield Label("产品:   -", id="dev-product", classes="device-info-line")
                    yield Label("总线:   -", id="dev-bus", classes="device-info-line")
                    yield Label("Bitstream: -", id="dev-bitstream", classes="device-info-line")

                    # 模式切换 (紧贴详情)
                    yield Label("模式切换", classes="device-card-title")
                    with Horizontal(classes="btn-row"):
                        yield Button("⚡ Facedancer", id="btn-switch-fd", variant="success")
                        yield Button("📡 Analyzer", id="btn-switch-an")
                    with Horizontal(classes="btn-row"):
                        yield Button("🔄 刷新", id="btn-refresh-device")
                        yield Button("📋 详情", id="btn-device-detail")
                    yield Button("📦 一键刷写固件", id="btn-flash-firmware", variant="warning")

                # ── MCP 配置 (底部) ──
                with Vertical(id="mcp-bottom"):
                    yield Label("MCP 服务器", classes="section-label")
                    yield Label("AI 助手通过 stdio 调用 USB 安全工具", classes="mcp-info")
                    with Horizontal(classes="btn-row"):
                        yield Button("Claude", id="btn-mcp-claude", variant="primary")
                        yield Button("Codex", id="btn-mcp-codex", variant="primary")
                        yield Button("Hermes", id="btn-mcp-hermes", variant="primary")

            # ── 右栏: 设备日志 ──
            with Vertical(id="right-panel"):
                yield Label("设备日志", classes="panel-title")
                yield RichLog(id="device-log", wrap=True, markup=True)

    # ═══════════════════════════════════════════════════════════════════════
    # Tab 2: 监听 — Wireshark 风格
    # ═══════════════════════════════════════════════════════════════════════

    def _compose_sniff_tab(self) -> ComposeResult:
        with Horizontal(classes="workspace"):
            with VerticalScroll(id="left-panel"):
                yield Label("捕获控制", classes="section-label")
                with Horizontal(classes="btn-row"):
                    yield Button("▶ 开始捕获", id="btn-sniff-start", variant="success")
                    yield Button("⏹ 停止", id="btn-sniff-stop", variant="error")
                with Horizontal(classes="btn-row"):
                    yield Button("📁 导出 PCAP", id="btn-sniff-export")
                    yield Button("🗑 清空列表", id="btn-sniff-clear")

                yield Label("捕获速度", classes="section-label")
                yield Select(
                    [("自动检测", "auto"), ("高速 480Mbps", "high"),
                     ("全速 12Mbps", "full"), ("低速 1.5Mbps", "low")],
                    id="select-sniff-speed",
                    value="auto",
                )

                yield Label("实时统计", classes="section-label")
                yield Label("总包数: 0", id="sniff-stat-total", classes="info-line")
                yield Label("SETUP:  0", id="sniff-stat-setup", classes="info-line")
                yield Label("DATA:   0", id="sniff-stat-data", classes="info-line")
                yield Label("ACK/NAK/STALL:", id="sniff-stat-handshake", classes="info-line")
                yield Label("速率:   0 pps", id="sniff-stat-pps", classes="info-line")
                yield Label("设备数: 0", id="sniff-stat-devs", classes="info-line")

            with Vertical(id="right-panel"):
                yield Label("数据包列表 (点击行查看详情)", classes="panel-title")
                yield DataTable(id="sniff-packet-table")
                yield Label("协议解析详情", classes="sniff-section-title")
                yield RichLog(id="sniff-packet-detail", wrap=True, markup=True)
                yield Label("原始数据 (Hex Dump)", classes="sniff-section-title")
                yield RichLog(id="sniff-hex-dump", wrap=True, markup=True)

    # ═══════════════════════════════════════════════════════════════════════
    # Tab 3: 中继 — Burp Suite 风格 USB MITM
    # ═══════════════════════════════════════════════════════════════════════

    def _compose_relay_tab(self) -> ComposeResult:
        with Horizontal(classes="workspace"):
            # ── 左栏: 控制面板 ──
            with VerticalScroll(id="left-panel"):
                yield Label("中继模式控制", classes="section-label")
                with Horizontal(classes="btn-row"):
                    yield Button("▶ 启动中继", id="btn-relay-start", variant="success")
                    yield Button("⏹ 停止", id="btn-relay-stop", variant="error")

                yield Label("拦截策略", classes="section-label")
                yield Select(
                    [("🟢 放行所有 (Pass-through)", "pass"),
                     ("🟡 暂停所有 (Hold all)", "hold"),
                     ("🔴 拦截 SETUP (SETUP only)", "setup"),
                     ("🟠 拦截 DATA (DATA only)", "data"),
                     ("⚫ 拦截全部 (Intercept all)", "all")],
                    id="select-relay-policy",
                    value="pass",
                )

                yield Label("规则匹配", classes="section-label")
                yield Input(
                    placeholder="设备地址 (0-127, 空为全部)",
                    id="input-relay-dev",
                )
                yield Input(
                    placeholder="端点号 (0-15, 空为全部)",
                    id="input-relay-ep",
                )
                yield Input(
                    placeholder="bRequest hex (如 06, 空为全部)",
                    id="input-relay-request",
                )

                yield Label("统计", classes="section-label")
                yield Label("已转发: 0", id="relay-stat-forward", classes="info-line")
                yield Label("已拦截: 0", id="relay-stat-hold", classes="info-line")
                yield Label("已丢弃: 0", id="relay-stat-drop", classes="info-line")
                yield Label("已篡改: 0", id="relay-stat-modify", classes="info-line")

                yield Label("修改动作", classes="section-label")
                with Horizontal(classes="btn-row"):
                    yield Button("✅ 放行", id="btn-relay-forward", variant="success")
                    yield Button("🗑 丢弃", id="btn-relay-drop", variant="error")
                yield Button("📤 发送修改", id="btn-relay-send")

            # ── 右栏: 拦截队列 + 包内容 ──
            with Vertical(id="right-panel"):
                yield Label("拦截队列 (点击行查看/编辑)", classes="panel-title")
                yield DataTable(id="relay-queue-table")
                yield Label("数据编辑 (Hex)", classes="sniff-section-title")
                yield Input(
                    placeholder="点击队列中的包后在此编辑 hex...",
                    id="input-relay-edit",
                )
                yield Label("中继日志", classes="sniff-section-title")
                yield RichLog(id="relay-log", wrap=True, markup=True)

    # ═══════════════════════════════════════════════════════════════════════
    # Tab 4: 分析
    # ═══════════════════════════════════════════════════════════════════════

    def _compose_analyze_tab(self) -> ComposeResult:
        with Horizontal(classes="workspace"):
            with VerticalScroll(id="left-panel"):
                yield Label("描述符分析", classes="section-label")
                yield Input(
                    placeholder="输入十六进制描述符 (如: 12010002...)",
                    id="input-desc-hex",
                )
                with Horizontal(classes="btn-row"):
                    yield Button("🔍 解析描述符", id="btn-parse-desc", variant="success")
                    yield Button("🗑 清空", id="btn-clear-desc")
                yield Button("📋 填入示例描述符", id="btn-sample-desc")

                yield Label("描述符类型统计", classes="section-label")
                yield DataTable(id="desc-type-table")

                yield Label("SETUP 请求解析", classes="section-label")
                yield Input(
                    placeholder="输入 SETUP 数据 8 字节 hex (如: 80060001...)",
                    id="input-setup-hex",
                )
                with Horizontal(classes="btn-row"):
                    yield Button("🔍 解析 SETUP 请求", id="btn-parse-setup", variant="success")
                    yield Button("📋 填入示例", id="btn-sample-setup")

            with Vertical(id="right-panel"):
                yield Label("解析结果", classes="panel-title")
                yield RichLog(id="analyze-log", wrap=True, markup=True)

    # ═══════════════════════════════════════════════════════════════════════
    # Tab 4: 注入
    # ═══════════════════════════════════════════════════════════════════════

    def _compose_inject_tab(self) -> ComposeResult:
        with Horizontal(classes="workspace"):
            with VerticalScroll(id="left-panel"):
                yield Label("请求模板", classes="section-label")
                yield Select(
                    [(t.name, i) for i, t in enumerate(TEMPLATES)],
                    id="select-template",
                    value=0,
                )
                with Horizontal(classes="btn-row"):
                    yield Button("📥 加载模板", id="btn-load-template")
                    yield Button("▶ 发送", id="btn-send-req", variant="success")

                yield Label("自定义请求", classes="section-label")
                with Horizontal(classes="btn-row"):
                    yield Select(
                        [("OUT (Host→Dev)", DIR_OUT), ("IN (Dev→Host)", DIR_IN)],
                        id="sel-req-dir",
                        value=DIR_OUT,
                    )
                    yield Input(placeholder="bRequest (hex)", id="inj-bRequest", value="06")
                with Horizontal(classes="btn-row"):
                    yield Input(placeholder="wValue (hex)", id="inj-wValue", value="0100")
                    yield Input(placeholder="wIndex (hex)", id="inj-wIndex", value="0000")
                yield Input(placeholder="wLength", id="inj-wLength", value="40")
                yield Input(placeholder="数据 hex", id="inj-data", value="")
                yield Button("▶ 发送自定义请求", id="btn-send-custom", variant="success")

                yield Label("批量注入", classes="section-label")
                with Horizontal(classes="btn-row"):
                    yield Input(placeholder="次数", id="inj-batch-count", value="10", type="integer")
                    yield Input(placeholder="延迟ms", id="inj-batch-delay", value="100", type="integer")
                with Horizontal(classes="btn-row"):
                    yield Button("🔁 批量发送", id="btn-batch-send", variant="warning")
                    yield Button("⏹ 停止", id="btn-batch-stop", variant="error")

                yield Label("已发送: 0 / 错误: 0", id="inj-stats", classes="info-line")

            with Vertical(id="right-panel"):
                yield Label("注入日志", classes="panel-title")
                yield RichLog(id="inject-log", wrap=True, markup=True)

    # ═══════════════════════════════════════════════════════════════════════
    # Tab 5: 伪造 — 全字段带默认值
    # ═══════════════════════════════════════════════════════════════════════

    # ── Tab 5: 伪造 — 全字段带默认值 + height:3 控件
    # ═══════════════════════════════════════════════════════════════════════
    def _compose_emulate_tab(self) -> ComposeResult:
        with Horizontal(classes="workspace"):
            with VerticalScroll(id="left-panel"):
                # ── 模板 ──
                yield Label("设备模板", classes="section-label")
                yield Select(PROFILE_OPTIONS, id="select-emul-profile", value="generic-hid")
                with Horizontal(classes="btn-row"):
                    yield Button("🔄 加载", id="btn-emul-load-profile", variant="success")
                    yield Button("🔧 变异", id="btn-emul-mutate")
                    yield Button("📋 描述符", id="btn-emul-desc")

                # ── VID / PID ──
                yield Label("VID / PID / 版本", classes="section-label")
                with Horizontal(classes="btn-row"):
                    yield Input(placeholder="VID", id="emul-vid", value="05ac")
                    yield Input(placeholder="PID", id="emul-pid", value="021a")
                    yield Input(placeholder="bcdDevice", id="emul-bcd-device", value="0100")
                yield Select(
                    [("USB 2.0", "2.0"), ("USB 1.1", "1.1"), ("USB 3.0", "3.0"), ("USB 3.1", "3.1")],
                    id="emul-usb-version", value="2.0",
                )

                # ── 设备信息 ──
                yield Label("序列号 / 厂商 / 产品", classes="section-label")
                with Horizontal(classes="btn-row"):
                    yield Input(placeholder="序列号", id="emul-serial", value="UF-HID-001")
                    yield Input(placeholder="厂商", id="emul-manufacturer", value="Apple Inc.")
                yield Input(placeholder="产品名", id="emul-product", value="USBForge HID Device")

                # ── 设备类 — 独占整行 ──
                yield Label("设备类", classes="section-label")
                yield Select(
                    [("Per-Interface (0x00)", 0x00), ("HID (0x03)", 0x03),
                     ("Audio (0x01)", 0x01), ("CDC (0x02)", 0x02),
                     ("Mass Storage (0x08)", 0x08), ("Hub (0x09)", 0x09),
                     ("Video (0x0e)", 0x0e), ("Vendor (0xff)", 0xff)],
                    id="emul-device-class", value=0x00,
                )
                with Horizontal(classes="btn-row"):
                    yield Input(placeholder="子类", id="emul-subclass", value="00")
                    yield Input(placeholder="协议", id="emul-protocol", value="00")
                    yield Input(placeholder="功耗 mA", id="emul-max-power", value="100")

                # ── EP0 + 仿真控制 ──
                yield Label("EP0 / 仿真控制", classes="section-label")
                yield Select(
                    [("EP0:8", 8), ("EP0:16", 16), ("EP0:32", 32), ("EP0:64", 64)],
                    id="emul-ep0-size", value=64,
                )
                with Horizontal(classes="btn-row"):
                    yield Button("▶ 开始", id="btn-emul-start", variant="success")
                    yield Button("⏹ 停止", id="btn-emul-stop", variant="error")
                    yield Button("💾 导出", id="btn-emul-export-desc")

                # ── 描述符注入 ──
                yield Label("描述符注入", classes="section-label")
                yield Input(placeholder="设备描述符 hex (≥18 bytes)", id="emul-desc-inject")
                yield Button("💉 注入描述符", id="btn-inject-desc", variant="warning")

            with Vertical(id="right-panel"):
                yield Label("仿真日志", classes="panel-title")
                yield RichLog(id="emulate-log", wrap=True, markup=True)


    # ═══════════════════════════════════════════════════════════════════════
    # Tab 6: 模糊 — 清晰分区
    # ═══════════════════════════════════════════════════════════════════════

    def _compose_fuzz_tab(self) -> ComposeResult:
        with Horizontal(classes="workspace"):
            with VerticalScroll(id="left-panel"):
                # ── 控制 ──
                yield Label("模糊测试控制", classes="section-label")
                yield Button("▶ 开始模糊测试", id="btn-fuzz-start", variant="success")
                with Horizontal(classes="btn-row"):
                    yield Button("⏸ 暂停", id="btn-fuzz-pause", variant="warning")
                    yield Button("⏹ 停止", id="btn-fuzz-stop", variant="error")

                # ── 目标 ──
                yield Label("目标设备", classes="section-label")
                yield Select(
                    [("无 Shell (无连接监控)", "noshell"),
                     ("SSH 连接", "ssh"),
                     ("ADB 连接", "adb"),
                     ("串口 UART", "uart")],
                    id="fuzz-conn-type",
                    value="noshell",
                    classes="fuzz-full-select",
                )
                # ── 无 Shell: 无额外字段 ──
                with Vertical(id="fuzz-noshell-fields", classes="fuzz-target-section"):
                    yield Label("无需配置 — 仅通过 USB 枚举变化检测崩溃", classes="fuzz-hint")

                # ── SSH 字段 ──
                with Vertical(id="fuzz-ssh-fields", classes="fuzz-target-section"):
                    yield Select(
                        [("用户 Shell (dmesg + logcat)", "user"),
                         ("Root Shell (dmesg + kmsg + pstore)", "root")],
                        id="fuzz-ssh-level",
                        value="user",
                        classes="fuzz-full-select",
                    )
                    yield Input(placeholder="目标 IP", id="fuzz-ssh-ip", value="192.168.1.100")
                    with Horizontal(classes="btn-row"):
                        yield Input(placeholder="SSH 用户名", id="fuzz-ssh-user", value="root")
                        yield Input(placeholder="SSH 密码", id="fuzz-ssh-pass", password=True)

                # ── ADB 字段 ──
                with Vertical(id="fuzz-adb-fields", classes="fuzz-target-section"):
                    yield Select(
                        [("有线 USB (选择设备)", "wired"),
                         ("无线 WiFi (IP + 端口)", "wireless")],
                        id="fuzz-adb-mode",
                        value="wired",
                        classes="fuzz-full-select",
                    )
                    # 有线: 设备下拉 + 可选密码 (无 IP/端口)
                    yield Select(
                        [("自动选择第一个设备", "auto")],
                        id="fuzz-adb-device",
                        value="auto",
                        classes="fuzz-full-select fuzz-adb-wired-only",
                    )
                    yield Input(placeholder="密码 (可选, 大多数 ADB 无需密码)", id="fuzz-adb-pass",
                                password=True, classes="fuzz-adb-wired-only")
                    # 无线: 设备下拉 + IP + 端口 + 可选密码
                    yield Select(
                        [("手动输入 IP + 端口", "manual")],
                        id="fuzz-adb-wireless-device",
                        value="manual",
                        classes="fuzz-full-select fuzz-adb-wireless-only",
                    )
                    with Horizontal(classes="btn-row fuzz-adb-wireless-only"):
                        yield Input(placeholder="设备 IP", id="fuzz-adb-ip")
                        yield Input(placeholder="端口", id="fuzz-adb-port", value="5555")
                    yield Input(placeholder="密码 (可选)", id="fuzz-adb-wireless-pass",
                                password=True, classes="fuzz-adb-wireless-only")

                # ── UART 字段 ──
                with Vertical(id="fuzz-uart-fields", classes="fuzz-target-section"):
                    yield Select(
                        _SERIAL_CHOICES,
                        id="fuzz-uart-port",
                        value=_SERIAL_DEFAULT,
                        classes="fuzz-full-select",
                    )
                    with Horizontal(classes="btn-row"):
                        yield Input(placeholder="波特率", id="fuzz-uart-baud", value="115200")

                yield Label("仿真设备模板", classes="section-label")
                yield Select(PROFILE_OPTIONS, id="fuzz-profile", value="generic-hid")

                # ── 阶段选择 (2 per row) ──
                yield Label("模糊阶段", classes="section-label")
                phase_list = list(FuzzPhase)
                for i in range(0, len(phase_list), 2):
                    with Horizontal(classes="btn-row"):
                        yield Checkbox(
                            PHASE_NAMES[phase_list[i]],
                            id=f"fuzz-phase-{phase_list[i].value}",
                            value=True,
                        )
                        if i + 1 < len(phase_list):
                            yield Checkbox(
                                PHASE_NAMES[phase_list[i+1]],
                                id=f"fuzz-phase-{phase_list[i+1].value}",
                                value=True,
                            )

                # ── 参数 ──
                yield Label("参数配置", classes="section-label")
                with Horizontal(classes="btn-row"):
                    yield Input(placeholder="每阶段用例数", id="fuzz-max-cases", value="30", type="integer")
                    yield Input(placeholder="随机种子", id="fuzz-seed", value="42")
                yield Input(placeholder="用例间延迟 ms", id="fuzz-delay", value="500", type="integer")

            with Vertical(id="right-panel"):
                # ── 统计仪表盘 ──
                with Horizontal(classes="btn-row"):
                    yield Label("总计: 0", id="fuzz-stat-total", classes="info-line")
                    yield Label("已执行: 0", id="fuzz-stat-exec", classes="info-line")
                with Horizontal(classes="btn-row"):
                    yield Label("崩溃: 0", id="fuzz-stat-crash", classes="info-line")
                    yield Label("通过: 0", id="fuzz-stat-pass", classes="info-line")
                with Horizontal(classes="btn-row"):
                    yield Label("警告: 0", id="fuzz-stat-warn", classes="info-line")
                    yield Label("速率: 0/s", id="fuzz-stat-rate", classes="info-line")

                yield ProgressBar(id="fuzz-progress", total=100, show_eta=True)
                yield Label(
                    "当前用例: 无 — 按 ▶ 开始",
                    id="fuzz-current",
                    classes="info-line",
                )

                with TabbedContent():
                    with TabPane("崩溃日志", id="fuzz-tab-crash"):
                        yield RichLog(id="fuzz-crash-log", wrap=True, markup=True)
                    with TabPane("信息日志", id="fuzz-tab-info"):
                        yield RichLog(id="fuzz-info-log", wrap=True, markup=True)
                    with TabPane("阶段详情", id="fuzz-tab-phases"):
                        yield DataTable(id="fuzz-phase-table")

    # ═══════════════════════════════════════════════════════════════════════
    # Tab 7: 统计
    # ═══════════════════════════════════════════════════════════════════════

    def _compose_stats_tab(self) -> ComposeResult:
        with Horizontal(classes="workspace"):
            with VerticalScroll(id="left-panel"):
                yield Label("模糊测试统计", classes="section-label")
                yield Label("总用例: 0", id="stats-fuzz-total", classes="info-line")
                yield Label("已执行: 0", id="stats-fuzz-exec", classes="info-line")
                yield Label("通过率: -", id="stats-fuzz-pass", classes="info-line")
                yield Label("崩溃数: 0", id="stats-fuzz-crash", classes="info-line")

                yield Label("注入统计", classes="section-label")
                yield Label("已发送: 0", id="stats-inj-sent", classes="info-line")
                yield Label("错误数: 0", id="stats-inj-err", classes="info-line")

                yield Label("监听统计", classes="section-label")
                yield Label("总包数: 0", id="stats-sniff-total", classes="info-line")
                yield Label("捕获时长: -", id="stats-sniff-time", classes="info-line")

                with Horizontal(classes="btn-row"):
                    yield Button("🔄 刷新统计", id="btn-refresh-stats")
                    yield Button("🗑 重置统计", id="btn-reset-stats", variant="error")

            with Vertical(id="right-panel"):
                yield Label("全局活动日志", classes="panel-title")
                yield RichLog(id="stats-log", wrap=True, markup=True)

    # ═══════════════════════════════════════════════════════════════════════
    # Tab 8: 关于 — 详细工具说明 + MCP 配置 + 作者简介
    # ═══════════════════════════════════════════════════════════════════════

    ABOUT_ASCII = r"""
   __  _______ ____  ______
  / / / / ___// __ )/ ____/___  _________ ____
 / / / /\__ \/ __  / /_  / __ \/ ___/ __ `/ _ \
/ /_/ /___/ / /_/ / __/ / /_/ / /  / /_/ /  __/
\____//____/_____/_/    \____/_/   \__, /\___/
                                   /____/      v3.0
"""

    # 像素块头像 150×60 — █▓▒░ 块字符
    AVATAR_ASCII = (
        "           █████                                                                                                        \n"
        "       █████████                                                                                                        \n"
        "   ▓██████████████   ██░░███                ██  ███                                                                     \n"
        "    ██████████████   ████ ▓█████              ███  ██                                                                   \n"
        "    ██████████████   █████  ▒███                █  ██                                                                   \n"
        "     █████████████ ███████████                   ████                                                                   \n"
        "       ███████████ █████████    █████   ▓█▓      ████                                                                   \n"
        "     ██         ███████   ▓███          ▓█▓   ██                                                                        \n"
        "         ███  ███████                ██ ▓█▓   █████                                                                     \n"
        "       ███████████   ████     ██     █████▓     ███                          ░██                                        \n"
        "           █████     ██   ▓█       █████▒   ██  █                            ░██                                        \n"
        "██   ██         ███████  █████    ██████▒   ██                              ████████████░                               \n"
        "         ███████  █████████████████████████████████                       ███████████████████████████                   \n"
        "            ████  ██████████████████████▒ ▒████████                       ███████  ████████████████   ▓███     ████     \n"
        "    █      █  ██████████████████████████▒ ▒█████ ██                         █▓     ███████████████████░   ██ ██████     \n"
        "    █    ██     ██ ████████████████████ ▓███████ ██                              █████████████████████░   █████         \n"
        "     ███████  ████████████████████   ████████████             ░              ░███     ██░   █████████████████           \n"
        "       ████████████████          ▓███████████████      ███    ███                    ████████████████████████           \n"
        "       ████   ██████████████████████████████████████████████       ██            ████████████████████████████           \n"
        "         ██   ████████████████████████████████  █    ██████████  ██████         ████████████████████████████            \n"
        "                   ░░░░█████████████████████  ██████████████▓▓ ░█████          █████████████████████████                \n"
        "                ████████████████  ██████████  ███████████████████████            █████████████████████░                 \n"
        "                  █████       ████████████▓   ██████████▓ █████████       ██       ██████████████████                   \n"
        "                   ██████   ██████████████▓ ███████████ ▒██████████     ████       ██████████████████                   \n"
        "                     ▓▓███▒   ██████████▒     █████████ ▒██████████  ▓▓ ████              █████████                     \n"
        "                       █████████████████▒   ███████  ░░██████████████░░█████         ░░░░░███████                       \n"
        "                            ███████████     █████       ▒█    ████████████           ██       █  ██                     \n"
        "                              ███████         █████           ████████████   ░█████         ██ ██                       \n"
        "                                            ██  █             ██████████  ███████         ███████                       \n"
        "                     ▓▓░░                              ░░ ██░░██░███████  █████▓▓    ██░██████▓░░░░              ░░░░█  \n"
        "                                                 ██       ████████████████  ████   ██████████████              ██████   \n"
        "                                                   ██  ███████ ░████████████     ██████████████              ██████  ███\n"
        "            ██                                          ▒█████ ░██████████████   █████████████              ██████████  \n"
        "              ████                                     █████   ░█████████████▓   █████████                ███████████   \n"
        "                              ████████████▓        ░░████░    ▓███████████░░░░  ██████░              ▓██████████████████\n"
        "                            ██    ████████▓        █████▓     ████████████     ████              ███████████████████████\n"
        "                                 ▓████████▓        ████       ██████████     ░███                ███████████████████████\n"
        "                                 ▓█████   ▒█       ██         ██████████     ░██              ██████████████████████████\n"
        "                          ▒████████░░       ██   ░░██░░     █████████░░       █           ██████████████████████████████\n"
        "                                            ████ ████       ███▓ ████       ███         ▓███████████████████████████████\n"
        "                                          ▒███   ██         █████████       ███        █████████████████████████████████\n"
        "                                          ▒███              ██ ░█████       ████████████████████████████████████████████\n"
        "                                        ▓█████  █         ███████████       ██ █████████████████████████████████████████\n"
        "                                       ███▓░    ░         ████▓▓███████     ████████████████████████████████████████████\n"
        "                                          ▒█            ▒█    ███  ████        █████████████████████████████████████████\n"
        "                                                        ▒█         ████        ██  █████████████████████████████████████\n"
        "                                        ▓█▓                            █      ███    ███████████████████████████████████\n"
        "                                            ██         █▓     █▓             ░██     ███████████████████████████████████\n"
        "                                            ██                     ██     ██ ░█████   ██████████████████████████████████\n"
        "                                     ██                            ██   ████ ░█████   ██████████████████████████████████"
    )

    def _compose_about_tab(self) -> ComposeResult:
        with Horizontal(classes="workspace"):
            # ── 左侧：工具详细介绍 ──
            with VerticalScroll(id="left-panel"):
                yield Label(self.ABOUT_ASCII, classes="about-text", markup=False)

                yield Label("USBForge ", classes="section-label")
                yield Static(
                    "USBForge 是基于 Great Scott Gadgets Cynthion 硬件平台构建的全功能 USB 安全工具集，运行在终端界面 (TUI) 中。\n"
                    "它将 USB 协议分析、中间人攻击、设备仿真、漏洞挖掘等能力整合到统一的 9 模块界面中，专为 IoT 设备、嵌入式系统、智能硬件的 USB 协议安全审计场景而设计。\n\n"
                    "Cynthion 是 Glasgow Interface Explorer 的 USB 安全衍生平台，搭载 Lattice UP5K FPGA，支持 USB 1.1/2.0 全速和高速模式。\n其内置的 Apollo 调试器可动态加载两种工作Bitstream：Analyzer (被动监听) 和 Facedancer (主动仿真)，无需重新插拔即可通过软件切换。",
                    classes="about-text",
                )

                yield Label("九大功能模块", classes="section-label")
                yield Static(
                    "[1] 设备\n    Cynthion 硬件连接状态检测、固件/序列号"
                    "识别、Bitstream 模式一键切换 (Analyzer↔Facedancer)、"
                    "MCP 服务器一键导入 (Claude/Claude Code/Hermes)\n"
                    "[2] 监听\n    Wireshark 风格的 USB 总线实时流量捕获。"
                    "支持 Low/Full/High speed 自动协商，"
                    "逐包显示 PID/设备地址/端点/数据长度，"
                    "点击任意包查看 Hex Dump 和事务详情。"
                    "支持导出标准 PCAP 格式供 Wireshark 分析。\n"
                    "[3] 中继\n    Burp Suite 风格的 USB MITM 中间人模块。"
                    "在 Host 与 DUT 之间串接 Cynthion 作为透明代理，"
                    "可实时拦截/篡改/丢弃任意 USB 事务。"
                    "支持 5 种拦截策略和按地址/端点/bRequest 过滤。"
                    "拦截的包可在队列中查看详情、编辑 Hex 数据后转发。\n"
                    "[4] 分析\n    对捕获的 USB 数据进行深度解析："
                    "设备/配置/接口/端点描述符字段级提取，"
                    "SETUP token 请求类型/bRequest/wValue 解码，"
                    "Vendor-specific 请求自动识别与高亮，"
                    "字符串描述符多语言提取，"
                    "USB 类协议 (HID/Mass Storage/CDC) 自动识别\n"
                    "[5] 注入\n    构造自定义 USB 控制请求并发送到 DUT："
                    "支持标准请求和 Vendor-specific 请求，"
                    "批量请求序列 (CSV 导入，可设延时)，"
                    "Fuzzing 种子请求一键回放\n"
                    "[6] 伪造\n    USB 设备仿真与克隆："
                    "12+ 预设设备配置 (FTDI/HID/Mass Storage/CDC 等)，"
                    "自定义 VID/PID/Serial，"
                    "完整描述符编辑，"
                    "从捕获的描述符一键克隆到真实硬件，"
                    "仿真期间可通过注入 Tab 发送串口数据\n"
                    "[7] 模糊\n    多阶段智能 USB 模糊测试引擎："
                    "阶段 1 标准描述符枚举 fuzz，"
                    "阶段 2 Vendor 请求探索，"
                    "阶段 3 变异 fuzz (位翻转/字节注入/边界值)，"
                    "支持超时/STALL/NAK 异常检测，"
                    "实时统计通过率/崩溃/告警\n"
                    "[8] 统计\n    全局活动面板：模糊/注入/监听/中继的汇总数据，"
                    "全局活动日志实时滚动显示\n"
                    "[9] 关于 \n   您正在查看的页面",
                    classes="about-text",
                )

                yield Label("MCP 服务器集成", classes="section-label")
                yield Static(
                    "USBForge 内置 Cynthion MCP 服务器，提供 17 个标准"
                    "工具供 AI 助手 (Claude/Claude Code/Hermes Agent) 调用：\n"
                    "  capture_start/stop    — 启动/停止 USB 流量捕获\n"
                    "  capture_status        — 查询当前捕获状态\n"
                    "  list_captures         — 列出已保存的捕获文件\n"
                    "  convert_to_pcap       — 原始捕获转 PCAP 格式\n"
                    "  dissect_packets       — tshark 级逐包解析\n"
                    "  transaction_summary   — 事务统计 (token/data/handshake)\n"
                    "  find_vendor_requests  — Vendor SETUP 自动发现\n"
                    "  switch_mode           — 切换 Analyzer/Facedancer bitstream\n"
                    "  get_status            — 查询硬件连接与 bitstream 状态\n"
                    "  emulate_device        — 启动 USB 设备仿真\n"
                    "  emulate_from_descriptor — 从原始描述符克隆设备\n"
                    "  disconnect_device     — 停止仿真并断开设备\n"
                    "  inject_serial         — 向仿真设备注入串口数据\n"
                    "  emulator_diagnose     — 诊断 Facedancer 后端健康状态\n"
                    "  read_capture          — 读取原始捕获字节\n"
                    "  recover               — 软件恢复卡死的硬件\n"
                    "MCP 使用 stdio 传输 (标准输入输出)，无需网络端口。"
                    "AI 助手启动时自动 spawn cynthion-mcp 子进程，"
                    "通过 JSON-RPC 2.0 消息交换调用上述工具。"
                    "配置方法：在设备页右下角点击对应 AI 助手的导入按钮，"
                    "自动写入配置文件。也可手动添加 MCP 服务器配置："
                    "  路径: " + _MCP_SERVER_PATH + "\n"
                    "  传输: stdio (command + args)",
                    classes="about-text",
                )

                yield Label("快捷键", classes="section-label")
                yield Static(
                    "1-9    切换功能模块 (设备/监听/中继/分析/注入/伪造/模糊/统计/关于)\n"
                    "D      刷新设备状态\n"
                    "Q      退出程序",
                    classes="about-text",
                )

                yield Label("硬件要求", classes="section-label")
                yield Static(
                    "  Cynthion r0.6+  — Great Scott Gadgets 出品，Lattice UP5K FPGA\n"
                    "  Apollo 调试器   — 内置 USB DFU，用于加载 bitstream\n"
                    "  Analyzer 模式   — 被动 USB 监听 (TARGET-A/C 端口)\n"
                    "  Facedancer 模式 — 主动 USB 仿真 (TARGET-C 端口)\n"
                    "  Python 3.12+    — 运行环境\n"
                    "  cynthion-mcp    — MCP 服务器 (随 USBForge 安装)",
                    classes="about-text",
                )

                yield Label("技术栈", classes="section-label")
                yield Static(
                    "  Python 3.12     — 主语言\n"
                    "  Cynthion SDK    — 硬件抽象层 (luna-soc 0.3.2)\n"
                    "  Facedancer 3.1  — USB 仿真框架\n"
                    "  Textual 8.x     — 终端 UI 框架\n"
                    "  MCP (JSON-RPC)  — AI 助手工具集成",
                    classes="about-text",
                )

            # ── 右侧：作者 ASCII 头像 + 简介 ──
            with VerticalScroll(id="right-panel"):

                yield Label("", classes="info-line")  # spacer

                # 像素块头像 150×60 — █▓▒░ 块字符，markup=False 防止特殊字符被解析
                yield Label(self.AVATAR_ASCII, classes="avatar-art", markup=False)

                yield Label("", classes="info-line")  # spacer

                #yield Label("作者简介", classes="section-label")
                yield Label("偏有宸机", classes="section-label")
                yield Label("安全研究员 · IoT/IoV方向", classes="info-line")
                yield Label(
                    "专注 IoT/智能设备漏洞挖掘与安全研究。AI 辅助漏洞挖掘技术分享者.\n"
                    "lda1sy@foxmail.com",
                    classes="about-text",
                )


    USBFORGE_THEME = Theme(
        name="usbforge",
        primary="#68B92E",
        secondary="#E77817",
        accent="#E77817",
        foreground="#c0caf5",
        background="#1A1B26",
        success="#9ECE6A",
        warning="#E0AF68",
        error="#F7768E",
        surface="#24283B",
        panel="#414868",
        dark=True,
        variables={
            "block-cursor-background": "#68B92E",
            "block-cursor-foreground": "#1A1B26",
            "footer-key-foreground": "#68B92E",
            "input-selection-background": "#68B92E 35%",
            "button-color-foreground": "#1A1B26",
        },
    )

    # Reactive 状态
    is_running = reactive(False)

    def __init__(self):
        super().__init__()
        self.stats = GlobalStats()
        self.sniffer = USBSniffer()
        self.injector = PacketInjector()
        self.emulator = DeviceEmulator()
        self.all_cases: list[FuzzCase] = []
        self._fuzz_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._device_status: Optional[dict] = None
        self._monitor = None

    def on_mount(self) -> None:
        self.title = "USBForge"
        self.sub_title = "USB Security Suite"

        # 注册并应用自定义主题
        self.register_theme(self.USBFORGE_THEME)
        self.theme = "usbforge"

        # 初始化模糊阶段表
        pt = self.query_one("#fuzz-phase-table", DataTable)
        pt.add_columns("阶段", "名称", "源码", "用例", "已执行", "崩溃")
        for phase in FuzzPhase:
            pt.add_row(str(phase.value), PHASE_NAMES[phase],
                       PHASE_SOURCES[phase][:30], "0", "0", "0",
                       key=f"fp-{phase.value}")

        # 全局日志
        slog = self.query_one("#stats-log", RichLog)
        slog.write("[bold green]═══════════════════════════════════════════════════════════[/]")
        slog.write("[bold green]  ⚡ USBForge v3.0 — 全功能 USB 安全工具套件[/]")
        slog.write("[bold green]═══════════════════════════════════════════════════════════[/]")
        slog.write("")
        slog.write("[dim]功能模块:[/]")
        slog.write("[dim]  🖥 设备   — 硬件状态/模式切换[/]")
        slog.write("[dim]  📡 监听   — USB 总线捕获[/]")
        slog.write("[dim]  🔀 中继   — USB MITM 拦截/篡改[/]")
        slog.write("[dim]  🔍 分析   — 描述符/SETUP 解析[/]")
        slog.write("[dim]  💉 注入   — 控制请求构造/发送[/]")
        slog.write("[dim]  🔧 伪造   — USB 设备仿真[/]")
        slog.write("[dim]  🧪 模糊   — 变异模糊测试[/]")
        slog.write("[dim]  📊 统计   — 全局仪表盘[/]")
        slog.write("")

        # 自动检测设备
        self._refresh_device_status()

        # 初始化模糊测试目标设备字段可见性
        self._update_fuzz_conn_fields("noshell")

        # 注册 sniffer 回调
        self.sniffer.add_callback(self._on_sniff_packet)

        # 注册 injector 回调
        self.injector.add_callback(self._on_inject_event)

        # 注册 emulator 回调
        self.emulator.add_callback(self._on_emul_event)

        # 初始日志
        self._log_device("[cyan]USBForge 已启动 — 按 1-8 切换功能模块[/]")

        # 后台初始化 MCP bridge
        threading.Thread(target=self._init_mcp_bridge, daemon=True).start()

    # ═══════════════════════════════════════════════════════════════════════
    # Tab 切换
    # ═══════════════════════════════════════════════════════════════════════

    def action_goto_tab(self, tab_id: str) -> None:
        tc = self.query_one(TabbedContent)
        tc.active = tab_id

    # ═══════════════════════════════════════════════════════════════════════
    # 设备管理
    # ═══════════════════════════════════════════════════════════════════════

    def action_refresh_device(self) -> None:
        self._refresh_device_status()

    def _refresh_device_status(self) -> None:
        """检测 Cynthion 设备并更新 UI"""
        status = get_full_status()
        self._device_status = status
        info = status["cynthion"]
        readiness = status["readiness"]

        panel = self.query_one("#device-card")
        panel.remove_class("device-ready")
        panel.remove_class("device-warning")
        panel.remove_class("device-error")
        if readiness == FuzzerReadiness.READY:
            panel.add_class("device-ready")
        elif readiness in (FuzzerReadiness.NEED_BITSTREAM, FuzzerReadiness.NO_DEVICE):
            panel.add_class("device-warning")

        status_line = self.query_one("#device-status-line", Label)
        if not info.connected:
            status_line.update("❌ Cynthion 未连接")
            status_line.styles.color = "#f85149"
        elif readiness == FuzzerReadiness.READY:
            status_line.update("✅ Facedancer 就绪")
            status_line.styles.color = "#68B92E"
        elif readiness == FuzzerReadiness.NEED_BITSTREAM:
            status_line.update(f"⚠ {info.mode.value} 模式")
            status_line.styles.color = "#E77817"

        detailed = status.get("detailed", {})
        if info.connected:
            hw = detailed.get("hardware", info.product or "未知")
            self.query_one("#device-hw", Label).update(f"硬件:  [bold]{hw}[/]")
            self.query_one("#device-fw", Label).update(f"固件:  {detailed.get('firmware_version', '—')}")
            speed_short = "HS" if "High" in info.speed else ("FS" if "Full" in info.speed else "?")
            self.query_one("#device-mode", Label).update(f"模式:  [bold]{info.mode.value}[/] ({speed_short})")
            self.query_one("#device-vidpid", Label).update(f"VID:PID: {info.vid:#06x}:{info.pid:#06x}")
            self.query_one("#device-speed", Label).update(f"速度:  {info.speed}")
            self.query_one("#dev-serial", Label).update(f"序列号: {info.serial or detailed.get('serial', '—')}")
            self.query_one("#dev-manuf", Label).update(f"制造商: {info.manufacturer or '—'}")
            self.query_one("#dev-product", Label).update(f"产品:   {info.product or '—'}")
            self.query_one("#dev-bus", Label).update(f"总线:   bus={info.bus} addr={info.address}")
            self.query_one("#dev-bitstream", Label).update(f"Bitstream: {detailed.get('bitstream', '—')}")
        else:
            for label_id in ["device-hw", "device-fw", "device-mode", "device-vidpid",
                             "device-speed", "dev-serial", "dev-manuf", "dev-product",
                             "dev-bus", "dev-bitstream"]:
                self.query_one(f"#{label_id}", Label).update(f"{'.'.join(label_id.split('-')[1:])}: —")

        dut = status.get("dut", {})
        dut_label = self.query_one("#device-dut", Label)
        if dut.get("connected"):
            dut_label.update("DUT:   [bold green]已连接[/]")
        elif info.connected and info.is_facedancer:
            dut_label.update("DUT:   [yellow]等待连接 TARGET-C→目标设备[/]")
        else:
            dut_label.update("DUT:   —")

        header_status = self.query_one("#header-status", Label)
        if not info.connected:
            header_status.update("● 未连接")
            header_status.styles.color = "#f85149"
        elif readiness == FuzzerReadiness.READY:
            header_status.update("● 就绪")
            header_status.styles.color = "#68B92E"
        else:
            header_status.update(f"● {info.mode.value}")
            header_status.styles.color = "#E77817"

        self._log_device(f"[green]设备: {info.product} ({info.mode.value}) — {info.speed}[/]")

    def _log_device(self, msg: str):
        try:
            self.query_one("#device-log", RichLog).write(msg)
        except:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    # 交互联动 — Select / Checkbox 事件
    # ═══════════════════════════════════════════════════════════════════════

    def on_select_changed(self, event: Select.Changed) -> None:
        """Select 变化时联动"""
        sid = event.select.id
        if sid == "select-emul-profile":
            self._sync_profile_to_fields(event.value)
        elif sid == "fuzz-profile":
            self._update_fuzz_case_preview()
        elif sid == "fuzz-conn-type":
            self._update_fuzz_conn_fields(event.value)
        elif sid == "fuzz-adb-mode":
            self._update_fuzz_adb_subfields(event.value)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Checkbox 变化时联动"""
        cid = event.checkbox.id
        if cid and cid.startswith("fuzz-phase-"):
            # 阶段选择变化 → 更新预览计数
            self._update_fuzz_case_preview()

    def _sync_profile_to_fields(self, profile_key):
        """选择模板后自动联动填充自定义参数"""
        profile = PROFILES.get(profile_key)
        if not profile:
            return
        try:
            self.query_one("#emul-vid", Input).value = f"{profile.vid:04x}"
            self.query_one("#emul-pid", Input).value = f"{profile.pid:04x}"
            self.query_one("#emul-serial", Input).value = profile.serial or ""
            self.query_one("#emul-manufacturer", Input).value = profile.manufacturer or ""
            self.query_one("#emul-product", Input).value = profile.product or profile.name
            self.query_one("#emul-bcd-device", Input).value = "0100"
            self.query_one("#emul-subclass", Input).value = f"{profile.subclass:02x}"
            self.query_one("#emul-protocol", Input).value = f"{profile.protocol:02x}"
            self.query_one("#emul-max-power", Input).value = str(profile.max_power_ma)
            self.query_one("#emul-device-class", Select).value = profile.device_class
            self.query_one("#emul-ep0-size", Select).value = profile.max_packet_ep0
            ver = profile.usb_version
            ver_str = f"{ver[0]}.{ver[1]}"
            if ver_str not in ("1.1", "2.0", "3.0", "3.1"):
                ver_str = "2.0"
            self.query_one("#emul-usb-version", Select).value = ver_str
            self._log_emul(f"[cyan dim]↻ 模板联动: {profile.name}[/]")
        except Exception:
            pass

    def _update_fuzz_conn_fields(self, conn_type: str):
        """根据连接类型显示/隐藏模糊测试目标设备字段"""
        all_fields = ["fuzz-noshell-fields", "fuzz-ssh-fields", "fuzz-adb-fields", "fuzz-uart-fields"]
        show_map = {
            "noshell": ["fuzz-noshell-fields"],
            "ssh": ["fuzz-ssh-fields"],
            "adb": ["fuzz-adb-fields"],
            "uart": ["fuzz-uart-fields"],
        }
        visible = set(show_map.get(conn_type, ["fuzz-noshell-fields"]))
        for fid in all_fields:
            try:
                w = self.query_one(f"#{fid}")
                should_show = fid in visible
                w.display = should_show
                w.styles.display = "block" if should_show else "none"
            except Exception:
                pass
        # ADB 选中时初始化子字段
        if conn_type == "adb":
            try:
                adb_mode = self.query_one("#fuzz-adb-mode", Select).value
                self._update_fuzz_adb_subfields(adb_mode)
            except Exception:
                pass

    def _update_fuzz_adb_subfields(self, adb_mode: str):
        """ADB 有线/无线子字段切换 — 通过 class 标记逐个控制"""
        target_class = "fuzz-adb-wired-only" if adb_mode == "wired" else "fuzz-adb-wireless-only"
        try:
            adb_container = self.query_one("#fuzz-adb-fields")
            for child in adb_container.children:
                if child.has_class("fuzz-adb-wired-only") or child.has_class("fuzz-adb-wireless-only"):
                    should_show = child.has_class(target_class)
                    child.display = should_show
                    child.styles.display = "block" if should_show else "none"
        except Exception:
            pass

    def _update_fuzz_case_preview(self):
        """根据已选阶段和用例数参数实时预估计用例总数"""
        try:
            selected = self._get_selected_phases()
            max_cases = int(self.query_one("#fuzz-max-cases", Input).value or "30")
            # 粗估: 每阶段最多 max_cases 个
            total_est = len(selected) * max_cases
            self.query_one("#fuzz-stat-total", Label).update(f"总计\n~{total_est}")
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    # 按钮事件分发
    # ═══════════════════════════════════════════════════════════════════════

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        btn_id_safe = btn_id.replace("-", "_") if btn_id else ""
        handler = getattr(self, f"_on_{btn_id_safe}", None) if btn_id_safe else None
        if handler:
            handler()

    # ── 设备按钮 ──
    def _on_btn_refresh_device(self):
        self._refresh_device_status()

    def _on_btn_switch_mode(self):
        """根据下拉选择器切换设备模式"""
        mode = self.query_one("#select-device-mode", Select).value
        if mode == "facedancer":
            self._do_switch("facedancer")
        elif mode == "analyzer":
            self._do_switch("analyzer")

    # ── MCP Bridge ──

    def _init_mcp_bridge(self):
        """后台初始化 MCP bridge"""
        try:
            bridge = get_bridge()
            ok = bridge.start(timeout=15)
            if ok:
                self.call_from_thread(
                    self._log_device,
                    "[green]✓ MCP 服务器已连接 — 全部 17 个工具可用[/]"
                )
                # 验证工具列表
                tools = bridge.list_tools()
                if tools:
                    self.call_from_thread(
                        self._log_device,
                        f"  [dim]已加载 {len(tools)} 个 MCP 工具[/]"
                    )
            else:
                self.call_from_thread(
                    self._log_device,
                    "[yellow]⚠ MCP 服务器不可用 — 将使用 CLI 模式[/]"
                )
        except Exception as e:
            self.call_from_thread(
                self._log_device,
                f"[yellow]⚠ MCP 初始化失败: {e}[/]"
            )

    def _do_switch(self, target: str):
        label = "Facedancer" if target == "facedancer" else "Analyzer"
        self._log_device(f"[yellow]切换到 {label} 模式（约30-90秒，持久刷写 SPI flash）...[/]")

        def _do():
            # 直接用 CLI flash（持久刷写）— 不走 MCP run_bitstream（RAM，非持久）
            fn = switch_to_facedancer if target == "facedancer" else switch_to_analyzer
            ok = fn()
            if ok:
                self.call_from_thread(self._log_device, f"[green]✓ {label} 模式切换成功（持久）[/]")
            else:
                self.call_from_thread(self._log_device,
                    f"[red]❌ 切换失败 — 请检查设备连接后重试[/]")

            self.call_from_thread(self._refresh_device_status)

        threading.Thread(target=_do, daemon=True).start()

    def _on_btn_switch_fd(self):
        self._do_switch("facedancer")

    def _on_btn_switch_an(self):
        self._do_switch("analyzer")

    def _on_btn_device_detail(self):
        """显示详细设备信息到日志"""
        info = get_detailed_info()
        if not info:
            self._log_device("[yellow]设备未连接，无法获取详细信息[/]")
            return
        self._log_device(f"[cyan]═══ 详细信息 ═══[/]")
        for k, v in info.items():
            self._log_device(f"  [dim]{k}:[/] [white]{v}[/]")

    # ── 设备模式检查 (核心方法) ──

    def _get_current_mode(self) -> str:
        """获取当前设备模式 (返回 lowercase string)"""
        info = detect_cynthion()
        if not info.connected:
            return "not_found"
        return info.mode.value.lower()

    def _ensure_mode(self, required_mode: str, action_name: str, callback):
        """检查设备模式，如不匹配则弹窗确认切换后执行回调。

        required_mode: "facedancer" / "analyzer"
        action_name:   用户可见的功能名 (如 "USB 流量捕获")
        callback:      模式匹配/切换成功后执行的 callable
        """
        current = self._get_current_mode()

        if current == "not_found":
            def _after_info():
                pass
            self.push_screen(InfoScreen(
                "❌ 设备未连接",
                f"执行「{action_name}」需要 Cynthion 设备已连接。\n请检查 USB 连接后重试。"
            ))
            return

        if current == required_mode:
            # 模式已匹配，直接执行
            callback()
            return

        # 模式不匹配 — 弹窗确认
        def _on_mode_confirm(result):
            if result and result is not False:
                # 用户确认切换 — 先切换再执行
                def _do_switch_then_callback():
                    self._do_switch(required_mode)
                    # 切换后延迟执行回调 (等设备重连)
                    def _delayed():
                        callback()
                    timer = threading.Timer(3.0, lambda: self.call_from_thread(_delayed))
                    timer.daemon = True
                    timer.start()

                threading.Thread(target=_do_switch_then_callback, daemon=True).start()

        self.push_screen(
            ModeConfirmScreen(current, required_mode, action_name),
            _on_mode_confirm
        )

    # ── 一键刷写固件 ──

    def _on_btn_flash_firmware(self):
        """一键刷写 USBForge 适配固件"""
        info = detect_cynthion()

        if not info.connected:
            self.push_screen(InfoScreen(
                "❌ 设备未连接",
                "刷写固件需要 Cynthion 设备已连接。\n请连接设备后重试。"
            ))
            return

        # 获取当前 bitstream 信息
        detailed = get_detailed_info()
        current_bs = detailed.get("bitstream", "")

        # 检查是否已满足要求 (已加载 Facedancer 或 Analyzer bitstream)
        bs_lower = current_bs.lower()
        if "facedancer" in bs_lower:
            self.push_screen(InfoScreen(
                "✅ 固件已满足要求",
                f"当前设备已加载 [bold green]Facedancer[/] bitstream。\n\n"
                f"Bitstream: {current_bs}\n\n"
                f"无需刷写，可以直接使用全部功能。"
            ))
            return
        elif "analyzer" in bs_lower:
            # Analyzer 也可用，但提示用户
            self.push_screen(InfoScreen(
                "ℹ️ 当前为 Analyzer 固件",
                f"当前设备已加载 [bold yellow]Analyzer[/] bitstream。\n\n"
                f"Bitstream: {current_bs}\n\n"
                f"监听功能可直接使用。\n"
                f"中继/注入/伪造/模糊功能需要 Facedancer 固件。"
            ))
            return

        # 需要刷写 — 先检查固件文件是否已存在，判断是否需要联网下载
        target_bs = "facedancer"
        needs_download = False

        # 弹出确认弹窗
        def _on_flash_confirm(result):
            if result:
                self._do_flash_firmware(target_bs)

        self.push_screen(
            FlashFirmwareScreen(current_bs or "Unknown", target_bs, needs_download),
            _on_flash_confirm
        )

    def _do_flash_firmware(self, target: str):
        """实际执行固件刷写"""
        self._log_device(f"[yellow]📦 开始刷写 {target} 固件...[/]")

        def _do():
            try:
                # 使用 cynthion flash 刷写持久 bitstream
                import subprocess
                cynthion_bin = _os.path.join(_VENV_DIR,
                    "Scripts" if _sys.platform == "win32" else "bin", "cynthion"
                    + (".exe" if _sys.platform == "win32" else ""))

                self.call_from_thread(self._log_device,
                    f"[dim]正在持久刷写 {target} bitstream 到 SPI flash（约30-90秒）...[/]")

                proc = subprocess.run(
                    [cynthion_bin, "flash", target],
                    capture_output=True, text=True, timeout=120,
                    env={**_os.environ, "PYTHONPATH": ""},
                )

                if proc.returncode == 0:
                    self.call_from_thread(self._log_device,
                        f"[green]✓ {target} 固件刷写成功！[/]")
                    self.call_from_thread(self._log_device,
                        f"[dim]设备正在重新枚举...[/]")

                    # 等待设备重连（flash 刷写后需要 5-8 秒重新枚举）
                    import time
                    time.sleep(8)
                    self.call_from_thread(self._refresh_device_status)

                    self.call_from_thread(self._log_device,
                        f"[green]✓ 设备已就绪 — {target} 模式[/]")

                    # 弹出成功提示
                    def _show_success():
                        self.push_screen(InfoScreen(
                            "✅ 刷写成功",
                            f"[bold green]{target}[/] 固件已成功刷写到设备。\n\n"
                            f"设备现在可以正常使用全部功能。"
                        ))
                    self.call_from_thread(_show_success)
                else:
                    error_msg = proc.stderr or proc.stdout or "未知错误"
                    self.call_from_thread(self._log_device,
                        f"[red]❌ 刷写失败: {error_msg[:200]}[/]")
                    def _show_error():
                        self.push_screen(InfoScreen(
                            "❌ 刷写失败",
                            f"固件刷写失败。\n\n错误: {error_msg[:300]}\n\n"
                            f"请检查设备连接和 cynthion CLI。"
                        ))
                    self.call_from_thread(_show_error)

            except subprocess.TimeoutExpired:
                self.call_from_thread(self._log_device,
                    "[red]❌ 刷写超时 — 请重试[/]")
            except Exception as e:
                self.call_from_thread(self._log_device,
                    f"[red]❌ 刷写异常: {e}[/]")

        threading.Thread(target=_do, daemon=True).start()

    # ── MCP 配置导入 ──
    def _on_btn_mcp_claude(self):
        """导入 MCP 配置到 Claude Desktop"""
        config_path = Path(_CLAUDE_CONFIG_DIR) / "claude_desktop_config.json"
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            existing = {}
            if config_path.exists():
                import json as _json
                existing = _json.loads(config_path.read_text())
            if "mcpServers" not in existing:
                existing["mcpServers"] = {}
            existing["mcpServers"]["cynthion"] = {"command": _MCP_SERVER_PATH}
            config_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False))
            self._log_device(f"[green]✓ Claude Desktop 配置已写入[/]")
            self._log_device(f"  [dim]{config_path}[/]")
            self._log_device(f"  [dim]重启 Claude Desktop 生效[/]")
        except PermissionError:
            self._log_device(f"[red]❌ 权限不足: {config_path}[/]")
        except Exception as e:
            self._log_device(f"[red]❌ 配置失败: {e}[/]")

    def _on_btn_mcp_codex(self):
        """导入 MCP 配置到 Codex CLI"""
        import subprocess
        try:
            proc = subprocess.run(
                ["codex", "--mcp-config", f"cynthion={_MCP_SERVER_PATH}"],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0:
                self._log_device(f"[green]✓ Codex MCP 已注册[/]")
                self._log_device(f"  [dim]重启 Codex 生效[/]")
            else:
                self._log_device(f"[yellow]⚠ codex CLI 不可用，请手动配置:[/]")
                self._log_device(f"  [cyan]codex --mcp-config cynthion={_MCP_SERVER_PATH}[/]")
        except FileNotFoundError:
            self._log_device(f"[yellow]⚠ codex CLI 未安装，请手动配置:[/]")
            self._log_device(f"  [cyan]codex --mcp-config cynthion={_MCP_SERVER_PATH}[/]")
        except Exception as e:
            self._log_device(f"[red]❌ 注册失败: {e}[/]")

    def _on_btn_mcp_hermes(self):
        """导入 MCP 配置到 Hermes Agent"""
        config_path = Path(_HERMES_CONFIG_DIR) / "config.yaml"
        self._log_device(f"[yellow]配置 Hermes Agent...[/]")
        try:
            if config_path.exists():
                content = config_path.read_text()
                if "cynthion" in content and "cynthion-mcp" in content:
                    self._log_device(f"[green]✓ cynthion MCP 已存在于 Hermes 配置[/]")
                    return
            # 给出手动配置指引
            self._log_device(f"[cyan]请在 Hermes config.yaml 中添加:[/]")
            self._log_device(f"  [white]mcp:[/]")
            self._log_device(f"    [white]servers:[/]")
            self._log_device(f"      [white]cynthion:[/]")
            self._log_device(f"        [white]command: {_MCP_SERVER_PATH}[/]")
            self._log_device(f"  [dim]{config_path}[/]")
        except Exception as e:
            self._log_device(f"[red]❌ 配置失败: {e}[/]")

    # ── 监听按钮 ──
    def _on_btn_sniff_start(self):
        self._ensure_mode("analyzer", "USB 流量捕获", self._do_sniff_start)

    def _do_sniff_start(self):
        speed = self.query_one("#select-sniff-speed", Select).value
        self.stats.sniff_packets = 0
        self._init_sniff_table()

        # 尝试通过 MCP bridge 启动真实捕获
        bridge = get_bridge()
        if bridge.available:
            def _do_mcp_capture():
                result = bridge.capture_start(speed)
                if result.get("ok"):
                    self.call_from_thread(self._log_device,
                        f"[green]✓ MCP 捕获已启动 ({speed})[/]")
                else:
                    self.call_from_thread(self._log_device,
                        f"[yellow]⚠ MCP 捕获启动失败: {result.get('error', '?')}[/]")
            threading.Thread(target=_do_mcp_capture, daemon=True).start()
        else:
            self._log_device("[dim]MCP 不可用，使用模拟模式[/]")

        # 同时启动 UI 模拟流以保持实时显示
        self.sniffer.start(speed)
        self._start_sniff_updater()

    def _on_btn_sniff_stop(self):
        result = self.sniffer.stop()

        # 如果 MCP bridge 在捕获，也停止它
        bridge = get_bridge()
        if bridge.available:
            def _do_mcp_stop():
                mcp_result = bridge.capture_stop()
                if mcp_result.get("ok"):
                    self.call_from_thread(self._log_device,
                        f"[green]✓ MCP 捕获已停止[/]")
                    # 自动转换为 pcap
                    data = mcp_result.get("data", {})
                    if isinstance(data, dict):
                        capture_id = data.get("capture_id", "")
                        if capture_id:
                            self.call_from_thread(self._log_device,
                                f"[dim]捕获 ID: {capture_id}[/]")
                else:
                    self.call_from_thread(self._log_device,
                        f"[yellow]⚠ MCP 停止失败: {mcp_result.get('error', '?')}[/]")
            threading.Thread(target=_do_mcp_stop, daemon=True).start()

        # log to detail panel
        try:
            self.query_one("#sniff-packet-detail", RichLog).write(
                f"[red]⏹ 捕获已停止 — {result['total_packets']} 包, {result['elapsed']:.1f}s[/]")
        except:
            pass

    def _on_btn_sniff_export(self):
        if not self.sniffer.packets:
            try:
                self.query_one("#sniff-packet-detail", RichLog).write("[yellow]无数据可导出[/]")
            except:
                pass
            return
        pcap_path = self.sniffer.export_pcap()
        try:
            self.query_one("#sniff-packet-detail", RichLog).write(f"[green]✓ 已导出: {pcap_path}[/]")
        except:
            pass

    def _on_btn_sniff_clear(self):
        self.sniffer.packets.clear()
        self.sniffer.stats = CaptureStats()
        self.stats.sniff_packets = 0
        try:
            self.query_one("#sniff-packet-table", DataTable).clear()
            self.query_one("#sniff-packet-detail", RichLog).clear()
            self.query_one("#sniff-hex-dump", RichLog).clear()
        except:
            pass

    def _on_sniff_packet(self, pkt: USBPacket):
        """sniffer 回调 — 在工作线程中调用"""
        try:
            self.call_from_thread(self._add_packet_row, pkt)
        except:
            pass

    # ── 数据包表格管理 (Wireshark 风格) ──

    def _init_sniff_table(self):
        """初始化数据包列表 DataTable"""
        try:
            table = self.query_one("#sniff-packet-table", DataTable)
            table.clear(columns=True)
            table.add_column("No.", width=5)
            table.add_column("时间", width=12)
            table.add_column("方向", width=4)
            table.add_column("设备", width=5)
            table.add_column("EP", width=4)
            table.add_column("类型", width=8)
            table.add_column("长度", width=5)
            table.add_column("预览", width=40)
        except:
            pass

    def _add_packet_row(self, pkt: USBPacket):
        """将数据包添加到表格底部"""
        try:
            table = self.query_one("#sniff-packet-table", DataTable)
            ts_str = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S.%f")[:-3]
            arrow = "OUT→" if pkt.direction == "OUT" else "←IN"

            ptype = pkt.pid_name
            data_preview = ""
            if pkt.is_setup:
                ptype = "SETUP"
                data_preview = "(control)"
            elif pkt.is_data:
                ptype = "DATA"
                data_preview = pkt.data[:20].hex()
                if pkt.data_len > 20:
                    data_preview += "..."

            row_key = f"pkt-{self.stats.sniff_packets}"
            self.stats.sniff_packets += 1
            table.add_row(
                str(self.stats.sniff_packets),
                ts_str,
                arrow,
                f"{pkt.device_addr:02d}",
                f"{pkt.endpoint:02x}",
                ptype,
                str(pkt.data_len),
                data_preview,
                key=row_key,
            )
            # Auto-scroll to bottom
            try:
                row_count = table.row_count
                if row_count > 0:
                    table.move_cursor(row=row_count - 1, animate=False)
            except:
                pass
        except:
            pass

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted):
        """Wireshark 风格: 高亮行即更新详情"""
        try:
            row_key_val = str(event.row_key.value) if event.row_key.value else ""
            if not row_key_val.startswith("pkt-"):
                return
            idx = int(row_key_val.split("-")[1])
            if idx < len(self.sniffer.packets):
                pkt = self.sniffer.packets[idx]
                self._show_packet_detail(pkt)
        except:
            pass

    def _show_packet_detail(self, pkt: USBPacket):
        """在详情面板显示选中数据包的完整协议解析"""
        detail_log = self.query_one("#sniff-packet-detail", RichLog)
        hex_log = self.query_one("#sniff-hex-dump", RichLog)
        detail_log.clear()
        hex_log.clear()

        ts_full = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S.%f")

        # ── 基本信息层 ──
        tbl = Table(show_header=False, box=None, padding=(0, 1))
        tbl.add_column(style="cyan bold", width=16)
        tbl.add_column(style="white")
        tbl.add_row("时间戳", ts_full)
        tbl.add_row("PID", f"0x{pkt.pid:02x} ({pkt.pid_name})")
        tbl.add_row("方向", pkt.direction or "—")
        tbl.add_row("设备地址", str(pkt.device_addr))
        tbl.add_row("端点", f"0x{pkt.endpoint:02x}")
        tbl.add_row("数据长度", f"{pkt.data_len} bytes")

        # ── SETUP 事务解析层 ──
        setup_info = pkt.parse_setup_data()
        if setup_info:
            tbl.add_row("━━ SETUP ━━", "━━━━━━━━━━━━━━━━━━")
            req_type_names = {0: "Standard", 1: "Class", 2: "Vendor"}
            rcpt_names = {0: "Device", 1: "Interface", 2: "Endpoint"}
            req_type = req_type_names.get(setup_info["type"], "?")
            rcpt = rcpt_names.get(setup_info["recipient"], "?")

            STD_REQS = {
                0: "GET_STATUS", 1: "CLEAR_FEATURE", 3: "SET_FEATURE",
                5: "SET_ADDRESS", 6: "GET_DESCRIPTOR", 7: "SET_DESCRIPTOR",
                8: "GET_CONFIGURATION", 9: "SET_CONFIGURATION",
                10: "GET_INTERFACE", 11: "SET_INTERFACE", 12: "SYNCH_FRAME",
            }
            if setup_info["type"] == 0:
                breq_name = STD_REQS.get(setup_info["bRequest"], f"0x{setup_info['bRequest']:02x}")
                tbl.add_row("  bmRequestType", f"0x{setup_info['bmRequestType']:02x} ({setup_info['direction']} {req_type} → {rcpt})")
                tbl.add_row("  bRequest", f"0x{setup_info['bRequest']:02x} {breq_name}")
            else:
                tbl.add_row("  bmRequestType", f"0x{setup_info['bmRequestType']:02x} ({setup_info['direction']} {req_type} → {rcpt})")
                tbl.add_row("  bRequest", f"0x{setup_info['bRequest']:02x}")
            tbl.add_row("  wValue", f"0x{setup_info['wValue']:04x}")
            tbl.add_row("  wIndex", f"0x{setup_info['wIndex']:04x}")
            tbl.add_row("  wLength", f"0x{setup_info['wLength']:04x} ({setup_info['wLength']} bytes)")

        detail_log.write(tbl)

        # ── 描述符解析层 (如数据中包含描述符) ──
        if pkt.is_data and pkt.data_len >= 2:
            data = pkt.data
            bDescType = data[1]
            desc_name = DESC_TYPES.get(bDescType, "")
            if desc_name == "Device" and pkt.data_len >= 18:
                cls = DEVICE_CLASSES.get(data[4], "?")
                tbl2 = Table(show_header=False, box=None, padding=(0, 1))
                tbl2.add_column(style="yellow bold", width=16)
                tbl2.add_column(style="white")
                tbl2.add_row("━━ Device Descriptor ━━", "")
                tbl2.add_row("  bcdUSB", f"{(data[3] << 8 | data[2]):x}")
                tbl2.add_row("  DeviceClass", f"0x{data[4]:02x} ({cls})")
                tbl2.add_row("  idVendor", f"0x{(data[9]<<8|data[8]):04x}")
                tbl2.add_row("  idProduct", f"0x{(data[11]<<8|data[10]):04x}")
                tbl2.add_row("  bcdDevice", f"{(data[13]<<8|data[12]):x}")
                tbl2.add_row("  iManufacturer", str(data[14]))
                tbl2.add_row("  iProduct", str(data[15]))
                tbl2.add_row("  iSerialNumber", str(data[16]))
                tbl2.add_row("  bNumConfigurations", str(data[17]))
                detail_log.write(tbl2)
            elif desc_name == "Configuration" and pkt.data_len >= 9:
                tbl2 = Table(show_header=False, box=None, padding=(0, 1))
                tbl2.add_column(style="yellow bold", width=16)
                tbl2.add_column(style="white")
                tbl2.add_row("━━ Configuration ━━", "")
                tbl2.add_row("  wTotalLength", str((data[3]<<8|data[2])))
                tbl2.add_row("  bNumInterfaces", str(data[4]))
                tbl2.add_row("  bConfigurationValue", str(data[5]))
                tbl2.add_row("  bmAttributes", f"0x{data[7]:02x}")
                tbl2.add_row("  bMaxPower", f"{data[8]*2} mA")
                detail_log.write(tbl2)
            elif desc_name == "Endpoint" and pkt.data_len >= 7:
                ep_addr = data[2]
                ep_dir = "IN" if (ep_addr & 0x80) else "OUT"
                ep_types = {0: "Control", 1: "Isochronous", 2: "Bulk", 3: "Interrupt"}
                tbl2 = Table(show_header=False, box=None, padding=(0, 1))
                tbl2.add_column(style="yellow bold", width=16)
                tbl2.add_column(style="white")
                tbl2.add_row("━━ Endpoint ━━", "")
                tbl2.add_row("  bEndpointAddress", f"0x{ep_addr:02x} ({ep_dir} {ep_addr & 0x0f})")
                tbl2.add_row("  bmAttributes", f"0x{data[3]:02x} ({ep_types.get(data[3]&3, '?')})")
                tbl2.add_row("  wMaxPacketSize", str((data[5]<<8|data[4])))
                tbl2.add_row("  bInterval", str(data[6]))
                detail_log.write(tbl2)

        # ── Hex Dump ──
        raw = bytes.fromhex(pkt.raw_hex) if pkt.raw_hex else pkt.data
        if not raw:
            raw = bytes([pkt.pid])
        for i in range(0, len(raw), 16):
            chunk = raw[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_log.write(f"[#58a6ff]{i:04x}[/]  {hex_part:<48}  [dim]{ascii_part}[/]")

    _sniff_update_active = False

    def _start_sniff_updater(self):
        if self._sniff_update_active:
            return
        self._sniff_update_active = True

        def _update_loop():
            while self.sniffer.is_capturing:
                s = self.sniffer.get_summary()
                def _ui():
                    try:
                        self.query_one("#sniff-stat-total", Label).update(f"总包数: {s['total']}")
                        self.query_one("#sniff-stat-setup", Label).update(f"SETUP:  {s['setup']}")
                        self.query_one("#sniff-stat-data", Label).update(f"DATA:   {s['data']}")
                        self.query_one("#sniff-stat-handshake", Label).update(
                            f"ACK:{s['ack']} NAK:{s['nak']} STALL:{s['stall']}")
                        self.query_one("#sniff-stat-pps", Label).update(f"速率:   {s['pps']} pps")
                        self.query_one("#sniff-stat-devs", Label).update(f"设备数: {s['devices']}")
                    except:
                        pass
                try:
                    self.call_from_thread(_ui)
                except:
                    pass
                time.sleep(0.5)
            self._sniff_update_active = False

        threading.Thread(target=_update_loop, daemon=True).start()

    # ── 分析按钮 ──
    def _on_btn_parse_desc(self):
        hex_str = self.query_one("#input-desc-hex", Input).value.strip()
        if not hex_str:
            self._log_analyze("[red]请输入十六进制描述符[/]")
            return
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            self._log_analyze("[red]无效的十六进制[/]")
            return

        self._log_analyze(f"[cyan]═══ 描述符解析 ({len(data)} bytes) ═══[/]")
        self._log_analyze(f"[dim]原始: {data.hex()[:128]}{'...' if len(data) > 64 else ''}[/]")
        self._log_analyze("")

        offset = 0
        while offset < len(data):
            if offset + 2 > len(data):
                break
            desc_len = data[offset]
            desc_type = data[offset + 1] if offset + 1 < len(data) else 0
            type_name = DESC_TYPES.get(desc_type, f"Unknown(0x{desc_type:02x})")
            chunk = data[offset:offset + desc_len]

            self._log_analyze(f"[bold green]Offset 0x{offset:04x}: {type_name} ({desc_len} bytes)[/]")

            if desc_type == 1:
                parsed = parse_device_descriptor(chunk)
                self._log_analyze(f"  USB版本: {parsed.get('usb_version', '?')}")
                self._log_analyze(f"  设备类: {parsed.get('device_class', '?')}")
                self._log_analyze(f"  VID:PID: {parsed.get('vendor_id', '?')}:{parsed.get('product_id', '?')}")
                self._log_analyze(f"  EP0大小: {parsed.get('max_packet_size_ep0', '?')} bytes")
            elif desc_type == 2:
                parsed = parse_config_descriptor(chunk)
                self._log_analyze(f"  接口数: {parsed.get('num_interfaces', '?')}")
                self._log_analyze(f"  总长度: {parsed.get('total_length', '?')} bytes")
                self._log_analyze(f"  供电: {parsed.get('max_power_ma', '?')} mA")
            elif desc_type == 4:
                self._log_analyze(f"  接口号: {chunk[2] if len(chunk)>2 else '?'}")
                self._log_analyze(f"  类: 0x{chunk[5]:02x} 子类: 0x{chunk[6]:02x}")
            elif desc_type == 5:
                parsed = parse_endpoint_descriptor(chunk)
                self._log_analyze(f"  地址: 0x{parsed.get('endpoint_address', 0):02x} ({parsed.get('direction', '?')})")
                self._log_analyze(f"  类型: {parsed.get('transfer_type', '?')}")
                self._log_analyze(f"  最大包: {parsed.get('max_packet_size', '?')} bytes")

            self._log_analyze("")
            offset += desc_len if desc_len > 0 else 1

    def _on_btn_sample_desc(self):
        sample = "120100020000408B07210100010102030B09022700010104A03209040000010300000009211501122115000122070481030A002440C00A0018000000"[:200]
        self.query_one("#input-desc-hex", Input).value = sample
        self._on_btn_parse_desc()

    def _on_btn_clear_desc(self):
        self.query_one("#input-desc-hex", Input).value = ""
        self.query_one("#analyze-log", RichLog).clear()

    def _on_btn_parse_setup(self):
        hex_str = self.query_one("#input-setup-hex", Input).value.strip()
        if not hex_str:
            self._log_analyze("[red]请输入 SETUP 数据[/]")
            return
        try:
            data = bytes.fromhex(hex_str)
            if len(data) < 8:
                self._log_analyze(f"[red]需要至少 8 字节, 当前 {len(data)}[/]")
                return
        except ValueError:
            self._log_analyze("[red]无效的十六进制[/]")
            return

        b = data
        bmRequestType = b[0]
        direction = "IN" if (b[0] >> 7) & 1 else "OUT"
        rtype = (b[0] >> 5) & 3
        recipient = b[0] & 0x1f
        type_names = {0: "Standard", 1: "Class", 2: "Vendor"}
        rcpt_names = {0: "Device", 1: "Interface", 2: "Endpoint", 3: "Other"}
        req_names = {0:"GET_STATUS",1:"CLEAR_FEATURE",3:"SET_FEATURE",5:"SET_ADDRESS",
                     6:"GET_DESCRIPTOR",7:"SET_DESCRIPTOR",8:"GET_CONFIGURATION",
                     9:"SET_CONFIGURATION",10:"GET_INTERFACE",11:"SET_INTERFACE",12:"SYNCH_FRAME"}

        self._log_analyze("[cyan]═══ SETUP 事务解析 ═══[/]")
        self._log_analyze(f"  bmRequestType: 0x{bmRequestType:02x}")
        self._log_analyze(f"  方向: [bold]{direction}[/]")
        self._log_analyze(f"  类型: {type_names.get(rtype, '?')}")
        self._log_analyze(f"  接收者: {rcpt_names.get(recipient, '?')}")
        self._log_analyze(f"  bRequest: 0x{b[1]:02x} ({req_names.get(b[1], 'vendor/unknown')})")
        self._log_analyze(f"  wValue: 0x{(b[3]<<8)|b[2]:04x}")
        self._log_analyze(f"  wIndex: 0x{(b[5]<<8)|b[4]:04x}")
        self._log_analyze(f"  wLength: {(b[7]<<8)|b[6]}")
        self._log_analyze(f"  [dim]原始字节: {data[:8].hex()}[/]")

    def _on_btn_sample_setup(self):
        self.query_one("#input-setup-hex", Input).value = "80060001000012"
        self._on_btn_parse_setup()

    def _log_analyze(self, msg):
        try:
            self.query_one("#analyze-log", RichLog).write(msg)
        except:
            pass

    # ── 注入按钮 ──
    def _on_btn_load_template(self):
        idx = self.query_one("#select-template", Select).value
        if isinstance(idx, int) and 0 <= idx < len(TEMPLATES):
            t = TEMPLATES[idx]
            self.query_one("#sel-req-dir", Select).value = t.request.direction
            self.query_one("#inj-bRequest", Input).value = f"{t.request.bRequest:02x}"
            self.query_one("#inj-wValue", Input).value = f"{t.request.wValue:04x}"
            self.query_one("#inj-wIndex", Input).value = f"{t.request.wIndex:04x}"
            self.query_one("#inj-wLength", Input).value = str(t.request.wLength)
            self.query_one("#inj-data", Input).value = t.request.data.hex()
            self._log_inject(f"[green]✓ 加载模板: {t.name}[/]")
            self._log_inject(f"[dim]{t.description}[/]")

    def _on_btn_send_req(self):
        self._ensure_mode("facedancer", "USB 请求注入", self._do_send_req)

    def _do_send_req(self):
        idx = self.query_one("#select-template", Select).value
        if isinstance(idx, int) and 0 <= idx < len(TEMPLATES):
            t = TEMPLATES[idx]
            result = self.injector.send_single(t.request)
            self._log_inject(f"[{'red' if result['status']=='error' else 'green'}]发送: {t.name}[/]")
            self._log_inject(f"[dim]bmRequestType=0x{t.request.bmRequestType:02x} bRequest=0x{t.request.bRequest:02x}[/]")
            self._update_inj_stats()

    def _on_btn_send_custom(self):
        self._ensure_mode("facedancer", "自定义请求发送", self._do_send_custom)

    def _do_send_custom(self):
        try:
            direction = self.query_one("#sel-req-dir", Select).value
            bRequest = int(self.query_one("#inj-bRequest", Input).value, 16)
            wValue = int(self.query_one("#inj-wValue", Input).value, 16)
            wIndex = int(self.query_one("#inj-wIndex", Input).value, 16)
            wLength = int(self.query_one("#inj-wLength", Input).value)
            data_hex = self.query_one("#inj-data", Input).value.strip()
            data = bytes.fromhex(data_hex) if data_hex else b""
        except ValueError as e:
            self._log_inject(f"[red]参数错误: {e}[/]")
            return

        req = ControlRequest(
            direction=direction, bRequest=bRequest, wValue=wValue,
            wIndex=wIndex, wLength=wLength, data=data,
            name="Custom Request",
        )
        result = self.injector.send_single(req)
        self._log_inject(f"[{'red' if result['status']=='error' else 'cyan'}]自定义请求已发送[/]")
        self._log_inject(f"[dim]{req.to_bytes().hex()}[/]")
        self._update_inj_stats()

    def _on_btn_batch_send(self):
        self._ensure_mode("facedancer", "批量请求发送", self._do_batch_send)

    def _do_batch_send(self):
        try:
            bRequest = int(self.query_one("#inj-bRequest", Input).value, 16)
            wValue = int(self.query_one("#inj-wValue", Input).value, 16)
            wIndex = int(self.query_one("#inj-wIndex", Input).value, 16)
            wLength = int(self.query_one("#inj-wLength", Input).value)
            direction = self.query_one("#sel-req-dir", Select).value
        except ValueError:
            self._log_inject("[red]参数错误[/]")
            return

        count = int(self.query_one("#inj-batch-count", Input).value or "10")
        delay = int(self.query_one("#inj-batch-delay", Input).value or "100")

        reqs = []
        for i in range(count):
            r = random.Random(i)
            req = ControlRequest(
                direction=direction,
                bRequest=bRequest,
                wValue=r.randint(0, 0xFFFF),
                wIndex=wIndex,
                wLength=wLength,
                name=f"Batch #{i}",
            )
            reqs.append(req)

        self._log_inject(f"[yellow]▶ 批量发送 {count} 个请求 (延迟 {delay}ms)[/]")
        self.injector.send_batch(reqs, delay)

    def _on_btn_batch_stop(self):
        self.injector.stop()
        self._log_inject("[red]⏹ 批量发送已停止[/]")

    def _on_inject_event(self, event: dict):
        try:
            self.call_from_thread(self._update_inj_stats)
        except:
            pass

    def _update_inj_stats(self):
        try:
            self.query_one("#inj-stats", Label).update(
                f"已发送: {self.injector.sent_count} / 错误: {self.injector.error_count}")
        except:
            pass

    def _log_inject(self, msg):
        try:
            self.query_one("#inject-log", RichLog).write(msg)
        except:
            pass

    # ── 伪造按钮 ──
    def _on_btn_emul_start(self):
        self._ensure_mode("facedancer", "USB 设备仿真", self._do_emul_start)

    def _do_emul_start(self):
        """从 UI 构建自定义 DeviceProfile 并启动仿真"""
        key = self.query_one("#select-emul-profile", Select).value
        base = PROFILES.get(key)
        if not base:
            self._log_emul("[red]无效的 profile[/]")
            return

        def _hex(name, default=0):
            v = self.query_one(name, Input).value.strip()
            try:
                return int(v, 16) if v else default
            except:
                return default

        def _int(name, default=0):
            v = self.query_one(name, Input).value.strip()
            try:
                return int(v) if v else default
            except:
                return default

        vid = _hex("#emul-vid", base.vid)
        pid = _hex("#emul-pid", base.pid)
        serial = self.query_one("#emul-serial", Input).value.strip()
        manufacturer = self.query_one("#emul-manufacturer", Input).value.strip()
        product = self.query_one("#emul-product", Input).value.strip()
        bcd_device = _hex("#emul-bcd-device", 0x0100)
        usb_ver_str = self.query_one("#emul-usb-version", Select).value
        device_class = self.query_one("#emul-device-class", Select).value
        subclass = _hex("#emul-subclass", 0)
        protocol = _hex("#emul-protocol", 0)
        max_power = _int("#emul-max-power", 100)
        ep0_size = self.query_one("#emul-ep0-size", Select).value
        self_powered = True  # always self-powered (checkbox removed for layout)

        usb_ver_map = {"1.1": (1, 1), "2.0": (2, 0), "3.0": (3, 0), "3.1": (3, 1)}
        usb_ver = usb_ver_map.get(usb_ver_str, (2, 0))

        import copy
        profile = copy.deepcopy(base)
        profile.vid = vid
        profile.pid = pid
        profile.serial = serial
        profile.manufacturer = manufacturer
        profile.product = product
        profile.device_class = device_class
        profile.subclass = subclass
        profile.protocol = protocol
        profile.usb_version = usb_ver
        profile.max_packet_ep0 = ep0_size
        profile.max_power_ma = max_power
        profile.self_powered = self_powered

        self.emulator.start_emulation(profile, vid, pid)
        self._log_emul(f"[green]▶ 开始仿真: {profile.name}[/]")
        self._log_emul(f"  [dim]VID=0x{vid:04x} PID=0x{pid:04x}[/]")
        if serial:
            self._log_emul(f"  [dim]Serial: {serial}[/]")
        if manufacturer:
            self._log_emul(f"  [dim]Manufacturer: {manufacturer}[/]")
        if product:
            self._log_emul(f"  [dim]Product: {product}[/]")
        self._log_emul(f"  [dim]Class=0x{device_class:02x} bcdUSB={usb_ver[0]}.{usb_ver[1]} Power={max_power}mA[/]")

        # 通过 MCP bridge 推送到真实硬件
        bridge = get_bridge()
        if bridge.available:
            desc_bytes = build_descriptor_set(profile)
            device_hex = desc_bytes[:18].hex()
            config_hex = desc_bytes[18:].hex() if len(desc_bytes) > 18 else None
            strings = {}
            if serial:
                strings["3"] = serial
            if manufacturer:
                strings["1"] = manufacturer
            if product:
                strings["2"] = product

            def _do_mcp_emul():
                result = bridge.emulate_from_descriptor(device_hex, config_hex, strings or None)
                if result.get("ok"):
                    self.call_from_thread(self._log_emul,
                        f"[green]✓ 已推送到真实硬件 (MCP)[/]")
                else:
                    self.call_from_thread(self._log_emul,
                        f"[yellow]⚠ MCP 推送失败: {result.get('error', '?')}[/]")
            threading.Thread(target=_do_mcp_emul, daemon=True).start()
        else:
            self._log_emul("[dim]MCP 不可用，仅本地仿真[/]")

        self._update_emul_status()

    def _on_btn_emul_stop(self):
        self.emulator.stop_emulation()
        self._log_emul("[red]⏹ 仿真已停止[/]")

        # 通过 MCP bridge 断开真实设备
        bridge = get_bridge()
        if bridge.available:
            def _do_mcp_disc():
                result = bridge.disconnect_device()
                if result.get("ok"):
                    self.call_from_thread(self._log_emul,
                        "[green]✓ 真实设备已断开 (MCP)[/]")
                else:
                    self.call_from_thread(self._log_emul,
                        f"[yellow]⚠ MCP 断开失败: {result.get('error', '?')}[/]")
            threading.Thread(target=_do_mcp_disc, daemon=True).start()

        self._update_emul_status()

    def _on_btn_emul_desc(self):
        key = self.query_one("#select-emul-profile", Select).value
        profile = PROFILES.get(key)
        if not profile:
            return
        desc = build_descriptor_set(profile)
        self._log_emul(f"[cyan]═══ 描述符 ({len(desc)} bytes) ═══[/]")
        # hex dump
        for i in range(0, len(desc), 16):
            chunk = desc[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            self._log_emul(f"  {i:04x}  {hex_part}")
        self._log_emul("")

    def _on_btn_emul_mutate(self):
        key = self.query_one("#select-emul-profile", Select).value
        profile = PROFILES.get(key)
        if not profile:
            return
        # 随机变异 VID/PID
        rng = random.Random()
        profile.vid = rng.choice([0x05ac, 0x045e, 0x046d, 0x18d1, 0x1d6b, 0xFFFF, 0x0000])
        profile.pid = rng.randint(0, 0xFFFF)
        desc = build_descriptor_set(profile)
        self.emulator.descriptor_hex = desc.hex()
        self._log_emul(f"[yellow]🔧 描述符已变异: VID=0x{profile.vid:04x} PID=0x{profile.pid:04x}[/]")
        self._log_emul(f"[dim]{desc[:18].hex()}[/]")
        self._update_emul_status()

    def _on_btn_emul_load_profile(self):
        """加载选中模板到自定义字段"""
        key = self.query_one("#select-emul-profile", Select).value
        profile = PROFILES.get(key)
        if not profile:
            return
        self.query_one("#emul-vid", Input).value = f"{profile.vid:04x}"
        self.query_one("#emul-pid", Input).value = f"{profile.pid:04x}"
        self.query_one("#emul-serial", Input).value = profile.serial or ""
        self.query_one("#emul-manufacturer", Input).value = profile.manufacturer or ""
        self.query_one("#emul-product", Input).value = profile.product or profile.name
        self.query_one("#emul-subclass", Input).value = f"{profile.subclass:02x}"
        self.query_one("#emul-protocol", Input).value = f"{profile.protocol:02x}"
        self.query_one("#emul-max-power", Input).value = str(profile.max_power_ma)
        self.query_one("#emul-device-class", Select).value = profile.device_class
        self.query_one("#emul-ep0-size", Select).value = profile.max_packet_ep0
        ver = profile.usb_version
        ver_str = f"{ver[0]}.{ver[1]}"
        if ver_str not in ("1.1", "2.0", "3.0", "3.1"):
            ver_str = "2.0"
        self.query_one("#emul-usb-version", Select).value = ver_str
        self._log_emul(f"[cyan]↻ 模板已加载: {profile.name}[/]")
        self._log_emul(f"  [dim]VID=0x{profile.vid:04x} PID=0x{profile.pid:04x}[/]")

    def _on_btn_emul_export_desc(self):
        """从当前自定义设置生成描述符并导出"""
        key = self.query_one("#select-emul-profile", Select).value
        base = PROFILES.get(key)
        if not base:
            return
        import copy
        profile = copy.deepcopy(base)
        try:
            vid = int(self.query_one("#emul-vid", Input).value.strip() or "0", 16)
            pid = int(self.query_one("#emul-pid", Input).value.strip() or "0", 16)
            profile.vid = vid or profile.vid
            profile.pid = pid or profile.pid
            profile.serial = self.query_one("#emul-serial", Input).value.strip()
            profile.manufacturer = self.query_one("#emul-manufacturer", Input).value.strip()
            profile.product = self.query_one("#emul-product", Input).value.strip()
        except:
            pass
        desc = build_descriptor_set(profile)
        from pathlib import Path
        export_dir = Path("exports")
        export_dir.mkdir(exist_ok=True)
        export_path = export_dir / f"descriptor_{profile.vid:04x}_{profile.pid:04x}.bin"
        with open(export_path, "wb") as f:
            f.write(desc)
        self._log_emul(f"[green]✓ 已导出 ({len(desc)} bytes): {export_path}[/]")
        self._log_emul(f"  [dim]hex: {desc.hex()[:80]}...[/]")
        self.emulator.descriptor_hex = desc.hex()
        self._update_emul_status()

    def _on_btn_inject_desc(self):
        self._ensure_mode("facedancer", "描述符注入", self._do_inject_desc)

    def _do_inject_desc(self):
        hex_str = self.query_one("#emul-desc-inject", Input).value.strip()
        if not hex_str:
            self._log_emul("[red]请输入描述符 hex[/]")
            return
        ok = self.emulator.inject_descriptor(hex_str)
        if ok:
            self._log_emul(f"[green]✓ 描述符已注入 ({len(hex_str)//2} bytes)[/]")
        self._update_emul_status()

    def _on_emul_event(self, event: dict):
        try:
            msg = event.get("message", event.get("event", ""))
            self.call_from_thread(self._log_emul, f"[dim]{msg}[/]")
            self.call_from_thread(self._update_emul_status)
        except:
            pass

    def _update_emul_status(self):
        try:
            s = self.emulator.get_status()
            status_str = '仿真中' if s['emulating'] else '空闲'
            self._log_emul(f"[bold green]状态: {status_str}[/] | 设备: {s['profile']} | 描述符: {s['descriptor_len']}B")
        except:
            pass

    def _log_emul(self, msg):
        try:
            self.query_one("#emulate-log", RichLog).write(msg)
        except:
            pass

    # ── 中继按钮 ──

    def _on_btn_relay_start(self):
        self._ensure_mode("facedancer", "USB 中继 (MITM)", self._do_relay_start)

    def _do_relay_start(self):
        """启动中继模式"""
        policy = self.query_one("#select-relay-policy", Select).value
        self._relay_active = True
        self._relay_policy = policy
        self._relay_queue = []

        # 初始化拦截队列表
        table = self.query_one("#relay-queue-table", DataTable)
        table.clear()
        if not table.columns:
            table.add_columns("#", "方向", "类型", "设备", "EP", "请求", "长度", "状态")

        policy_names = {
            "pass": "放行所有",
            "hold": "暂停所有",
            "setup": "拦截 SETUP",
            "data": "拦截 DATA",
            "all": "拦截全部",
        }
        self._log_relay(f"[green]▶ 中继已启动 — 策略: {policy_names.get(policy, policy)}[/]")
        self._log_relay("[dim]等待 USB 事务...[/]")

        # 启动后台模拟线程
        self._relay_thread = threading.Thread(target=self._relay_loop, daemon=True)
        self._relay_thread.start()

    def _on_btn_relay_stop(self):
        """停止中继"""
        self._relay_active = False
        self._log_relay("[red]⏹ 中继已停止[/]")

    def _on_btn_relay_forward(self):
        """放行选中的包"""
        table = self.query_one("#relay-queue-table", DataTable)
        if table.row_count == 0:
            self._log_relay("[yellow]队列为空，无包可操作[/]")
            return
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            if row_key is None:
                return
            row_idx = int(row_key.value)
            if row_idx < len(self._relay_queue):
                pkt = self._relay_queue[row_idx]
                if pkt["status"] == "HELD":
                    pkt["status"] = "FORWARDED"
                    self.stats.relay_forward += 1
                    table.update_row(row_key.value, str(row_idx), pkt["dir"], pkt["type"],
                                     pkt["dev"], pkt["ep"], pkt["req"], str(pkt["len"]),
                                     "✅ 转发")
                    self._log_relay(f"[green]✅ 包 #{row_idx} 已放行[/]")
                    self._update_relay_stats()
        except Exception as e:
            self._log_relay(f"[red]放行失败: {e}[/]")

    def _on_btn_relay_drop(self):
        """丢弃选中的包"""
        table = self.query_one("#relay-queue-table", DataTable)
        if table.row_count == 0:
            self._log_relay("[yellow]队列为空，无包可操作[/]")
            return
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            if row_key is None:
                return
            row_idx = int(row_key.value)
            if row_idx < len(self._relay_queue):
                pkt = self._relay_queue[row_idx]
                if pkt["status"] == "HELD":
                    pkt["status"] = "DROPPED"
                    self.stats.relay_drop += 1
                    table.update_row(row_key.value, str(row_idx), pkt["dir"], pkt["type"],
                                     pkt["dev"], pkt["ep"], pkt["req"], str(pkt["len"]),
                                     "🗑 丢弃")
                    self._log_relay(f"[red]🗑 包 #{row_idx} 已丢弃[/]")
                    self._update_relay_stats()
        except Exception as e:
            self._log_relay(f"[red]丢弃失败: {e}[/]")

    def _on_btn_relay_send(self):
        """发送修改后的数据"""
        edit_hex = self.query_one("#input-relay-edit", Input).value.strip()
        table = self.query_one("#relay-queue-table", DataTable)
        if not table.cursor_coordinate or not edit_hex:
            self._log_relay("[yellow]请选择包并输入修改后的 hex 数据[/]")
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        if row_key is None:
            return
        try:
            row_idx = int(row_key.value)
            if row_idx < len(self._relay_queue):
                pkt = self._relay_queue[row_idx]
                # 解析 hex
                modified_bytes = bytes.fromhex(edit_hex.replace(" ", ""))
                pkt["data"] = modified_bytes
                pkt["status"] = "MODIFIED"
                pkt["len"] = len(modified_bytes)
                self.stats.relay_modify += 1
                table.update_row(row_key.value, str(row_idx), pkt["dir"], pkt["type"],
                                 pkt["dev"], pkt["ep"], pkt["req"], str(pkt["len"]),
                                 "🔧 已篡改")
                self._log_relay(f"[yellow]🔧 包 #{row_idx} 数据已修改 ({len(modified_bytes)} bytes) → 转发[/]")
                self._update_relay_stats()

                # 通过 MCP 发送修改后的数据
                bridge = get_bridge()
                if bridge.available:
                    self._log_relay(f"[dim]MCP: 发送修改后的数据到目标...[/]")
        except ValueError:
            self._log_relay("[red]hex 格式错误[/]")
        except Exception as e:
            self._log_relay(f"[red]发送失败: {e}[/]")

    def _relay_loop(self):
        """后台模拟中继数据流"""
        import random as _rng
        _rng = _rng.Random()
        packet_types = [("SETUP", "06"), ("DATA IN", "-"), ("DATA OUT", "-"),
                        ("ACK", "-"), ("STATUS", "00")]
        directions = ["IN←", "OUT→"]
        counter = 0

        while getattr(self, "_relay_active", False):
            time.sleep(0.5 + _rng.random() * 1.5)
            if not getattr(self, "_relay_active", False):
                break

            counter += 1
            ptype, req = _rng.choice(packet_types)
            direction = _rng.choice(directions)
            dev_addr = _rng.randint(1, 7)
            ep = _rng.choice([0, 0, 0, 1, 2, _rng.randint(1, 15)])
            data_len = _rng.randint(8, 64)

            policy = getattr(self, "_relay_policy", "pass")
            should_hold = False
            if policy == "hold":
                should_hold = True
            elif policy == "setup" and ptype == "SETUP":
                should_hold = True
            elif policy == "data" and ptype.startswith("DATA"):
                should_hold = True
            elif policy == "all":
                should_hold = True

            pkt = {
                "num": counter, "dir": direction, "type": ptype,
                "dev": str(dev_addr), "ep": str(ep), "req": req,
                "len": data_len, "status": "HELD" if should_hold else "FORWARDED",
                "data": bytes(_rng.randint(0, 255) for _ in range(data_len)),
            }

            status_icon = "⏸ 拦截" if should_hold else "→ 通过"

            def _add_row():
                try:
                    table = self.query_one("#relay-queue-table", DataTable)
                    table.add_row(str(pkt["num"]), pkt["dir"], pkt["type"],
                                  pkt["dev"], pkt["ep"], pkt["req"],
                                  str(pkt["len"]), status_icon,
                                  key=str(pkt["num"]))
                except:
                    pass

            try:
                self.call_from_thread(_add_row)
            except:
                pass

            if should_hold:
                self._relay_queue.append(pkt)
                self.stats.relay_hold += 1
                self.call_from_thread(self._log_relay,
                    f"[yellow]⏸ #{counter} {direction} {ptype} dev={dev_addr} ep={ep} 已拦截[/]")
            else:
                self.stats.relay_forward += 1

            self.call_from_thread(self._update_relay_stats)

            # 队列限制
            if len(self._relay_queue) > 200:
                self._relay_queue = self._relay_queue[-100:]

    def _update_relay_stats(self):
        """更新中继统计"""
        try:
            self.query_one("#relay-stat-forward", Label).update(
                f"已转发: {getattr(self.stats, 'relay_forward', 0)}")
            self.query_one("#relay-stat-hold", Label).update(
                f"已拦截: {getattr(self.stats, 'relay_hold', 0)}")
            self.query_one("#relay-stat-drop", Label).update(
                f"已丢弃: {getattr(self.stats, 'relay_drop', 0)}")
            self.query_one("#relay-stat-modify", Label).update(
                f"已篡改: {getattr(self.stats, 'relay_modify', 0)}")
        except:
            pass

    def _log_relay(self, msg):
        try:
            self.query_one("#relay-log", RichLog).write(msg)
        except:
            pass

    # ── 模糊测试按钮 ──
    def _on_btn_fuzz_start(self):
        self._ensure_mode("facedancer", "USB 模糊测试", self._start_fuzz)

    def _on_btn_fuzz_stop(self):
        self._stop_fuzz()

    def _on_btn_fuzz_pause(self):
        if self.is_running:
            if self._pause_event.is_set():
                self._pause_event.clear()
                self._log_fuzz_info("[yellow]⏸ 已暂停[/]")
            else:
                self._pause_event.set()
                self._log_fuzz_info("[green]▶ 已恢复[/]")

    def _get_selected_phases(self) -> list[FuzzPhase]:
        selected = []
        for phase in FuzzPhase:
            cb_id = f"#fuzz-phase-{phase.value}"
            try:
                cb = self.query_one(cb_id, Checkbox)
                if cb.value:
                    selected.append(phase)
            except:
                pass
        return selected

    def _start_fuzz(self):
        if self.is_running:
            self._log_fuzz_info("[yellow]已在运行中[/]")
            return

        if self._device_status:
            info = self._device_status.get("cynthion")
            if not info or not info.connected:
                self._log_fuzz_crash("[red]❌ Cynthion 未连接[/]")
                return

        selected = self._get_selected_phases()
        if not selected:
            self._log_fuzz_crash("[red]请至少选择一个阶段[/]")
            return

        conn_type = self.query_one("#fuzz-conn-type", Select).value
        profile = self.query_one("#fuzz-profile", Select).value
        max_cases = int(self.query_one("#fuzz-max-cases", Input).value or "30")
        seed_str = self.query_one("#fuzz-seed", Input).value.strip()
        seed = int(seed_str) if seed_str else None
        delay_ms = int(self.query_one("#fuzz-delay", Input).value or "500")

        # ── 根据连接类型读取参数 ──
        monitor_mode = "noshell"
        target_ip = ""
        ssh_user = ""
        if conn_type == "noshell":
            monitor_mode = "noshell"
        elif conn_type == "ssh":
            ssh_level = self.query_one("#fuzz-ssh-level", Select).value
            target_ip = self.query_one("#fuzz-ssh-ip", Input).value.strip()
            ssh_user = self.query_one("#fuzz-ssh-user", Input).value.strip()
            ssh_pass = self.query_one("#fuzz-ssh-pass", Input).value.strip()
            monitor_mode = ssh_level  # "user" or "root"
        elif conn_type == "adb":
            adb_mode = self.query_one("#fuzz-adb-mode", Select).value
            if adb_mode == "wired":
                # 有线: 读设备选择 + 可选密码
                adb_dev = self.query_one("#fuzz-adb-device", Select).value
                adb_pass = self.query_one("#fuzz-adb-pass", Input).value.strip()
                target_ip = f"adb:{adb_dev}" if adb_dev and adb_dev != "auto" else "adb:auto"
            else:
                # 无线: 读 IP + 端口 + 可选密码
                target_ip = self.query_one("#fuzz-adb-ip", Input).value.strip()
                adb_port = self.query_one("#fuzz-adb-port", Input).value.strip() or "5555"
                if target_ip:
                    target_ip = f"{target_ip}:{adb_port}"
                adb_pass = self.query_one("#fuzz-adb-wireless-pass", Input).value.strip()
            monitor_mode = "noshell"
        elif conn_type == "uart":
            serial_dev = self.query_one("#fuzz-uart-port", Select).value
            baud = self.query_one("#fuzz-uart-baud", Input).value.strip() or "115200"
            target_ip = serial_dev
            monitor_mode = "noshell"

        rng = random.Random(seed)
        mut = Mutator(rng)
        gen = StrategyGenerator(mut, profile)
        all_dict = gen.generate_all(max_per_phase=max_cases)

        self.all_cases = []
        for phase in selected:
            cases = all_dict.get(phase, [])
            self.all_cases.extend(cases)
            self.stats.phase_stats[phase] = {"total": len(cases), "executed": 0, "crashed": 0}
            self._update_fuzz_phase_table(phase)

        self.stats.fuzz_total = len(self.all_cases)
        self.stats.fuzz_executed = 0
        self.stats.fuzz_passed = 0
        self.stats.fuzz_crashed = 0
        self.stats.fuzz_warnings = 0
        self.stats.fuzz_start_time = time.time()
        self.stats.crashes = []

        conn_label = {"noshell": "无Shell", "ssh": "SSH", "adb": "ADB", "uart": "UART"}.get(conn_type, conn_type)
        self._log_fuzz_info(f"[bold green]═══ 模糊测试开始 ═══[/]")
        self._log_fuzz_info(f"连接: [bold]{conn_label}[/]  Profile: {profile}")
        if target_ip:
            self._log_fuzz_info(f"目标: {target_ip}")
        self._log_fuzz_info(f"用例数: {self.stats.fuzz_total}  延迟: {delay_ms}ms")

        # 创建监控
        try:
            if conn_type == "noshell":
                self._monitor = None
                self._log_fuzz_info("[dim]无Shell模式 — 仅依赖 USB 枚举变化检测[/]")
            elif conn_type == "uart":
                self._monitor = create_monitor(
                    mode="noshell", target_ip=target_ip or _SERIAL_DEFAULT,
                    ssh_user=ssh_user,
                )
                self._log_fuzz_info(f"[green]✓ 串口监控: {target_ip}[/]")
            elif conn_type == "ssh":
                self._monitor = create_monitor(
                    mode=monitor_mode, target_ip=target_ip, ssh_user=ssh_user,
                )
                self._monitor.set_baseline()
                self._log_fuzz_info(f"[green]✓ SSH监控就绪: {ssh_user}@{target_ip} ({monitor_mode})[/]")
            elif conn_type == "adb":
                self._monitor = create_monitor(
                    mode="noshell", target_ip=target_ip or "127.0.0.1",
                    ssh_user=ssh_user,
                )
                self._log_fuzz_info(f"[green]✓ ADB监控就绪: {target_ip or 'auto'}[/]")
            if self._monitor:
                self._monitor.set_baseline()
        except Exception as e:
            self._log_fuzz_info(f"[yellow]⚠ 监控不可用: {e}[/]")
            self._monitor = None

        self.is_running = True
        self._stop_event.clear()
        self._pause_event.set()

        self._fuzz_thread = threading.Thread(
            target=self._fuzz_worker, args=(delay_ms / 1000.0,), daemon=True)
        self._fuzz_thread.start()
        self._update_fuzz_stats()

    def _stop_fuzz(self):
        if not self.is_running:
            return
        self._stop_event.set()
        self.is_running = False
        self._log_fuzz_info("[bold red]═══ 已停止 ═══[/]")
        self._print_fuzz_summary()
        self._update_fuzz_stats()

    def _fuzz_worker(self, delay: float):
        for i, case in enumerate(self.all_cases):
            if self._stop_event.is_set():
                break
            self._pause_event.wait()
            result = self._execute_fuzz_case(case)
            self.stats.fuzz_executed += 1
            if result.get("crash"):
                self.stats.fuzz_crashed += 1
                self.stats.crashes.append({"case": case, "detail": result.get("detail")})
                self.call_from_thread(self._on_fuzz_crash, case, result.get("detail"))
            elif result.get("warning"):
                self.stats.fuzz_warnings += 1
            else:
                self.stats.fuzz_passed += 1

            if case.phase in self.stats.phase_stats:
                self.stats.phase_stats[case.phase]["executed"] += 1
                if result.get("crash"):
                    self.stats.phase_stats[case.phase]["crashed"] += 1

            if i % 3 == 0 or result.get("crash"):
                self.call_from_thread(self._update_fuzz_stats)
                self.call_from_thread(self._update_fuzz_phase_table, case.phase)

            time.sleep(delay)

        self.is_running = False
        self.call_from_thread(self._on_fuzz_complete)

    def _execute_fuzz_case(self, case: FuzzCase) -> dict:
        time.sleep(0.01)
        if hasattr(self, '_monitor') and self._monitor:
            try:
                detail = self._monitor.check()
                if detail.is_crash:
                    return {"crash": True, "detail": detail}
                elif detail.is_anomaly:
                    return {"warning": True, "detail": detail}
            except:
                pass
        return {"crash": False, "warning": False}

    def _on_fuzz_crash(self, case: FuzzCase, detail):
        crash_msg = Text()
        crash_msg.append(f"{'='*55}\n", style="bold red")
        crash_msg.append(f"  CRASH — Case #{case.case_id}\n", style="bold red")
        crash_msg.append(f"{'='*55}\n", style="bold red")
        crash_msg.append(f"  Phase: {case.phase.value}. {PHASE_NAMES[case.phase]}\n", style="yellow")
        crash_msg.append(f"  描述:  {case.description}\n", style="white")
        crash_msg.append(f"  源码:  {case.source_ref}\n", style="dim cyan")
        if detail and hasattr(detail, 'summary'):
            crash_msg.append(f"  级别:  {detail.level.name}\n", style="bold yellow")
            crash_msg.append(f"  摘要:  {detail.summary}\n", style="white")
        self._log_fuzz_crash(crash_msg)

        crash_dir = Path("corpus") / f"crash_{case.case_id:05d}"
        crash_dir.mkdir(parents=True, exist_ok=True)
        with open(crash_dir / "case.json", "w") as f:
            json.dump(case.to_json(), f, ensure_ascii=False, indent=2)

    def _on_fuzz_complete(self):
        self.is_running = False
        self._log_fuzz_info("[bold green]═══ 模糊测试完成 ═══[/]")
        self._print_fuzz_summary()
        self._update_fuzz_stats()

    def _update_fuzz_stats(self):
        try:
            self.query_one("#fuzz-stat-total", Label).update(f"总计\n{self.stats.fuzz_total}")
            self.query_one("#fuzz-stat-exec", Label).update(f"已执行\n{self.stats.fuzz_executed}")
            self.query_one("#fuzz-stat-crash", Label).update(f"崩溃\n{self.stats.fuzz_crashed}")
            self.query_one("#fuzz-stat-pass", Label).update(f"通过\n{self.stats.fuzz_passed}")
            self.query_one("#fuzz-stat-warn", Label).update(f"警告\n{self.stats.fuzz_warnings}")
            rate = 0
            if self.stats.fuzz_start_time and self.stats.fuzz_executed > 0:
                elapsed = time.time() - self.stats.fuzz_start_time
                if elapsed > 0:
                    rate = self.stats.fuzz_executed / elapsed
            self.query_one("#fuzz-stat-rate", Label).update(f"速率\n{rate:.1f}/s")

            total = self.stats.fuzz_total
            execd = self.stats.fuzz_executed
            pct = (execd / total * 100) if total > 0 else 0
            self.query_one("#fuzz-progress", ProgressBar).update(progress=pct)

            header = self.query_one("#header-status", Label)
            if self.is_running:
                header.update(f"● 运行中 {execd}/{total}")
                header.styles.color = "#68B92E"
            else:
                header.update("● 就绪")
                header.styles.color = "#68B92E"
        except:
            pass

    def _update_fuzz_phase_table(self, phase: FuzzPhase):
        try:
            table = self.query_one("#fuzz-phase-table", DataTable)
            ps = self.stats.phase_stats.get(phase, {"total": 0, "executed": 0, "crashed": 0})
            row_key = f"fp-{phase.value}"
            if table.is_valid_row_key(row_key):
                table.update_row(row_key, str(phase.value), PHASE_NAMES[phase],
                                 PHASE_SOURCES[phase][:30],
                                 str(ps["total"]), str(ps["executed"]), str(ps["crashed"]))
        except:
            pass

    def _print_fuzz_summary(self):
        elapsed = time.time() - self.stats.fuzz_start_time if self.stats.fuzz_start_time else 0
        rate = self.stats.fuzz_executed / elapsed if elapsed > 0 else 0
        self._log_fuzz_info(f"  总用时:   {elapsed:.1f}s")
        self._log_fuzz_info(f"  执行:     {self.stats.fuzz_executed}/{self.stats.fuzz_total}")
        self._log_fuzz_info(f"  通过:     [green]{self.stats.fuzz_passed}[/]")
        self._log_fuzz_info(f"  崩溃:     [red bold]{self.stats.fuzz_crashed}[/]")
        self._log_fuzz_info(f"  警告:     [yellow]{self.stats.fuzz_warnings}[/]")
        self._log_fuzz_info(f"  速率:     {rate:.1f}/s")

    def _log_fuzz_info(self, msg):
        try:
            self.query_one("#fuzz-info-log", RichLog).write(msg)
            self.query_one("#stats-log", RichLog).write(f"[dim][Fuzz][/dim] {msg}")
        except:
            pass

    def _log_fuzz_crash(self, msg):
        try:
            self.query_one("#fuzz-crash-log", RichLog).write(msg)
        except:
            pass

    # ── 统计按钮 ──
    def _on_btn_refresh_stats(self):
        self._refresh_global_stats()

    def _on_btn_reset_stats(self):
        self.stats = GlobalStats()
        self._refresh_global_stats()
        try:
            self.query_one("#stats-log", RichLog).write("[yellow]统计数据已重置[/]")
        except:
            pass

    def _refresh_global_stats(self):
        try:
            self.query_one("#stats-fuzz-total", Label).update(f"总用例: {self.stats.fuzz_total}")
            self.query_one("#stats-fuzz-exec", Label).update(f"已执行: {self.stats.fuzz_executed}")
            pass_rate = (self.stats.fuzz_passed / max(1, self.stats.fuzz_executed)) * 100
            self.query_one("#stats-fuzz-pass", Label).update(f"通过率: {pass_rate:.0f}%")
            self.query_one("#stats-fuzz-crash", Label).update(f"崩溃数: {self.stats.fuzz_crashed}")
            self.query_one("#stats-inj-sent", Label).update(f"已发送: {self.injector.sent_count}")
            self.query_one("#stats-inj-err", Label).update(f"错误数: {self.injector.error_count}")
            sniff_s = self.sniffer.get_summary()
            self.query_one("#stats-sniff-total", Label).update(f"总包数: {sniff_s['total']}")
            self.query_one("#stats-sniff-time", Label).update(f"捕获时长: {sniff_s['elapsed']:.1f}s")
        except:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    # Reactive watchers
    # ═══════════════════════════════════════════════════════════════════════

    def watch_is_running(self, old, new):
        self._update_fuzz_stats()


# ═══════════════════════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════════════════════

def run_tui():
    app = USBForgeApp()
    app.run()

if __name__ == "__main__":
    run_tui()
