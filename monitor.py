#!/usr/bin/env python3
"""
monitor.py — 三场景 USB 崩溃监控后端

场景一: 无 Shell     → ICMP ping + USB 重枚举探测 (dmesg 不可读)
场景二: 普通用户 Shell → dmesg + logcat + /proc 检查
场景三: Root Shell   → dmesg + logcat + kmsg + pstore + crashdump

支持 Linux / Android 设备
"""

from __future__ import annotations

import os
import re
import subprocess
import time
import socket
import select
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Callable


# ═══════════════════════════════════════════════════════════════════════════════
# 崩溃检测结果
# ═══════════════════════════════════════════════════════════════════════════════

class CrashLevel(IntEnum):
    NONE     = 0   # 无异常
    WARNING  = 1   # 警告 (dmesg warn/oops 但未崩溃)
    RECOVER  = 2   # 可恢复 (USB 子系统重新枚举)
    CRASH    = 3   # 崩溃 (内核 panic / 重启 / 死锁)


@dataclass
class CrashDetail:
    level:      CrashLevel = CrashLevel.NONE
    summary:    str = ""
    details:    list[str] = field(default_factory=list)
    log_snippet: str = ""
    timestamp:  float = 0.0

    @property
    def is_crash(self) -> bool:
        return self.level >= CrashLevel.CRASH

    @property
    def is_anomaly(self) -> bool:
        return self.level >= CrashLevel.WARNING

    def to_dict(self) -> dict:
        return {
            "level": self.level.name,
            "summary": self.summary,
            "details": self.details,
            "log_snippet": self.log_snippet[:2000],
            "timestamp": self.timestamp,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SSH 连接管理
# ═══════════════════════════════════════════════════════════════════════════════

class SSHConnection:
    """SSH 连接封装 — 支持 adb shell 和 ssh 两种方式"""

    def __init__(self, target: str, mode: str = "ssh", port: int = 22,
                 user: str = "root", adb_serial: Optional[str] = None):
        """
        target: IP 地址
        mode:   "ssh" | "adb"
        port:   SSH 端口
        user:   SSH 用户名
        adb_serial: adb 设备序列号 (mode="adb" 时使用)
        """
        self.target = target
        self.mode = mode
        self.port = port
        self.user = user
        self.adb_serial = adb_serial

    def run(self, command: str, timeout: float = 10.0) -> tuple[int, str]:
        """执行远程命令，返回 (exit_code, stdout)"""
        try:
            if self.mode == "adb":
                args = ["adb"]
                if self.adb_serial:
                    args.extend(["-s", self.adb_serial])
                args.extend(["shell", command])
            else:
                args = ["ssh", "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=no",
                        "-p", str(self.port), f"{self.user}@{self.target}", command]
            result = subprocess.run(args, capture_output=True, timeout=timeout, text=True)
            return result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return -1, "TIMEOUT"
        except FileNotFoundError:
            return -1, f"{'adb' if self.mode == 'adb' else 'ssh'} command not found"
        except Exception as e:
            return -1, str(e)

    def is_reachable(self) -> bool:
        """测试连接是否可用"""
        code, _ = self.run("echo OK", timeout=5.0)
        return code == 0

    def has_root(self) -> bool:
        """检查是否有 root 权限"""
        code, out = self.run("id", timeout=5.0)
        return code == 0 and ("uid=0" in out or "root" in out.lower())


# ═══════════════════════════════════════════════════════════════════════════════
# 内核崩溃日志模式 — 从真实 CVE 和 Linux 源码分析中提取
# ═══════════════════════════════════════════════════════════════════════════════

# dmesg 中的 USB 崩溃/oops 模式
KERNEL_CRASH_PATTERNS = [
    # 内核 panic (最严重)
    (r"Kernel panic.*USB",                              CrashLevel.CRASH),
    (r"BUG:.*kernel.*NULL.*pointer.*dereference",       CrashLevel.CRASH),
    (r"BUG:.*unable to handle kernel",                  CrashLevel.CRASH),
    (r"BUG:.*kernel.*paging request",                   CrashLevel.CRASH),
    (r"BUG:.*spinlock.*lockup",                         CrashLevel.CRASH),
    (r"Call Trace.*usb",                                CrashLevel.CRASH),
    (r"Oops:.*usb",                                     CrashLevel.CRASH),
    (r"RIP:.*usb",                                      CrashLevel.CRASH),
    # USB 子系统错误 (可恢复)
    (r"usb \d+-\d+:.*device descriptor read.*error",    CrashLevel.RECOVER),
    (r"usb \d+-\d+:.*reset.*high.speed.*USB.*device.*using.*ehci", CrashLevel.RECOVER),
    (r"usb \d+-\d+:.*device not accepting address",     CrashLevel.RECOVER),
    (r"usb \d+-\d+:.*cannot reset",                     CrashLevel.RECOVER),
    (r"usb \d+-\d+:.*over.current.condition",           CrashLevel.RECOVER),
    (r"usb \d+-\d+:.*port.reset.*error",                CrashLevel.RECOVER),
    (r"hub.*port.*power.*error",                        CrashLevel.RECOVER),
    (r"xhci.*controller.*error",                        CrashLevel.RECOVER),
    (r"ehci.*controller.*error",                        CrashLevel.RECOVER),
    (r"dwc.*controller.*error",                         CrashLevel.RECOVER),
    (r"usbcore.*NOT.enabled",                           CrashLevel.RECOVER),
    # 警告级别
    (r"usb \d+-\d+:.*string descriptor.*error",         CrashLevel.WARNING),
    (r"usb \d+-\d+:.*configuration.*error",             CrashLevel.WARNING),
    (r"usb \d+-\d+:.*rejected.*invalid",                CrashLevel.WARNING),
    (r"usb \d+-\d+:.*will be disabled",                 CrashLevel.WARNING),
    (r"WARNING:.*CPU.*PID.*usb",                        CrashLevel.WARNING),
    (r"WARNING:.*usb",                                  CrashLevel.WARNING),
]

# Android logcat USB 崩溃模式
ANDROID_CRASH_PATTERNS = [
    # Java 层崩溃
    (r"AndroidRuntime.*FATAL.*Usb",                     CrashLevel.CRASH),
    (r"AndroidRuntime.*FATAL.*usb",                     CrashLevel.CRASH),
    (r"AndroidRuntime.*FATAL.*USB",                     CrashLevel.CRASH),
    (r"ActivityManager.*Process.*usb.*died",            CrashLevel.CRASH),
    # Native 崩溃
    (r"libc.*Fatal signal.*usb|USB",                    CrashLevel.CRASH),
    (r"DEBUG.*pid.*tid.*>>>.*usb",                      CrashLevel.CRASH),
    (r"tombstone.*usb",                                 CrashLevel.CRASH),
    (r"backtrace.*libusbhost|libusb_.*\.so",           CrashLevel.CRASH),
    # UsbService 异常
    (r"UsbService.*Exception",                          CrashLevel.WARNING),
    (r"UsbHostManager.*Exception",                      CrashLevel.WARNING),
    (r"UsbDeviceManager.*Exception",                    CrashLevel.WARNING),
    (r"UsbDebuggingManager.*Exception",                 CrashLevel.WARNING),
    # UsbService 重启
    (r"system_server.*died.*usb",                       CrashLevel.CRASH),
    (r"Watchdog.*killed.*system_server",                CrashLevel.CRASH),
    # 内核日志转发到 logcat
    (r"kernel.*\[.*\].*\[usb",                          CrashLevel.RECOVER),
    (r"kernel.*BUG.*usb",                               CrashLevel.CRASH),
    (r"kernel.*Call Trace.*usb",                        CrashLevel.CRASH),
]


# ═══════════════════════════════════════════════════════════════════════════════
# 监控后端基类
# ═══════════════════════════════════════════════════════════════════════════════

class BaseMonitor:
    """监控后端基类"""

    def __init__(self, name: str):
        self.name = name
        self._baseline_set = False

    def set_baseline(self):
        """设置基线（在模糊测试开始前调用）"""
        self._baseline_set = True

    def check(self) -> CrashDetail:
        """检查目标状态，返回崩溃详情"""
        raise NotImplementedError

    def recover(self) -> bool:
        """尝试恢复目标到可测状态"""
        return True

    def description(self) -> str:
        return self.name


# ═══════════════════════════════════════════════════════════════════════════════
# 场景一: 无 Shell — ICMP ping + TCP 端口探测
# ═══════════════════════════════════════════════════════════════════════════════

class NoShellMonitor(BaseMonitor):
    """
    场景一: 无法获取目标 shell
    
    监控方法:
      1. ICMP ping 存活检测
      2. TCP 端口探测 (可选, 需指定已知开放端口)
      3. USB 重枚举检测 — 通过 Cynthion 自身的 USB 连接状态推断
    
    局限性: 只能检测到系统级崩溃 (重启/死机), 无法发现子组件异常
    """

    def __init__(self, target_ip: str, tcp_ports: Optional[list[int]] = None,
                 ping_timeout: float = 3.0, crash_threshold: int = 3):
        super().__init__("无Shell监控 (ICMP+TCP)")
        self.target_ip = target_ip
        self.tcp_ports = tcp_ports or [5555]  # 默认检测 ADB 端口
        self.ping_timeout = ping_timeout
        self.crash_threshold = crash_threshold  # 连续 N 次无响应判定崩溃
        self._alive = True

    def _ping(self) -> bool:
        """ICMP ping"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(int(self.ping_timeout)), self.target_ip],
                capture_output=True, timeout=self.ping_timeout + 2
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _tcp_check(self, port: int) -> bool:
        """TCP 端口连通性检查"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def check(self) -> CrashDetail:
        detail = CrashDetail(timestamp=time.time())

        # 多轮 ping 检测
        fail_count = 0
        for attempt in range(self.crash_threshold):
            if self._ping():
                fail_count = 0
                break
            fail_count += 1
            if attempt < self.crash_threshold - 1:
                time.sleep(1.0)

        if fail_count >= self.crash_threshold:
            # TCP 二次确认
            tcp_ok = any(self._tcp_check(p) for p in self.tcp_ports)
            if not tcp_ok:
                detail.level = CrashLevel.CRASH
                detail.summary = f"目标 {self.target_ip} 连续 {fail_count} 次无响应 (ICMP + TCP 均失败)"
                detail.details.append(f"ICMP ping 失败 x{fail_count}")
                detail.details.append(f"TCP 端口 {self.tcp_ports} 均不可达")
                self._alive = False
            else:
                detail.level = CrashLevel.WARNING
                detail.summary = "ICMP 失败但 TCP 端口仍开放 — 可能仅 USB 子系统异常"
                detail.details.append(f"TCP 端口可达, 但 ping 不通")
        else:
            self._alive = True

        return detail

    def recover(self) -> bool:
        """等待目标重启恢复"""
        for _ in range(30):  # 最多等 150 秒
            if self._ping():
                return True
            time.sleep(5)
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# 场景二: 普通用户 Shell — dmesg restricted + logcat
# ═══════════════════════════════════════════════════════════════════════════════

class UserShellMonitor(BaseMonitor):
    """
    场景二: 有普通用户 shell (adb shell untrusted 或 ssh user)
    
    监控方法:
      1. dmesg (如果可读 — 部分设备需要 root)
      2. logcat (Android) / journalctl (Linux)
      3. /proc/kernel/panic / /proc/last_kmsg
      4. ADB USB 设备列表变化
      5. uptime 变化 (检测重启)
    """

    def __init__(self, conn: SSHConnection):
        super().__init__("用户Shell监控 (dmesg+logcat)")
        self.conn = conn
        self._uptime_baseline = ""
        self._dmesg_baseline_size = 0
        self._logcat_cleared = False
        self._is_android = False
        self._detect_platform()

    def _detect_platform(self):
        """检测目标平台 (Android / Linux)"""
        code, out = self.conn.run("getprop ro.build.version.release 2>/dev/null || cat /etc/os-release 2>/dev/null | head -1")
        if code == 0 and out.strip():
            if "release" in out or "android" in out.lower():
                self._is_android = True
            else:
                self._is_android = False

    def set_baseline(self):
        super().set_baseline()
        # 记录 uptime
        _, self._uptime_baseline = self.conn.run("cat /proc/uptime 2>/dev/null || uptime")
        # 清空 logcat 缓冲 (Android)
        if self._is_android:
            self.conn.run("logcat -c 2>/dev/null")
            self._logcat_cleared = True
        # 记录 dmesg 基线大小
        _, dmesg = self.conn.run("dmesg 2>/dev/null | wc -l")
        try:
            self._dmesg_baseline_size = int(dmesg.strip()) if dmesg.strip() else 0
        except ValueError:
            self._dmesg_baseline_size = 0

    def check(self) -> CrashDetail:
        detail = CrashDetail(timestamp=time.time())

        # 1. 检测重启 (uptime 重置)
        _, current_uptime = self.conn.run("cat /proc/uptime 2>/dev/null || uptime")
        if current_uptime.strip() and self._uptime_baseline.strip():
            # 如果 uptime 变小了，说明重启过
            if self._parse_uptime_seconds(current_uptime) < self._parse_uptime_seconds(self._uptime_baseline) * 0.9:
                detail.level = CrashLevel.CRASH
                detail.summary = "系统已重启 (uptime 重置)"
                detail.details.append(f"基线 uptime: {self._uptime_baseline.strip()}")
                detail.details.append(f"当前 uptime: {current_uptime.strip()}")
                return detail

        # 2. dmesg 检查 (如果可读)
        _, dmesg_new = self.conn.run("dmesg 2>/dev/null")
        if dmesg_new.strip():
            new_lines = dmesg_new.split('\n')
            if len(new_lines) > self._dmesg_baseline_size:
                recent = '\n'.join(new_lines[self._dmesg_baseline_size:])
                detail = self._scan_for_crashes(recent, "dmesg", detail)
                if detail.is_crash:
                    return detail

        # 3. logcat 检查 (Android)
        if self._is_android:
            _, logcat_out = self.conn.run("logcat -d -b crash -b main *:W 2>/dev/null | tail -100")
            if logcat_out.strip():
                detail = self._scan_for_crashes(logcat_out, "logcat", detail)
                if detail.is_crash:
                    return detail

        # 4. /proc/last_kmsg / pstore 检查
        _, last_kmsg = self.conn.run("cat /proc/last_kmsg 2>/dev/null || cat /sys/fs/pstore/console-ramoops-0 2>/dev/null | tail -50")
        if last_kmsg.strip() and ("panic" in last_kmsg.lower() or "oops" in last_kmsg.lower()):
            detail.level = CrashLevel.CRASH
            detail.summary = "检测到上次启动的内核崩溃日志 (pstore/last_kmsg)"
            detail.log_snippet = last_kmsg[:1000]
            detail.details.append("来源: /proc/last_kmsg 或 pstore")

        return detail

    def _parse_uptime_seconds(self, uptime_str: str) -> float:
        """从 uptime 字符串中提取秒数"""
        try:
            # /proc/uptime 格式: "12345.67 98765.43"
            parts = uptime_str.strip().split()
            return float(parts[0])
        except (ValueError, IndexError):
            return 0.0

    def _scan_for_crashes(self, log_text: str, source: str, detail: CrashDetail) -> CrashDetail:
        """在日志中扫描崩溃模式"""
        patterns = KERNEL_CRASH_PATTERNS + ANDROID_CRASH_PATTERNS
        max_level = CrashLevel.NONE
        matched_patterns = []

        for pattern, level in patterns:
            matches = re.findall(pattern, log_text, re.IGNORECASE | re.MULTILINE)
            if matches:
                if level > max_level:
                    max_level = level
                matched_patterns.append(f"[{source}] {pattern} ({level.name})")

        if max_level > detail.level:
            detail.level = max_level
            detail.summary = f"在 {source} 中检测到 {max_level.name} 级别异常"
            detail.details.extend(matched_patterns[:5])
            # 提取上下文日志片段
            for pattern, _ in patterns:
                m = re.search(pattern, log_text, re.IGNORECASE | re.MULTILINE)
                if m:
                    start = max(0, m.start() - 200)
                    end = min(len(log_text), m.end() + 200)
                    detail.log_snippet = log_text[start:end]
                    break

        return detail


# ═══════════════════════════════════════════════════════════════════════════════
# 场景三: Root Shell — 全量内核日志 + crashdump + 动态追踪
# ═══════════════════════════════════════════════════════════════════════════════

class RootShellMonitor(UserShellMonitor):
    """
    场景三: 有 root shell (adb root 或 ssh root)
    
    增强监控方法 (在 UserShellMonitor 基础上):
      1. dmesg 完全可读
      2. /dev/kmsg 实时监控
      3. /sys/kernel/debug/usb 动态追踪
      4. pstore 完整 dump
      5. USB sysfs 状态变化
      6. 内核 trace (kprobe/tracepoint 可选)
      7. 崩溃后自动抓取 dmesg + pstore + logcat 全量日志
    """

    def __init__(self, conn: SSHConnection):
        super().__init__(conn)
        self.name = "Root Shell监控 (全量日志+pstore+trace)"
        self._usb_sysfs_baseline = ""
        self._kmsg_fd: Optional[int] = None

    def set_baseline(self):
        super().set_baseline()
        # 额外记录 USB sysfs 状态
        _, self._usb_sysfs_baseline = self.conn.run(
            "find /sys/bus/usb/devices/ -name idVendor 2>/dev/null | head -20 | xargs cat 2>/dev/null"
        )

    def check(self) -> CrashDetail:
        # 先执行父类检查
        detail = super().check()
        if detail.is_crash:
            # 如果崩溃了，抓取完整的诊断日志
            detail = self._capture_full_crash_dump(detail)
            return detail

        # Root 独有的增强检查

        # 1. /dev/kmsg 实时读取 (非阻塞)
        _, kmsg = self.conn.run("timeout 1 dd if=/dev/kmsg bs=4096 count=1 2>/dev/null || true")
        if kmsg.strip():
            detail = self._scan_for_crashes(kmsg, "kmsg", detail)

        # 2. USB sysfs 变化检测
        _, current_usb = self.conn.run(
            "find /sys/bus/usb/devices/ -name idVendor 2>/dev/null | head -20 | xargs cat 2>/dev/null"
        )
        if current_usb.strip() != self._usb_sysfs_baseline.strip():
            # USB 设备树变化是正常的（因为我们正在模拟设备），但突变可能表示异常
            detail.details.append("USB sysfs 设备树发生变化")
            if detail.level < CrashLevel.WARNING:
                detail.level = CrashLevel.WARNING
                detail.summary = "USB 设备树异常变化"

        # 3. 检查 /sys/kernel/debug/usb (如果存在)
        _, debug_usb = self.conn.run(
            "ls -la /sys/kernel/debug/usb/ 2>/dev/null && cat /sys/kernel/debug/usb/devices 2>/dev/null | tail -30"
        )
        if "error" in debug_usb.lower() and "disconnect" in debug_usb.lower():
            if detail.level < CrashLevel.RECOVER:
                detail.level = CrashLevel.RECOVER
                detail.summary = "USB debug 信息显示设备异常断连"

        # 4. 检查内核线程状态 (D 状态 = 不可中断睡眠 = 可能死锁)
        _, d_state = self.conn.run(
            "ps -eo stat,pid,comm 2>/dev/null | grep '^D' | grep -i usb || true"
        )
        if d_state.strip():
            if detail.level < CrashLevel.CRASH:
                detail.level = CrashLevel.CRASH
                detail.summary = "USB 相关内核线程进入 D 状态 (可能死锁)"
                detail.details.append(f"D-state 线程:\n{d_state.strip()[:500]}")

        return detail

    def _capture_full_crash_dump(self, detail: CrashDetail) -> CrashDetail:
        """崩溃后抓取完整诊断信息"""
        crash_dump_commands = [
            ("dmesg",        "dmesg 2>/dev/null | tail -200"),
            ("pstore",       "cat /sys/fs/pstore/console-ramoops-0 2>/dev/null | tail -100"),
            ("last_kmsg",    "cat /proc/last_kmsg 2>/dev/null | tail -100"),
            ("logcat_crash", "logcat -d -b crash 2>/dev/null | tail -100"),
            ("logcat_main",  "logcat -d -b main *:E 2>/dev/null | tail -50"),
            ("tombstones",   "ls -lt /data/tombstones/ 2>/dev/null | head -5"),
            ("usb_sysfs",    "ls -la /sys/bus/usb/devices/ 2>/dev/null"),
            ("kernel_trace", "cat /sys/kernel/debug/tracing/trace 2>/dev/null | grep -i usb | tail -50"),
        ]

        full_dump = []
        for name, cmd in crash_dump_commands:
            code, out = self.conn.run(cmd, timeout=5.0)
            if out.strip():
                full_dump.append(f"--- {name} ---\n{out.strip()}\n")

        if full_dump:
            detail.log_snippet = '\n'.join(full_dump)[:4000]
            detail.details.append(f"已抓取 {len(full_dump)} 份崩溃诊断日志")

        return detail


# ═══════════════════════════════════════════════════════════════════════════════
# 监控后端工厂
# ═══════════════════════════════════════════════════════════════════════════════

def create_monitor(
    mode: str = "noshell",
    target_ip: Optional[str] = None,
    ssh_user: str = "root",
    ssh_port: int = 22,
    adb_serial: Optional[str] = None,
    tcp_ports: Optional[list[int]] = None,
) -> BaseMonitor:
    """
    根据场景创建监控后端

    mode: "noshell" | "user" | "root"
    """
    if mode == "noshell":
        return NoShellMonitor(
            target_ip=target_ip or "192.168.1.1",
            tcp_ports=tcp_ports,
        )
    elif mode in ("user", "root"):
        # 判断使用 adb 还是 ssh
        conn_mode = "adb" if adb_serial or (target_ip and ":" in str(target_ip)) else "ssh"
        conn = SSHConnection(
            target=target_ip or "127.0.0.1",
            mode=conn_mode,
            port=ssh_port,
            user=ssh_user,
            adb_serial=adb_serial,
        )
        if mode == "root":
            return RootShellMonitor(conn)
        else:
            return UserShellMonitor(conn)
    else:
        raise ValueError(f"未知监控模式: {mode}")
