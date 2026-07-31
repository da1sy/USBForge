#!/usr/bin/env python3
"""
relay.py — USB 中继 / MITM 引擎

功能:
  · 基于 Facedancer USBProxyDevice 实现 USB MITM 中继
  · Cynthion TARGET-C 伪装真实设备 (USB Device 角色, 面向目标 Host)
  · Mac libusb 直连真实设备 (USB Host 角色, 通过 pyusb/libusb1)
  · 全量 EP0 控制 + 批量/中断数据双向转发
  · 自定义过滤规则: 拦截/放行/篡改/丢弃
  · 实时流量日志 + pcap 导出
  · 线程安全: 可在 TUI 后台线程中运行

架构 (Facedancer USBProxy 标准模式):
  [目标 Host (车机)] ←USB→ [TARGET-C: USBProxyDevice 伪装]
                                   ↕ 过滤器链 (RelayFilter)
  [Mac libusb/pyusb] ←USB→ [真实 USB 设备 (鼠标适配器/键盘/任意)]

  注: 真实 USB 设备必须插在 Mac 的 USB 口上 (非 Cynthion Target-A)。
  Cynthion Target-A 在 Facedancer 模式下不作为 USB Host 端口使用。

依赖: facedancer (USBProxyDevice, USBProxySetupFilters, USBProxyFilter)
"""

from __future__ import annotations

import os
import sys
import time
import threading
import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Any
from collections import deque

# 环境修复 — 与其他 USBForge 模块一致
os.environ.pop("PYTHONPATH", None)
sys.path = [p for p in sys.path if "hermes-agent" not in p]

from facedancer.proxy import USBProxyDevice, LibUSB1Device
from facedancer.filters.standard import USBProxySetupFilters
from facedancer.filters.logging import USBProxyPrettyPrintFilter
from facedancer.filters.base import USBProxyFilter
from facedancer.logging import log


# ═══════════════════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════════════════

class RelayPolicy(Enum):
    """中继策略"""
    PASS_THROUGH = "pass"       # 全量放行 (仅日志)
    HOLD_ALL = "hold"           # 全量拦截 (等待手动放行)
    HOLD_SETUP = "setup"        # 仅拦截 SETUP 控制请求
    HOLD_DATA = "data"          # 仅拦截 DATA 数据传输
    DROP_ALL = "drop"           # 全量丢弃


class PacketAction(Enum):
    """单个包的动作"""
    FORWARDED = "FORWARDED"     # 已转发
    HELD = "HELD"               # 已拦截 (等待放行)
    DROPPED = "DROPPED"         # 已丢弃
    MODIFIED = "MODIFIED"       # 已篡改


@dataclass
class RelayPacket:
    """中继数据包记录"""
    seq: int = 0
    timestamp: str = ""
    direction: str = ""         # "OUT→" (Host→Device) / "←IN" (Device→Host) / "CTL_IN" / "CTL_OUT"
    ep_num: int = 0
    request: str = ""           # 控制请求描述
    data: bytes = b""
    action: PacketAction = PacketAction.FORWARDED
    original_data: bytes = b""  # 篡改前的原始数据

    def summary(self) -> str:
        flags = {
            PacketAction.FORWARDED: "→",
            PacketAction.HELD: "⏸",
            PacketAction.DROPPED: "🗑",
            PacketAction.MODIFIED: "🔧",
        }
        return f"#{self.seq} {self.direction} EP{self.ep_num} {self.request} [{len(self.data)}B] {flags.get(self.action, '?')}"


@dataclass
class RelayStats:
    """中继统计"""
    forwarded: int = 0
    held: int = 0
    dropped: int = 0
    modified: int = 0
    errors: int = 0
    started_at: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 自定义中继过滤器 — 拦截/放行/篡改引擎
# ═══════════════════════════════════════════════════════════════════════════════

class RelayFilter(USBProxyFilter):
    """
    USBForge 自定义中继过滤器

    功能:
      · 实时记录所有 USB 传输
      · 根据策略拦截/放行/丢弃
      · 支持手动放行/丢弃拦截的包
      · 支持数据篡改
      · 回调通知 TUI 更新
    """

    def __init__(self, policy: RelayPolicy = RelayPolicy.PASS_THROUGH,
                 on_packet: Optional[Callable[[RelayPacket], None]] = None):
        self.policy = policy
        self.on_packet = on_packet
        self.stats = RelayStats()
        self.stats.started_at = time.time()
        self._seq = 0
        self._lock = threading.Lock()
        self._held_packets: deque[RelayPacket] = deque(maxlen=200)
        # seq → (签名, 新数据)。签名 = (direction, ep_num, request), 下一次出现
        # 相同签名的包时用新数据替换。
        self._pending_modifications: dict[int, tuple[tuple, bytes]] = {}
        # seq → 已见包记录 — 供 modify_packet() 反查选中包的签名
        self._recent_packets: dict[int, RelayPacket] = {}
        self._running = True

    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def _make_packet(self, direction: str, ep_num: int, request: str,
                     data: bytes, action: PacketAction) -> RelayPacket:
        pkt = RelayPacket(
            seq=self._next_seq(),
            timestamp=datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            direction=direction,
            ep_num=ep_num,
            request=request,
            data=data,
            action=action,
        )
        with self._lock:
            self._recent_packets[pkt.seq] = pkt
        return pkt

    def _apply_modification(self, direction: str, ep_num: int, request: str,
                            data: bytes) -> tuple[bytes, bool]:
        """若有匹配的待篡改请求, 返回 (替换数据, True); 否则 (原数据, False)。"""
        with self._lock:
            for seq, (signature, new_data) in list(self._pending_modifications.items()):
                if signature == (direction, ep_num, request):
                    del self._pending_modifications[seq]
                    self._recent_packets[seq].data = new_data
                    self.stats.modified += 1
                    return new_data, True
        return data, False

    def _emit(self, pkt: RelayPacket):
        """发送包记录到回调"""
        if self.on_packet:
            try:
                self.on_packet(pkt)
            except Exception:
                pass

    def _decide_action(self, is_setup: bool = False, is_data: bool = False) -> PacketAction:
        """根据策略决定动作"""
        if self.policy == RelayPolicy.PASS_THROUGH:
            return PacketAction.FORWARDED
        elif self.policy == RelayPolicy.HOLD_ALL:
            return PacketAction.HELD
        elif self.policy == RelayPolicy.HOLD_SETUP and is_setup:
            return PacketAction.HELD
        elif self.policy == RelayPolicy.HOLD_DATA and is_data:
            return PacketAction.HELD
        elif self.policy == RelayPolicy.DROP_ALL:
            return PacketAction.DROPPED
        return PacketAction.FORWARDED

    # ── EP0 控制请求过滤 ──

    def filter_control_in_setup(self, request, stalled):
        """IN 控制请求 SETUP 阶段"""
        if not self._running:
            return request, stalled

        action = self._decide_action(is_setup=True)
        req_str = str(request) if request else ""

        if action == PacketAction.HELD:
            pkt = self._make_packet("CTL_IN", 0, req_str, b"", action)
            with self._lock:
                self._held_packets.append(pkt)
            self.stats.held += 1
            self._emit(pkt)
            # 吸收包 — 不转发
            return None, True

        elif action == PacketAction.DROPPED:
            pkt = self._make_packet("CTL_IN", 0, req_str, b"", action)
            self.stats.dropped += 1
            self._emit(pkt)
            return None, True

        # 放行
        pkt = self._make_packet("CTL_IN", 0, req_str, b"", PacketAction.FORWARDED)
        self.stats.forwarded += 1
        self._emit(pkt)
        return request, stalled

    def filter_control_in(self, request, data, stalled):
        """IN 控制请求数据阶段 (Device → Host)"""
        if not self._running:
            return request, data, stalled

        if data:
            req_str = str(request) if request else ""
            new_data, modified = self._apply_modification("←IN", 0, req_str, bytes(data))
            action = PacketAction.MODIFIED if modified else PacketAction.FORWARDED
            pkt = self._make_packet("←IN", 0, req_str, new_data, action)
            self._emit(pkt)
            if modified:
                data = new_data

        return request, data, stalled

    def filter_control_out(self, request, data):
        """OUT 控制请求 (Host → Device)"""
        if not self._running:
            return request, data

        action = self._decide_action(is_setup=True)
        req_str = str(request) if request else ""

        if action == PacketAction.HELD:
            pkt = self._make_packet("CTL_OUT", 0, req_str, bytes(data), action)
            with self._lock:
                self._held_packets.append(pkt)
            self.stats.held += 1
            self._emit(pkt)
            return None, None  # 吸收

        elif action == PacketAction.DROPPED:
            pkt = self._make_packet("CTL_OUT", 0, req_str, bytes(data), action)
            self.stats.dropped += 1
            self._emit(pkt)
            return None, None

        new_data, modified = self._apply_modification("CTL_OUT", 0, req_str, bytes(data))
        action = PacketAction.MODIFIED if modified else PacketAction.FORWARDED
        pkt = self._make_packet("CTL_OUT", 0, req_str, new_data, action)
        self.stats.forwarded += 1
        self._emit(pkt)
        if modified:
            data = new_data
        return request, data

    # ── 批量/中断端点过滤 ──

    def filter_in(self, ep_num, data):
        """IN 传输 (Device → Host)"""
        if not self._running:
            return ep_num, data

        action = self._decide_action(is_data=True)

        if action == PacketAction.HELD:
            pkt = self._make_packet("←IN", ep_num, "", bytes(data), action)
            with self._lock:
                self._held_packets.append(pkt)
            self.stats.held += 1
            self._emit(pkt)
            return ep_num, None  # NAK

        elif action == PacketAction.DROPPED:
            pkt = self._make_packet("←IN", ep_num, "", bytes(data), action)
            self.stats.dropped += 1
            self._emit(pkt)
            return ep_num, None

        new_data, modified = self._apply_modification("←IN", ep_num, "", bytes(data))
        action = PacketAction.MODIFIED if modified else PacketAction.FORWARDED
        pkt = self._make_packet("←IN", ep_num, "", new_data, action)
        self.stats.forwarded += 1
        self._emit(pkt)
        if modified:
            data = new_data
        return ep_num, data

    def filter_out(self, ep_num, data):
        """OUT 传输 (Host → Device)"""
        if not self._running:
            return ep_num, data

        action = self._decide_action(is_data=True)

        if action == PacketAction.HELD:
            pkt = self._make_packet("OUT→", ep_num, "", bytes(data), action)
            with self._lock:
                self._held_packets.append(pkt)
            self.stats.held += 1
            self._emit(pkt)
            return ep_num, None  # 吸收

        elif action == PacketAction.DROPPED:
            pkt = self._make_packet("OUT→", ep_num, "", bytes(data), action)
            self.stats.dropped += 1
            self._emit(pkt)
            return ep_num, None

        new_data, modified = self._apply_modification("OUT→", ep_num, "", bytes(data))
        action = PacketAction.MODIFIED if modified else PacketAction.FORWARDED
        pkt = self._make_packet("OUT→", ep_num, "", new_data, action)
        self.stats.forwarded += 1
        self._emit(pkt)
        if modified:
            data = new_data
        return ep_num, data

    # ── 外部控制接口 ──

    def set_policy(self, policy: RelayPolicy):
        self.policy = policy

    def release_packet(self, seq: int) -> bool:
        """手动放行一个拦截的包"""
        with self._lock:
            for i, pkt in enumerate(self._held_packets):
                if pkt.seq == seq:
                    pkt.action = PacketAction.FORWARDED
                    del self._held_packets[i]
                    self.stats.forwarded += 1
                    self._emit(pkt)
                    return True
        return False

    def drop_packet(self, seq: int) -> bool:
        """手动丢弃一个拦截的包"""
        with self._lock:
            for i, pkt in enumerate(self._held_packets):
                if pkt.seq == seq:
                    pkt.action = PacketAction.DROPPED
                    del self._held_packets[i]
                    self.stats.dropped += 1
                    self._emit(pkt)
                    return True
        return False

    def modify_packet(self, seq: int, new_data: bytes) -> bool:
        """篡改指定包 — 下一次出现相同签名 (方向/端点/请求) 的包时替换数据。

        若选中的包还在拦截队列中, 直接替换数据并放行; 否则排队等下一次匹配。
        """
        with self._lock:
            pkt = self._recent_packets.get(seq)
            if pkt is None:
                return False
            signature = (pkt.direction, pkt.ep_num, pkt.request)
            # 若该包仍在拦截队列, 就地替换并放行
            for i, held in enumerate(self._held_packets):
                if held.seq == seq:
                    held.data = new_data
                    held.action = PacketAction.MODIFIED
                    del self._held_packets[i]
                    self.stats.modified += 1
                    self._emit(held)
                    return True
            self._pending_modifications[seq] = (signature, new_data)
        return True

    def get_held_packets(self) -> list[RelayPacket]:
        with self._lock:
            return list(self._held_packets)

    def stop(self):
        self._running = False


# ═══════════════════════════════════════════════════════════════════════════════
# 中继引擎 — 核心管理类
# ═══════════════════════════════════════════════════════════════════════════════

class RelayEngine:
    """
    USB 中继引擎

    管理 USBProxyDevice + 过滤器链的生命周期。
    可在后台线程运行, 提供 start/stop/stats 接口。
    """

    def __init__(self):
        self.proxy_device: Optional[USBProxyDevice] = None
        self.relay_filter: Optional[RelayFilter] = None
        self.setup_filter: Optional[USBProxySetupFilters] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._error: Optional[str] = None
        self.stats = RelayStats()

    @staticmethod
    def find_target_device(vid: Optional[int] = None, pid: Optional[int] = None) -> list[dict]:
        """
        列出所有可作为代理目标的 USB 设备

        Returns:
            [{"vid": 0x1234, "pid": 0x5678, "name": "...", "bus": 0, "addr": 0}, ...]
        """
        try:
            import usb1
            results = []
            ctx = usb1.USBContext()
            for dev in ctx.getDeviceList():
                v = dev.getVendorID()
                p = dev.getProductID()
                # 跳过 Cynthion 自身
                if v == 0x1d50 and p in (0x615b, 0x615c, 0x615e):
                    continue
                name = ""
                try:
                    name = dev.getProduct()
                except:
                    pass
                if vid is not None and v != vid:
                    continue
                if pid is not None and p != pid:
                    continue
                results.append({
                    "vid": v,
                    "pid": p,
                    "name": name or f"{v:#06x}:{p:#06x}",
                    "bus": dev.getBusNumber(),
                    "addr": dev.getDeviceAddress(),
                    "speed": dev.getDeviceSpeed(),
                })
            return results
        except Exception as e:
            log.error(f"find_target_device: {e}")
            return []

    def start(self, vid: int, pid: int,
              policy: RelayPolicy = RelayPolicy.PASS_THROUGH,
              on_packet: Optional[Callable[[RelayPacket], None]] = None) -> bool:
        """
        启动 USB 中继

        Args:
            vid: 目标设备 Vendor ID
            pid: 目标设备 Product ID
            policy: 中继策略
            on_packet: 包回调 (在线程中调用, 需线程安全)

        Returns:
            True if started successfully
        """
        if self._running:
            self._error = "Already running"
            return False

        self._error = None

        # ── 预检: 确认设备存在且可 claim ──
        try:
            import usb.core
            dev = usb.core.find(idVendor=vid, idProduct=pid)
            if dev is None:
                self._error = f"找不到设备 {vid:#06x}:{pid:#06x} — 请确认设备已插入 Mac USB 口"
                return False

            # 检查内核驱动是否占用
            try:
                for intf in dev.get_active_configuration():
                    iface = intf.bInterfaceNumber
                    if dev.is_kernel_driver_active(iface):
                        try:
                            dev.detach_kernel_driver(iface)
                            log.warning(f"Detached kernel driver from interface {iface}")
                        except usb.core.USBError:
                            self._error = (
                                f"macOS 内核驱动占用接口 {iface}，无法 claim 设备。\n"
                                f"请用 root 权限运行 USBForge: sudo ./run.sh"
                            )
                            return False
            except Exception:
                pass  # 某些设备不支持 kernel driver 查询

        except Exception as e:
            self._error = f"设备预检失败: {e}"
            return False

        def _run():
            try:
                # 创建过滤器链
                self.relay_filter = RelayFilter(policy=policy, on_packet=on_packet)

                # 创建 USBProxyDevice — TARGET-C 伪装真实设备
                self.proxy_device = USBProxyDevice(
                    idVendor=vid,
                    idProduct=pid,
                )

                # 标准过滤器: 处理 SET_ADDRESS/SET_CONFIGURATION/SET_INTERFACE
                self.setup_filter = USBProxySetupFilters(self.proxy_device, verbose=1)
                self.proxy_device.add_filter(self.setup_filter)

                # USBForge 中继过滤器
                self.proxy_device.add_filter(self.relay_filter)

                # 连接设备 (初始化 Cynthion TARGET-C + 通过 libusb 连接真实设备)
                # USBProxyDevice.__init__ 已通过 LibUSB1Device 找到真实设备
                # emulate() = connect() + run_with() (内部 asyncio.run) + disconnect()
                self.stats.started_at = time.time()

                # emulate() 是同步阻塞调用 — 内部自己管理 asyncio 事件循环
                self.proxy_device.emulate()

            except Exception as e:
                self._error = str(e)
                log.error(f"RelayEngine thread error: {e}")
                import traceback
                traceback.print_exc()
            finally:
                self._running = False

        self._thread = threading.Thread(target=_run, daemon=True)
        self._running = True
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> bool:
        """停止中继"""
        self._running = False
        if self.relay_filter:
            self.relay_filter.stop()
        if self.proxy_device:
            try:
                self.proxy_device.disconnect()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=timeout)
        return True

    def set_policy(self, policy: RelayPolicy):
        if self.relay_filter:
            self.relay_filter.set_policy(policy)

    def get_stats(self) -> RelayStats:
        if self.relay_filter:
            return self.relay_filter.stats
        return self.stats

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def error(self) -> Optional[str]:
        return self._error


# ═══════════════════════════════════════════════════════════════════════════════
# 便捷函数
# ═══════════════════════════════════════════════════════════════════════════════

def start_relay(vid: int, pid: int,
                policy: str = "pass",
                on_packet: Callable[[RelayPacket], None] = None) -> RelayEngine:
    """
    便捷启动函数

    Args:
        vid: 目标设备 VID
        pid: 目标设备 PID
        policy: "pass" / "hold" / "setup" / "data" / "drop"
        on_packet: 包回调

    Returns:
        RelayEngine 实例
    """
    policy_map = {
        "pass": RelayPolicy.PASS_THROUGH,
        "hold": RelayPolicy.HOLD_ALL,
        "setup": RelayPolicy.HOLD_SETUP,
        "data": RelayPolicy.HOLD_DATA,
        "drop": RelayPolicy.DROP_ALL,
    }
    relay_policy = policy_map.get(policy, RelayPolicy.PASS_THROUGH)

    engine = RelayEngine()
    engine.start(vid, pid, policy=relay_policy, on_packet=on_packet)
    return engine


def list_target_devices() -> list[dict]:
    """列出可代理的 USB 设备 (排除 Cynthion 自身)"""
    return RelayEngine.find_target_device()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI 测试入口
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="USBForge Relay — USB MITM 中继引擎")
    parser.add_argument("--vid", type=lambda x: int(x, 0), required=True, help="目标设备 VID")
    parser.add_argument("--pid", type=lambda x: int(x, 0), required=True, help="目标设备 PID")
    parser.add_argument("--policy", default="pass", choices=["pass", "hold", "setup", "data", "drop"])
    parser.add_argument("--list", action="store_true", help="列出可代理的设备")
    args = parser.parse_args()

    if args.list:
        devices = list_target_devices()
        if not devices:
            print("未找到可代理的 USB 设备")
        else:
            print(f"找到 {len(devices)} 个可代理设备:")
            for d in devices:
                print(f"  {d['name']}  {d['vid']:#06x}:{d['pid']:#06x}  bus={d['bus']} addr={d['addr']}")
        sys.exit(0)

    def on_pkt(pkt: RelayPacket):
        print(f"[{pkt.timestamp}] {pkt.summary()}")

    print(f"启动 USB 中继: {args.vid:#06x}:{args.pid:#06x} policy={args.policy}")
    print("按 Ctrl+C 停止")

    engine = start_relay(args.vid, args.pid, policy=args.policy, on_packet=on_pkt)

    try:
        while engine.is_running:
            time.sleep(0.5)
            if engine.error:
                print(f"错误: {engine.error}")
                break
    except KeyboardInterrupt:
        print("\n停止中继...")
        engine.stop()
        s = engine.get_stats()
        print(f"统计: 转发={s.forwarded} 拦截={s.held} 丢弃={s.dropped} 篡改={s.modified}")
