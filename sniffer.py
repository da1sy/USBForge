#!/usr/bin/env python3
"""
sniffer.py — USB 总线监听 / 流量分析

功能:
  · 调用 cynthion analyzer bitstream 捕获 USB 流量
  · 解析 USB 事务层 (SETUP/DATA/HANDSHAKE)
  · 提取设备描述符、配置描述符
  · 实时统计事务计数
  · 导出 pcap (LINKTYPE_USB_2_0)

依赖: Cynthion analyzer bitstream, tshark (可选)
"""

from __future__ import annotations

import os
import re
import subprocess
import time
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional, Callable

# 环境修复
os.environ.pop("PYTHONPATH", None)

_CYNTHION_BIN = "/Users/da1sy/tools/cynthion/.venv/bin/cynthion"
_TSHARK_BIN = "/usr/local/bin/tshark" if os.path.exists("/usr/local/bin/tshark") else "/opt/homebrew/bin/tshark"
_CAP_DIR = Path.home() / ".cynthion-mcp" / "captures"


# ═══════════════════════════════════════════════════════════════════════════════
# USB 事务类型
# ═══════════════════════════════════════════════════════════════════════════════

# USB CRC5 多项式表 — 对应 Wireshark crc5_usb_11bit_input() (USB 2.0 spec §8.3.5.1)
# 每条目 = 输入位 i 置 1 时对寄存器的影响
_CRC5_BVALS = [
    0x1e, 0x15, 0x03, 0x06, 0x0c, 0x18, 0x19, 0x1b,
    0x1f, 0x17, 0x07, 0x0e, 0x1c, 0x11, 0x0b, 0x16,
    0x05, 0x0a, 0x14,
]


def _usb_crc5(v: int, vl: int = 11) -> int:
    """计算 USB 11 位 token/SOF 字段的 CRC5 (多项式 x^5+x^2+1, 种子 0x02)。"""
    rv = 0x02
    for i in range(vl):
        if v & (1 << i):
            rv ^= _CRC5_BVALS[19 - vl + i]
    return rv


def _usb_crc16(data: bytes) -> int:
    """计算 USB 数据包 payload 的 CRC16 (多项式 0x8005 反射, 种子/异或 0xFFFF)。"""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc ^ 0xFFFF


class PacketType(IntEnum):
    SETUP = 0   # SETUP token
    IN = 1      # IN token
    OUT = 2     # OUT token
    DATA0 = 3   # DATA0 packet
    DATA1 = 4   # DATA1 packet
    ACK = 5     # ACK handshake
    NAK = 6     # NAK handshake
    STALL = 7   # STALL handshake
    SOF = 8     # Start of Frame
    PING = 9    # PING (high-speed)
    SPLIT = 10  # Split transaction


class DeviceSpeed(IntEnum):
    LOW = 0     # 1.5 Mbps
    FULL = 1    # 12 Mbps
    HIGH = 2    # 480 Mbps
    SUPER = 3   # 5 Gbps


# 标准 USB 2.0 PID 值 (USB spec Table 8-1) → 名称 / PacketType
PID_MAP = {
    0xe1: ("OUT", PacketType.OUT),
    0x69: ("IN", PacketType.IN),
    0xa5: ("SOF", PacketType.SOF),
    0x2d: ("SETUP", PacketType.SETUP),
    0xc3: ("DATA0", PacketType.DATA0),
    0x4b: ("DATA1", PacketType.DATA1),
    0x87: ("DATA2", PacketType.DATA0),   # high-speed
    0x0f: ("MDATA", PacketType.DATA0),   # high-speed
    0xd2: ("ACK", PacketType.ACK),
    0x5a: ("NAK", PacketType.NAK),
    0x1e: ("STALL", PacketType.STALL),
    0x96: ("NYET", PacketType.NAK),      # high-speed
    0x3c: ("PRE/ERR", PacketType.STALL),
    0x78: ("SPLIT", PacketType.SPLIT),   # high-speed
    0xb4: ("PING", PacketType.PING),
    0xf0: ("EXT", PacketType.SPLIT),
}

# PacketType → 线上 PID 字节 (标准 USB 线上 PID 值, 与 LINKTYPE_USB_2_0 pcap 一致)
_WIRE_PID = {
    PacketType.SETUP: 0x2D,
    PacketType.IN: 0x69,
    PacketType.OUT: 0xE1,
    PacketType.DATA0: 0xC3,
    PacketType.DATA1: 0x4B,
    PacketType.ACK: 0xD2,
    PacketType.NAK: 0x5A,
    PacketType.STALL: 0x1E,
    PacketType.SOF: 0xA5,
    PacketType.PING: 0xB4,
}


def _encode_link_frame(pkt: 'USBPacket', sof_counter: int = 0) -> bytes:
    """把解码后的 USBPacket 重建为链路层线上字节 (PID 开头, 含 CRC)。

    与 Cynthion analyzer 捕获的 LINKTYPE_USB_2_0 pcap 记录格式一致:
      · token (SETUP/IN/OUT/PING)   : PID + 2B (ADDR+ENDP+CRC5)
      · SOF                         : PID + 2B (framenum+CRC5)
      · DATA0/DATA1                 : PID + payload + CRC16 (LE)
      · handshake (ACK/NAK/STALL)   : PID
    """
    ptype = pkt.packet_type
    pid = _WIRE_PID.get(ptype, pkt.pid or 0)
    payload = pkt.data or b""

    if ptype in (PacketType.SETUP, PacketType.IN, PacketType.OUT, PacketType.PING):
        field = (pkt.device_addr & 0x7F) | ((pkt.endpoint & 0x0F) << 7)
        word = (_usb_crc5(field) << 11) | field
        return bytes([pid, word & 0xFF, (word >> 8) & 0xFF])
    if ptype == PacketType.SOF:
        frame = sof_counter & 0x7FF
        word = (_usb_crc5(frame) << 11) | frame
        return bytes([pid, word & 0xFF, (word >> 8) & 0xFF])
    if ptype in (PacketType.DATA0, PacketType.DATA1):
        crc = _usb_crc16(payload)
        return bytes([pid]) + payload + crc.to_bytes(2, "little")
    # handshake / 未知类型
    return bytes([pid])


# MCP tshark PID names → PacketType (tshark uses lowercase hex PID values)
# Maps the pid_name strings from summarise_packet() to our PacketType enum
_PID_NAME_TO_TYPE = {
    "SOF": PacketType.SOF,
    "SETUP": PacketType.SETUP,
    "IN": PacketType.IN,
    "OUT": PacketType.OUT,
    "SPLIT": PacketType.SPLIT,
    "PING": PacketType.PING,
    "DATA0": PacketType.DATA0,
    "DATA1": PacketType.DATA1,
    "DATA2": PacketType.DATA0,
    "MDATA": PacketType.DATA0,
    "ACK": PacketType.ACK,
    "NAK": PacketType.NAK,
    "STALL": PacketType.STALL,
    "NYET": PacketType.NAK,
    "PRE_OR_ERR": PacketType.STALL,
}


@dataclass
class USBPacket:
    """单个 USB 数据包"""
    timestamp: float = 0.0
    pid: int = 0
    pid_name: str = ""
    packet_type: PacketType = PacketType.ACK
    device_addr: int = 0
    endpoint: int = 0
    data: bytes = b""
    direction: str = ""  # "IN" / "OUT"
    raw_hex: str = ""

    @property
    def is_setup(self) -> bool:
        return self.packet_type == PacketType.SETUP

    @property
    def is_data(self) -> bool:
        return self.packet_type in (PacketType.DATA0, PacketType.DATA1)

    @property
    def data_len(self) -> int:
        return len(self.data)

    def parse_setup_data(self) -> Optional[dict]:
        """解析 SETUP token 后的 8 字节请求数据"""
        if not self.is_data or len(self.data) < 8:
            return None
        b = self.data
        bmRequestType = b[0]
        return {
            "bmRequestType": b[0],
            "direction": "IN" if (b[0] >> 7) & 1 else "OUT",
            "type": (b[0] >> 5) & 3,  # 0=standard, 1=class, 2=vendor
            "recipient": b[0] & 0x1f,  # 0=device, 1=interface, 2=endpoint
            "bRequest": b[1],
            "wValue": (b[3] << 8) | b[2],
            "wIndex": (b[5] << 8) | b[4],
            "wLength": (b[7] << 8) | b[6],
        }


@dataclass
class CaptureStats:
    """捕获统计"""
    total_packets: int = 0
    setup_count: int = 0
    data_count: int = 0
    ack_count: int = 0
    nak_count: int = 0
    stall_count: int = 0
    by_device: dict[int, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)
    start_time: float = 0.0

    @property
    def elapsed(self) -> float:
        if not self.start_time:
            return 0
        return time.time() - self.start_time

    @property
    def pps(self) -> float:
        e = self.elapsed
        if e < 1:
            return 0
        return self.total_packets / e


# ═══════════════════════════════════════════════════════════════════════════════
# USB 描述符解析器
# ═══════════════════════════════════════════════════════════════════════════════

DESC_TYPES = {
    1: "Device",
    2: "Configuration",
    3: "String",
    4: "Interface",
    5: "Endpoint",
    6: "DeviceQualifier",
    7: "OtherSpeed",
    8: "InterfacePower",
    9: "OTG",
    0x0a: "InterfacePower",
    0x15: "BOS",
    0x21: "HID",
    0x22: "Report",
    0x23: "Physical",
    0x24: "CS_Interface",  # Class-Specific Interface
    0x25: "CS_Endpoint",
    0x29: "Hub",
    0x2a: "SuperSpeed_EP_Companion",
}

DEVICE_CLASSES = {
    0x00: "Unknown",
    0x01: "Audio",
    0x02: "CDC-Comm",
    0x03: "HID",
    0x05: "Physical",
    0x06: "Image",
    0x07: "Printer",
    0x08: "Mass Storage",
    0x09: "Hub",
    0x0a: "CDC-Data",
    0x0b: "Smart Card",
    0x0d: "Content Security",
    0x0e: "Video",
    0x0f: "Personal Healthcare",
    0x10: "Audio/Video",
    0x11: "Billboard",
    0xdc: "Diagnostic",
    0xe0: "Wireless Controller",
    0xef: "Miscellaneous",
    0xfe: "Application Specific",
    0xff: "Vendor Specific",
}


def parse_device_descriptor(data: bytes) -> dict:
    """解析设备描述符 (18 bytes)"""
    if len(data) < 18:
        return {"error": f"too short: {len(data)} < 18"}
    return {
        "type": DESC_TYPES.get(data[1], f"Unknown({data[1]})"),
        "usb_version": f"{data[3]:02x}.{data[2]:02x}",
        "device_class": DEVICE_CLASSES.get(data[4], f"Unknown(0x{data[4]:02x})"),
        "device_subclass": data[5],
        "protocol": data[6],
        "max_packet_size_ep0": data[7],
        "vendor_id": f"0x{data[9]:02x}{data[8]:02x}",
        "product_id": f"0x{data[11]:02x}{data[10]:02x}",
        "device_version": f"{data[13]:02x}.{data[12]:02x}",
        "manufacturer_idx": data[14],
        "product_idx": data[15],
        "serial_idx": data[16],
        "num_configurations": data[17],
    }


def parse_config_descriptor(data: bytes) -> dict:
    """解析配置描述符 (>=9 bytes)"""
    if len(data) < 9:
        return {"error": f"too short"}
    attrs = data[7]
    return {
        "type": DESC_TYPES.get(data[1], "Unknown"),
        "total_length": (data[3] << 8) | data[2],
        "num_interfaces": data[4],
        "config_value": data[5],
        "config_string_idx": data[6],
        "self_powered": bool(attrs & 0x40),
        "remote_wakeup": bool(attrs & 0x20),
        "max_power_ma": data[8] * 2,  # in mA
        "raw_attributes": attrs,
    }


def parse_endpoint_descriptor(data: bytes) -> dict:
    """解析端点描述符 (7 bytes)"""
    if len(data) < 7:
        return {"error": "too short"}
    addr = data[2]
    attrs = data[3]
    transfer_types = {0: "Control", 1: "Isochronous", 2: "Bulk", 3: "Interrupt"}
    return {
        "type": DESC_TYPES.get(data[1], "Unknown"),
        "endpoint_address": addr,
        "direction": "IN" if addr & 0x80 else "OUT",
        "endpoint_number": addr & 0x0f,
        "transfer_type": transfer_types.get(attrs & 0x03, "Unknown"),
        "max_packet_size": (data[5] << 8) | data[4],
        "interval": data[6],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 捕获管理器
# ═══════════════════════════════════════════════════════════════════════════════

class USBSniffer:
    """USB 总线流量捕获管理器"""

    def __init__(self):
        self.is_capturing = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.stats = CaptureStats()
        self.packets: list[USBPacket] = []
        self._max_packets = 10000  # ring buffer
        self._callbacks: list[Callable] = []
        self._batch_callbacks: list[Callable] = []
        self.current_capture_file: Optional[Path] = None
        self.last_capture_id: Optional[str] = None  # MCP capture_id of last session

    def add_callback(self, cb: Callable):
        self._callbacks.append(cb)

    def add_batch_callback(self, cb: Callable):
        """注册批量回调 — 用于一次性加载大量数据包(如 MCP dissect 结果)"""
        self._batch_callbacks.append(cb)

    def _notify(self, packet: USBPacket):
        for cb in self._callbacks:
            try:
                cb(packet)
            except Exception:
                pass

    def _notify_batch(self, packets: list):
        for cb in self._batch_callbacks:
            try:
                cb(packets)
            except Exception:
                pass

    def start(self, speed: str = "auto") -> bool:
        """启动捕获 (需要 analyzer bitstream)

        首先尝试通过 MCP bridge 做真实捕获；若 MCP 不可用则降级模拟。
        """
        if self.is_capturing:
            return True

        _CAP_DIR.mkdir(parents=True, exist_ok=True)
        self.current_capture_file = _CAP_DIR / f"capture_{int(time.time())}.bin"

        self._stop_event.clear()
        self.is_capturing = True
        self.stats = CaptureStats(start_time=time.time())
        self.packets.clear()

        # 启动捕获线程
        self._thread = threading.Thread(
            target=self._capture_worker,
            args=(speed,),
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self) -> dict:
        """停止捕获 — 设置停止标志，立即返回(不等 MCP 解析)"""
        self.is_capturing = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

        return {
            "total_packets": self.stats.total_packets,
            "elapsed": self.stats.elapsed,
            "pps": self.stats.pps,
            "capture_file": str(self.current_capture_file) if self.current_capture_file else "",
            "capture_id": self.last_capture_id or "",
        }

    def _capture_worker(self, speed: str):
        """捕获工作线程 — 优先 MCP 真实捕获，否则降级模拟。

        真实模式流程:
          1. bridge.capture_start(speed)  → 得到 capture_id
          2. 捕获进行中，capture_status 轮询
          3. 用户点 Stop 时 stop() 置 _stop_event
          4. bridge.capture_stop()
          5. bridge.dissect_packets(capture_id) → tshark 结构化结果
          6. 转换为 USBPacket 对象，逐条回调 UI
        """
        try:
            from mcp_bridge import get_bridge
            bridge = get_bridge()
            if bridge.available or bridge.start(timeout=15):
                self._capture_via_mcp(bridge, speed)
            else:
                self._capture_simulated()
        except Exception:
            self._capture_simulated()

    def _capture_via_mcp(self, bridge, speed: str):
        """通过 MCP bridge 调用真实 Cynthion analyzer 捕获"""
        # 1) 启动捕获
        r = bridge.capture_start(speed)
        if not r.get("ok"):
            self._capture_simulated()
            return

        cap_data = r.get("data", {})
        self.last_capture_id = cap_data.get("id", "")

        # 2) 等待用户停止 — 轻量轮询, 不每轮调 MCP
        while not self._stop_event.is_set():
            time.sleep(0.2)

        # 3) 停止捕获
        stop_r = bridge.capture_stop()
        if stop_r.get("ok"):
            stop_data = stop_r.get("data", {})
            # capture_stop 返回 "id" 而非 "capture_id"
            self.last_capture_id = stop_data.get("id", self.last_capture_id)

        # 4) 解析捕获数据 — 调用 dissect_packets 获取结构化包
        if self.last_capture_id:
            self._load_packets_from_mcp(bridge, self.last_capture_id)

    def _load_packets_from_mcp(self, bridge, capture_id: str, limit: int = 2000):
        """从 MCP dissect_packets 结果加载真实数据包到 self.packets (批量模式)"""
        r = bridge.dissect_packets(capture_id, limit=limit)
        if not r.get("ok"):
            return

        data = r.get("data", {})
        pkts = data.get("packets", [])
        batch: list[USBPacket] = []
        for p in pkts:
            pkt = self._mcp_packet_to_usbpacket(p)
            if pkt:
                # 直接更新内部状态，不触发逐包回调(避免 UI 洪泛)
                self.packets.append(pkt)
                if len(self.packets) > self._max_packets:
                    self.packets.pop(0)
                self.stats.total_packets += 1
                self.stats.by_device[pkt.device_addr] = self.stats.by_device.get(pkt.device_addr, 0) + 1
                self.stats.by_type[pkt.pid_name] = self.stats.by_type.get(pkt.pid_name, 0) + 1
                if pkt.is_setup:
                    self.stats.setup_count += 1
                elif pkt.is_data:
                    self.stats.data_count += 1
                elif pkt.pid_name == "ACK":
                    self.stats.ack_count += 1
                elif pkt.pid_name == "NAK":
                    self.stats.nak_count += 1
                elif pkt.pid_name == "STALL":
                    self.stats.stall_count += 1

                batch.append(pkt)
                # 分批发送，每 200 条一批
                if len(batch) >= 200:
                    self._notify_batch(batch)
                    batch.clear()
        # 发送剩余的
        if batch:
            self._notify_batch(batch)

    @staticmethod
    def _mcp_packet_to_usbpacket(p: dict) -> Optional['USBPacket']:
        """将 MCP tshark summarise_packet 结果转为 USBPacket"""
        try:
            pid_str = p.get("pid") or ""
            pid_val = int(pid_str, 16) if isinstance(pid_str, str) else 0
            pid_name = p.get("pid_name") or ""
            ptype = _PID_NAME_TO_TYPE.get(pid_name, PacketType.ACK)

            dev_addr = 0
            dev = p.get("device")
            if dev is not None:
                dev_addr = int(dev)

            ep_val = 0
            ep = p.get("endpoint")
            if ep is not None:
                ep_val = int(ep)

            # direction from src/dst
            src = p.get("src") or ""
            dst = p.get("dst") or ""
            if "host" in src.lower():
                direction = "OUT"
            elif "host" in dst.lower():
                direction = "IN"
            else:
                direction = ""

            # extra fields may contain data payload
            extra = p.get("extra") or {}
            raw_data = b""
            for k, v in extra.items():
                if isinstance(v, str) and all(c in "0123456789abcdef:" for c in v.lower()):
                    cleaned = v.replace(":", "")
                    try:
                        raw_data = bytes.fromhex(cleaned)
                        if len(raw_data) > 0:
                            break
                    except ValueError:
                        continue

            ts = p.get("time", 0.0)

            return USBPacket(
                timestamp=float(ts) if ts else time.time(),
                pid=pid_val,
                pid_name=pid_name,
                packet_type=ptype,
                device_addr=dev_addr,
                endpoint=ep_val,
                data=raw_data,
                direction=direction,
                raw_hex=raw_data.hex() if raw_data else "",
            )
        except Exception:
            return None

    def _capture_simulated(self):
        """模拟模式 — 生成示例流量用于 UI 演示 (无硬件时降级)"""
        import random
        rng = random.Random()

        pid_cycle = [
            (0x2d, "SETUP", PacketType.SETUP),
            (0xd2, "DATA0", PacketType.DATA0),
            (0x4a, "ACK", PacketType.ACK),
            (0x69, "IN", PacketType.IN),
            (0xd3, "DATA1", PacketType.DATA1),
            (0x4a, "ACK", PacketType.ACK),
        ]

        while not self._stop_event.is_set():
            for pid_val, name, ptype in pid_cycle:
                if self._stop_event.is_set():
                    break
                dev_addr = rng.randint(0, 5)
                ep = rng.choice([0, 0, 0, 1, 2])
                raw_data = bytes(rng.getrandbits(8) for _ in range(8)) if ptype in (PacketType.SETUP,) else b""

                pkt = USBPacket(
                    timestamp=time.time(),
                    pid=pid_val,
                    pid_name=name,
                    packet_type=ptype,
                    device_addr=dev_addr,
                    endpoint=ep,
                    data=raw_data,
                    raw_hex=raw_data.hex(),
                )
                self._add_packet(pkt)
                time.sleep(0.05)

    def _add_packet(self, pkt: USBPacket):
        self.packets.append(pkt)
        if len(self.packets) > self._max_packets:
            self.packets.pop(0)

        self.stats.total_packets += 1
        self.stats.by_device[pkt.device_addr] = self.stats.by_device.get(pkt.device_addr, 0) + 1
        self.stats.by_type[pkt.pid_name] = self.stats.by_type.get(pkt.pid_name, 0) + 1

        if pkt.is_setup:
            self.stats.setup_count += 1
        elif pkt.is_data:
            self.stats.data_count += 1
        elif pkt.pid_name == "ACK":
            self.stats.ack_count += 1
        elif pkt.pid_name == "NAK":
            self.stats.nak_count += 1
        elif pkt.pid_name == "STALL":
            self.stats.stall_count += 1

        self._notify(pkt)

    def export_pcap(self, filepath: Optional[Path] = None) -> Path:
        """导出为 pcap 格式 (LINKTYPE_USB_2_0 = 288)。

        LINKTYPE_USB_2_0 记录内容是原始链路层线上字节 (PID 开头, 含 CRC),
        与 Cynthion analyzer 捕获格式一致 — Wireshark/tshark 的 usbll dissector 直接消费。
        """
        if filepath is None:
            filepath = _CAP_DIR / f"export_{int(time.time())}.pcap"
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "wb") as f:
            # pcap global header (little-endian, microsecond timestamps)
            f.write(b"\xd4\xc3\xb2\xa1")  # magic (little-endian host byte order)
            f.write((2).to_bytes(2, "little"))  # version major
            f.write((4).to_bytes(2, "little"))  # version minor
            f.write((0).to_bytes(4, "little"))  # thiszone
            f.write((0).to_bytes(4, "little"))  # sigfigs
            f.write((65535).to_bytes(4, "little"))  # snaplen
            f.write((288).to_bytes(4, "little"))  # LINKTYPE_USB_2_0 = 288

            sof_counter = 0
            for pkt in self.packets:
                ts = int(pkt.timestamp)
                ts_us = int((pkt.timestamp - ts) * 1e6)
                if pkt.packet_type == PacketType.SOF:
                    sof_counter += 1
                frame = _encode_link_frame(pkt, sof_counter)
                cap_len = len(frame)

                f.write(ts.to_bytes(4, "little"))
                f.write(ts_us.to_bytes(4, "little"))
                f.write(cap_len.to_bytes(4, "little"))
                f.write(cap_len.to_bytes(4, "little"))
                f.write(frame)

        return filepath

    def get_summary(self) -> dict:
        """获取当前捕获摘要"""
        return {
            "capturing": self.is_capturing,
            "total": self.stats.total_packets,
            "setup": self.stats.setup_count,
            "data": self.stats.data_count,
            "ack": self.stats.ack_count,
            "nak": self.stats.nak_count,
            "stall": self.stats.stall_count,
            "pps": round(self.stats.pps, 1),
            "elapsed": round(self.stats.elapsed, 1),
            "devices": len(self.stats.by_device),
            "top_devices": sorted(self.stats.by_device.items(), key=lambda x: -x[1])[:5],
            "type_dist": dict(sorted(self.stats.by_type.items(), key=lambda x: -x[1])),
        }
