#!/usr/bin/env python3
"""
injector.py — USB 流量篡改 / 数据包注入

功能:
  · 构造自定义 USB 控制请求 (standard/class/vendor)
  · 构造自定义 USB 数据包
  · 批量发包 / 重放攻击
  · 描述符克隆与注入
  · MitM: 在 TARGET-C↔DUT 之间拦截并修改数据

依赖: facedancer (USBDevice/USBEndpoint/USBConfiguration)
"""

from __future__ import annotations

import os
import struct
import time
import threading
import random
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional, Callable

# 环境修复
os.environ.pop("PYTHONPATH", None)

import sys
sys.path = [p for p in sys.path if "hermes-agent" not in p]


# ═══════════════════════════════════════════════════════════════════════════════
# USB 请求类型常量
# ═══════════════════════════════════════════════════════════════════════════════

# bmRequestType 方向
DIR_OUT = 0x00  # Host → Device
DIR_IN = 0x80   # Device → Host

# bmRequestType 类型
TYPE_STANDARD = 0x00
TYPE_CLASS = 0x20
TYPE_VENDOR = 0x40

# bmRequestType 接收者
RCV_DEVICE = 0x00
RCV_INTERFACE = 0x01
RCV_ENDPOINT = 0x02
RCV_OTHER = 0x03

# 标准请求 bRequest
REQ_GET_STATUS = 0x00
REQ_CLEAR_FEATURE = 0x01
REQ_SET_FEATURE = 0x03
REQ_SET_ADDRESS = 0x05
REQ_GET_DESCRIPTOR = 0x06
REQ_SET_DESCRIPTOR = 0x07
REQ_GET_CONFIGURATION = 0x08
REQ_SET_CONFIGURATION = 0x09
REQ_GET_INTERFACE = 0x0a
REQ_SET_INTERFACE = 0x0b
REQ_SYNCH_FRAME = 0x0c

# 描述符类型
DESC_DEVICE = 0x0100
DESC_CONFIG = 0x0200
DESC_STRING = 0x0300
DESC_INTERFACE = 0x0400
DESC_ENDPOINT = 0x0500
DESC_DEVICE_QUALIFIER = 0x0600
DESC_HID = 0x2100
DESC_REPORT = 0x2200


@dataclass
class ControlRequest:
    """USB 控制传输请求"""
    direction: int = DIR_OUT    # 0x00=OUT, 0x80=IN
    req_type: int = TYPE_STANDARD
    recipient: int = RCV_DEVICE
    bRequest: int = 0x06        # GET_DESCRIPTOR
    wValue: int = 0x0100        # Device descriptor
    wIndex: int = 0
    wLength: int = 64
    data: bytes = b""
    name: str = ""

    @property
    def bmRequestType(self) -> int:
        return self.direction | self.req_type | self.recipient

    def to_bytes(self) -> bytes:
        """8 字节 SETUP 事务数据"""
        return struct.pack("<BBHHH",
                           self.bmRequestType,
                           self.bRequest,
                           self.wValue,
                           self.wIndex,
                           self.wLength)

    def to_dict(self) -> dict:
        type_names = {0: "Standard", 1: "Class", 2: "Vendor"}
        rcpt_names = {0: "Device", 1: "Interface", 2: "Endpoint", 3: "Other"}
        req_names = {
            0: "GET_STATUS", 1: "CLEAR_FEATURE", 3: "SET_FEATURE",
            5: "SET_ADDRESS", 6: "GET_DESCRIPTOR", 7: "SET_DESCRIPTOR",
            8: "GET_CONFIGURATION", 9: "SET_CONFIGURATION",
            10: "GET_INTERFACE", 11: "SET_INTERFACE", 12: "SYNCH_FRAME",
        }
        return {
            "bmRequestType": f"0x{self.bmRequestType:02x}",
            "direction": "IN" if self.direction else "OUT",
            "type": type_names.get(self.req_type >> 5, "?"),
            "recipient": rcpt_names.get(self.recipient, "?"),
            "bRequest": f"0x{self.bRequest:02x} ({req_names.get(self.bRequest, 'unknown')})",
            "wValue": f"0x{self.wValue:04x}",
            "wIndex": f"0x{self.wIndex:04x}",
            "wLength": self.wLength,
            "data_hex": self.data.hex()[:64],
        }


@dataclass
class PacketTemplate:
    """预置数据包模板"""
    name: str
    description: str
    request: ControlRequest
    category: str = "standard"  # standard/class/vendor/fuzz


# ═══════════════════════════════════════════════════════════════════════════════
# 预置请求模板
# ═══════════════════════════════════════════════════════════════════════════════

TEMPLATES = [
    PacketTemplate(
        name="Get Device Descriptor",
        description="获取设备描述符 (VID/PID/Class)",
        request=ControlRequest(direction=DIR_IN, bRequest=REQ_GET_DESCRIPTOR, wValue=DESC_DEVICE, wLength=18),
        category="standard",
    ),
    PacketTemplate(
        name="Get Config Descriptor",
        description="获取配置描述符 (接口/端点)",
        request=ControlRequest(direction=DIR_IN, bRequest=REQ_GET_DESCRIPTOR, wValue=DESC_CONFIG, wLength=255),
        category="standard",
    ),
    PacketTemplate(
        name="Get HID Descriptor",
        description="获取 HID 类描述符",
        request=ControlRequest(direction=DIR_IN, bRequest=REQ_GET_DESCRIPTOR, wValue=DESC_HID, wLength=9),
        category="class",
    ),
    PacketTemplate(
        name="Get HID Report",
        description="获取 HID 报告描述符",
        request=ControlRequest(direction=DIR_IN, bRequest=REQ_GET_DESCRIPTOR, wValue=DESC_REPORT, wLength=255),
        category="class",
    ),
    PacketTemplate(
        name="Get String Descriptor 0",
        description="获取语言 ID 列表",
        request=ControlRequest(direction=DIR_IN, bRequest=REQ_GET_DESCRIPTOR, wValue=DESC_STRING, wLength=4),
        category="standard",
    ),
    PacketTemplate(
        name="Get Status (Device)",
        description="获取设备状态 (供电/远程唤醒)",
        request=ControlRequest(direction=DIR_IN, bRequest=REQ_GET_STATUS, wLength=2),
        category="standard",
    ),
    PacketTemplate(
        name="Set Address 0",
        description="设置设备地址为 0 (攻击: 强制地址冲突)",
        request=ControlRequest(direction=DIR_OUT, bRequest=REQ_SET_ADDRESS, wValue=0),
        category="fuzz",
    ),
    PacketTemplate(
        name="Set Config 0",
        description="取消配置 (可能导致驱动崩溃)",
        request=ControlRequest(direction=DIR_OUT, bRequest=REQ_SET_CONFIGURATION, wValue=0),
        category="fuzz",
    ),
    PacketTemplate(
        name="Vendor Request 0xFF",
        description="厂商自定义请求 (探测后门)",
        request=ControlRequest(direction=DIR_IN, req_type=TYPE_VENDOR, bRequest=0xFF, wLength=64),
        category="vendor",
    ),
    PacketTemplate(
        name="UAC Volume Get",
        description="USB Audio Class: 获取音量",
        request=ControlRequest(direction=DIR_IN, req_type=TYPE_CLASS, recipient=RCV_INTERFACE,
                               bRequest=0x81, wValue=0x0200, wLength=2),
        category="class",
    ),
    PacketTemplate(
        name="MSC Inquiry",
        description="Mass Storage: INQUIRY 命令",
        request=ControlRequest(direction=DIR_OUT, req_type=TYPE_CLASS, recipient=RCV_INTERFACE,
                               bRequest=0xFE, wValue=0, wLength=0x24),
        category="class",
    ),
    PacketTemplate(
        name="Hub GetDescriptor",
        description="Hub 类描述符请求",
        request=ControlRequest(direction=DIR_IN, req_type=TYPE_CLASS, bRequest=REQ_GET_DESCRIPTOR,
                               wValue=0x2900, wLength=9),
        category="class",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# 描述符构造器
# ═══════════════════════════════════════════════════════════════════════════════

def build_device_descriptor(
    vid: int = 0x05ac, pid: int = 0x021a,
    device_class: int = 0, subclass: int = 0, protocol: int = 0,
    usb_version: tuple = (2, 0), max_packet_ep0: int = 64,
) -> bytes:
    """构造设备描述符"""
    return struct.pack("<BBBBHHHHBBBBBB",
        18, 1,                              # bLength, bDescriptorType
        usb_version[1], usb_version[0],     # bcdUSB
        device_class, subclass, protocol,   # class/subclass/protocol
        max_packet_ep0,                     # bMaxPacketSize0
        vid & 0xFFFF, pid & 0xFFFF,         # idVendor, idProduct
        0x01, 0x00,                         # bcdDevice
        1, 2, 3,                            # iManufacturer, iProduct, iSerialNumber
        1,                                  # bNumConfigurations
    )


def build_config_descriptor(
    num_interfaces: int = 1,
    config_value: int = 1,
    max_power_ma: int = 100,
    self_powered: bool = True,
    remote_wakeup: bool = False,
) -> bytes:
    """构造配置描述符"""
    attrs = 0x80
    if self_powered:
        attrs |= 0x40
    if remote_wakeup:
        attrs |= 0x20
    return struct.pack("<BBBBBBBB",
        9, 2,                               # bLength, bDescriptorType
        (num_interfaces * 9 + 9) & 0xFF,    # wTotalLength (low)
        ((num_interfaces * 9 + 9) >> 8) & 0xFF,  # wTotalLength (high)
        num_interfaces, config_value,       # bNumInterfaces, bConfigurationValue
        0,                                  # iConfiguration
        attrs, max_power_ma // 2,           # bmAttributes, bMaxPower
    )


def build_endpoint_descriptor(
    ep_addr: int = 0x81,
    transfer_type: int = 3,  # Interrupt
    max_packet_size: int = 8,
    interval: int = 10,
) -> bytes:
    """构造端点描述符"""
    return struct.pack("<BBBBBBB",
        7, 5,                               # bLength, bDescriptorType
        ep_addr,                            # bEndpointAddress
        transfer_type,                      # bmAttributes
        max_packet_size & 0xFF,             # wMaxPacketSize (low)
        (max_packet_size >> 8) & 0xFF,      # wMaxPacketSize (high)
        interval,                           # bInterval
    )


def build_full_hid_descriptor() -> bytes:
    """构造完整 HID 设备描述符集 (device + config + interface + endpoint + HID)"""
    dev_desc = build_device_descriptor(
        vid=0x05ac, pid=0x021a,
        device_class=0, subclass=0, protocol=0,
    )

    # HID interface
    iface_desc = struct.pack("<BBBBBBBB",
        9, 4, 0, 0, 1, 3, 0, 0,  # interface, HID, no boot
    )
    # HID class descriptor
    hid_desc = struct.pack("<BBBBBBBBH",
        9, 0x21, 0x11, 0x01, 0, 1, 0x22, 34, 0,
    )
    # Interrupt IN endpoint
    ep_desc = build_endpoint_descriptor(ep_addr=0x81, transfer_type=3, max_packet_size=8, interval=10)

    config_desc = struct.pack("<BBBBBBBB",
        9, 2,
        (9 + 9 + 9 + 7) & 0xFF,
        ((9 + 9 + 9 + 7) >> 8) & 0xFF,
        1, 1, 0, 0x80, 50,
    )

    return dev_desc + config_desc + iface_desc + hid_desc + ep_desc


# ═══════════════════════════════════════════════════════════════════════════════
# 数据包注入器
# ═══════════════════════════════════════════════════════════════════════════════

class PacketInjector:
    """USB 数据包注入 / 发送器"""

    def __init__(self):
        self.is_sending = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.sent_count = 0
        self.error_count = 0
        self._callbacks: list[Callable] = []
        self._host = None          # LibUSBHostApp 实例 (host 模式)
        self._facedancer_dev = None  # Facedancer 设备 (device 模式, 用于 inject_serial)
        self._connect_host()

    def _connect_host(self):
        """尝试连接 Cynthion host 后端 (TARGET-A → DUT)"""
        try:
            from facedancer.backends.libusbhost import LibUSBHostApp
            self._host = LibUSBHostApp()
            self._host.connect()
        except Exception:
            self._host = None

    def add_callback(self, cb: Callable):
        self._callbacks.append(cb)

    def _notify(self, event: dict):
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def send_single(self, req: ControlRequest) -> dict:
        """发送单个控制请求到 DUT (通过 Cynthion host 后端)"""
        result = {
            "request": req.to_dict(),
            "timestamp": time.time(),
            "status": "sent",
            "response_hex": "",
            "error": "",
        }

        try:
            if self._host is not None:
                # 通过 Cynthion LibUSBHost 后端发送真实 USB 控制请求
                if req.direction == DIR_IN:
                    # IN 方向 — 主机读取设备数据
                    data = self._host.control_request_in(
                        request_type=req.req_type,
                        recipient=req.recipient,
                        request=req.bRequest,
                        value=req.wValue,
                        index=req.wIndex,
                        length=req.wLength,
                    )
                    result["response_hex"] = bytes(data).hex() if data else ""
                    result["status"] = "ok"
                else:
                    # OUT 方向 — 主机向设备发送数据
                    self._host.control_request_out(
                        request_type=req.req_type,
                        recipient=req.recipient,
                        request=req.bRequest,
                        value=req.wValue,
                        index=req.wIndex,
                        data=list(req.data) if req.data else [],
                    )
                    result["status"] = "ok"
                self.sent_count += 1
            else:
                # 无硬件 — 降级模拟
                self.sent_count += 1
                result["status"] = "sent (no hardware)"
        except Exception as e:
            self.error_count += 1
            result["status"] = "error"
            result["error"] = str(e)

        self._notify(result)
        return result

    def send_batch(self, requests: list[ControlRequest], delay_ms: int = 100) -> threading.Thread:
        """批量发送（异步线程）"""
        self.is_sending = True
        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._batch_worker,
            args=(requests, delay_ms / 1000.0),
            daemon=True,
        )
        self._thread.start()
        return self._thread

    def stop(self):
        self.is_sending = False
        self._stop_event.set()

    def _batch_worker(self, requests: list[ControlRequest], delay: float):
        for req in requests:
            if self._stop_event.is_set():
                break
            self.send_single(req)
            time.sleep(delay)
        self.is_sending = False
        self._notify({"event": "batch_complete", "sent": self.sent_count, "errors": self.error_count})

    def replay_pcap(self, pcap_path: Path) -> dict:
        """从 pcap (LINKTYPE_USB_2_0) 文件重放 USB 控制请求"""
        result = {"replayed": 0, "errors": 0}

        try:
            import struct as _struct
            data = pcap_path.read_bytes()

            if len(data) < 24:
                result["error"] = "pcap 文件过小"
                self._notify({"event": "replay_complete", **result})
                return result

            # 解析 pcap global header
            magic = _struct.unpack_from("<I", data, 0)[0]
            if magic == 0xA1B2C3D4:
                endian = "<"
            elif magic == 0xD4C3B2A1:
                endian = ">"
            else:
                result["error"] = f"非标准 pcap magic: 0x{magic:08x}"
                self._notify({"event": "replay_complete", **result})
                return result

            linktype = _struct.unpack_from(f"{endian}I", data, 20)[0]
            # LINKTYPE_USB_2_0 = 288, LINKTYPE_USB_LINUX = 189

            offset = 24  # 跳过 global header
            while offset + 16 <= len(data):
                incl_len = _struct.unpack_from(f"{endian}I", data, offset + 8)[0]
                offset += 16

                if offset + incl_len > len(data):
                    break

                pkt_data = data[offset:offset + incl_len]
                offset += incl_len

                # 解析 USB setup 包
                # LINKTYPE_USB_2_0 格式: USB header (64 bytes) + setup data
                # header offset 0x28 = endpoint, 0x08 = transfer_type
                usb_hdr_offset = 0

                # 检查是否为控制传输 (transfer_type=2 in USB_2_0 header)
                if linktype == 288 and len(pkt_data) >= 72:
                    # USB 2.0 header is 64 bytes, setup data starts at 64
                    xfer_type = pkt_data[0x08] if len(pkt_data) > 0x08 else 0xFF
                    setup_data = pkt_data[64:72] if len(pkt_data) >= 72 else b""

                    if xfer_type == 2 and len(setup_data) >= 8:
                        # 解析 8 字节 SETUP: bmRequestType, bRequest, wValue, wIndex, wLength
                        bmrt = setup_data[0]
                        breq = setup_data[1]
                        wval = _struct.unpack_from("<H", setup_data, 2)[0]
                        wind = _struct.unpack_from("<H", setup_data, 4)[0]
                        wlen = _struct.unpack_from("<H", setup_data, 6)[0]

                        req = ControlRequest(
                            direction=bmrt & 0x80,
                            req_type=bmrt & 0x60,
                            recipient=bmrt & 0x03,
                            bRequest=breq,
                            wValue=wval,
                            wIndex=wind,
                            wLength=wlen,
                            name=f"pcap replay SETUP",
                        )
                        self.send_single(req)
                        result["replayed"] += 1

                elif linktype == 189 and len(pkt_data) >= 64:
                    # LINKTYPE_USB_LINUX 格式
                    xfer_type = pkt_data[0] if len(pkt_data) > 0 else 0xFF
                    setup_data = pkt_data[48:56] if len(pkt_data) >= 56 else b""

                    if xfer_type == 2 and len(setup_data) >= 8:
                        bmrt = setup_data[0]
                        breq = setup_data[1]
                        wval = _struct.unpack_from("<H", setup_data, 2)[0]
                        wind = _struct.unpack_from("<H", setup_data, 4)[0]
                        wlen = _struct.unpack_from("<H", setup_data, 6)[0]

                        req = ControlRequest(
                            direction=bmrt & 0x80,
                            req_type=bmrt & 0x60,
                            recipient=bmrt & 0x03,
                            bRequest=breq,
                            wValue=wval,
                            wIndex=wind,
                            wLength=wlen,
                            name="pcap replay SETUP",
                        )
                        self.send_single(req)
                        result["replayed"] += 1

                time.sleep(0.001)  # 节流

        except Exception as e:
            result["error"] = str(e)

        self._notify({"event": "replay_complete", **result})
        return result


# ═══════════════════════════════════════════════════════伪装补全══════════════════════════════════════
# 变异引擎 (用于 fuzz/inject 组合)
# ═══════════════════════════════════════════════════════════════════════════════

def mutate_request(base: ControlRequest, rng: random.Random) -> list[ControlRequest]:
    """对控制请求进行变异，生成一系列测试用例"""
    variants = []

    # 变异 bRequest
    for val in [0x00, 0x01, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0a, 0x0b, 0x0c, 0xFF, rng.randint(0, 255)]:
        v = ControlRequest(
            direction=base.direction, req_type=base.req_type,
            recipient=base.recipient, bRequest=val,
            wValue=base.wValue, wIndex=base.wIndex, wLength=base.wLength,
            name=f"{base.name} (bRequest=0x{val:02x})",
        )
        variants.append(v)

    # 变异 wValue
    for val in [0x0000, 0x0001, 0x00FF, 0x0100, 0xFFFF, rng.randint(0, 0xFFFF)]:
        v = ControlRequest(
            direction=base.direction, req_type=base.req_type,
            recipient=base.recipient, bRequest=base.bRequest,
            wValue=val, wIndex=base.wIndex, wLength=base.wLength,
            name=f"{base.name} (wValue=0x{val:04x})",
        )
        variants.append(v)

    # 变异 wLength (缓冲区溢出)
    for val in [0, 1, 0xFF, 0x0100, 0xFFFF, 65535, 0x7FFF, 0x8000]:
        v = ControlRequest(
            direction=base.direction, req_type=base.req_type,
            recipient=base.recipient, bRequest=base.bRequest,
            wValue=base.wValue, wIndex=base.wIndex, wLength=val,
            name=f"{base.name} (wLength={val})",
        )
        variants.append(v)

    return variants
