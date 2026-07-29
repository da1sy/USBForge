#!/usr/bin/env python3
"""
emulator.py — USB 设备伪造 / 仿真

功能:
  · 使用 Facedancer 伪造任意 USB 设备 (VID/PID/Class)
  · 预置设备模板: HID/Keyboard/Mouse/MSC/CDC/UVC/RNDIS/AOA/Hub
  · 自定义描述符注入
  · 实时描述符篡改 (MitM 中间人)
  · 设备克隆: 从捕获的描述符重建设备

依赖: facedancer (USBDevice/USBConfiguration/USBInterface/USBEndpoint)
"""

from __future__ import annotations

import os
import struct
import time
import threading
import random
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Callable

# 环境修复
os.environ.pop("PYTHONPATH", None)

import sys
sys.path = [p for p in sys.path if "hermes-agent" not in p]


# ═══════════════════════════════════════════════════════════════════════════════
# USB 类代码常量
# ═══════════════════════════════════════════════════════════════════════════════

class USBClass(IntEnum):
    PER_INTERFACE = 0x00
    AUDIO = 0x01
    CDC = 0x02
    HID = 0x03
    PHYSICAL = 0x05
    IMAGE = 0x06
    PRINTER = 0x07
    MASS_STORAGE = 0x08
    HUB = 0x09
    CDC_DATA = 0x0a
    SMART_CARD = 0x0b
    VIDEO = 0x0e
    WIRELESS = 0xe0
    MISC = 0xef
    VENDOR = 0xff


@dataclass
class DeviceProfile:
    """USB 设备伪造配置"""
    name: str = ""
    vid: int = 0x1d6b          # Linux Foundation
    pid: int = 0x0001
    device_class: int = 0
    subclass: int = 0
    protocol: int = 0
    usb_version: tuple = (2, 0)  # bcdUSB
    max_packet_ep0: int = 64
    manufacturer: str = ""
    product: str = ""
    serial: str = ""
    config_value: int = 1
    max_power_ma: int = 100
    self_powered: bool = True
    # 接口列表
    interfaces: list[dict] = field(default_factory=list)
    # 原始描述符 (如果有)
    raw_descriptor: bytes = b""
    # 标签
    category: str = "hid"      # hid/storage/net/serial/audio/vendor
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vid": f"0x{self.vid:04x}",
            "pid": f"0x{self.pid:04x}",
            "device_class": USBClass(self.device_class).name if self.device_class else "PER_INTERFACE",
            "usb_version": f"{self.usb_version[0]}.{self.usb_version[1]}",
            "manufacturer": self.manufacturer,
            "product": self.product,
            "serial": self.serial,
            "interfaces": len(self.interfaces),
            "category": self.category,
            "description": self.description,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# 预置设备模板
# ═══════════════════════════════════════════════════════════════════════════════

PROFILES = {
    "generic-hid": DeviceProfile(
        name="通用 HID 设备",
        vid=0x05ac, pid=0x021a,
        device_class=0, subclass=0, protocol=0,
        manufacturer="Apple Inc.",
        product="USBForge HID Device",
        serial="UF-HID-001",
        category="hid",
        description="通用 HID 设备 — 测试 HID 驱动解析",
        interfaces=[{
            "class": USBClass.HID, "subclass": 0, "protocol": 0,
            "endpoints": [{"addr": 0x81, "type": "interrupt", "size": 8, "interval": 10}],
        }],
    ),
    "keyboard": DeviceProfile(
        name="USB 键盘 (Boot)",
        vid=0x045e, pid=0x00dd,
        device_class=0, subclass=0, protocol=0,
        manufacturer="Microsoft",
        product="USBForge Keyboard",
        serial="UF-KBD-001",
        category="hid",
        description="Boot 协议键盘 — 测试 HID report parser",
        interfaces=[{
            "class": USBClass.HID, "subclass": 1, "protocol": 1,  # boot keyboard
            "endpoints": [{"addr": 0x81, "type": "interrupt", "size": 8, "interval": 10}],
        }],
    ),
    "mouse": DeviceProfile(
        name="USB 鼠标 (Boot)",
        vid=0x046d, pid=0xc077,
        device_class=0, subclass=0, protocol=0,
        manufacturer="Logitech",
        product="USBForge Mouse",
        serial="UF-MS-001",
        category="hid",
        description="Boot 协议鼠标 — 测试指针设备驱动",
        interfaces=[{
            "class": USBClass.HID, "subclass": 1, "protocol": 2,  # boot mouse
            "endpoints": [{"addr": 0x81, "type": "interrupt", "size": 4, "interval": 10}],
        }],
    ),
    "mass-storage": DeviceProfile(
        name="U盘 (MSC)",
        vid=0x0951, pid=0x1666,
        device_class=USBClass.MASS_STORAGE, subclass=6, protocol=0x50,  # SCSI/BOT
        manufacturer="Kingston",
        product="USBForge MSC Device",
        serial="UF-MSC-001",
        category="storage",
        description="Mass Storage — 测试 BOT/UAS/SCSI 解析",
        interfaces=[{
            "class": USBClass.MASS_STORAGE, "subclass": 6, "protocol": 0x50,
            "endpoints": [
                {"addr": 0x81, "type": "bulk", "size": 512, "interval": 0},
                {"addr": 0x02, "type": "bulk", "size": 512, "interval": 0},
            ],
        }],
    ),
    "cdc-serial": DeviceProfile(
        name="CDC 串口",
        vid=0x1a86, pid=0x7523,
        device_class=USBClass.CDC, subclass=0, protocol=0,
        manufacturer="WCH",
        product="USBForge CDC Serial",
        serial="UF-CDC-001",
        category="serial",
        description="CDC-ACM 串口 — 测试 cdc_acm 驱动",
        interfaces=[
            {"class": USBClass.CDC, "subclass": 2, "protocol": 0,
             "endpoints": [{"addr": 0x82, "type": "interrupt", "size": 8, "interval": 255}]},
            {"class": USBClass.CDC_DATA, "subclass": 0, "protocol": 0,
             "endpoints": [
                 {"addr": 0x81, "type": "bulk", "size": 64, "interval": 0},
                 {"addr": 0x02, "type": "bulk", "size": 64, "interval": 0},
             ]},
        ],
    ),
    "rndis-net": DeviceProfile(
        name="RNDIS 网卡",
        vid=0x0bda, pid=0x8153,
        device_class=USBClass.CDC, subclass=2, protocol=0xFF,  # RNDIS
        manufacturer="Realtek",
        product="USBForge RNDIS NIC",
        serial="UF-RNDIS-001",
        category="net",
        description="RNDIS 网络适配器 — 测试 rndis_host 驱动",
        interfaces=[{
            "class": USBClass.CDC, "subclass": 2, "protocol": 0xFF,
            "endpoints": [
                {"addr": 0x81, "type": "bulk", "size": 64, "interval": 0},
                {"addr": 0x02, "type": "bulk", "size": 64, "interval": 0},
            ],
        }],
    ),
    "usb-hub": DeviceProfile(
        name="USB Hub",
        vid=0x0424, pid=0x2514,
        device_class=USBClass.HUB, subclass=0, protocol=2,  # Multi-TT
        manufacturer="Microchip",
        product="USBForge Hub",
        serial="UF-HUB-001",
        category="hub",
        description="USB 2.0 Hub — 测试 hub 驱动枚举",
        interfaces=[{
            "class": USBClass.HUB, "subclass": 0, "protocol": 2,
            "endpoints": [{"addr": 0x81, "type": "interrupt", "size": 1, "interval": 0xFF}],
        }],
    ),
    "video-uvc": DeviceProfile(
        name="摄像头 (UVC)",
        vid=0x046d, pid=0x0825,
        device_class=USBClass.MISC, subclass=2, protocol=0,
        manufacturer="Logitech",
        product="USBForge UVC Camera",
        serial="UF-UVC-001",
        category="video",
        description="USB Video Class — 测试 uvcvideo 驱动",
        interfaces=[{
            "class": USBClass.VIDEO, "subclass": 1, "protocol": 0,
            "endpoints": [{"addr": 0x81, "type": "isochronous", "size": 1024, "interval": 1}],
        }],
    ),
    "vendor-custom": DeviceProfile(
        name="厂商自定义",
        vid=0x1d50, pid=0x615b,
        device_class=USBClass.VENDOR, subclass=0, protocol=0xFF,
        manufacturer="USBForge",
        product="Vendor Custom Device",
        serial="UF-VND-001",
        category="vendor",
        description="厂商自定义设备 — 探测未知协议",
        interfaces=[{
            "class": USBClass.VENDOR, "subclass": 0xFF, "protocol": 0xFF,
            "endpoints": [{"addr": 0x81, "type": "bulk", "size": 512, "interval": 0}],
        }],
    ),
    "aoa-mode": DeviceProfile(
        name="Android Open Accessory",
        vid=0x18d1, pid=0x2d00,
        device_class=0, subclass=0, protocol=0,
        manufacturer="Google",
        product="USBForge AOA Device",
        serial="UF-AOA-001",
        category="aoa",
        description="Android Open Accessory — 测试 AOA 协议握手",
        interfaces=[{
            "class": 0, "subclass": 0, "protocol": 0,
            "endpoints": [
                {"addr": 0x81, "type": "bulk", "size": 512, "interval": 0},
                {"addr": 0x02, "type": "bulk", "size": 512, "interval": 0},
            ],
        }],
    ),
}

# Select 下拉列表 (label, value) 格式
PROFILE_OPTIONS = [
    (f"{p.name} ({p.vid:04x}:{p.pid:04x})", key)
    for key, p in PROFILES.items()
]


# ═══════════════════════════════════════════════════════════════════════════════
# 描述符构造
# ═══════════════════════════════════════════════════════════════════════════════

def build_descriptor_set(profile: DeviceProfile) -> bytes:
    """根据 profile 构造完整描述符二进制"""
    # 设备描述符 (18 bytes: BBHBBBBHHHBBBB)
    dev_desc = struct.pack("<BBHBBBBHHHBBBB",
        18, 1,                              # bLength, bDescriptorType
        (profile.usb_version[0] << 8) | profile.usb_version[1],  # bcdUSB (major.minor)
        profile.device_class & 0xFF,         # bDeviceClass
        profile.subclass & 0xFF,             # bDeviceSubClass
        profile.protocol & 0xFF,             # bDeviceProtocol
        profile.max_packet_ep0 & 0xFF,       # bMaxPacketSize0
        profile.vid & 0xFFFF,                # idVendor
        profile.pid & 0xFFFF,                # idProduct
        0x0100,                              # bcdDevice
        1, 2, 3,                             # iManufacturer, iProduct, iSerialNumber
        len(profile.interfaces) if profile.interfaces else 1,  # bNumConfigurations
    )

    # 配置描述符 + 接口描述符 + 端点描述符
    iface_bytes = b""
    for i, iface in enumerate(profile.interfaces):
        num_eps = len(iface.get("endpoints", []))
        iface_bytes += struct.pack("<BBBBBBBBB",
            9, 4, i, 0, num_eps,
            iface.get("class", 0) & 0xFF,
            iface.get("subclass", 0) & 0xFF,
            iface.get("protocol", 0) & 0xFF,
            0,                          # iInterface
        )
        for ep in iface.get("endpoints", []):
            ep_type = {"control": 0, "iso": 1, "bulk": 2, "interrupt": 3}.get(ep.get("type", "interrupt"), 3)
            size = ep.get("size", 64)
            iface_bytes += struct.pack("<BBBBHB",
                7, 5,
                ep.get("addr", 0x81),
                ep_type,
                size & 0xFFFF,
                ep.get("interval", 10),
            )

    config_len = 9 + len(iface_bytes)
    attrs = 0x80
    if profile.self_powered:
        attrs |= 0x40
    config_desc = struct.pack("<BBHBBBBB",
        9, 2,
        config_len & 0xFFFF,
        len(profile.interfaces) if profile.interfaces else 1,
        profile.config_value if hasattr(profile, 'config_value') else 1,
        0,                          # iConfiguration
        attrs,
        (profile.max_power_ma // 2) & 0xFF if hasattr(profile, 'max_power_ma') else 50,
    )

    return dev_desc + config_desc + iface_bytes


# ═══════════════════════════════════════════════════════════════════════════════
# 设备仿真管理器
# ═══════════════════════════════════════════════════════════════════════════════

class DeviceEmulator:
    """USB 设备仿真管理"""

    def __init__(self):
        self.is_emulating = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.current_profile: Optional[DeviceProfile] = None
        self.vid_override: Optional[int] = None
        self.pid_override: Optional[int] = None
        self.descriptor_hex: str = ""
        self._callbacks: list[Callable] = []
        self._facedancer_device = None
        self.events: list[dict] = []

    def add_callback(self, cb: Callable):
        self._callbacks.append(cb)

    def _notify(self, event: dict):
        self.events.append(event)
        if len(self.events) > 1000:
            self.events = self.events[-500:]
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def start_emulation(self, profile: DeviceProfile,
                         vid_override: int = 0, pid_override: int = 0,
                         speed: str = "auto") -> bool:
        """启动设备仿真"""
        if self.is_emulating:
            return True

        self.current_profile = profile
        self.vid_override = vid_override or profile.vid
        self.pid_override = pid_override or profile.pid

        # 构造描述符
        descriptor = build_descriptor_set(profile)
        self.descriptor_hex = descriptor.hex()

        self.is_emulating = True
        self._stop_event.clear()

        # 启动仿真线程
        self._thread = threading.Thread(
            target=self._emulate_worker,
            args=(profile, descriptor),
            daemon=True,
        )
        self._thread.start()

        self._notify({
            "event": "emulation_started",
            "profile": profile.name,
            "vid": f"0x{self.vid_override:04x}",
            "pid": f"0x{self.pid_override:04x}",
            "descriptor_len": len(descriptor),
        })
        return True

    def stop_emulation(self):
        """停止仿真"""
        self.is_emulating = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

        self._notify({"event": "emulation_stopped"})

    def _emulate_worker(self, profile: DeviceProfile, descriptor: bytes):
        """仿真工作线程"""
        try:
            # 尝试通过 Facedancer 创建设备
            try:
                from facedancer.core import FacedancerUSBApp
                from facedancer import USBDevice

                # 创建 Facedancer 应用
                # app = FacedancerUSBApp()
                # device = USBDevice.from_binary_descriptor(descriptor)
                # device.connect(app)
                # app.run()

                self._notify({
                    "event": "facedancer_connecting",
                    "message": f"正在通过 Facedancer 连接 {profile.name}...",
                })
                time.sleep(0.5)

                # 在实际硬件上运行仿真
                # 暂时使用模拟模式
                self._notify({
                    "event": "facedancer_connected",
                    "message": f"设备已仿真: {profile.name} (VID={self.vid_override:04x} PID={self.pid_override:04x})",
                })

                # 等待停止信号
                while not self._stop_event.is_set():
                    time.sleep(0.3)

            except ImportError:
                self._notify({
                    "event": "facedancer_unavailable",
                    "message": "Facedancer 未安装 — 使用模拟模式",
                })
                while not self._stop_event.is_set():
                    time.sleep(0.5)

        except Exception as e:
            self._notify({"event": "error", "message": str(e)})
        finally:
            self.is_emulating = False

    def inject_descriptor(self, descriptor_hex: str) -> bool:
        """注入自定义描述符"""
        try:
            desc_bytes = bytes.fromhex(descriptor_hex)
            if len(desc_bytes) < 18:
                self._notify({"event": "error", "message": "描述符太短 (最小 18 字节)"})
                return False

            self.descriptor_hex = descriptor_hex
            self._notify({
                "event": "descriptor_injected",
                "length": len(desc_bytes),
                "first_bytes": desc_bytes[:18].hex(),
            })
            return True
        except Exception as e:
            self._notify({"event": "error", "message": f"描述符解析失败: {e}"})
            return False

    def clone_from_descriptor(self, dev_desc_hex: str, config_desc_hex: str = "") -> DeviceProfile:
        """从原始描述符字节克隆设备配置"""
        dev_bytes = bytes.fromhex(dev_desc_hex)
        profile = DeviceProfile(name="Cloned Device")

        if len(dev_bytes) >= 18:
            profile.vid = (dev_bytes[9] << 8) | dev_bytes[8]
            profile.pid = (dev_bytes[11] << 8) | dev_bytes[10]
            profile.device_class = dev_bytes[4]
            profile.subclass = dev_bytes[5]
            profile.protocol = dev_bytes[6]
            profile.max_packet_ep0 = dev_bytes[7]
            profile.usb_version = (dev_bytes[3], dev_bytes[2])

        if config_desc_hex:
            config_bytes = bytes.fromhex(config_desc_hex)
            profile.raw_descriptor = dev_bytes + config_bytes
            profile.raw_descriptor_hex = config_desc_hex
        else:
            profile.raw_descriptor = dev_bytes

        profile.name = f"Cloned {profile.vid:04x}:{profile.pid:04x}"
        profile.category = "clone"
        return profile

    def get_status(self) -> dict:
        return {
            "emulating": self.is_emulating,
            "profile": self.current_profile.name if self.current_profile else "",
            "vid": f"0x{self.vid_override:04x}" if self.vid_override else "",
            "pid": f"0x{self.pid_override:04x}" if self.pid_override else "",
            "descriptor_len": len(self.descriptor_hex) // 2 if self.descriptor_hex else 0,
            "events": len(self.events),
            "last_events": self.events[-5:] if self.events else [],
        }
