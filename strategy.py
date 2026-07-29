#!/usr/bin/env python3
"""
strategy.py — 基于真实 Linux/Android USB 源码分析的增强模糊测试策略

策略来源（源码文件 → 漏洞模式 → 测试用例）:
  drivers/usb/core/config.c   → 描述符边界检查绕过
  drivers/usb/core/hub.c      → 枚举状态机异常
  drivers/usb/core/message.c  → 控制传输 URB 处理
  drivers/hid/hid-core.c      → HID 报告描述符解析
  drivers/usb/storage/*.c     → SCSI/BOT/UAS 协议
  drivers/net/usb/*.c          → USB 网卡 (RNDIS/ECM)
  Android UsbHostManager.java → JNI Native 崩溃
  Android UsbService.java     → Framework 异常
"""

from __future__ import annotations

import struct
import random
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════════════
# 从源码中提取的精确常量值 — 这些是变异的"靶心"
# ═══════════════════════════════════════════════════════════════════════════════

# --- drivers/usb/core/hub.c 枚举常量 ---
HUB_CONSTS = {
    "GET_DESCRIPTOR_TRIES":      2,      # 最大重试次数 (USB2.0)
    "GET_DESCRIPTOR_BUFSIZE":    64,     # 首次描述符读取的缓冲区大小
    "SET_ADDRESS_TRIES":         2,
    "PORT_RESET_TRIES":          5,
    "PORT_INIT_TRIES":           4,
    "DETECT_DISCONNECT_TRIES":   5,
    "USB_CTRL_SET_TIMEOUT":      5000,   # ms
    "USB_SHORT_SET_ADDRESS_REQ_TIMEOUT": 500, # ms
    "HUB_DEBOUNCE_TIMEOUT":      2000,   # ms
}

# --- drivers/hid/hid-core.c 限制值 ---
HID_LIMITS = {
    "HID_MAX_DESCRIPTOR_SIZE":   4096,   # 最大报告描述符大小
    "HID_MAX_USAGES":            12288,
    "HID_MAX_FIELDS":            128,
    "HID_MAX_IDS":               256,
    "HID_MAX_BUFFER_SIZE":       65536,
    "HID_DEFAULT_MAX_BUFFER_SIZE": 8192,
}

# --- 描述符大小常量 (drivers/usb/core/config.c) ---
DESC_SIZES = {
    "USB_DT_DEVICE_SIZE":        18,
    "USB_DT_CONFIG_SIZE":        9,
    "USB_DT_INTERFACE_SIZE":     9,
    "USB_DT_ENDPOINT_SIZE":      7,
    "USB_DT_ENDPOINT_AUDIO_SIZE": 9,    # 等时端点的扩展大小
    "USB_DT_SS_EP_COMP_SIZE":    6,     # SuperSpeed 端点伴侣
    "USB_DT_SSP_ISOC_EP_COMP_SIZE": 8,  # SuperSpeedPlus
    "USB_DT_HID_SIZE":           9,
    "USB_DT_REPORT_SIZE":        0,     # 变长
}

# --- USB 设备类码 ---
USB_CLASS_CODES = {
    0x00: "使用接口描述符定义",
    0x02: "通信设备 (CDC)",
    0x03: "HID (人机接口设备)",
    0x05: "物理设备",
    0x06: "图像设备",
    0x07: "打印机",
    0x08: "大容量存储 (MSC)",
    0x09: "Hub",
    0x0A: "CDC-Data",
    0x0B: "智能卡",
    0x0D: "内容安全",
    0x0E: "视频设备 (UVC)",
    0x0F: "个人医疗",
    0x10: "音频/视频设备",
    0x11: " billboarding",
    0xDC: "诊断设备",
    0xE0: "无线控制器 (蓝牙)",
    0xEF: "杂项设备",
    0xFE: "应用特定",
    0xFF: "厂商特定",
}

# --- 端点类型 ---
EP_TYPES = {
    0x00: "控制 (Control)",
    0x01: "等时 (Isochronous)",
    0x02: "批量 (Bulk)",
    0x03: "中断 (Interrupt)",
}

# --- wMaxPacketSize 限制 (高速 USB 2.0) ---
EP_MAXPACKET_SIZES = {
    "control":      [8, 16, 32, 64],
    "interrupt":    [1, 2, ..., 1024],   # 高速最大 1024
    "bulk":         [512],                # 高速必须 512
    "isochronous":  [1024],               # 高速最大 1024
    "ss_bulk":      [1024],               # SuperSpeed
    "ss_interrupt": [1024],
    "ss_isoch":     [1024, 2048, 3072],  # SS+ 可达 3072
}


# ═══════════════════════════════════════════════════════════════════════════════
# 模板描述符 — 基于真实 USB 规范
# ═══════════════════════════════════════════════════════════════════════════════

# 标准 HID 设备 — 键盘 (18 字节)
TPL_DEVICE_DESC = bytes([
    0x12,       # bLength
    0x01,       # bDescriptorType (Device)
    0x00, 0x02, # bcdUSB 2.0
    0x00,       # bDeviceClass (defined in interface)
    0x00,       # bDeviceSubClass
    0x00,       # bDeviceProtocol
    0x40,       # bMaxPacketSize0 (64)
    0x34, 0x12, # idVendor (示例)
    0x78, 0x56, # idProduct (示例)
    0x00, 0x01, # bcdDevice
    0x01,       # iManufacturer
    0x02,       # iProduct
    0x03,       # iSerialNumber
    0x01,       # bNumConfigurations
])

# 配置描述符 (34 字节 — HID 键盘)
TPL_CONFIG_DESC = bytes([
    # --- Configuration Descriptor (9 bytes) ---
    0x09,       # bLength
    0x02,       # bDescriptorType (Configuration)
    0x22, 0x00, # wTotalLength (34 bytes)
    0x01,       # bNumInterfaces
    0x01,       # bConfigurationValue
    0x00,       # iConfiguration
    0x80,       # bmAttributes (Bus Powered)
    0x32,       # MaxPower (100mA)
    # --- Interface Descriptor (9 bytes) ---
    0x09,       # bLength
    0x04,       # bDescriptorType (Interface)
    0x00,       # bInterfaceNumber
    0x00,       # bAlternateSetting
    0x01,       # bNumEndpoints
    0x03,       # bInterfaceClass (HID)
    0x01,       # bInterfaceSubClass (Boot Interface)
    0x01,       # bInterfaceProtocol (Keyboard)
    0x00,       # iInterface
    # --- HID Descriptor (9 bytes) ---
    0x09,       # bLength
    0x21,       # bDescriptorType (HID)
    0x10, 0x01, # bcdHID (1.10)
    0x00,       # bCountryCode
    0x01,       # bNumDescriptors
    0x22,       # bDescriptorType (Report)
    0x3F, 0x00, # wDescriptorLength (63 bytes)
    # --- Endpoint Descriptor (7 bytes) ---
    0x07,       # bLength
    0x05,       # bDescriptorType (Endpoint)
    0x81,       # bEndpointAddress (IN, EP1)
    0x03,       # bmAttributes (Interrupt)
    0x08, 0x00, # wMaxPacketSize (8)
    0x0A,       # bInterval (10ms)
])

# HID Report Descriptor (键盘 — 63 bytes)
TPL_HID_REPORT = bytes([
    0x05, 0x01, # Usage Page (Generic Desktop)
    0x09, 0x06, # Usage (Keyboard)
    0xA1, 0x01, # Collection (Application)
    0x05, 0x07, #   Usage Page (Keyboard)
    0x19, 0xE0, #   Usage Minimum (Left Control)
    0x29, 0xE7, #   Usage Maximum (Right GUI)
    0x15, 0x00, #   Logical Minimum (0)
    0x25, 0x01, #   Logical Maximum (1)
    0x75, 0x01, #   Report Size (1)
    0x95, 0x08, #   Report Count (8)
    0x81, 0x02, #   Input (Data,Var,Abs)
    0x95, 0x01, #   Report Count (1)
    0x75, 0x08, #   Report Size (8)
    0x81, 0x01, #   Input (Cnst,Arr,Abs)
    0x95, 0x05, #   Report Count (5)
    0x75, 0x01, #   Report Size (1)
    0x05, 0x08, #   Usage Page (LEDs)
    0x19, 0x01, #   Usage Minimum (Num Lock)
    0x29, 0x05, #   Usage Maximum (Kana)
    0x91, 0x02, #   Output (Data,Var,Abs)
    0x95, 0x01, #   Report Count (1)
    0x75, 0x03, #   Report Report Size (3)
    0x91, 0x01, #   Output (Cnst,Arr,Abs)
    0x95, 0x06, #   Report Count (6)
    0x75, 0x08, #   Report Size (8)
    0x15, 0x00, #   Logical Minimum (0)
    0x25, 0x65, #   Logical Maximum (101)
    0x05, 0x07, #   Usage Page (Keyboard)
    0x19, 0x00, #   Usage Minimum (0)
    0x29, 0x65, #   Usage Maximum (101)
    0x81, 0x00, #   Input (Data,Arr,Abs)
    0xC0,       # End Collection
])

# MSC (大容量存储) 配置描述符
TPL_MSC_CONFIG = bytes([
    # Configuration Descriptor
    0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32,
    # Interface Descriptor
    0x09, 0x04, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00,
    # Endpoint IN (Bulk)
    0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00,
    # Endpoint OUT (Bulk)
    0x07, 0x05, 0x02, 0x02, 0x00, 0x02, 0x00,
])


# ═════════════════════════════════════════════════　════════════════════════════
# 变异引擎 — 基础变异原语 (AFL/Syzkaller 风格)
# ═══════════════════════════════════════════════════════════════════════════════

class Mutator:
    """变异引擎 — 15 种基础变异原语 + USB 特定变异"""

    INTEREST_8  = [0, 1, 2, 3, 4, 8, 16, 32, 64, 100, 127, 128, 129, 200, 254, 255]
    INTEREST_16 = [0, 1, 2, 3, 4, 8, 16, 32, 64, 100, 127, 128, 255, 256, 511, 512,
                   1000, 1023, 1024, 4096, 32767, 32768, 65534, 65535]
    INTEREST_32 = [0, 1, 2, 3, 4, 8, 16, 32, 64, 127, 128, 255, 256, 511, 512,
                   4096, 32767, 32768, 65535, 65536, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]

    def __init__(self, rng: Optional[random.Random] = None):
        self.rng = rng or random.Random()

    # ── 基础变异原语 ──

    def bitflip(self, data: bytes) -> bytes:
        buf = bytearray(data)
        byte_idx = self.rng.randrange(len(buf))
        bit_idx = self.rng.randrange(8)
        buf[byte_idx] ^= (1 << bit_idx)
        return bytes(buf)

    def byteflip(self, data: bytes) -> bytes:
        buf = bytearray(data)
        idx = self.rng.randrange(len(buf))
        buf[idx] ^= 0xFF
        return bytes(buf)

    def arith(self, data: bytes, max_delta: int = 35) -> bytes:
        buf = bytearray(data)
        idx = self.rng.randrange(len(buf))
        buf[idx] = (buf[idx] + self.rng.randint(-max_delta, max_delta)) & 0xFF
        return bytes(buf)

    def interest_8(self, data: bytes) -> bytes:
        buf = bytearray(data)
        idx = self.rng.randrange(len(buf))
        buf[idx] = self.rng.choice(self.INTEREST_8)
        return bytes(buf)

    def interest_16(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if len(buf) < 2:
            return bytes(buf)
        idx = self.rng.randrange(len(buf) - 1)
        val = self.rng.choice(self.INTEREST_16)
        struct.pack_into('<H', buf, idx, val & 0xFFFF)
        return bytes(buf)

    def interest_32(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if len(buf) < 4:
            return bytes(buf)
        idx = self.rng.randrange(len(buf) - 3)
        val = self.rng.choice(self.INTEREST_32)
        struct.pack_into('<I', buf, idx, val & 0xFFFFFFFF)
        return bytes(buf)

    def insert_bytes(self, data: bytes, max_count: int = 8) -> bytes:
        idx = self.rng.randrange(len(data) + 1)
        count = self.rng.randint(1, max_count)
        new_bytes = bytes(self.rng.randint(0, 255) for _ in range(count))
        return data[:idx] + new_bytes + data[idx:]

    def delete_bytes(self, data: bytes, max_count: int = 4) -> bytes:
        if len(data) <= max_count:
            return data
        idx = self.rng.randrange(len(data) - max_count)
        count = self.rng.randint(1, max_count)
        return data[:idx] + data[idx+count:]

    def duplicate_chunk(self, data: bytes, max_chunk: int = 16) -> bytes:
        if len(data) < 2:
            return data
        chunk_size = min(self.rng.randint(1, max_chunk), len(data))
        src_idx = self.rng.randrange(len(data) - chunk_size + 1)
        dst_idx = self.rng.randrange(len(data) + 1)
        chunk = data[src_idx:src_idx+chunk_size]
        return data[:dst_idx] + chunk + data[dst_idx:]

    def havoc(self, data: bytes, iterations: int = 8) -> bytes:
        """随机组合多种变异 (AFL havoc 模式)"""
        buf = bytearray(data)
        ops = [self.bitflip, self.byteflip, self.arith, self.interest_8,
               self.interest_16, self.interest_32, self.insert_bytes,
               self.delete_bytes, self.duplicate_chunk]
        for _ in range(iterations):
            op = self.rng.choice(ops)
            buf = bytearray(op(bytes(buf)))
        return bytes(buf)

    # ── USB 描述符特定变异 ──

    def mutate_descriptor_length(self, data: bytes) -> bytes:
        """篡改 bLength — 来自 config.c 中 `size -= h->bLength` 的攻击面"""
        buf = bytearray(data)
        # 关键边界值: 0, 1, size-1, size+1, 0xFF
        target_length = self.rng.choice([
            0, 1, 2,                                    # 过小 → 负偏移
            len(data) - 1,                              # 比实际小 1
            len(data),                                  # 正好
            len(data) + 1,                              # 超出 1 字节
            len(data) + 9,                              # 超出一个描述符大小
            0xFF,                                        # 最大值
        ])
        buf[0] = target_length & 0xFF
        return bytes(buf)

    def mutate_descriptor_type(self, data: bytes) -> bytes:
        """篡改 bDescriptorType — 来自 config.c find_next_descriptor() 解析器混淆"""
        buf = bytearray(data)
        # 所有已知类型码 + 随机值
        known_types = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x21, 0x22, 0x23,
                       0x24, 0x25, 0x30, 0x41, 0x42, 0xFF]
        buf[1] = self.rng.choice(known_types + [self.rng.randint(0, 255)])
        return bytes(buf)

    def mutate_vid_pid(self, data: bytes) -> bytes:
        """篡改 VID/PID — 触发特定驱动加载路径"""
        buf = bytearray(data)
        if len(buf) >= 12:
            # 知名 VID 列表 + 随机
            known_vids = [0x05AC, 0x046D, 0x045E, 0x054C, 0x18D1,
                          0x19E5, 0x22B8, 0x0BB4, 0x04E8, 0x0781]
            vid = self.rng.choice(known_vids + [self.rng.randint(0, 0xFFFF)])
            pid = self.rng.randint(0, 0xFFFF)
            struct.pack_into('<HH', buf, 8, vid, pid)
        return bytes(buf)

    def mutate_class_codes(self, data: bytes) -> bytes:
        """篡改 Device Class/SubClass/Protocol — 触发不同驱动匹配"""
        buf = bytearray(data)
        if len(buf) >= 7:
            class_codes = list(USB_CLASS_CODES.keys())
            buf[4] = self.rng.choice(class_codes + [0xFF])  # bDeviceClass
            buf[5] = self.rng.randint(0, 255)                # bDeviceSubClass
            buf[6] = self.rng.randint(0, 255)                # bDeviceProtocol
        return bytes(buf)


# ═══════════════════════════════════════════════════════════════════════════════
# 测试用例与阶段定义
# ═══════════════════════════════════════════════════════════════════════════════

class FuzzPhase(IntEnum):
    DESCRIPTOR     = 1   # Phase 1: 描述符变异
    CONTROL        = 2   # Phase 2: 控制传输模糊
    ENUMERATION    = 3   # Phase 3: 枚举状态机
    DATA_TRANSFER  = 4   # Phase 4: 数据传输模糊
    TIMING         = 5   # Phase 5: 时序模糊
    HID_REPORT     = 6   # Phase 6: HID 报告描述符 (新增 — 来自 hid-core.c 分析)
    CLASS_SPECIFIC = 7   # Phase 7: 类特定协议 (MSC/CDC/UVC — 来自 storage/net 分析)
    MOBILE_SPECIFIC = 8  # Phase 8: 移动设备协议 (RNDIS/AOA/MTP — 嵌入式设备常见)


PHASE_NAMES = {
    FuzzPhase.DESCRIPTOR:     "描述符变异",
    FuzzPhase.CONTROL:        "控制传输模糊",
    FuzzPhase.ENUMERATION:    "枚举状态机",
    FuzzPhase.DATA_TRANSFER:  "数据传输模糊",
    FuzzPhase.TIMING:         "时序模糊",
    FuzzPhase.HID_REPORT:     "HID 报告描述符",
    FuzzPhase.CLASS_SPECIFIC: "类特定协议",
    FuzzPhase.MOBILE_SPECIFIC: "移动设备协议",
}

# 源码分析来源说明
PHASE_SOURCES = {
    FuzzPhase.DESCRIPTOR:     "drivers/usb/core/config.c → find_next_descriptor(), usb_parse_endpoint()",
    FuzzPhase.CONTROL:        "drivers/usb/core/message.c → usb_control_msg(), URB 处理",
    FuzzPhase.ENUMERATION:    "drivers/usb/core/hub.c → hub_port_init(), hub_set_address()",
    FuzzPhase.DATA_TRANSFER:  "drivers/usb/core/urb.c, drivers/usb/core/message.c → bulk/msg 传输",
    FuzzPhase.TIMING:         "drivers/usb/core/hub.c → 枚举重试/超时常量",
    FuzzPhase.HID_REPORT:     "drivers/hid/hid-core.c → hid_parse_report(), hid_open_report()",
    FuzzPhase.CLASS_SPECIFIC: "drivers/usb/storage/transport.c, drivers/net/usb/*.c",
    FuzzPhase.MOBILE_SPECIFIC:   "Android UsbHostManager.java, drivers/usb/gadget, AOA 协议",
}


@dataclass
class FuzzCase:
    """单个模糊测试用例"""
    case_id: int
    phase: FuzzPhase
    description: str
    # 设备模拟参数
    device_descriptor:   Optional[bytes] = None
    config_descriptor:   Optional[bytes] = None
    hid_report_descriptor: Optional[bytes] = None
    string_descriptors:  Optional[dict[int, bytes]] = None
    # 控制传输参数
    stall_ep0:           bool = False
    disconnect_on_req:   Optional[str] = None  # "GET_DESC", "SET_ADDR", "SET_CONFIG"
    delay_response_ms:   int = 0
    # 数据传输参数
    ep_data_override:    Optional[dict[int, bytes]] = None  # {endpoint_addr: data}
    # 类特定参数
    class_request_handler: Optional[str] = None  # "CBW_FUZZ", "RNDIS_FUZZ" 等
    # 元数据
    source_ref:          str = ""  # 对应的源码位置
    tags:                list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        d = {}
        for k, v in self.__dict__.items():
            if isinstance(v, bytes):
                d[k] = v.hex()
            elif isinstance(v, dict):
                d[k] = {str(k2): v2.hex() if isinstance(v2, bytes) else v2 for k2, v2 in v.items()}
            elif isinstance(v, FuzzPhase):
                d[k] = int(v)
            elif isinstance(v, list):
                d[k] = v
            else:
                d[k] = v
        return d

    @classmethod
    def from_json(cls, d: dict) -> "FuzzCase":
        kwargs = {}
        for k, v in d.items():
            if k in ("device_descriptor", "config_descriptor", "hid_report_descriptor") and isinstance(v, str):
                kwargs[k] = bytes.fromhex(v)
            elif k == "string_descriptors" and isinstance(v, dict):
                kwargs[k] = {int(k2): bytes.fromhex(v2) if isinstance(v2, str) else v2 for k2, v2 in v.items()}
            elif k == "ep_data_override" and isinstance(v, dict):
                kwargs[k] = {int(k2): bytes.fromhex(v2) if isinstance(v2, str) else v2 for k2, v2 in v.items()}
            elif k == "phase" and isinstance(v, int):
                kwargs[k] = FuzzPhase(v)
            else:
                kwargs[k] = v
        return cls(**kwargs)


# ══════════════════════════════════════════ ════════════════════════════════════
# 策略生成器 — 8 个阶段，每个阶段的用例都映射到具体源码路径
# ═══════════════════════════════════════════════════════════════════════════════

class StrategyGenerator:
    """基于源码分析的策略生成器"""

    # 设备类型配置
    PROFILES = {
        "generic-hid":    {"vid": 0x1234, "pid": 0x5678, "class": 0x00, "subclass": 0x00, "protocol": 0x00},
        "keyboard":       {"vid": 0x1234, "pid": 0x5678, "class": 0x00, "subclass": 0x00, "protocol": 0x00},
        "mouse":          {"vid": 0x1234, "pid": 0x5679, "class": 0x00, "subclass": 0x00, "protocol": 0x00},
        "generic-msc":    {"vid": 0x054C, "pid": 0x01D0, "class": 0x00, "subclass": 0x00, "protocol": 0x00},
        "generic-cdc":    {"vid": 0x05AC, "pid": 0x1402, "class": 0x02, "subclass": 0x00, "protocol": 0x00},
        "generic-uvc":    {"vid": 0x045E, "pid": 0x075D, "class": 0x0E, "subclass": 0x00, "protocol": 0x00},
        "generic-audio":  {"vid": 0x1234, "pid": 0x56AB, "class": 0x00, "subclass": 0x00, "protocol": 0x00},
        "rndis-net":      {"vid": 0x0422, "pid": 0x1234, "class": 0xEF, "subclass": 0x01, "protocol": 0x01},
        "aoa-device":     {"vid": 0x18D1, "pid": 0x2D00, "class": 0x00, "subclass": 0x00, "protocol": 0x00},
        "generic-ubs":    {"vid": 0x1234, "pid": 0x56CD, "class": 0x09, "subclass": 0x00, "protocol": 0x00},
        "generic-vendor": {"vid": 0x1234, "pid": 0x56FF, "class": 0xFF, "subclass": 0xFF, "protocol": 0xFF},
    }

    def __init__(self, mutator: Mutator, profile: str = "generic-hid"):
        self.mutator = mutator
        self.profile = profile
        self._case_counter = 0

    def _next_id(self) -> int:
        self._case_counter += 1
        return self._case_counter

    def _new_case(self, phase: FuzzPhase, description: str, **kwargs) -> FuzzCase:
        return FuzzCase(
            case_id=self._next_id(),
            phase=phase,
            description=description,
            **kwargs,
        )

    def _base_device_desc(self) -> bytes:
        """获取基础设备描述符（根据 profile 定制）"""
        buf = bytearray(TPL_DEVICE_DESC)
        prof = self.PROFILES.get(self.profile, self.PROFILES["generic-hid"])
        buf[4], buf[5], buf[6] = prof["class"], prof["subclass"], prof["protocol"]
        struct.pack_into('<HH', buf, 8, prof["vid"], prof["pid"])
        return bytes(buf)

    def _base_config_desc(self) -> bytes:
        if "msc" in self.profile:
            return TPL_MSC_CONFIG
        return TPL_CONFIG_DESC

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 1: 描述符变异 — drivers/usb/core/config.c
    # ═══════════════════════════════════════════════════════════════════════

    def gen_descriptor_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        """
        策略来源: config.c 的 find_next_descriptor() 循环:
          while (size > 0) {
              buffer += h->bLength;
              size -= h->bLength;     ← 如果 bLength=0，死循环
          }
        和 usb_parse_endpoint():
          if (d->bLength >= USB_DT_ENDPOINT_AUDIO_SIZE)  ← 边界分支
          else if (d->bLength >= USB_DT_ENDPOINT_SIZE)
        """
        cases = []
        base_dev = self._base_device_desc()
        base_cfg = self._base_config_desc()

        # 1.1 bLength 篡改 — config.c `size -= h->bLength`
        # 关键攻击值: 0 (死循环), 1 (仅 1 字节前进), size-1, size+1, 0xFF
        for i in range(min(10, max_cases)):
            mutated = self.mutator.mutate_descriptor_length(base_dev)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR,
                f"DeviceDesc bLength={mutated[0]:#x} (原始=0x12)",
                device_descriptor=mutated,
                source_ref="config.c:find_next_descriptor() — size -= h->bLength",
                tags=["bLength", "device_desc"],
            ))

        # 1.2 Config descriptor wTotalLength 篡改
        for i in range(min(6, max_cases)):
            cfg = bytearray(base_cfg)
            total_len_vals = [
                0, 1, 8,                       # 过小
                len(base_cfg) - 1,              # 比实际小
                len(base_cfg) + 100,            # 超出实际
                0xFFFF,                          # 最大值
                0x00FF,                          # 大但不合理
            ]
            val = self.mutator.rng.choice(total_len_vals)
            struct.pack_into('<H', cfg, 2, val)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR,
                f"ConfigDesc wTotalLength={val} (实际={len(base_cfg)})",
                device_descriptor=base_dev,
                config_descriptor=bytes(cfg),
                source_ref="config.c:usb_parse_configuration() — desc->wTotalLength",
                tags=["wTotalLength", "config_desc"],
            ))

        # 1.3 bDescriptorType 篡改 — 使解析器进入错误分支
        for i in range(min(4, max_cases)):
            mutated = self.mutator.mutate_descriptor_type(base_dev)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR,
                f"DeviceDesc bDescriptorType={mutated[1]:#x} (原始=0x01)",
                device_descriptor=mutated,
                source_ref="config.c:find_next_descriptor() — 类型混淆",
                tags=["bDescriptorType"],
            ))

        # 1.4 bNumInterfaces 声称有比实际更多的接口
        for extra in [5, 16, 50, 255]:
            cfg = bytearray(base_cfg)
            cfg[4] = extra  # bNumInterfaces
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR,
                f"ConfigDesc bNumInterfaces={extra} (实际=1) — 越界读取",
                device_descriptor=base_dev,
                config_descriptor=bytes(cfg),
                source_ref="config.c:usb_parse_configuration() — bNumInterfaces > 实际接口数",
                tags=["bNumInterfaces", "OOB"],
            ))

        # 1.5 Endpoint bLength 篡改 — config.c usb_parse_endpoint()
        cfg = bytearray(base_cfg)
        ep_offset = len(base_cfg) - 7  # 最后 7 字节是 endpoint desc
        for ep_len in [0, 3, 6, 8, 9, 0xFF]:
            cfg2 = bytearray(cfg)
            cfg2[ep_offset] = ep_len  # endpoint bLength
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR,
                f"EP bLength={ep_len} (原始=7) — USB_DT_ENDPOINT_SIZE/AUDIO_SIZE 分支",
                device_descriptor=base_dev,
                config_descriptor=bytes(cfg2),
                source_ref="config.c:usb_parse_endpoint() — if (d->bLength >= USB_DT_ENDPOINT_AUDIO_SIZE)",
                tags=["endpoint", "bLength"],
            ))

        # 1.6 wMaxPacketSize 篡改 — 超出协议限制
        cfg = bytearray(base_cfg)
        ep_offset = len(base_cfg) - 7
        for mps in [0, 1, 0x0800, 0x4000, 0xFFFF]:
            cfg2 = bytearray(cfg)
            struct.pack_into('<H', cfg2, ep_offset + 4, mps)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR,
                f"EP wMaxPacketSize={mps:#x} — 超出高速限制",
                device_descriptor=base_dev,
                config_descriptor=bytes(cfg2),
                source_ref="config.c:usb_parse_endpoint() — maxpacket check",
                tags=["wMaxPacketSize", "endpoint"],
            ))

        # 1.7 嵌套描述符 — 在 config desc 中插入意外的子描述符
        for dt in [0x21, 0x24, 0x25, 0x30, 0xFF]:
            cfg2 = bytearray(base_cfg)
            # 在 endpoint 前插入一个不期望的描述符
            insert_pos = len(base_cfg) - 7
            fake_desc = bytes([4, dt, 0x00, 0x00])
            cfg2 = cfg2[:insert_pos] + fake_desc + cfg2[insert_pos:]
            # 更新 wTotalLength
            struct.pack_into('<H', cfg2, 2, len(cfg2))
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR,
                f"插入未预期描述符 type={dt:#x} — 解析器路径混淆",
                device_descriptor=base_dev,
                config_descriptor=bytes(cfg2),
                source_ref="config.c:usb_parse_interface() — 非预期子描述符处理",
                tags=["nested", "descriptor_injection"],
            ))

        return cases

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 2: 控制传输模糊 — drivers/usb/core/message.c
    # ═══════════════════════════════════════════════════════════════════════

    def gen_control_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        """
        策略来源: message.c 的 usb_control_msg():
          dr->bRequest = request;
          dr->wValue = cpu_to_le16(value);
          dr->wLength = cpu_to_le16(size);
        以及 hub.c 中的标准请求处理。
        """
        cases = []
        base_dev = self._base_device_desc()
        base_cfg = self._base_config_desc()

        # 2.1 对 GET_DESCRIPTOR 返回异常数据
        for desc_type in [0x01, 0x02, 0x03, 0x06, 0x07]:
            for wLength in [0, 1, 0xFF, 0xFFFF]:
                cases.append(self._new_case(
                    FuzzPhase.CONTROL,
                    f"GET_DESCRIPTOR(type={desc_type:#x}) wLength={wLength} — 返回错误长度",
                    device_descriptor=base_dev,
                    config_descriptor=base_cfg,
                    ep_data_override={0x80: bytes(self.mutator.rng.randint(0, 255) for _ in range(min(wLength, 64)))},
                    source_ref="message.c:usb_control_msg() — wLength != 实际数据长度",
                    tags=["GET_DESCRIPTOR", "wLength_mismatch"],
                ))

        # 2.2 对 SET_CONFIGURATION 返回 STALL
        cases.append(self._new_case(
            FuzzPhase.CONTROL,
            "SET_CONFIGURATION 后 EP0 STALL — hub_port_init 后续步骤失败",
            device_descriptor=base_dev,
            config_descriptor=base_cfg,
            stall_ep0=True,
            disconnect_on_req="SET_CONFIG",
            source_ref="hub.c:hub_port_init() — SET_CONFIGURATION 失败处理",
            tags=["STALL", "SET_CONFIGURATION"],
        ))

        # 2.3 异常的 Standard 请求
        for bmRequestType in [0x00, 0x01, 0x02, 0x80, 0x81, 0x82, 0xC0, 0xC1]:
            for bRequest in range(0, 16):
                cases.append(self._new_case(
                    FuzzPhase.CONTROL,
                    f"异常控制请求 bmRequestType={bmRequestType:#x} bRequest={bRequest}",
                    device_descriptor=base_dev,
                    config_descriptor=base_cfg,
                    class_request_handler=f"RAW:{bmRequestType:#x}:{bRequest}",
                    source_ref="message.c:usb_control_msg() — 未处理的请求类型",
                    tags=["control", "unhandled_request"],
                ))

        # 控制数量到 max_cases
        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 3: 枚举状态机 — drivers/usb/core/hub.c
    # ═══════════════════════════════════════════════════════════════════════

    def gen_enumeration_cases(self, max_cases: int = 20) -> list[FuzzCase]:
        """
        策略来源: hub.c hub_port_init() 枚举序列:
          1. GET_DESCRIPTOR (64 bytes, timeout=initial_descriptor_timeout)
          2. SET_ADDRESS (timeout=5000ms / 500ms quirk)
          3. GET_DESCRIPTOR (full 18 bytes)
          4. GET_DESCRIPTOR (config)
          5. SET_CONFIGURATION
        
        攻击: 在每个步骤中断/延迟/返回错误
        """
        cases = []
        base_dev = self._base_device_desc()
        base_cfg = self._base_config_desc()

        # 3.1 在特定枚举步骤断连
        for step in ["GET_DESC", "SET_ADDR", "GET_FULL_DESC", "GET_CONFIG", "SET_CONFIG"]:
            cases.append(self._new_case(
                FuzzPhase.ENUMERATION,
                f"在 {step} 步骤后断连 — 枚举状态机异常",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                disconnect_on_req=step,
                source_ref="hub.c:hub_port_init() — 枚举中断处理",
                tags=["disconnect", step],
            ))

        # 3.2 临界超时 — 接近但不等于超时值
        for timeout_ms in [
            HUB_CONSTS["USB_CTRL_SET_TIMEOUT"] - 100,
            HUB_CONSTS["USB_CTRL_SET_TIMEOUT"] - 10,
            HUB_CONSTS["USB_SHORT_SET_ADDRESS_REQ_TIMEOUT"] - 10,
            HUB_CONSTS["HUB_DEBOUNCE_TIMEOUT"] - 100,
        ]:
            cases.append(self._new_case(
                FuzzPhase.ENUMERATION,
                f"响应延迟 {timeout_ms}ms — 接近超时边界",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                delay_response_ms=int(timeout_ms),
                source_ref="hub.c — initial_descriptor_timeout / USB_CTRL_SET_TIMEOUT",
                tags=["timing", "critical_timeout"],
            ))

        # 3.3 快速重连循环 — 消耗 PORT_INIT_TRIES
        for count in [HUB_CONSTS["PORT_INIT_TRIES"] + 1, HUB_CONSTS["PORT_RESET_TRIES"] + 1, 10, 20]:
            pass  # 用 timing cases 中的快速重连代替

        for count in [3, 5, HUB_CONSTS["PORT_INIT_TRIES"] + 1, HUB_CONSTS["PORT_RESET_TRIES"] + 1]:
            cases.append(self._new_case(
                FuzzPhase.ENUMERATION,
                f"快速重连 x{count} — 消耗 PORT_INIT_TRIES={HUB_CONSTS['PORT_INIT_TRIES']}",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                disconnect_on_req="RAPID_RECONNECT",
                source_ref="hub.c:hub_port_init() — PORT_INIT_TRIES 重试耗尽",
                tags=["rapid_reconnect", "retry_exhaustion"],
            ))

        return cases[:max_cases]

    # ═════════════════════════════════   ═════════════════════════════════════
    # Phase 4: 数据传输模糊 — drivers/usb/storage/transport.c
    # ═══════════════════════════════════════════════════════════════════════

    def gen_data_transfer_cases(self, max_cases: int = 20) -> list[FuzzCase]:
        cases = []
        base_dev = self._base_device_desc()
        base_cfg = self._base_config_desc()

        # 4.1 超大数据包
        for size in [0, 1, 64, 512, 4096, 65535]:
            data = bytes(self.mutator.rng.randint(0, 255) for _ in range(size))
            cases.append(self._new_case(
                FuzzPhase.DATA_TRANSFER,
                f"EP1 IN 返回 {size} 字节随机数据",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                ep_data_override={0x81: data},
                source_ref="drivers/usb/core/message.c — usb_bulk_msg buffer",
                tags=["bulk", "oversized"],
            ))

        # 4.2 格式字符串
        for pattern in [b'%s%s%s%s%n%n%n%n', b'%x%x%x%x', b'AAAA' * 64, b'\x00' * 512, b'\xff' * 512]:
            cases.append(self._new_case(
                FuzzPhase.DATA_TRANSFER,
                f"EP 数据注入: {pattern[:20]}...",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                ep_data_override={0x81: pattern},
                source_ref="driver-specific data parsing",
                tags=["format_string", "data_injection"],
            ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 5: 时序模糊
    # ═══════════════════════════════════════════════════════════════════════

    def gen_timing_cases(self, max_cases: int = 15) -> list[FuzzCase]:
        cases = []
        base_dev = self._base_device_desc()
        base_cfg = self._base_config_desc()

        for delay in [50, 100, 200, 490, 495, 500, 990, 995, 1000, 2000, 4900, 4950, 5000]:
            cases.append(self._new_case(
                FuzzPhase.TIMING,
                f"响应延迟 {delay}ms",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                delay_response_ms=delay,
                source_ref="hub.c — 超时边界值",
                tags=["timing"],
            ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 6: HID 报告描述符 — drivers/hid/hid-core.c (新增)
    # ═══════════════════════════════════════════════════════════════════════

    def gen_hid_report_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        """
        策略来源: hid-core.c 的 hid_parse_report() / hid_open_report():
          - item parsing (short/long item)
          - collection_stack_size 动态分配
          - usage_index >= HID_MAX_USAGES 检查
          - report->maxfield >= HID_MAX_FIELDS 检查
          - Global/Local state stack
          - Logical/Physical min/max 边界
        
        已知 CVE:
          CVE-2024-2BUG: hid_report_raw_event OOB
          CVE-2022-0529: hid_input_field overflow
          CVE-2019-3819: hid_map_usage OOB
        """
        cases = []
        base_dev = self._base_device_desc()
        base_cfg = self._base_config_desc()

        # 6.1 报告描述符长度边界
        for desc_len in [0, 1, 2, HID_LIMITS["HID_MAX_DESCRIPTOR_SIZE"],
                         HID_LIMITS["HID_MAX_DESCRIPTOR_SIZE"] + 1,
                         HID_LIMITS["HID_MAX_DESCRIPTOR_SIZE"] * 2]:
            data = bytes(self.mutator.rng.randint(0, 255) for _ in range(min(desc_len, 8192)))
            cases.append(self._new_case(
                FuzzPhase.HID_REPORT,
                f"HID Report 长度={desc_len} (限制={HID_LIMITS['HID_MAX_DESCRIPTOR_SIZE']})",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                hid_report_descriptor=data,
                source_ref="hid-core.c:hid_open_report() — HID_MAX_DESCRIPTOR_SIZE",
                tags=["hid", "length_boundary"],
            ))

        # 6.2 破坏 HID item 的 Short item tag/size
        for i in range(min(6, max_cases)):
            data = bytearray(TPL_HID_REPORT)
            # 篡改 item header byte (high nibble = tag, low nibble = size)
            idx = self.mutator.rng.randrange(0, len(data), 2)  # 在 item header 位置
            data[idx] = self.mutator.rng.choice([0x00, 0x01, 0x03, 0xFE, 0xFF])
            cases.append(self._new_case(
                FuzzPhase.HID_REPORT,
                f"HID item header 篡改 @{idx} → {data[idx]:#x} (tag/size 混淆)",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                hid_report_descriptor=bytes(data),
                source_ref="hid-core.c:hid_parse_report() — item.size 解析",
                tags=["hid", "item_header"],
            ))

        # 6.3 Global item 状态栈溢出 — Push/Pop 操作
        # hid-core.c 用 collection_stack 追踪嵌套，大量 Push 可触发 realloc
        push_op = bytes([0xA4])  # Push global state
        for n_pushes in [10, 50, 100, 500]:
            data = push_op * n_pushes + TPL_HID_REPORT
            cases.append(self._new_case(
                FuzzPhase.HID_REPORT,
                f"HID Push x{n_pushes} — global state stack 溢出",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                hid_report_descriptor=data,
                source_ref="hid-core.c:hid_parser_global() — collection_stack_size",
                tags=["hid", "stack_overflow", "push"],
            ))

        # 6.4 巨大的 Report Count + Report Size — 导致内存分配爆炸
        # hid-core.c: hid_add_field() 分配 report->field[report->maxfield]
        # report_count * report_size 可能导致巨大分配
        bomb_desc = bytes([
            0x05, 0x01,       # Usage Page (Generic Desktop)
            0x09, 0x06,       # Usage (Keyboard)
            0xA1, 0x01,       # Collection (Application)
            0x95, 0xFF, 0x00, # Report Count = 255 (2-byte size)
            0x75, 0xFF,       # Report Size = 255 bits
            0x81, 0x02,       # Input (Data,Var,Abs)
            0xC0,             # End Collection
        ])
        cases.append(self._new_case(
            FuzzPhase.HID_REPORT,
            f"HID Report Count=255 × Size=255 bits — 内存分配炸弹 ({255*255} bits)",
            device_descriptor=base_dev,
            config_descriptor=base_cfg,
            hid_report_descriptor=bomb_desc,
            source_ref="hid-core.c:hid_add_field() — report_count × report_size",
            tags=["hid", "memory_bomb", "allocation"],
        ))

        # 6.5 无限嵌套 Collection — collection_stack 溢出
        nested = b''
        for _ in range(200):
            nested += bytes([0xA1, 0x01])  # Collection (Application)
        nested += TPL_HID_REPORT
        cases.append(self._new_case(
            FuzzPhase.HID_REPORT,
            "HID 200 层嵌套 Collection — collection_stack 深度溢出",
            device_descriptor=base_dev,
            config_descriptor=base_cfg,
            hid_report_descriptor=nested,
            source_ref="hid-core.c:hid_parse_collections() — collection_stack_size",
            tags=["hid", "nested_collection", "depth"],
        ))

        # 6.6 Usage 表溢出 — 超过 HID_MAX_USAGES
        usage_data = bytes([
            0x05, 0x01,  # Usage Page
        ])
        for _ in range(HID_LIMITS["HID_MAX_USAGES"] + 100):
            usage_data += bytes([0x09, 0x00])  # Usage (ID=0)
        usage_data += bytes([0xA1, 0x01, 0xC0])  # Collection + End
        cases.append(self._new_case(
            FuzzPhase.HID_REPORT,
            f"HID Usage 表溢出 ({HID_LIMITS['HID_MAX_USAGES']+100} usages > 限制 {HID_LIMITS['HID_MAX_USAGES']})",
            device_descriptor=base_dev,
            config_descriptor=base_cfg,
            hid_report_descriptor=usage_data[:8192],  # 截断到最大长度
            source_ref="hid-core.c — usage_index >= HID_MAX_USAGES",
            tags=["hid", "usage_overflow"],
        ))

        # 6.7 havoc 变异 HID report
        for _ in range(min(5, max_cases)):
            mutated = self.mutator.havoc(TPL_HID_REPORT, iterations=4)
            cases.append(self._new_case(
                FuzzPhase.HID_REPORT,
                "HID Report havoc 变异",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                hid_report_descriptor=mutated,
                source_ref="hid-core.c — 全变异覆盖",
                tags=["hid", "havoc"],
            ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 7: 类特定协议 — MSC BOT/CDC/UVC (新增)
    # ═══════════════════════════════════════════════════════════════════════

    def gen_class_specific_cases(self, max_cases: int = 20) -> list[FuzzCase]:
        """
        策略来源: drivers/usb/storage/transport.c — CBW/CSW 协议
        SCSI Command Block Wrapper (CBW) 结构:
          0-3:   dCBWSignature (0x43425355 = "USBC")
          4-7:   dCBWTag
          8-11:  dCBWDataTransferLength
          12:    bmCBWFlags (0x80=IN, 0x00=OUT)
          13:    bCBWLUN (0-15)
          14:    bCBWCBLength (1-16)
          15-30: CBWCB (SCSI command block)
        """
        cases = []
        base_dev = self._base_device_desc()
        msc_cfg = TPL_MSC_CONFIG

        # 7.1 畸形 CBW — 签名错误
        for sig in [0x00000000, 0x43425354, 0xFFFFFFFF, 0x55534243]:
            cbw = bytearray(31)
            struct.pack_into('<I', cbw, 0, sig)
            struct.pack_into('<I', cbw, 4, 0x12345678)  # tag
            struct.pack_into('<I', cbw, 8, 0x200)        # transfer length
            cbw[12] = 0x80                                # IN
            cbw[13] = 0                                    # LUN
            cbw[14] = 6                                    # CDB length
            cbw[15] = 0x28                                 # SCSI READ(10)
            cases.append(self._new_case(
                FuzzPhase.CLASS_SPECIFIC,
                f"MSC CBW 签名错误 ={sig:#010x} (正确=0x43425355)",
                device_descriptor=base_dev,
                config_descriptor=msc_cfg,
                ep_data_override={0x01: bytes(cbw)},
                source_ref="drivers/usb/storage/transport.c — CBW signature validation",
                tags=["msc", "cbw", "signature"],
            ))

        # 7.2 SCSI 命令长度越界
        for cdb_len in [0, 1, 5, 16, 17, 31, 255]:
            cbw = bytearray(31)
            struct.pack_into('<I', cbw, 0, 0x43425355)
            cbw[14] = cdb_len
            cases.append(self._new_case(
                FuzzPhase.CLASS_SPECIFIC,
                f"MSC CBW bCBWCBLength={cdb_len} (有效=1-16)",
                device_descriptor=base_dev,
                config_descriptor=msc_cfg,
                ep_data_override={0x01: bytes(cbw)},
                source_ref="drivers/usb/storage/transport.c — bCBWCBLength validation",
                tags=["msc", "cbw", "cdb_length"],
            ))

        # 7.3 dCBWDataTransferLength 超大值
        for xfer_len in [0, 1, 0xFFFFFFFF, 0x80000000]:
            cbw = bytearray(31)
            struct.pack_into('<I', cbw, 0, 0x43425355)
            struct.pack_into('<I', cbw, 8, xfer_len)
            cbw[14] = 10
            cases.append(self._new_case(
                FuzzPhase.CLASS_SPECIFIC,
                f"MSC CBW dCBWDataTransferLength={xfer_len:#010x} — 超大传输",
                device_descriptor=base_dev,
                config_descriptor=msc_cfg,
                ep_data_override={0x01: bytes(cbw)},
                source_ref="drivers/usb/storage/transport.c — dCBWDataTransferLength",
                tags=["msc", "transfer_length"],
            ))

        # 7.4 LUN 越界
        for lun in [0, 1, 15, 16, 255]:
            cbw = bytearray(31)
            struct.pack_into('<I', cbw, 0, 0x43425355)            # correct sig
            cbw[13] = lun
            cbw[14] = 6
            cases.append(self._new_case(
                FuzzPhase.CLASS_SPECIFIC,
                f"MSC CBW LUN={lun} (有效=0-15) — 越界访问",
                device_descriptor=base_dev,
                config_descriptor=msc_cfg,
                ep_data_override={0x01: bytes(cbw)},
                source_ref="drivers/usb/storage/transport.c — bCBWLUN",
                tags=["msc", "lun_oob"],
            ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 8: 移动设备协议 — AOA/RNDIS/MTP
    # ═══════════════════════════════════════════════════════════════════════

    def gen_mobile_specific_cases(self, max_cases: int = 20) -> list[FuzzCase]:
        """
        策略来源:
          - Android Open Accessory (AOA) 协议 — 嵌入式/移动设备常用 USB 协议
          - RNDIS/ECM 网卡 — 嵌入式设备联网和 tethering
          - MTP/PTP — 媒体传输
          - Android USB HAL — hardware/interfaces/usb
        
        AOA 协议流程:
          1. Host 发送 GET_PROTOCOL (vendor request 51)
          2. Host 发送 SEND_STRING (vendor request 52)
          3. Host 发送 START (vendor request 53)
          4. Device 重新枚举为 AOA 模式 (VID=0x18D1, PID=0x2D00-0x2D05)
        """
        cases = []
        base_dev = self._base_device_desc()
        base_cfg = self._base_config_desc()

        # 8.1 AOA 协议伪装 — 伪装为 AOA 配件
        aoa_desc = bytearray(TPL_DEVICE_DESC)
        struct.pack_into('<HH', aoa_desc, 8, 0x18D1, 0x2D00)  # Google VID, AOA PID
        cases.append(self._new_case(
            FuzzPhase.MOBILE_SPECIFIC,
            "AOA 配件伪装 (VID=0x18D1 PID=0x2D00) — 触发 Android UsbHostManager",
            device_descriptor=bytes(aoa_desc),
            config_descriptor=base_cfg,
            source_ref="Android UsbHostManager.java — AOA device detection",
            tags=["aoa", "android"],
        ))

        # 8.2 AOA PID 遍历 — 0x2D00~0x2D05 各有不同含义
        for pid in [0x2D00, 0x2D01, 0x2D02, 0x2D03, 0x2D04, 0x2D05]:
            desc = bytearray(TPL_DEVICE_DESC)
            struct.pack_into('<HH', desc, 8, 0x18D1, pid)
            cases.append(self._new_case(
                FuzzPhase.MOBILE_SPECIFIC,
                f"AOA PID 遍历 PID={pid:#06x} — 不同 AOA 子模式",
                device_descriptor=bytes(desc),
                config_descriptor=base_cfg,
                source_ref="Android UsbHostManager.java — AOA PID 处理",
                tags=["aoa", "pid_fuzz"],
            ))

        # 8.3 RNDIS 网卡伪装 — 嵌入式设备常见
        for vid, pid in [(0x0422, 0x1234), (0x17EF, 0x7205), (0x13B1, 0x0018),
                         (0x0BDA, 0x8152), (0x07B8, 0x7260)]:
            desc = bytearray(TPL_DEVICE_DESC)
            struct.pack_into('<HH', desc, 8, vid, pid)
            cases.append(self._new_case(
                FuzzPhase.MOBILE_SPECIFIC,
                f"RNDIS 网卡伪装 VID={vid:#06x} PID={pid:#06x} — 触发 rndis_host 驱动",
                device_descriptor=bytes(desc),
                config_descriptor=base_cfg,
                source_ref="drivers/net/usb/rndis_host.c — rndis_driver",
                tags=["rndis", "network"],
            ))

        # 8.4 MTP/PTP 设备伪装 — 触发 Android MtpServer
        for vid, pid in [(0x04E8, 0x6860), (0x04E8, 0x6863), (0x22B8, 0x7028)]:
            desc = bytearray(TPL_DEVICE_DESC)
            desc[4] = 0x06  # bDeviceClass = Image
            struct.pack_into('<HH', desc, 8, vid, pid)
            cases.append(self._new_case(
                FuzzPhase.MOBILE_SPECIFIC,
                f"MTP/PTP 伪装 VID={vid:#06x} PID={pid:#06x} — 触发 Android MtpServer",
                device_descriptor=bytes(desc),
                config_descriptor=base_cfg,
                source_ref="Android MtpServer.java — MTP device handler",
                tags=["mtp", "android"],
            ))

        # 8.5 常见嵌入式设备 USB PID 伪装
        mobile_vendors = [
            (0x18D1, 0x4EE1, "Google/Android"),
            (0x0BB4, 0x0C02, "HTC (Android)"),
            (0x22B8, 0x2E61, "Motorola (Android)"),
            (0x1942, 0x041E, "Unknown Vendor"),
            (0x0451, 0xD022, "TI (嵌入式 SoC)"),
            (0x1286, 0x2026, "NVIDIA Tegra (嵌入式)"),
            (0x0471, 0x2107, "Philips (消费电子)"),
        ]
        for vid, pid, name in mobile_vendors:
            desc = bytearray(TPL_DEVICE_DESC)
            struct.pack_into('<HH', desc, 8, vid, pid)
            cases.append(self._new_case(
                FuzzPhase.MOBILE_SPECIFIC,
                f"厂商伪装: {name} (VID={vid:#06x} PID={pid:#06x})",
                device_descriptor=bytes(desc),
                config_descriptor=base_cfg,
                source_ref="Android UsbHostManager.java — vendor-specific handling",
                tags=["car_vendor", "brand_spoof"],
            ))

        # 8.6 adb 接口伪装 — 触发 adbd
        desc = bytearray(TPL_DEVICE_DESC)
        struct.pack_into('<HH', desc, 8, 0x18D1, 0x4EE2)  # Google ADB interface
        cases.append(self._new_case(
            FuzzPhase.MOBILE_SPECIFIC,
            "ADB 接口伪装 (VID=0x18D1 PID=0x4EE2) — 触发 adbd 启动",
            device_descriptor=bytes(desc),
            config_descriptor=base_cfg,
            source_ref="Android adb daemon — USB interface matching",
            tags=["adb", "android"],
        ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════ 重试耗尽 ════
    # 全量生成
    # ═══════════════════════════════════════════════════════════════════════

    def generate_all(self, max_per_phase: int = 30) -> dict[FuzzPhase, list[FuzzCase]]:
        """生成所有阶段的用例"""
        generators = {
            FuzzPhase.DESCRIPTOR:     self.gen_descriptor_cases,
            FuzzPhase.CONTROL:        self.gen_control_cases,
            FuzzPhase.ENUMERATION:    self.gen_enumeration_cases,
            FuzzPhase.DATA_TRANSFER:  self.gen_data_transfer_cases,
            FuzzPhase.TIMING:         self.gen_timing_cases,
            FuzzPhase.HID_REPORT:     self.gen_hid_report_cases,
            FuzzPhase.CLASS_SPECIFIC: self.gen_class_specific_cases,
            FuzzPhase.MOBILE_SPECIFIC:   self.gen_mobile_specific_cases,
        }
        result = {}
        for phase, gen in generators.items():
            result[phase] = gen(max_cases=max_per_phase)
        return result
