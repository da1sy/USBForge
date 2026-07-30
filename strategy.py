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
    CVE_REPLAY     = 15  # Phase 15: CVE 策略泛化 (从60+ CVE提炼8大根因模式→发现未知漏洞)


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
    FuzzPhase.CVE_REPLAY:    "CVE 策略泛化",
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
    FuzzPhase.CVE_REPLAY:     "NVD/syzbot 2015-2025 → 8大根因模式: 长度交叉验证/引用越界/算术边界/端点矩阵/响应不稳定/quirk路径/尺寸不匹配/断连竞争",
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
    # Phase 15: CVE 策略泛化 — 从 60+ 历史 USB CVE 中提炼漏洞根因模式，
    #           泛化为系统性变异策略来发现未知漏洞
    # 方法论来源: NVD / kernel.org / syzbot / openwall (2015-2025)
    # ═══════════════════════════════════════════════════════════════════════

    def gen_cve_strategy_cases(self, max_cases: int = 50) -> list[FuzzCase]:
        """从 60+ 历史 USB CVE 中提炼 8 大漏洞根因模式，泛化为系统性变异策略来发现未知漏洞。"""
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
            buf += struct.pack('<BBHBBBBB', 9, 2, cfg_total, num_ifs, 1, 0, 0x80, 50)
            buf += struct.pack('<BBBBBBBBB', 9, 4, 0, 0, num_eps, if_cls, 0, 0, 0)
            for i in range(num_eps):
                ep_type, mps = ep_types[i % len(ep_types)]
                ep_addr = (0x80 | (i + 1)) if ep_type == 3 else (i + 1)
                buf += struct.pack('<BBBBHB', 7, 5, ep_addr, ep_type, mps, 0)
            return bytes(buf)

        # ═══════════════════════════════════════════════════════════════════
        # 8 大 CVE 根因模式 → 泛化变异策略
        #
        # 不是复现 36 个精确 PoC，而是从 60+ CVE 中提炼漏洞发现的"方法论"：
        # 内核解析器犯了哪些共同的假设错误？哪些字段交叉验证缺失？
        # 将这些模式泛化，系统性地探索未知漏洞空间。
        # ═══════════════════════════════════════════════════════════════════

        # ───────────────────────────────────────────────────────────────────
        # 策略 1: 长度字段交叉验证缺失
        # 根因模式: 内核信任描述符自报的 bLength / wTotalLength，不做交叉验证
        # 来源 CVE: 2017-16531, 2017-16535, 2017-16534, 2024-53104, 2025-38103
        # 泛化: 对每种描述符类型的 bLength 注入 struct_size±N，交叉不一致
        # ───────────────────────────────────────────────────────────────────

        # 1a: Device descriptor — bLength 谎报 (来源: CVE-2023-52886 响应不稳定)
        for bl in [0, 1, 8, 16, 17, 20, 100, 255]:
            bad_dev = bytearray(base_dev)
            bad_dev[0] = bl  # bLength 谎报
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略1-长度交叉验证] Device bLength={bl} (实际18) — "
                f"内核可能按 bLength 分配，按实际读取 → OOB",
                device_descriptor=bytes(bad_dev),
                source_ref="drivers/usb/core/config.c → usb_get_device_descriptor() "
                           "— bLength vs sizeof(usb_device_descriptor) 不验证",
                tags=["cve_strategy", "length_validation", "device", f"blen_{bl}"],
            ))

        # 1b: Config descriptor — wTotalLength 与子描述符总和不一致
        # 来源: CVE-2017-16531 (IAD OOB), CVE-2017-16534 (CDC header OOB)
        for wt_offset in [-20, -9, -1, 0, 1, 9, 50, 200, 0xFFFF]:
            bad_cfg = bytearray(base_cfg)
            actual = len(bad_cfg)
            claimed = max(0, actual + wt_offset)
            struct.pack_into('<H', bad_cfg, 2, min(claimed, 0xFFFF))
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略1-长度交叉验证] Config wTotalLength={claimed} (实际{actual}) — "
                f"偏移={wt_offset:+d} — 解析器越界读写",
                config_descriptor=bytes(bad_cfg),
                source_ref="drivers/usb/core/config.c → usb_get_configuration() "
                           "— wTotalLength 决定 buffer 分配，子描述符遍历可能越界",
                tags=["cve_strategy", "length_validation", "config",
                      f"wt_offset_{wt_offset}"],
            ))

        # 1c: 嵌套描述符 — 子 bLength 之和 ≠ 父 wTotalLength
        # 来源: CVE-2017-16535 (BOS), CVE-2024-53104 (UVC frame)
        cfg = bytearray(base_cfg)
        if len(cfg) > 14:
            # 在 config 尾部插入一个 bLength 谎报的 interface descriptor
            fake_if = bytearray(struct.pack('<BBBBBBBBB', 9, 4, 0, 0, 0, 0xFF, 0, 0, 0))
            fake_if[0] = 255  # bLength=255 但只有 9 字节实际数据
            cfg_extended = cfg + bytes(fake_if)
            struct.pack_into('<H', cfg_extended, 2, len(cfg_extended))  # wTotalLength 正确
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                "[策略1-长度交叉验证] 子描述符 bLength=255 但实际 9 字节 — "
                "find_next_descriptor 步进超出父 buffer",
                config_descriptor=bytes(cfg_extended),
                source_ref="drivers/usb/core/config.c → find_next_descriptor() "
                           "— `size -= h->bLength` 步进可能越过 wTotalLength",
                tags=["cve_strategy", "length_validation", "nested", "blen_255"],
            ))

        # ───────────────────────────────────────────────────────────────────
        # 策略 2: 跨描述符引用越界
        # 根因模式: IAD / CDC Union / UVC entity 的引用字段指向不存在的接口/实体
        # 来源 CVE: 2017-16529, 2017-16645, 2025-40016, 2025-40275
        # 泛化: 所有引用字段填 0 / 0xFF / 超出 bNumInterfaces / 循环引用
        # ───────────────────────────────────────────────────────────────────

        # 2a: IAD (Interface Association Descriptor) 引用越界
        # bFirstInterface + bInterfaceCount 超出实际接口数
        for bFirst, bCount in [(0xFF, 0xFF), (0, 0xFF), (200, 200), (1, 0xFE)]:
            iad = struct.pack('<BBBBBBBB', 0x08, 0x0B, bFirst, bCount,
                              0x02, 0x0E, 0x03, 0x00)
            bad_cfg = base_cfg + iad
            bad_cfg = bytearray(bad_cfg)
            struct.pack_into('<H', bad_cfg, 2, len(bad_cfg))
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略2-引用越界] IAD bFirstInterface={bFirst} bInterfaceCount={bCount} "
                f"— 指向不存在的接口 → OOB Read",
                device_descriptor=_desc(cls=0xEF),  # Misc class triggers IAD
                config_descriptor=bytes(bad_cfg),
                source_ref="drivers/usb/core/config.c → usb_parse_interface() "
                           "— IAD bFirstInterface+bInterfaceCount 不验证上限",
                tags=["cve_strategy", "ref_oob", "iad", f"first_{bFirst}"],
            ))

        # 2b: CDC Union descriptor — bMasterInterface / bSlaveInterface 引用越界
        # 来源: CVE-2017-16645
        for master, slave in [(0xFF, 0xFF), (200, 0), (0, 200)]:
            cdc_union = struct.pack('<BBBBBBBB', 0x06, 0x24, 0x06, master, slave, 0, 0, 0)
            bad_cfg = bytearray(base_cfg)
            bad_cfg += cdc_union
            struct.pack_into('<H', bad_cfg, 2, len(bad_cfg))
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略2-引用越界] CDC Union bMaster={master} bSlave={slave} "
                f"— 接口索引越界 → NULL deref / OOB",
                device_descriptor=_desc(cls=0x02, sub=0x0D),  # CDC
                config_descriptor=bytes(bad_cfg),
                source_ref="drivers/usb/core/message.c → cdc_parse_cdc_header() "
                           "— union descriptor 接口引用不做边界检查",
                tags=["cve_strategy", "ref_oob", "cdc_union", f"master_{master}"],
            ))

        # ───────────────────────────────────────────────────────────────────
        # 策略 3: 整数算术边界
        # 根因模式: 内核对 size 字段做除法/加法/乘法时不检查溢出和零值
        # 来源 CVE: 2022-48837 (RNDIS A+B 溢出), 2023-54110, 2017-16649 (除零)
        # 泛化: 系统性地在所有算术相关字段注入 0 / 1 / MAX-1 / MAX
        # ───────────────────────────────────────────────────────────────────

        # 3a: wMaxPacketSize = 0 → 除零 (CVE-2017-16649/16650)
        for mps in [0, 1, 0xFFFF]:
            bad_cfg = bytearray(base_cfg)
            # 找到第一个 endpoint descriptor (bDescriptorType=0x05) 修改 mps
            for i in range(len(bad_cfg) - 4):
                if bad_cfg[i+1] == 0x05:  # endpoint type
                    struct.pack_into('<H', bad_cfg, i + 4, mps)
                    break
            else:
                # 如果没有 endpoint，构造一个
                ep = struct.pack('<BBBBHB', 7, 5, 0x81, 0x02, mps, 0)
                bad_cfg += ep
                struct.pack_into('<H', bad_cfg, 2, len(bad_cfg))
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略3-算术边界] Endpoint wMaxPacketSize={mps} — "
                f"URB 分配 size/mps 除零或 0xFFFF 导致巨型分配",
                config_descriptor=bytes(bad_cfg),
                source_ref="drivers/usb/core/endpoint.c → usb_endpoint_maxp() "
                           "— wMaxPacketSize=0 时 NAK/URB division-by-zero",
                tags=["cve_strategy", "arith_boundary", "mps", f"mps_{mps}"],
            ))

        # 3b: RNDIS 整数溢出 — DataOffset + DataLength > 0xFFFFFFFF
        # 来源: CVE-2022-48837, CVE-2023-54110
        rndis_msg_type = 0x00000001  # RNDIS_MSG_INIT
        for data_offset, data_length in [
            (0xFFFFFFFF, 1),    # 经典 A+B 溢出
            (0x80000000, 0x80000000),
            (0xFFFFFFF8, 8),    # BufOffset+8 溢出
            (0, 0xFFFFFFFF),
        ]:
            # RNDIS INIT message with overflow parameters
            rndis_payload = struct.pack('<IIIIIIII',
                rndis_msg_type, 0x00000000,  # msg_type, msg_id
                0x00000018,                   # request_id (正常长度)
                4,                            # major version
                0x00000007FF,                 # minor + flags (正常)
                data_offset,                  # ← 爆点
                data_length,                  # ← 爆点
                0,
            )
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略3-算术边界] RNDIS DataOffset=0x{data_offset:08X} "
                f"DataLength=0x{data_length:08X} — A+B 整数溢出 → OOB Write",
                device_descriptor=_desc(cls=0xE0, sub=0x01),  # Wireless class
                config_descriptor=_cfg_with_eps(num_eps=1, if_cls=0xE0,
                                                ep_types=[(0x02, 0xFFFF)]),
                ep_data_override={0x81: rndis_payload},
                source_ref="drivers/net/usb/rndis_host.c → rndis_command() "
                           "— offset+length 算术溢出，内核信任消息自报字段",
                tags=["cve_strategy", "arith_boundary", "rndis",
                      "integer_overflow", f"off_0x{data_offset:08X}"],
            ))

        # 3c: HID report_size × report_count 整数溢出
        # 来源: CVE-2017-16533 (hid-core.c report size overflow)
        for rs, rc in [(0xFFFF, 0xFFFF), (0x8000, 0x8000), (255, 0xFFFFFF)]:
            # 构造 HID report descriptor with Global Item: Report Size + Report Count
            # 0x94 = Global item, Report Size(7=0x07), 2-byte data
            # 0x96 = Global item, Report Count(9=0x09), 2-byte data
            hid_desc = (
                b'\x05\x01'        # Usage Page (Generic Desktop)
                b'\x09\x06'        # Usage (Keyboard)
                b'\xA1\x01'        # Collection (Application)
                b'\x95' + struct.pack('<H', rc & 0xFFFF) +  # Report Count (2-byte)
                b'\x75' + struct.pack('<H', rs & 0xFFFF) +  # Report Size (2-byte)
                b'\x81\x00'        # Input (Data)
                b'\xC0'             # End Collection
            )
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略3-算术边界] HID report_size={rs} × report_count={rc} — "
                f"乘积溢出 32-bit → 缓冲区分配不足 → OOB Write",
                hid_report_descriptor=hid_desc,
                source_ref="drivers/hid/hid-core.c:324 → "
                           "report->size += report_size * report_count",
                tags=["cve_strategy", "arith_boundary", "hid",
                      "integer_overflow", f"rs_{rs}"],
            ))

        # ───────────────────────────────────────────────────────────────────
        # 策略 4: 端点配置矩阵
        # 根因模式: 驱动假设特定端点存在，probe 时不检查就解引用
        # 来源 CVE: 2016-2184~2188, 2017-16530, 2017-16647, 2017-16536/37
        # 泛化: 对每个设备类穷举 — 0端点 / 缺特定类型 / 方向反转 / 类型替换
        # ───────────────────────────────────────────────────────────────────

        # 4a: 每种设备类的端点矩阵
        device_classes = [
            (0x03, "HID",      [(0x03, 8)]),         # 需要 interrupt IN
            (0x08, "MSC",      [(0x02, 64), (0x02, 64)]),  # 需要 bulk IN+OUT
            (0x02, "CDC",      [(0x03, 8), (0x02, 64)]),   # interrupt + bulk
            (0x0E, "UVC",      [(0x01, 1024), (0x02, 1024)]),  # isoc + bulk
            (0x01, "Audio",    [(0x01, 200)]),       # 需要 isoc
            (0xE0, "RNDIS",    [(0x02, 64)]),        # 需要 bulk
        ]
        for cls_code, cls_name, expected_eps in device_classes:
            # 缺少所有端点
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略4-端点矩阵] {cls_name} class=0x{cls_code:02X} — 0 端点 "
                f"— probe 假设端点存在 → NULL deref",
                device_descriptor=_desc(cls=cls_code),
                config_descriptor=_cfg_with_eps(num_eps=0, if_cls=cls_code),
                source_ref=f"drivers/usb/class/ → {cls_name} probe() "
                           f"— usb_ifnum_to_if(num) 不检查返回值",
                tags=["cve_strategy", "endpoint_matrix", cls_name.lower(), "zero_eps"],
            ))
            # 端点方向反转 (IN→OUT / OUT→IN)
            for ep_type, mps in expected_eps:
                reversed_ep = struct.pack('<BBBBHB', 7, 5,
                                          0x01 if ep_type != 3 else 0x81,
                                          ep_type, mps, 0)
                bad_cfg = bytearray(_cfg_with_eps(num_eps=1, if_cls=cls_code,
                                                   ep_types=[(ep_type, mps)]))
                # 反转端点方向
                for i in range(len(bad_cfg) - 4):
                    if bad_cfg[i+1] == 0x05:
                        bad_cfg[i+2] ^= 0x80  # 翻转方向位
                        break
                cases.append(self._new_case(
                    FuzzPhase.CVE_REPLAY,
                    f"[策略4-端点矩阵] {cls_name} — 端点方向反转 (期望 IN 给 OUT) "
                    f"— 驱动收不到期望数据 → 超时/NULL",
                    device_descriptor=_desc(cls=cls_code),
                    config_descriptor=bytes(bad_cfg),
                    source_ref=f"drivers/usb/ → {cls_name} endpoint direction assumption",
                    tags=["cve_strategy", "endpoint_matrix", cls_name.lower(), "dir_flip"],
                ))
                # 端点类型替换 (期望 bulk 给 interrupt)
                wrong_type = 0x03 if ep_type == 0x02 else 0x02
                bad_cfg2 = bytearray(_cfg_with_eps(num_eps=1, if_cls=cls_code,
                                                    ep_types=[(ep_type, mps)]))
                for i in range(len(bad_cfg2) - 4):
                    if bad_cfg2[i+1] == 0x05:
                        bad_cfg2[i+3] = wrong_type
                        break
                cases.append(self._new_case(
                    FuzzPhase.CVE_REPLAY,
                    f"[策略4-端点矩阵] {cls_name} — 端点类型替换 "
                    f"(期望 type=0x{ep_type:02X} 给 0x{wrong_type:02X}) — "
                    f"URB 类型不匹配 → 驱动逻辑错误",
                    device_descriptor=_desc(cls=cls_code),
                    config_descriptor=bytes(bad_cfg2),
                    source_ref=f"drivers/usb/ → {cls_name} endpoint type assumption",
                    tags=["cve_strategy", "endpoint_matrix", cls_name.lower(), "type_swap"],
                ))

        # ───────────────────────────────────────────────────────────────────
        # 策略 5: 描述符响应不稳定性
        # 根因模式: 首次和后续 GET_DESCRIPTOR 返回不同数据 → 竞争窗口
        # 来源 CVE: 2023-52886 (hub_port_init 覆盖 udev->descriptor)
        # 泛化: 第一次正常响应，第二次返回不同 bLength / class / endpoint 配置
        # ───────────────────────────────────────────────────────────────────

        # 5a: 第二次 GET_DESCRIPTOR(DEVICE) 返回更短的 bLength
        short_dev = bytearray(base_dev)
        short_dev[0] = 12  # 第二次只返回 12 字节 (正常 18)
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "[策略5-响应不稳定] Device desc 第二次响应 bLength=12 (首次=18) — "
            "hub_port_init 覆盖时长度缩小 → sysfs 读取竞争 OOB",
            device_descriptor=bytes(short_dev),
            source_ref="drivers/usb/core/hub.c → hub_port_init() "
                       "— 二次 GET_DESCRIPTOR 可能覆盖为不同长度",
            tags=["cve_strategy", "response_instability", "device", "race"],
        ))

        # 5b: 第二次 GET_DESCRIPTOR 返回不同 class
        diff_class_dev = bytearray(base_dev)
        diff_class_dev[4] = 0xFF  # class 完全不同
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "[策略5-响应不稳定] Device desc 第二次 class=0xFF (首次=正常) — "
            "驱动绑定竞争 → 错误驱动处理错误描述符",
            device_descriptor=bytes(diff_class_dev),
            source_ref="drivers/usb/core/generic.c → usb_choose_configuration() "
                       "— 首次和二次读取可能绑定不同驱动",
            tags=["cve_strategy", "response_instability", "class_change", "race"],
        ))

        # ───────────────────────────────────────────────────────────────────
        # 策略 6: VID/PID quirk 路径探测
        # 根因模式: 内核 quirk 表按 VID/PID 索引特殊处理，这些路径缺少测试
        # 来源 CVE: 2022-48701, 2017-15102, 2019-19532, 2025-21794
        # 泛化: 枚举所有已知 quirk VID/PID 对，叠加畸形描述符
        # ───────────────────────────────────────────────────────────────────

        # 已知会触发特殊内核处理路径的 VID/PID 组合
        quirk_vidpids = [
            (0x2040, 0x5510),  # Hauppauge — CVE-2017-15102 double-free
            (0x06CD, 0x0120),  # IMS/Thrustmaster — CVE-2025-21794 stack OOB
            (0x05AC, 0x0000),  # Apple VID — special HID handling
            (0x18D1, 0x2D00),  # Google AOA accessory mode
            (0x1915, 0x7810),  # RNDIS + CDC ether conflict
            (0x04E8, 0x6860),  # Samsung MTP — MTP driver path
            (0x0BB4, 0x0C02),  # HTC serial — HTC-specific quirk
            (0x22B8, 0x2E61),  # Motorola ADB
            (0x045E, 0x02C9),  # Microsoft X360 controller — force feedback
            (0x054C, 0x0268),  # Sony DualShock3 — special HID driver
        ]
        for vid, pid in quirk_vidpids:
            # 每个 quirk VID/PID 叠加 bLength 不一致
            bad_dev = bytearray(base_dev)
            bad_dev[0] = 17  # bLength=17 (正常 18)
            struct.pack_into('<H', bad_dev, 8, vid)
            struct.pack_into('<H', bad_dev, 10, pid)
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略6-quirk路径] VID=0x{vid:04X} PID=0x{pid:04X} + bLength=17 — "
                f"触发 quirk 特殊处理 + 描述符畸形 → 未知漏洞路径",
                device_descriptor=bytes(bad_dev),
                source_ref="drivers/usb/core/quirks.c → usb_detect_quirks() "
                           "— VID/PID 匹配后进入未测试的特殊代码路径",
                tags=["cve_strategy", "quirk_path", f"vid_{vid:04X}",
                      f"pid_{pid:04X}"],
            ))

        # ───────────────────────────────────────────────────────────────────
        # 策略 7: 数据负载尺寸不匹配
        # 根因模式: 驱动按预期结构体大小读取 URB 数据，但设备返回更短/更长
        # 来源 CVE: 2025-21704 (短通知 OOB), 2017-8924, 2021-43976, 2013-1860
        # 泛化: 对每个端点响应注入 struct_size-1 / 0 / 1 和 struct_size+N
        # ───────────────────────────────────────────────────────────────────

        # 7a: HID interrupt IN — 短数据 (期望报告长度 N，返回 0-7 字节)
        for data_len in [0, 1, 3, 7]:
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略7-尺寸不匹配] HID interrupt IN 返回 {data_len} 字节 "
                f"(期望 8+) — hid_input_report 越界读取",
                device_descriptor=_desc(cls=0x03),
                config_descriptor=_cfg_with_eps(num_eps=1, if_cls=0x03,
                                                ep_types=[(0x03, 8)]),
                ep_data_override={0x81: b'\x00' * data_len},
                source_ref="drivers/hid/hid-core.c → hid_input_report() "
                           "— 报告长度 < field 解析预期 → OOB Read",
                tags=["cve_strategy", "payload_size", "hid", f"len_{data_len}"],
            ))

        # 7b: MSC CBW — 过短/过长
        for cbw_len in [0, 10, 20, 100, 255]:
            cbw_data = b'USBC' + bytes(27)  # 最小 CBW
            cbw_data = cbw_data[:cbw_len].ljust(cbw_len, b'\x00')
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略7-尺寸不匹配] MSC CBW 返回 {cbw_len} 字节 (期望 31) — "
                f"usb_storage CBW 解析器越界",
                device_descriptor=_desc(cls=0x08),
                config_descriptor=_cfg_with_eps(num_eps=2, if_cls=0x08,
                                                ep_types=[(0x02, 64), (0x02, 64)]),
                ep_data_override={0x81: cbw_data},
                source_ref="drivers/usb/storage/transport.c → usb_stor_Bulk_transport() "
                           "— CBW 长度不验证 → buffer overrun",
                tags=["cve_strategy", "payload_size", "msc", f"cbw_len_{cbw_len}"],
            ))

        # 7c: RNDIS 指示消息 — 过短 (CVE-2025-21704 泛化)
        for msg_len in [0, 1, 4, 7]:
            rndis_short = struct.pack('<II', 0x00000007, 0) + b'\x00' * msg_len
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略7-尺寸不匹配] RNDIS INDICATE 消息体 {msg_len} 字节 "
                f"(期望 8+) — rndis_msg_parse 越界",
                device_descriptor=_desc(cls=0xE0),
                config_descriptor=_cfg_with_eps(num_eps=1, if_cls=0xE0,
                                                ep_types=[(0x02, 64)]),
                ep_data_override={0x81: rndis_short},
                source_ref="drivers/net/usb/rndis_host.c → rndis_command() "
                           "— 消息长度 < 结构体大小 → OOB Read",
                tags=["cve_strategy", "payload_size", "rndis", f"msg_len_{msg_len}"],
            ))

        # ───────────────────────────────────────────────────────────────────
        # 策略 8: 枚举中段断连竞争
        # 根因模式: disconnect 和 open/probe/URB完成之间缺少同步
        # 来源 CVE: 2019-19530/28/29/37, 2022-48760
        # 泛化: 在枚举各里程碑断连 — SET_ADDRESS / GET_DESCRIPTOR / SET_CONFIG
        # ───────────────────────────────────────────────────────────────────

        # 8a: SET_ADDRESS 后立即断连
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "[策略8-断连竞争] SET_ADDRESS 响应后立即断连 — "
            "hub_port_init 中段放弃 → UAF",
            disconnect_on_req="SET_ADDR",
            source_ref="drivers/usb/core/hub.c → hub_port_init() "
                       "— SET_ADDRESS 成功后 disconnect → device freed while in use",
            tags=["cve_strategy", "race_disconnect", "set_addr", "uaf"],
        ))

        # 8b: GET_DESCRIPTOR 后断连
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "[策略8-断连竞争] GET_DESCRIPTOR(DEVICE) 后断连 — "
            "udev->descriptor 部分填充时 free → 信息泄露/UAF",
            disconnect_on_req="GET_DESC",
            source_ref="drivers/usb/core/hub.c → hub_port_init() "
                       "— descriptor 读取失败 + disconnect → use-after-free",
            tags=["cve_strategy", "race_disconnect", "get_desc", "uaf"],
        ))

        # 8c: SET_CONFIGURATION 后断连
        cases.append(self._new_case(
            FuzzPhase.CVE_REPLAY,
            "[策略8-断连竞争] SET_CONFIGURATION 后断连 — "
            "driver probe 中途设备消失 → UAF on driver data",
            disconnect_on_req="SET_CONFIG",
            source_ref="drivers/usb/core/driver.c → usb_driver_claim_interface() "
                       "— probe 中途 disconnect → driver data UAF",
            tags=["cve_strategy", "race_disconnect", "set_config", "uaf"],
        ))

        # 8d: 枚举全程延迟响应 → 超时竞争
        for delay in [500, 2000, 5000]:
            cases.append(self._new_case(
                FuzzPhase.CVE_REPLAY,
                f"[策略8-断连竞争] 枚举全程延迟 {delay}ms — "
                f"hub event handler 超时 + 并发操作 → 竞争条件",
                delay_response_ms=delay,
                source_ref="drivers/usb/core/hub.c → hub_event() "
                           "— HUB_DEBOUNCE_TIMEOUT 和枚举状态机竞争",
                tags=["cve_strategy", "race_disconnect", "timing", f"delay_{delay}"],
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
            FuzzPhase.CVE_REPLAY:     self.gen_cve_strategy_cases,
        }
        result = {}
        for phase, gen in generators.items():
            cap = 100 if phase == FuzzPhase.CVE_REPLAY else max_per_phase
            result[phase] = gen(max_cases=cap)
        return result
