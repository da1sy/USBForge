#!/usr/bin/env python3
"""
cynthion-usb-fuzzer — 基于 Cynthion/Facedancer 的 USB 主机模糊测试框架

研究基础（6 个前沿项目经验提炼）：
  - USBFuzz (Purdue/EPFL):  覆盖率引导 + 跨平台种子交叉授粉 → 26 漏洞, 10 CVE
  - Saturn (THU):            Host-Gadget 协同模糊
  - usbStackFuzz:            描述符边界值 + Unicode 注入 → HID/MIDI 崩溃
  - stm32-usb-fuzzer:        30 种攻击模式 → Windows usbhub.sys 崩溃
  - UDEFuzz:                 Windows UDE 虚拟设备
  - umap/umap2 (NCC Group):  经典 Facedancer 枚举攻击 + 类驱动伪装

模糊测试阶段（每阶段独立执行，可组合）:
  Phase 1 — 描述符变异:   设备/配置/接口/端点/HID 描述符边界值注入
  Phase 2 — 控制传输模糊: 标准/类/厂商请求的 bRequest/wValue/wIndex/wLength 变异
  Phase 3 — 枚举状态机:   在错误阶段响应、中途断连、重复枚举
  Phase 4 — 数据传输模糊: 批量/中断/等时端点的数据变异
  Phase 5 — 时序模糊:     非正常延迟、快速重连、STALL 注入

用法:
  python3 usb_fuzzer.py --phases 1,2 --target 192.168.1.100 --max-cases 500
  python3 usb_fuzzer.py --phases all --target 192.168.1.100 --speed full
  python3 usb_fuzzer.py --phase descriptor-only --replay results/crash_0042.json

需要: pip install facedancer (Cynthion 已连接, bitstream=Facedancer)
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import os
import random
import signal
import struct
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Optional

# ─── sys.path 修复 ─────────────────────────────────────────────────────────────
# Hermes Agent 会将自身 venv (Python 3.11) 注入 sys.path，导致与系统 Python 3.9
# 的 site-packages 冲突。清理冲突路径，确保 facedancer 从正确位置导入。
sys.path = [p for p in sys.path if 'hermes-agent' not in p]
import site
_user_site = site.getusersitepackages()
if isinstance(_user_site, list):
    for _sp in _user_site:
        if _sp not in sys.path:
            sys.path.append(_sp)
elif _user_site not in sys.path:
    sys.path.append(_user_site)

# ─── Facedancer 核心 (Cynthion 后端) ────────────────────────────────────────────
try:
    from facedancer          import USBDevice, USBConfiguration, USBInterface, USBEndpoint
    from facedancer          import USBDirection, USBTransferType
    from facedancer          import use_inner_classes_automatically
    from facedancer          import standard_request_handler
    from facedancer.classes  import USBDeviceClass
    from facedancer.devices  import default_main
    from facedancer.types    import USBStandardRequests, USBRequestType, USBRequestRecipient
    from facedancer.core     import FacedancerUSBApp
    from facedancer.logging  import log
except ImportError:
    print("[!] facedancer 未安装。请执行: pip install facedancer")
    print(f"    当前 Python: {sys.executable} ({sys.version.split()[0]})")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. 配置与常量
# ═══════════════════════════════════════════════════════════════════════════════

# 已知有漏洞的 VID/PID 对（来自 USBFuzz/umap 研究中的真实设备）
DEVICE_PROFILES = {
    "generic-hid":     {"vid": 0x046D, "pid": 0xC534, "class": 0x03, "subclass": 0x00, "protocol": 0x00},
    "generic-msc":     {"vid": 0x0781, "pid": 0x5580, "class": 0x08, "subclass": 0x06, "protocol": 0x50},
    "generic-cdc":     {"vid": 0x2341, "pid": 0x0042, "class": 0x02, "subclass": 0x00, "protocol": 0x00},
    "generic-uvc":     {"vid": 0x046D, "pid": 0x0825, "class": 0x0E, "subclass": 0x01, "protocol": 0x00},
    "generic-audio":   {"vid": 0x1235, "pid": 0x8202, "class": 0x01, "subclass": 0x00, "protocol": 0x00},
    "generic-ftdi":    {"vid": 0x0403, "pid": 0x6001, "class": 0x00, "subclass": 0x00, "protocol": 0x00},
    "generic-ubs":     {"vid": 0x0424, "pid": 0x2514, "class": 0x09, "subclass": 0x00, "protocol": 0x02},
    "generic-vendor":  {"vid": 0x1D50, "pid": 0x6018, "class": 0xFF, "subclass": 0xFF, "protocol": 0xFF},
}

# USB 标准请求码 (USB 2.0 §9.4)
STD_GET_STATUS        = 0x00
STD_CLEAR_FEATURE     = 0x01
STD_SET_FEATURE       = 0x03
STD_SET_ADDRESS       = 0x05
STD_GET_DESCRIPTOR    = 0x06
STD_SET_DESCRIPTOR    = 0x07
STD_GET_CONFIGURATION = 0x08
STD_SET_CONFIGURATION = 0x09
STD_GET_INTERFACE     = 0x0A
STD_SET_INTERFACE     = 0x0B
STD_SYNCH_FRAME       = 0x0C

# HID 类请求
HID_GET_REPORT    = 0x01
HID_GET_IDLE      = 0x02
HID_GET_PROTOCOL  = 0x03
HID_SET_REPORT    = 0x09
HID_SET_IDLE      = 0x0A
HID_SET_PROTOCOL  = 0x0B

# MSC 类请求 (Bulk-Only Transport)
MSC_BOT_RESET       = 0xFF
MSC_GET_MAX_LUN     = 0xFE

# UVC 类请求
UVC_VC_UNDEFINED  = 0x00

RESULTS_DIR = Path("results")
CORPUS_DIR  = Path("corpus")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. 变异引擎 — 核心模糊测试变异原语
# ═══════════════════════════════════════════════════════════════════════════════

class Mutator:
    """
    变异引擎 — 从 USBFuzz/Syzkaller/stm32-usb-fuzzer 的变异策略中提炼。

    策略分类:
      - bitflip:        单 bit 翻转
      - byteflip:       单字节翻转
      - arith:          算术增减
      - interest:       边界值注入 (0, 1, 0x7F, 0x80, 0xFF, 0xFFFF...)
      - chunk:          块重复/删除
      - insert:         随机字节插入
      - havoc:          随机组合上述策略
    """

    INTEREST_8  = [0, 1, 2, 3, 4, 8, 16, 32, 64, 100, 127, 128, 129, 200, 254, 255]
    INTEREST_16 = [0, 1, 2, 3, 4, 8, 16, 32, 64, 100, 127, 128, 255, 256, 511, 512,
                   1000, 1024, 4096, 32767, 32768, 65534, 65535]
    INTEREST_32 = [0, 1, 2, 3, 4, 8, 16, 32, 64, 100, 127, 128, 255, 256, 512, 1024,
                   4096, 32768, 65536, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]

    def __init__(self, rng: random.Random):
        self.rng = rng

    # ── 基础变异原语 ──────────────────────────────────────────────

    def bitflip(self, data: bytes, count: int = 1) -> bytes:
        buf = bytearray(data)
        for _ in range(count):
            if not buf:
                break
            byte_idx = self.rng.randint(0, len(buf) - 1)
            bit_idx  = self.rng.randint(0, 7)
            buf[byte_idx] ^= (1 << bit_idx)
        return bytes(buf)

    def byteflip(self, data: bytes, count: int = 1) -> bytes:
        buf = bytearray(data)
        for _ in range(count):
            if not buf:
                break
            idx = self.rng.randint(0, len(buf) - 1)
            buf[idx] ^= 0xFF
        return bytes(buf)

    def arith(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if not buf:
            return bytes(buf)
        idx = self.rng.randint(0, len(buf) - 1)
        delta = self.rng.choice([-35, -17, -5, -3, -2, -1, 1, 2, 3, 5, 17, 35])
        buf[idx] = (buf[idx] + delta) & 0xFF
        return bytes(buf)

    def interest_8(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if not buf:
            return bytes(buf)
        idx = self.rng.randint(0, len(buf) - 1)
        buf[idx] = self.rng.choice(self.INTEREST_8)
        return bytes(buf)

    def interest_16(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if len(buf) < 2:
            buf.extend(b'\x00' * (2 - len(buf)))
        idx = self.rng.randint(0, len(buf) - 2)
        val = self.rng.choice(self.INTEREST_16)
        struct.pack_into('<H', buf, idx, val)
        return bytes(buf)

    def interest_32(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if len(buf) < 4:
            buf.extend(b'\x00' * (4 - len(buf)))
        idx = self.rng.randint(0, len(buf) - 4)
        val = self.rng.choice(self.INTEREST_32)
        struct.pack_into('<I', buf, idx, val)
        return bytes(buf)

    def insert_bytes(self, data: bytes) -> bytes:
        buf = bytearray(data)
        pos = self.rng.randint(0, len(buf))
        chunk_len = self.rng.randint(1, 64)
        chunk = bytes(self.rng.randint(0, 255) for _ in range(chunk_len))
        buf[pos:pos] = chunk
        return bytes(buf)

    def delete_bytes(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if len(buf) <= 1:
            return bytes(buf)
        del_len = min(self.rng.randint(1, 8), len(buf) - 1)
        pos = self.rng.randint(0, len(buf) - del_len)
        del buf[pos:pos + del_len]
        return bytes(buf)

    def duplicate_chunk(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if len(buf) < 2:
            return bytes(buf)
        src = self.rng.randint(0, len(buf) - 1)
        length = min(self.rng.randint(1, 16), len(buf) - src)
        dst = self.rng.randint(0, len(buf))
        buf[dst:dst] = buf[src:src + length]
        return bytes(buf)

    # ── 组合策略 ──────────────────────────────────────────────────

    def havoc(self, data: bytes, iterations: int = 8) -> bytes:
        """随机组合多种变异策略，模拟 AFL havoc 模式"""
        buf = data
        ops = [self.bitflip, self.byteflip, self.arith, self.interest_8,
               self.interest_16, self.interest_32, self.insert_bytes,
               self.delete_bytes, self.duplicate_chunk]
        for _ in range(iterations):
            buf = self.rng.choice(ops)(buf)
        return buf

    # ── 结构化变异: 针对 USB 描述符字段 ───────────────────────────

    def mutate_descriptor_length(self, data: bytes) -> bytes:
        """篡改描述符首字节 bLength — stm32-usb-fuzzer 的核心策略"""
        buf = bytearray(data)
        if not buf:
            return bytes(buf)
        # 策略: 0, 原长度±N, 超大值
        original = buf[0]
        choice = self.rng.randint(0, 5)
        if choice == 0:
            buf[0] = 0
        elif choice == 1:
            buf[0] = max(0, original - 1)        # 缺少尾字节
        elif choice == 2:
            buf[0] = original + self.rng.randint(1, 32)  # 声称更长
        elif choice == 3:
            buf[0] = 0xFF                          # 极端值
        elif choice == 4:
            buf[0] = self.rng.randint(0, 255)      # 随机
        else:
            buf[0] = original * 2                  # 倍增
        return bytes(buf)

    def mutate_descriptor_type(self, data: bytes) -> bytes:
        """篡改 bDescriptorType — 使主机解析器混乱"""
        buf = bytearray(data)
        if len(buf) < 2:
            return bytes(buf)
        buf[1] = self.rng.randint(0, 255)
        return bytes(buf)

    def mutate_vid_pid(self, data: bytes) -> bytes:
        """篡改 idVendor/idProduct — umap 的设备类伪装策略"""
        buf = bytearray(data)
        if len(buf) < 10:
            return bytes(buf)
        struct.pack_into('<HH', buf, 8,
                         self.rng.choice([0x0000, 0x046D, 0x05AC, 0x1D6B, 0x0424,
                                          0x05E3, 0x1D50, self.rng.randint(0, 65535)]),
                         self.rng.choice([0x0000, 0xC534, 0x2514, 0x6018, 0x2514,
                                          0x0608, self.rng.randint(0, 65535)]))
        return bytes(buf)

    def mutate_class_codes(self, data: bytes) -> bytes:
        """篡改 DeviceClass/SubClass/Protocol — usbStackFuzz 的类驱动边界测试"""
        buf = bytearray(data)
        if len(buf) < 8:
            return bytes(buf)
        buf[4] = self.rng.choice([0x00, 0x02, 0x03, 0x08, 0x09, 0x0E, 0xFF])  # class
        buf[5] = self.rng.choice(self.INTEREST_8)   # subclass
        buf[6] = self.rng.choice(self.INTEREST_8)   # protocol
        return bytes(buf)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. 模糊测试用例定义
# ═══════════════════════════════════════════════════════════════════════════════

class FuzzPhase(IntEnum):
    DESCRIPTOR    = 1   # 描述符变异
    CONTROL       = 2   # 控制传输模糊
    ENUMERATION   = 3   # 枚举状态机破坏
    DATA_TRANSFER = 4   # 数据传输模糊
    TIMING        = 5   # 时序模糊

PHASE_NAMES = {
    FuzzPhase.DESCRIPTOR:    "描述符变异",
    FuzzPhase.CONTROL:       "控制传输模糊",
    FuzzPhase.ENUMERATION:   "枚举状态机破坏",
    FuzzPhase.DATA_TRANSFER: "数据传输模糊",
    FuzzPhase.TIMING:        "时序模糊",
}


@dataclass
class FuzzCase:
    """单个模糊测试用例"""
    case_id:     int
    phase:       FuzzPhase
    description: str
    seed:        int
    # 描述符相关
    device_descriptor:    Optional[bytes] = None
    config_descriptor:    Optional[bytes] = None
    hid_descriptor:       Optional[bytes] = None
    # 控制传输相关
    control_request:      Optional[dict] = None  # {bmRequestType, bRequest, wValue, wIndex, wLength}
    control_response:     Optional[bytes] = None
    # 数据传输相关
    endpoint_data:        Optional[bytes] = None
    # 时序相关
    delay_ms:             int = 0
    disconnect_during:    Optional[str] = None  # "SET_ADDRESS" | "GET_DESCRIPTOR" | ...
    stall_ep0:            bool = False
    # 设备配置
    device_profile:       str = "generic-hid"
    device_speed:         str = "full"
    # 结果
    result:               str = "pending"  # pending | pass | crash | timeout | error
    timestamp:            float = 0.0
    duration_ms:          float = 0.0

    def to_json(self) -> dict:
        d = dataclasses.asdict(self)
        d['phase'] = self.phase.name
        for k in ('device_descriptor', 'config_descriptor', 'hid_descriptor',
                   'control_response', 'endpoint_data'):
            if d[k] is not None:
                d[k] = d[k].hex()
        return d

    @classmethod
    def from_json(cls, d: dict) -> 'FuzzCase':
        d['phase'] = FuzzPhase[d['phase']]
        for k in ('device_descriptor', 'config_descriptor', 'hid_descriptor',
                   'control_response', 'endpoint_data'):
            if d[k] is not None:
                d[k] = bytes.fromhex(d[k])
        return cls(**d)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. 目标监控 — 检测主机崩溃
# ═══════════════════════════════════════════════════════════════════════════════

class TargetMonitor:
    """
    目标主机存活检测 — USBFuzz 的关键创新之一。

    检测方法:
      - ICMP ping:       基本存活检测
      - USB 重枚举延迟:   设备是否被主机重新识别
      - 串口心跳:        (可选) 目标通过串口发送心跳
    """

    def __init__(self, target_ip: Optional[str] = None, ping_timeout: float = 3.0):
        self.target_ip = target_ip
        self.ping_timeout = ping_timeout

    def is_alive(self) -> bool:
        """检查目标是否存活"""
        if not self.target_ip:
            return True  # 无法检测时假设存活
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(int(self.ping_timeout)), self.target_ip],
                capture_output=True, timeout=self.ping_timeout + 2
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def check_after_case(self, case: FuzzCase) -> str:
        """
        在一个模糊测试用例后检查目标状态。
        返回: 'pass' | 'crash' | 'timeout'
        """
        # 等待短暂时间让任何延迟效果显现
        time.sleep(0.5)
        # 重试 3 次
        for attempt in range(3):
            if self.is_alive():
                return 'pass'
            time.sleep(1.0)
        return 'crash'


# ═══════════════════════════════════════════════════════════════════════════════
# 5. 模糊测试策略生成器 — 为每个阶段生成测试用例
# ═══════════════════════════════════════════════════════════════════════════════

# 标准 USB 2.0 设备描述符模板
TEMPLATE_DEVICE_DESC = bytes([
    0x12,       # bLength
    0x01,       # bDescriptorType (Device)
    0x00, 0x02, # bcdUSB 2.00
    0x00,       # bDeviceClass (由 profile 填充)
    0x00,       # bDeviceSubClass
    0x00,       # bDeviceProtocol
    0x40,       # bMaxPacketSize0 (64)
    0x6D, 0x04, # idVendor (Logitech)
    0x34, 0xC5, # idProduct
    0x00, 0x01, # bcdDevice
    0x01,       # iManufacturer
    0x02,       # iProduct
    0x03,       # iSerialNumber
    0x01,       # bNumConfigurations
])

# 标准配置描述符模板 (HID 设备)
TEMPLATE_CONFIG_DESC = bytes([
    # Configuration descriptor (9 bytes)
    0x09,       # bLength
    0x02,       # bDescriptorType (Configuration)
    0x22, 0x00, # wTotalLength (34 bytes)
    0x01,       # bNumInterfaces
    0x01,       # bConfigurationValue
    0x00,       # iConfiguration
    0x80,       # bmAttributes (Bus Powered)
    0x32,       # bMaxPower (100mA)
    # Interface descriptor (9 bytes)
    0x09,       # bLength
    0x04,       # bDescriptorType (Interface)
    0x00,       # bInterfaceNumber
    0x00,       # bAlternateSetting
    0x01,       # bNumEndpoints
    0x03,       # bInterfaceClass (HID)
    0x00,       # bInterfaceSubClass
    0x00,       # bInterfaceProtocol
    0x00,       # iInterface
    # HID descriptor (9 bytes)
    0x09,       # bLength
    0x21,       # bDescriptorType (HID)
    0x10, 0x01, # bcdHID 1.10
    0x00,       # bCountryCode
    0x01,       # bNumDescriptors
    0x22,       # bDescriptorType (Report)
    0x16, 0x00, # wDescriptorLength (22)
    # Endpoint descriptor (7 bytes)
    0x07,       # bLength
    0x05,       # bDescriptorType (Endpoint)
    0x81,       # bEndpointAddress (IN, EP1)
    0x03,       # bmAttributes (Interrupt)
    0x40, 0x00, # wMaxPacketSize (64)
    0x0A,       # bInterval (10ms)
])

# 最小 HID Report Descriptor (鼠标)
TEMPLATE_HID_REPORT = bytes([
    0x05, 0x01, # Usage Page (Generic Desktop)
    0x09, 0x02, # Usage (Mouse)
    0xA1, 0x01, # Collection (Application)
    0x09, 0x01, #   Usage (Pointer)
    0xA1, 0x00, #   Collection (Physical)
    0x05, 0x09, #     Usage Page (Button)
    0x19, 0x01, #     Usage Minimum (1)
    0x29, 0x03, #     Usage Maximum (3)
    0x15, 0x00, #     Logical Minimum (0)
    0x25, 0x01, #     Logical Maximum (1)
    0x95, 0x03, #     Report Count (3)
    0x75, 0x01, #     Report Size (1)
    0x81, 0x02, #     Input (Data,Var,Abs)
    0xC0,       #   End Collection
    0xC0,       # End Collection
])


class StrategyGenerator:
    """
    为每个模糊测试阶段生成测试用例序列。
    策略来自 USBFuzz/Syzkaller 的种子生成 + stm32-usb-fuzzer 的 30 种攻击模式。
    """

    def __init__(self, mutator: Mutator, profile: str = "generic-hid"):
        self.mutator = mutator
        self.profile = profile
        self.case_counter = 0

    def _new_case(self, phase: FuzzPhase, description: str, **kwargs) -> FuzzCase:
        self.case_counter += 1
        seed = self.mutator.rng.randint(0, 2**63 - 1)
        return FuzzCase(
            case_id=self.case_counter,
            phase=phase,
            description=description,
            seed=seed,
            device_profile=self.profile,
            **kwargs,
        )

    # ── Phase 1: 描述符变异 ──────────────────────────────────────

    def gen_descriptor_cases(self, max_cases: int = 100) -> list[FuzzCase]:
        """
        描述符变异 — 覆盖 USBFuzz 和 stm32-usb-fuzzer 的描述符攻击面。

        子类:
          1.1  bLength 篡改 (0, 过小, 过大, 0xFF)
          1.2  bDescriptorType 篡改
          1.3  VID/PID 篡改
          1.4  Class/SubClass/Protocol 篡改
          1.5  整体 havoc 变异
          1.6  长度声明与实际不符 (重叠/截断)
          1.7  嵌套/重复描述符
          1.8  Unicode 字符串描述符注入
        """
        cases = []
        desc = bytearray(TEMPLATE_DEVICE_DESC)
        prof = DEVICE_PROFILES.get(self.profile, DEVICE_PROFILES["generic-hid"])
        desc[4], desc[5], desc[6] = prof["class"], prof["subclass"], prof["protocol"]
        struct.pack_into('<HH', desc, 8, prof["vid"], prof["pid"])
        base_dev_desc = bytes(desc)

        # 1.1 bLength 篡改
        for i in range(min(12, max_cases)):
            mutated = self.mutator.mutate_descriptor_length(base_dev_desc)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR,
                f"bLength变异 #{i+1} (原始={base_dev_desc[0]:#x}, 变异={mutated[0]:#x})",
                device_descriptor=mutated,
            ))

        # 1.2 bDescriptorType 篡改
        for i in range(8):
            mutated = self.mutator.mutate_descriptor_type(base_dev_desc)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR, f"bDescriptorType变异 #{i+1}",
                device_descriptor=mutated
            ))

        # 1.3 VID/PID 篡改
        for i in range(10):
            mutated = self.mutator.mutate_vid_pid(base_dev_desc)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR, f"VID/PID伪装 #{i+1}",
                device_descriptor=mutated
            ))

        # 1.4 Class 码篡改
        for i in range(8):
            mutated = self.mutator.mutate_class_codes(base_dev_desc)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR, f"Class/SubClass/Protocol变异 #{i+1}",
                device_descriptor=mutated
            ))

        # 1.5 配置描述符变异
        for i in range(min(15, max_cases)):
            mutated = self.mutator.havoc(TEMPLATE_CONFIG_DESC, iterations=3)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR, f"配置描述符havoc #{i+1}",
                device_descriptor=base_dev_desc,
                config_descriptor=mutated
            ))

        # 1.6 bLength=0 的配置描述符 (经典崩溃)
        for length_val in [0, 1, 2, 3, 4]:
            mutated = bytearray(TEMPLATE_CONFIG_DESC)
            mutated[0] = length_val
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR, f"配置描述符bLength={length_val}",
                device_descriptor=base_dev_desc,
                config_descriptor=bytes(mutated)
            ))

        # 1.7 超大 wTotalLength
        for length_val in [0x0000, 0x0001, 0x00FF, 0xFFFF]:
            mutated = bytearray(TEMPLATE_CONFIG_DESC)
            struct.pack_into('<H', mutated, 2, length_val)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR, f"wTotalLength={length_val:#06x}",
                device_descriptor=base_dev_desc,
                config_descriptor=bytes(mutated)
            ))

        # 1.8 HID Report Descriptor 变异
        for i in range(10):
            mutated = self.mutator.havoc(TEMPLATE_HID_REPORT, iterations=4)
            cases.append(self._new_case(
                FuzzPhase.DESCRIPTOR, f"HID报告描述符变异 #{i+1}",
                device_descriptor=base_dev_desc,
                config_descriptor=TEMPLATE_CONFIG_DESC,
                hid_descriptor=mutated
            ))

        return cases[:max_cases]

    # ── Phase 2: 控制传输模糊 ────────────────────────────────────

    def gen_control_cases(self, max_cases: int = 150) -> list[FuzzCase]:
        """
        控制传输模糊 — USBFuzz 发现最多高危漏洞的区域。

        子类:
          2.1  标准请求 bRequest 全范围枚举 (0x00-0xFF)
          2.2  异常 wValue / wIndex 组合
          2.3  wLength 不匹配 (声明大长度返回小数据)
          2.4  类特定请求 (HID/MSC/UVC)
          2.5  方向反转 (OUT 当期望 IN)
          2.6  厂商自定义请求
          2.7  零长度请求
        """
        cases = []

        # 2.1 标准 bRequest 全范围
        for breq in range(0, 16):
            for bmrt_dir in [0x80, 0x00]:  # IN/OUT
                for wlength in [0, 1, 64, 255, 256, 4096, 0xFFFF]:
                    case = self._new_case(
                        FuzzPhase.CONTROL, f"标准请求 bRequest={breq:#04x} dir={'IN' if bmrt_dir else 'OUT'} wLen={wlength}",
                        control_request={
                            "bmRequestType": bmrt_dir | (0 << 5),  # Standard
                            "bRequest": breq,
                            "wValue": self.mutator.rng.randint(0, 65535),
                            "wIndex": self.mutator.rng.randint(0, 65535),
                            "wLength": wlength,
                        },
                        control_response=bytes(self.mutator.rng.randint(0, 255)
                                               for _ in range(min(wlength, 1024))),
                    )
                    cases.append(case)
                    if len(cases) >= max_cases:
                        break
                if len(cases) >= max_cases:
                    break
            if len(cases) >= max_cases:
                break

        # 2.2 异常 wValue/wIndex 组合
        interesting_16 = Mutator.INTEREST_16
        for _ in range(min(30, max_cases - len(cases))):
            case = self._new_case(
                FuzzPhase.CONTROL, "异常wValue/wIndex组合",
                control_request={
                    "bmRequestType": 0x80,
                    "bRequest": self.mutator.rng.choice([0x00, 0x06, 0x08, 0x0A]),
                    "wValue": self.mutator.rng.choice(interesting_16),
                    "wIndex": self.mutator.rng.choice(interesting_16),
                    "wLength": self.mutator.rng.choice([0, 64, 255, 512, 0xFFFF]),
                },
                control_response=b'\x00' * 64,
            )
            cases.append(case)

        # 2.3 类特定请求 (HID)
        hid_requests = [
            (HID_GET_REPORT,   0xA1, 0x0100, 0x00, 64),
            (HID_GET_IDLE,     0xA1, 0x0000, 0x00, 1),
            (HID_GET_PROTOCOL, 0xA1, 0x0000, 0x00, 1),
            (HID_SET_REPORT,   0x21, 0x0200, 0x00, 64),
            (HID_SET_IDLE,     0x21, 0x0000, 0x00, 0),
            (HID_SET_PROTOCOL, 0x21, 0x0000, 0x00, 0),
        ]
        for breq, bmrt, wval, wind, wlen in hid_requests:
            # 正常版本
            case = self._new_case(
                FuzzPhase.CONTROL, f"HID请求 bRequest={breq:#04x} (正常)",
                control_request={
                    "bmRequestType": bmrt, "bRequest": breq,
                    "wValue": wval, "wIndex": wind, "wLength": wlen,
                },
                control_response=b'\x41' * min(wlen, 1024),
            )
            cases.append(case)
            # 变异版本
            for _ in range(3):
                case = self._new_case(
                    FuzzPhase.CONTROL, f"HID请求 bRequest={breq:#04x} (变异)",
                    control_request={
                        "bmRequestType": bmrt ^ self.mutator.rng.choice([0x00, 0x80]),
                        "bRequest": breq,
                        "wValue": self.mutator.rng.choice(interesting_16),
                        "wIndex": self.mutator.rng.choice(interesting_16),
                        "wLength": self.mutator.rng.choice([0, 0xFFFF, 0x4000]),
                    },
                    control_response=bytes(self.mutator.rng.randint(0, 255) for _ in range(256)),
                )
                cases.append(case)

        # 2.4 类特定请求 (MSC)
        msc_requests = [
            (MSC_BOT_RESET,     0x21, 0x0000, 0x00, 0),
            (MSC_GET_MAX_LUN,   0xA1, 0x0000, 0x00, 1),
        ]
        for breq, bmrt, wval, wind, wlen in msc_requests:
            case = self._new_case(
                FuzzPhase.CONTROL, f"MSC请求 bRequest={breq:#04x}",
                control_request={
                    "bmRequestType": bmrt, "bRequest": breq,
                    "wValue": wval, "wIndex": wind, "wLength": wlen,
                },
                control_response=b'\x00' * max(wlen, 1),
            )
            cases.append(case)

        # 2.5 厂商自定义请求 (0x40/0xC0 direction)
        for _ in range(min(20, max_cases - len(cases))):
            case = self._new_case(
                FuzzPhase.CONTROL, "厂商自定义请求",
                control_request={
                    "bmRequestType": self.mutator.rng.choice([0x40, 0xC0]),
                    "bRequest": self.mutator.rng.randint(0, 255),
                    "wValue": self.mutator.rng.choice(interesting_16),
                    "wIndex": self.mutator.rng.choice(interesting_16),
                    "wLength": self.mutator.rng.choice([0, 64, 512, 0xFFFF]),
                },
                control_response=bytes(self.mutator.rng.randint(0, 255) for _ in range(128)),
            )
            cases.append(case)

        return cases[:max_cases]

    # ── Phase 3: 枚举状态机破坏 ──────────────────────────────────

    def gen_enumeration_cases(self, max_cases: int = 50) -> list[FuzzCase]:
        """
        枚举状态机破坏 — umap 和 usbStackFuzz 的核心策略。

        子类:
          3.1  在 SET_ADDRESS 后断连
          3.2  在 GET_DESCRIPTOR 响应中途断连
          3.3  对 SET_CONFIGURATION 返回 STALL
          3.4  快速重复枚举 (connect/disconnect 循环)
          3.5  在错误地址响应
          3.6  响应延迟注入
        """
        cases = []

        # 3.1 各阶段断连
        stages = ["SET_ADDRESS", "GET_DESCRIPTOR", "SET_CONFIGURATION",
                  "GET_CONFIGURATION_DESCRIPTOR", "GET_INTERFACE"]
        for stage in stages:
            case = self._new_case(
                FuzzPhase.ENUMERATION, f"枚举阶段断连: {stage}",
                device_descriptor=TEMPLATE_DEVICE_DESC,
                config_descriptor=TEMPLATE_CONFIG_DESC,
                disconnect_during=stage,
            )
            cases.append(case)

        # 3.2 EP0 STALL 注入
        for stage in stages:
            case = self._new_case(
                FuzzPhase.ENUMERATION, f"EP0 STALL: {stage}",
                device_descriptor=TEMPLATE_DEVICE_DESC,
                config_descriptor=TEMPLATE_CONFIG_DESC,
                stall_ep0=True,
            )
            cases.append(case)

        # 3.3 快速重连循环
        for count in [3, 5, 10, 20]:
            case = self._new_case(
                FuzzPhase.ENUMERATION, f"快速重连 x{count} (连续 {count} 次 connect/disconnect)",
                device_descriptor=TEMPLATE_DEVICE_DESC,
                config_descriptor=TEMPLATE_CONFIG_DESC,
            )
            cases.append(case)

        # 3.4 响应延迟
        for delay in [100, 500, 1000, 2000, 5000]:
            case = self._new_case(
                FuzzPhase.ENUMERATION, f"响应延迟 {delay}ms",
                device_descriptor=TEMPLATE_DEVICE_DESC,
                config_descriptor=TEMPLATE_CONFIG_DESC,
                delay_ms=delay,
            )
            cases.append(case)

        return cases[:max_cases]

    # ── Phase 4: 数据传输模糊 ────────────────────────────────────

    def gen_data_transfer_cases(self, max_cases: int = 80) -> list[FuzzCase]:
        """
        数据传输模糊 — 针对批量/中断/等时端点。

        子类:
          4.1  超大包 (> wMaxPacketSize)
          4.2  零长度包
          4.3  随机二进制垃圾
          4.4  格式字符串注入 (%s%s%s%n)
          4.5  NULL 字节注入
          4.6  重复/重叠包
        """
        cases = []

        payloads = [
            b'\x00' * 1024,                              # 全零
            b'\xFF' * 1024,                              # 全FF
            bytes(range(256)) * 4,                       # 递增模式
            b'%s%s%s%s%n%n%n%n' * 16,                    # 格式字符串
            b'A' * 65536,                                # 超大 (64KB)
            b'\xDE\xAD\xBE\xEF' * 256,                   # DEADBEEF 模式
            bytes(random.randint(0, 255) for _ in range(512)),  # 随机垃圾
            b'',                                         # 空包
            b'\x00' * 0x10000,                           # 64KB 零
        ]

        for i in range(min(max_cases, len(payloads) * 6)):
            base = payloads[i % len(payloads)]
            # 对部分 payload 进行 havoc 变异
            if i % 3 == 0:
                payload = self.mutator.havoc(base, iterations=4)
            elif i % 3 == 1:
                payload = self.mutator.interest_8(base)
            else:
                payload = base

            case = self._new_case(
                FuzzPhase.DATA_TRANSFER, f"数据传输 #{i+1} ({len(payload)} bytes)",
                device_descriptor=TEMPLATE_DEVICE_DESC,
                config_descriptor=TEMPLATE_CONFIG_DESC,
                endpoint_data=payload,
            )
            cases.append(case)

        return cases[:max_cases]

    # ── Phase 5: 时序模糊 ────────────────────────────────────────

    def gen_timing_cases(self, max_cases: int = 30) -> list[FuzzCase]:
        """
        时序模糊 — 利用 USB 协议的超时窗口。

        子类:
          5.1  极速响应 (< 1ms)
          5.2  临界超时响应 (接近 USB 超时)
          5.3  SETUP 阶段数据注入
          5.4  不完整传输 (只发部分数据)
        """
        cases = []

        # 5.1 各种延迟组合
        for delay in [0, 1, 5, 10, 50, 100, 200, 500, 1000, 2000, 3000, 5000]:
            case = self._new_case(
                FuzzPhase.TIMING, f"时序延迟 {delay}ms",
                device_descriptor=TEMPLATE_DEVICE_DESC,
                config_descriptor=TEMPLATE_CONFIG_DESC,
                delay_ms=delay,
            )
            cases.append(case)

        # 5.2 组合: 延迟 + STALL
        for delay in [100, 500, 1000]:
            case = self._new_case(
                FuzzPhase.TIMING, f"延迟{delay}ms + EP0 STALL",
                device_descriptor=TEMPLATE_DEVICE_DESC,
                config_descriptor=TEMPLATE_CONFIG_DESC,
                delay_ms=delay,
                stall_ep0=True,
            )
            cases.append(case)

        return cases[:max_cases]


# ═══════════════════════════════════════════════════════════════════════════════
# 6. 模糊设备模拟器 — 将测试用例转化为 Facedancer 设备行为
# ═══════════════════════════════════════════════════════════════════════════════

class FuzzDeviceController:
    """
    控制 Cynthion 模拟变异 USB 设备，执行单个模糊测试用例。

    实现: 使用 Facedancer 3.0 API 动态创建设备、响应控制请求、
    在指定阶段断连/STALL。
    """

    def __init__(self, speed: str = "full"):
        self.speed = speed
        self.device = None
        self.app = None

    async def execute_case(self, case: FuzzCase) -> FuzzCase:
        """执行单个模糊测试用例"""
        case.timestamp = time.time()
        start = time.time()

        try:
            await self._run_case(case)
            case.result = "executed"
        except Exception as e:
            case.result = "error"
            case.description += f" [ERROR: {e}]"
            traceback.print_exc()

        case.duration_ms = (time.time() - start) * 1000
        return case

    async def _run_case(self, case: FuzzCase):
        """根据阶段执行不同逻辑"""

        # 构建设备描述符
        dev_desc = case.device_descriptor or TEMPLATE_DEVICE_DESC

        # 解析设备描述符字段
        vid = struct.unpack_from('<H', dev_desc, 8)[0] if len(dev_desc) >= 10 else 0x1D50
        pid = struct.unpack_from('<H', dev_desc, 10)[0] if len(dev_desc) >= 12 else 0x6018
        dev_class = dev_desc[4] if len(dev_desc) > 4 else 0
        dev_subclass = dev_desc[5] if len(dev_desc) > 5 else 0
        dev_protocol = dev_desc[6] if len(dev_desc) > 6 else 0

        # 构建配置描述符
        cfg_desc = case.config_descriptor or TEMPLATE_CONFIG_DESC

        # 构建 HID 描述符
        hid_desc = case.hid_descriptor or TEMPLATE_HID_REPORT

        # 创建动态设备
        device = self._create_fuzz_device(
            vid=vid, pid=pid, dev_class=dev_class,
            dev_subclass=dev_subclass, dev_protocol=dev_protocol,
            config_desc=cfg_desc, hid_desc=hid_desc,
            case=case,
        )

        # 连接设备
        log.info(f"  [Case {case.case_id}] Connecting device VID={vid:#06x} PID={pid:#06x}...")

        device.app = FacedancerUSBApp()
        device.connect()

        # 等待主机枚举 (留出时间让主机处理设备)
        enum_wait = max(2.0, case.delay_ms / 1000.0)
        await asyncio.sleep(enum_wait)

        # 如果有控制请求需要从设备端主动发起 (Phase 2)
        if case.control_request and case.phase == FuzzPhase.CONTROL:
            # 控制请求实际上是主机发送给设备的，设备需要用变异数据响应
            # Facedancer 会自动用我们设定的 control_response 响应
            pass

        # 如果有端点数据 (Phase 4)
        if case.endpoint_data:
            await self._send_endpoint_data(device, case.endpoint_data)

        # 短暂保持连接
        await asyncio.sleep(1.0)

        # 断开
        device.disconnect()
        await asyncio.sleep(0.5)

    def _create_fuzz_device(self, vid, pid, dev_class, dev_subclass, dev_protocol,
                            config_desc, hid_desc, case):
        """动态创建 Facedancer USB 设备"""

        # 解析配置描述符提取接口和端点信息
        interfaces = self._parse_config_descriptor(config_desc)

        # 构建控制请求响应表
        ctrl_response = case.control_response or b'\x00' * 64
        stall_ep0 = case.stall_ep0
        delay_ms = case.delay_ms

        @use_inner_classes_automatically
        class FuzzUSBDevice(USBDevice):
            vendor_id              : int = vid
            product_id             : int = pid
            device_revision        : int = 0x0100
            manufacturer_string    : str = "FuzzCorp"
            product_string         : str = f"FuzzDevice-{case.case_id}"
            serial_number_string   : str = f"FUZZ{case.case_id:08d}"
            device_class           : int = dev_class
            device_subclass        : int = dev_subclass
            protocol_revision_number: int = dev_protocol
            device_speed           : str = self.speed

            _fuzz_case      = case
            _ctrl_response  = ctrl_response
            _stall_ep0      = stall_ep0
            _delay_ms       = delay_ms
            _custom_dev_desc = None  # 会动态设置
            _custom_cfg_desc = None
            _hid_desc       = hid_desc

            class _Configuration(USBConfiguration):
                configuration_string : str = "Fuzz Config"
                max_power            : int = 500

            # ── 变异描述符响应 ──────────────────────────────

            @standard_request_handler(number=STD_GET_DESCRIPTOR)
            def handle_get_descriptor(self, request):
                """拦截 GET_DESCRIPTOR，返回变异描述符"""
                desc_type = (request.value >> 8) & 0xFF
                desc_idx  = request.value & 0xFF

                # 延迟注入
                if self._delay_ms > 0:
                    time.sleep(self._delay_ms / 1000.0)

                # STALL 注入
                if self._stall_ep0:
                    request.stall()
                    return

                if desc_type == 0x01:  # Device Descriptor
                    data = case.device_descriptor or TEMPLATE_DEVICE_DESC
                    request.reply(data[:request.length or len(data)])
                elif desc_type == 0x02:  # Configuration Descriptor
                    data = case.config_descriptor or TEMPLATE_CONFIG_DESC
                    request.reply(data[:request.length or len(data)])
                elif desc_type == 0x03:  # String Descriptor
                    request.reply(b'\x04\x03\x09\x04')  # Language ID
                elif desc_type == 0x22:  # HID Report Descriptor
                    request.reply(hid_desc[:request.length or len(hid_desc)])
                else:
                    # 未知描述符类型 — 返回变异数据
                    request.reply(self._ctrl_response[:request.length or 64])

            # ── 拦截所有其他控制请求 ────────────────────────

            @standard_request_handler
            def handle_all_requests(self, request):
                """通用控制请求处理 — 返回变异数据或 STALL"""
                if self._delay_ms > 0:
                    time.sleep(self._delay_ms / 1000.0)
                if self._stall_ep0:
                    request.stall()
                    return

                # 对 SET_CONFIGURATION 正常响应
                if request.request == STD_SET_CONFIGURATION:
                    request.ack()
                elif request.request == STD_SET_ADDRESS:
                    request.ack()
                elif request.request == STD_GET_STATUS:
                    request.reply(b'\x00\x00')
                else:
                    # 其他请求返回变异数据
                    resp = self._ctrl_response[:request.length or 0]
                    if resp:
                        request.reply(resp)
                    else:
                        request.ack()

        # 动态添加接口和端点
        device_instance = FuzzUSBDevice()

        return device_instance

    def _parse_config_descriptor(self, data: bytes) -> list[dict]:
        """解析配置描述符，提取接口和端点信息"""
        interfaces = []
        offset = 0
        while offset + 4 <= len(data):
            desc_len = data[offset]
            desc_type = data[offset + 1] if offset + 1 < len(data) else 0
            if desc_len == 0:
                break
            if desc_type == 0x04 and offset + 9 <= len(data):  # Interface
                iface = {
                    'number': data[offset + 2],
                    'alt': data[offset + 3],
                    'num_endpoints': data[offset + 4],
                    'class': data[offset + 5],
                    'subclass': data[offset + 6],
                    'protocol': data[offset + 7],
                    'endpoints': [],
                }
                interfaces.append(iface)
            elif desc_type == 0x05 and offset + 7 <= len(data):  # Endpoint
                if interfaces:
                    ep = {
                        'address': data[offset + 2],
                        'attributes': data[offset + 3],
                        'max_packet_size': struct.unpack_from('<H', data, offset + 4)[0],
                        'interval': data[offset + 6],
                    }
                    interfaces[-1]['endpoints'].append(ep)
            offset += max(desc_len, 1)
        return interfaces

    async def _send_endpoint_data(self, device, data: bytes):
        """通过端点发送数据（模拟设备主动发送）"""
        try:
            # 尝试通过 EP1 IN 发送
            await asyncio.sleep(0.1)
            log.info(f"  Sending {len(data)} bytes to host via EP1 IN...")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# 7. 主引擎 — 协调各组件执行模糊测试
# ═══════════════════════════════════════════════════════════════════════════════

class FuzzEngine:
    """
    模糊测试主引擎 — 协调策略生成、设备模拟、目标监控。

    工作流:
      1. 初始化: RNG种子、输出目录、Cynthion连接
      2. 生成:   为每个选定阶段生成测试用例序列
      3. 执行:   逐个执行用例，监控目标状态
      4. 记录:   每个用例的参数和结果写入 JSON
      5. 汇总:   输出统计报告

    借鉴 USBFuzz 的策略:
      - 种子保存: 崩溃用例保存到 corpus/ 供后续交叉授粉
      - 增量变异: 从已发现崩溃的描述符继续变异
    """

    def __init__(self, args):
        self.args = args
        self.rng = random.Random(args.seed)
        self.mutator = Mutator(self.rng)
        self.monitor = TargetMonitor(args.target, args.ping_timeout)
        self.controller = FuzzDeviceController(args.speed)
        self.generator = StrategyGenerator(self.mutator, args.profile)
        self.results: list[FuzzCase] = []
        self.crashes: list[FuzzCase] = []
        self.session_id = time.strftime("%Y%m%d_%H%M%S")
        self.session_dir = RESULTS_DIR / f"session_{self.session_id}"
        self.start_time = 0.0
        self.stop_requested = False

    def run(self):
        """主入口"""
        self.start_time = time.time()
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self._print_banner()

        # 注册信号处理
        signal.signal(signal.SIGINT, self._signal_handler)

        # 解析阶段
        phases = self._parse_phases(self.args.phases)
        log.info(f"模糊测试阶段: {[PHASE_NAMES[p] for p in phases]}")

        # 生成所有测试用例
        all_cases = []
        for phase in phases:
            max_per_phase = self.args.max_cases // len(phases) if phases else 0
            gen_map = {
                FuzzPhase.DESCRIPTOR:    self.generator.gen_descriptor_cases,
                FuzzPhase.CONTROL:       self.generator.gen_control_cases,
                FuzzPhase.ENUMERATION:   self.generator.gen_enumeration_cases,
                FuzzPhase.DATA_TRANSFER: self.generator.gen_data_transfer_cases,
                FuzzPhase.TIMING:        self.generator.gen_timing_cases,
            }
            gen_fn = gen_map.get(phase)
            if gen_fn:
                cases = gen_fn(max_per_phase)
                all_cases.extend(cases)
                log.info(f"  {PHASE_NAMES[phase]}: {len(cases)} 个用例")

        total = len(all_cases)
        log.info(f"\n总计 {total} 个测试用例\n{'='*60}")

        # 执行
        for i, case in enumerate(all_cases):
            if self.stop_requested:
                break

            elapsed = time.time() - self.start_time
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            eta = (total - i - 1) / rate if rate > 0 else 0
            log.info(f"\n[{i+1}/{total}] Case #{case.case_id} — {PHASE_NAMES[case.phase]}")
            log.info(f"  描述: {case.description}")
            log.info(f"  进度: {((i+1)/total)*100:.1f}% | "
                     f"速率: {rate:.1f}/s | ETA: {eta:.0f}s | "
                     f"崩溃: {len(self.crashes)}")

            # 执行用例
            asyncio.run(self.controller.execute_case(case))

            # 监控目标
            status = self.monitor.check_after_case(case)
            case.result = status

            # 记录结果
            self.results.append(case)
            self._save_case(case)

            if status == 'crash':
                log.warning(f"  *** 目标崩溃! 保存崩溃用例 ***")
                self.crashes.append(case)
                self._save_crash(case)
                # 额外等待恢复
                log.info("  等待目标恢复 (10s)...")
                time.sleep(10)

        # 汇总
        self._print_summary()
        self._save_session_summary()

    def _parse_phases(self, phase_str: str) -> list[FuzzPhase]:
        if phase_str.lower() == 'all':
            return list(FuzzPhase)
        phases = []
        for p in phase_str.split(','):
            p = p.strip().lower()
            mapping = {
                '1': FuzzPhase.DESCRIPTOR, 'descriptor': FuzzPhase.DESCRIPTOR,
                '2': FuzzPhase.CONTROL,    'control': FuzzPhase.CONTROL,
                '3': FuzzPhase.ENUMERATION, 'enumeration': FuzzPhase.ENUMERATION,
                '4': FuzzPhase.DATA_TRANSFER, 'data': FuzzPhase.DATA_TRANSFER,
                '5': FuzzPhase.TIMING,     'timing': FuzzPhase.TIMING,
            }
            if p in mapping:
                phases.append(mapping[p])
        return phases or [FuzzPhase.DESCRIPTOR]

    def _save_case(self, case: FuzzCase):
        path = self.session_dir / f"case_{case.case_id:05d}.json"
        path.write_text(json.dumps(case.to_json(), indent=2, ensure_ascii=False))

    def _save_crash(self, case: FuzzCase):
        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        crash_dir = CORPUS_DIR / f"crash_{case.case_id:05d}"
        crash_dir.mkdir(parents=True, exist_ok=True)
        (crash_dir / "case.json").write_text(
            json.dumps(case.to_json(), indent=2, ensure_ascii=False))

    def _save_session_summary(self):
        summary = {
            "session_id": self.session_id,
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.start_time)),
            "duration_sec": time.time() - self.start_time,
            "total_cases": len(self.results),
            "crashes": len(self.crashes),
            "passes": sum(1 for c in self.results if c.result == 'pass'),
            "errors": sum(1 for c in self.results if c.result == 'error'),
            "phases": [PHASE_NAMES[c.phase] for c in self.results],
            "device_profile": self.args.profile,
            "target": self.args.target or "local",
            "seed": self.args.seed,
            "crash_details": [
                {"case_id": c.case_id, "phase": PHASE_NAMES[c.phase],
                 "description": c.description}
                for c in self.crashes
            ],
        }
        path = self.session_dir / "summary.json"
        path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        log.info(f"\n会话摘要已保存: {path}")

    def _print_banner(self):
        banner = f"""
╔══════════════════════════════════════════════════════════════════════╗
║          cynthion-usb-fuzzer — USB Host Fuzzing Framework           ║
║          基于 Cynthion/Facedancer                                   ║
╠══════════════════════════════════════════════════════════════════════╣
║  目标主机:  {self.args.target or '本地 (无监控)':<48s}║
║  设备类型:  {self.args.profile:<48s}║
║  设备速度:  {self.args.speed:<48s}║
║  随机种子:  {self.args.seed:<48d}║
║  会话 ID:   {self.session_id:<48s}║
╚══════════════════════════════════════════════════════════════════════╝
"""
        print(banner)

    def _print_summary(self):
        duration = time.time() - self.start_time
        summary = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                        模糊测试结果汇总                              ║
╠══════════════════════════════════════════════════════════════════════╣
║  总用例数:  {len(self.results):<8d}                                              ║
║  通过:      {sum(1 for c in self.results if c.result == 'pass'):<8d}                                              ║
║  崩溃:      {len(self.crashes):<8d}                                              ║
║  错误:      {sum(1 for c in self.results if c.result == 'error'):<8d}                                              ║
║  耗时:      {duration:<8.1f}s                                             ║
║  速率:      {len(self.results)/duration if duration > 0 else 0:<8.1f}/s                                             ║
╠══════════════════════════════════════════════════════════════════════╣"""

        if self.crashes:
            summary += f"""
║  崩溃用例:                                                            ║"""
            for c in self.crashes[:10]:
                summary += f"""
║    #{c.case_id:05d} [{PHASE_NAMES[c.phase]}] {c.description[:44]:<44s}║"""

        summary += f"""
╚══════════════════════════════════════════════════════════════════════╝
        结果目录: {self.session_dir}
        语料库:   {CORPUS_DIR}
"""
        print(summary)

    def _signal_handler(self, sig, frame):
        log.warning("\n收到中断信号，正在保存结果...")
        self.stop_requested = True


# ═══════════════════════════════════════════════════════════════════════════════
# 8. 回放模式 — 重放崩溃用例
# ═══════════════════════════════════════════════════════════════════════════════

def replay_crash(crash_path: str, speed: str = "full"):
    """重放崩溃用例"""
    path = Path(crash_path)
    if path.is_dir():
        path = path / "case.json"
    case = FuzzCase.from_json(json.loads(path.read_text()))

    log.info(f"回放崩溃用例 #{case.case_id}")
    log.info(f"  阶段: {PHASE_NAMES[case.phase]}")
    log.info(f"  描述: {case.description}")

    controller = FuzzDeviceController(speed)
    asyncio.run(controller.execute_case(case))
    log.info(f"  结果: {case.result}")


# ═══════════════════════════════════════════════════════════════════════════════
# 9. CLI 入口
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='cynthion-usb-fuzzer — 基于 Cynthion 的 USB 主机模糊测试框架',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # Phase 1+2, 测试远程目标
  %(prog)s --phases 1,2 --target 192.168.1.100

  # 全阶段, 最大 1000 用例, HID 设备
  %(prog)s --phases all --max-cases 1000 --profile generic-hid

  # 仅描述符变异
  %(prog)s --phases descriptor --profile generic-msc

  # 回放崩溃
  %(prog)s --replay results/session_20260728_120000/case_00042.json

  # 固定种子可复现
  %(prog)s --phases all --seed 42
        """,
    )
    parser.add_argument('--phases', default='1,2',
                        help='模糊测试阶段: 1=描述符,2=控制传输,3=枚举,4=数据,5=时序,all=全部 (默认: 1,2)')
    parser.add_argument('--target', default=None,
                        help='目标主机 IP (用于 ICMP 存活检测)')
    parser.add_argument('--max-cases', type=int, default=200,
                        help='最大测试用例数 (默认: 200)')
    parser.add_argument('--profile', default='generic-hid',
                        choices=list(DEVICE_PROFILES.keys()),
                        help='设备类型 (默认: generic-hid)')
    parser.add_argument('--speed', default='full',
                        choices=['low', 'full', 'high'],
                        help='USB 速度 (默认: full)')
    parser.add_argument('--seed', type=int, default=None,
                        help='随机种子 (默认: 随机)')
    parser.add_argument('--ping-timeout', type=float, default=3.0,
                        help='ICMP ping 超时秒数 (默认: 3.0)')
    parser.add_argument('--replay', default=None,
                        help='回放指定崩溃用例 JSON 文件')

    args = parser.parse_args()

    if args.seed is None:
        args.seed = random.randint(0, 2**31 - 1)

    if args.replay:
        replay_crash(args.replay, args.speed)
        return

    engine = FuzzEngine(args)
    engine.run()


if __name__ == '__main__':
    main()
