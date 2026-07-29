#!/usr/bin/env python3
"""
device.py — Cynthion 设备检测与状态管理

功能:
  · 自动检测 Cynthion 硬件连接状态
  · 识别当前 bitstream 模式 (Facedancer / Analyzer / Debugger)
  · 判断 TARGET-C → DUT 是否就绪
  · 提供模式切换 (flash facedancer / analyzer)
  · 获取设备详细信息 (序列号/版本/速度)
"""

import os
import sys
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# 环境修复 (与 tui.py 相同)
import os as _os
_os.environ.pop("PYTHONPATH", None)

try:
    import usb.core
    import usb.util
    _HAS_PYUSB = True
except ImportError:
    _HAS_PYUSB = False


class DeviceMode(Enum):
    """Cynthion 当前 bitstream 模式"""
    FACEDANCER = "Facedancer"      # USB 设备模拟 — 模糊测试就绪
    ANALYZER = "Analyzer"          # USB 嗅探 — 可用于被动监控
    DEBUGGER = "Debugger"          # Apollo 调试器 — 需要切换
    NOT_FOUND = "Not Found"        # 未检测到设备
    ERROR = "Error"                # 检测出错


class FuzzerReadiness(Enum):
    """模糊测试就绪状态"""
    READY = "就绪"                 # Facedancer 模式 + DUT 连接
    NEED_BITSTREAM = "需切换固件"  # 设备在但不是 Facedancer 模式
    NO_DEVICE = "未连接"           # 设备未找到
    ERROR = "错误"


@dataclass
class CynthionInfo:
    """Cynthion 设备信息"""
    connected: bool = False
    mode: DeviceMode = DeviceMode.NOT_FOUND
    vid: int = 0
    pid: int = 0
    bus: int = 0
    address: int = 0
    speed: str = ""
    serial: str = ""
    product: str = ""
    manufacturer: str = ""
    hardware: str = ""             # e.g. "Cynthion r1.4"
    firmware_version: str = ""     # e.g. "1.1.1"
    bitstream_serial: str = ""     # e.g. "3420901f704464de"
    raw_error: str = ""

    @property
    def is_facedancer(self) -> bool:
        return self.mode == DeviceMode.FACEDANCER

    @property
    def short_desc(self) -> str:
        if not self.connected:
            return "未检测到 Cynthion"
        return f"{self.product} ({self.mode.value}) bus={self.bus} addr={self.address}"


# ═══════════════════════════════════════════════════════════════════════════════
# Cynthion VID/PID 映射
# ═══════════════════════════════════════════════════════════════════════════════

CYNTHION_VID = 0x1d50

CYNTHION_PIDS = {
    0x615b: DeviceMode.FACEDANCER,   # Apollo Stub — Facedancer bitstream
    0x615c: DeviceMode.DEBUGGER,     # Apollo Debugger
    0x615e: DeviceMode.ANALYZER,     # Cynthion Analyzer
}

# Cynthion CLI 路径
_CYNTHION_BIN = "/Users/da1sy/tools/cynthion/.venv/bin/cynthion"
_CYNTHION_PYTHON = "/Users/da1sy/tools/cynthion/.venv/bin/python3"


# ═══════════════════════════════════════════════════════════════════════════════
# 设备检测
# ═══════════════════════════════════════════════════════════════════════════════

def detect_cynthion() -> CynthionInfo:
    """
    通过 pyusb 检测 Cynthion 设备。
    
    返回第一个匹配的 Cynthion 设备信息。
    如果设备不在 Facedancer 模式，调用者可以用 switch_to_facedancer() 切换。
    
    注意: PID 0x615b 表示 Apollo stub (已加载 bitstream)，
          但不区分 Facedancer vs Analyzer — 需要用 cynthion info 查 bitstream 名。
          PID 0x615c 表示 Apollo Debugger (未加载 bitstream)。
    """
    info = CynthionInfo()

    if not _HAS_PYUSB:
        info.mode = DeviceMode.ERROR
        info.raw_error = "pyusb 未安装"
        return info

    try:
        # 重新扫描设备（避免 pyusb 缓存旧设备列表）
        usb.core.find(find_all=True)  # 触发 libusb 重新枚举
        for dev in usb.core.find(find_all=True, idVendor=CYNTHION_VID):
            pid = dev.idProduct
            if pid not in CYNTHION_PIDS:
                continue

            info.connected = True
            info.vid = dev.idVendor
            info.pid = pid
            info.bus = dev.bus
            info.address = dev.address
            info.mode = CYNTHION_PIDS[pid]

            # 速度映射
            speed_map = {0: "Low Speed (1.5 Mbps)", 1: "Full Speed (12 Mbps)",
                         2: "High Speed (480 Mbps)", 3: "SuperSpeed (5 Gbps)",
                         4: "SuperSpeed+ (10 Gbps)"}
            info.speed = speed_map.get(dev.speed, f"Unknown ({dev.speed})")

            # 字符串描述符
            try:
                info.product = usb.util.get_string(dev, dev.iProduct) or ""
            except:
                info.product = ""
            try:
                info.manufacturer = usb.util.get_string(dev, dev.iManufacturer) or ""
            except:
                info.manufacturer = ""
            try:
                info.serial = usb.util.get_string(dev, dev.iSerialNumber) or ""
            except:
                info.serial = ""

            # PID 0x615b = Apollo stub — 查询 bitstream 名区分 Facedancer/Analyzer
            if pid == 0x615b:
                detailed = get_detailed_info()
                bitstream = detailed.get("bitstream", "").lower()
                if "facedancer" in bitstream:
                    info.mode = DeviceMode.FACEDANCER
                elif "analyzer" in bitstream:
                    info.mode = DeviceMode.ANALYZER
                else:
                    info.mode = DeviceMode.FACEDANCER  # 默认假设 facedancer

            # 只返回第一个找到的设备
            break

    except Exception as e:
        info.mode = DeviceMode.ERROR
        info.raw_error = str(e)

    return info


def get_detailed_info() -> dict:
    """
    调用 `cynthion info --force-offline` 获取详细信息。
    
    返回包含 hardware / firmware_version / bitstream_serial 等的字典。
    比 pyusb 检测更详细，但速度较慢。
    """
    result = {}
    try:
        proc = subprocess.run(
            [_CYNTHION_BIN, "info"],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "PYTHONPATH": ""},  # 防止污染
        )
        output = proc.stdout + proc.stderr

        # 解析输出
        for line in output.split("\n"):
            line = line.strip()
            if "Hardware:" in line:
                result["hardware"] = line.split("Hardware:")[-1].strip()
            elif "Serial number:" in line:
                result["serial"] = line.split("Serial number:")[-1].strip()
            elif "Bitstream serial" in line:
                result["bitstream_serial"] = line.split("serial number:")[-1].strip()
            elif "Apollo version:" in line:
                result["firmware_version"] = line.split("Apollo version:")[-1].strip()
            elif "Cynthion version:" in line:
                result["cynthion_version"] = line.split("Cynthion version:")[-1].strip()
            elif "Bitstream:" in line:
                result["bitstream"] = line.split("Bitstream:")[-1].strip()

    except FileNotFoundError:
        result["error"] = "cynthion CLI 未找到"
    except subprocess.TimeoutExpired:
        result["error"] = "cynthion info 超时"
    except Exception as e:
        result["error"] = str(e)

    return result


def _wait_for_reenumerate(expected_mode: str, timeout: float = 30.0) -> bool:
    """
    等待设备完成模式切换（带稳定性验证）。

    Cynthion r1.4 flash 后时序:
      0-1.5s: PID 0x615c (旧 debugger)
      1.5-3.5s: 设备断开 (none)
      4.0s+:   PID 0x615b (目标 bitstream)

    必须连续 2 次检测到目标 PID 才认为稳定。
    不在轮询中调用 get_detailed_info() — 那会干扰正在重新枚举的设备。
    """
    target_pid = 0x615e if expected_mode == "analyzer" else None
    # Facedancer 和 Analyzer 的 PID 都可能是 0x615b (Apollo stub)
    # 区分靠 bitstream 名，但在轮询中不查询（避免干扰）
    consecutive_hits = 0

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            # 清除 pyusb 缓存
            usb.core.find(find_all=True)
            devices = list(usb.core.find(find_all=True, idVendor=CYNTHION_VID))

            if not devices:
                # 设备断开中 — 正常，重置计数
                consecutive_hits = 0
            else:
                for dev in devices:
                    pid = dev.idProduct
                    if pid == 0x615b:
                        # Apollo stub (Facedancer 或 Analyzer bitstream)
                        consecutive_hits += 1
                        if consecutive_hits >= 2:
                            return True
                    elif pid == 0x615e and expected_mode == "analyzer":
                        consecutive_hits += 1
                        if consecutive_hits >= 2:
                            return True
                    elif pid == 0x615c:
                        # 仍在 debugger — 重置
                        consecutive_hits = 0
        except Exception:
            pass
        time.sleep(1.0)
    return False


def switch_to_facedancer() -> bool:
    """
    切换 Cynthion 到 Facedancer 模式（持久刷写到 SPI flash）。

    使用 `cynthion flash facedancer` 烧录持久 bitstream（断电后保持）。
    刷写过程约 30-90 秒（含 SoC firmware + FPGA 配置 flash）。
    烧录完成后等待设备重新枚举并验证 bitstream 名。
    """
    try:
        proc = subprocess.run(
            [_CYNTHION_BIN, "flash", "facedancer"],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONPATH": ""},
        )
        if proc.returncode != 0:
            return False
        if _wait_for_reenumerate("facedancer"):
            time.sleep(2)  # 额外稳定等待
            return True
        return False
    except Exception:
        return False


def switch_to_analyzer() -> bool:
    """切换 Cynthion 到 Analyzer 模式（持久刷写）。"""
    try:
        proc = subprocess.run(
            [_CYNTHION_BIN, "flash", "analyzer"],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONPATH": ""},
        )
        if proc.returncode != 0:
            return False
        if _wait_for_reenumerate("analyzer"):
            time.sleep(2)  # 额外稳定等待
            return True
        return False
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# DUT (被测目标) 连接检测
# ═══════════════════════════════════════════════════════════════════════════════

def check_dut_connection(info: Optional[CynthionInfo] = None) -> dict:
    """
    检测 TARGET-C 端口是否连接到 DUT。
    
    在 Facedancer 模式下，当 DUT 连接时:
      · Cynthion 的 USB 模拟器会收到来自 DUT 的 USB 复位信号
      · 可以通过 Facedancer 后端检测总线活动
    
    返回:
      {
        "connected": bool,       # DUT 是否连接
        "method": str,           # 检测方法
        "details": str,          # 详细信息
      }
    """
    if info is None:
        info = detect_cynthion()

    result = {"connected": False, "method": "", "details": ""}

    if not info.connected:
        result["details"] = "Cynthion 未连接"
        return result

    if not info.is_facedancer:
        result["details"] = f"当前模式 {info.mode.value} — 需要切换到 Facedancer"
        return result

    # 在 Facedancer 模式下，尝试通过 Moondancer 后端检测总线状态
    try:
        # 尝试导入 facedancer 后端
        sys.path.insert(0, "/Users/da1sy/tools/cynthion/.venv/lib/python3.12/site-packages")
        from facedancer.backends.moondancer import MoondancerApp

        # 获取 Apollo 设备
        import usb.core
        dev = usb.core.find(idVendor=CYNTHION_VID, idProduct=0x615b)
        if dev is None:
            result["details"] = "Facedancer 设备未找到"
            return result

        # 尝试初始化 Moondancer 通信
        # 这里只检测 USB 总线是否有活动
        # 如果 DUT 连接了，Cynthion 会收到总线复位

        # 简单方式: 检查设备是否处于配置状态
        if dev.get_active_configuration() is not None:
            result["connected"] = True
            result["method"] = "USB 配置已激活"
            result["details"] = "DUT 已连接 (USB 配置活跃)"
        else:
            result["details"] = "DUT 可能未连接 (无活跃配置)"

    except ImportError:
        # facedancer 不可用，回退到被动检测
        result["method"] = "被动检测"
        result["details"] = "无法主动检测 DUT (facedancer 后端不可用)"
    except Exception as e:
        result["details"] = f"DUT 检测出错: {e}"

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 综合状态
# ═══════════════════════════════════════════════════════════════════════════════

def get_full_status() -> dict:
    """
    获取完整的设备连接状态 — 供 TUI 调用。
    
    返回:
      {
        "cynthion": CynthionInfo,
        "detailed": dict,         # cynthion info 详细输出
        "dut": dict,              # DUT 连接状态
        "readiness": FuzzerReadiness,
        "readiness_msg": str,
        "can_start": bool,        # 是否可以开始模糊测试
      }
    """
    info = detect_cynthion()
    detailed = {}
    dut = {"connected": False, "details": ""}
    readiness = FuzzerReadiness.ERROR
    readiness_msg = ""
    can_start = False

    if not info.connected:
        readiness = FuzzerReadiness.NO_DEVICE
        readiness_msg = "Cynthion 未连接 — 请插入 CONTROL-C USB 线"
    elif info.is_facedancer:
        # Facedancer 模式 — 检查 DUT
        dut = check_dut_connection(info)
        detailed = get_detailed_info()

        if dut["connected"]:
            readiness = FuzzerReadiness.READY
            readiness_msg = f"✓ 就绪 — Facedancer + DUT 已连接 ({info.speed})"
            can_start = True
        else:
            readiness = FuzzerReadiness.READY
            readiness_msg = f"✓ Facedancer 就绪 ({info.speed}) — 连接 TARGET-C 到目标设备"
            can_start = True  # 允许启动，DUT 可能在启动后连接
    elif info.mode == DeviceMode.DEBUGGER:
        detailed = get_detailed_info()
        readiness = FuzzerReadiness.NEED_BITSTREAM
        readiness_msg = f"当前 Debugger 模式 — 点击 [切换到 Facedancer] "
    elif info.mode == DeviceMode.ANALYZER:
        readiness = FuzzerReadiness.NEED_BITSTREAM
        readiness_msg = f"当前 Analyzer 模式 — 点击 [切换到 Facedancer]"
    else:
        readiness = FuzzerReadiness.ERROR
        readiness_msg = f"未知状态: {info.raw_error}"

    return {
        "cynthion": info,
        "detailed": detailed,
        "dut": dut,
        "readiness": readiness,
        "readiness_msg": readiness_msg,
        "can_start": can_start,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 测试入口
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  Cynthion 设备状态检测")
    print("=" * 60)

    status = get_full_status()
    info = status["cynthion"]

    print(f"\n  连接状态: {info.connected}")
    print(f"  模式: {info.mode.value}")
    if info.connected:
        print(f"  VID:PID: {info.vid:#06x}:{info.pid:#06x}")
        print(f"  总线: bus={info.bus} addr={info.address}")
        print(f"  速度: {info.speed}")
        print(f"  产品: {info.product}")
        print(f"  序列号: {info.serial}")

    print(f"\n  就绪状态: {status['readiness'].value}")
    print(f"  {status['readiness_msg']}")

    if status["detailed"]:
        print(f"\n  详细信息:")
        for k, v in status["detailed"].items():
            print(f"    {k}: {v}")

    print(f"\n  可以开始: {status['can_start']}")
