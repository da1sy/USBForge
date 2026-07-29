#!/usr/bin/env python3
"""
mcp_bridge.py — MCP 服务器桥接层

将 USBForge TUI 连接到 cynthion-mcp 服务器的真实硬件能力。
通过 stdio JSON-RPC 2.0 协议与 cynthion-mcp 通信。

功能:
  · 模式切换 (switch_mode)
  · USB 流量捕获 (capture_start / capture_stop)
  · 捕获解码 (convert_to_pcap / dissect_packets / transaction_summary)
  · 设备模拟 (emulate_device / emulate_from_descriptor / disconnect_device)
  · 串口注入 (inject_serial)
  · 硬件诊断 (get_status / recover / emulator_diagnose)

使用:
  from mcp_bridge import MCPBridge
  bridge = MCPBridge()
  bridge.start()  # 启动 MCP server 子进程
  result = bridge.call_tool("get_status")
  bridge.stop()
"""

from __future__ import annotations

import os
import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Optional

os.environ.pop("PYTHONPATH", None)

_MCP_SERVER = "/Users/da1sy/tools/cynthion/.venv/bin/cynthion-mcp"
_CAP_DIR = Path.home() / ".cynthion-mcp" / "captures"


class MCPBridge:
    """MCP 服务器桥接 — 管理 cynthion-mcp 子进程并通过 JSON-RPC 调用工具。"""

    def __init__(self):
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._request_id = 0
        self._initialized = False
        self._available = False

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def available(self) -> bool:
        """MCP server 是否可用（已初始化且响应正常）"""
        return self._available

    def start(self, timeout: float = 10.0) -> bool:
        """启动 MCP server 子进程并完成 initialize 握手。"""
        if self.is_running:
            return True

        try:
            self._proc = subprocess.Popen(
                [_MCP_SERVER],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "PYTHONPATH": ""},
            )
        except FileNotFoundError:
            self._available = False
            return False
        except Exception:
            self._available = False
            return False

        # 完成 MCP initialize 握手
        try:
            resp = self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "USBForge", "version": "3.0.0"},
            }, timeout=timeout)

            if resp and "result" in resp:
                # 发送 initialized 通知
                self._send_notification("notifications/initialized", {})
                self._available = True
                return True
        except Exception:
            pass

        self._available = False
        return False

    def stop(self):
        """停止 MCP server 子进程。"""
        if self._proc:
            try:
                self._proc.stdin.close()
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
            self._available = False
            self._initialized = False

    def call_tool(self, name: str, arguments: dict = None, timeout: float = 30.0) -> dict:
        """
        调用 MCP 工具并返回结果。

        返回: {"ok": bool, "data": ..., "error": str|None}
        """
        if not self.is_running:
            if not self.start():
                return {"ok": False, "error": "MCP server 不可用"}

        try:
            resp = self._send_request("tools/call", {
                "name": name,
                "arguments": arguments or {},
            }, timeout=timeout)

            if resp and "result" in resp:
                result = resp["result"]
                # MCP tool result 格式: {"content": [{"type": "text", "text": "..."}]}
                content = result.get("content", [])
                if content:
                    text = content[0].get("text", "")
                    try:
                        parsed = json.loads(text)
                        return {"ok": True, "data": parsed}
                    except (json.JSONDecodeError, TypeError):
                        return {"ok": True, "data": text}
                return {"ok": True, "data": result}

            if resp and "error" in resp:
                return {"ok": False, "error": str(resp["error"].get("message", resp["error"]))}

            return {"ok": False, "error": "无响应"}

        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "超时"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def list_tools(self) -> list[dict]:
        """列出 MCP 服务器提供的所有工具。"""
        if not self.is_running:
            if not self.start():
                return []

        try:
            resp = self._send_request("tools/list", {}, timeout=10)
            if resp and "result" in resp:
                return resp["result"].get("tools", [])
        except Exception:
            pass
        return []

    # ═══════════════════════════════════════════════════════════════════════
    # 高级 API — 针对常用操作的便捷封装
    # ═══════════════════════════════════════════════════════════════════════

    def get_status(self) -> dict:
        """获取设备状态"""
        return self.call_tool("get_status")

    def switch_mode(self, applet: str) -> dict:
        """切换模式 (analyzer / facedancer)"""
        return self.call_tool("switch_mode", {"applet": applet}, timeout=30)

    def capture_start(self, speed: str = "auto") -> dict:
        """开始 USB 流量捕获"""
        return self.call_tool("capture_start", {"speed": speed}, timeout=15)

    def capture_status(self) -> dict:
        """获取捕获状态"""
        return self.call_tool("capture_status")

    def capture_stop(self) -> dict:
        """停止捕获"""
        return self.call_tool("capture_stop", timeout=15)

    def list_captures(self) -> dict:
        """列出所有捕获"""
        return self.call_tool("list_captures")

    def convert_to_pcap(self, capture_id: str) -> dict:
        """转换捕获为 pcap"""
        return self.call_tool("convert_to_pcap", {"capture_id": capture_id})

    def transaction_summary(self, capture_id: str) -> dict:
        """获取事务摘要"""
        return self.call_tool("transaction_summary", {"capture_id": capture_id})

    def dissect_packets(self, capture_id: str, display_filter: str = None, limit: int = 100) -> dict:
        """解析数据包"""
        args = {"capture_id": capture_id, "limit": limit}
        if display_filter:
            args["display_filter"] = display_filter
        return self.call_tool("dissect_packets", args)

    def find_vendor_requests(self, capture_id: str) -> dict:
        """查找厂商自定义请求"""
        return self.call_tool("find_vendor_requests", {"capture_id": capture_id})

    def emulator_diagnose(self) -> dict:
        """模拟器诊断"""
        return self.call_tool("emulator_diagnose")

    def emulate_device(self, device_type: str = "ftdi", vendor_id: int = None, product_id: int = None) -> dict:
        """模拟 USB 设备"""
        args = {"device_type": device_type}
        if vendor_id is not None:
            args["vendor_id"] = vendor_id
        if product_id is not None:
            args["product_id"] = product_id
        return self.call_tool("emulate_device", args)

    def emulate_from_descriptor(self, device_desc_hex: str, config_desc_hex: str = None, strings: dict = None) -> dict:
        """从描述符克隆设备"""
        args = {"device_descriptor_hex": device_desc_hex}
        if config_desc_hex:
            args["configuration_descriptor_hex"] = config_desc_hex
        if strings:
            args["strings"] = strings
        return self.call_tool("emulate_from_descriptor", args)

    def disconnect_device(self) -> dict:
        """断开模拟设备"""
        return self.call_tool("disconnect_device")

    def inject_serial(self, text: str) -> dict:
        """注入串口数据"""
        return self.call_tool("inject_serial", {"text": text})

    # ═══════════════════════════════════════════════════════════════════════
    # JSON-RPC 内部通信
    # ═══════════════════════════════════════════════════════════════════════

    def _send_request(self, method: str, params: dict, timeout: float = 30.0) -> Optional[dict]:
        """发送 JSON-RPC 请求并等待响应。"""
        with self._lock:
            if not self._proc or self._proc.poll() is not None:
                return None

            self._request_id += 1
            req_id = self._request_id

            request = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params,
            }

            data = (json.dumps(request) + "\n").encode("utf-8")
            self._proc.stdin.write(data)
            self._proc.stdin.flush()

            # 读取响应（按行读取直到找到匹配 id 的响应）
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                line = self._read_line(timeout=max(0.5, deadline - time.monotonic()))
                if line is None:
                    break
                if not line.strip():
                    continue
                try:
                    resp = json.loads(line)
                    if resp.get("id") == req_id:
                        return resp
                    # 其他响应（通知等）跳过
                except json.JSONDecodeError:
                    continue

            return None

    def _send_notification(self, method: str, params: dict):
        """发送 JSON-RPC 通知（不等待响应）。"""
        if not self._proc or self._proc.poll() is not None:
            return
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        data = (json.dumps(notification) + "\n").encode("utf-8")
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def _read_line(self, timeout: float = 5.0) -> Optional[str]:
        """从 stdout 读取一行（带超时）。"""
        if not self._proc:
            return None

        # 使用线程读取以实现超时
        result = [None]
        def _read():
            try:
                line = self._proc.stdout.readline()
                result[0] = line.decode("utf-8") if line else None
            except Exception:
                result[0] = None

        t = threading.Thread(target=_read, daemon=True)
        t.start()
        t.join(timeout=timeout)
        return result[0]


# ═══════════════════════════════════════════════════════════════════════════════
# 单例实例
# ═══════════════════════════════════════════════════════════════════════════════

_bridge: Optional[MCPBridge] = None
_bridge_lock = threading.Lock()


def get_bridge() -> MCPBridge:
    """获取全局 MCP bridge 单例。"""
    global _bridge
    with _bridge_lock:
        if _bridge is None:
            _bridge = MCPBridge()
        return _bridge


def check_mcp_available() -> bool:
    """检查 MCP server 是否可用。"""
    bridge = get_bridge()
    if not bridge.is_running:
        if not bridge.start():
            return False
    return bridge.available
