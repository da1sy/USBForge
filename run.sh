#!/usr/bin/env bash
# USBForge v3.0 — 全功能 USB 安全工具套件
# 基于 Cynthion 平台 / Facedancer 框架
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 清除可能冲突的 PYTHONPATH
unset PYTHONPATH

# 优先使用 Cynthion .venv 的 Python 3.12
# 支持两种查找方式：同级 venv 或上级 venv
if [ -f "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PYTHON="$SCRIPT_DIR/.venv/bin/python3"
elif [ -f "$(dirname "$SCRIPT_DIR")/.venv/bin/python3" ]; then
    PYTHON="$(dirname "$SCRIPT_DIR")/.venv/bin/python3"
else
    echo "错误: 未找到 Python 虚拟环境"
    echo "请先创建 venv 并安装依赖:"
    echo "  python3 -m venv .venv"
    echo "  .venv/bin/pip install cynthion facedancer textual rich pyusb"
    exit 1
fi

exec "$PYTHON" tui.py "$@"
