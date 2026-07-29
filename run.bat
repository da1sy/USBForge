@echo off
REM USBForge v3.0 — 全功能 USB 安全工具套件
REM 基于 Cynthion 平台 / Facedancer 框架
setlocal

cd /d "%~dp0"

REM 清除可能冲突的 PYTHONPATH
set PYTHONPATH=

REM 优先使用本地 venv，其次上级 venv
set "PYTHON=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=%~dp0..\.venv\Scripts\python.exe"

if not exist "%PYTHON%" (
    echo 错误: 未找到 Python 虚拟环境
    echo 请先创建 venv 并安装依赖:
    echo   python -m venv .venv
    echo   .venv\Scripts\pip install cynthion facedancer textual rich pyusb pyfiglet libusb
    pause
    exit /b 1
)

REM 添加 libusb DLL 到 PATH (pyusb 后端需要)
set "LIBUSB_DLL=%~dp0.venv\Lib\site-packages\libusb\_platform\windows\x86_64"
if exist "%LIBUSB_DLL%\libusb-1.0.dll" set "PATH=%LIBUSB_DLL%;%PATH%"

"%PYTHON%" tui.py %*
endlocal
