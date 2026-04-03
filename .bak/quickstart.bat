@echo off
REM IDA-Graphy 快速启动脚本 (Windows)
REM ========================================

echo.
echo ========================================
echo IDA-Graphy 快速启动向导
echo ========================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到Python，请先安装Python 3.8+
    pause
    exit /b 1
)

echo [1/4] Python 已安装
echo.

REM 安装依赖
echo [2/4] 正在安装依赖...
pip install -r requirements.txt
if errorlevel 1 (
    echo [警告] 依赖安装失败，继续尝试...
)
echo.

REM 安装包
echo [3/4] 正在安装 ida-graphy...
pip install -e .
if errorlevel 1 (
    echo [错误] 安装失败
    pause
    exit /b 1
)
echo.

REM 运行测试
echo [4/4] 运行基础测试...
python test_ida_graphy.py
if errorlevel 1 (
    echo [警告] 部分测试失败，这可能是因为IDA未安装或路径未配置
    echo 请编辑 config.yaml 文件设置正确的IDA路径
)
echo.

echo ========================================
echo 安装完成！
echo ========================================
echo.
echo 使用方法:
echo   ida-graphy --binary your_binary.exe
echo   ida-graphy --binaries *.dll
echo   ida-graphy --config config.yaml --binary app.exe
echo.
echo 配置文件: config.yaml
echo 文档: README.md, USAGE_EXAMPLES.md
echo.
pause
