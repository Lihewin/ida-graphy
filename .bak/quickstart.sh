#!/bin/bash
# IDA-Graphy 快速启动脚本 (Linux/Mac)
# ========================================

set -e

echo ""
echo "========================================"
echo "IDA-Graphy 快速启动向导"
echo "========================================"
echo ""

# 检查Python
if ! command -v python3 &> /dev/null; then
    echo "[错误] 未检测到Python3，请先安装Python 3.8+"
    exit 1
fi

echo "[1/4] Python3 已安装"
echo ""

# 安装依赖
echo "[2/4] 正在安装依赖..."
pip3 install -r requirements.txt || echo "[警告] 依赖安装失败，继续尝试..."
echo ""

# 安装包
echo "[3/4] 正在安装 ida-graphy..."
pip3 install -e . || {
    echo "[错误] 安装失败"
    exit 1
}
echo ""

# 运行测试
echo "[4/4] 运行基础测试..."
python3 test_ida_graphy.py || {
    echo "[警告] 部分测试失败，这可能是因为IDA未安装或路径未配置"
    echo "请编辑 config.yaml 文件设置正确的IDA路径"
}
echo ""

echo "========================================"
echo "安装完成！"
echo "========================================"
echo ""
echo "使用方法:"
echo "  ida-graphy --binary your_binary"
echo "  ida-graphy --binaries *.so"
echo "  ida-graphy --config config.yaml --binary app"
echo ""
echo "配置文件: config.yaml"
echo "文档: README.md, USAGE_EXAMPLES.md"
echo ""
