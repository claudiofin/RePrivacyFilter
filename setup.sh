#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "==> Creating virtual environment..."
python3 -m venv .venv

echo "==> Installing dependencies..."
.venv/bin/pip install -r requirements.txt -q

ONNX_PATH="$HOME/privacy-filter/PrivacyFilter.onnx"
ONNX_DATA="$HOME/privacy-filter/PrivacyFilter.onnx.data"

if [ ! -f "$ONNX_PATH" ] || [ ! -f "$ONNX_DATA" ]; then
    echo ""
    echo "WARNING: ONNX model not found at $ONNX_PATH"
    echo "You need the model files to run Lei."
    echo "See README for instructions on how to export them."
    echo ""
else
    echo "==> Model found at $ONNX_PATH ($(du -sh "$ONNX_DATA" | cut -f1) weights)"
fi

echo ""
echo "==> Done! Run Lei with:"
echo "    ./lei              # interactive dashboard"
echo "    ./lei run <cmd>    # wrap a command"
echo "    ./lei env          # print env vars"
