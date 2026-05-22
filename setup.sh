#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "==> Creating virtual environment..."
python3 -m venv .venv

echo "==> Installing dependencies..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -r requirements.txt -q

echo "==> Downloading ONNX model from HuggingFace (q4f16, ~772 MB)..."
.venv/bin/python -c "
from privacy_engine import download_model
path = download_model()
print(f'    Model cached at: {path}')
"

echo ""
echo "==> Done! Run Re with:"
echo "    ./re              # interactive dashboard"
echo "    ./re run <cmd>    # wrap a command"
echo "    ./re env          # print env vars"
