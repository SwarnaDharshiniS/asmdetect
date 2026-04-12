#!/bin/bash
# setup.sh — install everything for asmdetect
# Run once: bash setup.sh

set -e
echo ""
echo "=================================="
echo "  asmdetect — Setup"
echo "=================================="
echo ""

# Python packages
echo "[1/3] Installing Python packages..."
pip install --upgrade pip --quiet
pip install \
    torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu --quiet
pip install \
    transformers datasets accelerate evaluate \
    scikit-learn pandas numpy tqdm \
    streamlit watchdog plyer \
    matplotlib seaborn \
    huggingface_hub --quiet

echo "      Done."

# System tools
echo "[2/3] Installing system tools..."
if command -v apt &> /dev/null; then
    sudo apt install -y binutils 2>/dev/null || echo "      (binutils already installed)"
fi
echo "      Done."

# Verify
echo "[3/3] Verifying installation..."
python -c "import torch; print(f'      torch     : {torch.__version__}')"
python -c "import transformers; print(f'      transformers: {transformers.__version__}')"
python -c "import streamlit; print(f'      streamlit : {streamlit.__version__}')"
python -c "import watchdog; print(f'      watchdog  : {watchdog.__version__}')"
objdump --version 2>/dev/null | head -1 | sed 's/^/      /' || echo "      objdump   : not found"

echo ""
echo "=================================="
echo "  Setup complete."
echo "  Now run:  bash run.sh"
echo "=================================="
echo ""
