#!/bin/bash
# run.sh — start asmdetect (UI + watcher + security check)
# Usage: bash run.sh
#        bash run.sh --no-watcher      (UI only)
#        bash run.sh --port 8502       (custom port)

PORT=8501
START_WATCHER=true

for arg in "$@"; do
    case $arg in
        --no-watcher) START_WATCHER=false ;;
        --port) PORT="$2"; shift ;;
    esac
done

echo ""
echo "=================================="
echo "  asmdetect — Starting"
echo "=================================="
echo ""
echo "  UI        : http://localhost:$PORT"
echo "  Watcher   : $START_WATCHER"
echo "  Press Ctrl+C to stop all."
echo ""

# Set Gmail credentials if .env exists
if [ -f ".env" ]; then
    echo "  Loading .env credentials..."
    export $(grep -v '^#' .env | xargs)
fi

# Start Streamlit UI (foreground — keeps terminal alive)
streamlit run app.py \
    --server.port $PORT \
    --server.headless true \
    --browser.gatherUsageStats false \
    --theme.base light
