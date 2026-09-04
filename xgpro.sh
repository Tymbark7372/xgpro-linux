#!/bin/bash
# Launch XGPro T48 under Wine with USB bridge

# Start bridge daemon if not running
if ! pgrep -x xgpro-bridge >/dev/null 2>&1; then
    echo "Starting USB bridge daemon..."
    xgpro-bridge &
    sleep 1
fi

WINEPREFIX=~/.wine-xgpro \
WINEDLLOVERRIDES="winusb=n" \
wine ~/.wine-xgpro/drive_c/Xgpro/Xgpro.exe 2>&1 | grep --line-buffered '\[winusb\]\|\[bridge\]' &
