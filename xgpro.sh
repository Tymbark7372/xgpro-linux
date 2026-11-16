#!/bin/bash
# Launch Xgpro under Wine with the USB bridge.
#
#   ./xgpro.sh                     Xgpro.exe       (T48 / T56 / TL866II Plus)
#   XGPRO_APP=Xgpro_T76 ./xgpro.sh Xgpro_T76.exe  (T76)
#
# Environment:
#   WINEPREFIX   Wine prefix (default: ~/.wine-xgecu)
#   XGPRO_APP   subdirectory inside the prefix (default: Xgpro)
#   XGPRO_EXE   executable name (default: Xgpro.exe)
#   XGPRO_DEBUG set to 1 for verbose USB/shim logging

set -u

WINEPREFIX="${WINEPREFIX:-$HOME/.wine-xgecu}"
APP_DIR="${XGPRO_APP:-Xgpro}"
TARGET_EXE="${XGPRO_EXE:-Xgpro.exe}"
BROKER="${XGPRO_BRIDGE:-xgpro-bridge}"

if ! pgrep -x "$(basename "$BROKER")" >/dev/null 2>&1; then
    echo "Starting USB bridge daemon..."
    "$BROKER" &
    sleep 1
fi

WINEPREFIX="$WINEPREFIX" \
WINEDLLOVERRIDES="winusb=n" \
wine "$WINEPREFIX/drive_c/$APP_DIR/$TARGET_EXE" 2>&1 \
    | grep --line-buffered '\[winusb\]\|\[bridge\]' &
