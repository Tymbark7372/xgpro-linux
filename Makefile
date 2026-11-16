CC_WIN = i686-w64-mingw32-gcc
CC = gcc
CFLAGS = -O2 -Wall

# Wine prefix holding the Xgpro install, and the subdirectory it lives in.
WINEPREFIX ?= $(HOME)/.wine-xgecu
APP_DIR ?= Xgpro
BINDIR ?= $(HOME)/.local/bin

all: winusb.dll bridge_daemon

winusb.dll: winusb_bridge.c winusb.def
	$(CC_WIN) $(CFLAGS) -shared -o $@ winusb_bridge.c winusb.def -lws2_32 -Wl,--enable-stdcall-fixup

bridge_daemon: bridge_daemon.c bridge_proto.h
	$(CC) $(CFLAGS) -o $@ bridge_daemon.c -lusb-1.0 -lpthread

clean:
	rm -f winusb.dll bridge_daemon

install: winusb.dll bridge_daemon
	install -Dm644 winusb.dll $(WINEPREFIX)/drive_c/$(APP_DIR)/winusb.dll
	install -Dm755 bridge_daemon $(BINDIR)/xgpro-bridge
	install -Dm755 xgpro.sh $(BINDIR)/xgpro
	@echo "Installed shim into $(WINEPREFIX)/drive_c/$(APP_DIR) and xgpro into $(BINDIR)"

.PHONY: all clean install
