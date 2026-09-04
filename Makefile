CC_WIN = i686-w64-mingw32-gcc
CC = gcc
CFLAGS = -O2 -Wall

all: winusb.dll bridge_daemon

winusb.dll: winusb_bridge.c winusb.def
	$(CC_WIN) $(CFLAGS) -shared -o $@ winusb_bridge.c winusb.def -lws2_32 -Wl,--enable-stdcall-fixup

bridge_daemon: bridge_daemon.c bridge_proto.h
	$(CC) $(CFLAGS) -o $@ bridge_daemon.c -lusb-1.0

clean:
	rm -f winusb.dll bridge_daemon

install: winusb.dll bridge_daemon
	cp winusb.dll $(HOME)/.wine-xgpro/drive_c/Xgpro/winusb.dll
	cp bridge_daemon /usr/local/bin/xgpro-bridge

.PHONY: all clean install
