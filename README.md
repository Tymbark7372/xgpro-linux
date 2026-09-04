# xgpro-linux

Run XGPro natively on Linux through Wine, with full USB support.

## What this is

XGecu only provides Windows software for their programmers. Existing Linux solutions either don't work reliably (Wine USB passthrough) or have limited chip support (minipro). This project replaces Wine's broken WinUSB layer with a custom implementation that talks directly to the hardware through libusb.

## How it works

Two components:

- **bridge_daemon**: Native Linux process that claims the USB device via libusb and listens on localhost. Proxies bulk USB transfers over TCP.
- **winusb_bridge.c** (compiled to winusb.dll): Replaces WinUSB.dll inside Wine. Patches XGPro's import table at runtime to intercept device enumeration and USB I/O, then forwards everything to the daemon over TCP.

XGPro thinks it's talking to a real Windows USB device. The programmer thinks it's talking to the Windows driver. Neither side knows anything unusual is happening.

## Requirements

- Wine (tested with wine-10.0)
- libusb-1.0 (`apt install libusb-1.0-0-dev`)
- MinGW cross compiler (`apt install gcc-mingw-w64-i686`)
- XGPro installed in a Wine prefix at `~/.wine-xgpro/drive_c/Xgpro/`
- udev rule for the programmer (VID a466, PID 0a53)
- the programmer of course.

## Build

```
make
```

## Install

```
sudo make install
```

## udev rule

Create `/etc/udev/rules.d/99-xgecu.rules`:

```
SUBSYSTEM=="usb", ATTR{idVendor}=="a466", ATTR{idProduct}=="0a53", MODE="0666", GROUP="plugdev"
```

Then reload:

```
sudo udevadm control --reload-rules && sudo udevadm trigger
```

## Usage

```
~/xgpro.sh
```

Or manually:

```
xgpro-bridge &
WINEPREFIX=~/.wine-xgpro WINEDLLOVERRIDES="winusb=n" wine ~/.wine-xgpro/drive_c/Xgpro/Xgpro.exe
```

For debug output:

```
xgpro-bridge -v &
XGPRO_DEBUG=1 WINEPREFIX=~/.wine-xgpro WINEDLLOVERRIDES="winusb=n" wine ~/.wine-xgpro/drive_c/Xgpro/Xgpro.exe
```

## What works

- Everything just like on the official software.
- Flash read and write
- Verify
- Erase
- All chip types supported by XGPro

## Compatibility

The T48, T56, and TL866II Plus all share the same USB VID/PID (a466:0a53) and use XGPro, so the bridge should work with all three. The T76 uses USB 3.0 and may need a different PID (untested).

## Tested with

- XGPro v13.16
- XGecu T48 (TL866II-3G)
- Wine 10.0 on Kali Linux
- 16Mbit SPI flash (MX25L12805D), full read in ~42 seconds

## License

MIT - do whatever just put my name on it.

made by [Tymbark7372](https://github.com/Tymbark7372)
