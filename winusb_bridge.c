/*
 * WinUSB emulation layer for XGPro T48 under Wine.
 *
 * Replaces WINUSB.DLL, patches the IAT to intercept
 * SetupAPI device enumeration and CreateFileA for the T48.
 * Forwards USB I/O to bridge_daemon over TCP localhost.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


#define BRIDGE_PORT 7372
#define MAX_TRANSFER_LEN (16 * 1024 * 1024)
#define BRIDGE_TOKEN_LEN 32
#define BRIDGE_TOKEN_PATH_WINE "Z:\\tmp\\.xgpro-bridge-token"

enum bridge_cmd {
    CMD_OPEN = 1,
    CMD_CLOSE,
    CMD_READ_PIPE,
    CMD_WRITE_PIPE,
    CMD_SET_PIPE_POLICY,
    CMD_FLUSH_PIPE,
    CMD_ABORT_PIPE,
};

#pragma pack(push, 1)
typedef struct {
    uint8_t cmd;
    uint8_t pipe_id;
    uint32_t length;
} bridge_request_t;

typedef struct {
    int32_t status;
    uint32_t length;
} bridge_response_t;
#pragma pack(pop)

typedef struct {
    DWORD cbSize;
    GUID  InterfaceClassGuid;
    DWORD Flags;
    ULONG_PTR Reserved;
} MY_SP_DEVICE_INTERFACE_DATA;

typedef struct {
    DWORD cbSize;
    char  DevicePath[260];
} MY_SP_DEVICE_INTERFACE_DETAIL_DATA_A;

static const GUID XGPRO_GUID = {
    0xE7E8BA13, 0x2A81, 0x446E,
    {0xA1, 0x1E, 0x72, 0x39, 0x8F, 0xBD, 0xA8, 0x2F}
};

#define FAKE_HDEVINFO       ((HANDLE)(ULONG_PTR)0xDE000001)
#define FAKE_FILE_HANDLE    ((HANDLE)(ULONG_PTR)0xCA000001)
#define FAKE_WINUSB_HANDLE  ((void *)(ULONG_PTR)0xBE000001)
#define FAKE_DEV_PATH       "\\\\?\\USB#VID_A466&PID_0A53#T48#{e7e8ba13-2a81-446e-a11e-72398fbda82f}"

static SOCKET bridge_sock = INVALID_SOCKET;
static int wsa_inited = 0;
static CRITICAL_SECTION bridge_cs;
static int debug_verbose = -1;

static void bridge_disconnect(void) {
    if (bridge_sock != INVALID_SOCKET) {
        closesocket(bridge_sock);
        bridge_sock = INVALID_SOCKET;
    }
}

static int is_verbose(void) {
    if (debug_verbose < 0)
        debug_verbose = (getenv("XGPRO_DEBUG") != NULL);
    return debug_verbose;
}

static void dbg(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);
    fprintf(stderr, "[winusb] %s\n", buf);
}


static int bridge_send(const void *buf, int len);

static int bridge_connect(void) {
    if (bridge_sock != INVALID_SOCKET) return 0;

    if (!wsa_inited) {
        WSADATA wsa;
        int err = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (err != 0) {
            dbg("WSAStartup failed: %d", err);
            return -1;
        }
        wsa_inited = 1;
    }

    bridge_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bridge_sock == INVALID_SOCKET) {
        dbg("socket failed: %d", WSAGetLastError());
        return -1;
    }

    {
        int flag = 1;
        setsockopt(bridge_sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&flag, sizeof(flag));
    }

    {
        int bufsize = 256 * 1024;
        setsockopt(bridge_sock, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsize, sizeof(bufsize));
        setsockopt(bridge_sock, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize, sizeof(bufsize));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BRIDGE_PORT);
    addr.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */

    if (connect(bridge_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        dbg("connect to bridge failed: %d", WSAGetLastError());
        closesocket(bridge_sock);
        bridge_sock = INVALID_SOCKET;
        return -1;
    }

    dbg("Connected to bridge daemon on port %d", BRIDGE_PORT);

    {
        HANDLE hFile = CreateFileA(BRIDGE_TOKEN_PATH_WINE, GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            dbg("Failed to open token file: %s (err=%d)", BRIDGE_TOKEN_PATH_WINE, (int)GetLastError());
            closesocket(bridge_sock);
            bridge_sock = INVALID_SOCKET;
            return -1;
        }
        uint8_t token[BRIDGE_TOKEN_LEN];
        DWORD bytes_read = 0;
        BOOL ok = ReadFile(hFile, token, BRIDGE_TOKEN_LEN, &bytes_read, NULL);
        CloseHandle(hFile);
        if (!ok || bytes_read != BRIDGE_TOKEN_LEN) {
            dbg("Failed to read token file (read %u bytes)", (unsigned)bytes_read);
            closesocket(bridge_sock);
            bridge_sock = INVALID_SOCKET;
            return -1;
        }
        if (bridge_send(token, BRIDGE_TOKEN_LEN) < 0) {
            dbg("Failed to send auth token");
            bridge_disconnect();
            return -1;
        }
        dbg("Auth token sent to bridge daemon");
    }

    return 0;
}

static int bridge_send(const void *buf, int len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        int n = send(bridge_sock, p, len, 0);
        if (n <= 0) { bridge_disconnect(); return -1; }
        p += n;
        len -= n;
    }
    return 0;
}

static int bridge_recv(void *buf, int len) {
    char *p = (char *)buf;
    while (len > 0) {
        int n = recv(bridge_sock, p, len, 0);
        if (n <= 0) { bridge_disconnect(); return -1; }
        p += n;
        len -= n;
    }
    return 0;
}


static HANDLE WINAPI my_SetupDiGetClassDevsA(
    const GUID *ClassGuid, const char *Enumerator, HWND hwndParent, DWORD Flags)
{
    if (ClassGuid && memcmp(ClassGuid, &XGPRO_GUID, sizeof(GUID)) == 0) {
        dbg("SetupDiGetClassDevsA: matched XGPro GUID -> returning fake HDEVINFO");
        return FAKE_HDEVINFO;
    }
    dbg("SetupDiGetClassDevsA: unknown GUID, returning INVALID_HANDLE_VALUE");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return INVALID_HANDLE_VALUE;
}

static BOOL WINAPI my_SetupDiEnumDeviceInterfaces(
    HANDLE DeviceInfoSet, void *DeviceInfoData,
    const GUID *InterfaceClassGuid, DWORD MemberIndex,
    MY_SP_DEVICE_INTERFACE_DATA *DeviceInterfaceData)
{
    if (DeviceInfoSet == FAKE_HDEVINFO && MemberIndex == 0) {
        dbg("SetupDiEnumDeviceInterfaces: returning T48 at index 0");
        if (DeviceInterfaceData) {
            DeviceInterfaceData->cbSize = sizeof(MY_SP_DEVICE_INTERFACE_DATA);
            memcpy(&DeviceInterfaceData->InterfaceClassGuid, &XGPRO_GUID, sizeof(GUID));
            DeviceInterfaceData->Flags = 1;
            DeviceInterfaceData->Reserved = 0;
        }
        return TRUE;
    }
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

static BOOL WINAPI my_SetupDiGetDeviceInterfaceDetailA(
    HANDLE DeviceInfoSet, MY_SP_DEVICE_INTERFACE_DATA *InterfaceData,
    MY_SP_DEVICE_INTERFACE_DETAIL_DATA_A *DetailData, DWORD DetailDataSize,
    DWORD *RequiredSize, void *DeviceInfoData)
{
    DWORD needed = offsetof(MY_SP_DEVICE_INTERFACE_DETAIL_DATA_A, DevicePath) + strlen(FAKE_DEV_PATH) + 1;
    dbg("SetupDiGetDeviceInterfaceDetailA: needed=%u provided=%u", needed, DetailDataSize);

    if (RequiredSize) *RequiredSize = needed;

    if (!DetailData || DetailDataSize < needed) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    DetailData->cbSize = 5;
    strncpy(DetailData->DevicePath, FAKE_DEV_PATH, sizeof(DetailData->DevicePath) - 1);
    DetailData->DevicePath[sizeof(DetailData->DevicePath) - 1] = '\0';
    dbg("  -> path: %s", DetailData->DevicePath);
    return TRUE;
}

static BOOL WINAPI my_SetupDiDestroyDeviceInfoList(HANDLE DeviceInfoSet) {
    dbg("SetupDiDestroyDeviceInfoList");
    return TRUE;
}


typedef HANDLE (WINAPI *pfn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static pfn_CreateFileA orig_CreateFileA = NULL;

static HANDLE WINAPI my_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreation, DWORD dwFlags, HANDLE hTemplate)
{
    if (lpFileName) {
        char upper[512];
        strncpy(upper, lpFileName, sizeof(upper) - 1);
        upper[sizeof(upper) - 1] = '\0';
        _strupr(upper);
        if (strstr(upper, "VID_A466")) {
            dbg("CreateFileA: intercepted T48 device open -> fake handle");
            return FAKE_FILE_HANDLE;
        }
    }
    if (!orig_CreateFileA) {
        orig_CreateFileA = (pfn_CreateFileA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
    }
    if (!orig_CreateFileA) {
        SetLastError(ERROR_INTERNAL_ERROR);
        return INVALID_HANDLE_VALUE;
    }
    return orig_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSA, dwCreation, dwFlags, hTemplate);
}


static HINTERNET WINAPI my_InternetOpenA(
    LPCSTR lpszAgent, DWORD dwAccessType,
    LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
{
    if (is_verbose())
        dbg("InternetOpenA: stubbed");
    return (HINTERNET)(ULONG_PTR)0xDEAD0001;
}

static HINTERNET WINAPI my_InternetConnectA(
    HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort,
    LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService,
    DWORD dwFlags, DWORD_PTR dwContext)
{
    if (is_verbose())
        dbg("InternetConnectA: stubbed");
    SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
    return NULL;
}

static HINTERNET WINAPI my_InternetOpenUrlA(
    HINTERNET hInternet, LPCSTR lpszUrl,
    LPCSTR lpszHeaders, DWORD dwHeadersLength,
    DWORD dwFlags, DWORD_PTR dwContext)
{
    if (is_verbose())
        dbg("InternetOpenUrlA: stubbed");
    SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
    return NULL;
}

static HINTERNET WINAPI my_HttpOpenRequestA(
    HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName,
    LPCSTR lpszVersion, LPCSTR lpszReferrer,
    LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
    if (is_verbose())
        dbg("HttpOpenRequestA: stubbed");
    SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
    return NULL;
}

static BOOL WINAPI my_HttpSendRequestA(
    HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength)
{
    if (is_verbose())
        dbg("HttpSendRequestA: stubbed");
    SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
    return FALSE;
}

static BOOL WINAPI my_InternetCloseHandle(HINTERNET hInternet)
{
    return TRUE;
}


static void patch_iat_entry(HMODULE module, const char *target_dll,
                            const char *func_name, void *new_func, void **orig_func)
{
    ULONG_PTR base = (ULONG_PTR)module;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (import_rva == 0 || import_size == 0)
        return;

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + import_rva);

    for (; imp->Name; imp++) {
        const char *dll_name = (const char *)(base + imp->Name);
        if (_stricmp(dll_name, target_dll) != 0) continue;

        IMAGE_THUNK_DATA *orig_thunk = imp->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk)
            : (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        IMAGE_THUNK_DATA *iat_thunk  = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);

        for (; orig_thunk->u1.AddressOfData; orig_thunk++, iat_thunk++) {
            if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;

            IMAGE_IMPORT_BY_NAME *import = (IMAGE_IMPORT_BY_NAME *)(base + orig_thunk->u1.AddressOfData);
            if (strcmp((const char *)import->Name, func_name) != 0) continue;

            DWORD old_protect;
            VirtualProtect(&iat_thunk->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &old_protect);

            if (orig_func) *orig_func = (void *)iat_thunk->u1.Function;
            iat_thunk->u1.Function = (ULONG_PTR)new_func;

            VirtualProtect(&iat_thunk->u1.Function, sizeof(ULONG_PTR), old_protect, &old_protect);
            return;
        }
    }
}

static void install_hooks(void) {
    HMODULE exe = GetModuleHandleA(NULL);

    orig_CreateFileA = (pfn_CreateFileA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");

    patch_iat_entry(exe, "SETUPAPI.dll", "SetupDiGetClassDevsA",
                    my_SetupDiGetClassDevsA, NULL);
    patch_iat_entry(exe, "SETUPAPI.dll", "SetupDiEnumDeviceInterfaces",
                    my_SetupDiEnumDeviceInterfaces, NULL);
    patch_iat_entry(exe, "SETUPAPI.dll", "SetupDiGetDeviceInterfaceDetailA",
                    my_SetupDiGetDeviceInterfaceDetailA, NULL);
    patch_iat_entry(exe, "SETUPAPI.dll", "SetupDiDestroyDeviceInfoList",
                    my_SetupDiDestroyDeviceInfoList, NULL);

    patch_iat_entry(exe, "KERNEL32.dll", "CreateFileA",
                    my_CreateFileA, (void **)&orig_CreateFileA);

    patch_iat_entry(exe, "WININET.dll", "InternetOpenA",
                    my_InternetOpenA, NULL);
    patch_iat_entry(exe, "WININET.dll", "InternetConnectA",
                    my_InternetConnectA, NULL);
    patch_iat_entry(exe, "WININET.dll", "InternetOpenUrlA",
                    my_InternetOpenUrlA, NULL);
    patch_iat_entry(exe, "WININET.dll", "HttpOpenRequestA",
                    my_HttpOpenRequestA, NULL);
    patch_iat_entry(exe, "WININET.dll", "HttpSendRequestA",
                    my_HttpSendRequestA, NULL);
    patch_iat_entry(exe, "WININET.dll", "InternetCloseHandle",
                    my_InternetCloseHandle, NULL);
}


__declspec(dllexport) BOOL __stdcall WinUsb_Initialize(
    HANDLE DeviceHandle, void **InterfaceHandle)
{
    dbg("WinUsb_Initialize");

    EnterCriticalSection(&bridge_cs);
    if (bridge_connect() < 0) {
        dbg("  -> failed to connect to bridge");
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_request_t req = { CMD_OPEN, 0, 0 };
    if (bridge_send(&req, sizeof(req)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_response_t resp;
    if (bridge_recv(&resp, sizeof(resp)) < 0 || resp.status != 0) {
        dbg("  -> bridge open failed: %d", resp.status);
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    LeaveCriticalSection(&bridge_cs);

    if (InterfaceHandle) *InterfaceHandle = FAKE_WINUSB_HANDLE;
    dbg("  -> success");
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_Free(void *InterfaceHandle) {
    dbg("WinUsb_Free");
    EnterCriticalSection(&bridge_cs);
    if (bridge_sock != INVALID_SOCKET) {
        bridge_request_t req = { CMD_CLOSE, 0, 0 };
        bridge_send(&req, sizeof(req));
        bridge_response_t resp;
        bridge_recv(&resp, sizeof(resp));
        closesocket(bridge_sock);
        bridge_sock = INVALID_SOCKET;
    }
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_WritePipe(
    void *InterfaceHandle, UCHAR PipeID,
    PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred, void *Overlapped)
{
    if (is_verbose()) {
        char hex[128] = {0};
        ULONG i, off = 0;
        for (i = 0; i < BufferLength && i < 32 && off < sizeof(hex) - 4; i++)
            off += snprintf(hex + off, sizeof(hex) - off, "%02x ", Buffer ? Buffer[i] : 0);
        dbg("WinUsb_WritePipe pipe=0x%02x len=%u data=%s", PipeID, BufferLength, hex);
    }

    EnterCriticalSection(&bridge_cs);
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_request_t req = { CMD_WRITE_PIPE, PipeID, BufferLength };
    if (bridge_send(&req, sizeof(req)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    if (BufferLength > 0 && bridge_send(Buffer, BufferLength) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_response_t resp;
    if (bridge_recv(&resp, sizeof(resp)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    LeaveCriticalSection(&bridge_cs);

    if (LengthTransferred) *LengthTransferred = resp.length;
    if (resp.status != 0) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_ReadPipe(
    void *InterfaceHandle, UCHAR PipeID,
    PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred, void *Overlapped)
{
    if (is_verbose())
        dbg("WinUsb_ReadPipe pipe=0x%02x len=%u", PipeID, BufferLength);

    EnterCriticalSection(&bridge_cs);
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_request_t req = { CMD_READ_PIPE, PipeID, BufferLength };
    if (bridge_send(&req, sizeof(req)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    bridge_response_t resp;
    if (bridge_recv(&resp, sizeof(resp)) < 0) {
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    if (resp.length > MAX_TRANSFER_LEN) {
        dbg("WinUsb_ReadPipe: resp.length %u exceeds max, disconnecting", resp.length);
        bridge_disconnect();
        LeaveCriticalSection(&bridge_cs);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    uint32_t total_from_daemon = resp.length;
    if (resp.length > BufferLength) {
        dbg("WARNING: daemon sent %u bytes but buffer only holds %u", total_from_daemon, BufferLength);
        resp.length = BufferLength;
    }

    if (resp.length > 0 && Buffer) {
        if (bridge_recv(Buffer, resp.length) < 0) {
            LeaveCriticalSection(&bridge_cs);
            SetLastError(ERROR_GEN_FAILURE);
            return FALSE;
        }
    }

    if (total_from_daemon > resp.length) {
        uint32_t remain = total_from_daemon - resp.length;
        char discard[4096];
        while (remain > 0) {
            uint32_t chunk = remain < sizeof(discard) ? remain : sizeof(discard);
            if (bridge_recv(discard, chunk) < 0) {
                LeaveCriticalSection(&bridge_cs);
                SetLastError(ERROR_GEN_FAILURE);
                return FALSE;
            }
            remain -= chunk;
        }
    }
    LeaveCriticalSection(&bridge_cs);

    if (LengthTransferred) *LengthTransferred = resp.length;
    if (resp.status != 0) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_SetPipePolicy(
    void *InterfaceHandle, UCHAR PipeID, ULONG PolicyType, ULONG ValueLength, void *Value)
{
    if (is_verbose())
        dbg("WinUsb_SetPipePolicy pipe=0x%02x policy=%u", PipeID, PolicyType);

    EnterCriticalSection(&bridge_cs);
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        return TRUE;
    }
    bridge_request_t req = { CMD_SET_PIPE_POLICY, PipeID, PolicyType };
    bridge_send(&req, sizeof(req));
    bridge_response_t resp;
    bridge_recv(&resp, sizeof(resp));
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_FlushPipe(void *InterfaceHandle, UCHAR PipeID) {
    if (is_verbose())
        dbg("WinUsb_FlushPipe 0x%02x", PipeID);

    EnterCriticalSection(&bridge_cs);
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        return TRUE;
    }
    bridge_request_t req = { CMD_FLUSH_PIPE, PipeID, 0 };
    bridge_send(&req, sizeof(req));
    bridge_response_t resp;
    bridge_recv(&resp, sizeof(resp));
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_AbortPipe(void *InterfaceHandle, UCHAR PipeID) {
    if (is_verbose())
        dbg("WinUsb_AbortPipe 0x%02x", PipeID);

    EnterCriticalSection(&bridge_cs);
    if (bridge_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&bridge_cs);
        return TRUE;
    }
    bridge_request_t req = { CMD_ABORT_PIPE, PipeID, 0 };
    bridge_send(&req, sizeof(req));
    bridge_response_t resp;
    bridge_recv(&resp, sizeof(resp));
    LeaveCriticalSection(&bridge_cs);
    return TRUE;
}

typedef struct {
    UCHAR bLength;
    UCHAR bDescriptorType;
    UCHAR bInterfaceNumber;
    UCHAR bAlternateSetting;
    UCHAR bNumEndpoints;
    UCHAR bInterfaceClass;
    UCHAR bInterfaceSubClass;
    UCHAR bInterfaceProtocol;
    UCHAR iInterface;
} USB_INTERFACE_DESCRIPTOR;

typedef struct {
    ULONG PipeType;
    UCHAR PipeId;
    USHORT MaximumPacketSize;
    UCHAR Interval;
} WINUSB_PIPE_INFORMATION;

__declspec(dllexport) BOOL __stdcall WinUsb_QueryInterfaceSettings(
    void *InterfaceHandle, UCHAR AlternateInterfaceNumber, USB_INTERFACE_DESCRIPTOR *desc)
{
    dbg("WinUsb_QueryInterfaceSettings alt=%u", AlternateInterfaceNumber);
    if (AlternateInterfaceNumber != 0 || !desc) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return FALSE;
    }
    desc->bLength = 9;
    desc->bDescriptorType = 4;
    desc->bInterfaceNumber = 0;
    desc->bAlternateSetting = 0;
    desc->bNumEndpoints = 4;
    desc->bInterfaceClass = 0xFF;
    desc->bInterfaceSubClass = 0xFF;
    desc->bInterfaceProtocol = 0xFF;
    desc->iInterface = 0;
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_QueryPipe(
    void *InterfaceHandle, UCHAR AlternateInterfaceNumber, UCHAR PipeIndex,
    WINUSB_PIPE_INFORMATION *PipeInfo)
{
    dbg("WinUsb_QueryPipe alt=%u index=%u", AlternateInterfaceNumber, PipeIndex);
    if (!PipeInfo || AlternateInterfaceNumber != 0) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return FALSE;
    }
    switch (PipeIndex) {
    case 0:
        PipeInfo->PipeType = 3;
        PipeInfo->PipeId = 0x01;
        PipeInfo->MaximumPacketSize = 512;
        PipeInfo->Interval = 0;
        return TRUE;
    case 1:
        PipeInfo->PipeType = 3;
        PipeInfo->PipeId = 0x81;
        PipeInfo->MaximumPacketSize = 512;
        PipeInfo->Interval = 0;
        return TRUE;
    case 2:
        PipeInfo->PipeType = 3;
        PipeInfo->PipeId = 0x02;
        PipeInfo->MaximumPacketSize = 512;
        PipeInfo->Interval = 0;
        return TRUE;
    case 3:
        PipeInfo->PipeType = 3;
        PipeInfo->PipeId = 0x82;
        PipeInfo->MaximumPacketSize = 512;
        PipeInfo->Interval = 0;
        return TRUE;
    default:
        SetLastError(ERROR_NO_MORE_ITEMS);
        return FALSE;
    }
}

__declspec(dllexport) BOOL __stdcall WinUsb_QueryDeviceInformation(
    void *InterfaceHandle, ULONG InformationType, PULONG BufferLength, void *Buffer)
{
    dbg("WinUsb_QueryDeviceInformation type=%u", InformationType);
    if (InformationType == 1 && Buffer && BufferLength && *BufferLength >= 1) {
        *(UCHAR *)Buffer = 3;
        *BufferLength = 1;
        return TRUE;
    }
    return FALSE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_GetDescriptor(
    void *h, UCHAR DescriptorType, UCHAR Index, USHORT LanguageID,
    PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred)
{
    dbg("WinUsb_GetDescriptor type=%u index=%u lang=%u", DescriptorType, Index, LanguageID);
    SetLastError(ERROR_GEN_FAILURE);
    return FALSE;
}

__declspec(dllexport) BOOL __stdcall WinUsb_ControlTransfer(void *h, void *sp, UCHAR *buf, ULONG len, PULONG xfer, void *ol) { dbg("WinUsb_ControlTransfer (stub)"); return FALSE; }
__declspec(dllexport) BOOL __stdcall WinUsb_GetAssociatedInterface(void *h, UCHAR idx, void **ah) { dbg("WinUsb_GetAssociatedInterface idx=%u", idx); SetLastError(ERROR_NO_MORE_ITEMS); return FALSE; }
__declspec(dllexport) BOOL __stdcall WinUsb_GetCurrentAlternateSetting(void *h, PUCHAR alt) { dbg("WinUsb_GetCurrentAlternateSetting"); if (alt) *alt = 0; return TRUE; }
__declspec(dllexport) BOOL __stdcall WinUsb_GetOverlappedResult(void *h, void *ol, PULONG xfer, BOOL wait) { dbg("WinUsb_GetOverlappedResult (stub)"); return FALSE; }
__declspec(dllexport) BOOL __stdcall WinUsb_GetPipePolicy(void *h, UCHAR pid, ULONG pt, PULONG vl, void *v) { dbg("WinUsb_GetPipePolicy pipe=0x%02x policy=%u", pid, pt); return TRUE; }
__declspec(dllexport) BOOL __stdcall WinUsb_GetPowerPolicy(void *h, ULONG pt, PULONG vl, void *v) { dbg("WinUsb_GetPowerPolicy (stub)"); return FALSE; }
__declspec(dllexport) BOOL __stdcall WinUsb_ResetPipe(void *h, UCHAR pid) { dbg("WinUsb_ResetPipe pipe=0x%02x", pid); return TRUE; }
__declspec(dllexport) BOOL __stdcall WinUsb_SetCurrentAlternateSetting(void *h, UCHAR alt) { dbg("WinUsb_SetCurrentAlternateSetting alt=%u", alt); return TRUE; }
__declspec(dllexport) BOOL __stdcall WinUsb_SetPowerPolicy(void *h, ULONG pt, ULONG vl, void *v) { dbg("WinUsb_SetPowerPolicy (stub)"); return FALSE; }

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&bridge_cs);
        install_hooks();
    }
    if (fdwReason == DLL_PROCESS_DETACH) {
        DeleteCriticalSection(&bridge_cs);
    }
    return TRUE;
}
