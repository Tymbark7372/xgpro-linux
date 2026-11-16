#ifndef BRIDGE_PROTO_H
#define BRIDGE_PROTO_H

#include <stdint.h>

#define BRIDGE_PORT 7372

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

/* All XGecu programmers share the same vendor ID and differ only by PID. */
#define XGPRO_VID      0xA466
#define XGPRO_PID_T48  0x0A53   /* T48, T56, TL866II Plus */
#define XGPRO_PID_T76  0x1A86   /* T76 */

/* Bulk endpoint addresses are discovered from the device descriptor, because
 * they are not guaranteed to be identical across programmer models. */

#define BRIDGE_TOKEN_LEN 32
#define BRIDGE_TOKEN_PATH "/tmp/.xgpro-bridge-token"

#endif
