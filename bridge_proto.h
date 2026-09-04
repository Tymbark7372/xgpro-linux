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

#define T48_VID 0xA466
#define T48_PID 0x0A53

#define T48_EP1_OUT 0x01
#define T48_EP1_IN  0x81
#define T48_EP2_OUT 0x02
#define T48_EP2_IN  0x82

#define BRIDGE_TOKEN_LEN 32
#define BRIDGE_TOKEN_PATH "/tmp/.xgpro-bridge-token"

#endif
