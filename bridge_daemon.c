#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <libusb-1.0/libusb.h>
#include "bridge_proto.h"

static int verbose = 0;

#define MAX_TRANSFER_LEN (16 * 1024 * 1024)
#define MAX_BULK_EPS 16

/* Programmers are told apart by PID only; the VID is shared. */
static const struct xgpro_model {
    uint16_t pid;
    const char *name;
} XGPRO_MODELS[] = {
    { XGPRO_PID_T48, "T48/T56/TL866II Plus" },
    { XGPRO_PID_T76, "T76" },
};
#define XGPRO_MODEL_COUNT ((int)(sizeof(XGPRO_MODELS) / sizeof(XGPRO_MODELS[0])))

static libusb_device_handle *dev_handle = NULL;
static libusb_context *ctx = NULL;
static volatile int running = 1;
static int kernel_driver_detached = 0;
static uint8_t auth_token[BRIDGE_TOKEN_LEN];
static uint8_t bulk_eps[MAX_BULK_EPS];
static int bulk_ep_count = 0;
static const char *model_name = NULL;

static void sig_handler(int sig) {
    (void)sig;
    running = 0;
}

static int valid_pipe_id(uint8_t pipe_id) {
    for (int i = 0; i < bulk_ep_count; i++) {
        if (bulk_eps[i] == pipe_id) return 1;
    }
    return 0;
}

/* Endpoint addresses differ between programmer generations, so read them
 * from the active configuration instead of assuming the TL866 layout. */
static int discover_bulk_endpoints(void) {
    struct libusb_config_descriptor *config = NULL;
    const struct libusb_interface *iface;
    const struct libusb_interface_descriptor *alt;

    bulk_ep_count = 0;

    if (libusb_get_active_config_descriptor(libusb_get_device(dev_handle), &config) < 0 ||
        !config || config->bNumInterfaces < 1) {
        fprintf(stderr, "[bridge] Warning: cannot read configuration descriptor\n");
        return -1;
    }

    iface = &config->interface[0];
    if (iface->num_altsetting < 1) {
        libusb_free_config_descriptor(config);
        return -1;
    }
    alt = &iface->altsetting[0];

    for (int i = 0; i < alt->bNumEndpoints; i++) {
        const struct libusb_endpoint_descriptor *ep = &alt->endpoint[i];

        if ((ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_TRANSFER_TYPE_BULK)
            continue;
        if (bulk_ep_count >= MAX_BULK_EPS)
            break;

        bulk_eps[bulk_ep_count++] = ep->bEndpointAddress;
        if (verbose) {
            fprintf(stderr, "[bridge] Bulk endpoint 0x%02x (%s, max packet %u)\n",
                    ep->bEndpointAddress,
                    (ep->bEndpointAddress & LIBUSB_ENDPOINT_IN) ? "IN" : "OUT",
                    ep->wMaxPacketSize);
        }
    }

    libusb_free_config_descriptor(config);

    if (bulk_ep_count == 0) {
        fprintf(stderr, "[bridge] Warning: no bulk endpoints on interface 0\n");
        return -1;
    }
    return 0;
}

static int generate_token(void) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("[bridge] open /dev/urandom");
        return -1;
    }
    ssize_t n = read(fd, auth_token, BRIDGE_TOKEN_LEN);
    close(fd);
    if (n != BRIDGE_TOKEN_LEN) {
        fprintf(stderr, "[bridge] Failed to read random bytes\n");
        return -1;
    }

    unlink(BRIDGE_TOKEN_PATH);
    fd = open(BRIDGE_TOKEN_PATH, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror("[bridge] create token file");
        return -1;
    }
    n = write(fd, auth_token, BRIDGE_TOKEN_LEN);
    close(fd);
    if (n != BRIDGE_TOKEN_LEN) {
        fprintf(stderr, "[bridge] Failed to write token file\n");
        unlink(BRIDGE_TOKEN_PATH);
        return -1;
    }

    fprintf(stderr, "[bridge] Auth token written to %s\n", BRIDGE_TOKEN_PATH);
    return 0;
}

static int open_device(void) {
    if (dev_handle) return 0;

    for (int i = 0; i < XGPRO_MODEL_COUNT && !dev_handle; i++) {
        dev_handle = libusb_open_device_with_vid_pid(ctx, XGPRO_VID, XGPRO_MODELS[i].pid);
        if (dev_handle) model_name = XGPRO_MODELS[i].name;
    }
    if (!dev_handle) {
        fprintf(stderr, "[bridge] No XGecu programmer found (VID=%04x PIDs:", XGPRO_VID);
        for (int i = 0; i < XGPRO_MODEL_COUNT; i++)
            fprintf(stderr, " %04x", XGPRO_MODELS[i].pid);
        fprintf(stderr, ")\n");
        return -1;
    }
    fprintf(stderr, "[bridge] Found %s\n", model_name);

    if (libusb_kernel_driver_active(dev_handle, 0) == 1) {
        int dr = libusb_detach_kernel_driver(dev_handle, 0);
        if (dr == 0) {
            kernel_driver_detached = 1;
        } else {
            fprintf(stderr, "[bridge] Warning: detach kernel driver failed: %s\n", libusb_error_name(dr));
        }
    }

    /* A redundant SET_CONFIGURATION wedges the CH569 in the T76: the next
     * bulk transfer fails with LIBUSB_ERROR_IO and only a power cycle
     * clears it. The device is already configured, so leave it alone. */
    int cfg = 0;
    if (libusb_get_configuration(dev_handle, &cfg) < 0 || cfg <= 0) {
        int r = libusb_set_configuration(dev_handle, 1);
        if (r < 0) {
            fprintf(stderr, "[bridge] Failed to set configuration: %s\n", libusb_error_name(r));
            libusb_close(dev_handle);
            dev_handle = NULL;
            kernel_driver_detached = 0;
            return -1;
        }
    } else if (verbose) {
        fprintf(stderr, "[bridge] Already configured (value %d), not re-setting\n", cfg);
    }

    int r = libusb_claim_interface(dev_handle, 0);
    if (r < 0) {
        fprintf(stderr, "[bridge] Failed to claim interface: %s\n", libusb_error_name(r));
        libusb_close(dev_handle);
        dev_handle = NULL;
        kernel_driver_detached = 0;
        return -1;
    }

    if (discover_bulk_endpoints() < 0) {
        fprintf(stderr, "[bridge] Falling back to TL866 endpoint layout\n");
        bulk_eps[0] = 0x01;
        bulk_eps[1] = 0x81;
        bulk_eps[2] = 0x02;
        bulk_eps[3] = 0x82;
        bulk_ep_count = 4;
    }

    /* No SET_INTERFACE / CLEAR_HALT here on purpose. The device is already
     * on alt setting 0 with no halted endpoints, and issuing those requests
     * to the CH569 in the T76 wedges it the same way a redundant
     * SET_CONFIGURATION does: the next bulk transfer fails with
     * LIBUSB_ERROR_IO and needs a power cycle. minipro never sends them
     * either. Endpoints are only cleared after a transfer actually fails. */

    fprintf(stderr, "[bridge] %s opened, configured, and interface claimed\n", model_name);
    return 0;
}

static void reset_endpoint(uint8_t ep) {
    if (!dev_handle) return;
    libusb_clear_halt(dev_handle, ep);
}

static void close_device(void) {
    if (dev_handle) {
        libusb_release_interface(dev_handle, 0);
        if (kernel_driver_detached) {
            libusb_attach_kernel_driver(dev_handle, 0);
            kernel_driver_detached = 0;
        }
        libusb_close(dev_handle);
        dev_handle = NULL;
        fprintf(stderr, "[bridge] Programmer closed\n");
    }
}

static int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int authenticate_client(int client_fd) {
    uint8_t client_token[BRIDGE_TOKEN_LEN];
    if (recv_all(client_fd, client_token, BRIDGE_TOKEN_LEN) < 0) {
        fprintf(stderr, "[bridge] Auth failed: could not read token from client\n");
        return -1;
    }
    if (memcmp(client_token, auth_token, BRIDGE_TOKEN_LEN) != 0) {
        fprintf(stderr, "[bridge] Auth failed: invalid token\n");
        return -1;
    }
    fprintf(stderr, "[bridge] Client authenticated\n");
    return 0;
}

static void handle_client(int client_fd) {
    fprintf(stderr, "[bridge] XGPro connected\n");

    if (authenticate_client(client_fd) < 0) {
        fprintf(stderr, "[bridge] Rejecting unauthenticated client\n");
        close(client_fd);
        return;
    }

    while (running) {
        bridge_request_t req;
        if (recv_all(client_fd, &req, sizeof(req)) < 0) break;

        bridge_response_t resp = {0, 0};
        uint8_t *data_buf = NULL;

        switch (req.cmd) {
        case CMD_OPEN:
            resp.status = open_device();
            if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
            break;

        case CMD_CLOSE:
            close_device();
            resp.status = 0;
            if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
            break;

        case CMD_WRITE_PIPE: {
            if (!valid_pipe_id(req.pipe_id) || (req.pipe_id & 0x80)) {
                fprintf(stderr, "[bridge] CMD_WRITE_PIPE: rejecting invalid endpoint 0x%02x\n", req.pipe_id);
                uint8_t discard_ep[4096];
                uint32_t rem = req.length;
                while (rem > 0) {
                    uint32_t chunk = rem < sizeof(discard_ep) ? rem : sizeof(discard_ep);
                    if (recv_all(client_fd, discard_ep, chunk) < 0) goto disconnect;
                    rem -= chunk;
                }
                resp.status = -1;
                if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
                break;
            }
            if (req.length > MAX_TRANSFER_LEN) {
                uint8_t discard[4096];
                uint32_t remain = req.length;
                while (remain > 0) {
                    uint32_t chunk = remain < sizeof(discard) ? remain : sizeof(discard);
                    if (recv_all(client_fd, discard, chunk) < 0) goto disconnect;
                    remain -= chunk;
                }
                resp.status = -1;
                if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
                break;
            }
            if (req.length > 0) {
                data_buf = malloc(req.length);
                if (!data_buf) {
                    resp.status = -1;
                    send_all(client_fd, &resp, sizeof(resp));
                    goto disconnect;
                }
                if (recv_all(client_fd, data_buf, req.length) < 0) {
                    free(data_buf);
                    goto disconnect;
                }
            }
            if (!dev_handle) {
                resp.status = -1;
            } else {
                int transferred = 0;
                if (verbose) {
                    fprintf(stderr, "[bridge] WRITE ep=0x%02x len=%u data=", req.pipe_id, req.length);
                    for (uint32_t i = 0; i < req.length && i < 32; i++)
                        fprintf(stderr, "%02x ", data_buf[i]);
                    fprintf(stderr, "\n");
                }
                int r = libusb_bulk_transfer(dev_handle, req.pipe_id,
                                             data_buf, req.length,
                                             &transferred, 120000);
                if (r == 0 && transferred != (int)req.length) {
                    /* Never report a short write as success: a truncated
                     * chunk inside a firmware image or chip payload would
                     * corrupt the device silently. */
                    fprintf(stderr, "[bridge] WRITE ep=0x%02x short transfer %d/%u\n",
                            req.pipe_id, transferred, req.length);
                    r = LIBUSB_ERROR_IO;
                }
                resp.status = (r == 0) ? 0 : r;
                resp.length = transferred;
                if (r != 0) {
                    if (verbose)
                        fprintf(stderr, "[bridge] WRITE error: %s, transferred=%d\n", libusb_error_name(r), transferred);
                    reset_endpoint(req.pipe_id);
                }
            }
            if (send_all(client_fd, &resp, sizeof(resp)) < 0) {
                free(data_buf);
                goto disconnect;
            }
            free(data_buf);
            break;
        }

        case CMD_READ_PIPE: {
            if (!valid_pipe_id(req.pipe_id) || !(req.pipe_id & 0x80)) {
                fprintf(stderr, "[bridge] CMD_READ_PIPE: rejecting invalid endpoint 0x%02x\n", req.pipe_id);
                resp.status = -1;
                if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
                break;
            }
            if (req.length == 0) {
                resp.status = 0;
                resp.length = 0;
                if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
                break;
            }
            if (req.length > MAX_TRANSFER_LEN) {
                resp.status = -1;
                if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
                break;
            }
            data_buf = malloc(req.length);
            if (!data_buf) {
                resp.status = -1;
                if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
                break;
            }
            memset(data_buf, 0, req.length);
            if (!dev_handle) {
                resp.status = -1;
                if (send_all(client_fd, &resp, sizeof(resp)) < 0) {
                    free(data_buf);
                    goto disconnect;
                }
                free(data_buf);
                break;
            }
            int transferred = 0;
            int r = libusb_bulk_transfer(dev_handle, req.pipe_id,
                                         data_buf, req.length,
                                         &transferred, 120000);
            resp.status = (r == 0) ? 0 : r;
            if (r != 0) {
                if (verbose)
                    fprintf(stderr, "[bridge] READ error: %s, transferred=%d\n", libusb_error_name(r), transferred);
                reset_endpoint(req.pipe_id);
                resp.length = 0;
            } else {
                resp.length = transferred;
                if (verbose) {
                    fprintf(stderr, "[bridge] READ ep=0x%02x len=%d data=", req.pipe_id, transferred);
                    for (int i = 0; i < transferred && i < 32; i++)
                        fprintf(stderr, "%02x ", data_buf[i]);
                    fprintf(stderr, "\n");
                }
            }
            if (send_all(client_fd, &resp, sizeof(resp)) < 0) {
                free(data_buf);
                goto disconnect;
            }
            if (resp.length > 0 && send_all(client_fd, data_buf, resp.length) < 0) {
                free(data_buf);
                goto disconnect;
            }
            free(data_buf);
            break;
        }

        case CMD_FLUSH_PIPE:
        case CMD_ABORT_PIPE:
        case CMD_SET_PIPE_POLICY:
            if (!valid_pipe_id(req.pipe_id)) {
                fprintf(stderr, "[bridge] Rejecting pipe command for invalid endpoint 0x%02x\n", req.pipe_id);
                resp.status = -1;
            } else {
                resp.status = 0;
            }
            if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
            break;

        default:
            fprintf(stderr, "[bridge] Unknown command %d\n", req.cmd);
            resp.status = -1;
            if (send_all(client_fd, &resp, sizeof(resp)) < 0) goto disconnect;
            break;
        }
    }

disconnect:
    fprintf(stderr, "[bridge] XGPro disconnected\n");
    close(client_fd);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
    }
    struct sigaction sa = {0};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (generate_token() < 0) {
        fprintf(stderr, "[bridge] Failed to generate auth token\n");
        return 1;
    }

    int r = libusb_init(&ctx);
    if (r < 0) {
        fprintf(stderr, "[bridge] libusb_init failed: %s\n", libusb_error_name(r));
        return 1;
    }

    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        perror("[bridge] socket");
        return 1;
    }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(BRIDGE_PORT);

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[bridge] bind");
        return 1;
    }

    if (listen(srv_fd, 1) < 0) {
        perror("[bridge] listen");
        return 1;
    }

    fprintf(stderr, "[bridge] Listening on 127.0.0.1:%d\n", BRIDGE_PORT);
    fprintf(stderr, "[bridge] Waiting for XGPro...\n");

    while (running) {
        int client_fd = accept(srv_fd, NULL, NULL);
        if (client_fd < 0) {
            if (running) perror("[bridge] accept");
            break;
        }
        int flag = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        int bufsize = 256 * 1024;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        handle_client(client_fd);
        close_device();
    }

    close(srv_fd);
    close_device();
    unlink(BRIDGE_TOKEN_PATH);
    libusb_exit(ctx);
    fprintf(stderr, "[bridge] Shutdown\n");
    return 0;
}
