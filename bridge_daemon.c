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

static libusb_device_handle *dev_handle = NULL;
static libusb_context *ctx = NULL;
static volatile int running = 1;
static int kernel_driver_detached = 0;
static uint8_t auth_token[BRIDGE_TOKEN_LEN];

static void sig_handler(int sig) {
    (void)sig;
    running = 0;
}

static int valid_pipe_id(uint8_t pipe_id) {
    uint8_t ep = pipe_id & 0x7F;
    return ep == 0x01 || ep == 0x02;
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

    dev_handle = libusb_open_device_with_vid_pid(ctx, T48_VID, T48_PID);
    if (!dev_handle) {
        fprintf(stderr, "[bridge] T48 not found (VID=%04x PID=%04x)\n", T48_VID, T48_PID);
        return -1;
    }

    if (libusb_kernel_driver_active(dev_handle, 0) == 1) {
        int dr = libusb_detach_kernel_driver(dev_handle, 0);
        if (dr == 0) {
            kernel_driver_detached = 1;
        } else {
            fprintf(stderr, "[bridge] Warning: detach kernel driver failed: %s\n", libusb_error_name(dr));
        }
    }

    int r = libusb_set_configuration(dev_handle, 1);
    if (r < 0 && r != LIBUSB_ERROR_BUSY) {
        fprintf(stderr, "[bridge] Failed to set configuration: %s\n", libusb_error_name(r));
        libusb_close(dev_handle);
        dev_handle = NULL;
        kernel_driver_detached = 0;
        return -1;
    }

    r = libusb_claim_interface(dev_handle, 0);
    if (r < 0) {
        fprintf(stderr, "[bridge] Failed to claim interface: %s\n", libusb_error_name(r));
        libusb_close(dev_handle);
        dev_handle = NULL;
        kernel_driver_detached = 0;
        return -1;
    }

    libusb_set_interface_alt_setting(dev_handle, 0, 0);
    libusb_clear_halt(dev_handle, 0x01);
    libusb_clear_halt(dev_handle, 0x81);
    libusb_clear_halt(dev_handle, 0x02);
    libusb_clear_halt(dev_handle, 0x82);

    fprintf(stderr, "[bridge] T48 opened, configured, and interface claimed\n");
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
        fprintf(stderr, "[bridge] T48 closed\n");
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
