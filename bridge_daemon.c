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
#include <pthread.h>
#include "bridge_proto.h"

static int verbose = 0;

#define MAX_TRANSFER_LEN (16 * 1024 * 1024)
#define MAX_BULK_EPS 16

/* Programmers are told apart by PID only; the VID is shared.
 *
 * The families differ in more than identity, and the differences are not
 * cosmetic: the T76 has one payload endpoint and a dead 0x83 that Xgpro still
 * reads from, while the T48 family splits payloads across two endpoints that
 * must be drained together or the firmware wedges. Keep that in one table
 * instead of scattering PID checks. */
static const struct xgpro_model {
    uint16_t    pid;
    const char *name;
    uint8_t     payload_in;        /* payload read endpoint */
    uint8_t     payload_in_peer;   /* second half, 0 when single-endpoint */
    uint8_t     payload_out;       /* payload write endpoint */
    uint8_t     payload_out_peer;  /* second half, 0 when single-endpoint */
    uint8_t     unused_in_ep;      /* endpoint the firmware never services */
    int         settle_ms;         /* wait after re-enumeration */
} XGPRO_MODELS[] = {
    { XGPRO_PID_T48, "T48/T56/TL866II Plus", 0x82, 0x83, 0x02, 0x03, 0x00, 1000 },
    { XGPRO_PID_T76, "T76",                  0x82, 0x00, 0x05, 0x00, 0x83, 1000 },
};
#define XGPRO_MODEL_COUNT ((int)(sizeof(XGPRO_MODELS) / sizeof(XGPRO_MODELS[0])))

static libusb_device_handle *dev_handle = NULL;
static libusb_context *ctx = NULL;
static volatile int running = 1;
static int kernel_driver_detached = 0;
static uint8_t auth_token[BRIDGE_TOKEN_LEN];
static int commands_since_open = 0;   /* >0 once the handle has done real work */
static int event_fd = -1;                 /* subscribed client for hotplug events */
static pthread_mutex_t event_mu = PTHREAD_MUTEX_INITIALIZER;
static int send_all(int fd, const void *buf, size_t len);
static uint8_t bulk_eps[MAX_BULK_EPS];
static int bulk_ep_count = 0;
static const char *model_name = NULL;
static const struct xgpro_model *model = NULL;   /* profile of the opened device */
static int srv_fd = -1;
static int active_client = -1;
static pthread_t event_thread;
static int event_thread_started = 0;
static pthread_mutex_t clients_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t clients_cv = PTHREAD_COND_INITIALIZER;
static int clients_running = 0;


static void handle_client(int client_fd);
static void close_device(void);
static int open_device(void);

/* Real hotplug, no fabrication: the app is told about attach/detach exactly
 * when the programmer does it. This is what the firmware-update flow needs,
 * because the T76 re-enumerates (and even changes bus) at the bootloader
 * switch. */
static int LIBUSB_CALL hotplug_cb(libusb_context *ctx, libusb_device *dev,
                                  libusb_hotplug_event event, void *user_data)
{
    struct libusb_device_descriptor dd;
    bridge_event_t ev;
    (void)ctx;
    (void)user_data;

    if (libusb_get_device_descriptor(dev, &dd) < 0) return 0;
    ev.evt = (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) ? 1 : 0;
    ev.pid = dd.idProduct;

    fprintf(stderr, "[bridge] hotplug: %s pid=%04x\n",
            ev.evt ? "arrived" : "removed", ev.pid);

    pthread_mutex_lock(&event_mu);
    if (event_fd >= 0) {
        if (send_all(event_fd, &ev, sizeof(ev)) < 0) {
            close(event_fd);
            event_fd = -1;
        }
    }
    pthread_mutex_unlock(&event_mu);
    return 0;
}

static void *usb_event_thread(void *arg)
{
    struct timeval tv = {0, 100000};
    (void)arg;
    while (running)
        libusb_handle_events_timeout_completed(ctx, &tv, NULL);
    return NULL;
}


static int transfer_timeout(uint32_t requested);

/* ------------------------------------------------------------------------
 * TL866II+/T48/T56 dual-endpoint payload
 *
 * This family splits a payload block across two IN endpoints (0x82/0x83) and
 * two OUT endpoints (0x02/0x03), alternating 64-byte chunks, and expects both
 * halves to be transferred *at the same time*: minipro's read_payload2()
 * submits length/2 on each endpoint and then deinterlaces.
 *
 * Draining one endpoint at a time does not just fail, it wedges the device:
 * the firmware blocks inside its read handler waiting to push the other half,
 * so the command channel stops answering and only a power cycle recovers it.
 *
 * So pair the requests here: transfer both halves concurrently, return the one
 * the app asked for, and cache the sibling for its next request.
 * ---------------------------------------------------------------------- */

#define PAIR_MIN_LEN 65          /* >64 bytes: the dual-endpoint path */

static struct {
    int      valid;
    uint8_t  ep;
    uint32_t len;
    uint8_t *data;
} sibling_cache;

static void sibling_cache_clear(void)
{
    free(sibling_cache.data);
    sibling_cache.valid = 0;
    sibling_cache.ep = 0;
    sibling_cache.len = 0;
    sibling_cache.data = NULL;
}

static uint8_t payload_sibling(uint8_t ep)
{
    if (!model || !model->payload_in_peer) return 0;
    if (ep == model->payload_in)      return model->payload_in_peer;
    if (ep == model->payload_in_peer) return model->payload_in;
    return 0;
}

typedef struct {
    uint8_t  ep;
    uint8_t *buf;
    uint32_t len;
    int      timeout;
    int      transferred;
    int      result;
} io_job_t;

static void *io_job_run(void *arg)
{
    io_job_t *j = arg;
    j->transferred = 0;
    j->result = libusb_bulk_transfer(dev_handle, j->ep, j->buf, j->len,
                                     &j->transferred, j->timeout);
    return NULL;
}

/* Run two transfers concurrently and wait for both. */
static void io_pair(io_job_t *a, io_job_t *b)
{
    pthread_t ta, tb;

    if (pthread_create(&ta, NULL, io_job_run, a) != 0) {
        io_job_run(a);
    }
    if (pthread_create(&tb, NULL, io_job_run, b) != 0) {
        io_job_run(b);
    }
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
}


/* Writes use the same split as reads (minipro: "This is from XgPro"), so the
 * two halves must go out together as well. The app is not guaranteed to have
 * both halves ready when we see the first one, so hold it - answering
 * immediately, because it may be waiting for that answer before sending the
 * second - and transmit the pair when the sibling arrives. */
static struct {
    int      valid;
    uint8_t  ep;
    uint32_t len;
    uint8_t *data;
} pending_write;

static void pending_write_clear(void)
{
    free(pending_write.data);
    pending_write.data = NULL;
    pending_write.valid = 0;
    pending_write.ep = 0;
    pending_write.len = 0;
}

/* Never let a held half be dropped silently: send it on its own and say so. */
static void pending_write_flush(void)
{
    if (!pending_write.valid) return;

    if (dev_handle && pending_write.len) {
        int transferred = 0;
        int r = libusb_bulk_transfer(dev_handle, pending_write.ep,
                                     pending_write.data, pending_write.len,
                                     &transferred, 5000);
        fprintf(stderr, "[bridge] unpaired write flushed: ep=0x%02x len=%u %s (%d)\n",
                pending_write.ep, pending_write.len, libusb_error_name(r), transferred);
    }
    pending_write_clear();
}

/* Returns 0 when handled (response already sent), -1 to use the generic path. */
static int handle_paired_write(int client_fd, bridge_request_t *req,
                               bridge_response_t *resp, uint8_t *buf)
{
    uint8_t other;
    io_job_t a, b;
    int timeout;

    if (!dev_handle || !model || !model->payload_out_peer)
        return -1;
    if (req->length < PAIR_MIN_LEN)
        return -1;
    if (req->pipe_id != model->payload_out && req->pipe_id != model->payload_out_peer)
        return -1;

    other = (req->pipe_id == model->payload_out) ? model->payload_out_peer
                                                 : model->payload_out;

    /* The sibling of what we are holding? Send the pair together. */
    if (pending_write.valid && pending_write.ep == other &&
        pending_write.len == req->length) {
        timeout = transfer_timeout(req->timeout_ms);

        memset(&a, 0, sizeof(a));
        a.ep = pending_write.ep; a.buf = pending_write.data;
        a.len = pending_write.len; a.timeout = timeout;
        memset(&b, 0, sizeof(b));
        b.ep = req->pipe_id; b.buf = buf; b.len = req->length; b.timeout = timeout;

        if (verbose)
            fprintf(stderr, "[bridge] paired write: 0x%02x and 0x%02x, %u bytes each\n",
                    a.ep, b.ep, a.len);
        io_pair(&a, &b);
        if (verbose)
            fprintf(stderr, "[bridge] paired write: 0x%02x -> %s (%d), 0x%02x -> %s (%d)\n",
                    a.ep, libusb_error_name(a.result), a.transferred,
                    b.ep, libusb_error_name(b.result), b.transferred);
        pending_write_clear();

        resp->status = b.result;
        resp->length = (b.result == 0) ? (uint32_t)b.transferred : 0;
        if (a.result == 0 && b.result == 0) commands_since_open++;
        free(buf);   /* the caller hands ownership over */
        if (send_all(client_fd, resp, sizeof(*resp)) < 0) return 0;
        return 0;
    }

    /* Otherwise hold this half and report success; the pair follows. */
    pending_write_flush();
    pending_write.data = buf;
    pending_write.ep = req->pipe_id;
    pending_write.len = req->length;
    pending_write.valid = 1;
    if (verbose)
        fprintf(stderr, "[bridge] holding write half 0x%02x (%u bytes) for its pair\n",
                req->pipe_id, req->length);

    resp->status = 0;
    resp->length = req->length;
    if (send_all(client_fd, resp, sizeof(*resp)) < 0) return 0;
    return 0;
}

/* Returns 0 when the request was handled (response already sent), -1 to fall
 * back to the generic path. */
static int handle_paired_read(int client_fd, bridge_request_t *req,
                              bridge_response_t *resp)
{
    uint8_t  other = payload_sibling(req->pipe_id);
    uint8_t *req_buf = NULL, *other_buf = NULL;
    io_job_t a, b;
    int timeout;

    if (!dev_handle || other == 0 || req->length < PAIR_MIN_LEN)
        return -1;

    /* Serve the sibling half we already fetched. */
    if (sibling_cache.valid && sibling_cache.ep == req->pipe_id &&
        sibling_cache.len == req->length) {
        if (verbose)
            fprintf(stderr, "[bridge] paired read: serving cached 0x%02x (%u bytes)\n",
                    req->pipe_id, req->length);
        resp->status = 0;
        resp->length = req->length;
        if (send_all(client_fd, resp, sizeof(*resp)) < 0) return 0;
        send_all(client_fd, sibling_cache.data, sibling_cache.len);
        sibling_cache_clear();
        return 0;
    }

    sibling_cache_clear();

    timeout = transfer_timeout(req->timeout_ms);
    req_buf = malloc(req->length);
    other_buf = malloc(req->length);
    if (!req_buf || !other_buf) {
        free(req_buf);
        free(other_buf);
        return -1;
    }

    memset(&a, 0, sizeof(a));
    a.ep = req->pipe_id;  a.buf = req_buf;   a.len = req->length; a.timeout = timeout;
    memset(&b, 0, sizeof(b));
    b.ep = other;         b.buf = other_buf; b.len = req->length; b.timeout = timeout;

    if (verbose)
        fprintf(stderr, "[bridge] paired read: 0x%02x and 0x%02x, %u bytes each\n",
                a.ep, b.ep, req->length);
    io_pair(&a, &b);

    if (verbose)
        fprintf(stderr, "[bridge] paired read: 0x%02x -> %s (%d), 0x%02x -> %s (%d)\n",
                a.ep, libusb_error_name(a.result), a.transferred,
                b.ep, libusb_error_name(b.result), b.transferred);

    /* Keep the sibling's half for the app's next request. */
    if (a.result == 0 && b.result == 0 && b.transferred == (int)req->length) {
        sibling_cache.valid = 1;
        sibling_cache.ep = other;
        sibling_cache.len = req->length;
        sibling_cache.data = other_buf;
        other_buf = NULL;
    }
    free(other_buf);

    resp->status = a.result;
    resp->length = (a.result == 0) ? (uint32_t)a.transferred : 0;
    if (send_all(client_fd, resp, sizeof(*resp)) < 0) {
        free(req_buf);
        return 0;
    }
    if (resp->length > 0)
        send_all(client_fd, req_buf, resp->length);
    free(req_buf);

    if (a.result == 0) commands_since_open++;
    return 0;
}

static void *client_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
    handle_client(fd);
    active_client = -1;
    close_device();
    close(fd);

    pthread_mutex_lock(&clients_mu);
    clients_running--;
    pthread_cond_signal(&clients_cv);
    pthread_mutex_unlock(&clients_mu);
    return NULL;
}

static void close_device(void);
static int open_device(void);

static void sig_handler(int sig) {
    (void)sig;
    running = 0;
    /* Break out of accept()/recv_all() so the device handle is released
     * before the process exits. A lingering daemon that still holds the
     * usbfs node wedges the programmer for the next instance. */
    if (srv_fd >= 0) close(srv_fd);
    srv_fd = -1;
    if (active_client >= 0) shutdown(active_client, SHUT_RDWR);
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

/* A wedged XGecu programmer answers bulk transfers with LIBUSB_ERROR_IO and
 * does not recover from a libusb_reset_device(); only a power cycle helps. */
static int warned_wedged = 0;

static void warn_if_wedged(int r) {
    if (r != LIBUSB_ERROR_IO || warned_wedged) return;
    warned_wedged = 1;
    fprintf(stderr, "[bridge] Endpoint I/O error: the programmer may be wedged. "
                    "A USB reset does not clear this; power-cycle it (unplug/replug).\n");
}

/* After a firmware update the device switches into its bootloader, which
 * resets and re-enumerates the USB device. The host side has to wait for it
 * to come back instead of failing the first open. */
#define OPEN_RETRY_TIMEOUT_MS  5000
#define OPEN_RETRY_INTERVAL_MS 200
/* After a reset the T76 needs time before it services commands. minipro
 * waits 1000 ms here ("Wait for T76 to boot, otherwise minipro_open will
 * fail"); without it the first command after re-enumeration goes unheard. */
#define BOOT_SETTLE_MS         1000   /* fallback when no profile is known */

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

/* The shim forwards the app's PIPE_TRANSFER_TIMEOUT so a transfer against a
 * device that just re-enumerated fails on the app's schedule instead of
 * blocking for the daemon's default. */
static int transfer_timeout(uint32_t requested) {
    if (requested == 0) return 120000;
    if (requested > 600000) return 600000;
    return (int)requested;
}

/* During a firmware update the app re-opens the device while the previous
 * instance is still on the bus; the first command then fails with NO_DEVICE.
 * Nothing was transferred, so it is safe to wait for the device to settle and
 * resend. Only done while the handle has not completed any command yet. */
static int retry_first_command(uint8_t ep, uint8_t *buf, uint32_t len, int *transferred)
{
    int r;

    close_device();
    if (open_device() != 0)
        return LIBUSB_ERROR_NO_DEVICE;

    *transferred = 0;
    r = libusb_bulk_transfer(dev_handle, ep, buf, len, transferred, 5000);
    if (r == 0)
        fprintf(stderr, "[bridge] first command retried successfully after re-enumeration\n");
    return r;
}

/* The T76's FPGA streams payload ahead of the host. If a new READ_CODE is
 * issued while data is still queued on the payload endpoint the endpoint
 * stalls and every subsequent read times out (Xgpro then reports verify
 * mismatches). Drain whatever is left before starting a new transaction. */
static void drain_payload_ep(uint8_t ep)
{
    uint8_t buf[4096];
    int total = 0;

    if (!dev_handle) return;

    for (int i = 0; i < 256; i++) {
        int n = 0;
        int r = libusb_bulk_transfer(dev_handle, ep, buf, sizeof(buf), &n, 20);
        if (r != 0 || n <= 0) break;
        total += n;
    }
    if (total > 0)
        fprintf(stderr, "[bridge] drained %d stale bytes from ep 0x%02x\n", total, ep);
}

static int open_device(void) {
    if (dev_handle) return 0;

    int waited = 0;

    for (;;) {
        for (int i = 0; i < XGPRO_MODEL_COUNT && !dev_handle; i++) {
            dev_handle = libusb_open_device_with_vid_pid(ctx, XGPRO_VID, XGPRO_MODELS[i].pid);
            if (dev_handle) {
                model = &XGPRO_MODELS[i];
                model_name = XGPRO_MODELS[i].name;
            }
        }
        if (dev_handle) break;

        if (waited >= OPEN_RETRY_TIMEOUT_MS) {
            fprintf(stderr, "[bridge] No XGecu programmer found (VID=%04x PIDs:", XGPRO_VID);
            for (int i = 0; i < XGPRO_MODEL_COUNT; i++)
                fprintf(stderr, " %04x", XGPRO_MODELS[i].pid);
            fprintf(stderr, ")\n");
            return -1;
        }

        fprintf(stderr, "[bridge] Device not present yet, waiting for re-enumeration (%d ms)\n", waited);
        usleep(OPEN_RETRY_INTERVAL_MS * 1000);
        waited += OPEN_RETRY_INTERVAL_MS;
    }

    if (waited > 0) {
        fprintf(stderr, "[bridge] Device came back after %d ms, settling %d ms before use\n",
                waited, BOOT_SETTLE_MS);
        usleep((model ? model->settle_ms : BOOT_SETTLE_MS) * 1000);
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

    commands_since_open = 0;
    fprintf(stderr, "[bridge] %s opened, configured, and interface claimed\n", model_name);
    return 0;
}

static void reset_endpoint(uint8_t ep) {
    if (!dev_handle) return;
    libusb_clear_halt(dev_handle, ep);
}

/* A firmware update pulls the device off the bus between transfers. Treat
 * that as a released handle so the next CMD_OPEN re-opens it, instead of
 * hammering a handle that libusb has already invalidated. */
static void handle_device_loss(int r) {
    if (r != LIBUSB_ERROR_NO_DEVICE) return;
    fprintf(stderr, "[bridge] Device left the bus (re-enumeration), releasing handle\n");
    close_device();
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

        if (req.cmd == CMD_SUBSCRIBE) {
            pthread_mutex_lock(&event_mu);
            event_fd = client_fd;
            pthread_mutex_unlock(&event_mu);
            fprintf(stderr, "[bridge] hotplug subscriber attached\n");
            /* Hold the connection open; events are pushed from the callback. */
            {
                char sink[64];
                while (read(client_fd, sink, sizeof(sink)) > 0) { }
            }
            pthread_mutex_lock(&event_mu);
            if (event_fd == client_fd) event_fd = -1;
            pthread_mutex_unlock(&event_mu);
            fprintf(stderr, "[bridge] hotplug subscriber gone\n");
            return;
        }

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

            if (handle_paired_write(client_fd, &req, &resp, data_buf) == 0) {
                data_buf = NULL;   /* ownership moved into the helper */
                break;
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
                if (req.pipe_id == 0x01 && req.length >= 1 && data_buf[0] == 0x0D)
                    drain_payload_ep(0x82);

                int r = libusb_bulk_transfer(dev_handle, req.pipe_id,
                                             data_buf, req.length,
                                             &transferred, transfer_timeout(req.timeout_ms));
                if (r == LIBUSB_ERROR_NO_DEVICE && transferred == 0 &&
                    commands_since_open == 0) {
                    fprintf(stderr, "[bridge] first command hit a vanished device, retrying\n");
                    r = retry_first_command(req.pipe_id, data_buf, req.length, &transferred);
                }
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
                if (r == 0) commands_since_open++;
                if (r != 0) {
                    if (verbose)
                        fprintf(stderr, "[bridge] WRITE error: %s, transferred=%d\n", libusb_error_name(r), transferred);
                    reset_endpoint(req.pipe_id);
                    warn_if_wedged(r);
                    handle_device_loss(r);
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

            if (handle_paired_read(client_fd, &req, &resp) == 0)
                break;

            /* The T76 firmware never services endpoint 0x83, yet Xgpro reads
             * 32 bytes from it after the status query. Waiting for a reply
             * burns the app's timeout and it then aborts the chip read after
             * two blocks. Answer immediately with a zero-length success;
             * wine64 works around the same quirk by completing the overlapped
             * request early. */
            if (model && model->unused_in_ep && req.pipe_id == model->unused_in_ep) {
                if (verbose)
                    fprintf(stderr, "[bridge] %s: faking zero-length read on unused endpoint 0x%02x\n",
                            model->name, model->unused_in_ep);
                resp.status = 0;
                resp.length = 0;
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
            if (verbose)
                fprintf(stderr, "[bridge] READ ep=0x%02x requested %u bytes (timeout %d ms)\n",
                        req.pipe_id, req.length, transfer_timeout(req.timeout_ms));
            int r = libusb_bulk_transfer(dev_handle, req.pipe_id,
                                         data_buf, req.length,
                                         &transferred, transfer_timeout(req.timeout_ms));
            if (r == 0 && transferred != (int)req.length && verbose)
                fprintf(stderr, "[bridge] READ ep=0x%02x short: got %d of %u\n",
                        req.pipe_id, transferred, req.length);
            resp.status = (r == 0) ? 0 : r;
            if (r != 0) {
                if (verbose)
                    fprintf(stderr, "[bridge] READ error: %s, transferred=%d\n", libusb_error_name(r), transferred);
                reset_endpoint(req.pipe_id);
                warn_if_wedged(r);
                handle_device_loss(r);
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

    libusb_hotplug_callback_handle hp_handle;
    int hp = libusb_hotplug_register_callback(ctx,
        LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
        LIBUSB_HOTPLUG_NO_FLAGS, XGPRO_VID, LIBUSB_HOTPLUG_MATCH_ANY,
        LIBUSB_HOTPLUG_MATCH_ANY, hotplug_cb, NULL, &hp_handle);
    if (hp != LIBUSB_SUCCESS) {
        fprintf(stderr, "[bridge] hotplug unavailable: %s (device notifications disabled)\n",
                libusb_error_name(hp));
    } else {
        if (pthread_create(&event_thread, NULL, usb_event_thread, NULL) == 0)
            event_thread_started = 1;
        else
            fprintf(stderr, "[bridge] failed to start libusb event thread\n");
    }

    srv_fd = socket(AF_INET, SOCK_STREAM, 0);
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
        active_client = client_fd;
        {
            pthread_t t;
            pthread_mutex_lock(&clients_mu);
            clients_running++;
            pthread_mutex_unlock(&clients_mu);
            if (pthread_create(&t, NULL, client_thread, (void *)(intptr_t)client_fd) == 0)
                pthread_detach(t);
            else {
                fprintf(stderr, "[bridge] failed to start client thread\n");
                close(client_fd);
                active_client = -1;
                pthread_mutex_lock(&clients_mu);
                clients_running--;
                pthread_mutex_unlock(&clients_mu);
            }
        }
    }

    if (srv_fd >= 0) close(srv_fd);

    /* Wait for client threads to finish their transfers: libusb_exit()
     * asserts (and aborts) if any thread is still inside the context. */
    pthread_mutex_lock(&clients_mu);
    while (clients_running > 0)
        pthread_cond_wait(&clients_cv, &clients_mu);
    pthread_mutex_unlock(&clients_mu);

    close_device();

    if (event_thread_started) {
        running = 0;
        pthread_join(event_thread, NULL);
        event_thread_started = 0;
    }

    unlink(BRIDGE_TOKEN_PATH);
    libusb_exit(ctx);
    fprintf(stderr, "[bridge] Shutdown\n");
    return 0;
}
