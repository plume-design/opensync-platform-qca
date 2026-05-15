/*
Copyright (c) 2015, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* libc */
#include <errno.h>
#include <linux/un.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

/* 3rd party */
#include <ev.h>

/* opensync */
#include <log.h>
#include <memutil.h>
#include <util.h>

/* local */
#include "osw_drv_spf13_hostap_listen.h"
#include "osw_drv_spf13_hostap_path.h"
#include "osw_drv_spf13_hostap_sock.h"
#include "osw_drv_spf13_macros.h"

#define OSW_DRV_SPF13_HOSTAP_LISTEN_ENDPOINT_ALIVE_TIMEOUT_SEC 20
#define OSW_DRV_SPF13_HOSTAP_LISTEN_ENDPOINT_PING_TIMEOUT_SEC  10

#define LOG_PREFIX_ENDPOINT(endpoint, fmt, ...)                                 \
    LOG_PREFIX(                                                                 \
            "hostap_listen_endpoint(ctrl_path=%s, alive=%s): " fmt,             \
            (endpoint) != NULL ? (endpoint)->ctrl_path : "NULL",                \
            (endpoint) != NULL ? (endpoint)->alive ? "true" : "false" : "NULL", \
            ##__VA_ARGS__)

struct osw_drv_spf13_hostap_listen_endpoint
{
    char *ctrl_path;
    ev_timer ping;
    ev_timer ping_timeout;
    bool alive;
    int borrowed_fd;
};
typedef struct osw_drv_spf13_hostap_listen_endpoint osw_drv_spf13_hostap_listen_endpoint_t;

struct osw_drv_spf13_hostap_listen
{
    ev_io hostap_listen_io;
    osw_drv_spf13_hostap_listen_endpoint_t *hostapd_global;
    osw_drv_spf13_hostap_listen_endpoint_t *supplicant_global;
    osw_drv_spf13_hostap_listen_recv_fn_t *recv_cb;
    osw_drv_spf13_hostap_listen_attached_fn_t *attached_cb;
    void *recv_priv;
    void *attached_priv;
};

static int osw_drv_spf13_hostap_listen_endpoint_attach(osw_drv_spf13_hostap_listen_endpoint_t *endpoint)
{
    if (endpoint == NULL) return -1;

    LOGI(LOG_PREFIX_ENDPOINT(endpoint, "attaching hostapd endpoint"));

    const char *cmd1 = "ATTACH";
    const char *cmd2 = "ATTACH probe_rx_events=1";
    const size_t cmd1_len = strlen(cmd1);
    const size_t cmd2_len = strlen(cmd2);
    const char *path = endpoint->ctrl_path;
    const int fd = endpoint->borrowed_fd;
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    STRSCPY_WARN(addr.sun_path, path);
    const int send1_err = sendto(fd, cmd1, cmd1_len, 0, (struct sockaddr *)&addr, sizeof(addr));
    const int send1_errno = errno;
    const int send2_err = sendto(fd, cmd2, cmd2_len, 0, (struct sockaddr *)&addr, sizeof(addr));
    const int send2_errno = errno;
    const bool both_failed = (send1_err < 0 && send2_err < 0);
    if (both_failed)
    {
        LOGW(LOG_PREFIX_ENDPOINT(endpoint, "failed to send hostapd attach commands: %d(%s), %d(%s)"),
             send1_err,
             strerror(send1_errno),
             send2_err,
             strerror(send2_errno));
        endpoint->alive = false;
        return -1;
    }

    return 0;
}

static void osw_drv_spf13_hostap_listen_endpoint_ping(osw_drv_spf13_hostap_listen_endpoint_t *endpoint)
{
    if (endpoint == NULL) return;
    if (endpoint->ctrl_path == NULL) return;

    ev_timer_stop(EV_DEFAULT_ & endpoint->ping_timeout);

    const char *ping_msg = "PING";
    const char *path = endpoint->ctrl_path;
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    STRSCPY_WARN(addr.sun_path, path);
    const int flags = MSG_DONTWAIT;
    const int send_err =
            sendto(endpoint->borrowed_fd, ping_msg, strlen(ping_msg), flags, (struct sockaddr *)&addr, sizeof(addr));
    if (send_err < 0)
    {
        const int send_errno = errno;
        if (endpoint->alive)
        {
            LOGW(LOG_PREFIX_ENDPOINT(endpoint, "failed to send hostapd ping: %d(%s)"), send_err, strerror(send_errno));
            endpoint->alive = false;
        }
        ev_timer_again(EV_DEFAULT_ & endpoint->ping);
        return;
    }

    LOGT(LOG_PREFIX_ENDPOINT(endpoint, "sent hostapd ping"));

    ev_timer_set(&endpoint->ping_timeout, OSW_DRV_SPF13_HOSTAP_LISTEN_ENDPOINT_PING_TIMEOUT_SEC, 0);
    ev_timer_start(EV_DEFAULT_ & endpoint->ping_timeout);
}

static void osw_drv_spf13_hostap_listen_endpoint_bump_alive(osw_drv_spf13_hostap_listen_endpoint_t *endpoint)
{
    if (endpoint == NULL) return;

    if (endpoint->alive == false)
    {
        LOGI(LOG_PREFIX_ENDPOINT(endpoint, "bumping hostapd endpoint alive, re-attaching"));
        endpoint->alive = true;
        osw_drv_spf13_hostap_listen_endpoint_attach(endpoint);
    }

    LOGT(LOG_PREFIX_ENDPOINT(endpoint, "bumped alive"));
    ev_timer_stop(EV_DEFAULT_ & endpoint->ping_timeout);
    ev_timer_again(EV_DEFAULT_ & endpoint->ping);
}

static void osw_drv_spf13_hostap_listen_endpoint_recv(
        osw_drv_spf13_hostap_listen_endpoint_t *endpoint,
        const struct sockaddr_un *addr)
{
    if (endpoint == NULL) return;
    if (addr == NULL) return;

    /* FIXME: This should canonicalize the sun_path. It can contain multiple
     * consecutive `/` or `..`. While a valid path, naive strcmp() won't be
     * able to figure that out.
     */
    const bool matching_path = (strcmp(addr->sun_path, endpoint->ctrl_path) == 0);
    if (matching_path)
    {
        osw_drv_spf13_hostap_listen_endpoint_bump_alive(endpoint);
    }
}

static void osw_drv_spf13_hostap_listen_endpoint_ping_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_hostap_listen_endpoint_t *endpoint = w->data;
    osw_drv_spf13_hostap_listen_endpoint_ping(endpoint);
}

static void osw_drv_spf13_hostap_listen_endpoint_ping_timeout(osw_drv_spf13_hostap_listen_endpoint_t *endpoint)
{
    if (endpoint == NULL) return;

    if (endpoint->alive)
    {
        LOGW(LOG_PREFIX_ENDPOINT(endpoint, "hostapd endpoint ping timeout, marking as dead"));
        endpoint->alive = false;
    }
}

static void osw_drv_spf13_hostap_listen_endpoint_ping_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_hostap_listen_endpoint_t *endpoint = w->data;
    osw_drv_spf13_hostap_listen_endpoint_ping_timeout(endpoint);
}

static osw_drv_spf13_hostap_listen_endpoint_t *osw_drv_spf13_hostap_listen_endpoint_new(int fd, const char *ctrl_path)
{
    if (ctrl_path == NULL) return NULL;

    osw_drv_spf13_hostap_listen_endpoint_t *endpoint = CALLOC(1, sizeof(*endpoint));
    endpoint->ctrl_path = STRDUP(ctrl_path);
    endpoint->borrowed_fd = fd;

    ev_timer_init(&endpoint->ping, osw_drv_spf13_hostap_listen_endpoint_ping_cb, 0, 0);
    endpoint->ping.data = endpoint;

    ev_timer_init(&endpoint->ping_timeout, osw_drv_spf13_hostap_listen_endpoint_ping_timeout_cb, 0, 0);
    endpoint->ping_timeout.data = endpoint;

    ev_timer_set(&endpoint->ping, 0, OSW_DRV_SPF13_HOSTAP_LISTEN_ENDPOINT_ALIVE_TIMEOUT_SEC);
    ev_timer_start(EV_DEFAULT_ & endpoint->ping);

    return endpoint;
}

static void osw_drv_spf13_hostap_listen_endpoint_drop(osw_drv_spf13_hostap_listen_endpoint_t *endpoint)
{
    if (endpoint == NULL) return;

    ev_timer_stop(EV_DEFAULT_ & endpoint->ping);
    ev_timer_stop(EV_DEFAULT_ & endpoint->ping_timeout);
    FREE(endpoint->ctrl_path);
    FREE(endpoint);
}

static void osw_drv_spf13_hostap_listen_halt(osw_drv_spf13_hostap_listen_t *listen)
{
    if (listen == NULL) return;

    ev_io_stop(EV_DEFAULT_ & listen->hostap_listen_io);

    if (listen->hostap_listen_io.fd >= 0)
    {
        close(listen->hostap_listen_io.fd);
        listen->hostap_listen_io.fd = -1;
    }
}

static void osw_drv_spf13_hostap_listen_io_cb(EV_P_ ev_io *io, int revents)
{
    osw_drv_spf13_hostap_listen_t *listen = io->data;
    if (listen == NULL) return;

    const int fd = io->fd;
    struct sockaddr_un addr = {0};
    socklen_t addr_len = sizeof(addr);
    char buf[4096];
    // const ssize_t recv_err = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
    const int flags = MSG_DONTWAIT;
    const ssize_t recv_err = recvfrom(fd, buf, sizeof(buf) - 1, flags, (struct sockaddr *)&addr, &addr_len);
    if (recv_err < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            LOGD(LOG_PREFIX("no data available on hostapd socket"));
            return;
        }
        LOGE(LOG_PREFIX("failed to receive data from hostapd socket: %s"), strerror(errno));
        osw_drv_spf13_hostap_listen_halt(listen);
        return;
    }
    buf[recv_err] = '\0'; /* null-terminate the buffer */

    osw_drv_spf13_hostap_listen_endpoint_recv(listen->hostapd_global, &addr);
    osw_drv_spf13_hostap_listen_endpoint_recv(listen->supplicant_global, &addr);

    const char *prefix_bss = "<";
    const char *prefix_global = "IFNAME=";
    const size_t prefix_bss_len = strlen(prefix_bss);
    const size_t prefix_global_len = strlen(prefix_global);
    const bool is_event_bss = (strncmp(buf, prefix_bss, prefix_bss_len) == 0);
    const bool is_event_global = (strncmp(buf, prefix_global, prefix_global_len) == 0);
    const bool is_ok = (strncmp(buf, "OK", 2) == 0);
    const bool is_pong = (strncmp(buf, "PONG", 4) == 0);
    if (is_event_global)
    {
        /* Eg. IFNAME=h-60 <3>AP-STA-DISCONNECTED 6e:4e:e2:ce:fa:75 */
        char *if_name = buf + prefix_global_len;
        char *space = strchr(if_name, ' ');
        if (space == NULL)
        {
            LOGW(LOG_PREFIX("ignoring hostapd event without space: %s"), buf);
            return;
        }
        *space = '\0'; /* null-terminate the interface name */

        char *level_str = space + 1; /* points to '<' */
        if (level_str == NULL || *level_str != '<')
        {
            LOGW(LOG_PREFIX("ignoring hostapd event without level: %s"), buf);
            return;
        }
        level_str++; /* skip '<' */

        char *level_end = strchr(level_str, '>');
        if (level_end == NULL)
        {
            LOGW(LOG_PREFIX("ignoring hostapd event without level end: %s"), buf);
            return;
        }
        *level_end = '\0'; /* null-terminate the level */
        level_end++;       /* skip '>' */

        const int level = atoi(level_str);

        char *message = level_end;
        const char *event_name = strsep(&message, " ");
        const char *event_data = message ?: "";

        LOGI(LOG_PREFIX("hostapd event: if_name=%s, level=%d, event_name=%s, event_data=%s"),
             if_name ?: "*",
             level,
             event_name ?: "*",
             event_data ?: "*");

        if (listen->recv_cb != NULL)
        {
            listen->recv_cb(listen->recv_priv, if_name, level, event_name, event_data);
        }
    }
    else if (is_event_bss)
    {
        LOGW(LOG_PREFIX("ignoring hostapd event for BSS: %s"), buf);
    }
    else if (is_ok)
    {
        LOGT(LOG_PREFIX("received hostapd response: %s"), buf);
        if (listen->attached_cb != NULL)
        {
            listen->attached_cb(listen->attached_priv);
        }
    }
    else if (is_pong)
    {
        LOGT(LOG_PREFIX("received hostapd response: %s"), buf);
    }
    else
    {
        LOGT(LOG_PREFIX("ignoring hostapd response: %s"), buf);
    }
}

osw_drv_spf13_hostap_listen_t *osw_drv_spf13_hostap_listen_new(
        osw_drv_spf13_hostap_listen_recv_fn_t *recv_cb,
        void *recv_priv,
        osw_drv_spf13_hostap_listen_attached_fn_t *attached_cb,
        void *attached_priv)
{
    if (recv_cb == NULL) return NULL;

    const int fd = osw_drv_spf13_hostap_sock_open();
    if (fd < 0)
    {
        LOGE(LOG_PREFIX("failed to open hostapd listen socket"));
        return NULL;
    }

    osw_drv_spf13_hostap_listen_t *listen = CALLOC(1, sizeof(*listen));
    ev_io_init(&listen->hostap_listen_io, osw_drv_spf13_hostap_listen_io_cb, fd, EV_READ);
    listen->hostap_listen_io.data = listen;
    ev_io_start(EV_DEFAULT_ & listen->hostap_listen_io);

    listen->recv_cb = recv_cb;
    listen->recv_priv = recv_priv;
    listen->attached_cb = attached_cb;
    listen->attached_priv = attached_priv;

    listen->hostapd_global = osw_drv_spf13_hostap_listen_endpoint_new(fd, osw_drv_spf13_hostap_path_hostapd_global());
    listen->supplicant_global =
            osw_drv_spf13_hostap_listen_endpoint_new(fd, osw_drv_spf13_hostap_path_supplicant_global());
    return listen;
}

void osw_drv_spf13_hostap_listen_drop(osw_drv_spf13_hostap_listen_t *listen)
{
    if (listen == NULL) return;

    osw_drv_spf13_hostap_listen_halt(listen);
    osw_drv_spf13_hostap_listen_endpoint_drop(listen->hostapd_global);
    osw_drv_spf13_hostap_listen_endpoint_drop(listen->supplicant_global);
    FREE(listen);
}
