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
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <net/if.h>
#include <dirent.h>
#include <errno.h>
#include <linux/un.h>
#include <nl80211_copy.h>

/* opensync */
#include <os_time.h>
#include <memutil.h>
#include <log.h>
#include <util.h>
#include <log.h>
#include <const.h>

/* osw */
#include <osw_drv.h>
#include <osw_module.h>
#include <osw_hostap_common.h>
#include <osw_hostap_conf.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_hostap_cmd.h"

#define LOG_PREFIX_HOSTAP_CMD(cmd, fmt, ...) \
    LOG_PREFIX("hostapd cmd: %s(fd=%d): %s: " fmt, cmd->path ?: "*", cmd->io.fd, cmd->request ?: "", ##__VA_ARGS__)

struct osw_drv_spf13_hostap_cmd
{
    ev_io io;
    char *path;    /* only used for logging */
    char *request; /* only used for logging */
    char *reply;
    void (*done_cb)(void *priv);
    void *priv;
    bool done;
    int64_t started_on;
};

static void osw_drv_spf13_hostap_cmd_halt(osw_drv_spf13_hostap_cmd_t *cmd)
{
    if (cmd == NULL) return;

    LOGD(LOG_PREFIX_HOSTAP_CMD(cmd, "halting hostapd command"));

    if (ev_is_active(&cmd->io))
    {
        ev_io_stop(EV_DEFAULT_ & cmd->io);
    }

    if (cmd->io.fd >= 0)
    {
        close(cmd->io.fd);
        cmd->io.fd = -1;
    }
}

void osw_drv_spf13_hostap_cmd_drop(osw_drv_spf13_hostap_cmd_t *cmd)
{
    if (cmd == NULL) return;

    LOGD(LOG_PREFIX_HOSTAP_CMD(cmd, "dropping hostapd command"));
    osw_drv_spf13_hostap_cmd_halt(cmd);
    FREE(cmd->path);
    FREE(cmd->request);
    FREE(cmd->reply);
    FREE(cmd);
}

void osw_drv_spf13_hostap_cmd_drop_all(osw_drv_spf13_hostap_cmd_t **cmds)
{
    if (cmds == NULL) return;

    for (size_t i = 0; cmds[i] != NULL; i++)
    {
        osw_drv_spf13_hostap_cmd_drop(cmds[i]);
        cmds[i] = NULL;
    }
    FREE(cmds);
}

void osw_drv_spf13_hostap_cmd_drop_array(osw_drv_spf13_hostap_cmd_t **cmds, size_t count)
{
    if (cmds == NULL || count == 0) return;

    for (size_t i = 0; i < count; i++)
    {
        osw_drv_spf13_hostap_cmd_drop(cmds[i]);
        cmds[i] = NULL;
    }
}

static void osw_drv_spf13_hostap_cmd_complete(osw_drv_spf13_hostap_cmd_t *cmd)
{
    if (cmd == NULL) return;

    LOGD(LOG_PREFIX_HOSTAP_CMD(cmd, "completing hostapd command"));

    const int64_t elapsed = clock_mono_ms() - cmd->started_on;
    LOGD(LOG_PREFIX_HOSTAP_CMD(cmd, "command completed in %" PRId64 " ms"), elapsed);

    osw_drv_spf13_hostap_cmd_halt(cmd);

    void (*done_cb)(void *priv) = cmd->done_cb;
    cmd->done_cb = NULL;
    cmd->done = true;

    if (done_cb != NULL)
    {
        done_cb(cmd->priv);
    }
}

static void osw_drv_spf13_hostap_cmd_io_cb(EV_P_ ev_io *io, int revents)
{
    osw_drv_spf13_hostap_cmd_t *cmd = io->data;
    if (cmd == NULL) return;

    const int fd = cmd->io.fd;
    char buf[4096];
    const ssize_t recv_err = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
    if (recv_err < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            LOGD(LOG_PREFIX_HOSTAP_CMD(cmd, "no data available on hostapd command socket"));

            return;
        }
        LOGE(LOG_PREFIX_HOSTAP_CMD(cmd, "failed to receive data from hostapd command socket: %s"), strerror(errno));
        osw_drv_spf13_hostap_cmd_complete(cmd);
        return;
    }
    buf[recv_err] = '\0'; /* null-terminate the buffer */

    cmd->reply = STRDUP(buf);
    if (cmd->reply == NULL)
    {
        LOGE(LOG_PREFIX_HOSTAP_CMD(cmd, "failed to allocate memory for hostapd command reply"));
        osw_drv_spf13_hostap_cmd_complete(cmd);
        return;
    }

    LOGD(LOG_PREFIX_HOSTAP_CMD(cmd, "received reply: len=%zd", recv_err));
    LOGT(LOG_PREFIX_HOSTAP_CMD(cmd, "received reply: buffer='%s'"), cmd->reply);

    osw_drv_spf13_hostap_cmd_complete(cmd);
}

const char *osw_drv_spf13_hostap_cmd_get_reply(osw_drv_spf13_hostap_cmd_t *cmd)
{
    if (cmd == NULL) return NULL;
    return cmd->reply;
}

const char *osw_drv_spf13_hostap_cmd_get_request(osw_drv_spf13_hostap_cmd_t *cmd)
{
    if (cmd == NULL) return NULL;
    return cmd->request;
}

bool osw_drv_spf13_hostap_cmd_is_done(osw_drv_spf13_hostap_cmd_t *cmd)
{
    if (cmd == NULL) return true;
    return cmd->done;
}

bool osw_drv_spf13_hostap_cmd_is_done_all(osw_drv_spf13_hostap_cmd_t **cmds)
{
    if (cmds == NULL) return true;

    for (size_t i = 0; cmds[i] != NULL; i++)
    {
        if (!osw_drv_spf13_hostap_cmd_is_done(cmds[i]))
        {
            return false;
        }
    }
    return true;
}

bool osw_drv_spf13_hostap_cmd_is_done_array(osw_drv_spf13_hostap_cmd_t **cmds, size_t count)
{
    if (cmds == NULL || count == 0) return true;

    for (size_t i = 0; i < count; i++)
    {
        if (!osw_drv_spf13_hostap_cmd_is_done(cmds[i]))
        {
            return false;
        }
    }
    return true;
}

bool osw_drv_spf13_hostap_cmd_is_ok(osw_drv_spf13_hostap_cmd_t *cmd)
{
    if (cmd == NULL) return true;
    const char *reply = osw_drv_spf13_hostap_cmd_get_reply(cmd);
    return strncmp(reply, "OK", 2) == 0;
}

osw_drv_spf13_hostap_cmd_t *osw_drv_spf13_hostap_cmd_new(
        int fd,
        const char *path,
        const char *request,
        void (*done_cb)(void *priv),
        void *priv)
{
    if (fd < 0)
    {
        LOGE(LOG_PREFIX("can't send hostapd command %s to %s, invalid file descriptor: %d"),
             request ?: "*",
             path ?: "*",
             fd);
        return NULL;
    }

    if (request == NULL)
    {
        LOGE(LOG_PREFIX("can't send hostapd command to %s, request is NULL"), path ?: "*");
        return NULL;
    }

    if (path == NULL)
    {
        LOGD(LOG_PREFIX("can't send hostapd command %s, path is NULL, instance probably not running"), request);
        return NULL;
    }

    osw_drv_spf13_hostap_cmd_t *cmd = CALLOC(1, sizeof(*cmd));
    cmd->started_on = clock_mono_ms();
    cmd->path = STRDUP(path);
    cmd->request = STRDUP(request);
    cmd->reply = NULL; /* will be filled later */
    cmd->done_cb = done_cb;
    cmd->priv = priv;

    ev_io_init(&cmd->io, osw_drv_spf13_hostap_cmd_io_cb, fd, EV_READ);
    cmd->io.data = cmd;

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    STRSCPY_WARN(addr.sun_path, path);

    const ssize_t send_err = sendto(fd, request, strlen(request), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (send_err < 0)
    {
        LOGD(LOG_PREFIX_HOSTAP_CMD(cmd, "failed to send request to hostapd: %s"), strerror(errno));
        osw_drv_spf13_hostap_cmd_drop(cmd);
        return NULL;
    }

    LOGD(LOG_PREFIX_HOSTAP_CMD(cmd, "sent request to hostapd"));
    ev_io_start(EV_DEFAULT_ & cmd->io);

    return cmd;
}

void osw_drv_spf13_hostap_cmd_expect_ok(osw_drv_spf13_hostap_cmd_t *cmd)
{
    if (cmd == NULL) return;

    const bool not_done_yet = !cmd->done;
    if (not_done_yet) return;

    const char *reply = osw_drv_spf13_hostap_cmd_get_reply(cmd);
    const bool starts_with_ok = reply != NULL && strncmp(reply, "OK", 2) == 0;
    if (starts_with_ok) return;

    LOGI(LOG_PREFIX_HOSTAP_CMD(cmd, "failed"));
}

osw_drv_spf13_hostap_cmd_t **osw_drv_spf13_hostap_cmd_extend(
        osw_drv_spf13_hostap_cmd_t **cmds,
        osw_drv_spf13_hostap_cmd_t *cmd)
{
    size_t count;
    for (count = 0; cmds != NULL && cmds[count] != NULL; count++)
    {
        /* Count the number of commands in the array */
    }
    cmds = REALLOC(cmds, (count + 2) * sizeof(*cmds));
    cmds[count] = cmd;
    cmds[count + 1] = NULL; /* NULL-terminate the array */
    return cmds;
}
