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
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* 3rd party */
#include <ev.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

/* opensync */
#include <os_time.h>
#include <memutil.h>
#include <log.h>
#include <util.h>
#include <log.h>
#include <const.h>

/* local */
#include "netlink/errno.h"
#include "netlink/socket.h"
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_nl_cmd.h"

#define LOG_PREFIX_NL_CMD(cmd, fmt, ...)        \
    LOG_PREFIX(                                 \
            "nl_cmd(fd=%d): %s: " fmt,          \
            (cmd) != NULL ? (cmd)->io.fd : -1,  \
            (cmd) != NULL ? (cmd)->id : "NULL", \
            ##__VA_ARGS__)

#define OSW_DRV_SPF13_NL_CMD_MIN_RETRY_DELAY_SEC 0.01f
#define OSW_DRV_SPF13_NL_CMD_MAX_RETRY_DELAY_SEC 0.1f

#define OSW_DRV_SPF13_NL_CMD_MAX_INTR_RETRIES 10

struct osw_drv_spf13_nl_cmd
{
    ev_io io;
    ev_timer intr_retry; /* used to handle NLE_DUMP_INTR */
    unsigned int intr_count;
    struct nl_sock *sock;
    char *id; /* Unique identifier for the command, used for logging */
    struct nl_msg *msg;
    struct nl_msg **resps; /* NULL terminated list of responses */
    void (*done_cb)(void *priv);
    void *priv;
    int error;
    bool done;
    int64_t started_on;
};

static size_t osw_drv_spf13_nl_cmd_num_resps(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL || cmd->resps == NULL) return 0;

    size_t i;
    for (i = 0; cmd->resps[i] != NULL; i++)
    {
        /* Count the number of responses */
    }
    return i;
}

static int osw_drv_spf13_nl_cmd_recv_cb(struct nl_msg *msg, void *arg)
{
    osw_drv_spf13_nl_cmd_t *cmd = (osw_drv_spf13_nl_cmd_t *)arg;
    if (cmd == NULL) return NL_SKIP;

    const size_t n = osw_drv_spf13_nl_cmd_num_resps(cmd);
    cmd->resps = REALLOC(cmd->resps, (n + 2) * sizeof(*cmd->resps));
    LOGD(LOG_PREFIX_NL_CMD(cmd, "received netlink at index %zu"), n);
    cmd->resps[n] = msg;
    cmd->resps[n + 1] = NULL; /* null-terminate the list */
    nlmsg_get(msg);           /* Increment the reference count of the message, so it can
                                 stay alive longer. It gets freed later in
                                 osw_drv_spf13_nl_cmd_drop() */
    return NL_OK;
}

static void osw_drv_spf13_nl_cmd_halt(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL) return;

    if (ev_is_active(&cmd->io))
    {
        ev_io_stop(EV_DEFAULT_ & cmd->io);
    }
}

static int osw_drv_spf13_nl_cmd_done_cb(struct nl_msg *msg, void *arg)
{
    osw_drv_spf13_nl_cmd_t *cmd = (osw_drv_spf13_nl_cmd_t *)arg;
    if (cmd == NULL) return NL_STOP;

    osw_drv_spf13_nl_cmd_halt(cmd);
    cmd->done = true;
    return NL_STOP;
}

static void osw_drv_spf13_nl_cmd_drop_resps(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL || cmd->resps == NULL) return;

    for (size_t i = 0; cmd->resps[i] != NULL; i++)
    {
        nlmsg_free(cmd->resps[i]);
    }
    FREE(cmd->resps);
    cmd->resps = NULL;
}

static void osw_drv_spf13_nl_cmd_handle_dump_intr(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL) return;
    const bool can_keep_retrying = cmd->intr_count < OSW_DRV_SPF13_NL_CMD_MAX_INTR_RETRIES;
    if (can_keep_retrying)
    {
        const float delay_range = OSW_DRV_SPF13_NL_CMD_MAX_RETRY_DELAY_SEC - OSW_DRV_SPF13_NL_CMD_MIN_RETRY_DELAY_SEC;
        const float delay = OSW_DRV_SPF13_NL_CMD_MIN_RETRY_DELAY_SEC + (rand() / (float)RAND_MAX) * delay_range;
        LOGI(LOG_PREFIX_NL_CMD(cmd, "received NLE_DUMP_INTR (count=%u), retrying in %.2f seconds"),
             cmd->intr_count,
             delay);
        cmd->intr_count++;
        cmd->done = false;
        cmd->error = 0;
        osw_drv_spf13_nl_cmd_drop_resps(cmd);
        osw_drv_spf13_nl_cmd_halt(cmd);
        ev_timer_stop(EV_DEFAULT_ & cmd->intr_retry);
        ev_timer_set(&cmd->intr_retry, delay, 0.0);
        ev_timer_start(EV_DEFAULT_ & cmd->intr_retry);
    }
    else
    {
        LOGW(LOG_PREFIX_NL_CMD(
                     cmd,
                     "received NLE_DUMP_INTR (count=%u), max retries reached, using possibly bogus responses"),
             cmd->intr_count);
    }
}

static void osw_drv_spf13_nl_cmd_notify_done(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL) return;

    void (*done_cb)(void *priv) = cmd->done_cb;
    cmd->done_cb = NULL;  // Clear the callback to avoid double calls
    if (done_cb != NULL)
    {
        done_cb(cmd->priv);
    }
}

static void osw_drv_spf13_nl_cmd_io_cb(EV_P_ ev_io *io, int revents)
{
    osw_drv_spf13_nl_cmd_t *cmd = io->data;
    if (cmd == NULL) return;

    const int err = nl_recvmsgs_default(cmd->sock);
    switch (err)
    {
        case -NLE_NOMEM:
            if (errno == ENOBUFS)
            {
                LOGN(LOG_PREFIX_NL_CMD(cmd, "netlink message overrun, expect missing responses"));
            }
            // FIXME: This could re-use the NLE_DUMP_INTR handling logic
            // but needs to drain the socket first before re-submitting the command.
            break;

        case -NLE_AGAIN:
            break;

        case -NLE_DUMP_INTR:
            /* Netlink dump commands are implemented in the kernel by calling the
             * underlying netlink's service dump() call. This means the underlying
             * service cannot or may not want to guarantee consistency for its data
             * structures across different calls. To signal that the data has changed
             * or is inconsistent, the kernel may return NLE_DUMP_INTR. This is
             * intended for userspace to attempt a retry in hopes of getting a
             * consistent view of the data.
             *
             * It would be dangerous to retry indefinitely so we limit the number of
             * retries with a random delay between them to make it more likely to grab
             * a proper dump.
             */
            osw_drv_spf13_nl_cmd_handle_dump_intr(cmd);
            break;

        case 0:
            break;

        default:
            LOGD(LOG_PREFIX_NL_CMD(cmd, "recvmsgs failed with error: %s (%d)"), nl_geterror(err), err);
            cmd->error = err;
            cmd->done = true;
            break;
    }

    if (cmd->done)
    {
        osw_drv_spf13_nl_cmd_halt(cmd);
        osw_drv_spf13_nl_cmd_notify_done(cmd);
        return;
    }
}

int osw_drv_spf13_nl_cmd_get_error(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL) return 0;
    return cmd->error;
}

void osw_drv_spf13_nl_cmd_drop(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL) return;

    LOGD(LOG_PREFIX_NL_CMD(cmd, "dropping command"));

    osw_drv_spf13_nl_cmd_halt(cmd);
    osw_drv_spf13_nl_cmd_drop_resps(cmd);

    if (ev_is_active(&cmd->intr_retry))
    {
        ev_timer_stop(EV_DEFAULT_ & cmd->intr_retry);
    }

    if (cmd->sock != NULL)
    {
        nl_socket_free(cmd->sock);
        cmd->sock = NULL;
    }

    if (cmd->msg != NULL)
    {
        nlmsg_free(cmd->msg);
        cmd->msg = NULL;
    }

    FREE(cmd->id);
    FREE(cmd);
}

static void osw_drv_spf13_nl_cmd_intr_retry_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_nl_cmd_t *cmd = w->data;
    if (cmd == NULL) return;

    /* The message was sent at least once already and it has been assigned a
     * specific sequence number. The socket tracks sequence numbers in order to
     * filter responses.
     *
     * Reset it back to NL_AUTO_SEQ so nl_send_auto_complete() can assign a new
     * one matching what the nl_sock expects.
     */
    struct nlmsghdr *nlh = nlmsg_hdr(cmd->msg);
    nlh->nlmsg_seq = NL_AUTO_SEQ;

    LOGD(LOG_PREFIX_NL_CMD(cmd, "retrying netlink command due to NLE_DUMP_INTR"));
    const int send_err = nl_send_auto_complete(cmd->sock, cmd->msg);
    if (send_err < 0)
    {
        LOGE(LOG_PREFIX_NL_CMD(cmd, "failed to send netlink message: %s (%d)"), nl_geterror(send_err), send_err);
        return;
    }

    ev_io_start(EV_DEFAULT_ & cmd->io);
}

osw_drv_spf13_nl_cmd_t *osw_drv_spf13_nl_cmd_new(
        struct nl_msg *msg,
        const char *id,
        void (*done_cb)(void *priv),
        void *priv)
{
    if (msg == NULL) return NULL;

    osw_drv_spf13_nl_cmd_t *cmd = CALLOC(1, sizeof(*cmd));
    ev_timer_init(&cmd->intr_retry, osw_drv_spf13_nl_cmd_intr_retry_cb, 0.0, 0.0);
    cmd->intr_retry.data = cmd;
    cmd->started_on = clock_mono_ms();
    cmd->id = STRDUP(id);
    cmd->msg = msg;
    cmd->resps = NULL;
    cmd->done = false;
    cmd->done_cb = done_cb;
    cmd->priv = priv;
    cmd->sock = nl_socket_alloc();
    if (cmd->sock == NULL)
    {
        LOGE(LOG_PREFIX_NL_CMD(cmd, "failed to allocate netlink socket"));
        osw_drv_spf13_nl_cmd_drop(cmd);
        return NULL;
    }

    if (genl_connect(cmd->sock) < 0)
    {
        LOGE(LOG_PREFIX_NL_CMD(cmd, "failed to connect to generic netlink"));
        osw_drv_spf13_nl_cmd_drop(cmd);
        return NULL;
    }

    nl_socket_modify_cb(cmd->sock, NL_CB_VALID, NL_CB_CUSTOM, osw_drv_spf13_nl_cmd_recv_cb, cmd);
    nl_socket_modify_cb(cmd->sock, NL_CB_ACK, NL_CB_CUSTOM, osw_drv_spf13_nl_cmd_done_cb, cmd);
    nl_socket_modify_cb(cmd->sock, NL_CB_FINISH, NL_CB_CUSTOM, osw_drv_spf13_nl_cmd_done_cb, cmd);
    nl_socket_set_nonblocking(cmd->sock);

    const int send_err = nl_send_auto_complete(cmd->sock, msg);
    if (send_err < 0)
    {
        LOGE(LOG_PREFIX_NL_CMD(cmd, "failed to send netlink message: %s (%d)"), nl_geterror(send_err), send_err);
        osw_drv_spf13_nl_cmd_drop(cmd);
        return NULL;
    }

    ev_io_init(&cmd->io, osw_drv_spf13_nl_cmd_io_cb, nl_socket_get_fd(cmd->sock), EV_READ);
    cmd->io.data = cmd;
    ev_io_start(EV_DEFAULT_ & cmd->io);

    LOGD(LOG_PREFIX_NL_CMD(cmd, "sent netlink message"));
    return cmd;
}

bool osw_drv_spf13_nl_cmd_is_done(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL) return true;
    return cmd->done;
}

struct nl_msg *osw_drv_spf13_nl_cmd_get_first_resp_only(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL || cmd->resps == NULL || cmd->resps[0] == NULL || cmd->resps[1] != NULL) return NULL;
    return cmd->resps[0];
}

struct nl_msg *osw_drv_spf13_nl_cmd_get_first_resp(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL || cmd->resps == NULL || cmd->resps[0] == NULL) return NULL;
    return cmd->resps[0];
}

struct nl_msg **osw_drv_spf13_nl_cmd_get_resps(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL || cmd->resps == NULL) return NULL;
    return cmd->resps;
}

const char *osw_drv_spf13_nl_cmd_get_id(osw_drv_spf13_nl_cmd_t *cmd)
{
    if (cmd == NULL) return NULL;
    return cmd->id;
}

static size_t osw_drv_spf13_nl_cmd_num_cmds(osw_drv_spf13_nl_cmd_t **cmds)
{
    if (cmds == NULL) return 0;

    size_t n = 0;
    while (cmds[n] != NULL)
    {
        n++;
    }
    return n;
}

osw_drv_spf13_nl_cmd_t **osw_drv_spf13_nl_cmd_extend(osw_drv_spf13_nl_cmd_t **cmds, osw_drv_spf13_nl_cmd_t *cmd)
{
    const size_t n = osw_drv_spf13_nl_cmd_num_cmds(cmds);
    cmds = REALLOC(cmds, (n + 2) * sizeof(*cmds));
    cmds[n] = cmd;
    cmds[n + 1] = NULL; /* null-terminate the list */
    return cmds;
}

bool osw_drv_spf13_nl_cmd_is_done_all(osw_drv_spf13_nl_cmd_t **cmd)
{
    if (cmd == NULL) return true;
    const size_t n = osw_drv_spf13_nl_cmd_num_cmds(cmd);
    size_t i;
    for (i = 0; i < n; i++)
    {
        if (!osw_drv_spf13_nl_cmd_is_done(cmd[i]))
        {
            return false;
        }
    }
    return true;
}

bool osw_drv_spf13_nl_cmd_is_done_array(osw_drv_spf13_nl_cmd_t **cmds, size_t n)
{
    if (cmds == NULL || n == 0) return true;
    size_t i;
    for (i = 0; i < n; i++)
    {
        if (!osw_drv_spf13_nl_cmd_is_done(cmds[i]))
        {
            return false;
        }
    }
    return true;
}

void osw_drv_spf13_nl_cmd_drop_all(osw_drv_spf13_nl_cmd_t **cmds)
{
    const size_t n = osw_drv_spf13_nl_cmd_num_cmds(cmds);
    size_t i;
    for (i = 0; i < n; i++)
    {
        osw_drv_spf13_nl_cmd_drop(cmds[i]);
        cmds[i] = NULL;
    }
    FREE(cmds);
}

void osw_drv_spf13_nl_cmd_drop_array(osw_drv_spf13_nl_cmd_t **cmds, size_t n)
{
    if (cmds == NULL || n == 0) return;
    size_t i;
    for (i = 0; i < n; i++)
    {
        osw_drv_spf13_nl_cmd_drop(cmds[i]);
        cmds[i] = NULL;
    }
}
