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

struct osw_plat_qsdk_nlcmd_resp
{
    struct nl_msg *first;
    struct nl_msg **msgs;
    size_t n_msgs;
};

struct osw_plat_qsdk_nlcmd
{
    struct osw_plat_qsdk11_4_async async;
    struct nl_80211 *nl;
    struct nl_msg *msg;
    struct nl_cmd *cmd;
    char *name;
    struct osw_plat_qsdk_nlcmd_resp resp_buf;
    struct osw_plat_qsdk_nlcmd_resp *resp;
};

#define LOG_PREFIX_NLCMD(ctx, fmt, ...) LOG_PREFIX("nlcmd: %s: " fmt, (ctx)->name, ##__VA_ARGS__)

static void osw_plat_qsdk_nlcmd_resp_cb(struct nl_cmd *cmd, struct nl_msg *msg, void *priv)
{
    struct osw_plat_qsdk_nlcmd *ctx = priv;
    struct osw_plat_qsdk_nlcmd_resp *resp = &ctx->resp_buf;
    const size_t elem_count = resp->n_msgs + 1;
    const size_t elem_size = sizeof(resp->msgs[0]);
    const size_t new_size = elem_size * elem_count;
    resp->msgs = REALLOC(resp->msgs, new_size);
    nlmsg_get(msg);
    resp->msgs[resp->n_msgs] = msg;
    if (resp->n_msgs == 0)
    {
        resp->first = resp->msgs[resp->n_msgs];
    }
    resp->n_msgs++;
    LOGD(LOG_PREFIX_NLCMD(ctx, "response %zu received", resp->n_msgs));
}

static void osw_plat_qsdk_nlcmd_done_cb(struct nl_cmd *cmd, void *priv)
{
    struct osw_plat_qsdk11_4_cb *waker = priv;
    osw_plat_qsdk11_4_cb_call(waker);
}

static enum osw_plat_qsdk11_4_async_result osw_plat_qsdk_nlcmd_poll_cb(void *priv, struct osw_plat_qsdk11_4_cb *waker)
{
    struct osw_plat_qsdk_nlcmd *ctx = priv;

    if (ctx->msg != NULL)
    {
        LOGD(LOG_PREFIX_NLCMD(ctx, "sending"));
        ASSERT(ctx->cmd == NULL, "");

        struct nl_conn *conn = nl_80211_get_conn(ctx->nl);
        ctx->cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(ctx->cmd, osw_plat_qsdk_nlcmd_resp_cb, ctx);
        nl_cmd_set_completed_fn(ctx->cmd, osw_plat_qsdk_nlcmd_done_cb, waker);
        nl_cmd_set_name(ctx->cmd, ctx->name);
        nl_cmd_set_msg(ctx->cmd, ctx->msg);
        ctx->msg = NULL;
    }

    if (nl_cmd_is_completed(ctx->cmd) == false)
    {
        LOGD(LOG_PREFIX_NLCMD(ctx, "pending"));
        return OSW_PLAT_QSDK11_4_ASYNC_PENDING;
    }

    if (ctx->resp != NULL)
    {
        memcpy(ctx->resp, &ctx->resp_buf, sizeof(*ctx->resp));
    }

    LOGD(LOG_PREFIX_NLCMD(ctx, "ready"));
    return OSW_PLAT_QSDK11_4_ASYNC_READY;
}

static void osw_plat_qsdk_nlcmd_drop_cb(void *priv)
{
    struct osw_plat_qsdk_nlcmd *ctx = priv;

    if (ctx->resp != NULL)
    {
        MEMZERO(*ctx->resp);
    }

    struct nl_cmd *cmd = ctx->cmd;
    ctx->cmd = NULL;
    nl_cmd_free(cmd);

    if (ctx->msg != NULL)
    {
        nlmsg_free(ctx->msg);
        ctx->msg = NULL;
    }

    struct osw_plat_qsdk_nlcmd_resp *resp = &ctx->resp_buf;
    size_t i;
    for (i = 0; i < resp->n_msgs; i++)
    {
        nlmsg_free(resp->msgs[i]);
    }

    FREE(resp->msgs);
    FREE(ctx->name);
    FREE(ctx);
}

static struct osw_plat_qsdk11_4_async *osw_plat_qsdk_nlcmd_alloc_resp(
        const char *name,
        struct nl_80211 *nl,
        struct nl_msg *msg,
        struct osw_plat_qsdk_nlcmd_resp *resp)
{
    struct osw_plat_qsdk_nlcmd *ctx = CALLOC(1, sizeof(*ctx));
    static const struct osw_plat_qsdk11_4_async_ops ops = {
        .poll_fn = osw_plat_qsdk_nlcmd_poll_cb,
        .drop_fn = osw_plat_qsdk_nlcmd_drop_cb,
    };
    ctx->nl = nl;
    ctx->name = STRDUP(name);
    ctx->msg = msg;
    ctx->resp = resp;
    LOGT(LOG_PREFIX_NLCMD(ctx, "allocated"));
    return osw_plat_qsdk11_4_async_impl(&ops, ctx);
}

static struct osw_plat_qsdk11_4_async *osw_plat_qsdk_nlcmd_alloc(
        const char *name,
        struct nl_80211 *nl,
        struct nl_msg *msg)
{
    return osw_plat_qsdk_nlcmd_alloc_resp(name, nl, msg, NULL);
}
