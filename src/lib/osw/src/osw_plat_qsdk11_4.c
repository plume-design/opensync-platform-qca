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
#include <string.h>
#include <limits.h>
#include <netinet/in.h>
//#include <net/if.h>
//#include <linux/if_arp.h> /* ARPHRD_IEEE80211 */
#include <glob.h>
#include <inttypes.h>

/* 3rd party */
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <linux/wireless.h>

/* opensync */
#include <ff_lib.h>
#include <kconfig.h>
#include <ds_tree.h>
#include <memutil.h>
#include <util.h>
#include <const.h>
#include <os_nif.h>
#include <log.h>
#include <rq.h>
#include <nl.h>
#include <nl_conn.h>
#include <nl_80211.h>
#include <nl_cmd_task.h>
#include <osn_netif.h>

#include <cr.h>
#include <cr_nl_cmd.h>
#include <cr_sleep.h>

/* osw */
#include <osw_drv.h>
#include <osw_state.h>
#include <osw_module.h>
#include <osw_drv_nl80211.h>
#include <osw_hostap.h>
#include <osw_drv_common.h>
#include <osw_time.h>
#include <osw_timer.h>
#include <osw_etc.h>

/* qsdk */
#define EXTERNAL_USE_ONLY
#define __bool_already_defined__
#ifndef __packed
#define __packed __attribute__((packed))
#endif

#if 0
#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN  1234
#endif
#ifndef _BIG_ENDIAN
#define _BIG_ENDIAN 4321
#endif

#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif
#endif

#include <ieee80211_external_config.h>
#include <qcatools_lib.h>
#include <ieee80211_defines.h>
//#include <ol_if_thermal.h>
//#include <qca-vendor.h>
#include <ext_ioctl_drv_if.h>
#include <cfg80211_external.h>
#include <if_athioctl.h>
#include <ieee80211_ioctl.h>
#include <dp_rate_stats_pub.h>
#include <ieee80211_ev.h>

#include "osw_plat_qsdk_qca_to_dfs_state.h"

/* Can't include this because headers are partially private.. god knows why */
#define QCA_VENDOR_OUI 0x001374

enum qca_wlan_genric_data {
    QCA_WLAN_VENDOR_ATTR_PARAM_INVALID = 0,
    QCA_WLAN_VENDOR_ATTR_PARAM_DATA,
    QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH,
    QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS,

    /* keep last */
    QCA_WLAN_VENDOR_ATTR_PARAM_LAST,
    QCA_WLAN_VENDOR_ATTR_PARAM_MAX = QCA_WLAN_VENDOR_ATTR_PARAM_LAST - 1
};

enum qca_wlan_get_params {
    QCA_WLAN_VENDOR_ATTR_GETPARAM_INVALID = 0,
    QCA_WLAN_VENDOR_ATTR_GETPARAM_COMMAND,

    /* keep last */
    QCA_WLAN_VENDOR_ATTR_GETPARAM_LAST,
    QCA_WLAN_VENDOR_ATTR_GETPARAM_MAX = QCA_WLAN_VENDOR_ATTR_GETPARAM_LAST - 1
};

#define OSW_PLAT_QSDK11_4_DRV_NAME "qsdk11_4_drv"

#define LOG_PREFIX(fmt, ...) \
    "osw: plat: qsdk11_4: " fmt, \
    ##__VA_ARGS__

#define LOG_PREFIX_PHY(phy_name, fmt, ...) \
    LOG_PREFIX("%s: " fmt, \
    phy_name, \
    ##__VA_ARGS__)

#define LOG_PREFIX_VIF(phy_name, vif_name, fmt, ...) \
    LOG_PREFIX_PHY(phy_name, "%s: " fmt, \
    vif_name, \
    ##__VA_ARGS__)

#define LOG_PREFIX_STA(phy_name, vif_name, sta_addr, fmt, ...) \
    LOG_PREFIX_VIF(phy_name, vif_name, OSW_HWADDR_FMT": " fmt, \
    OSW_HWADDR_ARG(sta_addr), \
    ##__VA_ARGS__)

#define LOG_PREFIX_MLD_STA(mld_sta, fmt, ...) \
    LOG_PREFIX("%s: " fmt, \
    (mld_sta)->mld_name, \
    ##__VA_ARGS__)

#define QCA_WIFI_MC_ME_DISABLE 0
#define QCA_WIFI_MC_ME_HYFI 5
#define QCA_WIFI_MC_ME_AMSDU 6

/* Unfortunately QCA SDK headers introduce conflicts with
 * net/if.h. There's nothing special about the function to
 * extern so might as well just explicitly extern it by
 * hand.
 */
extern unsigned int if_nametoindex(const char *ifname);

/* FIXME:
 *
 * This needs either to pre-allocate all known interface
 * names or supplement state reports based on ow_conf in
 * order to fake state reports so that it can implicitly
 * create arbitrary interface names on demand.
 *
 * Or to extend the osw_conf to allow adding new vifs even
 * if they dont exist in the base state, meaning
 * osw_confsync would need to probably be changed to handle
 * this properly too.
 */

static void
osw_plat_qsdk11_4_put_qca_vendor_cmd(struct nl_msg *msg,
                                     int family_id,
                                     uint32_t ifindex,
                                     uint32_t vendor_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, */
                                     uint32_t generic_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS, */
                                     uint32_t value,
                                     uint32_t flags,
                                     const void *data,
                                     size_t len)
{
    /* FIXME: check nla_put() results */
    const int genl_flags = 0;
    const int genl_cmd = NL80211_CMD_VENDOR;
    const int hdrlen = 0;
    const int version = 0;
    WARN_ON(genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, hdrlen, genl_flags, genl_cmd, version) == NULL);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, QCA_VENDOR_OUI);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, vendor_cmd);
    struct nlattr *vdata = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, generic_cmd);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_FLAGS, flags);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, value);
    if (data != NULL) {
        nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_LENGTH, len);
        nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA, len, data);
    }
    nla_nest_end(msg, vdata);
}

static void
osw_plat_qsdk11_4_put_qca_vendor_setparam(struct nl_msg *msg,
                                          int family_id,
                                          uint32_t ifindex,
                                          uint32_t vendor_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, */
                                          uint32_t generic_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, */
                                          uint32_t param_id,
                                          const void *data,
                                          size_t len)
{
    return osw_plat_qsdk11_4_put_qca_vendor_cmd(msg, family_id, ifindex, vendor_cmd, generic_cmd, param_id, 0, data, len);
}

static void
osw_plat_qsdk11_4_put_qca_vendor_getparam(struct nl_msg *msg,
                                          int family_id,
                                          uint32_t ifindex,
                                          uint32_t vendor_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, */
                                          uint32_t generic_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, */
                                          uint32_t param_id /* eg. IEEE80211_PARAM_ME */)
{
    return osw_plat_qsdk11_4_put_qca_vendor_cmd(msg, family_id, ifindex, vendor_cmd, generic_cmd, param_id, 0, NULL, 0);
}

static const void *
osw_plat_qsdk11_4_param_get_data(struct nl_msg *msg,
                                 int *len)
{
    if (msg == NULL) return NULL;

    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    const int err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, NL80211_ATTR_MAX, NULL);
    if (WARN_ON(err)) return NULL;

    struct nlattr *vendor = tb[NL80211_ATTR_VENDOR_DATA];
    if (WARN_ON(vendor == NULL)) return NULL;

    struct nlattr *tbv[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1];
    const int verr = nla_parse_nested(tbv, QCA_WLAN_VENDOR_ATTR_PARAM_MAX, vendor, NULL);
    if (WARN_ON(verr)) return NULL;

    struct nlattr *data = tbv[QCA_WLAN_VENDOR_ATTR_PARAM_DATA];
    struct nlattr *length = tbv[QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH];

    if (WARN_ON(data == NULL)) return NULL;

    const void *buf = nla_data(data);
    *len = nla_len(data);

    WARN_ON(length != NULL && nla_get_u32(length) != (uint32_t)*len);
    return buf;
}

static const uint32_t *
osw_plat_qsdk11_4_param_get_u32(struct nl_msg *msg)
{
    int len;
    const uint32_t *p = osw_plat_qsdk11_4_param_get_data(msg, &len);
    if (p == NULL) return NULL;
    if (WARN_ON(len != sizeof(uint32_t))) return NULL;
    return p;
}

struct osw_plat_qsdk11_4_get_param_arg {
    void *out;
    size_t out_size;
    bool not_enough_space;
    bool done;
};

static void
osw_plat_qsdk11_4_get_param_resp_cb(struct nl_cmd *cmd,
                                    struct nl_msg *msg,
                                    void *priv)
{
    struct osw_plat_qsdk11_4_get_param_arg *arg = priv;
    int len;
    const void *buf = osw_plat_qsdk11_4_param_get_data(msg, &len);
    if (buf == NULL) return;

    if ((size_t)len > arg->out_size) {
        len = arg->out_size;
        arg->not_enough_space = true;
    }

    arg->done = true;
    if (arg->out == NULL) return;

    memcpy(arg->out, buf, len);
}

static int
chan_to_dfs_idx(int chan)
{
    const int first_dfs = 52;
    const int spacing = 4;
    const int last_idx = NUM_DFS_CHANS - 1;
    if (chan < first_dfs) return -1;
    const int idx = (chan - first_dfs) / spacing;
    if (idx > last_idx) return -1;
    return idx;
}

static void
osw_plat_qsdk11_4_fill_chan_states(const char *phy_name,
                                   const struct ieee80211req_chaninfo_full *chans,
                                   struct osw_drv_phy_state *state)
{
    const struct ieee80211_ath_channel *arr = chans->req_chan_info.ic_chans;
    size_t i;
    for (i = 0; i < state->n_channel_states; i++) {
        struct osw_channel_state *cs = &state->channel_states[i];
        const struct osw_channel *c = &cs->channel;
        const uint32_t freq = c->control_freq_mhz;
        const int chan = osw_freq_to_chan(freq);
        bool is_dfs = false;
        size_t j;
        for (j = 0; j < chans->req_chan_info.ic_nchans; j++) {
            const struct ieee80211_ath_channel *ac = &arr[j];
            if (ac->ic_ieee == chan) {
                if (ac->ic_flagext & IEEE80211_CHAN_DFS) {
                    is_dfs = true;
                }
                break;
            }
        }
        if (is_dfs == false) continue;
        const int dfs_idx = chan_to_dfs_idx(chan);
        if (WARN_ON(dfs_idx < 0)) continue;
        const enum wlan_channel_dfs_state dfs_state = chans->dfs_chan_state_arr[dfs_idx];
        enum osw_channel_state_dfs new_state = osw_plat_qsdk_qca_to_dfs_state(dfs_state);
        LOGD(LOG_PREFIX_PHY(phy_name, "fix: chan: %d: dfs %d -> %d",
                            chan, cs->dfs_state,
                            new_state));
        cs->dfs_state = new_state;
    }
}

typedef void
osw_plat_qsdk11_4_cb_fn_t(void *priv);

struct osw_plat_qsdk11_4_cb {
    osw_plat_qsdk11_4_cb_fn_t *fn;
    void *priv;
};

static void
osw_plat_qsdk11_4_cb_call(const struct osw_plat_qsdk11_4_cb *cb)
{
    if (cb == NULL) return;
    if (cb->fn == NULL) return;
    cb->fn(cb->priv);
}

enum osw_plat_qsdk11_4_async_result {
    OSW_PLAT_QSDK11_4_ASYNC_PENDING,
    OSW_PLAT_QSDK11_4_ASYNC_READY,
};

typedef enum osw_plat_qsdk11_4_async_result
osw_plat_qsdk11_4_async_poll_fn_t(void *priv,
                                  struct osw_plat_qsdk11_4_cb *waker);

typedef void
osw_plat_qsdk11_4_async_drop_fn_t(void *priv);

struct osw_plat_qsdk11_4_async_ops {
    osw_plat_qsdk11_4_async_poll_fn_t *poll_fn;
    osw_plat_qsdk11_4_async_drop_fn_t *drop_fn;
};

struct osw_plat_qsdk11_4_async {
    const struct osw_plat_qsdk11_4_async_ops *ops;
    enum osw_plat_qsdk11_4_async_result state;
    void *priv;
    bool polling;
};

static struct osw_plat_qsdk11_4_async *
osw_plat_qsdk11_4_async_impl(const struct osw_plat_qsdk11_4_async_ops *ops,
                             void *priv)
{
    struct osw_plat_qsdk11_4_async *async = CALLOC(1, sizeof(*async));
    async->ops = ops;
    async->priv = priv;
    async->state = OSW_PLAT_QSDK11_4_ASYNC_PENDING;
    return async;
}

enum osw_plat_qsdk11_4_async_result
osw_plat_qsdk11_4_async_poll(struct osw_plat_qsdk11_4_async *async,
                             struct osw_plat_qsdk11_4_cb *waker)
{
    if (async == NULL) return OSW_PLAT_QSDK11_4_ASYNC_READY;
    if (async->ops == NULL) return OSW_PLAT_QSDK11_4_ASYNC_READY;
    if (async->ops->poll_fn == NULL) return OSW_PLAT_QSDK11_4_ASYNC_READY;
    if (WARN_ON(waker == NULL)) return  OSW_PLAT_QSDK11_4_ASYNC_READY;
    if (WARN_ON(async->polling)) return OSW_PLAT_QSDK11_4_ASYNC_PENDING;
    if (async->state == OSW_PLAT_QSDK11_4_ASYNC_PENDING) {
        async->polling = true;
        async->state = async->ops->poll_fn(async->priv, waker);
        async->polling = false;
    }
    return async->state;
}

static void
osw_plat_qsdk11_4_async_drop(struct osw_plat_qsdk11_4_async *async)
{
    if (async == NULL) return;
    if (async->ops != NULL && async->ops->drop_fn != NULL) async->ops->drop_fn(async->priv);
    FREE(async);
}

static void
osw_plat_qsdk11_4_async_drop_safe(struct osw_plat_qsdk11_4_async **async)
{
    osw_plat_qsdk11_4_async_drop(*async);
    *async = NULL;
}

enum osw_plat_qsdk11_4_param_u32_policy {
    OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
    OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL,
    OSW_PLAT_QSDK11_4_PARAM_SET_BITMASK,
};

struct osw_plat_qsdk11_4_param_u32_arg {
    struct nl_80211 *nl;
    enum osw_plat_qsdk11_4_param_u32_policy policy;
    uint32_t ifindex;
    uint32_t cmd_id;
    uint32_t param_id;
    uint32_t desired_value;
    uint32_t desired_bits_set;
    uint32_t desired_bits_mask;
    const char *vif_name;
    const char *param_name;
};

#define PARAM_U32_ARG(...) \
    ((struct osw_plat_qsdk11_4_param_u32_arg []) {__VA_ARGS__})

struct osw_plat_qsdk11_4_param_u32 {
    struct osw_plat_qsdk11_4_param_u32_arg arg;
    struct nl_cmd *get_cmd;
    struct nl_cmd *set_cmd;
    struct osw_plat_qsdk11_4_get_param_arg param;
    uint32_t current_value;
};

#define LOG_PREFIX_PARAM_U32(param, fmt, ...) \
    LOG_PREFIX("%s: %s: " fmt, \
               param->arg.vif_name, \
               param->arg.param_name, \
               ## __VA_ARGS__)

static void
osw_plat_qsdk11_4_param_u32_done_cb(struct nl_cmd *cmd, void *priv)
{
    struct osw_plat_qsdk11_4_cb *waker = priv;
    osw_plat_qsdk11_4_cb_call(waker);
}

static enum osw_plat_qsdk11_4_async_result
osw_plat_qsdk11_4_param_u32_poll_cb(void *priv,
                                    struct osw_plat_qsdk11_4_cb *waker)
{
    struct osw_plat_qsdk11_4_param_u32 *ctx = priv;
    struct osw_plat_qsdk11_4_param_u32_arg *arg = &ctx->arg;
    const enum osw_plat_qsdk11_4_param_u32_policy policy = arg->policy;
    struct nl_cmd **get_cmd = &ctx->get_cmd;
    struct nl_cmd **set_cmd = &ctx->set_cmd;
    struct nl_80211 *nl = arg->nl;
    const int family_id = nl_80211_get_family_id(nl);
    const uint32_t ifindex = arg->ifindex;
    const uint32_t cmd_id = arg->cmd_id;
    const uint32_t param_id = arg->param_id;

    switch (policy) {
        case OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS:
            break;
        case OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL:
        case OSW_PLAT_QSDK11_4_PARAM_SET_BITMASK:
            if (*get_cmd == NULL) {
                LOGT(LOG_PREFIX_PARAM_U32(ctx, "get: start"));

                memset(&ctx->param, 0, sizeof(ctx->param));
                ctx->param.out = &ctx->current_value;
                ctx->param.out_size = sizeof(&ctx->current_value);

                struct nl_conn *conn = nl_80211_get_conn(nl);
                struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
                struct nl_msg *msg = nlmsg_alloc();
                const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
                osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, cmd_id, param_id);
                nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, &ctx->param);
                nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_PARAM_U32(ctx, "get")));
                nl_cmd_set_msg(cmd, msg);
                *get_cmd = cmd;
            }
            nl_cmd_set_completed_fn(*get_cmd, osw_plat_qsdk11_4_param_u32_done_cb, waker);
            if (nl_cmd_is_completed(*get_cmd) == false) {
                return OSW_PLAT_QSDK11_4_ASYNC_PENDING;
            }
            else if (nl_cmd_is_failed(*get_cmd)) {
                LOGW(LOG_PREFIX_PARAM_U32(ctx, "get: failed: nl failure"));
                return OSW_PLAT_QSDK11_4_ASYNC_READY;
            }
            else if (ctx->param.done == false) {
                LOGW(LOG_PREFIX_PARAM_U32(ctx, "get: failed: no response"));
                return OSW_PLAT_QSDK11_4_ASYNC_READY;
            }
            LOGT(LOG_PREFIX_PARAM_U32(ctx, "get: read: dec %"PRIu32" hex 0x%08"PRIx32,
                                      ctx->current_value,
                                      ctx->current_value));
            break;
    }

    uint32_t value_to_set = 0;
    switch (policy) {
        case OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS:
            value_to_set = arg->desired_value;
            break;
        case OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL:
            if (arg->desired_value == ctx->current_value) {
                LOGT(LOG_PREFIX_PARAM_U32(ctx, "policy: already equal"));
                return OSW_PLAT_QSDK11_4_ASYNC_READY;
            }

            value_to_set = arg->desired_value;
            break;
        case OSW_PLAT_QSDK11_4_PARAM_SET_BITMASK:
            {
                const uint32_t value = ctx->current_value;
                const uint32_t mask = arg->desired_bits_mask;
                const uint32_t bits = arg->desired_bits_set;
                const bool already_set = ((value & mask) == bits);
                if (already_set) {
                    LOGT(LOG_PREFIX_PARAM_U32(ctx, "policy: already contains 0x%08"PRIx32" masked 0x%08"PRIx32,
                                              arg->desired_bits_set,
                                              arg->desired_bits_mask));
                    return OSW_PLAT_QSDK11_4_ASYNC_READY;
                }

                value_to_set = ctx->current_value;
                value_to_set &= ~mask;
                value_to_set |= bits;
            }
            break;
    }

    if (*set_cmd == NULL) {
        LOGT(LOG_PREFIX_PARAM_U32(ctx, "set: start: %"PRIu32" -> %"PRIu32,
                                  ctx->current_value,
                                  value_to_set));

        struct nl_conn *conn = nl_80211_get_conn(nl);
        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        struct nl_msg *msg = nlmsg_alloc();
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
        osw_plat_qsdk11_4_put_qca_vendor_setparam(msg, family_id, ifindex, vcmd, cmd_id, param_id, &value_to_set, sizeof(value_to_set));
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_PARAM_U32(ctx, "set")));
        nl_cmd_set_msg(cmd, msg);
        *set_cmd = cmd;
    }
    nl_cmd_set_completed_fn(*set_cmd, osw_plat_qsdk11_4_param_u32_done_cb, waker);
    if (nl_cmd_is_completed(*set_cmd) == false) {
        return OSW_PLAT_QSDK11_4_ASYNC_PENDING;
    }
    else if (nl_cmd_is_failed(*set_cmd)) {
        LOGW(LOG_PREFIX_PARAM_U32(ctx, "set: failed"));
        return OSW_PLAT_QSDK11_4_ASYNC_READY;
    }

    LOGT(LOG_PREFIX_PARAM_U32(ctx, "done"));
    return OSW_PLAT_QSDK11_4_ASYNC_READY;
}

static void
osw_plat_qsdk11_4_param_u32_drop_cb(void *priv)
{
    struct osw_plat_qsdk11_4_param_u32 *ctx = priv;
    if (ctx == NULL) return;

    struct nl_cmd *get_cmd = ctx->get_cmd;
    struct nl_cmd *set_cmd = ctx->set_cmd;
    ctx->get_cmd = NULL;
    ctx->set_cmd = NULL;
    nl_cmd_free(get_cmd);
    nl_cmd_free(set_cmd);

    FREE(ctx);
}

static struct osw_plat_qsdk11_4_async *
osw_plat_qsdk11_4_param_u32_alloc(const struct osw_plat_qsdk11_4_param_u32_arg *arg)
{
    struct osw_plat_qsdk11_4_param_u32 *ctx = CALLOC(1, sizeof(*ctx));
    static const struct osw_plat_qsdk11_4_async_ops ops = {
        .poll_fn = osw_plat_qsdk11_4_param_u32_poll_cb,
        .drop_fn = osw_plat_qsdk11_4_param_u32_drop_cb,
    };
    ctx->arg = *arg;
    return osw_plat_qsdk11_4_async_impl(&ops, ctx);
}

struct osw_plat_qsdk11_4_mbss_tx_vdev {
    struct osw_plat_qsdk11_4_async async;
    struct osw_plat_qsdk11_4_async *job_param;
    struct osw_drv_nl80211_ops *nl_ops;
    char *phy_name;
    char *vif_name;
    uint32_t ifindex;
    bool pulled_down;
    bool pulled_up;
};

#define LOG_PREFIX_MBSS_TX_VDEV(ctx, fmt, ...) \
    LOG_PREFIX("%s/%s: mbss_tx_vdev: " fmt, \
               (ctx)->phy_name, \
               (ctx)->vif_name, \
               ## __VA_ARGS__)

static enum osw_plat_qsdk11_4_async_result
osw_plat_qsdk11_4_mbss_tx_vdev_poll_cb(void *priv,
                                       struct osw_plat_qsdk11_4_cb *waker)
{
    struct osw_plat_qsdk11_4_mbss_tx_vdev *ctx = priv;
    char *phy_name = ctx->phy_name;

    if (ctx->pulled_down == false) {
        LOGT(LOG_PREFIX_MBSS_TX_VDEV(ctx, "phy: bringing down"));
        const bool down_failed = (os_nif_up(phy_name, false) == false);
        WARN_ON(down_failed);
        ctx->pulled_down = true;
    }

    if (ctx->job_param == NULL) {
        LOGT(LOG_PREFIX_MBSS_TX_VDEV(ctx, "param: allocating"));

        const uint32_t ifindex = ctx->ifindex;
        const char *vif_name = ctx->vif_name;
        struct osw_drv_nl80211_ops *nl_ops = ctx->nl_ops;

        struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
        if (WARN_ON(nl == NULL)) {
            return OSW_PLAT_QSDK11_4_ASYNC_READY;
        }

        const struct osw_plat_qsdk11_4_param_u32_arg arg = {
            .nl = nl,
            .ifindex = ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_MBSS_TXVDEV,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = 1,
            .vif_name = vif_name,
            .param_name = "mbss_tx_vdev",
        };
        ctx->job_param = osw_plat_qsdk11_4_param_u32_alloc(&arg);
    }

    const enum osw_plat_qsdk11_4_async_result result = osw_plat_qsdk11_4_async_poll(ctx->job_param, waker);
    switch (result) {
        case OSW_PLAT_QSDK11_4_ASYNC_PENDING:
            LOGT(LOG_PREFIX_MBSS_TX_VDEV(ctx, "param: pending"));
            return OSW_PLAT_QSDK11_4_ASYNC_PENDING;
        case OSW_PLAT_QSDK11_4_ASYNC_READY:
            LOGT(LOG_PREFIX_MBSS_TX_VDEV(ctx, "param: ready"));
            break;
    }

    if (ctx->pulled_up == false) {
        LOGT(LOG_PREFIX_MBSS_TX_VDEV(ctx, "phy: bringing up"));
        const bool up_failed = (os_nif_up(phy_name, true) == false);
        WARN_ON(up_failed);
        ctx->pulled_up = true;
    }

    return OSW_PLAT_QSDK11_4_ASYNC_READY;
}

static void
osw_plat_qsdk11_4_mbss_tx_vdev_drop_cb(void *priv)
{
    struct osw_plat_qsdk11_4_mbss_tx_vdev *ctx = priv;
    if (ctx == NULL) return;

    LOGT(LOG_PREFIX_MBSS_TX_VDEV(ctx, "dropping"));
    osw_plat_qsdk11_4_async_drop(ctx->job_param);
    FREE(ctx->phy_name);
    FREE(ctx->vif_name);
    FREE(ctx);
}

static struct osw_plat_qsdk11_4_async *
osw_plat_qsdk11_4_mbss_tx_vdev_alloc(struct osw_drv_nl80211_ops *nl_ops,
                                     const char *phy_name,
                                     const char *vif_name,
                                     uint32_t ifindex)
{
    struct osw_plat_qsdk11_4_mbss_tx_vdev *ctx = CALLOC(1, sizeof(*ctx));
    static const struct osw_plat_qsdk11_4_async_ops ops = {
        .poll_fn = osw_plat_qsdk11_4_mbss_tx_vdev_poll_cb,
        .drop_fn = osw_plat_qsdk11_4_mbss_tx_vdev_drop_cb,
    };
    ctx->nl_ops = nl_ops;
    ctx->phy_name = STRDUP(phy_name);
    ctx->vif_name = STRDUP(vif_name);
    ctx->ifindex = ifindex;
    LOGT(LOG_PREFIX_MBSS_TX_VDEV(ctx, "allocated"));
    return osw_plat_qsdk11_4_async_impl(&ops, ctx);
}

#include "osw_plat_qsdk_wifi_defs.h"
#include "osw_plat_qsdk_translate.h"
#include "osw_plat_qsdk_nl80211_msg.c.h"
#include "osw_plat_qsdk_nlcmd.c.h"
#include "osw_plat_qsdk_job_mode_upgrade.c.h"
#include "osw_plat_qsdk_jobqueue.c.h"
#include "osw_plat_qsdk_jobqueue_acl.c.h"

static struct nlattr *
osw_plat_qsdk_attr_mld_mac(struct nlattr **tb)
{
#ifdef WLAN_FEATURE_11BE
    /* This is apparently a vendor specific ABI breaking
     * nl80211.h change.
     *
     * This attribute can appear in Affiliated netdevs to
     * point to a master bonding netdev.
     */
    return tb[NL80211_ATTR_MLD_MAC];
#else
    return NULL;
#endif
}

static const struct osw_hwaddr *
osw_plat_qsdk_isi_mld_addr(const struct ieee80211req_sta_info *sta)
{
#ifdef WLAN_FEATURE_11BE
    if (sta->isi_is_mlo) {
        return osw_hwaddr_from_cptr_unchecked(sta->isi_mldaddr);
    }
#endif
    return NULL;
}

typedef void
osw_plat_qsdk11_4_task_completed_fn_t(void *priv);

struct osw_plat_qsdk11_4_task {
    ev_async ev_async;
    struct ev_loop *loop;
    struct osw_plat_qsdk11_4_cb waker;
    struct osw_plat_qsdk11_4_async *async;
    osw_plat_qsdk11_4_task_completed_fn_t *completed_fn;
    void *priv;
};

static void
osw_plat_qsdk11_4_task_drop(struct osw_plat_qsdk11_4_task *task)
{
    osw_plat_qsdk11_4_async_drop(task->async);
    ev_async_stop(task->loop, &task->ev_async);
    task->async = NULL;
}

static void
osw_plat_qsdk11_4_task_drop_when_done_cb(void *priv)
{
    struct osw_plat_qsdk11_4_task *task = priv;
    osw_plat_qsdk11_4_task_drop(task);
}

static void
osw_plat_qsdk11_4_task_ev_cb(struct ev_loop *loop,
                             ev_async *ev_async,
                             int revents)
{
    struct osw_plat_qsdk11_4_task *task = ev_async->data;
    const enum osw_plat_qsdk11_4_async_result result = osw_plat_qsdk11_4_async_poll(task->async, &task->waker);
    switch (result) {
        case OSW_PLAT_QSDK11_4_ASYNC_PENDING:
            break;
        case OSW_PLAT_QSDK11_4_ASYNC_READY:
            if (task->completed_fn != NULL) {
                task->completed_fn(task->priv);
                return;
            }
            break;
    }
}

static void
osw_plat_qsdk11_4_task_wake_cb(void *priv)
{
    struct osw_plat_qsdk11_4_task *task = priv;
    if (ev_is_active(&task->ev_async)) {
        ev_async_send(task->loop, &task->ev_async);
    }
    else {
        WARN_ON(1);
    }
}

static void
osw_plat_qsdk11_4_task_init(struct osw_plat_qsdk11_4_task *task,
                            osw_plat_qsdk11_4_task_completed_fn_t *completed_fn,
                            void *priv)
{
    ev_async_init(&task->ev_async, osw_plat_qsdk11_4_task_ev_cb);
    task->ev_async.data = task;
    task->loop = EV_DEFAULT;
    task->waker.fn = osw_plat_qsdk11_4_task_wake_cb;
    task->waker.priv = task;
    task->completed_fn = completed_fn;
    task->priv = priv;
}

static void
osw_plat_qsdk11_4_task_init_auto(struct osw_plat_qsdk11_4_task *task)
{
    osw_plat_qsdk11_4_task_init(task,
                                osw_plat_qsdk11_4_task_drop_when_done_cb,
                                task);
}

static void
osw_plat_qsdk11_4_task_start(struct osw_plat_qsdk11_4_task *task,
                             struct osw_plat_qsdk11_4_async *async)
{
    osw_plat_qsdk11_4_task_drop(task);
    task->async = async;
    ev_async_start(task->loop, &task->ev_async);
    osw_plat_qsdk11_4_cb_call(&task->waker);
}

#define PARAM_U32_TASK_START(task, arg) \
    osw_plat_qsdk11_4_task_start(task, osw_plat_qsdk11_4_param_u32_alloc(arg))

/*
NL80211_CMD_VENDOR

NL80211_ATTR_VENDOR_ID    QCA_VENDOR_OUI
NL80211_ATTR_VENDOR_SUBCMD cmdid
NL80211_ATTR_IFINDEX
nla = nla_nest_start NL80211_ATTR_VENDOR_DATA

QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_LENGTH u32 
QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND u32 
QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_FLAGS u32 
QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_PARAM u32 
QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA data 

nla_nest_end(msg, nla)

->
NL80211_ATTR_VENDOR_DATA
 -> DATA + LENGTH
 (attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA])o
 nla_get_u32(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH]);

*/

/* This is the global module state. Anything
 * long-running (sockets, observers) should go
 * here.
 */
struct osw_plat_qsdk11_4 {
    struct osw_state_observer state_obs;
    struct osw_drv_nl80211_ops *nl_ops;
    struct osw_drv_nl80211_hook *nl_hook;
    struct osw_hostap *hostap;
    struct osw_hostap_hook *hostap_hook;
    struct osw_drv *drv_nl80211;
    struct nl_conn *nl_conn;
    struct nl_conn_subscription *nl_conn_sub;
    struct nl_80211_sub *nl_sub;
    struct ev_io wext_io;
    struct ds_tree mld_stas;

    /* FIXME: This should open up its own personal
     * netlink socket to handle vendor specific
     * commands and events.
     */
};

#define util_nl_each_msg(buf, hdr, len) \
    for (hdr = buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len))

#define util_nl_each_msg_type(buf, hdr, len, type) \
    util_nl_each_msg(buf, hdr, len) \
        if (hdr->nlmsg_type == type)

#define util_nl_each_attr(hdr, attr, attrlen) \
    for (attr = NLMSG_DATA(hdr) + NLMSG_ALIGN(sizeof(struct ifinfomsg)), \
         attrlen = NLMSG_PAYLOAD(hdr, sizeof(struct ifinfomsg)); \
         RTA_OK(attr, attrlen); \
         attr = RTA_NEXT(attr, attrlen))

#define util_nl_each_attr_type(hdr, attr, attrlen, type) \
    util_nl_each_attr(hdr, attr, attrlen) \
        if (attr->rta_type == type)

#define util_nl_iwe_data(iwe) \
    ((void *)(iwe) + IW_EV_LCP_LEN)

#define util_nl_iwe_payload(iwe) \
    ((iwe)->len - IW_EV_POINT_LEN)

#define util_nl_iwe_next(iwe, iwelen) \
    ( (iwelen) -= (iwe)->len, (void *)(iwe) + (iwe)->len )

#define util_nl_iwe_ok(iwe, iwelen) \
    ((iwelen) >= (iwe)->len && (iwelen) > 0)

#define util_nl_each_iwe(attr, iwe, iwelen) \
    for (iwe = RTA_DATA(attr), \
         iwelen = RTA_PAYLOAD(attr); \
         util_nl_iwe_ok(iwe, iwelen); \
         iwe = util_nl_iwe_next(iwe, iwelen))

#define util_nl_each_iwe_type(attr, iwe, iwelen, type) \
    util_nl_each_iwe(attr, iwe, iwelen) \
        if (iwe->cmd == type)

struct osw_plat_qsdk11_4_phy {
    struct osw_plat_qsdk11_4 *m;
    const struct nl_80211_phy *info;
    struct osw_plat_qsdk11_4_task task_mbss_tx_vdev;
    struct osw_plat_qsdk11_4_task task_set_puncture_strict;
    struct osw_plat_qsdk11_4_task task_set_puncture_dfs;
    struct osw_plat_qsdk11_4_task task_set_next_radar_freq;
    struct osw_plat_qsdk11_4_task task_set_next_radar_width;
    osn_netif_t *netif;
};

struct osw_plat_qsdk11_4_mld_sta {
    char *mld_name;
    struct osw_plat_qsdk11_4 *m;
    struct osw_drv_vif_state_sta_link link;
    struct ds_tree_node node;
    struct ds_tree vifs;
};

struct osw_plat_qsdk11_4_vif {
    struct osw_plat_qsdk11_4 *m;
    const struct nl_80211_vif *info;
    struct osw_plat_qsdk11_4_mld_sta *mld_sta;
    struct osw_drv_vif_state_sta_link link;
    struct ds_tree_node node_mld_sta;
    struct rq q_stats;
    struct rq q_state;
    struct nl_cmd_task task_get_chanlist;
    struct nl_cmd_task task_get_mcast2ucast;
    struct nl_cmd_task task_get_mgmt_rate;
    struct nl_cmd_task task_get_mcast_rate;
    struct nl_cmd_task task_get_bcast_rate;
    struct nl_cmd_task task_get_beacon_rate;
    struct nl_cmd_task task_get_max_rate;
    struct nl_cmd_task task_get_cac_state;
    struct nl_cmd_task task_get_rrm;
    struct nl_cmd_task task_get_mbss_en;
    struct nl_cmd_task task_get_mbss_tx_vdev;
    struct nl_cmd_task task_get_next_radar_freq;
    struct nl_cmd_task task_get_next_radar_width;
    struct nl_cmd_task task_get_ap_bridge;
    struct nl_cmd_task task_get_puncture_bitmap;
    struct nl_cmd_task task_get_regdomain;
    struct nl_cmd_task task_get_country_id;
    struct nl_cmd_task task_get_country;
    struct nl_cmd_task task_get_wds;
    struct nl_cmd_task task_get_mbss_group;
    struct nl_cmd_task task_survey;
    struct osw_plat_qsdk11_4_task param_set_dbdc_enable;
    struct osw_plat_qsdk11_4_task param_set_dbdc_samessiddisable;
    struct osw_plat_qsdk11_4_task param_set_min_rssi_min;
    struct osw_plat_qsdk11_4_task param_set_frame_fwd;
    struct osw_plat_qsdk11_4_task param_set_frame_mask;
    struct osw_plat_qsdk11_4_task param_set_ol_stats;
    struct osw_plat_qsdk11_4_task param_set_flush_stats;
    struct osw_plat_qsdk11_4_task param_set_mcast2ucast;
    struct osw_plat_qsdk11_4_task param_set_rrm;
    struct osw_plat_qsdk11_4_task param_set_ap_bridge;
    struct osw_plat_qsdk11_4_task param_set_mgmt_rate;
    struct osw_plat_qsdk11_4_task param_set_mcast_rate;
    struct osw_plat_qsdk11_4_task param_set_bcast_rate;
    struct osw_plat_qsdk11_4_task param_set_beacon_rate;
    struct osw_plat_qsdk11_4_task param_set_wds;
    struct osw_plat_qsdk11_4_task task_set_acl;
    struct osw_plat_qsdk11_4_task task_set_acl_policy;
    struct osw_plat_qsdk11_4_task task_set_mode;
    struct osw_plat_qsdk11_4_task task_exttool_csa;
    struct osw_plat_qsdk11_4_task task_upgrade_mode;
    struct osw_plat_qsdk11_4_task task_get_acl;
    struct osw_plat_qsdk11_4_task task_get_acl_policy;
    struct osw_plat_qsdk_nlcmd_resp resp_get_acl;
    struct osw_plat_qsdk_nlcmd_resp resp_get_acl_policy;

    struct ieee80211req_chaninfo_full chanlist_next;
    struct ieee80211req_chaninfo_full chanlist_prev;
    struct osw_plat_qsdk11_4_get_param_arg mcast2ucast_arg;
    struct osw_plat_qsdk11_4_get_param_arg mgmt_rate_arg;
    struct osw_plat_qsdk11_4_get_param_arg mcast_rate_arg;
    struct osw_plat_qsdk11_4_get_param_arg bcast_rate_arg;
    struct osw_plat_qsdk11_4_get_param_arg beacon_rate_arg;
    struct osw_plat_qsdk11_4_get_param_arg max_rate_arg;
    struct osw_plat_qsdk11_4_get_param_arg cac_state_arg;
    struct osw_plat_qsdk11_4_get_param_arg rrm_arg;
    struct osw_plat_qsdk11_4_get_param_arg mbss_en_arg;
    struct osw_plat_qsdk11_4_get_param_arg mbss_tx_vdev_arg;
    struct osw_plat_qsdk11_4_get_param_arg next_radar_freq_arg;
    struct osw_plat_qsdk11_4_get_param_arg next_radar_width_arg;
    struct osw_plat_qsdk11_4_get_param_arg ap_bridge_arg;
    struct osw_plat_qsdk11_4_get_param_arg puncture_bitmap_arg;
    struct osw_plat_qsdk11_4_get_param_arg regdomain_arg;
    struct osw_plat_qsdk11_4_get_param_arg country_id_arg;
    struct osw_plat_qsdk11_4_get_param_arg wds_arg;
    struct osw_plat_qsdk11_4_get_param_arg mbss_group_arg;
    uint32_t mcast2ucast_next;
    uint32_t mcast2ucast_prev;
    uint32_t mgmt_rate_next;
    uint32_t mgmt_rate_prev;
    uint32_t mcast_rate_next;
    uint32_t mcast_rate_prev;
    uint32_t bcast_rate_next;
    uint32_t bcast_rate_prev;
    uint32_t beacon_rate_next;
    uint32_t beacon_rate_prev;
    uint32_t max_rate_next;
    uint32_t max_rate_prev;
    uint32_t cac_state_next;
    uint32_t cac_state_prev;
    uint32_t rrm_next;
    uint32_t rrm_prev;
    uint32_t mbss_en_next;
    uint32_t mbss_en_prev;
    uint32_t mbss_tx_vdev_next;
    uint32_t mbss_tx_vdev_prev;
    uint32_t next_radar_freq_next;
    uint32_t next_radar_freq_prev;
    uint32_t next_radar_width_next;
    uint32_t next_radar_width_prev;
    uint32_t ap_bridge_next;
    uint32_t ap_bridge_prev;
    uint32_t puncture_bitmap_next;
    uint32_t puncture_bitmap_prev;
    uint32_t regdomain_next;
    uint32_t regdomain_prev;
    uint32_t country_id_next;
    uint32_t country_id_prev;
    uint32_t wds_next;
    uint32_t wds_prev;
    uint32_t last_maccmd;
    uint32_t mbss_group_next;
    uint32_t mbss_group_prev;
    struct osw_hwaddr *last_getmac;
    size_t last_getmac_count;
    char country_next[3];
    char country_prev[3];

    struct osw_timer tx_power_changed;

    /* Survey stats are reported across multiple nl_msg
     * responses. The first one will be for home-channel,
     * and subsequent ones are foreign-channel. The catch
     * is, the foreign-channel report will contain the
     * home-channel frequency entry as well, but with
     * different counters - counters related to off-channel
     * visits only on that channel when it was not
     * home-channel. This entry needs to be skipped in order
     * to provide continuously accumulating values to
     * osw_stats. This variable is reset whenever given
     * query starts, and is used to mark down which
     * frequency needs to be skipped in the foreign-channel
     * messages.
     */
    uint32_t scan_home_freq;
    uint32_t last_home_freq;
};

static uint32_t
osw_plat_qsdk11_4_cycle_to_msec(struct osw_plat_qsdk11_4 *m,
                                uint64_t cycle)
{
    /* It looks like these are really usec, not
     * cycles, but I might be wrong.  Chances of
     * the MAC clock being at 1MHz are rather
     * slim, especially since older chips would
     * run at 88MHz or so.
     */
    cycle /= 1000;
    return (cycle & 0xffffffff);
}

static bool
osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(const char *vif_name)
{
    /* FIXME: This could use netlink instead of sysfs. */
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/sys/class/net/%s/type", vif_name);
    char *buf = file_get(path);
    const int type = buf ? atoi(buf) : 0xFFFF;
    FREE(buf);
    const bool type_matches = (type == ARPHRD_IEEE80211);
    const bool name_matches = (strstr(vif_name, "wifi") == vif_name);
    /* FIXME: This could still, theoretically, treat
     * non-qcawifi wireless-extension interfaces as qcawifi.
     * sysfs device/driver symlink can point to different
     * things on different builds though: ol_qca, cnss2,
     * etc.
     */
    return type_matches && name_matches;
}

static bool
osw_plat_qsdk11_4_is_enabled(void)
{
    if (osw_etc_get("OSW_PLAT_QSDK11_4_DISABLED")) return false;

    /* FIXME: THis should check something at runtime to
     * infer if QSDK 11.4 is running. Or infer if the
     * qcawifi driver at a certain revision is running, or
     * something..
     */

    return true;
}

static bool
osw_plat_qsdk11_4_is_disabled(void)
{
    return osw_plat_qsdk11_4_is_enabled() == false;
}

static bool
osw_plat_qsdk11_4_is_mld_phy(const char *phy_name)
{
    glob_t g;
    const char *pattern = "/sys/class/net/wifi*/mldphy_name";
    const int err = glob(pattern, 0, NULL, &g);
    const bool glob_failed = (err != 0);
    if (glob_failed) return false;
    size_t i;
    for (i = 0; i < g.gl_pathc; i++) {
        const char *path = g.gl_pathv[i];
        FILE *f = fopen(path, "rb");
        if (f != NULL) {
            char buf[32];
            MEMZERO(buf);
            fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            strchomp(buf, "\n\t ");
            const bool match = (strcmp(phy_name, buf) == 0);
            if (match) {
                globfree(&g);
                return true;
            }
        }
    }
    globfree(&g);
    return false;
}

static const char *
osw_plat_qsdk11_4_vif_into_phy_name(struct osw_plat_qsdk11_4_vif *vif)
{
    if (WARN_ON(vif->info == NULL)) return NULL;

    struct osw_plat_qsdk11_4 *m = vif->m;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (WARN_ON(nl == NULL)) return NULL;

    const struct nl_80211_phy *phy_info = nl_80211_phy_by_wiphy(nl, vif->info->wiphy);
    if (phy_info == NULL) return NULL;

    return phy_info->name;
}

static void
osw_plat_qsdk11_4_phy_report_changed(struct osw_plat_qsdk11_4_vif *vif)
{
    struct osw_plat_qsdk11_4 *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    const char *phy_name = osw_plat_qsdk11_4_vif_into_phy_name(vif);
    if (drv == NULL) return;
    if (phy_name == NULL) return;

    osw_drv_report_phy_changed(drv, phy_name);
}

static void
osw_plat_qsdk11_4_vif_report_changed(struct osw_plat_qsdk11_4_vif *vif)
{
    struct osw_plat_qsdk11_4 *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    const char *phy_name = osw_plat_qsdk11_4_vif_into_phy_name(vif);
    const char *vif_name = vif->info->name;
    if (drv == NULL) return;
    if (phy_name == NULL) return;

    osw_drv_report_vif_changed(drv, phy_name, vif_name);
}

static void
osw_plat_qsdk11_4_get_vif_non_wifi(const struct nl_80211_vif *vif,
                                   void *priv)
{
    const bool is_wifi_vif = (strstr(vif->name, "wifi") == vif->name);
    const struct nl_80211_vif **pvif = priv;

    if (*pvif != NULL) return;
    if (is_wifi_vif) return;
    *pvif = vif;
}

static void
osw_plat_qsdk11_4_get_vif_wifi(const struct nl_80211_vif *vif,
                               void *priv)
{
    const bool is_wifi_vif = (strstr(vif->name, "wifi") == vif->name);
    const struct nl_80211_vif **pvif = priv;

    if (*pvif != NULL) return;
    if (!is_wifi_vif) return;
    *pvif = vif;
}

static const struct nl_80211_vif *
osw_plat_qsdk11_4_get_vif(struct osw_plat_qsdk11_4 *m,
                          const char *phy_name,
                          const bool wifi_vif)
{
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const struct nl_80211_phy *phy_info = nl_80211_phy_by_name(nl, phy_name);
    if (phy_info == NULL) return NULL;
    void (*iter)(const struct nl_80211_vif *, void *) = wifi_vif
                                                      ? osw_plat_qsdk11_4_get_vif_wifi
                                                      : osw_plat_qsdk11_4_get_vif_non_wifi;
    const uint32_t wiphy = phy_info->wiphy;
    const struct nl_80211_vif *vif = NULL;
    nl_80211_vif_each(nl, &wiphy, iter, &vif);
    return vif;
}

static bool
osw_plat_qsdk11_4_vif_attr_set(struct osw_plat_qsdk11_4_vif *vif,
                               void *dst,
                               const void *src,
                               const size_t len)
{
    const bool changed = (memcmp(dst, src, len) != 0);
    memcpy(dst, src, len);
    return changed;
}

#define OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, dst, src) \
    osw_plat_qsdk11_4_vif_attr_set(vif, &(dst), &(src), sizeof(dst))

static enum osw_acl_policy
osw_plat_qsdk11_4_maccmd_to_policy(int num)
{
    if (num == 0) return OSW_ACL_NONE;
    if (num == 1) return OSW_ACL_ALLOW_LIST;
    if (num == 2) return OSW_ACL_DENY_LIST;
    return OSW_ACL_NONE;
}

static void
osw_plat_qsdk11_4_create_intf(struct osw_plat_qsdk11_4 *m,
                              struct osw_drv_conf *drv_conf)
{
    /* FIXME: This needs to do `iw create` or `wlanconfig ..
     * create` to create interface that don't really exist
     * yet. OSW does not expect interfaces to be create-able
     * from thin air right now.
     */
}

struct mode_map {
    enum osw_band band;
    enum osw_channel_width width;
    const char *mode;
    const char *mode_lower;
    const char *mode_upper;
};

static const char *
osw_plat_qsdk11_4_conf_to_mode(const struct osw_drv_vif_config *vif)
{
    /* FIXME: This should also set something explicit STA? */
    if (vif->vif_type != OSW_VIF_AP) return "AUTO";

    const struct osw_channel *c = &vif->u.ap.channel;
    const enum osw_channel_width width = c->width;
    const int freq = c->control_freq_mhz;
    const int sec_offset = osw_channel_ht40_offset(c);
    const enum osw_band band = osw_freq_to_band(freq);

    static const struct mode_map modes_eht[] = {
        { OSW_BAND_2GHZ, OSW_CHANNEL_20MHZ, "11GEHT20", NULL, NULL },
        { OSW_BAND_2GHZ, OSW_CHANNEL_40MHZ, "11GEHT40", "11AEHT40MINUS", "11GEHT40PLUS" },

        { OSW_BAND_5GHZ, OSW_CHANNEL_20MHZ, "11AEHT20", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_40MHZ, "11AEHT40", "11AEHT40MINUS", "11AEHT40PLUS" },
        { OSW_BAND_5GHZ, OSW_CHANNEL_80MHZ, "11AEHT80", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_160MHZ, "11AEHT160", NULL, NULL },

        { OSW_BAND_6GHZ, OSW_CHANNEL_20MHZ, "11AEHT20", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_40MHZ, "11AEHT40", "11AEHT40MINUS", "11AEHT40PLUS" },
        { OSW_BAND_6GHZ, OSW_CHANNEL_80MHZ, "11AEHT80", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_160MHZ, "11AEHT160", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_320MHZ, "11AEHT320", NULL, NULL },

        { OSW_BAND_UNDEFINED, OSW_CHANNEL_20MHZ, NULL, NULL, NULL },
    };

    static const struct mode_map modes_he[] = {
        { OSW_BAND_2GHZ, OSW_CHANNEL_20MHZ, "11GHE20", NULL, NULL },
        { OSW_BAND_2GHZ, OSW_CHANNEL_40MHZ, "11GHE40", "11GHE40MINUS", "11GHE40PLUS" },

        { OSW_BAND_5GHZ, OSW_CHANNEL_20MHZ, "11AHE20", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_40MHZ, "11AHE40", "11AHE40MINUS", "11AHE40PLUS" },
        { OSW_BAND_5GHZ, OSW_CHANNEL_80MHZ, "11AHE80", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_160MHZ, "11AHE160", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_80P80MHZ, "11AHE80_80", NULL, NULL },

        { OSW_BAND_6GHZ, OSW_CHANNEL_20MHZ, "11AHE20", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_40MHZ, "11AHE40", "11AHE40MINUS", "11AHE40PLUS" },
        { OSW_BAND_6GHZ, OSW_CHANNEL_80MHZ, "11AHE80", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_160MHZ, "11AHE160", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_80P80MHZ, "11AHE80_80", NULL, NULL },

        { OSW_BAND_UNDEFINED, OSW_CHANNEL_20MHZ, NULL, NULL, NULL },
    };

    static const struct mode_map modes_vht[] = {
        { OSW_BAND_2GHZ, OSW_CHANNEL_20MHZ, "11ACVHT20", NULL, NULL },
        { OSW_BAND_2GHZ, OSW_CHANNEL_40MHZ, "11ACVHT40", "11ACVHT40MINUS","11ACVHT40PLUS" },
        { OSW_BAND_2GHZ, OSW_CHANNEL_80MHZ, "11ACVHT80", NULL, NULL },
        { OSW_BAND_2GHZ, OSW_CHANNEL_160MHZ, "11ACVHT160", NULL, NULL },
        { OSW_BAND_2GHZ, OSW_CHANNEL_80P80MHZ, "11ACVHT80_80", NULL, NULL },

        { OSW_BAND_5GHZ, OSW_CHANNEL_20MHZ, "11ACVHT20", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_40MHZ, "11ACVHT40", "11ACVHT40MINUS","11ACVHT40PLUS" },
        { OSW_BAND_5GHZ, OSW_CHANNEL_80MHZ, "11ACVHT80", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_160MHZ, "11ACVHT160", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_80P80MHZ, "11ACVHT80_80", NULL, NULL },

        { OSW_BAND_6GHZ, OSW_CHANNEL_20MHZ, "11ACVHT20", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_40MHZ, "11ACVHT40", "11ACVHT40MINUS","11ACVHT40PLUS" },
        { OSW_BAND_6GHZ, OSW_CHANNEL_80MHZ, "11ACVHT80", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_160MHZ, "11ACVHT160", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_80P80MHZ, "11ACVHT80_80", NULL, NULL },

        { OSW_BAND_UNDEFINED, OSW_CHANNEL_20MHZ, NULL, NULL, NULL },
    };

    static const struct mode_map modes_ht[] = {
        { OSW_BAND_2GHZ, OSW_CHANNEL_20MHZ, "11NGHT20", NULL, NULL },
        { OSW_BAND_2GHZ, OSW_CHANNEL_40MHZ, "11NGHT40", "11NGHT40MINUS", "11NGHT40PLUS" },

        { OSW_BAND_5GHZ, OSW_CHANNEL_20MHZ, "11NAHT20", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_40MHZ, "11NAHT40", "11NAHT40MINUS", "11NAHT40PLUS" },

        { OSW_BAND_UNDEFINED, OSW_CHANNEL_20MHZ, NULL, NULL, NULL },
    };

    static const struct mode_map modes_legacy[] = {
        // { OSW_BAND_2GHZ, OSW_CHANNEL_20MHZ, "11B", NULL, NULL },
        { OSW_BAND_2GHZ, OSW_CHANNEL_20MHZ, "11G", NULL, NULL },
        { OSW_BAND_5GHZ, OSW_CHANNEL_20MHZ, "11A", NULL, NULL },
        { OSW_BAND_6GHZ, OSW_CHANNEL_20MHZ, "11A", NULL, NULL },

        { OSW_BAND_UNDEFINED, OSW_CHANNEL_20MHZ, NULL, NULL, NULL },
    };

    const struct mode_map *mode = modes_legacy;

    if (vif->u.ap.mode.eht_enabled) mode = modes_eht;
    else if (vif->u.ap.mode.he_enabled) mode = modes_he;
    else if (vif->u.ap.mode.vht_enabled) mode = modes_vht;
    else if (vif->u.ap.mode.ht_enabled) mode = modes_ht;

    while (mode->band != OSW_BAND_UNDEFINED) {
        if (mode->band == band &&
            mode->width == width) {
            if (sec_offset < 0 && mode->mode_lower != NULL)
                return mode->mode_lower;
            else if (sec_offset > 0 && mode->mode_upper != NULL)
                return mode->mode_upper;
            else
                return mode->mode;
        }
        mode++;
    }

    return "AUTO";
}

static char *
osw_plat_qsdk11_4_phy_max_mode(const char *phy_name,
                               const bool force_ac)
{
    const char *prefix = "802.11";
    const int max_2g_width = atoi(file_geta(strfmta("/sys/class/net/%s/2g_maxchwidth", phy_name)) ?: "0");
    const int max_5g_width = atoi(file_geta(strfmta("/sys/class/net/%s/5g_maxchwidth", phy_name)) ?: "0");
    const int max_6g_width = atoi(file_geta(strfmta("/sys/class/net/%s/6g_maxchwidth", phy_name)) ?: "0");
    const int max_bg_width = max_2g_width;
    const int max_a_width = max_5g_width > max_6g_width
                          ? max_5g_width
                          : max_6g_width;
    char *caps = file_geta(strfmta("/sys/class/net/%s/hwcaps", phy_name)) ?: "";
    if (caps == NULL) return NULL;
    if (strstr(caps, prefix) == NULL) return NULL;
    caps += strlen(prefix);

    bool mode_a = false;
    bool mode_b = false;
    bool mode_g = false;
    bool mode_n = false;
    bool mode_ac = false;
    bool mode_ax = false;
    bool mode_be = false;

    char *copy = strdupa(caps);
    const char *first = strsep(&copy, "/");
    while (first && *first) {
        switch (*first) {
            case 'a':
                mode_a = true;
                break;
            case 'b':
                mode_b = true;
                break;
            case 'g':
                mode_g = true;
                break;
            case 'n':
                mode_n = true;
                break;
            default:
                break;
        }
        first++;
    }

    const char *part;
    while ((part = strsep(&copy, "/")) != NULL) {
        if (strcmp(part, "ac") == 0) {
            mode_ac = true;
        }
        else if (strcmp(part, "ax") == 0) {
            mode_ax = true;
        }
        else if (strcmp(part, "be") == 0) {
            mode_be = true;
        }
    }

    if (mode_ax == false && mode_be == false) {
        /* Assume 11ac because 2.4GHz radio doesn't report
         * it but actually supports it..
         */
        mode_ac = force_ac;
    }

    if (mode_a == false && mode_b == false && mode_g == false && mode_n == false && (mode_ax || mode_be)) {
        mode_a = true;
    }

    if (mode_be) {
        if (mode_a) {
            return strfmt("11AEHT%d", max_a_width);
        }
        else {
            return strfmt("11GEHT%d", max_bg_width);
        }
    }
    else if (mode_ax) {
        if (mode_a) {
            return strfmt("11AHE%d", max_a_width);
        }
        else {
            return strfmt("11GHE%d", max_bg_width);
        }
    }
    else if (mode_ac) {
        if (mode_a) {
            return strfmt("11ACVHT%d", max_a_width);
        }
        else {
            return strfmt("11ACVHT%d", max_bg_width);
        }
    }
    else if (mode_n) {
        if (mode_a) {
            return strfmt("11AGHT%d", max_a_width);
        }
        else {
            return strfmt("11NGHT%d", max_bg_width);
        }
    }
    else if (mode_a) {
        return strfmt("11A");
    }
    else if (mode_g) {
        return strfmt("11G");
    }
    else if (mode_b) {
        return strfmt("11B");
    }
    else {
        return strfmt("AUTO");
    }
}

static void
osw_plat_qsdk11_4_exttool_csa_start(struct osw_plat_qsdk11_4 *m,
                                    const char *phy_name,
                                    const struct osw_channel *c)
{
    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, true);
    if (vif_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (vif == NULL) return;

    const char *name = strfmta("%s: exttool csa to "OSW_CHANNEL_FMT, phy_name, OSW_CHANNEL_ARG(c));
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const uint32_t ifindex = vif_info->ifindex;
    const int family_id = nl_80211_get_family_id(nl);
    struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_exttool_csa(family_id, ifindex, c);
    struct osw_plat_qsdk11_4_async *job = osw_plat_qsdk_nlcmd_alloc(name, nl, msg);
    osw_plat_qsdk11_4_task_start(&vif->task_exttool_csa, job);
}

static void
osw_plat_qsdk11_4_mode_upgrade_start(struct osw_plat_qsdk11_4 *m,
                                     struct osw_drv_phy_config *phy_conf,
                                     struct osw_drv_vif_config *vif_conf,
                                     const struct osw_channel *c)
{
    const char *new_mode = osw_plat_qsdk11_4_conf_to_mode(vif_conf);
    if (WARN_ON(new_mode == NULL)) return;

    const char *phy_name = phy_conf->phy_name;
    const char *vif_name = vif_conf->vif_name;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const struct nl_80211_vif *vif_info = nl_80211_vif_by_name(nl, vif_name);
    const uint32_t ifindex = vif_info->ifindex;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (vif == NULL) return;

    struct osw_plat_qsdk11_4_async *job = osw_plat_qsdk_mode_upgrade(nl, phy_name, vif_name, new_mode, c->width, ifindex);
    osw_plat_qsdk11_4_task_start(&vif->task_upgrade_mode, job);
}

static void
osw_plat_qsdk11_4_apply_csa(struct osw_plat_qsdk11_4 *m,
                            struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;
        size_t j;
        for (j = 0; j < phy->vif_list.count; j++) {
            struct osw_drv_vif_config *vif = &phy->vif_list.list[j];
            const struct osw_channel *c = &vif->u.ap.channel;
            const char *vif_name = vif->vif_name;

            if (vif->vif_type != OSW_VIF_AP) continue;
            if (vif->u.ap.csa_required == false) continue;

            osw_plat_qsdk11_4_mode_upgrade_start(m, phy, vif, c);

            LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "needs csa"));
            osw_plat_qsdk11_4_exttool_csa_start(m, phy_name, c);

            /* This is per PHY actually, so bail out, and go
             * to the next PHY. */
            break;
        }
    }
}

static int
osw_plat_qsdk11_4_policy_to_maccmd(enum osw_acl_policy policy)
{
    switch (policy) {
        case OSW_ACL_NONE: return IEEE80211_MACCMD_POLICY_OPEN;
        case OSW_ACL_ALLOW_LIST: return IEEE80211_MACCMD_POLICY_ALLOW;
        case OSW_ACL_DENY_LIST: return IEEE80211_MACCMD_POLICY_DENY;
    }
    /* unreachable */
    return IEEE80211_MACCMD_POLICY_OPEN;
}

static void
osw_plat_qsdk11_4_apply_rfkill(struct osw_plat_qsdk11_4 *m,
                               struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;

        if (phy->enabled_changed) {
            const bool ok = os_nif_up((char *)phy_name, phy->enabled);
            const bool failed = !ok;
            WARN_ON(failed);
        }
    }
}

static void
osw_plat_qsdk11_4_phy_apply_mbss_tx_vif_name(struct osw_plat_qsdk11_4 *m,
                                             struct osw_drv_phy_config *phy_conf,
                                             struct osw_plat_qsdk11_4_vif *vif,
                                             const char *vif_name)
{
    if (phy_conf->enabled == false) return;

    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return;

    const char *phy_name = phy_conf->phy_name;
    const struct nl_80211_phy *phy_info = nl_80211_phy_by_name(nl, phy_name);
    if (phy_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    if (sub == NULL) return;

    struct osw_plat_qsdk11_4_phy *phy = nl_80211_sub_phy_get_priv(sub, phy_info);
    if (phy == NULL) return;

    const struct nl_80211_vif *vif_info = nl_80211_vif_by_name(nl, vif_name);
    if (vif_info == NULL) return;

    const struct nl_80211_vif *phy_vif_info = nl_80211_vif_by_name(nl, phy_name);
    if (phy_vif_info == NULL) return;

    struct osw_plat_qsdk11_4_vif *phy_vif = nl_80211_sub_vif_get_priv(sub, phy_vif_info);
    if (phy_vif == NULL) return;

    const bool mbss_disabled = (phy_vif->mbss_en_prev == false);

    if (mbss_disabled) return;

    osw_plat_qsdk11_4_task_drop(&phy->task_mbss_tx_vdev);

    const uint32_t ifindex = vif_info->ifindex;
    struct osw_plat_qsdk11_4_async *async = osw_plat_qsdk11_4_mbss_tx_vdev_alloc(m->nl_ops,
                                                                                 phy_name,
                                                                                 vif_name,
                                                                                 ifindex);
    osw_plat_qsdk11_4_task_start(&phy->task_mbss_tx_vdev, async);
}

static void
osw_plat_qsdk11_4_pre_request_config_vif_ap(struct osw_plat_qsdk11_4 *m,
                                            struct osw_plat_qsdk11_4_vif *vif,
                                            struct osw_drv_conf *drv_conf,
                                            struct osw_drv_phy_config *phy_conf,
                                            struct osw_drv_vif_config *vif_conf,
                                            struct osw_drv_vif_config_ap *ap_conf)
{
    const bool beacon_rate_supported = (ap_conf->mode.beacon_rate.type == OSW_BEACON_RATE_ABG);
    const bool beacon_rate_changed = vif_conf->enabled
                                  && ap_conf->mode_changed
                                  && beacon_rate_supported;
    const bool mode_changed = (ap_conf->channel_changed == true)
                           && (ap_conf->csa_required == false);
    const uint32_t mgmt_kbps = (vif_conf->enabled && ap_conf->mode_changed)
                             ? osw_rate_legacy_to_halfmbps(ap_conf->mode.mgmt_rate) * 500
                             : 0;
    const uint32_t mcast_kbps = (vif_conf->enabled && ap_conf->mode_changed)
                              ? osw_rate_legacy_to_halfmbps(ap_conf->mode.mcast_rate) * 500
                              : 0;
    const bool mbss_mode_changed = (ap_conf->mbss_mode_changed == true)
                           && (vif_conf->enabled);

    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return;

    const int family_id = nl_80211_get_family_id(nl);
    const struct nl_80211_vif *info = vif->info;
    if (info == NULL) return;

    const char *vif_name = info->name;
    const uint32_t ifindex = info->ifindex;

    if (ap_conf->mcast2ucast_changed) {
        const uint32_t value = ap_conf->mcast2ucast
                             ? QCA_WIFI_MC_ME_HYFI
                             : QCA_WIFI_MC_ME_DISABLE;
        const struct osw_plat_qsdk11_4_param_u32_arg arg = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_ME,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = value,
            .vif_name = info->name,
            .param_name = "mcast2ucast",
        };
        PARAM_U32_TASK_START(&vif->param_set_mcast2ucast, &arg);
    }

    if (ap_conf->mode_changed) {
        const uint32_t value = ap_conf->mode.rrm_neighbor_report ? 1 : 0;
        const struct osw_plat_qsdk11_4_param_u32_arg arg = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_RRM_CAP,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = value,
            .vif_name = info->name,
            .param_name = "rrm",
        };

        PARAM_U32_TASK_START(&vif->param_set_rrm, &arg);
    }

    if (mgmt_kbps != 0) {
        const struct osw_plat_qsdk11_4_param_u32_arg mgmt_arg = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_MGMT_RATE,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = mgmt_kbps,
            .vif_name = info->name,
            .param_name = "mgmt_rate",
        };

        PARAM_U32_TASK_START(&vif->param_set_mgmt_rate, &mgmt_arg);
    }

    if (mcast_kbps != 0) {
        const struct osw_plat_qsdk11_4_param_u32_arg mcast_arg = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_MCAST_RATE,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = mcast_kbps,
            .vif_name = info->name,
            .param_name = "mcast_rate",
        };
        const struct osw_plat_qsdk11_4_param_u32_arg bcast_arg = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_BCAST_RATE,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = mcast_kbps,
            .vif_name = info->name,
            .param_name = "bcast_rate",
        };

        PARAM_U32_TASK_START(&vif->param_set_mcast_rate, &mcast_arg);
        PARAM_U32_TASK_START(&vif->param_set_bcast_rate, &bcast_arg);
    }

    if (ap_conf->isolated_changed) {
        const uint32_t value = ap_conf->isolated ? 0 : 1;
        const struct osw_plat_qsdk11_4_param_u32_arg arg = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_APBRIDGE,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = value,
            .vif_name = info->name,
            .param_name = "ap_bridge",
        };
        PARAM_U32_TASK_START(&vif->param_set_ap_bridge, &arg);
    }

    if (ap_conf->acl_policy_changed) {
        const int maccmd = osw_plat_qsdk11_4_policy_to_maccmd(ap_conf->acl_policy);
        struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_maccmd(family_id, ifindex, maccmd);
        const char *name = strfmta("%s: maccmd: %d", vif_name, maccmd);
        struct osw_plat_qsdk11_4_async *job = osw_plat_qsdk_nlcmd_alloc(name, nl, msg);
        osw_plat_qsdk11_4_task_start(&vif->task_set_acl_policy, job);
    }

    if (ap_conf->acl_changed) {
        struct osw_plat_qsdk11_4_async *jobqueue = osw_plat_qsdk_nl80211_jobqueue_acl(vif_name, nl, ifindex, ap_conf);
        osw_plat_qsdk11_4_task_start(&vif->task_set_acl, jobqueue);
    }

    if (mode_changed) {
        const char *new_mode = osw_plat_qsdk11_4_conf_to_mode(vif_conf);
        WARN_ON(new_mode == NULL);
        if (new_mode != NULL) {
            struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_mode(family_id, ifindex, new_mode);
            const char *name = strfmta("%s: mode: %s", vif_name, new_mode);
            struct osw_plat_qsdk11_4_async *job = osw_plat_qsdk_nlcmd_alloc(name, nl, msg);
            osw_plat_qsdk11_4_task_start(&vif->task_set_mode, job);
        }
    }

    if (beacon_rate_changed) {
        const uint32_t beacon_rate = ap_conf->mode.beacon_rate.u.legacy;
        const uint32_t beacon_halfmbps = osw_rate_legacy_to_halfmbps(beacon_rate);
        const uint32_t beacon_kbps = beacon_halfmbps * 500;
        const uint32_t value = beacon_kbps;
        const struct osw_plat_qsdk11_4_param_u32_arg arg = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_BEACON_RATE_FOR_VAP,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = value,
            .vif_name = info->name,
            .param_name = "beacon_rate",
        };
        PARAM_U32_TASK_START(&vif->param_set_beacon_rate, &arg);
    }

    if (mbss_mode_changed && ap_conf->mbss_mode == OSW_MBSS_TX_VAP) {
        osw_plat_qsdk11_4_phy_apply_mbss_tx_vif_name(m, phy_conf, vif, vif_name);
    }
}

static void
osw_plat_qsdk11_4_vif_disable_dbdc(struct osw_plat_qsdk11_4_vif *vif,
                                   struct nl_80211 *nl)
{
    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;
    const bool not_phy = (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name) == false);

    if (not_phy) return;

    const struct osw_plat_qsdk11_4_param_u32_arg arg_dbdc_enable = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = OL_ATH_PARAM_SHIFT
                      | OL_ATH_PARAM_DBDC_ENABLE,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL,
            .desired_value = 0,
            .vif_name = info->name,
            .param_name = "dbdc_enable",
    };

    const struct osw_plat_qsdk11_4_param_u32_arg arg_dbdc_samessiddisable = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = OL_ATH_PARAM_SHIFT
                      | OL_ATH_PARAM_SAME_SSID_DISABLE,
            /* There is no way to "get" for the this param */
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = 1,
            .vif_name = info->name,
            .param_name = "dbdc_samessiddisable",
    };

    PARAM_U32_TASK_START(&vif->param_set_dbdc_enable, &arg_dbdc_enable);
    PARAM_U32_TASK_START(&vif->param_set_dbdc_samessiddisable, &arg_dbdc_samessiddisable);
}


static void
osw_plat_qsdk11_4_vif_set_min_rssi_min(struct osw_plat_qsdk11_4_vif *vif,
                                   struct nl_80211 *nl)
{
    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;
    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    const struct osw_plat_qsdk11_4_param_u32_arg arg_min_rssi_min = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_ASSOC_MIN_RSSI,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL,
            .desired_value = -120,
            .vif_name = info->name,
            .param_name = "min_asoc_rssi",
    };

    PARAM_U32_TASK_START(&vif->param_set_min_rssi_min, &arg_min_rssi_min);
}

static void
osw_plat_qsdk11_4_vif_sta_mode_fix(struct osw_plat_qsdk11_4 *m,
                                   struct osw_plat_qsdk11_4_vif *vif,
                                   const char *phy_name)
{
    const char *vif_name = vif->info->name;
    const uint32_t ifindex = vif->info->ifindex;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const int family_id = nl_80211_get_family_id(nl);
    char *mode = osw_plat_qsdk11_4_phy_max_mode(phy_name, true);
    if (mode == NULL) {
        return;
    }

    const char *name = strfmta(LOG_PREFIX_VIF(phy_name, vif_name, "mode (noreset): set: %s", mode));
    struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_mode_noreset(family_id, ifindex, mode);
    FREE(mode);
    if (msg == NULL) {
        return;
    }

    struct osw_plat_qsdk11_4_async *job = osw_plat_qsdk_nlcmd_alloc(name, nl, msg);
    osw_plat_qsdk11_4_task_start(&vif->task_set_mode, job);
}

static void
osw_plat_qsdk11_4_vif_sta_multi_ap_fix(struct osw_plat_qsdk11_4 *m,
                                       struct osw_plat_qsdk11_4_vif *vif,
                                       const char *phy_name,
                                       struct osw_drv_vif_config_sta *sta_config)
{
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const struct nl_80211_vif *info = vif->info;
    if (info == NULL) return;

    const struct osw_drv_vif_sta_network *network = sta_config->network;
    if (network == NULL) return;

    const char *vif_name = info->name;
    const bool multi_ap = network->multi_ap;
    const struct osw_drv_vif_sta_network *n_next = network->next;

    while (n_next) {
        if (WARN_ON(n_next->multi_ap != multi_ap)) return;
        n_next = n_next->next;
    }

    const uint32_t multi_ap_value = multi_ap ? 1 : 0;

    if (sta_config->network_changed) {
        const struct osw_plat_qsdk11_4_param_u32_arg arg = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_WDS,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL,
            .desired_value = multi_ap_value,
            .vif_name = vif_name,
            .param_name = "wds",
        };
        PARAM_U32_TASK_START(&vif->param_set_wds, &arg);
    }
}

static void
osw_plat_qsdk11_4_pre_request_config_vif_sta(struct osw_plat_qsdk11_4 *m,
                                             struct osw_plat_qsdk11_4_vif *vif,
                                             struct osw_drv_conf *drv_conf,
                                             struct osw_drv_phy_config *phy_conf,
                                             struct osw_drv_vif_config *vif_conf,
                                             struct osw_drv_vif_config_sta *sta_conf)
{
    switch (sta_conf->operation) {
        case OSW_DRV_VIF_CONFIG_STA_CONNECT:
        case OSW_DRV_VIF_CONFIG_STA_RECONNECT:
            osw_plat_qsdk11_4_vif_sta_mode_fix(m, vif, phy_conf->phy_name);
            osw_plat_qsdk11_4_vif_sta_multi_ap_fix(m, vif, phy_conf->phy_name, sta_conf);
            break;
        case OSW_DRV_VIF_CONFIG_STA_NOP:
        case OSW_DRV_VIF_CONFIG_STA_DISCONNECT:
            break;
    }
}

static void
osw_plat_qsdk11_4_pre_request_config_vif(struct osw_plat_qsdk11_4 *m,
                                         struct osw_plat_qsdk11_4_vif *vif,
                                         struct osw_drv_conf *drv_conf,
                                         struct osw_drv_phy_config *phy_conf,
                                         struct osw_drv_vif_config *vif_conf)
{
    if (vif_conf->tx_power_dbm_changed) {
        /* The osw_drv_nl80211 itself is taking care of
         * setting the tx_power. However the kernel WLAN
         * driver updates the tx_power readouts with some
         * delay. Without this delayed vif_changed_report
         * tx_power value can remain stale in the system for
         * longer than necessary. The system can operate
         * without this but it's more responsive in settling
         * down (osw_confsync) with it.
         */
        const uint64_t at = osw_time_mono_clk() + OSW_TIME_SEC(5);
        osw_timer_arm_at_nsec(&vif->tx_power_changed, at);
    }

    switch (vif_conf->vif_type) {
        case OSW_VIF_AP:
            osw_plat_qsdk11_4_pre_request_config_vif_ap(m, vif, drv_conf, phy_conf, vif_conf, &vif_conf->u.ap);
            break;
        case OSW_VIF_STA:
            osw_plat_qsdk11_4_pre_request_config_vif_sta(m, vif, drv_conf, phy_conf, vif_conf, &vif_conf->u.sta);
            break;
        case OSW_VIF_AP_VLAN:
        case OSW_VIF_UNDEFINED:
            break;
    }
}

static void
osw_plat_qsdk11_4_phy_apply_disable_dbdc(struct osw_plat_qsdk11_4 *m,
                                         struct osw_drv_phy_config *phy_conf)
{
    if (phy_conf->enabled == false) return;

    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return;

    const char *phy_vif_name = phy_conf->phy_name;
    const struct nl_80211_vif *vif_info = nl_80211_vif_by_name(nl, phy_vif_name);
    if (vif_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    if (sub == NULL) return;

    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (vif == NULL) return;

    osw_plat_qsdk11_4_vif_disable_dbdc(vif, nl);
}

static void
osw_plat_qsdk11_4_phy_set_next_radar(struct osw_plat_qsdk11_4 *m,
                                     struct osw_drv_phy_config *phy_conf)
{
    if (phy_conf == NULL) return;
    if (phy_conf->enabled == false) return;

    const char *phy_name = phy_conf->phy_name;
    if (osw_plat_qsdk11_4_is_mld_phy(phy_name)) return;

    const uint32_t ifindex = if_nametoindex(phy_name);
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return;

    const struct nl_80211_phy *phy_info = nl_80211_phy_by_name(nl, phy_name);
    if (phy_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    if (sub == NULL) return;

    struct osw_plat_qsdk11_4_phy *phy = nl_80211_sub_phy_get_priv(sub, phy_info);
    if (phy == NULL) return;

#ifdef WLAN_FEATURE_NEXT_RADAR_WIDTH
    const int width_param_id = OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_NXT_RDR_WIDTH;
#else
    const int width_param_id = 0;
#endif

    const uint32_t desired_control_freq = phy_conf->radar_next_channel.control_freq_mhz;
    const struct osw_plat_qsdk11_4_param_u32_arg arg_next_radar_freq = {
            .nl = nl,
            .ifindex = ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = OL_ATH_PARAM_SHIFT
                      | OL_ATH_PARAM_NXT_RDR_FREQ,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL,
            .desired_value = desired_control_freq,
            .vif_name = phy_name,
            .param_name = "setNxtRadarFreq",
    };

    const uint32_t desired_width_mhz = osw_channel_width_to_mhz(phy_conf->radar_next_channel.width);
    WARN_ON(desired_control_freq != 0 && desired_width_mhz == 0);

    const struct osw_plat_qsdk11_4_param_u32_arg arg_next_radar_width = {
            .nl = nl,
            .ifindex = ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = width_param_id,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL,
            .desired_value = desired_width_mhz,
            .vif_name = phy_name,
            .param_name = "setNxtRadarWidth",
    };

    PARAM_U32_TASK_START(&phy->task_set_next_radar_freq, &arg_next_radar_freq);
    PARAM_U32_TASK_START(&phy->task_set_next_radar_width, &arg_next_radar_width);
}

static void
osw_plat_qsdk11_4_pre_request_config_cb(struct osw_drv_nl80211_hook *hook,
                                        struct osw_drv_conf *drv_conf,
                                        void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211_sub *sub = m->nl_sub;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);

    osw_plat_qsdk11_4_apply_rfkill(m, drv_conf);
    osw_plat_qsdk11_4_create_intf(m, drv_conf);
    osw_plat_qsdk11_4_apply_csa(m, drv_conf);

    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy_conf = &drv_conf->phy_list[i];
        osw_plat_qsdk11_4_phy_apply_disable_dbdc(m, phy_conf);
        osw_plat_qsdk11_4_phy_set_next_radar(m, phy_conf);

        size_t j;
        for (j = 0; j < phy_conf->vif_list.count; j++) {
            struct osw_drv_vif_config *vif_conf = &phy_conf->vif_list.list[j];
            const char *vif_name = vif_conf->vif_name;
            const struct nl_80211_vif *vif_info = nl_80211_vif_by_name(nl, vif_name);
            if (vif_info == NULL) continue;

            struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
            if (vif == NULL) continue;

            osw_plat_qsdk11_4_pre_request_config_vif(m, vif, drv_conf, phy_conf, vif_conf);
        }
    }
}

static void
osw_plat_qsdk11_4_drv_added_cb(struct osw_state_observer *obs,
                               struct osw_drv *drv)
{
    struct osw_plat_qsdk11_4 *m = container_of(obs, struct osw_plat_qsdk11_4, state_obs);
    const struct osw_drv_ops *ops = osw_drv_get_ops(drv);
    const char *drv_name = ops->name;
    const bool is_nl80211 = (strstr(drv_name, "nl80211") != NULL);
    const bool is_not_nl80211 = !is_nl80211;

    if (is_not_nl80211) return;

    /* Knowing the osw_drv pointer of nl80211 makes it
     * possible to inject / supplement extra events as if
     * the nl80211 driver did it. For example probe_req
     * reports, channel switch changes, DFS events -- any
     * event that may be unavailable in the vendor's vanilla
     * nl80211 behavior.
     */
    m->drv_nl80211 = drv;

    LOGI(LOG_PREFIX("bound to nl80211"));
}

static void
osw_plat_qsdk11_4_drv_removed_cb(struct osw_state_observer *obs,
                                 struct osw_drv *drv)
{
    struct osw_plat_qsdk11_4 *m = container_of(obs, struct osw_plat_qsdk11_4, state_obs);
    const bool is_not_nl80211 = (m->drv_nl80211 != drv);

    if (is_not_nl80211) return;

    m->drv_nl80211 = NULL;
    LOGI(LOG_PREFIX("unbound from nl80211"));
}

static void
osw_plat_qsdk11_4_init(struct osw_plat_qsdk11_4 *m)
{
    const struct osw_state_observer obs = {
        .name = __FILE__,
        .drv_added_fn = osw_plat_qsdk11_4_drv_added_cb,
        .drv_removed_fn = osw_plat_qsdk11_4_drv_removed_cb,
    };
    m->state_obs = obs;
    ds_tree_init(&m->mld_stas, ds_str_cmp, struct osw_plat_qsdk11_4_mld_sta, node);

}

static void
osw_plat_qsdk11_4_wifi_to_phy(const char *path,
                              char **phy_name,
                              char **wifi_name)
{
    char *cpy = STRDUP(path); /* -> /sys/class/net/wifiX */
    char *vif_name = basename(cpy); /* -> wifiX */
    const bool is_wifi = osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name);
    const bool is_not_wifi = (is_wifi == false);
    if (is_wifi) *wifi_name = STRDUP(vif_name);
    FREE(cpy);
    if (is_not_wifi) return;

    char idx_path[PATH_MAX];
    const size_t idx_path_max = sizeof(idx_path);
    const int idx_path_len = snprintf(idx_path, idx_path_max, "%s/phy80211/index", path);
    const bool idx_path_err = (idx_path_len < 0);
    const bool idx_path_truncated = ((size_t)idx_path_len >= idx_path_max);
    if (WARN_ON(idx_path_err)) return;
    if (WARN_ON(idx_path_truncated)) return;
    char *buf = file_get(idx_path);
    if (buf == NULL) return;
    const uint32_t wiphy = strtoul(buf, NULL, 10);
    FREE(buf);

    char arg[32];
    const size_t arg_max = sizeof(arg);
    const int arg_len = snprintf(arg, arg_max, "phy#%" PRIu32, wiphy);
    const bool arg_err = (arg_len < 0);
    const bool arg_truncated = ((size_t)arg_len >= arg_max);
    if (WARN_ON(arg_err)) return;
    if (WARN_ON(arg_truncated)) return;
    *phy_name = STRDUP(arg);
}

/* FIXME: This should not be a one-shot start call on module init. Instead this
 * should actually rely on nl80211 family listener and WIPHY appearance,
 * especially for runtime driver reloads, not just cfg80211 module reloads. The
 * catch is this probably needs to be quick enough to run _before_
 * osw_drv_nl80211. One way around this issue would be to make this module
 * _prevent_ the automatic osw_drv_nl80211 ops registration and registering it
 * here - this would guarantee ordering control. It is technically possible, I
 * guess, with drv_added_fn, and checking if it's a pointer that we know of
 * here - and if so, allowing it, otherwise immediatelly unregistering it.
 */
static void
osw_plat_qsdk11_4_rename_wiphy(void)
{
    /* FIXME: Use native netlink APIs instead of fork+exec */
    glob_t g;
    const char *pattern = "/sys/class/net/wifi*";
    const int err = glob(pattern, 0, NULL, &g);
    const bool glob_failed = (err != 0);
    if (glob_failed) return;
    size_t i;
    for (i = 0; i < g.gl_pathc; i++) {
        const char *path = g.gl_pathv[i];
        char *phy = NULL;
        char *wifi = NULL;
        osw_plat_qsdk11_4_wifi_to_phy(path, &phy, &wifi);
        if (phy != NULL && wifi != NULL) {
            LOGI("osw: plat: qsdk11_4: renaming %s to %s", phy, wifi);
            const char *out = strexa("iw", phy, "set", "name", wifi);
            WARN_ON(out == NULL);
        }
        FREE(phy);
        FREE(wifi);
    }
    globfree(&g);
}

static bool
osw_plat_qsdk_conf_vif_is_enabled(struct osw_drv_conf *drv_conf,
                                  const char *vif_name)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy_conf = &drv_conf->phy_list[i];
        size_t j;
        for (j = 0; j < phy_conf->vif_list.count; j++) {
            struct osw_drv_vif_config *vif_conf = &phy_conf->vif_list.list[j];
            const bool this_vif = (strcmp(vif_conf->vif_name, vif_name) == 0);
            const bool not_this_vif = (this_vif == false);
            if (not_this_vif) continue;
            return (phy_conf->enabled && vif_conf->enabled);
        }
    }
    return false;
}

static void
osw_plat_qsdk_ap_conf_prep_mld_link_args(const char *vif_name,
                                         struct osw_drv_conf *drv_conf,
                                         char *mld_link_macs, size_t mld_link_macs_len,
                                         char *mld_link_ids, size_t mld_link_ids_len)
{
    const char *slaves_path = strfmta("/sys/class/net/%s/master/bonding/slaves", vif_name);
    char *slaves = file_geta(slaves_path);
    char *if_name;
    while ((if_name = strsep(&slaves, " \r\n")) != NULL) {
        const bool sibling_enabled = osw_plat_qsdk_conf_vif_is_enabled(drv_conf, if_name);
        const bool sibling_not_enabled = (sibling_enabled == false);
        if (sibling_not_enabled) continue;

        const char *mac_path = strfmta("/sys/class/net/%s/address", if_name);
        const char *wifi_path = strfmta("/sys/class/net/%s/parent", if_name);
        char *mac_str = file_geta(mac_path);
        char *wifi_name = file_geta(wifi_path);
        if (mac_str == NULL) continue;
        if (wifi_name == NULL) continue;
        char *wifi_num = strpbrk(wifi_name, "1234567890");
        if (wifi_num == NULL) continue;

        strchomp(mac_str, "\r\n");
        strchomp(wifi_num, "\r\n");

        strscat(mld_link_macs, mac_str, mld_link_macs_len);
        strscat(mld_link_macs, " ", mld_link_macs_len);
        strscat(mld_link_ids, wifi_num, mld_link_ids_len);
        strscat(mld_link_ids, " ", mld_link_ids_len);
    }

    strchomp(mld_link_macs, " ");
    strchomp(mld_link_ids, " ");
}

static struct osw_drv_vif_config *
osw_plat_qsdk_conf_find_vif(struct osw_drv_conf *drv_conf,
                            const char *vif_name,
                            struct osw_drv_phy_config **phy)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy_conf = &drv_conf->phy_list[i];
        size_t j;
        for (j = 0; j < phy_conf->vif_list.count; j++) {
            struct osw_drv_vif_config *vif_conf = &phy_conf->vif_list.list[j];
            const bool this_vif = (strcmp(vif_conf->vif_name, vif_name) == 0);
            if (this_vif) {
                if (phy != NULL) *phy = phy_conf;
                return vif_conf;
            }
        }
    }
    return NULL;
}

static void
osw_plat_qsdk_mld_sta_invalidate(struct osw_plat_qsdk11_4_mld_sta *mld_sta)
{
    if (mld_sta == NULL) return;

    struct osw_plat_qsdk11_4 *m = mld_sta->m;
    struct osw_drv *drv = m->drv_nl80211;
    struct osw_plat_qsdk11_4_vif *vif;
    ds_tree_foreach(&mld_sta->vifs, vif) {
        const char *phy_name = osw_plat_qsdk11_4_vif_into_phy_name(vif);
        const char *vif_name = vif->info->name;
        osw_drv_report_vif_changed(drv, phy_name, vif_name);
    }
}

static struct osw_plat_qsdk11_4_mld_sta *
osw_plat_qsdk11_4_mld_sta_lookup(struct osw_plat_qsdk11_4 *m,
                                 const char *mld_name)
{
    if (m == NULL) return NULL;
    if (mld_name == NULL) return NULL;
    if (strlen(mld_name) == 0) return NULL;
    return ds_tree_find(&m->mld_stas, mld_name);
}

static struct osw_plat_qsdk11_4_mld_sta *
osw_plat_qsdk11_4_mld_sta_alloc(struct osw_plat_qsdk11_4 *m,
                                 const char *mld_name)
{
    if (m == NULL) return NULL;
    if (mld_name == NULL) return NULL;
    if (strlen(mld_name) == 0) return NULL;
    struct osw_plat_qsdk11_4_mld_sta *mld_sta = CALLOC(1, sizeof(*mld_sta));
    mld_sta->m = m;
    mld_sta->mld_name = STRDUP(mld_name);
    ds_tree_init(&mld_sta->vifs, ds_void_cmp, struct osw_plat_qsdk11_4_vif, node_mld_sta);
    ds_tree_insert(&m->mld_stas, mld_sta, mld_sta->mld_name);
    LOGI(LOG_PREFIX_MLD_STA(mld_sta, "allocated"));
    return mld_sta;
}

static void
osw_plat_qsdk11_4_mld_sta_drop(struct osw_plat_qsdk11_4_mld_sta *mld_sta)
{
    if (mld_sta == NULL) return;
    if (WARN_ON(mld_sta->m == NULL)) return;
    LOGI(LOG_PREFIX_MLD_STA(mld_sta, "dropping"));
    ds_tree_remove(&mld_sta->m->mld_stas, mld_sta);
    FREE(mld_sta->mld_name);
    FREE(mld_sta);
}

static void
osw_plat_qsdk11_4_mld_sta_gc(struct osw_plat_qsdk11_4_mld_sta *mld_sta)
{
    if (mld_sta == NULL) return;
    if (ds_tree_is_empty(&mld_sta->vifs) == false) return;
    osw_plat_qsdk11_4_mld_sta_drop(mld_sta);
}

static void
osw_plat_qsdk_vif_sta_set_mld(struct osw_plat_qsdk11_4_vif *vif,
                              const char *mld_name)
{
    if (vif == NULL) return;
    struct osw_plat_qsdk11_4 *m = vif->m;
    struct osw_plat_qsdk11_4_mld_sta *mld_sta = osw_plat_qsdk11_4_mld_sta_lookup(m, mld_name)
                                             ?: osw_plat_qsdk11_4_mld_sta_alloc(m, mld_name);
    if (vif->mld_sta == mld_sta) return;
    const char *phy_name = osw_plat_qsdk11_4_vif_into_phy_name(vif);
    const char *vif_name = vif->info->name;
    LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "mld: '%s' -> '%s'",
         vif->mld_sta ? vif->mld_sta->mld_name : "",
         mld_sta ? mld_sta->mld_name : ""));
    osw_plat_qsdk_mld_sta_invalidate(vif->mld_sta);
    osw_plat_qsdk_mld_sta_invalidate(mld_sta);
    if (vif->mld_sta != NULL) {
        ds_tree_remove(&vif->mld_sta->vifs, vif);
        osw_plat_qsdk11_4_mld_sta_gc(vif->mld_sta);
        vif->mld_sta = NULL;
    }
    if (mld_sta != NULL) {
        ds_tree_insert(&mld_sta->vifs, vif, vif);
        vif->mld_sta = mld_sta;
    }
}

static const struct osw_drv_vif_state_sta_link *
osw_plat_qsdk_mld_sta_get_associated_link(struct osw_plat_qsdk11_4_mld_sta *mld_sta)
{
    static struct osw_drv_vif_state_sta_link none;
    if (mld_sta == NULL) return &none;
    struct osw_plat_qsdk11_4_vif *vif;
    ds_tree_foreach(&mld_sta->vifs, vif) {
        if (vif->link.status == OSW_DRV_VIF_STATE_STA_LINK_CONNECTED) {
            return &vif->link;
        }
    }
    return &none;
}

static void
osw_plat_qsdk_mld_sta_recalc_link(struct osw_plat_qsdk11_4_mld_sta *mld_sta)
{
    if (mld_sta == NULL) return;

    const struct osw_drv_vif_state_sta_link *link = osw_plat_qsdk_mld_sta_get_associated_link(mld_sta);
    if (WARN_ON(link == NULL)) return;
    if (memcmp(link, &mld_sta->link, sizeof(*link)) == 0) return;

    LOGI(LOG_PREFIX_MLD_STA(mld_sta, "link: %s -> %s",
         osw_drv_vif_state_sta_link_status_to_cstr(mld_sta->link.status),
         osw_drv_vif_state_sta_link_status_to_cstr(link->status)));

    mld_sta->link = *link;
    osw_plat_qsdk_mld_sta_invalidate(mld_sta);
}

static void
osw_plat_qsdk_vif_sta_set_link(struct osw_plat_qsdk11_4_vif *vif,
                               const struct osw_drv_vif_state_sta_link *link)
{
    if (vif == NULL) return;
    if (WARN_ON(link == NULL)) return;
    if (memcmp(link, &vif->link, sizeof(*link)) == 0) return;
    vif->link = *link;
    struct osw_plat_qsdk11_4 *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    const char *phy_name = osw_plat_qsdk11_4_vif_into_phy_name(vif);
    const char *vif_name = vif->info->name;
    osw_drv_report_vif_changed(drv, phy_name, vif_name);
    osw_plat_qsdk_mld_sta_recalc_link(vif->mld_sta);
}

static bool
osw_plat_qsdk_conf_any_mlo_link_is_being_toggled(struct osw_drv_conf *drv_conf,
                                                 const char *vif_name)
{
    const char *slaves_path = strfmta("/sys/class/net/%s/master/bonding/slaves", vif_name);
    char *slaves = file_geta(slaves_path);
    char *if_name;
    while ((if_name = strsep(&slaves, " \r\n")) != NULL) {
        if (strlen(if_name) == 0) continue;

        struct osw_drv_vif_config *vif_conf = osw_plat_qsdk_conf_find_vif(drv_conf, if_name, NULL);
        if (WARN_ON(vif_conf == NULL)) continue;
        if (vif_conf->enabled_changed) return true;
    }
    return false;
}

/* The driver is not really dealing well with mlo link
 * reconfigurations and can get into perpetual
 * reconfiguration where one link goes up, and the other
 * goes down.
 */
static void
osw_plat_qsdk_mld_start_in_tandem(struct osw_drv_conf *drv_conf,
                                  const char *phy_name,
                                  const char *vif_name)
{
    const bool toggling = osw_plat_qsdk_conf_any_mlo_link_is_being_toggled(drv_conf, vif_name);
    const bool not_toggling = (toggling == false);
    if (not_toggling) return;

    const char *slaves_path = strfmta("/sys/class/net/%s/master/bonding/slaves", vif_name);
    char *slaves = file_geta(slaves_path);
    char *if_name;
    while ((if_name = strsep(&slaves, " \r\n")) != NULL) {
        if (strlen(if_name) == 0) continue;

        struct osw_drv_phy_config *phy_conf = NULL;
        struct osw_drv_vif_config *vif_conf = osw_plat_qsdk_conf_find_vif(drv_conf, if_name, &phy_conf);
        if (WARN_ON(vif_conf == NULL)) continue;

        if (vif_conf->enabled_changed == false) {
            LOGN(LOG_PREFIX_VIF(phy_conf->phy_name,
                                vif_conf->vif_name,
                                "forcing re-start due to mlo re-setup"));
            vif_conf->enabled_changed = true;
        }
    }
}

static void
osw_plat_qsdk11_4_ap_conf_mutate_cb(struct osw_hostap_hook *hook,
                                    const char *phy_name,
                                    const char *vif_name,
                                    struct osw_drv_conf *drv_conf,
                                    struct osw_hostap_conf_ap_config *hapd_conf,
                                    void *priv)
{
    /* hostapd will end up wasting 5s timing out
     * waiting for COUNTRY_UPDATE timeout before
     * moving to ENABLED state if these are set.
     * The driver doesn't really require 11d and
     * 11h options to operate on DFS, and
     * regulatory is set separately through
     * provisioning, so remove these knobs.
     */
    OSW_HOSTAP_CONF_UNSET(hapd_conf->country_code);
    OSW_HOSTAP_CONF_UNSET(hapd_conf->ieee80211d);
    OSW_HOSTAP_CONF_UNSET(hapd_conf->ieee80211h);

    /* The driver is generating Probe Responses internally */
    OSW_HOSTAP_CONF_SET_VAL(hapd_conf->send_probe_response, 0);

    /* The driver doesn't support this over nl80211. It also
     * is capable of more.
     */
    OSW_HOSTAP_CONF_UNSET(hapd_conf->beacon_rate);

    const char *mld_mac_path = strfmta("/sys/class/net/%s/master/bonding/../address", vif_name);
    char *mld_mac_addr = file_geta(mld_mac_path);

    if (mld_mac_addr != NULL) {
        strchomp(mld_mac_addr, " \r\n");
        char mld_link_macs[256];
        char mld_link_ids[256];
        MEMZERO(mld_link_macs);
        MEMZERO(mld_link_ids);
        osw_plat_qsdk_ap_conf_prep_mld_link_args(vif_name, drv_conf,
                                                 mld_link_macs, sizeof(mld_link_macs),
                                                 mld_link_ids, sizeof(mld_link_ids));
        STRSCAT(hapd_conf->extra_buf, strfmta("mld_link_macs=%s\n", mld_link_macs));
        STRSCAT(hapd_conf->extra_buf, strfmta("mld_link_ids=%s\n", mld_link_ids));
        STRSCAT(hapd_conf->extra_buf, strfmta("mld_mac_addr=%s\n", mld_mac_addr));

        osw_plat_qsdk_mld_start_in_tandem(drv_conf, phy_name, vif_name);
    }
}

static struct osw_drv_phy_config *
osw_plat_qsdk_drv_conf_get_phy(struct osw_drv_conf *drv_conf,
                               const char *phy_name)
{
    if (drv_conf == NULL) return NULL;
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy_conf = &drv_conf->phy_list[i];
        const bool match = (strcmp(phy_conf->phy_name, phy_name) == 0);
        if (match) return phy_conf;
    }
    return NULL;
}

static struct osw_drv_vif_config *
osw_plat_qsdk_phy_conf_get_vif(struct osw_drv_phy_config *phy_conf,
                               const char *vif_name)
{
    if (phy_conf == NULL) return NULL;
    size_t i;
    for (i = 0; i < phy_conf->vif_list.count; i++) {
        struct osw_drv_vif_config *vif_conf = &phy_conf->vif_list.list[i];
        const bool match = (strcmp(vif_conf->vif_name, vif_name) == 0);
        if (match) return vif_conf;
    }
    return NULL;
}

static int
osw_plat_qsdk_sta_conf_get_mld_links(struct osw_drv_conf *drv_conf,
                                     const char *vif_name)
{
    const char *slaves_path = strfmta("/sys/class/net/%s/master/bonding/slaves", vif_name);
    char *slaves = file_geta(slaves_path);
    char *if_name;
    int n = 0;
    while ((if_name = strsep(&slaves, " \r\n")) != NULL) {
        const bool exists = (strlen(if_name) > 0)
                         && (access(strfmta("/sys/class/net/%s", if_name), R_OK) == 0);
        const char *phy_path = strfmta("/sys/class/net/%s/parent", if_name);
        const char *phy_name = strchomp(file_geta(phy_path) ?: strdupa(""), " \r\n");
        struct osw_drv_phy_config *phy_conf = osw_plat_qsdk_drv_conf_get_phy(drv_conf, phy_name);
        struct osw_drv_vif_config *vif_conf = osw_plat_qsdk_phy_conf_get_vif(phy_conf, if_name);
        const bool enabled = vif_conf ? vif_conf->enabled : false;
        if (exists && enabled) n++;
    }
    return n;
}

static void
osw_plat_qsdk11_4_sta_conf_mutate_cb(struct osw_hostap_hook *hook,
                                     const char *phy_name,
                                     const char *vif_name,
                                     struct osw_drv_conf *drv_conf,
                                     struct osw_hostap_conf_sta_config *wpas_conf,
                                     void *priv)
{
    const char *mld_mac_path = strfmta("/sys/class/net/%s/master/bonding/../address", vif_name);
    char *mld_mac_addr = file_geta(mld_mac_path);
    if (mld_mac_addr != NULL) {
        strchomp(mld_mac_addr, " \r\n");
        const int num_mld_links = osw_plat_qsdk_sta_conf_get_mld_links(drv_conf, vif_name);
        STRSCAT(wpas_conf->extra_buf, strfmta("sta_mld_addr=%s\n", mld_mac_addr));
        STRSCAT(wpas_conf->extra_buf, strfmta("num_mlo_links=%d\n", num_mld_links));
        STRSCAT(wpas_conf->extra_buf, "preferred_assoc_link=0\n");
        STRSCAT(wpas_conf->extra_buf, "allow_non_ml_assoc=0\n");
        STRSCAT(wpas_conf->extra_buf, "mlo_skip_link_time=20\n"); /* seconds */

        osw_plat_qsdk_mld_start_in_tandem(drv_conf, phy_name, vif_name);
    }
}

static void
osw_plat_qsdk11_4_put_survey(struct osw_plat_qsdk11_4 *m,
                             struct osw_tlv *t,
                             const char *phy_name,
                             const struct channel_stats *cs)
{
    const uint32_t freq_mhz = cs->freq;
    const uint32_t active = osw_plat_qsdk11_4_cycle_to_msec(m, cs->cycle_cnt);
    const uint32_t tx = osw_plat_qsdk11_4_cycle_to_msec(m, cs->tx_frm_cnt);
    const uint32_t rx = osw_plat_qsdk11_4_cycle_to_msec(m, cs->rx_frm_cnt);
    const uint32_t inbss = osw_plat_qsdk11_4_cycle_to_msec(m, cs->bss_rx_cnt);
    const uint32_t busy = osw_plat_qsdk11_4_cycle_to_msec(m, cs->clear_cnt);
    const float noise = cs->chan_nf;

    LOGT(LOG_PREFIX_PHY(phy_name, "stats: survey:"
                        " freq=%"PRIu32" MHz"
                        " nf=%"PRId16" dB"
                        " total=%"PRIu32
                        " tx=%"PRIu32
                        " rx=%"PRIu32
                        " rx_bss=%"PRIu32
                        " clear=%"PRIu32,
                        cs->freq,
                        cs->chan_nf,
                        active,
                        tx,
                        rx,
                        inbss,
                        busy));

    /* FIXME: These stats aren't really msec. They are
     * MAC clock ticks. There's no way to get MAC clock
     * from the driver right now.
     *
     * Currently the code exclusively consumes
     * percentage variant which is automatically derived
     * from the msec bucket. Even if the msec bucket
     * uses a different unit, like MAC clock ticks,
     * it'll arrive at the same %, so it's fine for now.
     */

    const size_t off1 = osw_tlv_put_nested(t, OSW_STATS_CHAN);
    osw_tlv_put_string(t, OSW_STATS_CHAN_PHY_NAME, phy_name);
    osw_tlv_put_u32(t, OSW_STATS_CHAN_FREQ_MHZ, freq_mhz);
    osw_tlv_put_u32(t, OSW_STATS_CHAN_ACTIVE_MSEC, active);
    osw_tlv_put_float(t, OSW_STATS_CHAN_NOISE_FLOOR_DBM, noise);
    {

        const size_t off2 = osw_tlv_put_nested(t, OSW_STATS_CHAN_CNT_MSEC);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_TX, tx);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_RX, rx);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_RX_INBSS, inbss);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_BUSY, busy);
        osw_tlv_end_nested(t, off2);
    }
    osw_tlv_end_nested(t, off1);
}

static void
osw_plat_qsdk11_4_get_survey_stats_resp_cb(struct nl_cmd *cmd,
                                           struct nl_msg *msg,
                                           void *priv)
{
/* FIXME: Shouldn't this come from the driver? */
#define CFG80211_GET_CHAN_SURVEY_HOME_CHANNEL_STATS (1)
#define CFG80211_GET_CHAN_SURVEY_SCAN_CHANNEL_STATS (2)

    struct osw_plat_qsdk11_4_vif *vif = priv;
    struct osw_plat_qsdk11_4 *m = vif->m;
    //struct osw_plat_qsdk11_4 *m = priv;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);

    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    const int err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, NL80211_ATTR_MAX, NULL);
    if (WARN_ON(err)) return;

    struct nlattr *vendor = tb[NL80211_ATTR_VENDOR_DATA];
    if (WARN_ON(vendor == NULL)) return;

    struct nlattr *tbv[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1];
    const int verr = nla_parse_nested(tbv, QCA_WLAN_VENDOR_ATTR_PARAM_MAX, vendor, NULL);
    if (WARN_ON(verr)) return;

    struct nlattr *data = tbv[QCA_WLAN_VENDOR_ATTR_PARAM_DATA];
    struct nlattr *length = tbv[QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH];
    struct nlattr *flags = tbv[QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS];

    if (WARN_ON(data == NULL)) return;
    if (WARN_ON(flags == NULL)) return;

    const struct channel_stats *cs = nla_data(data);
    const size_t i_len = sizeof(*cs);
    uint32_t cs_len = nla_len(data);
    const bool is_home = (nla_get_u32(flags) == CFG80211_GET_CHAN_SURVEY_HOME_CHANNEL_STATS);

    WARN_ON(length != NULL && nla_get_u32(length) != cs_len);

    const struct nl_80211_phy *phy = nl_80211_phy_by_nla(nl, tb);
    if (WARN_ON(phy == NULL)) return;
    const char *phy_name = phy->name;
    uint32_t *home_freq = &vif->scan_home_freq;

    struct osw_tlv t;
    MEMZERO(t);

    while (cs_len >= i_len) {
        if (cs->freq != 0) {
            const bool skip = (*home_freq != 0 && cs->freq == *home_freq);
            if (!skip) {
                osw_plat_qsdk11_4_put_survey(m, &t, phy_name, cs);
            }
            if (is_home) {
                WARN_ON(*home_freq != 0);
                *home_freq = cs->freq;
                if (vif->last_home_freq != cs->freq) {
                    if (vif->last_home_freq != 0) {
                        LOGI(LOG_PREFIX_PHY(phy_name, "survey: resetting due to csa: "
                                            "%"PRIu32"MHz -> %"PRIu32"MHz",
                                            vif->last_home_freq,
                                            cs->freq));
                        osw_drv_report_stats_reset(OSW_STATS_CHAN);
                    }
                    vif->last_home_freq = cs->freq;
                }
            }
        }

        cs_len -= i_len;
        cs++;

        if (WARN_ON(is_home && cs_len > 0)) {
            /* This should not happen unless there's a
             * binary structure (ABI) mismatch, in which
             * case this should detect that and complain.
             */
            break;
        }
    }

    osw_drv_report_stats(drv, &t);
    osw_tlv_fini(&t);
}

static void
osw_plat_qsdk11_4_vif_get_country_resp_cb(struct nl_cmd *cmd,
                                          struct nl_msg *msg,
                                          void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;

    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    const int err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, NL80211_ATTR_MAX, NULL);
    if (WARN_ON(err)) return;

    struct nlattr *vendor = tb[NL80211_ATTR_VENDOR_DATA];
    if (WARN_ON(vendor == NULL)) return;

    struct nlattr *tbv[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1];
    const int verr = nla_parse_nested(tbv, QCA_WLAN_VENDOR_ATTR_PARAM_MAX, vendor, NULL);
    if (WARN_ON(verr)) return;

    struct nlattr *data = tbv[QCA_WLAN_VENDOR_ATTR_PARAM_DATA];
    struct nlattr *length = tbv[QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH];
    struct nlattr *flags = tbv[QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS];

    if (WARN_ON(data == NULL)) return;
    if (WARN_ON(flags == NULL)) return;

    const size_t min_len = 2;
    bool bad_length = false;
    bad_length |= WARN_ON(length != NULL && nla_get_u32(length) != (uint32_t)nla_len(data));
    bad_length |= WARN_ON((size_t)nla_len(data) < min_len);
    if (bad_length) return;

    const char *country = nla_data(data);
    vif->country_next[0] = country[0];
    vif->country_next[1] = country[1];
    vif->country_next[2] = '\0';
}

static struct nl_msg *
osw_plat_qsdk11_4_vif_cmd_survey_stats(struct nl_80211 *nl,
                                       uint32_t ifindex)
{
    const struct ieee80211req_athdbg data = {
        .cmd = IEEE80211_DBGREQ_GET_SURVEY_STATS,
    };
    const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
    const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_DBGREQ;
    const uint32_t flags = 0;
    const size_t len = sizeof(data);
    struct nl_msg *msg = nlmsg_alloc_size(len + 4096);
    const int family_id = nl_80211_get_family_id(nl);
    osw_plat_qsdk11_4_put_qca_vendor_cmd(msg, family_id, ifindex, vcmd, gcmd, 0, flags, &data, len);
    return msg;
}

static void
osw_plat_qsdk11_4_get_survey_phy(const struct nl_80211_phy *phy,
                                 void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    const char *phy_name = phy->name;
    if (osw_plat_qsdk11_4_is_mld_phy(phy_name)) return;

    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, false);
    if (vif_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (WARN_ON(vif == NULL)) return;

    rq_kill(&vif->q_stats);
    rq_resume(&vif->q_stats);

    vif->scan_home_freq = 0;
    rq_add_task(&vif->q_stats, &vif->task_survey.task);
}

static void
osw_plat_qsdk11_4_get_survey(struct osw_plat_qsdk11_4 *m)
{
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);

    nl_80211_phy_each(nl, osw_plat_qsdk11_4_get_survey_phy, m);
}

static void
osw_plat_qsdk11_4_flush_peer_stats_phy(const struct nl_80211_phy *phy,
                                       void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    bool is_phy_up = false;
    bool ret = false;

    const char *phy_name = phy->name;

    /* FIXME: This isn't terribly efficient. This
     * will be called fairly often and it'll
     * result in plenty of syscalls. This should
     * be cached, but this needs to be done
     * carefully in nl_80211_phy priv. The
     * phy_added_fn callback can be fired
     * out-of-order and the is_mld could change.
     */
    if (osw_plat_qsdk11_4_is_mld_phy(phy_name)) return;

    ret = os_nif_is_up(phy_name, &is_phy_up);
    if (ret == false) {
        LOGW(LOG_PREFIX_PHY(phy_name, "query whether interface is up failed"));
        return;
    }
    if (is_phy_up == false) {
        LOGT(LOG_PREFIX_PHY(phy_name, "state is down. %s skipped", __func__));
        return;
    }

    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, true);
    if (WARN_ON(vif_info == NULL)) return;

    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (WARN_ON(vif == NULL)) return;

    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (WARN_ON(nl == NULL)) return;

    const struct osw_plat_qsdk11_4_param_u32_arg arg_ol_stats = {
            .nl = nl,
            .ifindex = vif_info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = OL_SPECIAL_PARAM_SHIFT
                      | OL_SPECIAL_PARAM_ENABLE_OL_STATS,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL,
            .desired_value = 1,
            .vif_name = vif_info->name,
            .param_name = "ol_stats",
    };

    const struct osw_plat_qsdk11_4_param_u32_arg arg_flush_stats = {
            .nl = nl,
            .ifindex = vif_info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = OL_ATH_PARAM_SHIFT
                      | OL_ATH_PARAM_FLUSH_PEER_RATE_STATS,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_ALWAYS,
            .desired_value = 1,
            .vif_name = vif_info->name,
            .param_name = "flush_stats",
    };

    PARAM_U32_TASK_START(&vif->param_set_ol_stats, &arg_ol_stats);
    PARAM_U32_TASK_START(&vif->param_set_flush_stats, &arg_flush_stats);
}

static void
osw_plat_qsdk11_4_flush_peer_stats(struct osw_plat_qsdk11_4 *m)
{
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);

    nl_80211_phy_each(nl, osw_plat_qsdk11_4_flush_peer_stats_phy, m);
}

static void
osw_plat_qsdk11_4_pre_request_stats_cb(struct osw_drv_nl80211_hook *hook,
                                       unsigned int stats_mask,
                                       void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;

    if (stats_mask & (1 << OSW_STATS_CHAN)) {
        osw_plat_qsdk11_4_get_survey(m);
    }

    if (stats_mask & (1 << OSW_STATS_STA)) {
        osw_plat_qsdk11_4_flush_peer_stats(m);
    }
}

static void
osw_plat_qsdk11_4_phy_netif_cb(osn_netif_t *netif,
                               struct osn_netif_status *status)
{
    struct osw_plat_qsdk11_4_phy *phy = osn_netif_data_get(netif);
    struct osw_plat_qsdk11_4 *m = phy->m;
    struct osw_drv *drv = m->drv_nl80211;
    const char *phy_name = phy->info->name;

    osw_drv_report_phy_changed(drv, phy_name);
}

static void
osw_plat_qsdk11_4_phy_set_puncture_strict(struct osw_plat_qsdk11_4 *m,
                                          struct osw_plat_qsdk11_4_phy *phy)
{
    const char *phy_name = phy->info->name;
    if (osw_plat_qsdk11_4_is_mld_phy(phy_name)) return;

    const uint32_t ifindex = if_nametoindex(phy_name);
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return;

    const bool enable = 1;
    const int family_id = nl_80211_get_family_id(nl);
    struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_puncture_strict(family_id, ifindex, enable);
    if (msg == NULL) return;

    const char *name = strfmta("%s: puncture strict: %d", phy_name, enable);
    struct osw_plat_qsdk11_4_async *job = osw_plat_qsdk_nlcmd_alloc(name, nl, msg);
    osw_plat_qsdk11_4_task_start(&phy->task_set_puncture_strict, job);
}

static void
osw_plat_qsdk11_4_phy_set_puncture_dfs(struct osw_plat_qsdk11_4 *m,
                                       struct osw_plat_qsdk11_4_phy *phy)
{
    const char *phy_name = phy->info->name;
    if (osw_plat_qsdk11_4_is_mld_phy(phy_name)) return;

    const uint32_t ifindex = if_nametoindex(phy_name);
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return;

    const bool enable = ff_is_flag_enabled("use_dfs_punc") ? 1 : 0;
    const int family_id = nl_80211_get_family_id(nl);
    struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_puncture_dfs(family_id, ifindex, enable);
    if (msg == NULL) return;

    /* FIXME: This will generate an error info log for
     * non-DFS capable radio (ie. non-5GHz) right now. It's
     * harmless but may be confusing to the log reader.
     */

    const char *name = strfmta("%s: puncture dfs: %d", phy_name, enable);
    struct osw_plat_qsdk11_4_async *job = osw_plat_qsdk_nlcmd_alloc(name, nl, msg);
    osw_plat_qsdk11_4_task_start(&phy->task_set_puncture_dfs, job);
}

static void
osw_plat_qsdk11_4_phy_added_cb(const struct nl_80211_phy *info,
                               void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_phy *phy = nl_80211_sub_phy_get_priv(sub, info);
    if (phy == NULL) return;

    osw_plat_qsdk11_4_task_init_auto(&phy->task_mbss_tx_vdev);
    osw_plat_qsdk11_4_task_init_auto(&phy->task_set_puncture_strict);
    osw_plat_qsdk11_4_task_init_auto(&phy->task_set_puncture_dfs);
    osw_plat_qsdk11_4_task_init_auto(&phy->task_set_next_radar_freq);
    osw_plat_qsdk11_4_task_init_auto(&phy->task_set_next_radar_width);

    phy->info = info;
    phy->m = m;

    const char *phy_name = phy->info->name;
    phy->netif = osn_netif_new(phy_name);
    osn_netif_data_set(phy->netif, phy);
    osn_netif_status_notify(phy->netif, osw_plat_qsdk11_4_phy_netif_cb);

    osw_plat_qsdk11_4_phy_set_puncture_strict(m, phy);
    osw_plat_qsdk11_4_phy_set_puncture_dfs(m, phy);
}

static void
osw_plat_qsdk11_4_phy_removed_cb(const struct nl_80211_phy *info,
                                 void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_phy *phy = nl_80211_sub_phy_get_priv(sub, info);
    if (phy == NULL) return;

    osw_plat_qsdk11_4_task_drop(&phy->task_mbss_tx_vdev);
    osw_plat_qsdk11_4_task_drop(&phy->task_set_puncture_strict);
    osw_plat_qsdk11_4_task_drop(&phy->task_set_puncture_dfs);
    osw_plat_qsdk11_4_task_drop(&phy->task_set_next_radar_freq);
    osw_plat_qsdk11_4_task_drop(&phy->task_set_next_radar_width);

    phy->info = NULL;
    phy->m = NULL;

    osn_netif_del(phy->netif);
    phy->netif = NULL;
}

static void
osw_plat_qsdk11_4_vif_get_chanlist(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;

    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) {
        struct rq_task *t = &vif->task_get_chanlist.task;
        rq_task_kill(t);
        rq_add_task(q, t);
    }
}

static void
osw_plat_qsdk11_4_vif_get_regdomain(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;

    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) {
        struct rq_task *t = &vif->task_get_regdomain.task;
        rq_task_kill(t);
        rq_add_task(q, t);
    }
}

static void
osw_plat_qsdk11_4_vif_get_country_id(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;

    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) {
        struct rq_task *t = &vif->task_get_country_id.task;
        rq_task_kill(t);
        rq_add_task(q, t);
    }
}

static void
osw_plat_qsdk11_4_vif_get_country(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;

    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) {
        struct rq_task *t = &vif->task_get_country.task;
        rq_task_kill(t);
        rq_add_task(q, t);
    }
}

static void
osw_plat_qsdk11_4_vif_get_mcast2ucast(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_mcast2ucast.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}


static void
osw_plat_qsdk11_4_vif_get_wds(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_wds.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_mgmt_rate(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_mgmt_rate.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_mcast_rate(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_mcast_rate.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_bcast_rate(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_bcast_rate.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_beacon_rate(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_beacon_rate.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_max_rate(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_max_rate.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_cac_state(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_cac_state.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_rrm(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_rrm.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_mbss_en(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name) == false) return;

    struct rq_task *t = &vif->task_get_mbss_en.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_mbss_tx_vdev(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_mbss_tx_vdev.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_next_radar_freq(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) {
        struct rq_task *t = &vif->task_get_next_radar_freq.task;
        rq_task_kill(t);
        rq_add_task(q, t);
    }
}

static void
osw_plat_qsdk11_4_vif_get_next_radar_width(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) {
        struct rq_task *t = &vif->task_get_next_radar_width.task;
        rq_task_kill(t);
        rq_add_task(q, t);
    }
}

static void
osw_plat_qsdk11_4_vif_get_ap_bridge(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_ap_bridge.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_puncture_bitmap(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    const bool not_supported = (vif->task_get_puncture_bitmap.tmpl == NULL);
    if (not_supported) return;
    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_puncture_bitmap.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_acl(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;
    const uint32_t ifindex = info->ifindex;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct osw_plat_qsdk11_4 *m = vif->m;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const int family_id = nl_80211_get_family_id(nl);
    struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_getmac(family_id, ifindex);
    const char *name = strfmta("%s: getmac", vif_name);
    struct osw_plat_qsdk11_4_async *job = osw_plat_qsdk_nlcmd_alloc_resp(name, nl, msg, &vif->resp_get_acl);
    osw_plat_qsdk11_4_task_start(&vif->task_get_acl, job);
}

static void
osw_plat_qsdk11_4_vif_get_acl_policy(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;
    const uint32_t ifindex = info->ifindex;

    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct osw_plat_qsdk11_4 *m = vif->m;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const int family_id = nl_80211_get_family_id(nl);
    struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_get_maccmd(family_id, ifindex);
    const char *name = strfmta("%s: get_maccmd", vif_name);
    struct osw_plat_qsdk11_4_async *job = osw_plat_qsdk_nlcmd_alloc_resp(name, nl, msg, &vif->resp_get_acl_policy);
    osw_plat_qsdk11_4_task_start(&vif->task_get_acl_policy, job);
}

static void
osw_plat_qsdk11_4_vif_get_mbss_group(struct osw_plat_qsdk11_4_vif *vif)
{
    struct rq *q = &vif->q_state;
    rq_resume(q);

    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;

    const bool not_supported = (vif->task_get_mbss_group.tmpl == NULL);
    if (not_supported) return;
    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    struct rq_task *t = &vif->task_get_mbss_group.task;
    rq_task_kill(t);
    rq_add_task(q, t);
}

static void
osw_plat_qsdk11_4_vif_get_chanlist_done_cb(struct rq_task *task,
                                           void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->chanlist_prev, vif->chanlist_next);
    if (changed) osw_plat_qsdk11_4_phy_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_regdomain_done_cb(struct rq_task *task,
                                            void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->regdomain_prev, vif->regdomain_next);
    if (changed) osw_plat_qsdk11_4_phy_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_country_id_done_cb(struct rq_task *task,
                                             void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->country_id_prev, vif->country_id_next);
    if (changed) osw_plat_qsdk11_4_phy_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_country_done_cb(struct rq_task *task,
                                          void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->country_prev, vif->country_next);
    if (changed) osw_plat_qsdk11_4_phy_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_mcast2ucast_done_cb(struct rq_task *task,
                                              void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->mcast2ucast_prev, vif->mcast2ucast_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_wds_done_cb(struct rq_task *task,
                                              void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->wds_prev, vif->wds_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_mgmt_rate_done_cb(struct rq_task *task,
                                             void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->mgmt_rate_prev, vif->mgmt_rate_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_mcast_rate_done_cb(struct rq_task *task,
                                             void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->mcast_rate_prev, vif->mcast_rate_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_bcast_rate_done_cb(struct rq_task *task,
                                             void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->bcast_rate_prev, vif->bcast_rate_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_beacon_rate_done_cb(struct rq_task *task,
                                              void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->beacon_rate_prev, vif->beacon_rate_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_max_rate_done_cb(struct rq_task *task,
                                              void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->max_rate_prev, vif->max_rate_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_cac_state_done_cb(struct rq_task *task,
                                              void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->cac_state_prev, vif->cac_state_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_rrm_done_cb(struct rq_task *task,
                                      void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->rrm_prev, vif->rrm_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_mbss_en_done_cb(struct rq_task *task,
                                          void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->mbss_en_prev, vif->mbss_en_next);
    if (changed) osw_plat_qsdk11_4_phy_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_mbss_tx_vdev_done_cb(struct rq_task *task,
                                               void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->mbss_tx_vdev_prev, vif->mbss_tx_vdev_next);
    if (changed) osw_plat_qsdk11_4_phy_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_next_radar_freq_done_cb(struct rq_task *task,
                                               void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->next_radar_freq_prev, vif->next_radar_freq_next);
    if (changed) osw_plat_qsdk11_4_phy_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_next_radar_width_done_cb(struct rq_task *task,
                                               void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->next_radar_width_prev, vif->next_radar_width_next);
    if (changed) osw_plat_qsdk11_4_phy_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_ap_bridge_done_cb(struct rq_task *task,
                                            void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->ap_bridge_prev, vif->ap_bridge_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_get_puncture_bitmap_done_cb(struct rq_task *task,
                                                  void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->puncture_bitmap_prev, vif->puncture_bitmap_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_task_get_acl_done_cb(void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    struct osw_hwaddr *macs = NULL;
    size_t n_macs = 0;

    size_t i;
    for (i = 0; i < vif->resp_get_acl.n_msgs; i++) {
        struct nl_msg *msg = vif->resp_get_acl.msgs[i];
        int len = 0;
        const struct osw_hwaddr *mac = osw_plat_qsdk11_4_param_get_data(msg, &len);
        if (WARN_ON(mac == NULL)) continue;
        if (WARN_ON((size_t)len < sizeof(*mac))) continue;

        const size_t elem_size = sizeof(*macs);
        const size_t elem_count = n_macs + 1;
        const size_t new_size = elem_count * elem_size;
        macs = REALLOC(macs, new_size);
        memcpy(&macs[n_macs], mac, sizeof(*mac));
        n_macs++;
    }

    const size_t elem_size = sizeof(*macs);
    const size_t size = n_macs * elem_size;
    const bool changed = (vif->last_getmac_count != n_macs)
                      || (vif->last_getmac == NULL && macs != NULL)
                      || (vif->last_getmac != NULL && macs == NULL)
                      || ((vif->last_getmac != NULL && macs != NULL && memcmp(vif->last_getmac, macs, size) != 0));
    FREE(vif->last_getmac);
    vif->last_getmac = macs;
    vif->last_getmac_count = n_macs;
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_task_get_acl_policy_done_cb(void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    struct nl_msg *msg = vif->resp_get_acl_policy.first;
    const uint32_t *ptr = osw_plat_qsdk11_4_param_get_u32(msg);
    const uint32_t value = ptr ? *ptr : 0;
    const bool changed = (vif->last_maccmd != value);
    LOGT(LOG_PREFIX_VIF("", vif->info->name, "get_maccmd: %"PRIu32" -> %"PRIu32" (ptr=%p msg=%p)",
                        vif->last_maccmd, value, ptr, msg));
    vif->last_maccmd = value;
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_task_get_mbss_group_done_cb(struct rq_task *task,
                                                  void *priv)
{
    struct osw_plat_qsdk11_4_vif *vif = priv;
    const bool changed = OSW_PLAT_QSDK11_4_VIF_ATTR_SET(vif, vif->mbss_group_prev, vif->mbss_group_next);
    if (changed) osw_plat_qsdk11_4_vif_report_changed(vif);
}

static void
osw_plat_qsdk11_4_vif_enable_frame_fwd(struct osw_plat_qsdk11_4_vif *vif,
                                       struct nl_80211 *nl)
{
    const struct nl_80211_vif *info = vif->info;
    const char *vif_name = info->name;
    if (osw_plat_qsdk11_4_is_vif_name_qcawifi_phy(vif_name)) return;

    const struct nl_80211_phy *phy_info = nl_80211_phy_by_wiphy(nl, vif->info->wiphy);
    const char *phy_name = phy_info ? phy_info->name : NULL;
    const bool is_mld = phy_name ? osw_plat_qsdk11_4_is_mld_phy(phy_name) : false;
    if (is_mld) return;

    const uint32_t bits = 0
                        | (1 << (IEEE80211_FC0_SUBTYPE_AUTH >> IEEE80211_FC0_SUBTYPE_SHIFT))
                        | (1 << (IEEE80211_FC0_SUBTYPE_ASSOC_REQ >> IEEE80211_FC0_SUBTYPE_SHIFT))
                        | (1 << (IEEE80211_FC0_SUBTYPE_REASSOC_REQ >> IEEE80211_FC0_SUBTYPE_SHIFT))
                        | (1 << (IEEE80211_FC0_SUBTYPE_ACTION >> IEEE80211_FC0_SUBTYPE_SHIFT));

    const struct osw_plat_qsdk11_4_param_u32_arg arg_frame_fwd = {
        .nl = nl,
        .ifindex = info->ifindex,
        .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
        .param_id = IEEE80211_PARAM_FWD_ACTION_FRAMES_TO_APP,
        .policy = OSW_PLAT_QSDK11_4_PARAM_SET_IF_NOT_EQUAL,
        .desired_value = 1,
        .vif_name = info->name,
        .param_name = "fwd_action_frames_to_app",
    };

    const struct osw_plat_qsdk11_4_param_u32_arg arg_frame_mask = {
            .nl = nl,
            .ifindex = info->ifindex,
            .cmd_id = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            .param_id = IEEE80211_PARAM_VENDOR_FRAME_FWD_MASK,
            .policy = OSW_PLAT_QSDK11_4_PARAM_SET_BITMASK,
            .desired_bits_set = bits,
            .desired_bits_mask = bits,
            .vif_name = info->name,
            .param_name = "frame_fwd_mask",
    };

    PARAM_U32_TASK_START(&vif->param_set_frame_fwd, &arg_frame_fwd);
    PARAM_U32_TASK_START(&vif->param_set_frame_mask, &arg_frame_mask);
}

static void
osw_plat_qsdk11_4_vif_tx_power_changed_cb(struct osw_timer *t)
{
    struct osw_plat_qsdk11_4_vif *vif = container_of(t, struct osw_plat_qsdk11_4_vif, tx_power_changed);
    struct osw_plat_qsdk11_4 *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    const char *phy_name = osw_plat_qsdk11_4_vif_into_phy_name(vif);
    const char *vif_name = vif->info->name;

    if (drv == NULL) return;

    osw_drv_report_vif_changed(drv, phy_name, vif_name);
}

static void
osw_plat_qsdk11_4_vif_added_cb(const struct nl_80211_vif *info,
                               void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, info);
    if (vif == NULL) return;

    vif->info = info;
    vif->m = m;

    osw_timer_init(&vif->tx_power_changed, osw_plat_qsdk11_4_vif_tx_power_changed_cb);

    rq_init(&vif->q_stats, EV_DEFAULT);
    vif->q_stats.max_running = 1;

    const char *vif_name = info->name;
    const uint32_t ifindex = info->ifindex;
    const uint32_t wiphy = info->wiphy;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const int family_id = nl_80211_get_family_id(nl);
    const struct nl_80211_phy *phy_info = nl_80211_phy_by_wiphy(nl, wiphy);
    const char *phy_name = phy_info ? phy_info->name : NULL;
    struct nl_conn *conn = nl_80211_get_conn(nl);
    struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
    struct nl_msg *msg = osw_plat_qsdk11_4_vif_cmd_survey_stats(nl, ifindex);
    nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_survey_stats_resp_cb, vif);
    nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "survey stats")));
    nl_cmd_task_init(&vif->task_survey, cmd, msg);

    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_dbdc_enable);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_dbdc_samessiddisable);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_min_rssi_min);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_frame_fwd);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_frame_mask);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_ol_stats);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_flush_stats);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_mcast2ucast);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_rrm);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_ap_bridge);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_mgmt_rate);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_mcast_rate);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_bcast_rate);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_beacon_rate);
    osw_plat_qsdk11_4_task_init_auto(&vif->task_set_acl);
    osw_plat_qsdk11_4_task_init_auto(&vif->task_set_acl_policy);
    osw_plat_qsdk11_4_task_init_auto(&vif->task_set_mode);
    osw_plat_qsdk11_4_task_init_auto(&vif->param_set_wds);
    osw_plat_qsdk11_4_task_init_auto(&vif->task_exttool_csa);
    osw_plat_qsdk11_4_task_init_auto(&vif->task_upgrade_mode);
    osw_plat_qsdk11_4_task_init(&vif->task_get_acl,
                                osw_plat_qsdk11_4_vif_task_get_acl_done_cb,
                                vif);
    osw_plat_qsdk11_4_task_init(&vif->task_get_acl_policy,
                                osw_plat_qsdk11_4_vif_task_get_acl_policy_done_cb,
                                vif);

    osw_plat_qsdk11_4_vif_disable_dbdc(vif, nl);
    osw_plat_qsdk11_4_vif_enable_frame_fwd(vif, nl);
    osw_plat_qsdk11_4_vif_set_min_rssi_min(vif, nl);

    {
        rq_init(&vif->q_state, EV_DEFAULT);
        vif->q_state.max_running = 1;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS;
        const uint32_t flags = 0;

        struct ieee80211req_chaninfo_full *chans = &vif->chanlist_next;
        const struct extended_ioctl_wrapper data = {
            .cmd = EXTENDED_SUBIOCTL_GET_CHANINFO,
            .data = chans,
            .data_len = sizeof(*chans),
        };
        const size_t len = sizeof(data);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_cmd(msg, family_id, ifindex, vcmd, gcmd, 0, flags, &data, len);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get chanlist")));
        nl_cmd_task_init(&vif->task_get_chanlist, cmd, msg);
        vif->task_get_chanlist.task.completed_fn = osw_plat_qsdk11_4_vif_get_chanlist_done_cb;
        vif->task_get_chanlist.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_ME;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->mcast2ucast_arg;

        arg->out = &vif->mcast2ucast_next;
        arg->out_size = sizeof(vif->mcast2ucast_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get mcast2ucast")));
        nl_cmd_task_init(&vif->task_get_mcast2ucast, cmd, msg);
        vif->task_get_mcast2ucast.task.completed_fn = osw_plat_qsdk11_4_vif_get_mcast2ucast_done_cb;
        vif->task_get_mcast2ucast.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_MGMT_RATE;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->mgmt_rate_arg;

        arg->out = &vif->mgmt_rate_next;
        arg->out_size = sizeof(vif->mgmt_rate_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get mgmt_rate")));
        nl_cmd_task_init(&vif->task_get_mgmt_rate, cmd, msg);
        vif->task_get_mgmt_rate.task.completed_fn = osw_plat_qsdk11_4_vif_get_mgmt_rate_done_cb;
        vif->task_get_mgmt_rate.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_MCAST_RATE;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->mcast_rate_arg;

        arg->out = &vif->mcast_rate_next;
        arg->out_size = sizeof(vif->mcast_rate_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get mcast_rate")));
        nl_cmd_task_init(&vif->task_get_mcast_rate, cmd, msg);
        vif->task_get_mcast_rate.task.completed_fn = osw_plat_qsdk11_4_vif_get_mcast_rate_done_cb;
        vif->task_get_mcast_rate.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_BCAST_RATE;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->bcast_rate_arg;

        arg->out = &vif->bcast_rate_next;
        arg->out_size = sizeof(vif->bcast_rate_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get bcast_rate")));
        nl_cmd_task_init(&vif->task_get_bcast_rate, cmd, msg);
        vif->task_get_bcast_rate.task.completed_fn = osw_plat_qsdk11_4_vif_get_bcast_rate_done_cb;
        vif->task_get_bcast_rate.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_BEACON_RATE_FOR_VAP;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->beacon_rate_arg;

        arg->out = &vif->beacon_rate_next;
        arg->out_size = sizeof(vif->beacon_rate_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get beacon_rate")));
        nl_cmd_task_init(&vif->task_get_beacon_rate, cmd, msg);
        vif->task_get_beacon_rate.task.completed_fn = osw_plat_qsdk11_4_vif_get_beacon_rate_done_cb;
        vif->task_get_beacon_rate.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_GET_MAX_RATE;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->max_rate_arg;

        arg->out = &vif->max_rate_next;
        arg->out_size = sizeof(vif->max_rate_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get max_rate")));
        nl_cmd_task_init(&vif->task_get_max_rate, cmd, msg);
        vif->task_get_max_rate.task.completed_fn = osw_plat_qsdk11_4_vif_get_max_rate_done_cb;
        vif->task_get_max_rate.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_GET_CAC;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->cac_state_arg;

        arg->out = &vif->cac_state_next;
        arg->out_size = sizeof(vif->cac_state_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get cac_state")));
        nl_cmd_task_init(&vif->task_get_cac_state, cmd, msg);
        vif->task_get_cac_state.task.completed_fn = osw_plat_qsdk11_4_vif_get_cac_state_done_cb;
        vif->task_get_cac_state.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_RRM_CAP;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->rrm_arg;

        arg->out = &vif->rrm_next;
        arg->out_size = sizeof(vif->rrm_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get rrm cap")));
        nl_cmd_task_init(&vif->task_get_rrm, cmd, msg);
        vif->task_get_rrm.task.completed_fn = osw_plat_qsdk11_4_vif_get_rrm_done_cb;
        vif->task_get_rrm.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = OL_ATH_PARAM_SHIFT
                                | OL_ATH_PARAM_MBSS_EN;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->mbss_en_arg;

        arg->out = &vif->mbss_en_next;
        arg->out_size = sizeof(vif->mbss_en_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get mbss_en")));
        nl_cmd_task_init(&vif->task_get_mbss_en, cmd, msg);
        vif->task_get_mbss_en.task.completed_fn = osw_plat_qsdk11_4_vif_get_mbss_en_done_cb;
        vif->task_get_mbss_en.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_MBSS_TXVDEV;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->mbss_tx_vdev_arg;

        arg->out = &vif->mbss_tx_vdev_next;
        arg->out_size = sizeof(vif->mbss_tx_vdev_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get txvdev")));
        nl_cmd_task_init(&vif->task_get_mbss_tx_vdev, cmd, msg);
        vif->task_get_mbss_tx_vdev.task.completed_fn = osw_plat_qsdk11_4_vif_get_mbss_tx_vdev_done_cb;
        vif->task_get_mbss_tx_vdev.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = OL_ATH_PARAM_SHIFT
                                | OL_ATH_PARAM_NXT_RDR_FREQ;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->next_radar_freq_arg;

        arg->out = &vif->next_radar_freq_next;
        arg->out_size = sizeof(vif->next_radar_freq_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get next_radar_freq")));
        nl_cmd_task_init(&vif->task_get_next_radar_freq, cmd, msg);
        vif->task_get_next_radar_freq.task.completed_fn = osw_plat_qsdk11_4_vif_get_next_radar_freq_done_cb;
        vif->task_get_next_radar_freq.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
#ifdef WLAN_FEATURE_NEXT_RADAR_WIDTH
        const uint32_t param_id = OL_ATH_PARAM_SHIFT
                                | OL_ATH_PARAM_NXT_RDR_WIDTH;
#else
        const uint32_t param_id = 0;
#endif
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->next_radar_width_arg;

        arg->out = &vif->next_radar_width_next;
        arg->out_size = sizeof(vif->next_radar_width_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get next_radar_width")));
        nl_cmd_task_init(&vif->task_get_next_radar_width, cmd, msg);
        vif->task_get_next_radar_width.task.completed_fn = osw_plat_qsdk11_4_vif_get_next_radar_width_done_cb;
        vif->task_get_next_radar_width.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_APBRIDGE;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->ap_bridge_arg;

        arg->out = &vif->ap_bridge_next;
        arg->out_size = sizeof(vif->ap_bridge_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get apbridge")));
        nl_cmd_task_init(&vif->task_get_ap_bridge, cmd, msg);
        vif->task_get_ap_bridge.task.completed_fn = osw_plat_qsdk11_4_vif_get_ap_bridge_done_cb;
        vif->task_get_ap_bridge.task.priv = vif;
    }

    {
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->puncture_bitmap_arg;
        arg->out = &vif->puncture_bitmap_next;
        arg->out_size = sizeof(vif->puncture_bitmap_next);

        struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_get_puncture_bitmap(family_id, ifindex);
        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get puncture")));
        nl_cmd_task_init(&vif->task_get_puncture_bitmap, cmd, msg);
        vif->task_get_puncture_bitmap.task.completed_fn = osw_plat_qsdk11_4_vif_get_puncture_bitmap_done_cb;
        vif->task_get_puncture_bitmap.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = OL_SPECIAL_PARAM_SHIFT
                                | OL_SPECIAL_PARAM_REGDOMAIN;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->regdomain_arg;

        arg->out = &vif->regdomain_next;
        arg->out_size = sizeof(vif->regdomain_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get regdomain")));
        nl_cmd_task_init(&vif->task_get_regdomain, cmd, msg);
        vif->task_get_regdomain.task.completed_fn = osw_plat_qsdk11_4_vif_get_regdomain_done_cb;
        vif->task_get_regdomain.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = OL_SPECIAL_PARAM_SHIFT
                                | OL_SPECIAL_PARAM_COUNTRY_ID;
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->country_id_arg;

        arg->out = &vif->country_id_next;
        arg->out_size = sizeof(vif->country_id_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get country id")));
        nl_cmd_task_init(&vif->task_get_country_id, cmd, msg);
        vif->task_get_country_id.task.completed_fn = osw_plat_qsdk11_4_vif_get_country_id_done_cb;
        vif->task_get_country_id.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDORSUBCMD_COUNTRY_CONFIG;
        const uint32_t flags = 0;


        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_cmd(msg, family_id, ifindex, vcmd, gcmd, 0, flags, NULL, 0);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_vif_get_country_resp_cb, vif);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get country config")));
        nl_cmd_task_init(&vif->task_get_country, cmd, msg);
        vif->task_get_country.task.completed_fn = osw_plat_qsdk11_4_vif_get_country_done_cb;
        vif->task_get_country.task.priv = vif;
    }

    {
        const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
        const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
        const uint32_t param_id = IEEE80211_PARAM_WDS;

        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->wds_arg;

        arg->out = &vif->wds_next;
        arg->out_size = sizeof(vif->wds_next);

        struct nl_msg *msg = nlmsg_alloc();
        osw_plat_qsdk11_4_put_qca_vendor_getparam(msg, family_id, ifindex, vcmd, gcmd, param_id);

        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get wds")));
        nl_cmd_task_init(&vif->task_get_wds, cmd, msg);
        vif->task_get_wds.task.completed_fn = osw_plat_qsdk11_4_vif_get_wds_done_cb;
        vif->task_get_wds.task.priv = vif;
    }

    {
        struct osw_plat_qsdk11_4_get_param_arg *arg = &vif->mbss_group_arg;
        arg->out = &vif->mbss_group_next;
        arg->out_size = sizeof(vif->mbss_group_next);

        struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_get_mbss_group(family_id, ifindex);
        struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
        nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, arg);
        nl_cmd_set_name(cmd, strfmta(LOG_PREFIX_VIF(phy_name ?: "", vif_name, "get mbss group")));
        nl_cmd_task_init(&vif->task_get_mbss_group, cmd, msg);
        vif->task_get_mbss_group.task.completed_fn = osw_plat_qsdk11_4_vif_task_get_mbss_group_done_cb;
        vif->task_get_mbss_group.task.priv = vif;
    }

    if (osw_plat_qsdk11_4_is_mld_phy(phy_name)) return;
    osw_plat_qsdk11_4_vif_get_chanlist(vif);
    osw_plat_qsdk11_4_vif_get_mcast2ucast(vif);
    osw_plat_qsdk11_4_vif_get_mgmt_rate(vif);
    osw_plat_qsdk11_4_vif_get_mcast_rate(vif);
    osw_plat_qsdk11_4_vif_get_bcast_rate(vif);
    osw_plat_qsdk11_4_vif_get_beacon_rate(vif);
    osw_plat_qsdk11_4_vif_get_max_rate(vif);
    osw_plat_qsdk11_4_vif_get_cac_state(vif);
    osw_plat_qsdk11_4_vif_get_rrm(vif);
    osw_plat_qsdk11_4_vif_get_mbss_en(vif);
    osw_plat_qsdk11_4_vif_get_mbss_tx_vdev(vif);
    osw_plat_qsdk11_4_vif_get_next_radar_freq(vif);
    osw_plat_qsdk11_4_vif_get_next_radar_width(vif);
    osw_plat_qsdk11_4_vif_get_ap_bridge(vif);
    osw_plat_qsdk11_4_vif_get_puncture_bitmap(vif);
    osw_plat_qsdk11_4_vif_get_acl(vif);
    osw_plat_qsdk11_4_vif_get_acl_policy(vif);
    osw_plat_qsdk11_4_vif_get_regdomain(vif);
    osw_plat_qsdk11_4_vif_get_country_id(vif);
    osw_plat_qsdk11_4_vif_get_country(vif);
    osw_plat_qsdk11_4_vif_get_wds(vif);
    osw_plat_qsdk11_4_vif_get_mbss_group(vif);

    /* FIXME: There's no easy way to apply sta-only async
     * mode fix here. Some corner cases might not get
     * handled for now.
     */
}

static void
osw_plat_qsdk11_4_vif_removed_cb(const struct nl_80211_vif *info,
                                 void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, info);
    if (vif == NULL) return;

    osw_plat_qsdk11_4_task_drop(&vif->param_set_dbdc_enable);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_dbdc_samessiddisable);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_min_rssi_min);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_frame_fwd);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_frame_mask);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_ol_stats);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_flush_stats);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_mcast2ucast);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_rrm);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_ap_bridge);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_mgmt_rate);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_mcast_rate);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_bcast_rate);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_beacon_rate);
    osw_plat_qsdk11_4_task_drop(&vif->task_set_acl);
    osw_plat_qsdk11_4_task_drop(&vif->task_set_acl_policy);
    osw_plat_qsdk11_4_task_drop(&vif->task_set_mode);
    osw_plat_qsdk11_4_task_drop(&vif->param_set_wds);
    osw_plat_qsdk11_4_task_drop(&vif->task_exttool_csa);
    osw_plat_qsdk11_4_task_drop(&vif->task_upgrade_mode);
    osw_plat_qsdk11_4_task_drop(&vif->task_get_acl);
    osw_plat_qsdk11_4_task_drop(&vif->task_get_acl_policy);
    osw_plat_qsdk_vif_sta_set_mld(vif, NULL);

    FREE(vif->last_getmac);
    vif->last_getmac = NULL;

    rq_stop(&vif->q_stats);
    rq_kill(&vif->q_stats);
    rq_fini(&vif->q_stats);
    rq_stop(&vif->q_state);
    rq_kill(&vif->q_state);
    rq_fini(&vif->q_state);
    nl_cmd_task_fini(&vif->task_survey);
    nl_cmd_task_fini(&vif->task_get_chanlist);
    nl_cmd_task_fini(&vif->task_get_mcast2ucast);
    nl_cmd_task_fini(&vif->task_get_mgmt_rate);
    nl_cmd_task_fini(&vif->task_get_mcast_rate);
    nl_cmd_task_fini(&vif->task_get_bcast_rate);
    nl_cmd_task_fini(&vif->task_get_beacon_rate);
    nl_cmd_task_fini(&vif->task_get_max_rate);
    nl_cmd_task_fini(&vif->task_get_cac_state);
    nl_cmd_task_fini(&vif->task_get_rrm);
    nl_cmd_task_fini(&vif->task_get_mbss_en);
    nl_cmd_task_fini(&vif->task_get_mbss_tx_vdev);
    nl_cmd_task_fini(&vif->task_get_next_radar_freq);
    nl_cmd_task_fini(&vif->task_get_next_radar_width);
    nl_cmd_task_fini(&vif->task_get_ap_bridge);
    nl_cmd_task_fini(&vif->task_get_puncture_bitmap);
    nl_cmd_task_fini(&vif->task_get_regdomain);
    nl_cmd_task_fini(&vif->task_get_country_id);
    nl_cmd_task_fini(&vif->task_get_country);
    nl_cmd_task_fini(&vif->task_get_wds);
    nl_cmd_task_fini(&vif->task_get_mbss_group);

    vif->info = NULL;
    vif->m = NULL;
}

static void
osw_plat_qsdk11_4_event_stats_rx(struct osw_plat_qsdk11_4 *m,
                                 struct osw_tlv *t,
                                 const char *phy_name,
                                 const char *vif_name,
                                 const struct osw_hwaddr *sta_addr,
                                 const struct wlan_rx_rate_stats *stats,
                                 size_t stats_len)
{
    int left = WLANSTATS_CACHE_SIZE;

    uint64_t mpdu = 0;
    uint64_t retry = 0;
    uint64_t bytes = 0;

    while (stats_len >= sizeof(*stats) && left > 0) {
        mpdu += stats->num_mpdus;
        retry += stats->num_retries;
        bytes += stats->num_bytes;

        stats_len -= sizeof(*stats);
        stats++;
        left--;
    }

    WARN_ON(left != 0);
    WARN_ON(stats_len != 0);

    osw_tlv_put_u32_delta(t, OSW_STATS_STA_RX_BYTES, bytes);
    osw_tlv_put_u32_delta(t, OSW_STATS_STA_RX_FRAMES, mpdu);
    osw_tlv_put_u32_delta(t, OSW_STATS_STA_RX_RETRIES, retry);

    LOGT(LOG_PREFIX_STA(phy_name, vif_name, sta_addr,
                        "stats: rx:"
                        " mpdu=%"PRIu64
                        " retry=%"PRIu64
                        " bytes=%"PRIu64,
                        mpdu,
                        retry,
                        bytes));

    WARN_ON(bytes >= UINT32_MAX);
    WARN_ON(mpdu >= UINT32_MAX);
    WARN_ON(retry >= UINT32_MAX);
}

static void
osw_plat_qsdk11_4_event_stats_tx(struct osw_plat_qsdk11_4 *m,
                                 struct osw_tlv *t,
                                 const char *phy_name,
                                 const char *vif_name,
                                 const struct osw_hwaddr *sta_addr,
                                 const struct wlan_tx_rate_stats *stats,
                                 size_t stats_len)
{
    int left = WLANSTATS_CACHE_SIZE;

    uint64_t mpdu = 0;
    uint64_t retry = 0;
    uint64_t bytes = 0;

    while (stats_len >= sizeof(*stats) && left > 0) {
        if (WARN_ON(stats->mpdu_attempts < stats->mpdu_success)) {
            LOGW(LOG_PREFIX_STA(phy_name, vif_name, sta_addr,
                                "stats: tx:"
                                " mpdu_attempts=%"PRIu32
                                " mpdu_auccess=%"PRIu32
                                " num_bytes=%"PRIu32,
                                stats->mpdu_attempts,
                                stats->mpdu_success,
                                stats->num_bytes));
        }

        mpdu += stats->mpdu_success;
        retry += stats->mpdu_attempts - stats->mpdu_success;
        bytes += stats->num_bytes;

        stats_len -= sizeof(*stats);
        stats++;
        left--;
    }

    WARN_ON(left != 0);

    /* After a sequence of wlan_tx_rate_stats, there's
     * another struct appended. There's no struct definition
     * that contains both in driver headers though..
     */
    const struct wlan_tx_sojourn_stats *sojourn = (const void *)stats;
    if (WARN_ON(stats_len < sizeof(*sojourn))) return;

    osw_tlv_put_u32_delta(t, OSW_STATS_STA_TX_BYTES, bytes);
    osw_tlv_put_u32_delta(t, OSW_STATS_STA_TX_FRAMES, mpdu);
    osw_tlv_put_u32_delta(t, OSW_STATS_STA_TX_RETRIES, retry);

    LOGT(LOG_PREFIX_STA(phy_name, vif_name, sta_addr,
                        "stats: tx:"
                        " mpdu=%"PRIu64
                        " retry=%"PRIu64
                        " bytes=%"PRIu64,
                        mpdu,
                        retry,
                        bytes));

    WARN_ON(bytes >= UINT32_MAX);
    WARN_ON(mpdu >= UINT32_MAX);
    WARN_ON(retry >= UINT32_MAX);
}

static void
osw_plat_qsdk11_4_event_stats_avg(struct osw_plat_qsdk11_4 *m,
                                  struct osw_tlv *t,
                                  const char *phy_name,
                                  const char *vif_name,
                                  const struct osw_hwaddr *sta_addr,
                                  const struct wlan_avg_rate_stats *stats,
                                  size_t stats_len)
{
    const struct wlan_rate_avg *tx = stats->tx;
    const struct wlan_rate_avg *rx = stats->rx;
    size_t tx_size = sizeof(stats->tx);
    size_t rx_size = sizeof(stats->rx);

    stats_len -= tx_size;
    stats_len -= rx_size;
    WARN_ON(stats_len != 0);

    uint64_t tx_mbps = 0;
    uint64_t tx_ppdu = 0;
    uint64_t rx_mbps = 0;
    uint64_t rx_ppdu = 0;
    uint64_t snr = 0;
    uint64_t snr_cnt = 0;

    while (tx_size >= sizeof(*tx)) {
        tx_mbps += tx->sum_mbps;
        tx_ppdu += tx->num_ppdu;

        /* It seems Tx ACK SNR is prone to misreporting
         * lower-than-expected values. This can be mostly seen
         * on 6GHz band. Until this is fully investigated and
         * resolved don't use it unless explicitly enabled
         * through env flag. This ends up using Rx SNR only.
         */
        if (osw_etc_get("OSW_PLAT_QSDK11_4_USE_TX_ACK_SNR")) {
            snr += tx->sum_snr;
            snr_cnt += tx->num_snr;
        }

        tx_size -= sizeof(*tx);
        tx++;
    }

    while (rx_size >= sizeof(*rx)) {
        rx_mbps += rx->sum_mbps;
        rx_ppdu += rx->num_ppdu;
        snr += rx->sum_snr;
        snr_cnt += rx->num_snr;

        rx_size -= sizeof(*rx);
        rx++;
    }

    if (tx_ppdu > 0) tx_mbps /= tx_ppdu;
    if (rx_ppdu > 0) rx_mbps /= rx_ppdu;
    if (snr_cnt > 0) snr /= snr_cnt;

    if (tx_ppdu > 0) osw_tlv_put_u32(t, OSW_STATS_STA_TX_RATE_MBPS, tx_mbps);
    if (rx_ppdu > 0) osw_tlv_put_u32(t, OSW_STATS_STA_RX_RATE_MBPS, rx_mbps);
    if (snr_cnt > 0) osw_tlv_put_u32(t, OSW_STATS_STA_SNR_DB, snr);

    LOGT(LOG_PREFIX_STA(phy_name, vif_name, sta_addr,
                        "stats: avg:"
                        " tx=%"PRIu64
                        " rx=%"PRIu64
                        " snr=%"PRIu64,
                        tx_mbps,
                        rx_mbps,
                        snr));

    WARN_ON(tx_ppdu == 0 && tx_mbps > 0);
    WARN_ON(rx_ppdu == 0 && rx_mbps > 0);
    WARN_ON(snr_cnt == 0 && snr > 0);

    WARN_ON(tx_mbps >= UINT32_MAX);
    WARN_ON(rx_mbps >= UINT32_MAX);
    WARN_ON(snr >= UINT32_MAX);
}

static const char *
osw_plat_qsdk11_4_phy_sta_to_vif(struct osw_plat_qsdk11_4 *m,
                                 const char *phy_name,
                                 const struct osw_hwaddr *sta_addr)
{
    const struct osw_state_sta_info *info = osw_state_sta_lookup_newest(sta_addr);
    if (info == NULL) return NULL;

    const bool other_phy = (strcmp(info->vif->phy->phy_name, phy_name) != 0);
    if (other_phy) return NULL;

    return info->vif->vif_name;
}

static void
osw_plat_qsdk11_4_event_stats(struct osw_plat_qsdk11_4 *m,
                              const char *phy_name,
                              struct nlattr *vendor_data)
{
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return;

    if (WARN_ON(vendor_data == NULL)) return;
    if (WARN_ON(phy_name == NULL)) return;

    struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_MAX + 1];
    const int err = nla_parse_nested(tb, QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_MAX, vendor_data, NULL);
    if (WARN_ON(err)) return;

    struct nlattr *cache_type = tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_TYPE];
    struct nlattr *cache_data = tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_DATA];
    struct nlattr *cache_peer_mac = tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_PEER_MAC];
    struct nlattr *cache_peer_cookie = tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_PEER_COOKIE];

    if (WARN_ON(cache_type == NULL)) return;
    if (WARN_ON(cache_data == NULL)) return;
    if (WARN_ON(cache_peer_mac == NULL)) return;
    if (WARN_ON(cache_peer_cookie == NULL)) return;

    const uint32_t type = nla_get_u32(cache_type);
    const void *data = nla_data(cache_data);
    const size_t data_len = nla_len(cache_data);
    const uint8_t *peer_mac = nla_data(cache_peer_mac);
    const uint64_t peer_cookie = nla_get_u64(cache_peer_cookie);

    struct osw_hwaddr peer_addr;
    MEMZERO(peer_addr);

    if (WARN_ON(sizeof(peer_addr.octet) != nla_len(cache_peer_mac))) return;
    memcpy(peer_addr.octet, peer_mac, sizeof(peer_addr.octet));

    const char *vif_name = osw_plat_qsdk11_4_phy_sta_to_vif(m, phy_name, &peer_addr);
    /* This can't be easily WARN_ON, because self-peer
     * addresses will also be reported here. For now, just
     * silently exit.
     */
    if (vif_name == NULL) return;

    struct osw_tlv t;
    MEMZERO(t);

    size_t off = osw_tlv_put_nested(&t, OSW_STATS_STA);
    osw_tlv_put_string(&t, OSW_STATS_STA_PHY_NAME, phy_name);
    osw_tlv_put_string(&t, OSW_STATS_STA_VIF_NAME, vif_name);
    osw_tlv_put_hwaddr(&t, OSW_STATS_STA_MAC_ADDRESS, &peer_addr);

    switch (type) {
        case DP_PEER_RX_RATE_STATS:
            osw_plat_qsdk11_4_event_stats_rx(m, &t, phy_name, vif_name, &peer_addr, data, data_len);
            break;
        case DP_PEER_TX_RATE_STATS:
            osw_plat_qsdk11_4_event_stats_tx(m, &t, phy_name, vif_name, &peer_addr,data, data_len);
            break;
        case DP_PEER_AVG_RATE_STATS:
            osw_plat_qsdk11_4_event_stats_avg(m, &t, phy_name, vif_name, &peer_addr,data, data_len);
            break;
        default:
            LOGD(LOG_PREFIX_STA(phy_name, vif_name, &peer_addr,
                                "stats: unknown: type=%u len=%zu cookie=%"PRIu64,
                                type, data_len, peer_cookie));
            break;
    }

    osw_tlv_end_nested(&t, off);

    osw_drv_report_stats(drv, &t);
    osw_tlv_fini(&t);
}

static void
osw_plat_qsdk11_4_frame_fwd(struct osw_plat_qsdk11_4 *m,
                            const char *phy_name,
                            const char *vif_name,
                            const void *data,
                            const size_t data_len)
{
    if (WARN_ON(phy_name == NULL)) return;
    if (WARN_ON(vif_name == NULL)) return;
    if (WARN_ON(data == NULL)) return;

    size_t rem;
    const struct osw_drv_dot11_frame_header *hdr = ieee80211_frame_into_header(data, data_len, rem);
    if (hdr == NULL) return;
    (void)rem;

    const uint16_t fc = le16toh(hdr->frame_control);
    const uint16_t type = (fc & DOT11_FRAME_CTRL_TYPE_MASK);
    const uint16_t subtype = (fc & DOT11_FRAME_CTRL_SUBTYPE_MASK);
    const bool is_mgmt = (type == DOT11_FRAME_CTRL_TYPE_MGMT);
    const bool is_auth = (subtype == DOT11_FRAME_CTRL_SUBTYPE_AUTH);
    const bool is_assoc_req = (subtype == DOT11_FRAME_CTRL_SUBTYPE_ASSOC_REQ);
    const bool is_reassoc_req = (subtype == DOT11_FRAME_CTRL_SUBTYPE_REASSOC_REQ);
    const bool is_action = (subtype == DOT11_FRAME_CTRL_SUBTYPE_ACTION);
    const bool can_report = (is_mgmt && (is_auth
                                      || is_assoc_req
                                      || is_reassoc_req
                                      || is_action));
    const bool skip_report = !can_report;
    if (skip_report) return;

    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return;

    const struct osw_drv_vif_frame_rx rx = {
        .data = data,
        .len = data_len,
    };
    osw_drv_report_vif_frame_rx(drv,
                                phy_name,
                                vif_name,
                                &rx);
}

static void
osw_plat_qsdk11_4_event_get_wifi_conf(struct osw_plat_qsdk11_4 *m,
                                      const char *phy_name,
                                      const char *vif_name,
                                      struct nlattr *vendor_data)
{
    if (WARN_ON(vendor_data == NULL)) return;
    if (WARN_ON(phy_name == NULL)) return;
    if (WARN_ON(vif_name == NULL)) return;

    struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_CONFIG_MAX + 1];
    const int err = nla_parse_nested(tb, QCA_WLAN_VENDOR_ATTR_CONFIG_MAX, vendor_data, NULL);
    if (WARN_ON(err)) return;

    struct nlattr *generic_cmd = tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND];
    struct nlattr *generic_data = tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA];

    if (WARN_ON(generic_cmd == NULL)) return;
    if (WARN_ON(generic_data == NULL)) return;

    const uint32_t gencmd = nla_get_u32(generic_cmd);
    const void *data = nla_data(generic_data);
    const size_t data_len = nla_len(generic_data);

    switch (gencmd) {
        case QCA_NL80211_VENDOR_SUBCMD_FWD_MGMT_FRAME:
            osw_plat_qsdk11_4_frame_fwd(m,
                                        phy_name,
                                        vif_name,
                                        data,
                                        data_len);
            return;
    }
}

static void
osw_plat_qsdk11_4_event_vendor(struct osw_plat_qsdk11_4 *m,
                               const char *phy_name,
                               const char *vif_name,
                               struct nlattr *nla_vendor_id,
                               struct nlattr *nla_vendor_subcmd,
                               struct nlattr *nla_vendor_data)
{
    if (WARN_ON(nla_vendor_id == NULL)) return;
    if (WARN_ON(nla_vendor_subcmd == NULL)) return;

    const uint32_t id = nla_get_u32(nla_vendor_id);
    const uint32_t subcmd = nla_get_u32(nla_vendor_subcmd);

    if (id != QCA_NL80211_VENDOR_ID) return;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "event: vendor: cmd=%u data_len=%u",
                        subcmd,
                        nla_vendor_data ? nla_len(nla_vendor_data) : 0));

    switch (subcmd) {
        case QCA_NL80211_VENDOR_SUBCMD_PEER_STATS_CACHE_FLUSH:
            /* Can't pass vif_name. It's always the special
             * wifiX netdev, not the actual STA link netdev.
             */
            osw_plat_qsdk11_4_event_stats(m, phy_name, nla_vendor_data);
            return;
        case QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION:
            osw_plat_qsdk11_4_event_get_wifi_conf(m, phy_name, vif_name, nla_vendor_data);
            return;
    }
}

static void
osw_plat_qsdk11_4_nl_conn_event_cb(struct nl_conn_subscription *sub,
                                   struct nl_msg *msg,
                                   void *priv)
{
    const uint8_t cmd = genlmsg_hdr(nlmsg_hdr(msg))->cmd;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    const int err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, NL80211_ATTR_MAX, NULL);
    if (err) return;

    struct osw_plat_qsdk11_4 *m = priv;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const struct nl_80211_phy *phy_info = nl_80211_phy_by_nla(nl, tb);
    const struct nl_80211_vif *vif_info = nl_80211_vif_by_nla(nl, tb);
    const char *phy_name = phy_info ? phy_info->name : NULL;
    const char *vif_name = vif_info ? vif_info->name : NULL;

    struct nlattr *vendor_id = tb[NL80211_ATTR_VENDOR_ID];
    struct nlattr *vendor_subcmd = tb[NL80211_ATTR_VENDOR_SUBCMD];
    struct nlattr *vendor_data = tb[NL80211_ATTR_VENDOR_DATA];

    switch (cmd) {
        case NL80211_CMD_VENDOR:
            osw_plat_qsdk11_4_event_vendor(m,
                                           phy_name,
                                           vif_name,
                                           vendor_id,
                                           vendor_subcmd,
                                           vendor_data);
            return;
    }
}

static void
osw_plat_qsdk11_4_fix_phy_mac_addr(const char *phy_name,
                                   struct osw_drv_phy_state *state)
{
    os_macaddr_t dev_addr;
    char *ifname = STRDUP(phy_name);
    const bool dev_addr_valid = os_nif_macaddr_get(ifname, &dev_addr);
    FREE(ifname);
    if (dev_addr_valid) {
        struct osw_hwaddr mac_addr;
        memcpy(mac_addr.octet, &dev_addr.addr, ETH_ALEN);
        LOGD(LOG_PREFIX_PHY(phy_name, "fix: mac_addr: "OSW_HWADDR_FMT" -> "OSW_HWADDR_FMT,
                            OSW_HWADDR_ARG(&state->mac_addr),
                            OSW_HWADDR_ARG(&mac_addr)));
        state->mac_addr = mac_addr;
    }
}

static void
osw_plat_qsdk11_4_fix_phy_chan_states(struct osw_plat_qsdk11_4 *m,
                                      const char *phy_name,
                                      struct osw_drv_phy_state *state)
{
    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, true);
    if (vif_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (vif == NULL) return;

    const struct ieee80211req_chaninfo_full *chans = &vif->chanlist_prev;

    osw_plat_qsdk11_4_fill_chan_states(phy_name, chans, state);

    /* This will result in possible double-call because if
     * the chanlist really changed it will generate another
     * request call, but it won't invalidate state again
     * next time.
     */
    osw_plat_qsdk11_4_vif_get_chanlist(vif);
}

static void
osw_plat_qsdk11_4_fix_phy_next_radar(struct osw_plat_qsdk11_4 *m,
                                     const char *phy_name,
                                     struct osw_drv_phy_state *state)
{
    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, true);
    if (vif_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (vif == NULL) return;

    uint32_t control_freq = vif->next_radar_freq_prev;

    uint32_t width_mhz = 20;
    if (vif->next_radar_width_prev != 0)
    {
        // maybe we have width, if not, it will be inserted
        width_mhz = vif->next_radar_width_prev;
    }

    const int *p_chanlist = unii_5g_chan2list(osw_freq_to_chan(control_freq), width_mhz);
    const int center_freq_chan = osw_chan_avg(p_chanlist);
    const enum osw_band band = osw_freq_to_band(control_freq);
    const int center_freq_mhz = osw_chan_to_freq(band, center_freq_chan);
    const struct osw_channel c = {
        .control_freq_mhz = control_freq,
        .center_freq0_mhz = center_freq_mhz,
        .width = osw_channel_width_mhz_to_width(width_mhz),
        .puncture_bitmap = 0,
    };
    state->radar_next_channel = c;

    osw_plat_qsdk11_4_vif_get_next_radar_freq(vif);
    osw_plat_qsdk11_4_vif_get_next_radar_width(vif);
}

static void
osw_plat_qsdk11_4_fix_phy_regdomain(struct osw_plat_qsdk11_4 *m,
                                    const char *phy_name,
                                    struct osw_drv_phy_state *state)
{
    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, true);
    if (vif_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (vif == NULL) return;

    const uint32_t regdomain = vif->regdomain_prev;
    state->reg_domain.revision = regdomain;

    osw_plat_qsdk11_4_vif_get_regdomain(vif);
}

static void
osw_plat_qsdk11_4_fix_phy_country_id(struct osw_plat_qsdk11_4 *m,
                                     const char *phy_name,
                                     struct osw_drv_phy_state *state)
{
    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, true);
    if (vif_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (vif == NULL) return;

    const uint32_t country_id = vif->country_id_prev;
    state->reg_domain.iso3166_num = country_id;

    osw_plat_qsdk11_4_vif_get_country_id(vif);
}

static void
osw_plat_qsdk11_4_fix_phy_country(struct osw_plat_qsdk11_4 *m,
                                  const char *phy_name,
                                  struct osw_drv_phy_state *state)
{
    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, true);
    if (vif_info == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (vif == NULL) return;

    const char *country = vif->country_prev;
    const bool invalid_country = (country[0] == '0' &&
                                  country[1] == '0');
    const bool valid_country = (invalid_country == false);
    if (valid_country) {
        state->reg_domain.ccode[0] = country[0];
        state->reg_domain.ccode[1] = country[1];
        state->reg_domain.ccode[2] = '\0';
    }

    osw_plat_qsdk11_4_vif_get_country(vif);
}

static void
osw_plat_qsdk11_4_fix_phy_enabled(const char *phy_name,
                                  struct osw_drv_phy_state *state)
{
    os_nif_is_up((char *)phy_name, &state->enabled);
}

static void
osw_plat_qsdk11_4_fix_phy_puncture(struct osw_plat_qsdk11_4 *m,
                                   struct osw_drv_phy_state *state)
{
    /* FIXME: This should both consider runtime (and the
     * exposed APIs, eg. do a probe if command is
     * recognized) and check if the phy max mode supports
     * 11be.
     */
    state->puncture_supported = kconfig_enabled(CONFIG_QCA_WIFI_PUNCTURE_SUPPORTED);
}

static void
osw_plat_qsdk11_4_fix_phy_state_cb(struct osw_drv_nl80211_hook *hook,
                                   const char *phy_name,
                                   struct osw_drv_phy_state *state,
                                   void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;

    osw_plat_qsdk11_4_fix_phy_enabled(phy_name, state);
    osw_plat_qsdk11_4_fix_phy_mac_addr(phy_name, state);
    osw_plat_qsdk11_4_fix_phy_chan_states(m, phy_name, state);
    osw_plat_qsdk11_4_fix_phy_next_radar(m, phy_name, state);
    osw_plat_qsdk11_4_fix_phy_regdomain(m, phy_name, state);
    osw_plat_qsdk11_4_fix_phy_country_id(m, phy_name, state);
    osw_plat_qsdk11_4_fix_phy_country(m, phy_name, state);
    osw_plat_qsdk11_4_fix_phy_puncture(m, state);
}

static void
osw_plat_qsdk11_4_fix_mcast2ucast(struct osw_plat_qsdk11_4_vif *vif,
                                  const char *phy_name,
                                  const char *vif_name,
                                  struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;
    const uint32_t me = vif->mcast2ucast_prev;
    ap->mcast2ucast = (me != QCA_WIFI_MC_ME_DISABLE);
}

static void
osw_plat_qsdk11_4_fix_rates(struct osw_plat_qsdk11_4_vif *vif,
                            const char *phy_name,
                            const char *vif_name,
                            struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;
    const uint32_t bcn = vif->beacon_rate_prev;
    const uint32_t mgmt = vif->mgmt_rate_prev;
    const uint32_t mcast = vif->mcast_rate_prev;
    const uint32_t bcast = vif->bcast_rate_prev;
    const int kbps = bcn; /* eg. 1000 = 1mbps */
    const int halfmbps = kbps / 500;
    const enum osw_rate_legacy rate = osw_rate_legacy_from_halfmbps(halfmbps);
    const bool unknown_rate = osw_rate_is_invalid(rate);
    if (unknown_rate) return;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "beacon_rate: %d kbps", kbps));
    ap->mode.beacon_rate.type = OSW_BEACON_RATE_ABG;
    ap->mode.beacon_rate.u.legacy = rate;
    ap->mode.mgmt_rate = osw_rate_legacy_from_halfmbps(mgmt / 500);
    ap->mode.mcast_rate = (mcast == bcast)
                        ? osw_rate_legacy_from_halfmbps(mcast / 500)
                        : OSW_RATE_UNSPEC;
}


static void
osw_plat_qsdk11_4_fix_rrm(struct osw_plat_qsdk11_4_vif *vif,
                          const char *phy_name,
                          const char *vif_name,
                          struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;
    const uint32_t rrm = vif->rrm_prev;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "rrm: %d", rrm));
    ap->mode.rrm_neighbor_report = rrm;
}

static void
osw_plat_qsdk11_4_fix_ap_bridge(struct osw_plat_qsdk11_4_vif *vif,
                                const char *phy_name,
                                const char *vif_name,
                                struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;
    const uint32_t ap_bridge = vif->ap_bridge_prev;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "ap_bridge: %d", ap_bridge));
    ap->isolated = !ap_bridge;
}

static uint32_t osw_plat_qsdk11_4_puncture_bitmap_from_raw_u32(const char *phy_name,
                                      const char *vif_name,
                                      uint32_t prev_puncture_bitmap)
{
    uint32_t puncture_bitmap = prev_puncture_bitmap;

    /* The driver uses the same struct for handling connections
     * on interface as an AP and as a station. As AP in mode 802.11be
     * puncturing bitmap will be correctly set. As station, connected
     * to (i.e. GW) in non-802.11be mode the puncturing bitmap field
     * will be invalidated. Value "puncturing invalid" for
     * puncture_bitmap is 0xffff, while every channel is available.
     */
    if (prev_puncture_bitmap == 0xffff)
    {
        LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "puncture_bitmap: invalid value - fixing"));
        puncture_bitmap = 0x0000;
    }
    return puncture_bitmap;
}

static void
osw_plat_qsdk11_4_fix_puncture_bitmap(struct osw_plat_qsdk11_4_vif *vif,
                                      const char *phy_name,
                                      const char *vif_name,
                                      struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;

    const uint32_t puncture_bitmap = osw_plat_qsdk11_4_puncture_bitmap_from_raw_u32(phy_name, vif_name, vif->puncture_bitmap_prev);
    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "puncture_bitmap: %"PRIx32, puncture_bitmap));

    switch (state->vif_type) {
        case OSW_VIF_AP:
            {
                struct osw_drv_vif_state_ap *ap = &state->u.ap;
                ap->channel.puncture_bitmap = (puncture_bitmap & 0xffff);
                break;
            }
        case OSW_VIF_STA:
            {
                struct osw_drv_vif_state_sta *sta = &state->u.sta;
                sta->link.channel.puncture_bitmap = (puncture_bitmap & 0xffff);
                break;
            }
        case OSW_VIF_AP_VLAN:
        case OSW_VIF_UNDEFINED:
            break;
    }
}

static void
osw_plat_qsdk11_4_fix_acl(struct osw_plat_qsdk11_4_vif *vif,
                          const char *phy_name,
                          const char *vif_name,
                          struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;
    const struct osw_hwaddr *macs = vif->last_getmac;
    const size_t count = vif->last_getmac_count;
    const size_t size = count * sizeof(*macs);

    size_t i;
    for (i = 0; i < count; i++) {
        LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "acl: addr: "OSW_HWADDR_FMT, OSW_HWADDR_ARG(&macs[i])));
    }
    ap->acl.list = macs
                 ? MEMNDUP(macs, size)
                 : NULL;
    ap->acl.count = macs
                  ? count
                  : 0;
}

static void
osw_plat_qsdk11_4_fix_acl_policy(struct osw_plat_qsdk11_4_vif *vif,
                                 const char *phy_name,
                                 const char *vif_name,
                                 struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;
    const uint32_t maccmd = vif->last_maccmd;
    const enum osw_acl_policy policy = osw_plat_qsdk11_4_maccmd_to_policy(maccmd);

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "acl_policy: %"PRIu32" (%s)",
                        maccmd,
                        osw_acl_policy_to_str(policy)));
    ap->acl_policy = policy;
}

static void
osw_plat_qsdk11_4_fix_vif_mbss_tx_vif_state(struct osw_plat_qsdk11_4_vif *vif,
                                           const char *phy_name,
                                           const char *vif_name,
                                           struct osw_drv_vif_state *state,
                                           struct osw_plat_qsdk11_4 *m)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    struct nl_80211_sub *sub = m->nl_sub;
    const struct nl_80211_vif *phy_info = nl_80211_vif_by_name(nl, phy_name);
    struct osw_plat_qsdk11_4_vif *phy = nl_80211_sub_vif_get_priv(sub, phy_info);

    if (phy->mbss_en_prev == false) {
        ap->mbss_mode = OSW_MBSS_NONE;
        return;
    }

    const bool vif_is_mbss_tx_vdev = vif->mbss_tx_vdev_prev;
    const bool vif_is_not_mbss_tx_vdev = !vif_is_mbss_tx_vdev;

    if (vif_is_not_mbss_tx_vdev) {
        ap->mbss_mode = OSW_MBSS_NON_TX_VAP;
        return;
    }

    ap->mbss_mode = OSW_MBSS_TX_VAP;
}

static void
osw_plat_qsdk11_4_fix_vif_mbss_tx_vif_group(struct osw_plat_qsdk11_4_vif *vif,
                                           const char *phy_name,
                                           const char *vif_name,
                                           struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;
    if (ap == NULL) return;

    const uint32_t mbss_group = vif->mbss_group_prev;
    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "mbss_group: %d",
                        mbss_group));

    ap->mbss_group = mbss_group;
}

/* This returns the MLD Address for a given Affiliated netdev ifindex */
static const struct osw_hwaddr *
osw_plat_qsdk_find_mld_mac_by_ifindex(struct nl_msg **msgs,
                                      uint32_t ifindex)
{
    if (msgs == NULL) return NULL;

    while (*msgs != NULL) {
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        const int err = genlmsg_parse(nlmsg_hdr(*msgs), 0, tb, NL80211_ATTR_MAX, NULL);
        const bool parsed = (err == 0);
        if (parsed) {
            struct nlattr *index = tb[NL80211_ATTR_IFINDEX];
            struct nlattr *mld_addr = osw_plat_qsdk_attr_mld_mac(tb);
            const bool index_matches = (index != NULL)
                                    && (nla_get_u32(index) == ifindex);
            const bool mld_defined = (mld_addr != NULL);

            if (index_matches && mld_defined) {
                return osw_hwaddr_from_cptr(nla_data(mld_addr),
                                            nla_len(mld_addr));
            }
        }
        msgs++;
    }

    return NULL;
}

/* This is akin to if_nametoindex, except it deals
 * with MAC Addresses and netdev names.
 */
static const char *
osw_plat_qsdk_find_if_name_by_mac(struct nl_msg **msgs,
                                  const struct osw_hwaddr *addr)
{
    if (msgs == NULL) return NULL;

    while (*msgs != NULL) {
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        const int err = genlmsg_parse(nlmsg_hdr(*msgs), 0, tb, NL80211_ATTR_MAX, NULL);
        const bool parsed = (err == 0);
        if (parsed) {
            struct nlattr *if_name = tb[NL80211_ATTR_IFNAME];
            struct nlattr *mac = tb[NL80211_ATTR_MAC];
            const bool if_name_exists = (if_name != NULL);
            const struct osw_hwaddr *vif_addr = (mac != NULL)
                                              ? osw_hwaddr_from_cptr(nla_data(mac),
                                                                      nla_len(mac))
                                              : NULL;
            const bool mac_matches = (vif_addr != NULL)
                                   ? osw_hwaddr_is_equal(vif_addr, addr)
                                   : false;
            if (mac_matches && if_name_exists) {
                return nla_data(if_name);
            }
        }
        msgs++;
    }

    return NULL;
}

static struct nl_msg *
osw_plat_qsdk_msg_genl_get_family(const char *name)
{
    struct nl_msg *msg = nlmsg_alloc();
    if (WARN_ON(genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1) == NULL)) {
        goto free;
    }
    if (WARN_ON(nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, name) < 0)) {
        goto free;
    }
    return msg;
free:
    nlmsg_free(msg);
    return NULL;
}

static int
osw_plat_qsdk_parse_genl_family_id(struct nl_msg *msg)
{
    static struct nla_policy policy[CTRL_ATTR_MAX + 1] = {
        [CTRL_ATTR_FAMILY_ID] = { .type = NLA_U16 },
    };
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    const int parse_err = genlmsg_parse(nlh, 0, tb, CTRL_ATTR_MAX, policy);
    if (parse_err) return -1;
    struct nlattr *id = tb[CTRL_ATTR_FAMILY_ID];
    if (id != NULL) return nla_get_u16(id);
    return -1;
}

static int
osw_plat_qsdk_get_nl80211_family_id(void)
{
    struct nl_msg *msg = osw_plat_qsdk_msg_genl_get_family("nl80211");
    cr_nl_cmd_t *cmd = cr_nl_cmd(NULL, NETLINK_GENERIC, msg);
    while (cr_nl_cmd_run(cmd) == false) {}
    struct nl_msg *resp = cr_nl_cmd_resp(cmd);
    const int family_id = osw_plat_qsdk_parse_genl_family_id(resp);
    cr_nl_cmd_drop(&cmd);
    return family_id;
}

static struct nl_msg *
osw_plat_qsdk_msg_dump_interfaces(void)
{
    const int family_id = osw_plat_qsdk_get_nl80211_family_id();
    if (WARN_ON(family_id < 0)) return NULL;

    struct nl_msg *msg = nlmsg_alloc();
    const uint8_t cmd = NL80211_CMD_GET_INTERFACE;
    const int flags = NLM_F_DUMP;
    assert(genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, flags, cmd, 0) != NULL);

    return msg;
}

static void
osw_plat_qsdk_fix_state_mld_with_resp(struct osw_drv_mld_state *mld,
                                      uint32_t ifindex,
                                      struct nl_msg **msgs)
{
    const struct osw_hwaddr *mld_addr = osw_plat_qsdk_find_mld_mac_by_ifindex(msgs, ifindex);
    if (mld_addr == NULL) return;
    if (osw_hwaddr_is_zero(mld_addr)) return;
    mld->addr = *mld_addr;

    const char *mld_if_name = osw_plat_qsdk_find_if_name_by_mac(msgs, mld_addr);
    if (mld_if_name == NULL) return;
    STRSCPY_WARN(mld->if_name.buf, mld_if_name);
}

static void
osw_plat_qsdk_fix_state_mld(struct osw_plat_qsdk11_4 *m,
                            const char *vif_name,
                            struct osw_drv_vif_state *state)
{
    const uint32_t ifindex = if_nametoindex(vif_name);
    if (ifindex == 0) return;

    struct nl_msg *msg = osw_plat_qsdk_msg_dump_interfaces();
    cr_nl_cmd_t *cmd = cr_nl_cmd(NULL, NETLINK_GENERIC, msg);
    while (cr_nl_cmd_run(cmd) == false) {}

    struct nl_msg **msgs = cr_nl_cmd_resps(cmd);
    switch (state->vif_type) {
        case OSW_VIF_AP:
            osw_plat_qsdk_fix_state_mld_with_resp(&state->u.ap.mld, ifindex, msgs);
            break;
        case OSW_VIF_UNDEFINED:
            break;
        case OSW_VIF_AP_VLAN:
            break;
        case OSW_VIF_STA:
            osw_plat_qsdk_fix_state_mld_with_resp(&state->u.sta.mld, ifindex, msgs);
            break;
    }

    cr_nl_cmd_drop(&cmd);
}

static void
osw_plat_qsdk_fix_state_mld_sta(struct osw_plat_qsdk11_4 *m,
                                const char *vif_name,
                                struct osw_drv_vif_state *state)
{
    const char *mld_name = state->u.sta.mld.if_name.buf;
    if (strlen(mld_name) == 0) return;

    struct osw_plat_qsdk11_4_mld_sta *mld_sta = osw_plat_qsdk11_4_mld_sta_lookup(m, mld_name);
    if (mld_sta == NULL) return;

    const struct osw_hwaddr bssid = state->u.sta.link.bssid;
    const struct osw_channel channel = state->u.sta.link.channel;

    /* Inherit everything except the BSSID. The BSSID is
     * expected to be correct and is specific per link.
     * Other parameters like PMF, AKM are inherited from the
     * main link which was used for association itself.
     */
    state->u.sta.link = mld_sta->link;
    state->u.sta.link.bssid = bssid;
    state->u.sta.link.channel = channel;
}

static bool
osw_plat_qsdk_mlo_cac_in_progress(struct osw_plat_qsdk11_4_vif *vif)
{
    struct osw_plat_qsdk11_4 *m = vif->m;
    struct nl_80211_sub *sub = m->nl_sub;
    if (sub == NULL) return false;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return false;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return false;
    if (vif->info == NULL) return false;
    const char *vif_name = vif->info->name;
    const char *slaves_path = strfmta("/sys/class/net/%s/master/bonding/slaves", vif_name);
    char *slaves = file_geta(slaves_path);
    char *if_name;
    while ((if_name = strsep(&slaves, " \r\n")) != NULL) {
        if (strlen(if_name) == 0) continue;

        const struct nl_80211_vif *vif_info = nl_80211_vif_by_name(nl, vif_name);
        if (vif_info == NULL) continue;

        struct osw_plat_qsdk11_4_vif *other_vif = nl_80211_sub_vif_get_priv(sub, vif_info);
        if (vif == other_vif) continue;

        const bool other_vif_cac_in_progress = (other_vif->cac_state_prev != 0);
        if (other_vif_cac_in_progress) return true;
    }
    return false;
}

static void
osw_plat_qsdk11_4_fix_status(struct osw_plat_qsdk11_4_vif *vif,
                             const char *phy_name,
                             const char *vif_name,
                             struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP) return;

    const bool vap_is_down = (vif->max_rate_prev == 0);
    const bool cac_in_progress = (vif->cac_state_prev != 0);

    /* Initial MLO implementation does not support dynamic
     * (re)setup of AP MLD. This means that whenever any of
     * the links is down, all other links are down too. This
     * means that starting up operating on a DFS channel
     * that requires CAC implies other AP links will be kept
     * down too. As such additional check needs to be done
     * to "fake" the state report of other MLD links.
     */
    const bool mlo_cac_in_progress = osw_plat_qsdk_mlo_cac_in_progress(vif);

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "status: down=%d cac=%d",
                        vap_is_down,
                        cac_in_progress));

    /* Historically CAC was considered as "vap is up".
     * That's not entirely correct, but for osw_confsync it
     * is at the moment, until that is addressed in core.
     *
     * For the time being this allows reporting _really_
     * broken states where VAP is not beaconing *and* its
     * not because of CAC. This allows osw_confsync to
     * detect and recover.
     */
    const bool skip_override = (vap_is_down && (cac_in_progress || mlo_cac_in_progress))
                            || (vap_is_down == false);
    if (skip_override) return;

    osw_vif_status_set(&state->status, vap_is_down ? OSW_VIF_DISABLED : OSW_VIF_ENABLED);
}

static void
osw_plat_qsdk_fix_vif_sta_multi_ap_networks(struct osw_plat_qsdk11_4_vif *vif,
                                            const char *phy_name,
                                            const char *vif_name,
                                            struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_STA) return;

    const bool wds_state = vif->wds_prev;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "wds: %d", wds_state));

    struct osw_drv_vif_state_sta *sta = &state->u.sta;
    struct osw_drv_vif_sta_network *network = sta->network;

    while (network != NULL) {
        network->multi_ap = wds_state;
        network = network->next;
    }
}

static void
osw_plat_qsdk_fix_vif_sta_multi_ap_link(struct osw_plat_qsdk11_4_vif *vif,
                                        const char *phy_name,
                                        const char *vif_name,
                                        struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_STA) return;

    struct osw_drv_vif_state_sta *sta = &state->u.sta;

    if (sta == NULL) return;

    switch (sta->link.status) {
        case OSW_DRV_VIF_STATE_STA_LINK_CONNECTED:
            {
                sta->link.multi_ap = vif->wds_prev;
            }
        case OSW_DRV_VIF_STATE_STA_LINK_CONNECTING:
        case OSW_DRV_VIF_STATE_STA_LINK_DISCONNECTED:
        case OSW_DRV_VIF_STATE_STA_LINK_UNKNOWN:
            break;
    }
}

static void
osw_plat_qsdk_fix_vif_sta_multi_ap(struct osw_plat_qsdk11_4_vif *vif,
                                   const char *phy_name,
                                   const char *vif_name,
                                   struct osw_drv_vif_state *state)
{
    osw_plat_qsdk_fix_vif_sta_multi_ap_networks(vif, phy_name, vif_name, state);
    osw_plat_qsdk_fix_vif_sta_multi_ap_link(vif, phy_name, vif_name, state);
}

static const struct osw_state_vif_info *
osw_plat_qsdk_find_parent_ap_vlan(struct osw_plat_qsdk11_4_vif *child_vif,
                                  const char *vif_name)
{
    char *vif_name_copy = strdupa(vif_name);
    const char *parent_if_name = strsep(&vif_name_copy, ".");
    return osw_state_vif_lookup_by_vif_name(parent_if_name);
}

static void
osw_plat_qsdk_fix_vif_ap_multi_ap(struct osw_plat_qsdk11_4_vif *vif,
                                  const char *phy_name,
                                  const char *vif_name,
                                  struct osw_drv_vif_state *state)
{
    if (vif == NULL) return;
    if (state->vif_type != OSW_VIF_AP_VLAN) return;

    struct osw_drv_vif_state_ap_vlan *ap_vlan = &state->u.ap_vlan;
    if (ap_vlan == NULL) return;

    const struct osw_state_vif_info *parent_ap = osw_plat_qsdk_find_parent_ap_vlan(vif, vif_name);
    if (parent_ap == NULL) return;

    const struct osw_hwaddr *sta_addr = &state->mac_addr;

    osw_hwaddr_list_append(&ap_vlan->sta_addrs, sta_addr);
    memcpy(state->mac_addr.octet, &parent_ap->drv_state->mac_addr.octet, ETH_ALEN);
}

static void
osw_plat_qsdk11_4_fix_vif_state_cb(struct osw_drv_nl80211_hook *hook,
                                   const char *phy_name,
                                   const char *vif_name,
                                   struct osw_drv_vif_state *state,
                                   void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    struct nl_80211_sub *sub = m->nl_sub;
    const struct nl_80211_vif *vif_info = nl_80211_vif_by_name(nl, vif_name);
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);

    osw_plat_qsdk11_4_fix_mcast2ucast(vif, phy_name, vif_name, state);
    osw_plat_qsdk11_4_fix_rates(vif, phy_name, vif_name, state);
    osw_plat_qsdk11_4_fix_rrm(vif, phy_name, vif_name, state);
    osw_plat_qsdk11_4_fix_ap_bridge(vif, phy_name, vif_name, state);
    osw_plat_qsdk11_4_fix_puncture_bitmap(vif, phy_name, vif_name, state);
    osw_plat_qsdk11_4_fix_acl(vif, phy_name, vif_name, state);
    osw_plat_qsdk11_4_fix_acl_policy(vif, phy_name, vif_name, state);
    osw_plat_qsdk11_4_fix_status(vif, phy_name, vif_name, state);
    osw_plat_qsdk11_4_fix_vif_mbss_tx_vif_state(vif, phy_name, vif_name, state, m);
    osw_plat_qsdk11_4_fix_vif_mbss_tx_vif_group(vif, phy_name, vif_name, state);

    if (osw_plat_qsdk11_4_is_mld_phy(phy_name)) return;

    osw_plat_qsdk11_4_vif_get_mcast2ucast(vif);
    osw_plat_qsdk11_4_vif_get_mgmt_rate(vif);
    osw_plat_qsdk11_4_vif_get_mcast_rate(vif);
    osw_plat_qsdk11_4_vif_get_bcast_rate(vif);
    osw_plat_qsdk11_4_vif_get_beacon_rate(vif);
    osw_plat_qsdk11_4_vif_get_max_rate(vif);
    osw_plat_qsdk11_4_vif_get_cac_state(vif);
    osw_plat_qsdk11_4_vif_get_rrm(vif);
    osw_plat_qsdk11_4_vif_get_mbss_en(vif);
    osw_plat_qsdk11_4_vif_get_mbss_tx_vdev(vif);
    osw_plat_qsdk11_4_vif_get_ap_bridge(vif);
    osw_plat_qsdk11_4_vif_get_puncture_bitmap(vif);
    osw_plat_qsdk11_4_vif_get_acl(vif);
    osw_plat_qsdk11_4_vif_get_acl_policy(vif);
    osw_plat_qsdk11_4_vif_get_wds(vif);
    osw_plat_qsdk_fix_state_mld(m, vif_name, state);
    if (state->vif_type == OSW_VIF_STA) {
        osw_plat_qsdk_vif_sta_set_mld(vif, state->u.sta.mld.if_name.buf);
        osw_plat_qsdk_vif_sta_set_link(vif, &state->u.sta.link);
        osw_plat_qsdk_fix_state_mld_sta(m, vif_name, state);
    }
    osw_plat_qsdk_fix_vif_sta_multi_ap(vif, phy_name, vif_name, state);
    osw_plat_qsdk_fix_vif_ap_multi_ap(vif, phy_name, vif_name, state);
    osw_plat_qsdk11_4_vif_get_mbss_group(vif);
}

static const struct osw_hwaddr *
osw_plat_qsdk_list_sta_find_mld_addr(struct nl_msg **msgs,
                                     const struct osw_hwaddr *sta_addr)
{
    while (msgs != NULL && *msgs != NULL) {
        int len;
        const void *ptr = osw_plat_qsdk11_4_param_get_data(*msgs, &len);
        for (;;) {
            const struct ieee80211req_sta_info *sta = ptr;
            if (sta == NULL) break;
            if (len < (int)sizeof(*sta)) break;

            const struct osw_hwaddr *iter_addr = osw_hwaddr_from_cptr_unchecked(sta->isi_macaddr);
            if (osw_hwaddr_is_equal(sta_addr, iter_addr)) {
                const struct osw_hwaddr *mld_addr = osw_plat_qsdk_isi_mld_addr(sta);
                if (mld_addr != NULL) {
                    return mld_addr;
                }
            }

            ptr += sta->isi_len;
            len -= sta->isi_len;
        }
        msgs++;
    }
    return NULL;
}

static struct nl_msg *
osw_plat_qsdk_msg_list_sta(struct osw_plat_qsdk11_4 *m,
                           const char *vif_name)
{
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return NULL;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return NULL;
    const uint32_t ifindex = if_nametoindex(vif_name);
    const int family_id = nl_80211_get_family_id(nl);
    struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_list_sta(family_id, ifindex);
    return msg;
}

static void
osw_plat_qsdk_log_nl_cmd_failure(cr_nl_cmd_t *cmd)
{
    char buf[1024];
    cr_nl_cmd_log(cmd, buf, sizeof(buf));
    if (cr_nl_cmd_is_ok(cmd)) {
        LOGT("%s", buf);
    }
    else {
        LOGI("%s", buf);
    }
}

static bool
osw_plat_qsdk_sta_get_mld_addr(struct osw_plat_qsdk11_4 *m,
                               const char *vif_name,
                               const struct osw_hwaddr *sta_addr,
                               struct osw_hwaddr *mld_addr)
{
    const char *phy_name = "";
    const char *name = strfmta(LOG_PREFIX_STA(phy_name, vif_name, sta_addr, "list sta"));
    struct nl_msg *msg = osw_plat_qsdk_msg_list_sta(m, vif_name);
    cr_nl_cmd_t *cmd = cr_nl_cmd(NULL, NETLINK_GENERIC, msg);
    cr_nl_cmd_set_name(cmd, name);
    while (cr_nl_cmd_run(cmd) == false) {}
    osw_plat_qsdk_log_nl_cmd_failure(cmd);

    struct nl_msg **msgs = cr_nl_cmd_resps(cmd);
    const struct osw_hwaddr *addr = osw_plat_qsdk_list_sta_find_mld_addr(msgs, sta_addr);
    const bool can_store = (mld_addr != NULL);
    const bool found = (addr != NULL);
    if (found && can_store) {
        *mld_addr = *addr;
    }

    cr_nl_cmd_drop(&cmd);
    return found;
}

static void
osw_plat_qsdk11_4_fix_sta_state_cb(struct osw_drv_nl80211_hook *hook,
                                   const char *phy_name,
                                   const char *vif_name,
                                   const struct osw_hwaddr *sta_addr,
                                   struct osw_drv_sta_state *state,
                                   void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    osw_plat_qsdk_sta_get_mld_addr(m, vif_name, sta_addr, &state->mld_addr);
}

static void
util_nl_parse_iwevcustom(struct osw_plat_qsdk11_4 *m,
                         const char *ifname,
                         const void *data,
                         const size_t len)
{
    struct osw_drv *drv = m->drv_nl80211;
    const char *vif_name = ifname;

    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return;

    struct nl_80211_sub *sub = m->nl_sub;
    if (sub == NULL) return;

    const struct nl_80211_vif *vif_info = nl_80211_vif_by_name(nl, vif_name);
    if (vif_info == NULL) return;

    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, vif_info);
    if (vif == NULL) return;

    const char *phy_name = osw_plat_qsdk11_4_vif_into_phy_name(vif);
    if (phy_name == NULL) return;

    const struct iw_point *iwp;

    iwp = data - IW_EV_POINT_OFF;;
    data += IW_EV_POINT_LEN - IW_EV_POINT_OFF;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "parsing iwevcustom: flags=%hu length=%hu len=%zu",
                        iwp->flags, iwp->length, len));

    if (iwp->length > len) {
        LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "parsing iwevcustom: bad length"));
        return;
    }

    switch (iwp->flags) {
        case IEEE80211_EV_BLKLST_STA_AUTH_IND_AP:
            {
                const struct ev_msg *msg = data;
                if (iwp->length < sizeof(*msg)) return;

                const struct osw_hwaddr *addr = osw_hwaddr_from_cptr_unchecked(msg->addr);

                os_macaddr_t bssid;
                const bool bssid_ok = os_nif_macaddr_get((char *)ifname, &bssid);
                const bool bssid_not_ok = !bssid_ok;
                if (bssid_not_ok) return;

                struct osw_drv_dot11_frame_header auth_frame;
                MEMZERO(auth_frame);
                auth_frame.frame_control = htole16(DOT11_FRAME_CTRL_SUBTYPE_AUTH);
                memcpy(auth_frame.sa, addr->octet, ETH_ALEN);
                memcpy(auth_frame.da, bssid.addr, ETH_ALEN);
                memcpy(auth_frame.bssid, bssid.addr, ETH_ALEN);

                const struct osw_drv_vif_frame_rx rx = {
                    .data = (const void *)&auth_frame,
                    .len = sizeof(auth_frame),
                };

                if (drv == NULL) return;
                osw_drv_report_vif_frame_rx(drv,
                                            phy_name,
                                            vif_name,
                                            &rx);
            }
            return;
    }
}

static void
osw_plat_qsdk11_4_wext_fd_rx(struct osw_plat_qsdk11_4 *m,
                             const void *data,
                             size_t len)
{
    const struct iw_event *iwe;
    const struct nlmsghdr *hdr;
    const struct rtattr *attr;
    char ifname[32];
    int attrlen;
    int iwelen;

    util_nl_each_msg(data, hdr, len)
        if (hdr->nlmsg_type == RTM_NEWLINK ||
            hdr->nlmsg_type == RTM_DELLINK) {

            memset(ifname, 0, sizeof(ifname));

            util_nl_each_attr_type(hdr, attr, attrlen, IFLA_IFNAME)
                memcpy(ifname, RTA_DATA(attr), RTA_PAYLOAD(attr));

            if (strlen(ifname) == 0)
                continue;

            util_nl_each_attr_type(hdr, attr, attrlen, IFLA_WIRELESS)
                util_nl_each_iwe_type(attr, iwe, iwelen, IWEVCUSTOM)
                    util_nl_parse_iwevcustom(m,
                                             ifname,
                                             util_nl_iwe_data(iwe),
                                             util_nl_iwe_payload(iwe));
        }
}

static void
osw_plat_qsdk11_4_wext_stop(EV_P_ struct osw_plat_qsdk11_4 *m)
{
    ev_io_stop(EV_A_ &m->wext_io);
}

static void
osw_plat_qsdk11_4_wext_io_cb(EV_P_ ev_io *io, int events)
{
    struct osw_plat_qsdk11_4 *m = io->data;
    if (events == EV_READ) {
        const int fd = io->fd;
        char buf[4096];
        ssize_t len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (len > 0) {
            osw_plat_qsdk11_4_wext_fd_rx(m, buf, (size_t)len);
        }
        else {
            switch (errno) {
                case EAGAIN: return;
                case ENOBUFS: return;
                default:
                    LOGE(LOG_PREFIX("wext socket died: errno=%d (%s)",
                                    errno, strerror(errno)));
                    osw_plat_qsdk11_4_wext_stop(EV_A_ m);
                    break;
            }
        }
    }
}

static int
osw_plat_qsdk11_4_wext_open(void)
{
     const int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
     const bool failed_to_create_socket = (fd < 0);
     if (WARN_ON(failed_to_create_socket)) return -1;

     struct sockaddr_nl addr;
     MEMZERO(addr);
     addr.nl_family = AF_NETLINK;
     addr.nl_groups = RTMGRP_LINK;
     const int bind_err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
     const bool failed_to_bind = (bind_err != 0);
     if (WARN_ON(failed_to_bind)) {
        close(fd);
        return -1;
     }

     return fd;
}

static void
osw_plat_qsdk11_4_wext_start(EV_P_ struct osw_plat_qsdk11_4 *m)
{
    const int fd = osw_plat_qsdk11_4_wext_open();
    const bool failed_to_open = (fd < 0);
    if (WARN_ON(failed_to_open)) return;

    ev_io_init(&m->wext_io, osw_plat_qsdk11_4_wext_io_cb, fd, EV_READ);
    ev_io_start(EV_A_ &m->wext_io);
    m->wext_io.data = m;
}

static void
osw_plat_qsdk11_4_start(struct osw_plat_qsdk11_4 *m)
{
    if (osw_plat_qsdk11_4_is_disabled()) return;

    /* FIXME: This probably should look at
     * osw_plat_qsdk11_4_is_enabled() at some point.
     */

    static const struct osw_drv_nl80211_hook_ops nl_hook_ops = {
        .fix_phy_state_fn = osw_plat_qsdk11_4_fix_phy_state_cb,
        .fix_vif_state_fn = osw_plat_qsdk11_4_fix_vif_state_cb,
        .fix_sta_state_fn = osw_plat_qsdk11_4_fix_sta_state_cb,
        .pre_request_config_fn = osw_plat_qsdk11_4_pre_request_config_cb,
        .pre_request_stats_fn = osw_plat_qsdk11_4_pre_request_stats_cb,
    };

    static const struct nl_80211_sub_ops nl_sub_ops = {
        .phy_added_fn = osw_plat_qsdk11_4_phy_added_cb,
        .phy_removed_fn = osw_plat_qsdk11_4_phy_removed_cb,
        .vif_added_fn = osw_plat_qsdk11_4_vif_added_cb,
        .vif_removed_fn = osw_plat_qsdk11_4_vif_removed_cb,
        .priv_phy_size = sizeof(struct osw_plat_qsdk11_4_phy),
        .priv_vif_size = sizeof(struct osw_plat_qsdk11_4_vif),
    };

    static const struct osw_hostap_hook_ops hapd_hook_ops = {
        .ap_conf_mutate_fn = osw_plat_qsdk11_4_ap_conf_mutate_cb,
        .sta_conf_mutate_fn = osw_plat_qsdk11_4_sta_conf_mutate_cb,
    };

    struct ev_loop *loop = OSW_MODULE_LOAD(osw_ev);
    if (loop == NULL) return;

    m->nl_ops = OSW_MODULE_LOAD(osw_drv_nl80211);
    if (m->nl_ops == NULL) return;

    m->nl_hook = m->nl_ops->add_hook_ops_fn(m->nl_ops, &nl_hook_ops, m);
    if (WARN_ON(m->nl_hook == NULL)) return;

    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    m->nl_sub = nl_80211_alloc_sub(nl, &nl_sub_ops, m);
    if (WARN_ON(m->nl_sub == NULL)) return;

    m->nl_conn = nl_80211_get_conn(nl);
    m->nl_conn_sub = nl_conn_subscription_alloc();
    if (WARN_ON(m->nl_conn_sub == NULL)) return;
    nl_conn_subscription_set_event_fn(m->nl_conn_sub, osw_plat_qsdk11_4_nl_conn_event_cb, m);
    nl_conn_subscription_start(m->nl_conn_sub, m->nl_conn);

    m->hostap = OSW_MODULE_LOAD(osw_hostap);
    m->hostap_hook = osw_hostap_hook_alloc(m->hostap, &hapd_hook_ops, m);
    if (WARN_ON(m->hostap_hook == NULL)) return;

    osw_plat_qsdk11_4_wext_start(loop, m);
    osw_plat_qsdk11_4_rename_wiphy();
    osw_state_register_observer(&m->state_obs);
}

static struct osw_plat_qsdk11_4 g_osw_plat_qsdk11_4;

OSW_MODULE(osw_plat_qsdk11_4)
{
    struct osw_plat_qsdk11_4 *m = &g_osw_plat_qsdk11_4;
    osw_plat_qsdk11_4_init(m);
    osw_plat_qsdk11_4_start(m);
    return m;
}
