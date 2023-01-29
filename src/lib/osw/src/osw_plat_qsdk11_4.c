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
#include <linux/nl80211.h>

/* opensync */
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

/* osw */
#include <osw_drv.h>
#include <osw_state.h>
#include <osw_module.h>
#include <osw_drv_nl80211.h>
#include <osw_hostap.h>

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

#define QCA_WIFI_MC_ME_DISABLE 0
#define QCA_WIFI_MC_ME_HYFI 5
#define QCA_WIFI_MC_ME_AMSDU 6

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
osw_plat_qsdk11_4_put_qca_vendor_cmd(struct nl_80211 *nl,
                                     struct nl_msg *msg,
                                     uint32_t ifindex,
                                     uint32_t vendor_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, */
                                     uint32_t generic_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS, */
                                     uint32_t flags,
                                     const void *data,
                                     size_t len)
{
    /* FIXME: check nla_put() results */
    nl_80211_put_cmd(nl, msg, 0, NL80211_CMD_VENDOR);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, QCA_VENDOR_OUI);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, vendor_cmd);
    struct nlattr *vdata = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_LENGTH, len);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, generic_cmd);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_FLAGS, flags);
    //nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_PARAM, );
    nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA, len, data);
    nla_nest_end(msg, vdata);
}

static void
osw_plat_qsdk11_4_put_qca_vendor_setparam(struct nl_80211 *nl,
                                          struct nl_msg *msg,
                                          uint32_t ifindex,
                                          uint32_t vendor_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, */
                                          uint32_t cmd_id, /* eg. QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, */
                                          uint32_t param_id,
                                          const void *data,
                                          size_t len)
{
    /* FIXME: check nla_put() results */
    nl_80211_put_cmd(nl, msg, 0, NL80211_CMD_VENDOR);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, QCA_VENDOR_OUI);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, vendor_cmd);
    struct nlattr *vdata = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_LENGTH, len);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, cmd_id);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, param_id);
    nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA, len, data);
    nla_nest_end(msg, vdata);
}

static void
osw_plat_qsdk11_4_put_qca_vendor_getparam(struct nl_80211 *nl,
                                          struct nl_msg *msg,
                                          uint32_t ifindex,
                                          uint32_t vendor_cmd, /* eg. QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, */
                                          uint32_t cmd_id, /* eg. QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, */
                                          uint32_t param_id,
                                          const void *data,
                                          size_t len)
{
    /* FIXME: check nla_put() results */
    nl_80211_put_cmd(nl, msg, 0, NL80211_CMD_VENDOR);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, QCA_VENDOR_OUI);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, vendor_cmd);
    struct nlattr *vdata = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, cmd_id);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, param_id);
    nla_nest_end(msg, vdata);
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

    if (WARN_ON(data == NULL)) return;

    const void *buf = nla_data(data);
    uint32_t len = nla_len(data);

    WARN_ON(length != NULL && nla_get_u32(length) != len);

    if (len > arg->out_size) {
        len = arg->out_size;
        arg->not_enough_space = true;
    }

    arg->done = true;
    if (arg->out == NULL) return;

    memcpy(arg->out, buf, len);
}

static bool
osw_plat_qsdk11_4_get_param(struct nl_80211 *nl,
                            uint32_t ifindex,
                            uint32_t cmd_id,
                            uint32_t param_id,
                            void *out,
                            size_t out_size)
{
    struct osw_plat_qsdk11_4_get_param_arg arg = {
        .out = out,
        .out_size = out_size,
        .not_enough_space = false,
        .done = false,
    };
    struct nl_conn *conn = nl_80211_get_conn(nl);
    struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
    struct nl_msg *msg = nlmsg_alloc();
    const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
    osw_plat_qsdk11_4_put_qca_vendor_getparam(nl, msg, ifindex, vcmd, cmd_id, param_id, out, out_size);
    nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_param_resp_cb, &arg);
    nl_cmd_set_msg(cmd, msg);
    nl_cmd_wait(cmd, NULL);
    nl_cmd_free(cmd);
    return arg.done;
}

static bool
osw_plat_qsdk11_4_get_param_u32(struct nl_80211 *nl,
                                uint32_t ifindex,
                                uint32_t cmd_id,
                                uint32_t param_id,
                                uint32_t *value)
{
    const bool ok = osw_plat_qsdk11_4_get_param(nl, ifindex, cmd_id, param_id, value, sizeof(*value));
    LOGT(LOG_PREFIX("ifindex: %u: param: %d/%d = %d (%s)",
                    ifindex, cmd_id, param_id, *value, ok ? "good" : "bad"));
    return ok;
}

static void
osw_plat_qsdk11_4_set_param(struct nl_80211 *nl,
                            uint32_t ifindex,
                            uint32_t cmd_id,
                            uint32_t param_id,
                            const void *in,
                            size_t in_size)
{
    struct nl_conn *conn = nl_80211_get_conn(nl);
    struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
    struct nl_msg *msg = nlmsg_alloc();
    const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
    osw_plat_qsdk11_4_put_qca_vendor_setparam(nl, msg, ifindex, vcmd, cmd_id, param_id, in, in_size);
    nl_cmd_set_msg(cmd, msg);
    nl_cmd_wait(cmd, NULL);
    nl_cmd_free(cmd);
}

static void
osw_plat_qsdk11_4_set_param_u32(struct nl_80211 *nl,
                                uint32_t ifindex,
                                uint32_t cmd_id,
                                uint32_t param_id,
                                uint32_t value)
{
    LOGT(LOG_PREFIX("ifindex: %u: param: %d/%d = %d",
                    ifindex, cmd_id, param_id, value));
    osw_plat_qsdk11_4_set_param(nl, ifindex, cmd_id, param_id, &value, sizeof(value));
}

static void
osw_plat_qsdk11_4_get_chan_info_resp_cb(struct nl_cmd *cmd,
                                        struct nl_msg *msg,
                                        void *priv)
{
    bool *ok = priv;
    *ok = true;
    /* Actual data comes back through copy_to_user().. */
}

static bool
osw_plat_qsdk11_4_get_chan_info(struct nl_80211 *nl,
                                uint32_t ifindex,
                                struct ieee80211req_chaninfo_full *chans)
{
    if (WARN_ON(ifindex == 0)) return false;
    struct extended_ioctl_wrapper data = {
        .cmd = EXTENDED_SUBIOCTL_GET_CHANINFO,
        .data = chans,
        .data_len = sizeof(*chans),
    };
    struct nl_conn *conn = nl_80211_get_conn(nl);
    struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
    struct nl_msg *msg = nlmsg_alloc();
    const uint32_t vcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
    const uint32_t gcmd = QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS;
    const uint32_t flags = 0;
    const size_t len = sizeof(data);
    bool ok = false;
    osw_plat_qsdk11_4_put_qca_vendor_cmd(nl, msg, ifindex, vcmd, gcmd, flags, &data, len);
    nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_chan_info_resp_cb, &ok);
    nl_cmd_set_msg(cmd, msg);
    nl_cmd_wait(cmd, NULL);
    nl_cmd_free(cmd);
    return ok;
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

static enum osw_channel_state_dfs
qca_to_dfs_state(enum wlan_channel_dfs_state state)
{
    switch (state) {
        case WLAN_CH_DFS_S_INVALID:
            /* Not sure if this is correct, but.. */
            return OSW_CHANNEL_DFS_CAC_POSSIBLE;
        case WLAN_CH_DFS_S_CAC_REQ:
            return OSW_CHANNEL_DFS_CAC_POSSIBLE;
        case WLAN_CH_DFS_S_CAC_STARTED:
            return OSW_CHANNEL_DFS_CAC_IN_PROGRESS;
        case WLAN_CH_DFS_S_CAC_COMPLETED:
            return OSW_CHANNEL_DFS_CAC_COMPLETED;
        case WLAN_CH_DFS_S_NOL:
            return OSW_CHANNEL_DFS_NOL;
        case WLAN_CH_DFS_S_PRECAC_STARTED:
            return OSW_CHANNEL_DFS_CAC_IN_PROGRESS;
        case WLAN_CH_DFS_S_PRECAC_COMPLETED:
            return OSW_CHANNEL_DFS_CAC_COMPLETED;
    }
    WARN_ON(1);
    return OSW_CHANNEL_NON_DFS;
}

/* FIXME: cannot rely on net/if.h because QCA header files are conflicting with some bits in it */
unsigned int if_nametoindex(const char *ifname);

static void
osw_plat_qsdk11_4_fill_chan_states(struct nl_80211 *nl,
                                   const char *phy_name,
                                   struct osw_drv_phy_state *state)
{
    struct ieee80211req_chaninfo_full chans = {0};
    const struct ieee80211_ath_channel *arr = chans.req_chan_info.ic_chans;
    const bool ok = osw_plat_qsdk11_4_get_chan_info(nl, if_nametoindex(phy_name), &chans);
    const bool failed = !ok;
    if (WARN_ON(failed)) return;
    size_t i;
    for (i = 0; i < state->n_channel_states; i++) {
        struct osw_channel_state *cs = &state->channel_states[i];
        const struct osw_channel *c = &cs->channel;
        const uint32_t freq = c->control_freq_mhz;
        const int chan = osw_freq_to_chan(freq);
        bool is_dfs = false;
        size_t j;
        for (j = 0; j < chans.req_chan_info.ic_nchans; j++) {
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
        const enum wlan_channel_dfs_state dfs_state = chans.dfs_chan_state_arr[dfs_idx];
        enum osw_channel_state_dfs new_state = qca_to_dfs_state(dfs_state);
        LOGD(LOG_PREFIX_PHY(phy_name, "fix: chan: %d: dfs %d -> %d",
                            chan, cs->dfs_state,
                            new_state));
        cs->dfs_state = new_state;
    }
}

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

    /* FIXME: This assumes a single 2GHz band PHY, which
     * isn't necessarily true, but in practice it is. But
     * keep it sanitized with phy_2g.
     */
    int max_2g_chan;
    char phy_2g[32];

    /* FIXME: This should open up its own personal
     * netlink socket to handle vendor specific
     * commands and events.
     */
};

struct osw_plat_qsdk11_4_phy {
    struct osw_plat_qsdk11_4 *m;
    const struct nl_80211_phy *info;
};

struct osw_plat_qsdk11_4_vif {
    struct osw_plat_qsdk11_4 *m;
    const struct nl_80211_vif *info;
    struct rq q_stats;
    struct nl_cmd_task task_survey;

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
    if (getenv("OSW_PLAT_QSDK11_4_DISABLED")) return false;

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
osw_plat_qsdk11_4_fix_phy_chan_states(const char *phy_name,
                                      struct osw_drv_phy_state *state,
                                      struct osw_drv_nl80211_ops *nl_ops)
{
    if (nl_ops == NULL) return;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    osw_plat_qsdk11_4_fill_chan_states(nl, phy_name, state);
}

static void
osw_plat_qsdk11_4_update_max_2g_chan(struct osw_plat_qsdk11_4 *m,
                                     const char *phy_name,
                                     struct osw_drv_phy_state *state)
{
    size_t i;
    int max = 0;

    for (i = 0; i < state->n_channel_states; i++) {
        const struct osw_channel_state *cs = &state->channel_states[i];
        const struct osw_channel *c = &cs->channel;
        const int freq = c->control_freq_mhz;
        const enum osw_band band = osw_freq_to_band(freq);
        if (band != OSW_BAND_2GHZ) continue;
        const int chan = osw_freq_to_chan(freq);
        if (chan > max) max = chan;
    }

    if (max == 0) return;

    WARN_ON(strlen(m->phy_2g) > 0 &&
            strcmp(m->phy_2g, phy_name) != 0);

    if (m->max_2g_chan == max) return;

    STRSCPY_WARN(m->phy_2g, phy_name);
    LOGI(LOG_PREFIX_PHY(phy_name, "max 2g chan: %d -> %d",
                        m->max_2g_chan,
                        max));
    m->max_2g_chan = max;
}

static void
osw_plat_qsdk11_4_fix_phy_state_cb(struct osw_drv_nl80211_hook *hook,
                                   const char *phy_name,
                                   struct osw_drv_phy_state *state,
                                   void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;

    /* FIXME: This should be async */
    osw_plat_qsdk11_4_fix_phy_mac_addr(phy_name, state);
    osw_plat_qsdk11_4_fix_phy_chan_states(phy_name, state, m->nl_ops);
    osw_plat_qsdk11_4_update_max_2g_chan(m, phy_name, state);
}

static enum osw_acl_policy
osw_plat_qsdk11_4_maccmd_to_policy(int num)
{
    if (num == 0) return OSW_ACL_NONE;
    if (num == 1) return OSW_ACL_ALLOW_LIST;
    if (num == 2) return OSW_ACL_DENY_LIST;
    return OSW_ACL_NONE;
}

static void
osw_plat_qsdk11_4_fix_acl(const char *phy_name,
                          const char *vif_name,
                          struct osw_drv_vif_state *state)
{
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;

/*

root@host:~# iwpriv b-ap-24 getmac
b-ap-24   getmac:00:11:22:33:44:55
                 00:11:22:33:44:66
root@host:~# iwpriv b-ap-24 get_maccmd
b-ap-24   get_maccmd:0

*/

    /* FIXME: This should use vendor subcommands */

    char *maccmd = strexa(
        "iwpriv",
        vif_name,
        "get_maccmd"
    ) ?: "";

    char *acl = strexa(
        "iwpriv",
        vif_name,
        "getmac"
    ) ?: "";

    maccmd = (strstr(maccmd, ":") ?: ":") + 1;
    acl = (strstr(acl, ":") ?: ":") + 1;

    ap->acl_policy = osw_plat_qsdk11_4_maccmd_to_policy(atoi(maccmd));
    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "acl: policy: %s",
                        osw_acl_policy_to_str(ap->acl_policy)));

    const char *word;
    while ((word = strsep(&acl, " \r\n")) != NULL) {
        struct osw_hwaddr addr;
        const bool ok = osw_hwaddr_from_cstr(word, &addr);
        if (ok == false) continue;

        const size_t i = ap->acl.count;
        const size_t n = i + 1;
        const size_t size = n * sizeof(*ap->acl.list);

        ap->acl.list = REALLOC(ap->acl.list, size);
        ap->acl.list[i] = addr;
        ap->acl.count = n;
        LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "acl: addr: " OSW_HWADDR_FMT,
                            OSW_HWADDR_ARG(&addr)));
    }
}

static void
osw_plat_qsdk11_4_fix_mcast2ucast(struct osw_plat_qsdk11_4 *m,
                                  const char *phy_name,
                                  const char *vif_name,
                                  struct osw_drv_vif_state *state)
{
    if (state->vif_type != OSW_VIF_AP) return;

    struct osw_drv_vif_state_ap *ap = &state->u.ap;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const struct nl_80211_vif *vif_info = nl_80211_vif_by_name(nl, vif_name);
    if (vif_info == NULL) return;

    const uint32_t ifindex = vif_info->ifindex;
    uint32_t me = 0;
    const bool ok = osw_plat_qsdk11_4_get_param_u32(nl,
                                                    ifindex,
                                                    QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
                                                    IEEE80211_PARAM_ME,
                                                    &me);
    const bool bad = !ok;
    if (bad) return;

    ap->mcast2ucast = (me != QCA_WIFI_MC_ME_DISABLE);
}

static void
osw_plat_qsdk11_4_fix_vif_state_cb(struct osw_drv_nl80211_hook *hook,
                                   const char *phy_name,
                                   const char *vif_name,
                                   struct osw_drv_vif_state *state,
                                   void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;

    osw_plat_qsdk11_4_fix_acl(phy_name, vif_name, state);
    osw_plat_qsdk11_4_fix_mcast2ucast(m, phy_name, vif_name, state);
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
osw_plat_qsdk11_4_conf_to_mode(const struct osw_drv_vif_config *vif,
                               int max_2g_chan)
{
    /* FIXME: This should also set something explicit STA? */
    if (vif->vif_type != OSW_VIF_AP) return "AUTO";

    const struct osw_channel *c = &vif->u.ap.channel;
    const enum osw_channel_width width = c->width;
    const int freq = c->control_freq_mhz;
    const int sec_offset = osw_channel_ht40_offset(c, max_2g_chan);
    const enum osw_band band = osw_freq_to_band(freq);

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

    if (vif->u.ap.mode.he_enabled) mode = modes_he;
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

static void
osw_plat_qsdk11_4_fix_mode(struct osw_plat_qsdk11_4 *m,
                           struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;
        size_t j;
        for (j = 0; j < phy->vif_list.count; j++) {
            struct osw_drv_vif_config *vif = &phy->vif_list.list[j];
            const int max_2g_chan = (strcmp(phy_name, m->phy_2g) == 0)
                                  ? m->max_2g_chan
                                  : 0;
            const char *vif_name = vif->vif_name;

            if (vif->enabled == false) continue;
            if (vif->vif_type != OSW_VIF_AP) continue;
            if (vif->u.ap.csa_required == true) continue;
            if (vif->u.ap.channel_changed == false) continue;

            const char *new_mode = osw_plat_qsdk11_4_conf_to_mode(vif, max_2g_chan);
            if (WARN_ON(new_mode == NULL)) continue;

            LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "iwpriv mode = %s", new_mode));
            const char *result = strexa("iwpriv", vif_name, "mode", new_mode);
            WARN_ON(result == NULL);
        }
    }
}

static const char *
osw_plat_qsdk11_4_exttool_get_secoffset(const struct osw_channel *c,
                                        int max_2g_chan)
{
    const int offset = osw_channel_ht40_offset(c, max_2g_chan);
    if (offset < 0) return "3";
    if (offset > 0) return "1";
    return "1";
}

static const char *
osw_plat_qsdk11_4_exttool_get_chwidth(const struct osw_channel *c)
{
    switch (c->width) {
        case OSW_CHANNEL_20MHZ: return "0";
        case OSW_CHANNEL_40MHZ: return "1";
        case OSW_CHANNEL_80MHZ: return "2";
        case OSW_CHANNEL_160MHZ: return "3";
        case OSW_CHANNEL_80P80MHZ: return "3"; /* FIXME */
    }
    return "";
}

static const char *
osw_plat_qsdk11_4_exttool_get_band(const struct osw_channel *c)
{
    const int freq = c->control_freq_mhz;
    const enum osw_band band = osw_freq_to_band(freq);
    switch (band) {
        case OSW_BAND_UNDEFINED: return "0";
        case OSW_BAND_2GHZ: return "1";
        case OSW_BAND_5GHZ: return "2";
        case OSW_BAND_6GHZ: return "3";
    }
    return "0";
}

static void
osw_plat_qsdk11_4_exttool_csa(const char *phy_name,
                              const struct osw_channel *c,
                              int max_2g_chan)
{
    const int freq = c->control_freq_mhz;
    const int chan = osw_freq_to_chan(freq);
    const char *intf_arg = phy_name;
    char chan_arg[32];
    const char *band_arg = osw_plat_qsdk11_4_exttool_get_band(c);
    const char *numcsa_arg = "15";
    const char *chwidth_arg = osw_plat_qsdk11_4_exttool_get_chwidth(c);
    const char *secoffset_arg = osw_plat_qsdk11_4_exttool_get_secoffset(c, max_2g_chan);

    snprintf(chan_arg, sizeof(chan_arg), "%d", chan);

    LOGI(LOG_PREFIX_PHY(phy_name, "exttool: chanswitch(chan=%s band=%s width=%s offset=%s)",
                        chan_arg,
                        band_arg,
                        chwidth_arg,
                        secoffset_arg));

    const char *result = strexa(
            "exttool",
            "--interface", intf_arg,
            "--chanswitch",
            "--chan", chan_arg,
            "--band", band_arg,
            "--numcsa", numcsa_arg,
            "--chwidth", chwidth_arg,
            "--secoffset", secoffset_arg
    );
    WARN_ON(result == NULL);
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
            const int max_2g_chan = (strcmp(phy_name, m->phy_2g) == 0)
                                  ? m->max_2g_chan
                                  : 0;
            const char *vif_name = vif->vif_name;

            if (vif->vif_type != OSW_VIF_AP) continue;
            if (vif->u.ap.csa_required == false) continue;

            LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "needs csa"));
            osw_plat_qsdk11_4_exttool_csa(phy_name, c, max_2g_chan);

            /* This is per PHY actually, so bail out, and go
             * to the next PHY. */
            break;
        }
    }
}

static const char *
osw_plat_qsdk11_4_policy_to_maccmd(enum osw_acl_policy policy)
{
    switch (policy) {
        case OSW_ACL_NONE: return "0";
        case OSW_ACL_ALLOW_LIST: return "1";
        case OSW_ACL_DENY_LIST: return "2";
    }
    /* unreachable */
    return "0";
}

static void
osw_plat_qsdk11_4_apply_acl_policy(const char *phy_name,
                                   const char *vif_name,
                                   struct osw_drv_vif_config_ap *ap)
{
    if (ap->acl_policy_changed == false) return;

    const char *maccmd = osw_plat_qsdk11_4_policy_to_maccmd(ap->acl_policy);
    LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "acl: maccmd: %s", maccmd));
    const char *result = strexa(
        "iwpriv",
        vif_name,
        "maccmd",
        maccmd
    );
    WARN_ON(result == NULL);
}

static void
osw_plat_qsdk11_4_apply_acl_list(const char *phy_name,
                                 const char *vif_name,
                                 struct osw_drv_vif_config_ap *ap)
{
    if (ap->acl_changed == false) return;

    const char *result = strexa(
        "iwpriv",
        vif_name,
        "maccmd",
        "3" /* flush */
    );
    WARN_ON(result == NULL);

    size_t i;
    for (i = 0; i < ap->acl.count; i++) {
        const struct osw_hwaddr *addr = &ap->acl.list[i];
        struct osw_hwaddr_str buf;
        const char *str = osw_hwaddr2str(addr, &buf);
        if (WARN_ON(str == NULL)) continue;
        LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "acl: addmac: %s", str));
        const char *result = strexa(
            "iwpriv",
            vif_name,
            "addmac",
            str
        );
        WARN_ON(result == NULL);
    }
}

static void
osw_plat_qsdk11_4_apply_acl(struct osw_plat_qsdk11_4 *m,
                            struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;
        size_t j;
        for (j = 0; j < phy->vif_list.count; j++) {
            struct osw_drv_vif_config *vif = &phy->vif_list.list[j];
            struct osw_drv_vif_config_ap *ap = &vif->u.ap;
            const char *vif_name = vif->vif_name;

            if (vif->vif_type != OSW_VIF_AP) continue;

            osw_plat_qsdk11_4_apply_acl_policy(phy_name, vif_name, ap);
            osw_plat_qsdk11_4_apply_acl_list(phy_name, vif_name, ap);
        }
    }
}

static void
osw_plat_qsdk11_4_apply_mcast2ucast(struct osw_plat_qsdk11_4 *m,
                                    struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;
        size_t j;
        for (j = 0; j < phy->vif_list.count; j++) {
            struct osw_drv_vif_config *vif = &phy->vif_list.list[j];
            struct osw_drv_vif_config_ap *ap = &vif->u.ap;
            const char *vif_name = vif->vif_name;

            if (vif->vif_type != OSW_VIF_AP) continue;
            if (ap->mcast2ucast_changed == false) continue;

            struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
            struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
            const struct nl_80211_vif *vif_info = nl_80211_vif_by_name(nl, vif_name);
            if (vif_info == NULL) continue;
            const uint32_t ifindex = vif_info->ifindex;
            const uint32_t cmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
            const uint32_t param = IEEE80211_PARAM_ME;
            const uint32_t value = ap->mcast2ucast
                                 ? QCA_WIFI_MC_ME_HYFI
                                 : QCA_WIFI_MC_ME_DISABLE;
            LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "mcast2ucast: set: %d", value));
            osw_plat_qsdk11_4_set_param_u32(nl, ifindex, cmd, param, value);
        }
    }
}

static void
osw_plat_qsdk11_4_pre_request_config_cb(struct osw_drv_nl80211_hook *hook,
                                        struct osw_drv_conf *drv_conf,
                                        void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;

    osw_plat_qsdk11_4_create_intf(m, drv_conf);
    osw_plat_qsdk11_4_fix_mode(m, drv_conf);
    osw_plat_qsdk11_4_apply_csa(m, drv_conf);
    osw_plat_qsdk11_4_apply_acl(m, drv_conf);
    osw_plat_qsdk11_4_apply_mcast2ucast(m, drv_conf);
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

static void
osw_plat_qsdk11_4_ap_conf_mutate_cb(struct osw_hostap_hook *hook,
                                    const char *phy_name,
                                    const char *vif_name,
                                    struct osw_drv_conf *drv_conf,
                                    struct osw_hostap_conf_ap_config *hapd_conf,
                                    void *priv)
{
    /* The driver is generating Probe Responses internally */
    OSW_HOSTAP_CONF_SET_VAL(hapd_conf->send_probe_response, 0);
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
    const float noise = cs->noise_floor;

    LOGT(LOG_PREFIX_PHY(phy_name, "stats: survey:"
                        " freq=%"PRIu32" MHz"
                        " nf=%"PRId16" dB"
                        " total=%"PRIu32
                        " tx=%"PRIu32
                        " rx=%"PRIu32
                        " rx_bss=%"PRIu32
                        " clear=%"PRIu32,
                        cs->freq,
                        cs->noise_floor,
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
    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_cmd(nl, msg, ifindex, vcmd, gcmd, flags, &data, len);
    return msg;
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

static void
osw_plat_qsdk11_4_get_survey_phy(const struct nl_80211_phy *phy,
                                 void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    const char *phy_name = phy->name;
    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, false);
    if (WARN_ON(vif_info == NULL)) return;

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
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);

    const char *phy_name = phy->name;
    const struct nl_80211_vif *vif_info = osw_plat_qsdk11_4_get_vif(m, phy_name, true);
    if (WARN_ON(vif_info == NULL)) return;

    const uint32_t ifindex = vif_info->ifindex;
    const uint32_t cmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
    const uint32_t param = OL_ATH_PARAM_SHIFT
                         | OL_ATH_PARAM_FLUSH_PEER_RATE_STATS;
    osw_plat_qsdk11_4_set_param_u32(nl, ifindex, cmd, param, 1);

    const uint32_t param2 = OL_SPECIAL_PARAM_SHIFT
                          | OL_SPECIAL_PARAM_ENABLE_OL_STATS;
    uint32_t ol_stats_enabled = 0;
    const bool ok = osw_plat_qsdk11_4_get_param_u32(nl, ifindex, cmd, param2, &ol_stats_enabled);
    WARN_ON(!ok);
    if (!ol_stats_enabled) {
        LOGI(LOG_PREFIX_PHY(phy_name, "enabling ol stats"));
        osw_plat_qsdk11_4_set_param_u32(nl, ifindex, cmd, param2, 1);
    }
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
osw_plat_qsdk11_4_phy_added_cb(const struct nl_80211_phy *info,
                               void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_phy *phy = nl_80211_sub_phy_get_priv(sub, info);
    if (phy == NULL) return;

    phy->info = info;
    phy->m = m;
}

static void
osw_plat_qsdk11_4_phy_removed_cb(const struct nl_80211_phy *info,
                                 void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_phy *phy = nl_80211_sub_phy_get_priv(sub, info);
    if (phy == NULL) return;

    phy->info = NULL;
    phy->m = NULL;
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

    rq_init(&vif->q_stats, EV_DEFAULT);
    vif->q_stats.max_running = 1;

    const uint32_t ifindex = info->ifindex;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    struct nl_conn *conn = nl_80211_get_conn(nl);
    struct nl_cmd *cmd = nl_conn_alloc_cmd(conn);
    struct nl_msg *msg = osw_plat_qsdk11_4_vif_cmd_survey_stats(nl, ifindex);
    nl_cmd_set_response_fn(cmd, osw_plat_qsdk11_4_get_survey_stats_resp_cb, vif);
    nl_cmd_task_init(&vif->task_survey, cmd, msg);
}

static void
osw_plat_qsdk11_4_vif_removed_cb(const struct nl_80211_vif *info,
                                 void *priv)
{
    struct osw_plat_qsdk11_4 *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_qsdk11_4_vif *vif = nl_80211_sub_vif_get_priv(sub, info);
    if (vif == NULL) return;

    rq_stop(&vif->q_stats);
    rq_kill(&vif->q_stats);
    nl_cmd_task_fini(&vif->task_survey);

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

    WARN_ON(bytes >= UINT32_MAX);
    WARN_ON(mpdu >= UINT32_MAX);
    WARN_ON(retry >= UINT32_MAX);

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

    WARN_ON(bytes >= UINT32_MAX);
    WARN_ON(mpdu >= UINT32_MAX);
    WARN_ON(retry >= UINT32_MAX);

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
        snr += tx->sum_snr;
        snr_cnt += tx->num_snr;

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

    WARN_ON(tx_ppdu == 0 && tx_mbps > 0);
    WARN_ON(rx_ppdu == 0 && rx_mbps > 0);
    WARN_ON(snr_cnt == 0 && snr > 0);

    WARN_ON(tx_mbps >= UINT32_MAX);
    WARN_ON(rx_mbps >= UINT32_MAX);
    WARN_ON(snr >= UINT32_MAX);

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

    struct osw_drv *drv = m->drv_nl80211;
    osw_drv_report_stats(drv, &t);
    osw_tlv_fini(&t);
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

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "event: vendor: cmd=%u data_len=%zu",
                        subcmd,
                        nla_vendor_data ? nla_len(nla_vendor_data) : 0));

    switch (subcmd) {
        case QCA_NL80211_VENDOR_SUBCMD_PEER_STATS_CACHE_FLUSH:
            /* Can't pass vif_name. It's always the special
             * wifiX netdev, not the actual STA link netdev.
             */
            osw_plat_qsdk11_4_event_stats(m, phy_name, nla_vendor_data);
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
osw_plat_qsdk11_4_start(struct osw_plat_qsdk11_4 *m)
{
    if (osw_plat_qsdk11_4_is_disabled()) return;

    /* FIXME: This probably should look at
     * osw_plat_qsdk11_4_is_enabled() at some point.
     */

    /* Hardcoded. Ugly, but should work out for a while.. */
    setenv("OSW_DRV_NL80211_IGNORE_VIF_wifi0", "1", 1);
    setenv("OSW_DRV_NL80211_IGNORE_VIF_wifi1", "1", 1);
    setenv("OSW_DRV_NL80211_IGNORE_VIF_wifi2", "1", 1);
    setenv("OSW_DRV_NL80211_IGNORE_VIF_wifi3", "1", 1);
    setenv("OSW_DRV_NL80211_IGNORE_VIF_wifi4", "1", 1);
    setenv("OSW_DRV_NL80211_IGNORE_VIF_wifi5", "1", 1);

    static const struct osw_drv_nl80211_hook_ops nl_hook_ops = {
        .fix_phy_state_fn = osw_plat_qsdk11_4_fix_phy_state_cb,
        .fix_vif_state_fn = osw_plat_qsdk11_4_fix_vif_state_cb,
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
    };

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
