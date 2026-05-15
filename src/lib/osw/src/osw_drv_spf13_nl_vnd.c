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
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <nl80211_copy.h>

/* 3rd party */
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>

/* opensync */
#include <log.h>
#include <const.h>
#include <memutil.h>

/* osw */
#include <osw_types.h>
#include <osw_tlv.h>
#include <osw_stats_enum.h>
#include <osw_etc.h>

/* qca */
#define EXTERNAL_USE_ONLY
#define __bool_already_defined__
#ifndef __packed
#define __packed __attribute__((packed))
#endif

#if 0
#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN 1234
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
#include <cfg80211_ven_cmd.h>
#include <qcatools_lib.h>
#include <ieee80211_defines.h>
// #include <ol_if_thermal.h>
// #include <qca-vendor.h>
#include <ext_ioctl_drv_if.h>
#include <cfg80211_external.h>
#include <if_athioctl.h>
#include <ieee80211_ioctl.h>
#include <dp_rate_stats_pub.h>
#include <ieee80211_ev.h>

/* Headers containing this definition is actually not reachable through
 * staging/sysroot. huh. */
#define QCA_VENDOR_OUI 0x001374

enum qca_wlan_genric_data
{
    QCA_WLAN_VENDOR_ATTR_PARAM_INVALID = 0,
    QCA_WLAN_VENDOR_ATTR_PARAM_DATA,
    QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH,
    QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS,

    /* keep last */
    QCA_WLAN_VENDOR_ATTR_PARAM_LAST,
    QCA_WLAN_VENDOR_ATTR_PARAM_MAX = QCA_WLAN_VENDOR_ATTR_PARAM_LAST - 1
};

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_nl_vnd.h"
#include "osw_drv_spf13_netdev.h"

#define DEFINE_VAP_PARAM_U32(GET, SET, PARAM_ID)                                                         \
    struct nl_msg *GET(uint32_t nl80211_family_id, uint32_t ifindex, int8_t mlo_link_id)                 \
    {                                                                                                    \
        const osw_drv_spf13_nl_vnd_wifi_param_get_t param = {                                            \
            .nl80211_family_id = nl80211_family_id,                                                      \
            .ifindex = ifindex,                                                                          \
            .mlo_link_id = mlo_link_id,                                                                  \
            .param_id = (PARAM_ID),                                                                      \
        };                                                                                               \
        return osw_drv_spf13_nl_vnd_wifi_param_get(&param);                                              \
    }                                                                                                    \
                                                                                                         \
    struct nl_msg *SET(uint32_t nl80211_family_id, uint32_t ifindex, int8_t mlo_link_id, uint32_t value) \
    {                                                                                                    \
        const osw_drv_spf13_nl_vnd_wifi_param_set_u32_t param = {                                        \
            .nl80211_family_id = nl80211_family_id,                                                      \
            .ifindex = ifindex,                                                                          \
            .mlo_link_id = mlo_link_id,                                                                  \
            .param_id = (PARAM_ID),                                                                      \
            .value = value,                                                                              \
        };                                                                                               \
        return osw_drv_spf13_nl_vnd_wifi_param_set_u32(&param);                                          \
    }

#define DEFINE_RADIO_PARAM_U32(GET, SET, PARAM_ID)                                   \
    struct nl_msg *GET(uint32_t nl80211_family_id, uint32_t ifindex)                 \
    {                                                                                \
        const osw_drv_spf13_nl_vnd_wifi_param_get_t param = {                        \
            .nl80211_family_id = nl80211_family_id,                                  \
            .ifindex = ifindex,                                                      \
            .mlo_link_id = -1,                                                       \
            .param_id = (PARAM_ID),                                                  \
        };                                                                           \
        return osw_drv_spf13_nl_vnd_wifi_param_get(&param);                          \
    }                                                                                \
                                                                                     \
    struct nl_msg *SET(uint32_t nl80211_family_id, uint32_t ifindex, uint32_t value) \
    {                                                                                \
        const osw_drv_spf13_nl_vnd_wifi_param_set_u32_t param = {                    \
            .nl80211_family_id = nl80211_family_id,                                  \
            .ifindex = ifindex,                                                      \
            .mlo_link_id = -1,                                                       \
            .param_id = (PARAM_ID),                                                  \
            .value = value,                                                          \
        };                                                                           \
        return osw_drv_spf13_nl_vnd_wifi_param_set_u32(&param);                      \
    }

struct nl_msg *osw_drv_spf13_nl_vnd_generic_to_msg(const struct osw_drv_spf13_nl_vnd_generic *generic)
{
    struct nl_msg *msg = nlmsg_alloc_size(4096 + generic->data_len);
    const int genl_flags = 0;
    const int genl_cmd = NL80211_CMD_VENDOR;
    const int hdrlen = 0;
    const int version = 0;
    const uint32_t family_id = generic->nl80211_family_id;
    WARN_ON(genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, hdrlen, genl_flags, genl_cmd, version) == NULL);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, generic->ifindex);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, QCA_VENDOR_OUI);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, generic->vendor_cmd);
    struct nlattr *vdata = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, generic->generic_cmd);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_FLAGS, generic->flags);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, generic->value);
    if (generic->mlo_link_id >= 0)
    {
        nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_MLO_LINK_ID, generic->mlo_link_id);
    }
    if (generic->data_ptr != NULL)
    {
        nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_LENGTH, generic->data_len);
        nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA, generic->data_len, generic->data_ptr);
    }
    nla_nest_end(msg, vdata);
    return msg;
}

struct nl_msg *osw_drv_spf13_nl_vnd_wifi_param_set(const struct osw_drv_spf13_nl_vnd_wifi_param_set *param)
{
    const osw_drv_spf13_nl_vnd_generic_t generic = {
        .nl80211_family_id = param->nl80211_family_id,
        .ifindex = param->ifindex,
        .mlo_link_id = param->mlo_link_id,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
        .value = param->param_id,
        .data_ptr = param->data_ptr,
        .data_len = param->data_len,
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&generic);
}

struct nl_msg *osw_drv_spf13_nl_vnd_wifi_param_get(const struct osw_drv_spf13_nl_vnd_wifi_param_get *param)
{
    const osw_drv_spf13_nl_vnd_generic_t generic = {
        .nl80211_family_id = param->nl80211_family_id,
        .ifindex = param->ifindex,
        .mlo_link_id = param->mlo_link_id,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
        .value = param->param_id,
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&generic);
}

struct nl_msg *osw_drv_spf13_nl_vnd_wifi_param_set_u32(const osw_drv_spf13_nl_vnd_wifi_param_set_u32_t *param)
{
    const osw_drv_spf13_nl_vnd_generic_t generic = {
        .nl80211_family_id = param->nl80211_family_id,
        .ifindex = param->ifindex,
        .mlo_link_id = param->mlo_link_id,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
        .value = param->param_id,
        .data_ptr = &param->value,
        .data_len = sizeof(param->value),
        .flags = 0,
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&generic);
}

const void *osw_drv_spf13_nl_vnd_generic_from_msg(struct nl_msg *msg, uint32_t *len, uint32_t *flags)
{
    if (msg == NULL) return NULL;

    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    const int err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, NL80211_ATTR_MAX, NULL);
    if (err < 0) return NULL;

    struct nlattr *attr_vendor_data = tb[NL80211_ATTR_VENDOR_DATA];
    if (attr_vendor_data == NULL) return NULL;

    struct nlattr *vendor_tb[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1];
    const int vendor_err = nla_parse_nested(vendor_tb, QCA_WLAN_VENDOR_ATTR_PARAM_MAX, attr_vendor_data, NULL);
    if (vendor_err < 0) return NULL;

    struct nlattr *attr_data = vendor_tb[QCA_WLAN_VENDOR_ATTR_PARAM_DATA];
    struct nlattr *attr_flags = vendor_tb[QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS];

    if (attr_flags != NULL)
    {
        if (flags != NULL)
        {
            *flags = nla_get_u32(attr_flags);
        }
    }

    if (attr_data != NULL)
    {
        if (len != NULL)
        {
            *len = nla_len(attr_data);
        }
        return nla_data(attr_data);
    }

    return NULL;
}

const uint32_t *osw_drv_spf13_nl_vnd_u32_from_msg(struct nl_msg *msg)
{
    uint32_t len = 0;
    const uint32_t *maybe_u32 = osw_drv_spf13_nl_vnd_generic_from_msg(msg, &len, NULL);
    if (maybe_u32 == NULL) return NULL;
    if (len != sizeof(uint32_t)) return NULL;
    return maybe_u32;
}

struct nl_msg *osw_drv_spf13_nl_vnd_acl_del(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_hwaddr *mac_addr)
{
    const osw_drv_spf13_nl_vnd_generic_t param = {
        .nl80211_family_id = family_id,
        .ifindex = ifindex,
        .mlo_link_id = mlo_link_id,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDORSUBCMD_DELMAC,
        .data_ptr = mac_addr->octet,
        .data_len = sizeof(mac_addr->octet),
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&param);
}

struct nl_msg *osw_drv_spf13_nl_vnd_acl_add(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_hwaddr *mac_addr)
{
    const osw_drv_spf13_nl_vnd_generic_t param = {
        .nl80211_family_id = family_id,
        .ifindex = ifindex,
        .mlo_link_id = mlo_link_id,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDORSUBCMD_ADDMAC,
        .data_ptr = mac_addr->octet,
        .data_len = sizeof(mac_addr->octet),
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&param);
}

struct nl_msg *osw_drv_spf13_nl_vnd_acl_get(uint32_t family_id, uint32_t ifindex, int8_t mlo_link_id)
{
    const osw_drv_spf13_nl_vnd_generic_t param = {
        .nl80211_family_id = family_id,
        .ifindex = ifindex,
        .mlo_link_id = mlo_link_id,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDOR_SUBCMD_GET_ACLMAC};
    return osw_drv_spf13_nl_vnd_generic_to_msg(&param);
}

enum osw_acl_policy osw_drv_spf13_nl_vnd_acl_policy_from_u32(uint32_t value)
{
    switch (value)
    {
        case IEEE80211_MACCMD_POLICY_OPEN:
            return OSW_ACL_NONE;
        case IEEE80211_MACCMD_POLICY_ALLOW:
            return OSW_ACL_ALLOW_LIST;
        case IEEE80211_MACCMD_POLICY_DENY:
            return OSW_ACL_DENY_LIST;
        default:
            break;
    }
    WARN_ON(1);
    return OSW_ACL_NONE;
}

uint32_t osw_drv_spf13_nl_vnd_acl_policy_to_u32(enum osw_acl_policy acl_policy)
{
    switch (acl_policy)
    {
        case OSW_ACL_NONE:
            return IEEE80211_MACCMD_POLICY_OPEN;
        case OSW_ACL_ALLOW_LIST:
            return IEEE80211_MACCMD_POLICY_ALLOW;
        case OSW_ACL_DENY_LIST:
            return IEEE80211_MACCMD_POLICY_DENY;
    }
    /* never reached */
    return 0;
}

struct nl_msg *osw_drv_spf13_nl_vnd_acl_policy_get(uint32_t family_id, uint32_t ifindex, int8_t mlo_link_id)
{
    const osw_drv_spf13_nl_vnd_wifi_param_get_t param = {
        .nl80211_family_id = family_id,
        .ifindex = ifindex,
        .mlo_link_id = mlo_link_id,
        .param_id = IEEE80211_PARAM_MACCMD};
    return osw_drv_spf13_nl_vnd_wifi_param_get(&param);
}

struct nl_msg *osw_drv_spf13_nl_vnd_acl_policy_set(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        enum osw_acl_policy acl_policy)
{
    const osw_drv_spf13_nl_vnd_wifi_param_set_u32_t param = {
        .nl80211_family_id = family_id,
        .ifindex = ifindex,
        .mlo_link_id = mlo_link_id,
        .param_id = IEEE80211_PARAM_MACCMD,
        .value = acl_policy,
    };
    return osw_drv_spf13_nl_vnd_wifi_param_set_u32(&param);
}

static enum osw_channel_state_dfs osw_drv_spf13_nl_vnd_dfs_state_from_qca(uint8_t dfs_state)
{
    switch (dfs_state)
    {
        case WLAN_CH_DFS_S_INVALID:
            return OSW_CHANNEL_NON_DFS;
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
        case WLAN_CH_DFS_S_NON_DFS:
            return OSW_CHANNEL_NON_DFS;
    }
    WARN_ON(1);
    return OSW_CHANNEL_NON_DFS;
}

static int osw_drv_spf13_nl_vnd_chaninfo_dfs_idx(int chan)
{
    const int first_dfs = 52;
    const int spacing = 4;
    const int last_idx = NUM_DFS_CHANS - 1;
    if (chan < first_dfs) return -1;
    const int idx = (chan - first_dfs) / spacing;
    if (idx > last_idx) return -1;
    return idx;
}

struct osw_channel_state *osw_drv_spf13_nl_vnd_chaninfo_parse(struct nl_msg *msg, size_t *count)
{
    uint32_t len = 0;
    const struct extended_ioctl_wrapper *data = osw_drv_spf13_nl_vnd_generic_from_msg(msg, &len, NULL);
    if (WARN_ON(data == NULL)) return NULL;
    if (WARN_ON(len < sizeof(*data))) return NULL;
    const struct ieee80211req_chaninfo_full *chans = data->data;
    struct osw_channel_state *list = NULL;
    size_t i;
    for (i = 0; i < chans->req_chan_info.ic_nchans; i++)
    {
        if (WARN_ON(i >= ARRAY_SIZE(chans->req_chan_info.ic_chans))) break;
        const struct ieee80211_ath_channel *ac = &chans->req_chan_info.ic_chans[i];
        if (ac->ic_freq == 0) continue;

        int dfs_i = osw_drv_spf13_nl_vnd_chaninfo_dfs_idx(ac->ic_ieee);
        const enum wlan_channel_dfs_state dfs_state =
                (dfs_i != -1) ? chans->dfs_chan_state_arr[dfs_i] : WLAN_CH_DFS_S_INVALID;

        const struct osw_channel c = {
            .control_freq_mhz = ac->ic_freq,
            .center_freq0_mhz = ac->ic_freq,
        };

        const struct osw_channel_state cs = {
            .channel = c,
            .dfs_state = ac->ic_flagext & IEEE80211_CHAN_DFS ? osw_drv_spf13_nl_vnd_dfs_state_from_qca(dfs_state)
                                                             : OSW_CHANNEL_NON_DFS,
        };

        list = REALLOC(list, ((*count) + 1) * sizeof(*list));
        list[*count] = cs;
        (*count)++;
    }

    return list;
}

struct ieee80211req_chaninfo_full *osw_drv_spf13_nl_vnd_chaninfo_alloc_buf(uint32_t ifindex)
{
    /* This static buffer is here for a reason. Unfortunately the QCA vendor
     * command operates over a shared memory buffer. The buffer is shared via a
     * pointer in the netlink command. The response doesn't really come as a
     * netlink message over a netlink socket, but instead the kernel (WLAN
     * driver) fills the shared memory buffer with the response data. The
     * netlink message is just a notification that the data is ready in the
     * shared memory buffer and is virtually an echo of the request.
     *
     * This means cancellation of commands is troublesome. The buffer must be
     * guranteed to be valid until the command is completed. The buffer must
     * not be freed.
     *
     * To satisfy this requirement, the buffer is static and is never freed and
     * is addressed by radio id (wifiX). This assumes there's only ever 1
     * in-flight request per radio for chaninfo -- which it is at the time of
     * writing this.
     */
    static struct ieee80211req_chaninfo_full g_osw_drv_spf13_nl_vnd_chans[4];

    char ifname_buf[IFNAMSIZ] = {0};
    const char *ifname = if_indextoname(ifindex, ifname_buf);
    if (ifname == NULL) return NULL;
    if (osw_drv_spf13_netdev_is_qca_radio(ifname) == false) return NULL;
    const char *first_num = strpbrk(ifname, "0123456789");
    if (first_num == NULL) return NULL;
    const int radio_id = atoi(first_num);
    if (WARN_ON((size_t)radio_id >= ARRAY_SIZE(g_osw_drv_spf13_nl_vnd_chans))) return NULL;
    if (WARN_ON(radio_id < 0)) return NULL;
    struct ieee80211req_chaninfo_full *chans = &g_osw_drv_spf13_nl_vnd_chans[radio_id];
    memset(chans, 0, sizeof(*chans));

    return chans;
}

struct nl_msg *osw_drv_spf13_nl_vnd_chaninfo_get(uint32_t nl80211_family_id, uint32_t ifindex)
{
    struct ieee80211req_chaninfo_full *chans = osw_drv_spf13_nl_vnd_chaninfo_alloc_buf(ifindex);
    if (chans == NULL)
    {
        LOGW(LOG_PREFIX("failed to allocate chaninfo buffer for ifindex %u", ifindex));
        return NULL;
    }

    const struct extended_ioctl_wrapper data = {
        .cmd = EXTENDED_SUBIOCTL_GET_CHANINFO,
        .data = chans,
        .data_len = sizeof(*chans),
    };
    const osw_drv_spf13_nl_vnd_generic_t generic = {
        .nl80211_family_id = nl80211_family_id,
        .ifindex = ifindex,
        .mlo_link_id = -1,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS,
        .data_ptr = &data,
        .data_len = sizeof(data),
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&generic);
}

struct nl_msg *osw_drv_spf13_nl_vnd_radio_country_get(uint32_t nl80211_family_id, uint32_t ifindex)
{
    const osw_drv_spf13_nl_vnd_generic_t param = {
        .nl80211_family_id = nl80211_family_id,
        .ifindex = ifindex,
        .mlo_link_id = -1,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDORSUBCMD_COUNTRY_CONFIG,
        .value = 0, /* unused */
        .data_ptr = NULL,
        .data_len = 0,

    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&param);
}

bool osw_drv_spf13_nl_vnd_radio_country_parse(struct nl_msg *msg, char *country_code, size_t country_code_len)
{
    if (msg == NULL || country_code == NULL || country_code_len < 3) return false;

    uint32_t len = 0;
    const void *data = osw_drv_spf13_nl_vnd_generic_from_msg(msg, &len, NULL);
    if (data == NULL || len < 2) return false;

    const char *country = data;
    country_code[0] = country[0];
    country_code[1] = country[1];
    country_code[2] = '\0'; /* null-terminate the string */
    return true;
}

DEFINE_RADIO_PARAM_U32(
        osw_drv_spf13_nl_vnd_radio_param_rx_chainmask_get,
        osw_drv_spf13_nl_vnd_radio_param_rx_chainmask_set,
        OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_RXCHAINMASK)

DEFINE_RADIO_PARAM_U32(
        osw_drv_spf13_nl_vnd_radio_param_tx_chainmask_get,
        osw_drv_spf13_nl_vnd_radio_param_tx_chainmask_set,
        OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_TXCHAINMASK)

DEFINE_RADIO_PARAM_U32(
        osw_drv_spf13_nl_vnd_radio_param_reg_domain_get,
        osw_drv_spf13_nl_vnd_radio_param_reg_domain_set,
        OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_REGDOMAIN);

DEFINE_RADIO_PARAM_U32(
        osw_drv_spf13_nl_vnd_radio_param_country_id_get,
        osw_drv_spf13_nl_vnd_radio_param_country_id_set,
        OL_SPECIAL_PARAM_SHIFT | OL_SPECIAL_PARAM_COUNTRY_ID);

DEFINE_RADIO_PARAM_U32(
        osw_drv_spf13_nl_vnd_radio_param_next_radar_freq_get,
        osw_drv_spf13_nl_vnd_radio_param_next_radar_freq_set,
        OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_NXT_RDR_FREQ);

DEFINE_RADIO_PARAM_U32(
        osw_drv_spf13_nl_vnd_radio_param_next_radar_width_get,
        osw_drv_spf13_nl_vnd_radio_param_next_radar_width_set,
        OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_NXT_RDR_WIDTH);

DEFINE_RADIO_PARAM_U32(
        osw_drv_spf13_nl_vnd_radio_param_flush_peer_rate_stats_get,
        osw_drv_spf13_nl_vnd_radio_param_flush_peer_rate_stats_set,
        OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_NXT_RDR_WIDTH);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_bcn_rate_get,
        osw_drv_spf13_nl_vnd_vap_param_bcn_rate_set,
        IEEE80211_PARAM_BEACON_RATE_FOR_VAP);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_mgmt_rate_get,
        osw_drv_spf13_nl_vnd_vap_param_mgmt_rate_set,
        IEEE80211_PARAM_MGMT_RATE);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_mcast_rate_get,
        osw_drv_spf13_nl_vnd_vap_param_mcast_rate_set,
        IEEE80211_PARAM_MCAST_RATE);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_bcast_rate_get,
        osw_drv_spf13_nl_vnd_vap_param_bcast_rate_set,
        IEEE80211_PARAM_BCAST_RATE);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_rrm_get,
        osw_drv_spf13_nl_vnd_vap_param_rrm_set,
        IEEE80211_PARAM_RRM_CAP);

DEFINE_VAP_PARAM_U32(osw_drv_spf13_nl_vnd_vap_param_me_get, osw_drv_spf13_nl_vnd_vap_param_me_set, IEEE80211_PARAM_ME);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_mbss_en_get,
        osw_drv_spf13_nl_vnd_vap_param_mbss_en_set,
        OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_MBSS_EN);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_mbss_tx_vdev_get,
        osw_drv_spf13_nl_vnd_vap_param_mbss_tx_vdev_set,
        IEEE80211_PARAM_MBSS_TXVDEV);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_mbss_group_get,
        osw_drv_spf13_nl_vnd_vap_param_mbss_group_set,
        IEEE80211_PARAM_MBSS_GROUP);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_ap_bridge_get,
        osw_drv_spf13_nl_vnd_vap_param_ap_bridge_set,
        IEEE80211_PARAM_APBRIDGE);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_uapsd_get,
        osw_drv_spf13_nl_vnd_vap_param_uapsd_set,
        IEEE80211_PARAM_UAPSDINFO);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_vdev_up_get,
        osw_drv_spf13_nl_vnd_vap_param_vdev_up_set,  // no set!
        IEEE80211_PARAM_VDEV_UP);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_mbo_get,
        osw_drv_spf13_nl_vnd_vap_param_mbo_set,
        IEEE80211_PARAM_MBO);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_oce_get,
        osw_drv_spf13_nl_vnd_vap_param_oce_set,
        IEEE80211_PARAM_OCE);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_min_rssi_get,
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_min_rssi_set,
        IEEE80211_PARAM_OCE_ASSOC_MIN_RSSI);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_reject_get,
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_reject_set,
        IEEE80211_PARAM_OCE_ASSOC_REJECT);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_retry_delay_get,
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_retry_delay_set,
        IEEE80211_PARAM_OCE_ASSOC_RETRY_DELAY);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_max_sta_get,
        osw_drv_spf13_nl_vnd_vap_param_max_sta_set,
        IEEE80211_PARAM_MAXSTA);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_he_dl_mu_ofdma_get,
        osw_drv_spf13_nl_vnd_vap_param_he_dl_mu_ofdma_set,
        IEEE80211_PARAM_HE_DL_MU_OFDMA);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_he_ul_mu_ofdma_get,
        osw_drv_spf13_nl_vnd_vap_param_he_ul_mu_ofdma_set,
        IEEE80211_PARAM_HE_UL_MU_OFDMA);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_eht_dl_mu_ofdma_get,
        osw_drv_spf13_nl_vnd_vap_param_eht_dl_mu_ofdma_set,
        IEEE80211_PARAM_EHT_DL_MU_OFDMA);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_eht_ul_mu_ofdma_get,
        osw_drv_spf13_nl_vnd_vap_param_eht_ul_mu_ofdma_set,
        IEEE80211_PARAM_EHT_UL_MU_OFDMA);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_powersave_get,
        osw_drv_spf13_nl_vnd_vap_param_powersave_set,
        IEEE80211_PARAM_NETWORK_SLEEP);

DEFINE_VAP_PARAM_U32(
        osw_drv_spf13_nl_vnd_vap_param_athnewindo_get,
        osw_drv_spf13_nl_vnd_vap_param_athnewind_set,
        IEEE80211_PARAM_VAP_ENHIND);

#define OSW_DRV_SPF13_NL_VND_VAP_PARAM_ME_TUNNELING   (1 << 0)
#define OSW_DRV_SPF13_NL_VND_VAP_PARAM_ME_TRANSLATING (1 << 1)
#define OSW_DRV_SPF13_NL_VND_VAP_PARAM_ME_NO_SNOOPING (1 << 2)

bool osw_drv_spf13_nl_vnd_vap_param_me_parse(
        const uint32_t *value,
        bool *tunneling,
        bool *translating,
        bool *no_snooping)
{
    if (value == NULL) return false;
    if (tunneling != NULL)
    {
        *tunneling = (*value & OSW_DRV_SPF13_NL_VND_VAP_PARAM_ME_TUNNELING) != 0;
    }
    if (translating != NULL)
    {
        *translating = (*value & OSW_DRV_SPF13_NL_VND_VAP_PARAM_ME_TRANSLATING) != 0;
    }
    if (no_snooping != NULL)
    {
        *no_snooping = (*value & OSW_DRV_SPF13_NL_VND_VAP_PARAM_ME_NO_SNOOPING) != 0;
    }
    return true;
}

uint32_t osw_drv_spf13_nl_vnd_vap_param_me_build(bool tunneling, bool translating, bool no_snooping)
{
    uint32_t value = 0;
    if (tunneling)
    {
        value |= OSW_DRV_SPF13_NL_VND_VAP_PARAM_ME_TUNNELING;
    }
    if (translating)
    {
        value |= OSW_DRV_SPF13_NL_VND_VAP_PARAM_ME_TRANSLATING;
    }
    if (no_snooping)
    {
        value |= OSW_DRV_SPF13_NL_VND_VAP_PARAM_ME_NO_SNOOPING;
    }
    return value;
}

struct nl_msg *osw_drv_spf13_nl_vnd_radio_chanswitch(
        uint32_t nl80211_family_id,
        uint32_t wifi_ifindex,
        const struct osw_channel *c,
        int tbtt)
{
    struct extended_ioctl_wrapper data = {0};

    const int freq = c->control_freq_mhz;
    const int chan = osw_freq_to_chan(freq);
    const int chan2 = c->width == OSW_CHANNEL_80P80MHZ ? osw_freq_to_chan(c->center_freq1_mhz)
                      : c->width == OSW_CHANNEL_320MHZ ? osw_freq_to_chan(c->center_freq0_mhz)
                                                       : 0;
    const enum osw_band band = osw_freq_to_band(freq);
    struct osw_channel ht40c = *c;
    osw_channel_downgrade_to(&ht40c, OSW_CHANNEL_40MHZ);
    const bool center_to_the_left = (ht40c.control_freq_mhz > ht40c.center_freq0_mhz);
    const bool center_to_the_right = (ht40c.control_freq_mhz < ht40c.center_freq0_mhz);
    const bool center_is_equal = (ht40c.control_freq_mhz == ht40c.center_freq0_mhz);

    if (center_to_the_left)
    {
        data.ext_data.channel_switch_req.sec_chan_offset = WIFI_SEC_CHAN_OFFSET_IS_MINUS;
    }
    else if (center_to_the_right)
    {
        data.ext_data.channel_switch_req.sec_chan_offset = WIFI_SEC_CHAN_OFFSET_IS_PLUS;
    }
    else if (center_is_equal)
    {
        data.ext_data.channel_switch_req.sec_chan_offset = WIFI_SEC_CHAN_OFFSET_NA;
    }
    else
    {
        LOGE(LOG_PREFIX("unexpected channel center %d MHz", ht40c.control_freq_mhz));
        return NULL;
    }

    switch (c->width)
    {
        case OSW_CHANNEL_20MHZ:
            data.ext_data.channel_switch_req.target_chanwidth = WIFI_OPERATING_CHANWIDTH_20MHZ;
            break;
        case OSW_CHANNEL_40MHZ:
            data.ext_data.channel_switch_req.target_chanwidth = WIFI_OPERATING_CHANWIDTH_40MHZ;
            break;
        case OSW_CHANNEL_80MHZ:
            data.ext_data.channel_switch_req.target_chanwidth = WIFI_OPERATING_CHANWIDTH_80MHZ;
            break;
        case OSW_CHANNEL_80P80MHZ:
            data.ext_data.channel_switch_req.target_chanwidth = WIFI_OPERATING_CHANWIDTH_80_80MHZ;
            break;
        case OSW_CHANNEL_160MHZ:
            data.ext_data.channel_switch_req.target_chanwidth = WIFI_OPERATING_CHANWIDTH_160MHZ;
            break;
        case OSW_CHANNEL_320MHZ:
            data.ext_data.channel_switch_req.target_chanwidth = WIFI_OPERATING_CHANWIDTH_320MHZ;
            break;
        default:
            LOGE(LOG_PREFIX("unknown channel width %d", c->width));
            return NULL;
    }

    switch (band)
    {
        case OSW_BAND_2GHZ:
            data.ext_data.channel_switch_req.band = WLAN_BAND_2GHZ;
            break;
        case OSW_BAND_5GHZ:
            data.ext_data.channel_switch_req.band = WLAN_BAND_5GHZ;
            break;
        case OSW_BAND_6GHZ:
            data.ext_data.channel_switch_req.band = WLAN_BAND_6GHZ;
            break;
        default:
            LOGE(LOG_PREFIX("unknown band %d", osw_freq_to_band(c->control_freq_mhz)));
            return NULL;
    }

    data.cmd = EXTENDED_SUBIOCTL_CHANNEL_SWITCH;
    data.ext_data.channel_switch_req.target_pchannel = chan;
    data.ext_data.channel_switch_req.target_cfreq2 = chan2;
    data.ext_data.channel_switch_req.num_csa = tbtt;
    data.ext_data.channel_switch_req.force = 0;
    data.ext_data.channel_switch_req.puncture_bitmap = c->puncture_bitmap;

    const struct osw_drv_spf13_nl_vnd_generic data_generic = {
        .nl80211_family_id = nl80211_family_id,
        .ifindex = wifi_ifindex,
        .mlo_link_id = -1,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS,
        .data_ptr = &data,
        .data_len = sizeof(data),
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&data_generic);
}

struct nl_msg *osw_drv_spf13_nl_vnd_vap_list_sta(uint32_t family_id, uint32_t ifindex, int8_t mlo_link_id)
{
    const osw_drv_spf13_nl_vnd_generic_t param = {
        .nl80211_family_id = family_id,
        .ifindex = ifindex,
        .mlo_link_id = mlo_link_id,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDOR_SUBCMD_LIST_STA,
        .value = 0,
        .data_ptr = NULL,
        .data_len = 0,
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&param);
}

const osw_drv_spf13_nl_vnd_sta_info_t *osw_drv_spf13_nl_vnd_sta_info_get_first(struct nl_msg *msg, size_t *remaining)
{
    uint32_t len = 0;
    const struct ieee80211req_sta_info *sta = osw_drv_spf13_nl_vnd_generic_from_msg(msg, &len, NULL);

    if (sta == NULL) return NULL;
    if (len < sizeof(*sta)) return NULL;
    if (len < sta->isi_len) return NULL;

    *remaining = len;
    return (const osw_drv_spf13_nl_vnd_sta_info_t *)sta;
}

const osw_drv_spf13_nl_vnd_sta_info_t *osw_drv_spf13_nl_vnd_sta_info_get_next(
        const osw_drv_spf13_nl_vnd_sta_info_t *info,
        size_t *remaining)
{
    if (info == NULL) return NULL;
    if (remaining == NULL) return NULL;

    const struct ieee80211req_sta_info *sta = (const struct ieee80211req_sta_info *)info;
    if (*remaining < sta->isi_len) return NULL;
    *remaining -= sta->isi_len;
    const void *next = ((const void *)sta) + sta->isi_len;
    return next;
}

const struct osw_hwaddr *osw_drv_spf13_nl_vnd_sta_info_get_addr(const osw_drv_spf13_nl_vnd_sta_info_t *info)
{
    const struct ieee80211req_sta_info *sta = (const struct ieee80211req_sta_info *)info;
    return osw_hwaddr_from_cptr_unchecked(sta->isi_macaddr);
}

const struct osw_hwaddr *osw_drv_spf13_nl_vnd_sta_info_get_mld_addr(const osw_drv_spf13_nl_vnd_sta_info_t *info)
{
    const struct ieee80211req_sta_info *sta = (const struct ieee80211req_sta_info *)info;
    if (!sta->isi_is_mlo) return NULL;
    return osw_hwaddr_from_cptr_unchecked(sta->isi_mldaddr);
}

struct nl_msg *osw_drv_spf13_nl_vnd_vap_kickmac(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_hwaddr *mac_addr,
        osw_drv_spf13_nl_vnd_vap_kickmac_action_t action)
{
    const osw_drv_spf13_nl_vnd_generic_t param = {
        .nl80211_family_id = family_id,
        .ifindex = ifindex,
        .mlo_link_id = mlo_link_id,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDORSUBCMD_KICKMAC,
        .value = action == OSW_DRV_SPF13_NL_VND_VAP_KICKMAC_ACTION_NO_TX ? 1 : 0,
        .data_ptr = mac_addr->octet,
        .data_len = sizeof(mac_addr->octet),
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&param);
}

struct nl_msg *osw_drv_spf13_nl_vnd_radio_get_survey(uint32_t family_id, uint32_t ifindex)
{
    const struct ieee80211req_athdbg data = {
        .cmd = IEEE80211_DBGREQ_GET_SURVEY_STATS,
    };
    const osw_drv_spf13_nl_vnd_generic_t generic = {
        .nl80211_family_id = family_id,
        .ifindex = ifindex,
        .mlo_link_id = -1,
        .vendor_cmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        .generic_cmd = QCA_NL80211_VENDOR_SUBCMD_DBGREQ,
        .data_ptr = &data,
        .data_len = sizeof(data),
    };
    return osw_drv_spf13_nl_vnd_generic_to_msg(&generic);
}

static uint32_t osw_drv_spf13_nl_vnd_cycle_to_msec(uint64_t cycle)
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

static void osw_drv_spf13_nl_vnd_put_survey(struct osw_tlv *t, const char *phy_name, const struct channel_stats *cs)
{
    const uint32_t freq_mhz = cs->freq;
    const uint32_t active = osw_drv_spf13_nl_vnd_cycle_to_msec(cs->cycle_cnt);
    const uint32_t tx = osw_drv_spf13_nl_vnd_cycle_to_msec(cs->tx_frm_cnt);
    const uint32_t rx = osw_drv_spf13_nl_vnd_cycle_to_msec(cs->rx_frm_cnt);
    const uint32_t inbss = osw_drv_spf13_nl_vnd_cycle_to_msec(cs->bss_rx_cnt);
    const uint32_t busy = osw_drv_spf13_nl_vnd_cycle_to_msec(cs->clear_cnt);
    const float noise = cs->chan_nf;

    LOGT(LOG_PREFIX_PHY(
            phy_name,
            "stats: survey:"
            " freq=%" PRIu32 " MHz"
            " nf=%" PRId16 " dB"
            " total=%" PRIu32 " tx=%" PRIu32 " rx=%" PRIu32 " rx_bss=%" PRIu32 " clear=%" PRIu32,
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

void osw_drv_spf13_nl_vnd_fill_survey_stats(struct nl_msg **msgs, const char *phy_name, struct osw_tlv *t)
{
    struct nl_msg **iter;
    uint32_t home_freq = 0;

    // this puts the home survey stats only (if it exists)
    // and stores the home frequency for later use
    for (iter = msgs; iter != NULL && *iter != NULL; iter++)
    {
        struct nl_msg *msg = *iter;
        uint32_t len = 0;
        uint32_t flags = 0;
        const struct channel_stats *cs = osw_drv_spf13_nl_vnd_generic_from_msg(msg, &len, &flags);
        if (cs == NULL) continue;

        const bool is_home = (flags == 1);
        const bool is_scan = (flags == 2);

        if (is_home)
        {
            home_freq = cs->freq;
            osw_drv_spf13_nl_vnd_put_survey(t, phy_name, cs);
        }
        else if (is_scan)
        {
            /* do nothing for now */
        }
    }

    // this adds (the remaining) surveys for non-home channels
    for (iter = msgs; iter != NULL && *iter != NULL; iter++)
    {
        struct nl_msg *msg = *iter;
        uint32_t len = 0;
        uint32_t flags = 0;
        const struct channel_stats *cs = osw_drv_spf13_nl_vnd_generic_from_msg(msg, &len, &flags);
        if (cs == NULL) continue;

        const bool is_home = (flags == 1);
        const bool is_scan = (flags == 2);

        if (is_home)
        {
            /* dont here here */
        }
        else if (is_scan)
        {
            if (cs->freq != home_freq)
            {
                osw_drv_spf13_nl_vnd_put_survey(t, phy_name, cs);
            }
        }
    }
}

bool osw_drv_spf13_nl_vnd_event_subcmd_is_stats_flush(uint32_t subcmd)
{
    return subcmd == QCA_NL80211_VENDOR_SUBCMD_PEER_STATS_CACHE_FLUSH;
}

static void osw_drv_spf13_nl_vnd_fill_rate_stats_rx(
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

    while (stats_len >= sizeof(*stats) && left > 0)
    {
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

    LOGT(LOG_PREFIX_STA(
            phy_name,
            vif_name,
            sta_addr,
            "stats: rx:"
            " mpdu=%" PRIu64 " retry=%" PRIu64 " bytes=%" PRIu64,
            mpdu,
            retry,
            bytes));

    WARN_ON(bytes >= UINT32_MAX);
    WARN_ON(mpdu >= UINT32_MAX);
    WARN_ON(retry >= UINT32_MAX);
}

static void osw_drv_spf13_nl_vnd_fill_rate_stats_tx(
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

    while (stats_len >= sizeof(*stats) && left > 0)
    {
        if (WARN_ON(stats->mpdu_attempts < stats->mpdu_success))
        {
            LOGW(LOG_PREFIX_STA(
                    phy_name,
                    vif_name,
                    sta_addr,
                    "stats: tx:"
                    " mpdu_attempts=%" PRIu32 " mpdu_auccess=%" PRIu32 " num_bytes=%" PRIu32,
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

    LOGT(LOG_PREFIX_STA(
            phy_name,
            vif_name,
            sta_addr,
            "stats: tx:"
            " mpdu=%" PRIu64 " retry=%" PRIu64 " bytes=%" PRIu64,
            mpdu,
            retry,
            bytes));

    WARN_ON(bytes >= UINT32_MAX);
    WARN_ON(mpdu >= UINT32_MAX);
    WARN_ON(retry >= UINT32_MAX);
}

static void osw_drv_spf13_nl_vnd_fill_rate_stats_avg(
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

    while (tx_size >= sizeof(*tx))
    {
        tx_mbps += tx->sum_mbps;
        tx_ppdu += tx->num_ppdu;

        /* It seems Tx ACK SNR is prone to misreporting
         * lower-than-expected values. This can be mostly seen
         * on 6GHz band. Until this is fully investigated and
         * resolved don't use it unless explicitly enabled
         * through env flag. This ends up using Rx SNR only.
         */
        if (osw_etc_get("OSW_PLAT_QSDK11_4_USE_TX_ACK_SNR"))
        {
            snr += tx->sum_snr;
            snr_cnt += tx->num_snr;
        }

        tx_size -= sizeof(*tx);
        tx++;
    }

    while (rx_size >= sizeof(*rx))
    {
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

    LOGT(LOG_PREFIX_STA(
            phy_name,
            vif_name,
            sta_addr,
            "stats: avg:"
            " tx=%" PRIu64 " rx=%" PRIu64 " snr=%" PRIu64,
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

bool osw_drv_spf13_nl_vnd_fill_rate_stats(
        const void *data,
        size_t len,
        const char *phy_name,
        const char *(*get_vif_name_cb)(const char *phy_name, const struct osw_hwaddr *sta_addr),
        struct osw_tlv *t)
{
    if (WARN_ON(data == NULL)) return false;
    if (WARN_ON(phy_name == NULL)) return false;
    if (WARN_ON(get_vif_name_cb == NULL)) return false;
    if (WARN_ON(t == NULL)) return false;

    struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_MAX + 1];
    const int err = nla_parse(tb, QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_MAX, (void *)data, len, NULL);
    if (WARN_ON(err)) return false;

    struct nlattr *attr_cache_type = tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_TYPE];
    struct nlattr *attr_cache_data = tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_DATA];
    struct nlattr *attr_cache_peer_mac = tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_PEER_MAC];
    struct nlattr *attr_cache_peer_cookie = tb[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_PEER_COOKIE];

    if (WARN_ON(attr_cache_type == NULL)) return false;
    if (WARN_ON(attr_cache_data == NULL)) return false;
    if (WARN_ON(attr_cache_peer_mac == NULL)) return false;
    if (WARN_ON(attr_cache_peer_cookie == NULL)) return false;

    const uint32_t cache_type = nla_get_u32(attr_cache_type);
    const void *cache_data = nla_data(attr_cache_data);
    const size_t cache_data_len = nla_len(attr_cache_data);
    const uint8_t *cache_peer_mac = nla_data(attr_cache_peer_mac);
    const size_t cache_peer_mac_len = nla_len(attr_cache_peer_mac);
    // unused: const uint64_t cache_peer_cookie = nla_get_u64(attr_cache_peer_cookie);

    const struct osw_hwaddr *sta_addr = osw_hwaddr_from_cptr(cache_peer_mac, cache_peer_mac_len);
    if (WARN_ON(sta_addr == NULL)) return false;

    const char *vif_name = get_vif_name_cb(phy_name, sta_addr);
    /* It is expected that the caller may not be able to handle
     * post-disconnection last-breath reports. Don't generate a warning if
     * that's the case.
     */
    if (vif_name == NULL)
    {
        LOGI(LOG_PREFIX_STA(phy_name, "?", sta_addr, "stats: cant infer vif_name, did it just disconnect?"));
        return false;
    }

    const size_t off = osw_tlv_put_nested(t, OSW_STATS_STA);
    {
        osw_tlv_put_string(t, OSW_STATS_STA_PHY_NAME, phy_name);
        osw_tlv_put_string(t, OSW_STATS_STA_VIF_NAME, vif_name);
        osw_tlv_put_hwaddr(t, OSW_STATS_STA_MAC_ADDRESS, sta_addr);
        switch (cache_type)
        {
            case DP_PEER_RX_RATE_STATS:
                osw_drv_spf13_nl_vnd_fill_rate_stats_rx(t, phy_name, vif_name, sta_addr, cache_data, cache_data_len);
                break;
            case DP_PEER_TX_RATE_STATS:
                osw_drv_spf13_nl_vnd_fill_rate_stats_tx(t, phy_name, vif_name, sta_addr, cache_data, cache_data_len);
                break;
            case DP_PEER_AVG_RATE_STATS:
                osw_drv_spf13_nl_vnd_fill_rate_stats_avg(t, phy_name, vif_name, sta_addr, cache_data, cache_data_len);
                break;
            default:
                LOGD(LOG_PREFIX_STA(phy_name, vif_name, sta_addr, "stats: unknown cache type %d", cache_type));
                break;
        }
    }
    osw_tlv_end_nested(t, off);

    return true;
}
