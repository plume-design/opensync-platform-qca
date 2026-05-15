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

/* 3rd party */
#include <nl80211_copy.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

/* opensync */
#include <log.h>

/* osw */
#include <osw_types.h>
#include <osw_tlv.h>
#include <osw_drv.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_nl_80211.h"

struct nl_msg *osw_drv_spf13_nl_80211_msg_get_wiphy(const uint32_t family_id, const uint32_t wiphy)
{
    struct nl_msg *msg = nlmsg_alloc();
    const int flags = NLM_F_DUMP | NLM_F_ACK;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, flags, NL80211_CMD_GET_WIPHY, 0);
    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    nla_put_u32(msg, NL80211_ATTR_WIPHY, wiphy);
    return msg;
}

struct nl_msg *osw_drv_spf13_nl_80211_msg_get_interface(const uint32_t family_id, const uint32_t ifindex)
{
    if (ifindex == 0) return NULL;
    struct nl_msg *msg = nlmsg_alloc();
    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, flags, NL80211_CMD_GET_INTERFACE, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    return msg;
}

struct nl_msg *osw_drv_spf13_nl_80211_msg_dump_scan(const uint32_t family_id, const uint32_t ifindex)
{
    if (ifindex == 0) return NULL;
    struct nl_msg *msg = nlmsg_alloc();
    const int flags = NLM_F_DUMP | NLM_F_ACK;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, flags, NL80211_CMD_GET_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    return msg;
}

struct nl_msg *osw_drv_spf13_nl_80211_msg_set_tx_power_auto(uint32_t family_id, uint32_t ifindex, int8_t mlo_link_id)
{
    if (ifindex == 0) return NULL;
    struct nl_msg *msg = nlmsg_alloc();
    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, flags, NL80211_CMD_SET_WIPHY, 0);
    assert(nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) == 0);
    if (mlo_link_id >= 0)
    {
        assert(nla_put_u8(msg, NL80211_ATTR_MLO_LINK_ID, mlo_link_id) == 0);
    }
    assert(nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_SETTING, NL80211_TX_POWER_AUTOMATIC) == 0);
    return msg;
}

struct nl_msg *osw_drv_spf13_nl_80211_msg_set_tx_power_fixed(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        int32_t mbm)
{
    if (ifindex == 0) return NULL;
    struct nl_msg *msg = nlmsg_alloc();
    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, flags, NL80211_CMD_SET_WIPHY, 0);
    assert(nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) == 0);
    if (mlo_link_id >= 0)
    {
        assert(nla_put_u8(msg, NL80211_ATTR_MLO_LINK_ID, mlo_link_id) == 0);
    }
    assert(nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_SETTING, NL80211_TX_POWER_FIXED) == 0);
    assert(nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_LEVEL, (uint32_t)mbm) == 0);
    return msg;
}

struct nl_msg *osw_drv_spf13_nl_80211_msg_frame(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_channel *channel,
        const void *frame_buf,
        size_t frame_len)
{
    struct nl_msg *msg = nlmsg_alloc();
    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, flags, NL80211_CMD_FRAME, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    if (channel != NULL)
    {
        nla_put_flag(msg, NL80211_ATTR_OFFCHANNEL_TX_OK);
        nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, channel->control_freq_mhz);
    }
    if (mlo_link_id >= 0)
    {
        nla_put_u8(msg, NL80211_ATTR_MLO_LINK_ID, mlo_link_id);
    }
    nla_put(msg, NL80211_ATTR_FRAME, frame_len, frame_buf);

    return msg;
}
int osw_drv_spf13_nl_80211_get_family_id(void)
{
    struct nl_sock *sock = nl_socket_alloc();
    if (sock == NULL)
    {
        LOGE(LOG_PREFIX("failed to allocate netlink socket"));
        return -1;
    }

    if (genl_connect(sock) < 0)
    {
        LOGE(LOG_PREFIX("failed to connect to generic netlink"));
        nl_socket_free(sock);
        return -1;
    }

    const int family_id = genl_ctrl_resolve(sock, "nl80211");
    if (family_id < 0)
    {
        LOGE(LOG_PREFIX("failed to resolve nl80211 family id: %s"), nl_geterror(family_id));
        nl_socket_free(sock);
        return -1;
    }

    nl_socket_free(sock);
    LOGD(LOG_PREFIX("nl80211 family id: %d"), family_id);
    return family_id;
}

static int osw_drv_spf13_nl_80211_offset_from_nl_type(enum nl80211_channel_type type)
{
    switch (type)
    {
        case NL80211_CHAN_NO_HT:
            return 0;
        case NL80211_CHAN_HT20:
            return 0;
        case NL80211_CHAN_HT40MINUS:
            return -4;
        case NL80211_CHAN_HT40PLUS:
            return 4;
    }
    WARN_ON(1);
    return 0;
}

static enum osw_channel_width osw_drv_spf13_nl_80211_width_from_nl_type(enum nl80211_channel_type type)
{
    switch (type)
    {
        case NL80211_CHAN_NO_HT:
            return OSW_CHANNEL_20MHZ;
        case NL80211_CHAN_HT20:
            return OSW_CHANNEL_20MHZ;
        case NL80211_CHAN_HT40MINUS:
            return OSW_CHANNEL_40MHZ;
        case NL80211_CHAN_HT40PLUS:
            return OSW_CHANNEL_40MHZ;
    }
    WARN_ON(1);
    return OSW_CHANNEL_20MHZ;
}

static enum osw_channel_width osw_drv_spf13_nl_80211_width_from_nl_width(enum nl80211_chan_width width)
{
    switch (width)
    {
        case NL80211_CHAN_WIDTH_20_NOHT:
            return OSW_CHANNEL_20MHZ;
        case NL80211_CHAN_WIDTH_20:
            return OSW_CHANNEL_20MHZ;
        case NL80211_CHAN_WIDTH_40:
            return OSW_CHANNEL_40MHZ;
        case NL80211_CHAN_WIDTH_80:
            return OSW_CHANNEL_80MHZ;
        case NL80211_CHAN_WIDTH_80P80:
            return OSW_CHANNEL_80P80MHZ;
        case NL80211_CHAN_WIDTH_160:
            return OSW_CHANNEL_160MHZ;
        case NL80211_CHAN_WIDTH_320:
            return OSW_CHANNEL_320MHZ;
        default:
            break;
    }
    return OSW_CHANNEL_20MHZ;
}

bool osw_drv_spf13_nl_80211_try_into_chan(struct osw_channel *c, struct nlattr *tb[NL80211_ATTR_MAX + 1])
{
    memset(c, 0, sizeof(*c));

    struct nlattr *nl_freq = tb[NL80211_ATTR_WIPHY_FREQ];
    struct nlattr *nl_width = tb[NL80211_ATTR_CHANNEL_WIDTH];
    struct nlattr *nl_center1 = tb[NL80211_ATTR_CENTER_FREQ1];
    struct nlattr *nl_center2 = tb[NL80211_ATTR_CENTER_FREQ2];
    struct nlattr *nl_type = tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE];
    struct nlattr *nl_puncture = tb[NL80211_ATTR_PUNCT_BITMAP];

    if (nl_freq == NULL) return false;

    const uint32_t freq_mhz = nla_get_u32(nl_freq);

    c->control_freq_mhz = freq_mhz;

    if (nl_width != NULL)
    {
        enum nl80211_chan_width width = nla_get_u32(nl_width);
        const uint32_t center1_mhz = nl_center1 ? nla_get_u32(nl_center1) : 0;
        const uint32_t center2_mhz = nl_center2 ? nla_get_u32(nl_center2) : 0;
        c->width = osw_drv_spf13_nl_80211_width_from_nl_width(width);
        c->center_freq0_mhz = center1_mhz;
        c->center_freq1_mhz = center2_mhz;
    }
    else if (nl_type != NULL)
    {
        const enum nl80211_channel_type type = nla_get_u32(nl_type);
        const int offset_mhz = osw_drv_spf13_nl_80211_offset_from_nl_type(type);
        c->width = osw_drv_spf13_nl_80211_width_from_nl_type(type);
        c->center_freq0_mhz = freq_mhz + offset_mhz;
    }
    else
    {
        c->width = OSW_CHANNEL_20MHZ;
        c->center_freq0_mhz = freq_mhz;
    }

    // FIXME: Test if the qca-wifi driver actually signals puncturing in the
    // standard nl80211 chandefs.
    if (nl_puncture != NULL)
    {
        uint32_t puncture = nla_get_u32(nl_puncture);
        if (puncture > UINT16_MAX)
        {
            LOGW(LOG_PREFIX("puncture bitmap too large: 0x%" PRIx32 ", clipping"), puncture);
            puncture &= UINT16_MAX; /* clip to 16 bits */
        }
        c->puncture_bitmap = puncture;
    }

    return true;
}

static bool osw_drv_spf13_nl_80211_wiphy_ext_feat_is_set(
        const uint8_t *ext_feat,
        size_t ext_feat_len,
        enum nl80211_ext_feature_index feat)
{
    if (ext_feat == NULL) return false;
    const size_t byte_index = feat / 8;
    const size_t bit_index = feat % 8;
    if (byte_index >= ext_feat_len) return false;
    return (ext_feat[byte_index] & (1 << bit_index)) != 0;
}

void osw_drv_spf13_nl_80211_fill_wiphy(struct osw_drv_phy_state *phy_state, int wiphy_idx, struct nl_msg **msgs)
{
    if (phy_state == NULL) return;
    if (wiphy_idx < 0) return;
    for (; msgs != NULL && *msgs != NULL; msgs++)
    {
        struct nl_msg *msg = *msgs;
        struct nlattr *tb[NL80211_ATTR_MAX + 1] = {0};
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        if (genlmsg_parse(nlh, 0, tb, NL80211_ATTR_MAX, NULL) < 0)
        {
            LOGE(LOG_PREFIX("failed to parse netlink message"));
            continue;
        }

        struct nlattr *attr_wiphy = tb[NL80211_ATTR_WIPHY];
        if (nla_get_u32(attr_wiphy) != (uint32_t)wiphy_idx)
        {
            continue;
        }

        struct nlattr *attr_ext_feat = tb[NL80211_ATTR_EXT_FEATURES];
        if (attr_ext_feat != NULL)
        {
            const uint8_t *ext_feat = nla_data(attr_ext_feat);
            const size_t ext_feat_len = nla_len(attr_ext_feat);

            if (osw_drv_spf13_nl_80211_wiphy_ext_feat_is_set(ext_feat, ext_feat_len, NL80211_EXT_FEATURE_PUNCT))
            {
                phy_state->puncture_supported = true;
            }
        }

        struct nlattr *attr_interface_combinations = tb[NL80211_ATTR_INTERFACE_COMBINATIONS];
        if (attr_interface_combinations != NULL)
        {
            int rem;
            struct nlattr *combination;
            nla_for_each_nested(combination, attr_interface_combinations, rem)
            {
                struct nla_policy policy[MAX_NL80211_IFACE_COMB + 1] = {
                    [NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS] = {.type = NLA_U32},
                };
                struct nlattr *tb_combination[MAX_NL80211_IFACE_COMB + 1];
                const int err = nla_parse_nested(tb_combination, MAX_NL80211_IFACE_COMB, combination, policy);
                if (err) continue;

                struct nlattr *attr_radar_detect_widths = tb_combination[NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS];
                if (attr_radar_detect_widths != NULL)
                {
                    const uint32_t radar_detect_widths = nla_get_u32(attr_radar_detect_widths);
                    if (radar_detect_widths != 0)
                    {
                        phy_state->radar = OSW_RADAR_DETECT_ENABLED;
                    }
                }
            }
        }
    }
}

void osw_drv_spf13_nl_80211_fill_interface(
        struct osw_drv_vif_state *vif_state,
        struct nl_msg *msg,
        const int8_t mlo_link_id)
{
    if (vif_state == NULL) return;
    if (msg == NULL) return;

    struct nlattr *tb[NL80211_ATTR_MAX + 1] = {0};
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    if (genlmsg_parse(nlh, 0, tb, NL80211_ATTR_MAX, NULL) < 0)
    {
        LOGE(LOG_PREFIX("failed to parse netlink message"));
        return;
    }

    struct osw_channel c;
    osw_drv_spf13_nl_80211_try_into_chan(&c, tb);

    if (mlo_link_id >= 0)
    {
        struct nlattr *attr_mlo_links = tb[NL80211_ATTR_MLO_LINKS];
        if (attr_mlo_links != NULL)
        {
            struct nlattr *mlo_link;
            int rem;
            nla_for_each_nested(mlo_link, attr_mlo_links, rem)
            {
                struct nlattr *link_tb[NL80211_ATTR_MAX + 1] = {0};
                if (nla_parse(link_tb, NL80211_ATTR_MAX, nla_data(mlo_link), nla_len(mlo_link), NULL) < 0)
                {
                    continue;
                }

                struct nlattr *attr_mlo_link_id = link_tb[NL80211_ATTR_MLO_LINK_ID];
                if (attr_mlo_link_id == NULL)
                {
                    continue;
                }

                const int8_t this_mlo_link_id = (int8_t)nla_get_u8(attr_mlo_link_id);
                if (this_mlo_link_id != mlo_link_id)
                {
                    continue; /* skip other MLO links */
                }

                struct nlattr *attr_tx_power_level = link_tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL];
                if (attr_tx_power_level != NULL)
                {
                    const int32_t mbm = nla_get_u32(attr_tx_power_level);
                    const int32_t dbm = mbm / 100;
                    vif_state->tx_power_dbm = dbm;
                }

                struct osw_channel link_c;
                if (osw_drv_spf13_nl_80211_try_into_chan(&link_c, link_tb))
                {
                    c = link_c;
                }

                break; /* found the MLO link we are looking for */
            }
        }
    }

    struct nlattr *iftype_attr = tb[NL80211_ATTR_IFTYPE];
    if (iftype_attr != NULL)
    {
        switch (nla_get_u32(iftype_attr))
        {
            case NL80211_IFTYPE_AP:
                vif_state->vif_type = OSW_VIF_AP;
                vif_state->u.ap.channel = c;
                break;
            case NL80211_IFTYPE_AP_VLAN:
                vif_state->vif_type = OSW_VIF_AP_VLAN;
                break;
            case NL80211_IFTYPE_STATION:
                vif_state->vif_type = OSW_VIF_STA;
                vif_state->u.sta.link.channel = c;
                break;
        }
    }
}

const uint32_t *osw_drv_spf13_nl_80211_get_tx_power_level(struct nl_msg *msg, const int8_t mlo_link_id)
{
    if (msg == NULL) return NULL;

    struct nlattr *tb[NL80211_ATTR_MAX + 1] = {0};
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    if (genlmsg_parse(nlh, 0, tb, NL80211_ATTR_MAX, NULL) < 0)
    {
        LOGW(LOG_PREFIX("failed to parse netlink message"));
        return NULL;
    }

    struct nlattr *attr_mlo_links = tb[NL80211_ATTR_MLO_LINKS];
    if (attr_mlo_links != NULL)
    {
        struct nlattr *mlo_link;
        int rem;
        nla_for_each_nested(mlo_link, attr_mlo_links, rem)
        {
            struct nlattr *link_tb[NL80211_ATTR_MAX + 1] = {0};
            if (nla_parse(link_tb, NL80211_ATTR_MAX, nla_data(mlo_link), nla_len(mlo_link), NULL) < 0)
            {
                continue;
            }

            struct nlattr *attr_mlo_link_id = link_tb[NL80211_ATTR_MLO_LINK_ID];
            if (attr_mlo_link_id == NULL)
            {
                continue;
            }

            const int8_t this_mlo_link_id = (int8_t)nla_get_u8(attr_mlo_link_id);
            if (this_mlo_link_id != mlo_link_id)
            {
                continue; /* skip other MLO links */
            }

            struct nlattr *attr_tx_power_level = link_tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL];
            if (attr_tx_power_level != NULL)
            {
                return nla_data(attr_tx_power_level);
            }
        }
    }

    struct nlattr *attr_tx_power_level = tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL];
    if (attr_tx_power_level != NULL)
    {
        return nla_data(attr_tx_power_level);
    }

    return NULL;
}

struct nl_sock *osw_drv_spf13_nl_80211_listen(int (*recv_cb)(struct nl_msg *msg, void *arg), void *arg)
{
    struct nl_sock *sock = nl_socket_alloc();
    if (sock == NULL)
    {
        LOGE(LOG_PREFIX("failed to allocate netlink socket"));
        return NULL;
    }

    if (genl_connect(sock) < 0)
    {
        LOGE(LOG_PREFIX("failed to connect to generic netlink"));
        nl_socket_free(sock);
        return NULL;
    }

    static const char *groups[] = {"config", "scan", "regulatory", "mlme", "vendor", "nan", "testmode", NULL};

    size_t i;
    for (i = 0; groups[i] != NULL; i++)
    {
        const char *group = groups[i];
        const int group_id = genl_ctrl_resolve_grp(sock, "nl80211", group);
        if (group_id < 0)
        {
            LOGE(LOG_PREFIX("failed to resolve nl80211 %s group id: %s"), group, nl_geterror(group_id));
            nl_socket_free(sock);
            return NULL;
        }

        if (nl_socket_add_membership(sock, group_id) < 0)
        {
            LOGE(LOG_PREFIX("failed to add nl80211 %s group membership"), group);
            nl_socket_free(sock);
            return NULL;
        }

        LOGD(LOG_PREFIX("added nl80211 %s (%d) group membership"), group, group_id);
    }

    nl_socket_disable_auto_ack(sock);
    nl_socket_set_nonblocking(sock);
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, recv_cb, arg);

    return sock;
}

void osw_drv_spf13_nl_80211_fill_bss_stats(
        struct nl_msg *msg,
        const char *phy_name,
        uint32_t *freq_mhz,
        struct osw_tlv *t)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1] = {0};
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    if (genlmsg_parse(nlh, 0, tb, NL80211_ATTR_MAX, NULL) < 0)
    {
        LOGE(LOG_PREFIX("failed to parse netlink message"));
        return;
    }

    struct nlattr *attr_bss = tb[NL80211_ATTR_BSS];
    if (attr_bss == NULL)
    {
        LOGW(LOG_PREFIX("no BSS attribute in netlink message"));
        return;
    }

    struct nlattr *tb_bss[NL80211_BSS_MAX + 1] = {0};
    const int bss_err = nla_parse_nested(tb_bss, NL80211_BSS_MAX, attr_bss, NULL);
    if (bss_err < 0)
    {
        LOGW(LOG_PREFIX("failed to parse BSS attribute: %s"), nl_geterror(bss_err));
        return;
    }

    struct nlattr *attr_bssid = tb_bss[NL80211_BSS_BSSID];
    struct nlattr *attr_freq = tb_bss[NL80211_BSS_FREQUENCY];
    struct nlattr *attr_signal = tb_bss[NL80211_BSS_SIGNAL_MBM];
    struct nlattr *attr_ies = tb_bss[NL80211_BSS_INFORMATION_ELEMENTS];

    const struct osw_hwaddr *bssid =
            attr_bssid ? osw_hwaddr_from_cptr(nla_data(attr_bssid), nla_len(attr_bssid)) : NULL;
    *freq_mhz = (attr_freq && (size_t)nla_len(attr_freq) >= sizeof(*freq_mhz)) ? nla_get_u32(attr_freq) : 0;
    const int32_t mdbm = (attr_signal && (size_t)nla_len(attr_signal) >= sizeof(mdbm)) ? nla_get_u32(attr_signal) : 0;
    const int32_t rssi_dbm = mdbm / 100;
    const int32_t noise_dbm = osw_channel_nf_20mhz_fixup(0);
    const uint32_t snr_db = (rssi_dbm >= noise_dbm ? (rssi_dbm - noise_dbm) : 0);

    {
        const size_t off = osw_tlv_put_nested(t, OSW_STATS_BSS_SCAN);
        osw_tlv_put_string(t, OSW_STATS_BSS_SCAN_PHY_NAME, phy_name);
        osw_tlv_put_hwaddr(t, OSW_STATS_BSS_SCAN_MAC_ADDRESS, bssid);
        osw_tlv_put_u32(t, OSW_STATS_BSS_SCAN_FREQ_MHZ, *freq_mhz);
        osw_tlv_put_u32(t, OSW_STATS_BSS_SCAN_SNR_DB, snr_db);
        if (attr_ies != NULL)
        {
            osw_tlv_put_buf(t, OSW_STATS_BSS_SCAN_IES, nla_data(attr_ies), nla_len(attr_ies));
        }
        osw_tlv_end_nested(t, off);
    }
}

struct nl_msg *osw_drv_spf13_nl_80211_msg_roc(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_channel *channel,
        const uint32_t duration_msec)
{
    if (ifindex == 0) return NULL;
    if (channel == NULL) return NULL;

    struct nl_msg *msg = nlmsg_alloc();
    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, flags, NL80211_CMD_REMAIN_ON_CHANNEL, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, channel->control_freq_mhz);
    if (mlo_link_id >= 0)
    {
        nla_put_u8(msg, NL80211_ATTR_MLO_LINK_ID, mlo_link_id);
    }
    nla_put_u32(msg, NL80211_ATTR_DURATION, duration_msec);

    return msg;
}

struct nl_msg *osw_drv_spf13_nl_80211_msg_link_add(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_hwaddr *addr)
{
    if (ifindex == 0) return NULL;
    if (addr == NULL) return NULL;

    struct nl_msg *msg = nlmsg_alloc();
    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, flags, NL80211_CMD_ADD_LINK, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put_u8(msg, NL80211_ATTR_MLO_LINK_ID, mlo_link_id);
    nla_put(msg, NL80211_ATTR_MAC, OSW_HWADDR_LEN, addr->octet);

    return msg;
}
