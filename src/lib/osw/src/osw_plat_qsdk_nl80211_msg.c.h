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

static struct nl_msg *osw_plat_qsdk_nl80211_msg_x_mac(
        int family_id,
        uint32_t ifindex,
        const struct osw_hwaddr *mac,
        uint32_t generic_cmd)
{
    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_setparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            generic_cmd,
            0,
            mac,
            sizeof(*mac));
    return msg;
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_delmac(int family_id, uint32_t ifindex, const struct osw_hwaddr *mac)
{
    return osw_plat_qsdk_nl80211_msg_x_mac(family_id, ifindex, mac, QCA_NL80211_VENDORSUBCMD_DELMAC);
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_addmac(int family_id, uint32_t ifindex, const struct osw_hwaddr *mac)
{
    return osw_plat_qsdk_nl80211_msg_x_mac(family_id, ifindex, mac, QCA_NL80211_VENDORSUBCMD_ADDMAC);
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_getmac(int family_id, uint32_t ifindex)
{
    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_getparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_GET_ACLMAC,
            0);
    return msg;
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_maccmd(int family_id, uint32_t ifindex, uint32_t cmd)
{
    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_setparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            IEEE80211_PARAM_MACCMD,
            &cmd,
            sizeof(cmd));
    return msg;
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_puncture_strict(int family_id, uint32_t ifindex, bool enable)
{
#ifdef WLAN_FEATURE_11BE
    struct nl_msg *msg = nlmsg_alloc();
    const uint32_t v = enable ? 1 : 0;
    osw_plat_qsdk11_4_put_qca_vendor_setparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_STRICT_PUNCTURING,
            &v,
            sizeof(v));
    return msg;
#else
    return NULL;
#endif
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_puncture_dfs(int family_id, uint32_t ifindex, bool enable)
{
#ifdef WLAN_FEATURE_11BE
    struct nl_msg *msg = nlmsg_alloc();
    const uint32_t v = enable ? 1 : 0;
    osw_plat_qsdk11_4_put_qca_vendor_setparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_DFS_PUNCTURE,
            &v,
            sizeof(v));
    return msg;
#else
    return NULL;
#endif
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_get_maccmd(int family_id, uint32_t ifindex)
{
    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_getparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            IEEE80211_PARAM_MACCMD);
    return msg;
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_get_puncture_bitmap(int family_id, uint32_t ifindex)
{
#ifdef WLAN_FEATURE_11BE
    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_getparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            IEEE80211_PARAM_PUNCTURE_BITMAP);
    return msg;
#else
    return NULL;
#endif
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_mode(int family_id, uint32_t ifindex, const char *mode)
{
    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_setparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDORSUBCMD_WIRELESS_MODE,
            0,
            mode,
            strlen(mode) + 1);
    return msg;
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_mode_noreset(int family_id, uint32_t ifindex, const char *mode)
{
    const bool supported = kconfig_enabled(CONFIG_QCA_WIFI_MODE_NO_RESET_SUPPORTED);
    if (supported == false)
    {
        return NULL;
    }

    struct nl_msg *msg = nlmsg_alloc();
    const uint32_t flags = 1; /* 1 = do not reset vaps */
    osw_plat_qsdk11_4_put_qca_vendor_cmd(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDORSUBCMD_WIRELESS_MODE,
            0,
            flags,
            mode,
            strlen(mode) + 1);
    return msg;
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_exttool_csa(
        int family_id,
        uint32_t ifindex,
        const struct osw_channel *c)
{
    struct extended_ioctl_wrapper data;
    MEMZERO(data);

    const int freq = c->control_freq_mhz;
    const int chan = osw_freq_to_chan(freq);
    const int chan2 = c->width == OSW_CHANNEL_80P80MHZ ? osw_freq_to_chan(c->center_freq1_mhz)
                      : c->width == OSW_CHANNEL_320MHZ ? osw_freq_to_chan(c->center_freq0_mhz)
                                                       : 0;
    const enum osw_band band = osw_freq_to_band(freq);
    struct osw_channel ht40c;
    memcpy(&ht40c, &c, sizeof(c));
    osw_channel_downgrade_to(&ht40c, OSW_CHANNEL_40MHZ);
    const enum osw_plat_qsdk_wifi_sec_chan_offset offset =
            c->control_freq_mhz < c->center_freq0_mhz   ? OSW_PLAT_QSDK_WIFI_SEC_CHAN_OFFSET_IS_PLUS
            : c->control_freq_mhz > c->center_freq0_mhz ? OSW_PLAT_QSDK_WIFI_SEC_CHAN_OFFSET_IS_MINUS
                                                        : OSW_PLAT_QSDK_WIFI_SEC_CHAN_OFFSET_NA;

    data.cmd = EXTENDED_SUBIOCTL_CHANNEL_SWITCH;
    data.ext_data.channel_switch_req.target_chanwidth = osw_plat_qsdk_wifi_oper_width_from_width(c->width);
    data.ext_data.channel_switch_req.band = osw_plat_qsdk_wifi_band_from_band(band);
    data.ext_data.channel_switch_req.target_pchannel = chan;
    data.ext_data.channel_switch_req.target_cfreq2 = chan2;
    data.ext_data.channel_switch_req.sec_chan_offset = offset;
    data.ext_data.channel_switch_req.num_csa = 15;
    data.ext_data.channel_switch_req.force = 0;
    /* FIXME: Ifdefs are bad because they aren't necessarily
     * compiled / syntax-checked. It would be better to hold
     * a copy of the driver structure(s) locally. This one
     * keeps this simple for now.
     */
#ifdef CONFIG_QCA_WIFI_PUNCTURE_SUPPORTED
    data.ext_data.channel_switch_req.puncture_bitmap = c->puncture_bitmap;
#endif

    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_setparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS,
            0,
            &data,
            sizeof(data));
    return msg;
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_get_desmode(int family_id, uint32_t ifindex)
{
    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_getparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
            IEEE80211_PARAM_DESIRED_PHYMODE);
    return msg;
}

static struct nl_msg *osw_plat_qsdk_nl80211_msg_list_sta(int family_id, uint32_t ifindex)
{
    struct nl_msg *msg = nlmsg_alloc();
    osw_plat_qsdk11_4_put_qca_vendor_setparam(
            msg,
            family_id,
            ifindex,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_LIST_STA,
            0,
            NULL,
            0);
    return msg;
}
