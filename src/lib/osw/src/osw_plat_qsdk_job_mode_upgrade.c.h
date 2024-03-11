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

struct osw_plat_qsdk_mode_upgrade
{
    struct nl_80211 *nl;
    enum osw_channel_width target_width;
    uint32_t ifindex;
    char *phy_name;
    char *vif_name;
    char *new_mode;
    struct osw_plat_qsdk_nlcmd_resp resp_get_desmode;
    struct osw_plat_qsdk11_4_async *job_get_desmode;
    struct osw_plat_qsdk11_4_async *job_set_mode;
};

static enum osw_plat_qsdk11_4_async_result osw_plat_qsdk_mode_upgrade_poll_cb(
        void *priv,
        struct osw_plat_qsdk11_4_cb *waker)
{
    struct osw_plat_qsdk_mode_upgrade *data = priv;

    if (data->job_get_desmode == NULL)
    {
        const int family_id = nl_80211_get_family_id(data->nl);
        struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_get_desmode(family_id, data->ifindex);
        const char *name = strfmta(
                LOG_PREFIX_VIF(data->phy_name, data->vif_name, "mode upgrade: get: ifindex=%" PRIu32, data->ifindex));
        data->job_get_desmode = osw_plat_qsdk_nlcmd_alloc_resp(name, data->nl, msg, &data->resp_get_desmode);
    }

    const enum osw_plat_qsdk11_4_async_result result = osw_plat_qsdk11_4_async_poll(data->job_get_desmode, waker);
    switch (result)
    {
        case OSW_PLAT_QSDK11_4_ASYNC_PENDING:
            return OSW_PLAT_QSDK11_4_ASYNC_PENDING;
        case OSW_PLAT_QSDK11_4_ASYNC_READY:
            break;
    }

    struct nl_msg *msg = data->resp_get_desmode.first;
    if (msg == NULL)
    {
        return OSW_PLAT_QSDK11_4_ASYNC_READY;
    }

    /* The des_width will essentially hold the "maximum
     * channel width that is possible on the radio". Running
     * exttool/csa to a wider channel than that will
     * silently fail and do nothing. That's why this needs
     * to be caught and the driver told to re-program the
     * mode instead.
     *
     * Downfall of this is this will bring all vifs down
     * interrupting service and possibly restarting DFS in
     * non pre-CAC allowed regdomains.
     */

    const uint32_t *ptr = osw_plat_qsdk11_4_param_get_u32(msg);
    const uint32_t value = ptr ? *ptr : 0;
    const enum osw_channel_width des_width = osw_plat_qsdk_wifi_desmode_to_width(value);
    const bool is_80p80_mismatch =
            ((des_width == OSW_CHANNEL_80P80MHZ) && (data->target_width != OSW_CHANNEL_80P80MHZ))
            || ((des_width != OSW_CHANNEL_80P80MHZ) && (data->target_width == OSW_CHANNEL_80P80MHZ));
    const bool is_lower_than_necessary = (des_width < data->target_width);
    const bool need_upgrade = (is_80p80_mismatch || is_lower_than_necessary);
    const bool no_need_for_mode_change = (need_upgrade == false);
    if (no_need_for_mode_change)
    {
        return OSW_PLAT_QSDK11_4_ASYNC_READY;
    }

    if (data->job_set_mode == NULL)
    {
        const int family_id = nl_80211_get_family_id(data->nl);
        struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_mode(family_id, data->ifindex, data->new_mode);
        const char *name = strfmta(LOG_PREFIX_VIF(data->phy_name, data->vif_name, "mode upgrade: set"));
        data->job_set_mode = osw_plat_qsdk_nlcmd_alloc(name, data->nl, msg);
        LOGI(LOG_PREFIX_VIF(
                data->phy_name,
                data->vif_name,
                "mode upgrade: changing desmode %" PRIu32 " to %s to change width %sMHz -> %sMHz because%s%s",
                value,
                data->new_mode,
                osw_channel_width_to_str(des_width),
                osw_channel_width_to_str(data->target_width),
                is_80p80_mismatch ? " 80+80 mismatch" : "",
                is_lower_than_necessary ? " desmode is lower than target width" : ""));
    }

    return osw_plat_qsdk11_4_async_poll(data->job_set_mode, waker);
}

static void osw_plat_qsdk_mode_upgrade_drop_cb(void *priv)
{
    struct osw_plat_qsdk_mode_upgrade *data = priv;
    osw_plat_qsdk11_4_async_drop_safe(&data->job_get_desmode);
    osw_plat_qsdk11_4_async_drop_safe(&data->job_set_mode);
    FREE(data->new_mode);
    FREE(data->vif_name);
    FREE(data->phy_name);
    FREE(data);
}

static struct osw_plat_qsdk11_4_async *osw_plat_qsdk_mode_upgrade(
        struct nl_80211 *nl,
        const char *phy_name,
        const char *vif_name,
        const char *new_mode,
        enum osw_channel_width width,
        uint32_t ifindex)
{
    struct osw_plat_qsdk_mode_upgrade *data = CALLOC(1, sizeof(*data));
    static const struct osw_plat_qsdk11_4_async_ops ops = {
        .poll_fn = osw_plat_qsdk_mode_upgrade_poll_cb,
        .drop_fn = osw_plat_qsdk_mode_upgrade_drop_cb,
    };
    data->nl = nl;
    data->target_width = width;
    data->ifindex = ifindex;
    data->phy_name = STRDUP(phy_name);
    data->vif_name = STRDUP(vif_name);
    data->new_mode = STRDUP(new_mode);
    return osw_plat_qsdk11_4_async_impl(&ops, data);
}
