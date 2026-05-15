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

/* opensync */
#include <ds_tree.h>
#include <os_nif.h>
#include <os_time.h>

/* osw */
#include <osw_drv.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_nl_cmd.h"
#include "osw_drv_spf13_nl_vnd.h"
#include "osw_drv_spf13_nl_80211.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_types.h"
#include "util.h"
#include "osw_drv_spf13_request_phy_state.h"

#define OSW_DRV_SPF13_REQUEST_PHY_STATE_TIMEOUT_SEC 10

struct osw_drv_spf13_request_phy_state_pool
{
    ds_tree_t requests;
    struct osw_drv *drv;
    uint32_t nl80211_family_id;
};

enum osw_drv_spf13_request_phy_state_nl_cmd
{
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_GET_WIPHY,
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_TX_CHAINMASK,
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_RX_CHAINMASK,
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_CHANINFO,
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_COUNTRY,
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_COUNTRY_ID,
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_REG_DOMAIN,
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_NEXT_RADAR_FREQ,
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_NEXT_RADAR_WIDTH,

    /* keep last */
    OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_MAX
};

struct osw_drv_spf13_request_phy_state
{
    ds_tree_node_t node;
    osw_drv_spf13_request_phy_state_pool_t *pool;
    char *phy_name;
    uint32_t wiphy_idx;
    uint32_t netdev_ifindex;
    osw_drv_spf13_nl_cmd_t *nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_MAX];
    ev_timer timeout;
    int64_t started_on;
};

typedef struct osw_drv_spf13_request_phy_state osw_drv_spf13_request_phy_state_t;

static void osw_drv_spf13_request_phy_state_drop(struct osw_drv_spf13_request_phy_state *req)
{
    if (req == NULL) return;

    ev_timer_stop(EV_DEFAULT, &req->timeout);
    osw_drv_spf13_nl_cmd_drop_array(req->nl_cmds, OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_MAX);
    ds_tree_remove(&req->pool->requests, req);
    FREE(req->phy_name);
    FREE(req);
}

static void osw_drv_spf13_phy_fill_chainmask(
        struct osw_drv_phy_state *phy_state,
        osw_drv_spf13_nl_cmd_t *vnd_get_rx_chainmask,
        osw_drv_spf13_nl_cmd_t *vnd_get_tx_chainmask)
{
    if (phy_state == NULL) return;

    struct nl_msg *msg_rx_chainmask = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_rx_chainmask);
    struct nl_msg *msg_tx_chainmask = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_tx_chainmask);
    const uint32_t *rx_chainmask = osw_drv_spf13_nl_vnd_u32_from_msg(msg_rx_chainmask);
    const uint32_t *tx_chainmask = osw_drv_spf13_nl_vnd_u32_from_msg(msg_tx_chainmask);
    if (rx_chainmask == NULL) return;
    if (tx_chainmask == NULL) return;
    if (*rx_chainmask != *tx_chainmask) return;
    phy_state->tx_chainmask = *tx_chainmask;
}

static void osw_drv_spf13_phy_fill_chan_states(
        struct osw_drv_phy_state *phy_state,
        osw_drv_spf13_nl_cmd_t *vnd_get_chaninfo)
{
    struct nl_msg *msg = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_chaninfo);
    if (msg == NULL) return;

    phy_state->channel_states = osw_drv_spf13_nl_vnd_chaninfo_parse(msg, &phy_state->n_channel_states);
}

static void osw_drv_spf13_phy_fill_reg_domain(
        struct osw_drv_phy_state *phy_state,
        osw_drv_spf13_nl_cmd_t *vnd_get_country,
        osw_drv_spf13_nl_cmd_t *vnd_get_country_id,
        osw_drv_spf13_nl_cmd_t *vnd_get_reg_domain)
{
    if (phy_state == NULL) return;

    struct nl_msg *msg_country = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_country);
    struct nl_msg *msg_country_id = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_country_id);
    struct nl_msg *msg_reg_domain = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_reg_domain);
    const uint32_t *country_id = osw_drv_spf13_nl_vnd_u32_from_msg(msg_country_id);
    const uint32_t *reg_domain = osw_drv_spf13_nl_vnd_u32_from_msg(msg_reg_domain);

    if (country_id != NULL)
    {
        phy_state->reg_domain.iso3166_num = *country_id;
    }

    if (reg_domain != NULL)
    {
        phy_state->reg_domain.revision = *reg_domain;
    }

    osw_drv_spf13_nl_vnd_radio_country_parse(
            msg_country,
            phy_state->reg_domain.ccode,
            sizeof(phy_state->reg_domain.ccode));
}

static void osw_drv_spf13_phy_fill_next_radar_freq(
        struct osw_drv_phy_state *phy_state,
        osw_drv_spf13_nl_cmd_t *vnd_get_next_radar_freq,
        osw_drv_spf13_nl_cmd_t *vnd_get_next_radar_width)
{
    if (phy_state == NULL) return;

    struct nl_msg *msg_next_radar_freq = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_next_radar_freq);
    struct nl_msg *msg_next_radar_width = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_next_radar_width);
    const uint32_t *next_radar_freq = osw_drv_spf13_nl_vnd_u32_from_msg(msg_next_radar_freq);
    const uint32_t *next_radar_width = osw_drv_spf13_nl_vnd_u32_from_msg(msg_next_radar_width);

    if (next_radar_freq != NULL)
    {
        const int freq = *next_radar_freq;
        phy_state->radar_next_channel.control_freq_mhz = freq;
        phy_state->radar_next_channel.center_freq0_mhz = freq;

        if (next_radar_width != NULL)
        {
            const int width_mhz = *next_radar_width;
            const int chan = osw_freq_to_chan(freq);
            const int *chanlist = unii_5g_chan2list(chan, width_mhz);
            const int center = osw_chan_avg(chanlist);
            const enum osw_band band = osw_freq_to_band(freq);
            const int center_freq = osw_chan_to_freq(band, center);
            const enum osw_channel_width width = osw_channel_width_mhz_to_width(width_mhz);
            phy_state->radar_next_channel.center_freq0_mhz = center_freq;
            phy_state->radar_next_channel.width = width;
        }
    }
}

static void osw_drv_spf13_request_phy_state_complete(struct osw_drv_spf13_request_phy_state *req)
{
    if (req == NULL) return;

    struct osw_drv *drv = req->pool->drv;
    const char *phy_name = req->phy_name;

    bool is_up = false;
    os_nif_is_up(phy_name, &is_up);

    const bool phy_exists = osw_drv_spf13_netdev_is_qca_radio(phy_name);
    struct osw_drv_phy_state phy_state = {
        .exists = phy_exists,
        .enabled = is_up,
        .rsno_supported = true,
    };

    osw_drv_spf13_nl_cmd_t *get_wiphy = req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_GET_WIPHY];
    osw_drv_spf13_nl_cmd_t *vnd_get_rx_chainmask =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_RX_CHAINMASK];
    osw_drv_spf13_nl_cmd_t *vnd_get_tx_chainmask =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_TX_CHAINMASK];
    osw_drv_spf13_nl_cmd_t *vnd_get_chaninfo = req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_CHANINFO];
    osw_drv_spf13_nl_cmd_t *vnd_get_country = req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_COUNTRY];
    osw_drv_spf13_nl_cmd_t *vnd_get_country_id =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_COUNTRY_ID];
    osw_drv_spf13_nl_cmd_t *vnd_get_reg_domain =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_REG_DOMAIN];
    osw_drv_spf13_nl_cmd_t *vnd_get_next_radar_freq =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_NEXT_RADAR_FREQ];
    osw_drv_spf13_nl_cmd_t *vnd_get_next_radar_width =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_NEXT_RADAR_WIDTH];

    struct nl_msg **msgs_wiphy = osw_drv_spf13_nl_cmd_get_resps(get_wiphy);

    const char *mac_addr_str = file_geta(strfmta("/sys/class/net/%s/address", phy_name));
    osw_hwaddr_from_cstr(mac_addr_str, &phy_state.mac_addr);

    osw_drv_spf13_nl_80211_fill_wiphy(&phy_state, req->wiphy_idx, msgs_wiphy);
    osw_drv_spf13_phy_fill_next_radar_freq(&phy_state, vnd_get_next_radar_freq, vnd_get_next_radar_width);
    osw_drv_spf13_phy_fill_reg_domain(&phy_state, vnd_get_country, vnd_get_country_id, vnd_get_reg_domain);
    osw_drv_spf13_phy_fill_chan_states(&phy_state, vnd_get_chaninfo);
    osw_drv_spf13_phy_fill_chainmask(&phy_state, vnd_get_rx_chainmask, vnd_get_tx_chainmask);
    osw_drv_report_phy_state(drv, phy_name, &phy_state);

    const int64_t elapsed = clock_mono_ms() - req->started_on;
    LOGI(LOG_PREFIX_PHY(phy_name, "phy state request completed in %" PRId64 " ms"), elapsed);

    osw_drv_phy_state_report_free(&phy_state);
    osw_drv_spf13_request_phy_state_drop(req);
}

static bool osw_drv_spf13_request_phy_state_is_ready(osw_drv_spf13_request_phy_state_t *req)
{
    if (req == NULL) return true;
    return true && osw_drv_spf13_nl_cmd_is_done_array(req->nl_cmds, OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_MAX);
}

static void osw_drv_spf13_request_phy_state_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_request_phy_state_t *req = w->data;
    if (req == NULL) return;

    LOGI(LOG_PREFIX_PHY(req->phy_name, "phy state request timed out"));
    osw_drv_spf13_request_phy_state_complete(req);
}

static void osw_drv_spf13_request_phy_state_poll(void *priv)
{
    struct osw_drv_spf13_request_phy_state *req = priv;
    if (req == NULL) return;
    if (osw_drv_spf13_request_phy_state_is_ready(req) == false) return;
    osw_drv_spf13_request_phy_state_complete(req);
}

static osw_drv_spf13_request_phy_state_t *osw_drv_spf13_request_phy_state_new(
        osw_drv_spf13_request_phy_state_pool_t *pool,
        const char *phy_name)
{
    if (pool == NULL || phy_name == NULL) return NULL;

    osw_drv_spf13_request_phy_state_t *req = CALLOC(1, sizeof(*req));
    ev_timer_init(
            &req->timeout,
            osw_drv_spf13_request_phy_state_timeout_cb,
            OSW_DRV_SPF13_REQUEST_PHY_STATE_TIMEOUT_SEC,
            0);
    req->timeout.data = req;
    req->pool = pool;
    req->phy_name = STRDUP(phy_name);
    req->started_on = clock_mono_ms();
    req->netdev_ifindex = osw_drv_spf13_netdev_get_ifindex(phy_name);
    req->wiphy_idx = atoi(file_geta(strfmta("/sys/class/net/%s/phy80211/index", phy_name)) ?: "-1");

    const uint32_t ifindex = req->netdev_ifindex;
    const uint32_t wiphy = req->wiphy_idx;
    const uint32_t family_id = pool->nl80211_family_id;

    LOGD(LOG_PREFIX_PHY(phy_name, "requesting phy state for %s(%" PRIu32 ":%" PRIu32 ")"), phy_name, ifindex, wiphy);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_GET_WIPHY] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_80211_msg_get_wiphy(family_id, wiphy),
            strfmta("%s: get_wiphy(%" PRIu32 ")", phy_name, wiphy),
            osw_drv_spf13_request_phy_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_RX_CHAINMASK] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_radio_param_rx_chainmask_get(family_id, ifindex),
            strfmta("%s: get_rxchainmask(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_phy_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_TX_CHAINMASK] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_radio_param_tx_chainmask_get(family_id, ifindex),
            strfmta("%s: get_txchainmask(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_phy_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_CHANINFO] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_chaninfo_get(family_id, ifindex),
            strfmta("%s: get_chaninfo(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_phy_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_COUNTRY] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_radio_country_get(family_id, ifindex),
            strfmta("%s: get_country(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_phy_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_COUNTRY_ID] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_radio_param_country_id_get(family_id, ifindex),
            strfmta("%s: get_country_id(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_phy_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_REG_DOMAIN] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_radio_param_reg_domain_get(family_id, ifindex),
            strfmta("%s: get_reg_domain(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_phy_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_NEXT_RADAR_FREQ] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_radio_param_next_radar_freq_get(family_id, ifindex),
            strfmta("%s: get_next_radar_freq(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_phy_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_PHY_STATE_NL_CMD_VND_GET_NEXT_RADAR_WIDTH] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_radio_param_next_radar_width_get(family_id, ifindex),
            strfmta("%s: get_next_radar_width(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_phy_state_poll,
            req);

    ds_tree_insert(&pool->requests, req, req->phy_name);

    ev_timer_start(EV_DEFAULT, &req->timeout);
    return req;
}

static void osw_drv_spf13_request_phy_state_report_empty(struct osw_drv *drv, const char *phy_name)
{
    if (drv == NULL || phy_name == NULL) return;

    LOGI(LOG_PREFIX_PHY(phy_name, "reporting empty phy state"));
    struct osw_drv_phy_state phy_state = {
        .exists = false,
    };
    osw_drv_report_phy_state(drv, phy_name, &phy_state);
}

static void osw_drv_spf13_request_phy_state_pool_flush(osw_drv_spf13_request_phy_state_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_phy_state_t *req;
    while ((req = ds_tree_head(&pool->requests)) != NULL)
    {
        osw_drv_spf13_request_phy_state_report_empty(pool->drv, req->phy_name);
        osw_drv_spf13_request_phy_state_drop(req);
    }
}

osw_drv_spf13_request_phy_state_pool_t *osw_drv_spf13_request_phy_state_pool_new(
        struct osw_drv *drv,
        uint32_t nl80211_family_id)
{
    if (drv == NULL) return NULL;

    osw_drv_spf13_request_phy_state_pool_t *pool = CALLOC(1, sizeof(*pool));
    pool->nl80211_family_id = nl80211_family_id;
    pool->drv = drv;
    ds_tree_init(&pool->requests, ds_str_cmp, osw_drv_spf13_request_phy_state_t, node);
    return pool;
}

void osw_drv_spf13_request_phy_state_pool_drop(osw_drv_spf13_request_phy_state_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_phy_state_pool_flush(pool);
    FREE(pool);
}

void osw_drv_spf13_request_phy_state(osw_drv_spf13_request_phy_state_pool_t *pool, const char *phy_name)
{
    if (pool == NULL || phy_name == NULL) return;

    osw_drv_spf13_request_phy_state_t *req = ds_tree_find(&pool->requests, phy_name);
    const bool already_exists = (req != NULL);
    if (already_exists)
    {
        LOGI(LOG_PREFIX_PHY(phy_name, "cancelling existing phy state request"));
        osw_drv_spf13_request_phy_state_drop(req);
        req = NULL;
    }

    req = osw_drv_spf13_request_phy_state_new(pool, phy_name);
    if (req == NULL)
    {
        LOGE(LOG_PREFIX_PHY(phy_name, "failed to create phy state request"));
        osw_drv_spf13_request_phy_state_report_empty(pool->drv, phy_name);
        return;
    }

    osw_drv_spf13_request_phy_state_poll(req);
}
