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
#include <log.h>

/* osw */
#include <osw_etc.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_nl_cmd.h"
#include "osw_drv_spf13_nl_vnd.h"
#include "osw_drv_spf13_nl_80211.h"
#include "osw_drv_spf13_request_stats.h"

enum osw_drv_spf13_request_stats_nl_cmd
{
    OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_VND_FLUSH_PEER_RATE_STATS,
    OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_VND_DBGREQ_GET_SURVEY,
    OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_DUMP_SCAN,

    /* keep last */
    OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_MAX,
};

struct osw_drv_spf13_request_stats
{
    ds_tree_node_t node_pool;
    osw_drv_spf13_request_stats_pool_t *pool;
    char *phy_name;
    unsigned int stats_mask;
    osw_drv_spf13_nl_cmd_t *nl_cmds[OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_MAX];
};
typedef struct osw_drv_spf13_request_stats osw_drv_spf13_request_stats_t;

struct osw_drv_spf13_request_stats_pool
{
    ds_tree_t requests;
    uint32_t nl80211_family_id;
    struct osw_drv *drv;
};

static void osw_drv_spf13_request_stats_drop(osw_drv_spf13_request_stats_t *req)
{
    if (req == NULL) return;
    if (WARN_ON(req->pool == NULL)) return;

    ds_tree_remove(&req->pool->requests, req);
    req->pool = NULL;
    FREE(req->phy_name);
    osw_drv_spf13_nl_cmd_drop_array(req->nl_cmds, OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_MAX);
    FREE(req);
}

static void osw_drv_spf13_request_stats_report_surveys(osw_drv_spf13_request_stats_t *req)
{
    const char *phy_name = req->phy_name;
    struct osw_drv *drv = req->pool->drv;
    struct osw_tlv surveys = {0};
    struct nl_msg **survey_msgs =
            osw_drv_spf13_nl_cmd_get_resps(req->nl_cmds[OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_VND_DBGREQ_GET_SURVEY]);
    osw_drv_spf13_nl_vnd_fill_survey_stats(survey_msgs, phy_name, &surveys);
    osw_drv_report_stats(drv, &surveys);
    osw_tlv_fini(&surveys);
}

static void osw_drv_spf13_request_stats_report_neighbors(osw_drv_spf13_request_stats_t *req)
{
    const char *phy_name = req->phy_name;
    struct osw_drv *drv = req->pool->drv;
    struct nl_msg **scan_msgs =
            osw_drv_spf13_nl_cmd_get_resps(req->nl_cmds[OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_DUMP_SCAN]);
    if (scan_msgs == NULL) return;

    const uint32_t *freqs = osw_drv_spf13_netdev_phy_get_freq_list(phy_name);

    for (struct nl_msg **iter = scan_msgs; *iter != NULL; iter++)
    {
        struct nl_msg *msg = *iter;
        uint32_t freq = 0;
        struct osw_tlv t = {0};
        osw_drv_spf13_nl_80211_fill_bss_stats(msg, phy_name, &freq, &t);
        bool found = false;
        for (size_t i = 0; freqs[i] != 0; i++)
        {
            if (freqs[i] == freq)
            {
                found = true;
                break;
            }
        }
        if (found)
        {
            osw_drv_report_stats(drv, &t);
        }
        osw_tlv_fini(&t);
    }

    FREE(freqs);
}

static void osw_drv_spf13_request_stats_poll(void *priv)
{
    osw_drv_spf13_request_stats_t *req = priv;
    if (req == NULL) return;
    if (req->pool == NULL) return;

    if (osw_drv_spf13_nl_cmd_is_done_array(req->nl_cmds, OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_MAX) == false)
    {
        return;
    }

    // The peer rate stats are delivered over vendor events. They are consumed elsewhere.

    osw_drv_spf13_request_stats_report_surveys(req);
    osw_drv_spf13_request_stats_report_neighbors(req);
    osw_drv_spf13_request_stats_drop(req);
}

static osw_drv_spf13_request_stats_t *osw_drv_spf13_request_stats_new(
        osw_drv_spf13_request_stats_pool_t *pool,
        const char *phy_name)
{
    const uint32_t ifindex = osw_drv_spf13_netdev_get_ifindex(phy_name);
    const uint32_t family_id = pool->nl80211_family_id;

    osw_drv_spf13_request_stats_t *req = CALLOC(1, sizeof(*req));
    req->pool = pool;
    req->phy_name = STRDUP(phy_name);
    ds_tree_insert(&pool->requests, req, req->phy_name);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_VND_FLUSH_PEER_RATE_STATS] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_radio_param_flush_peer_rate_stats_set(family_id, ifindex, 1),
            strfmta("%s: flush_peer_rate_stats(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_stats_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_VND_DBGREQ_GET_SURVEY] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_radio_get_survey(family_id, ifindex),
            strfmta("%s: dbgreq_get_survey(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_stats_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_STATS_NL_CMD_DUMP_SCAN] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_80211_msg_dump_scan(family_id, ifindex),
            strfmta("%s: dump_scan(%" PRIu32 ")", phy_name, ifindex),
            osw_drv_spf13_request_stats_poll,
            req);

    return req;
}

osw_drv_spf13_request_stats_pool_t *osw_drv_spf13_request_stats_pool_new(
        struct osw_drv *drv,
        uint32_t nl80211_family_id)
{
    osw_drv_spf13_request_stats_pool_t *pool = CALLOC(1, sizeof(*pool));
    ds_tree_init(&pool->requests, ds_str_cmp, osw_drv_spf13_request_stats_t, node_pool);
    pool->nl80211_family_id = nl80211_family_id;
    pool->drv = drv;
    return pool;
}

static void osw_drv_spf13_request_stats_pool_flush(osw_drv_spf13_request_stats_pool_t *pool)
{
    osw_drv_spf13_request_stats_t *req;
    while ((req = ds_tree_head(&pool->requests)) != NULL)
    {
        osw_drv_spf13_request_stats_drop(req);
    }
}

void osw_drv_spf13_request_stats_pool_drop(osw_drv_spf13_request_stats_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_stats_pool_flush(pool);
    FREE(pool);
}

void osw_drv_spf13_request_stats(osw_drv_spf13_request_stats_pool_t *pool, unsigned int stats_mask)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_stats_pool_flush(pool);

    char **phy_list = osw_drv_spf13_netdev_get_list_of_str(osw_drv_spf13_netdev_is_qca_radio);
    for (char **phy_iter = phy_list; *phy_iter != NULL; phy_iter++)
    {
        const char *phy_name = *phy_iter;

        osw_drv_spf13_request_stats_t *req = osw_drv_spf13_request_stats_new(pool, phy_name);
        if (req == NULL)
        {
            LOGW(LOG_PREFIX("failed to create request stats for %s"), phy_name);
            continue;
        }

        osw_drv_spf13_request_stats_poll(req);
    }
    osw_drv_spf13_netdev_free_list_of_str(phy_list);
}
