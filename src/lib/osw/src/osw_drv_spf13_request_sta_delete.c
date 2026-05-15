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
#include <memutil.h>
#include <util.h>
#include <log.h>

/* osw */
#include <osw_types.h>

/* local */
#include "osw_drv_spf13_invalidations.h"
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_nl_cmd.h"
#include "osw_drv_spf13_nl_vnd.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_request_sta_delete.h"

struct osw_drv_spf13_request_sta_delete_id
{
    char *phy_name;
    char *vif_name;
    struct osw_hwaddr mac_addr;
    osw_drv_spf13_nl_vnd_vap_kickmac_action_t action;
};
typedef struct osw_drv_spf13_request_sta_delete_id osw_drv_spf13_request_sta_delete_id_t;

struct osw_drv_spf13_request_sta_delete
{
    ds_tree_node_t node_pool;
    osw_drv_spf13_request_sta_delete_id_t id;
    osw_drv_spf13_request_sta_delete_pool_t *pool;
    osw_drv_spf13_nl_cmd_t *vnd_kickmac_cmd;
};
typedef struct osw_drv_spf13_request_sta_delete osw_drv_spf13_request_sta_delete_t;

struct osw_drv_spf13_request_sta_delete_pool
{
    ds_tree_t requests; /**< osw_drv_spf13_request_sta_delete_id_t -> osw_drv_spf13_request_sta_delete_t */
    uint32_t nl80211_family_id;
    osw_drv_spf13_invalidations_t *invalidations;
};

static int osw_drv_spf13_request_sta_delete_id_cmp(
        const osw_drv_spf13_request_sta_delete_id_t *a,
        const osw_drv_spf13_request_sta_delete_id_t *b)
{
    if (a == NULL && b == NULL) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;

    const int phy_cmp = strcmp(a->phy_name, b->phy_name);
    const int vif_cmp = strcmp(a->vif_name, b->vif_name);
    const int mac_cmp = osw_hwaddr_cmp(&a->mac_addr, &b->mac_addr);
    const int action_cmp = (int)a->action - (int)b->action;

    if (phy_cmp != 0) return phy_cmp;
    if (vif_cmp != 0) return vif_cmp;
    if (mac_cmp != 0) return mac_cmp;
    if (action_cmp != 0) return action_cmp;

    return 0;
}

static void osw_drv_spf13_request_sta_delete_drop(osw_drv_spf13_request_sta_delete_t *request)
{
    if (request == NULL) return;

    ds_tree_remove(&request->pool->requests, request);
    osw_drv_spf13_nl_cmd_drop(request->vnd_kickmac_cmd);
    FREE(request->id.phy_name);
    FREE(request->id.vif_name);
    FREE(request);
}

static void osw_drv_spf13_request_sta_delete_poll(void *priv)
{
    osw_drv_spf13_request_sta_delete_t *request = priv;
    if (request == NULL) return;

    if (osw_drv_spf13_nl_cmd_is_done(request->vnd_kickmac_cmd) == false)
    {
        return;
    }

    const int err = osw_drv_spf13_nl_cmd_get_error(request->vnd_kickmac_cmd);
    if (err != 0)
    {
        LOGI(LOG_PREFIX_STA(
                request->id.phy_name,
                request->id.vif_name,
                &request->id.mac_addr,
                "failed to kick mac: %d",
                err));
    }

    osw_drv_spf13_invalidations_sta(
            request->pool->invalidations,
            request->id.phy_name,
            request->id.vif_name,
            &request->id.mac_addr);

    osw_drv_spf13_request_sta_delete_drop(request);
}

static osw_drv_spf13_request_sta_delete_t *osw_drv_spf13_request_sta_delete_new(
        osw_drv_spf13_request_sta_delete_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr,
        osw_drv_spf13_nl_vnd_vap_kickmac_action_t action)
{
    if (phy_name == NULL) return NULL;
    if (vif_name == NULL) return NULL;
    if (mac_addr == NULL || osw_hwaddr_is_zero(mac_addr)) return NULL;

    const char *netdev_name = strdupafree(osw_drv_spf13_netdev_from_phy_and_vif(phy_name, vif_name));
    if (netdev_name == NULL)
    {
        LOGE(LOG_PREFIX("failed to get netdev name for vif %s on phy %s", vif_name, phy_name));
        return NULL;
    }

    const uint32_t ifindex = osw_drv_spf13_netdev_get_ifindex(netdev_name);
    const uint8_t mlo_link_id =
            osw_drv_spf13_netdev_is_qca_vap_legacy(netdev_name) ? -1 : osw_drv_spf13_netdev_get_hw_link_id(phy_name);

    const osw_drv_spf13_request_sta_delete_id_t id = {
        .phy_name = STRDUP(phy_name),
        .vif_name = STRDUP(vif_name),
        .mac_addr = *mac_addr,
        .action = action,
    };

    osw_drv_spf13_request_sta_delete_t *request = CALLOC(1, sizeof(*request));
    request->id = id;
    request->pool = pool;
    ds_tree_insert(&pool->requests, request, &request->id);

    request->vnd_kickmac_cmd = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_kickmac(pool->nl80211_family_id, ifindex, mlo_link_id, mac_addr, action),
            strfmta("%s: vnd_kickmac(%" PRIu32 ":%" PRIi8 ", tx=%d)", netdev_name, ifindex, mlo_link_id, action),
            osw_drv_spf13_request_sta_delete_poll,
            request);

    return request;
}

osw_drv_spf13_request_sta_delete_pool_t *osw_drv_spf13_request_sta_delete_pool_new(
        osw_drv_spf13_invalidations_t *invalidations,
        uint32_t nl80211_family_id)
{
    osw_drv_spf13_request_sta_delete_pool_t *pool = CALLOC(1, sizeof(*pool));
    ds_tree_init(
            &pool->requests,
            (ds_key_cmp_t *)osw_drv_spf13_request_sta_delete_id_cmp,
            osw_drv_spf13_request_sta_delete_t,
            node_pool);
    pool->nl80211_family_id = nl80211_family_id;
    pool->invalidations = invalidations;
    return pool;
}

static void osw_drv_spf13_request_sta_delete_pool_flush(osw_drv_spf13_request_sta_delete_pool_t *pool)
{
    osw_drv_spf13_request_sta_delete_t *request = NULL;
    while ((request = ds_tree_head(&pool->requests)) != NULL)
    {
        osw_drv_spf13_request_sta_delete_drop(request);
    }
}

void osw_drv_spf13_request_sta_delete_pool_drop(osw_drv_spf13_request_sta_delete_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_sta_delete_pool_flush(pool);
    FREE(pool);
}

void osw_drv_spf13_request_sta_delete(
        osw_drv_spf13_request_sta_delete_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr)
{
    if (pool == NULL) return;

    const osw_drv_spf13_request_sta_delete_id_t id = {
        .phy_name = (char *)phy_name,
        .vif_name = (char *)vif_name,
        .mac_addr = *mac_addr,
        .action = OSW_DRV_SPF13_NL_VND_VAP_KICKMAC_ACTION_NO_TX,
    };
    osw_drv_spf13_request_sta_delete_t *request = ds_tree_find(&pool->requests, &id);
    if (request != NULL)
    {
        LOGI(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "already kicking mac, aborting previous request"));
        osw_drv_spf13_request_sta_delete_drop(request);
        request = NULL;
    }

    request = osw_drv_spf13_request_sta_delete_new(pool, phy_name, vif_name, mac_addr, id.action);
    if (request == NULL)
    {
        LOGI(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "failed to kick mac"));
        return;
    }

    osw_drv_spf13_request_sta_delete_poll(request);
}

void osw_drv_spf13_request_sta_deauth(
        osw_drv_spf13_request_sta_delete_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr)
{
    if (pool == NULL) return;

    const osw_drv_spf13_request_sta_delete_id_t id = {
        .phy_name = (char *)phy_name,
        .vif_name = (char *)vif_name,
        .mac_addr = *mac_addr,
        .action = OSW_DRV_SPF13_NL_VND_VAP_KICKMAC_ACTION_WITH_TX,
    };
    osw_drv_spf13_request_sta_delete_t *request = ds_tree_find(&pool->requests, &id);
    if (request != NULL)
    {
        LOGI(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "already kicking mac, aborting previous request"));
        osw_drv_spf13_request_sta_delete_drop(request);
        request = NULL;
    }

    request = osw_drv_spf13_request_sta_delete_new(pool, phy_name, vif_name, mac_addr, id.action);
    if (request == NULL)
    {
        LOGI(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "failed to kick mac"));
        return;
    }

    osw_drv_spf13_request_sta_delete_poll(request);
}
