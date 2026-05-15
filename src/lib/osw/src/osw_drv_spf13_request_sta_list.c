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
#include <log.h>
#include <util.h>

/* osw */
#include <osw_types.h>
#include <osw_drv.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_nl_cmd.h"
#include "osw_drv_spf13_nl_vnd.h"
#include "osw_drv_spf13_request_sta_list.h"

struct osw_drv_spf13_request_sta_list_id
{
    char *phy_name;
    char *vif_name;
};
typedef struct osw_drv_spf13_request_sta_list_id osw_drv_spf13_request_sta_list_id_t;

struct osw_drv_spf13_request_sta_list
{
    ds_tree_node_t node_pool;
    osw_drv_spf13_request_sta_list_id_t id;
    osw_drv_spf13_request_sta_list_pool_t *pool;
    osw_drv_spf13_nl_cmd_t *vnd_list_sta_cmd;
};
typedef struct osw_drv_spf13_request_sta_list osw_drv_spf13_request_sta_list_t;

struct osw_drv_spf13_request_sta_list_pool
{
    ds_tree_t requests; /**< osw_drv_spf13_request_sta_list_id_t -> osw_drv_spf13_request_sta_list_t */
    uint32_t nl80211_family_id;
    struct osw_drv *drv;
};

static int osw_drv_spf13_request_sta_list_id_cmp(
        const osw_drv_spf13_request_sta_list_id_t *a,
        const osw_drv_spf13_request_sta_list_id_t *b)
{
    if (a == NULL && b == NULL) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;

    const int phy_cmp = strcmp(a->phy_name, b->phy_name);
    const int vif_cmp = strcmp(a->vif_name, b->vif_name);

    if (phy_cmp != 0) return phy_cmp;
    if (vif_cmp != 0) return vif_cmp;

    return 0;
}

static void osw_drv_spf13_request_sta_list_drop(osw_drv_spf13_request_sta_list_t *request)
{
    if (request == NULL) return;

    ds_tree_remove(&request->pool->requests, request);
    FREE(request->id.phy_name);
    FREE(request->id.vif_name);
    FREE(request);
}

static void osw_drv_spf13_request_sta_list_build_list(
        osw_drv_spf13_request_sta_list_t *request,
        struct osw_hwaddr_list *sta_list)
{
    if (request == NULL) return;
    if (sta_list == NULL) return;

    osw_hwaddr_list_flush(sta_list);

    struct nl_msg **msg = osw_drv_spf13_nl_cmd_get_resps(request->vnd_list_sta_cmd);
    for (; msg != NULL && *msg != NULL; msg++)
    {
        size_t remaining = 0;
        const osw_drv_spf13_nl_vnd_sta_info_t *info = osw_drv_spf13_nl_vnd_sta_info_get_first(*msg, &remaining);
        while (info != NULL)
        {
            const struct osw_hwaddr *sta_addr = osw_drv_spf13_nl_vnd_sta_info_get_addr(info);
            if (sta_addr != NULL)
            {
                const bool exists = osw_hwaddr_list_contains(sta_list->list, sta_list->count, sta_addr);
                if (exists == false)
                {
                    osw_hwaddr_list_append(sta_list, sta_addr);
                }
            }
            info = osw_drv_spf13_nl_vnd_sta_info_get_next(info, &remaining);
        }
    }
}

static void osw_drv_spf13_request_sta_list_poll(void *priv)
{
    osw_drv_spf13_request_sta_list_t *request = priv;

    if (osw_drv_spf13_nl_cmd_is_done(request->vnd_list_sta_cmd) == false)
    {
        return;
    }

    struct osw_hwaddr_list sta_list = {0};
    osw_drv_spf13_request_sta_list_build_list(request, &sta_list);
    osw_drv_report_sta_enumeration(request->pool->drv, request->id.phy_name, request->id.vif_name, &sta_list);

    /* self-free */
    osw_drv_spf13_request_sta_list_drop(request);
}

static osw_drv_spf13_request_sta_list_t *osw_drv_spf13_request_sta_list_new(
        osw_drv_spf13_request_sta_list_pool_t *pool,
        const char *phy_name,
        const char *vif_name)
{
    if (pool == NULL) return NULL;
    if (phy_name == NULL) return NULL;
    if (vif_name == NULL) return NULL;

    const char *netdev_name = strdupafree(osw_drv_spf13_netdev_from_phy_and_vif(phy_name, vif_name));
    if (netdev_name == NULL)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to get netdev name for vif"));
        return NULL;
    }
    const uint32_t family_id = pool->nl80211_family_id;
    const unsigned int ifindex = osw_drv_spf13_netdev_get_ifindex(netdev_name);
    const int8_t mlo_link_id =
            osw_drv_spf13_netdev_is_qca_vap_legacy(netdev_name) ? -1 : osw_drv_spf13_netdev_get_hw_link_id(phy_name);

    osw_drv_spf13_request_sta_list_t *request = CALLOC(1, sizeof(*request));
    request->pool = pool;
    request->id.phy_name = STRDUP(phy_name);
    request->id.vif_name = STRDUP(vif_name);
    request->vnd_list_sta_cmd = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_list_sta(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_list_sta(%" PRIu32 ":%" PRIi8 ")", netdev_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_sta_list_poll,
            request);

    ds_tree_insert(&pool->requests, request, &request->id);
    return request;
}

void osw_drv_spf13_request_sta_list(
        osw_drv_spf13_request_sta_list_pool_t *pool,
        const char *phy_name,
        const char *vif_name)
{
    const osw_drv_spf13_request_sta_list_id_t id = {
        .phy_name = (char *)phy_name,
        .vif_name = (char *)vif_name,
    };
    osw_drv_spf13_request_sta_list_t *request = ds_tree_find(&pool->requests, &id);
    if (request != NULL)
    {
        osw_drv_spf13_request_sta_list_drop(request);
        request = NULL;
    }

    request = osw_drv_spf13_request_sta_list_new(pool, phy_name, vif_name);
    if (request == NULL)
    {
        struct osw_hwaddr_list empty = {0};
        osw_drv_report_sta_enumeration(pool->drv, phy_name, vif_name, &empty);
        return;
    }

    osw_drv_spf13_request_sta_list_poll(request);
}

osw_drv_spf13_request_sta_list_pool_t *osw_drv_spf13_request_sta_list_pool_new(
        struct osw_drv *drv,
        uint32_t nl80211_family_id)
{
    osw_drv_spf13_request_sta_list_pool_t *pool = CALLOC(1, sizeof(*pool));
    ds_tree_init(
            &pool->requests,
            (ds_key_cmp_t *)osw_drv_spf13_request_sta_list_id_cmp,
            osw_drv_spf13_request_sta_list_t,
            node_pool);
    pool->drv = drv;
    pool->nl80211_family_id = nl80211_family_id;
    return pool;
}

static void osw_drv_spf13_request_sta_list_pool_flush(osw_drv_spf13_request_sta_list_pool_t *pool)
{
    osw_drv_spf13_request_sta_list_t *request = NULL;
    while ((request = ds_tree_head(&pool->requests)) != NULL)
    {
        osw_drv_spf13_request_sta_list_drop(request);
    }
}

void osw_drv_spf13_request_sta_list_pool_drop(osw_drv_spf13_request_sta_list_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_sta_list_pool_flush(pool);
    FREE(pool);
}
