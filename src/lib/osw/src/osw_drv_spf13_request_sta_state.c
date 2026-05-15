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
#include <stdint.h>
#include <net/if.h>

/* opensync */
#include <memutil.h>
#include <log.h>
#include <util.h>

/* osw */
#include <osw_drv.h>
#include <osw_hostap.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_nl_cmd.h"
#include "osw_drv_spf13_nl_vnd.h"
#include "osw_drv_spf13_hostap_sock.h"
#include "osw_drv_spf13_hostap_path.h"
#include "osw_drv_spf13_hostap_cmd.h"
#include "osw_types.h"
#include "osw_drv_spf13_request_sta_state.h"

struct osw_drv_spf13_request_sta_state_pool
{
    ds_tree_t requests; /* osw_drv_spf13_request_sta_state_t */
    struct osw_drv *drv;
    uint32_t nl80211_family_id;
};

struct osw_drv_spf13_request_sta_state_id
{
    char *phy_name;
    char *vif_name;
    struct osw_hwaddr mac_addr;
};
typedef struct osw_drv_spf13_request_sta_state_id osw_drv_spf13_request_sta_state_id_t;

struct osw_drv_spf13_request_sta_state
{
    ds_tree_node_t node;
    osw_drv_spf13_request_sta_state_id_t id;
    osw_drv_spf13_request_sta_state_pool_t *pool;
    osw_drv_spf13_nl_cmd_t *vnd_list_sta_cmd;
    osw_drv_spf13_hostap_cmd_t *hostap_get_sta;
    char *ctrl_path_hapd;
};
typedef struct osw_drv_spf13_request_sta_state osw_drv_spf13_request_sta_state_t;

static int osw_drv_spf13_request_sta_state_id_cmp(
        const osw_drv_spf13_request_sta_state_id_t *a,
        const osw_drv_spf13_request_sta_state_id_t *b)
{
    if (a == NULL && b == NULL) return 0;
    if (a != NULL && b == NULL) return 1;
    if (a == NULL && b != NULL) return -1;

    if (a->phy_name == NULL && b->phy_name == NULL) return 0;
    if (a->phy_name != NULL && b->phy_name == NULL) return 1;
    if (a->phy_name == NULL && b->phy_name != NULL) return -1;
    const int cmp1 = strcmp(a->phy_name, b->phy_name);
    if (cmp1 != 0) return cmp1;

    if (a->vif_name == NULL && b->vif_name == NULL) return 0;
    if (a->vif_name != NULL && b->vif_name == NULL) return 1;
    if (a->vif_name == NULL && b->vif_name != NULL) return -1;
    const int cmp2 = strcmp(a->vif_name, b->vif_name);
    if (cmp2 != 0) return cmp2;

    const int cmp3 = osw_hwaddr_cmp(&a->mac_addr, &b->mac_addr);
    if (cmp3 != 0) return cmp3;

    return 0;
}

static void osw_drv_spf13_request_sta_state_drop(osw_drv_spf13_request_sta_state_t *req)
{
    if (req == NULL) return;

    osw_drv_spf13_nl_cmd_drop(req->vnd_list_sta_cmd);
    osw_drv_spf13_hostap_cmd_drop(req->hostap_get_sta);

    if (req->pool)
    {
        ds_tree_remove(&req->pool->requests, req);
        req->pool = NULL;
    }

    FREE(req->ctrl_path_hapd);
    FREE(req->id.phy_name);
    FREE(req->id.vif_name);
    FREE(req);
}

static const struct osw_hwaddr *osw_drv_spf13_request_sta_get_addr(osw_drv_spf13_request_sta_state_t *req)
{
    if (req == NULL) return NULL;

    struct nl_msg **msg = osw_drv_spf13_nl_cmd_get_resps(req->vnd_list_sta_cmd);
    for (; msg != NULL && *msg != NULL; msg++)
    {
        size_t remaining = 0;
        const osw_drv_spf13_nl_vnd_sta_info_t *info = osw_drv_spf13_nl_vnd_sta_info_get_first(*msg, &remaining);
        while (info != NULL)
        {
            const struct osw_hwaddr *sta_addr = osw_drv_spf13_nl_vnd_sta_info_get_addr(info);
            if (sta_addr != NULL)
            {
                const bool link_match = osw_hwaddr_is_equal(&req->id.mac_addr, sta_addr);
                if (link_match)
                {
                    const struct osw_hwaddr *mld_addr = osw_drv_spf13_nl_vnd_sta_info_get_mld_addr(info);
                    return mld_addr ?: sta_addr;
                }
            }
            info = osw_drv_spf13_nl_vnd_sta_info_get_next(info, &remaining);
        }
    }
    return NULL;
}

static void osw_drv_spf13_request_sta_state_report(osw_drv_spf13_request_sta_state_t *req)
{
    if (req == NULL) return;

    const char *phy_name = req->id.phy_name;
    const char *vif_name = req->id.vif_name;
    const struct osw_hwaddr *mac_addr = &req->id.mac_addr;

    LOGI(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "sta state report"));

    struct osw_drv_sta_state sta_state = {
        .connected = false,
    };

    const char *reply = osw_drv_spf13_hostap_cmd_get_reply(req->hostap_get_sta);
    if (reply != NULL)
    {
        const bool is_fail = strncmp(reply, "FAIL", 4) == 0;
        const bool is_ok = is_fail == false;
        if (is_ok)
        {
            struct osw_hostap_bss_sta hostap_sta = {0};
            osw_hostap_bss_sta_parse(reply, &hostap_sta);
            sta_state.connected = hostap_sta.authorized;
            if (hostap_sta.key_id_known)
            {
                sta_state.key_id = hostap_sta.key_id;
            }
            sta_state.akm = hostap_sta.akm;
            sta_state.pairwise_cipher = hostap_sta.pairwise_cipher;
            sta_state.pmf = hostap_sta.pmf;
        }
    }

    osw_drv_report_sta_state(req->pool->drv, phy_name, vif_name, mac_addr, &sta_state);
    osw_drv_sta_state_report_free(&sta_state);
}

static void osw_drv_spf13_request_sta_state_poll(void *priv)
{
    osw_drv_spf13_request_sta_state_t *req = priv;
    if (req == NULL) return;

    if (osw_drv_spf13_nl_cmd_is_done(req->vnd_list_sta_cmd) == false)
    {
        return;
    }

    if (req->hostap_get_sta == NULL)
    {
        const struct osw_hwaddr *mac_addr = osw_drv_spf13_request_sta_get_addr(req);
        if (mac_addr != NULL)
        {
            req->hostap_get_sta = osw_drv_spf13_hostap_cmd_new(
                    osw_drv_spf13_hostap_sock_open(),
                    req->ctrl_path_hapd,
                    strfmta("STA " OSW_HWADDR_FMT, OSW_HWADDR_ARG(mac_addr)),
                    osw_drv_spf13_request_sta_state_poll,
                    req);
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done(req->hostap_get_sta) == false)
    {
        return;
    }

    osw_drv_spf13_request_sta_state_report(req);
    osw_drv_spf13_request_sta_state_drop(req);
}

static osw_drv_spf13_request_sta_state_t *osw_drv_spf13_request_sta_state_new(
        osw_drv_spf13_request_sta_state_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr)
{
    if (pool == NULL) return NULL;
    if (phy_name == NULL) return NULL;
    if (vif_name == NULL) return NULL;
    if (mac_addr == NULL) return NULL;

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

    const osw_drv_spf13_request_sta_state_id_t id = {
        .phy_name = STRDUP(phy_name),
        .vif_name = STRDUP(vif_name),
        .mac_addr = *mac_addr,
    };

    osw_drv_spf13_request_sta_state_t *req = CALLOC(1, sizeof(*req));
    req->pool = pool;
    req->id = id;
    ds_tree_insert(&pool->requests, req, &req->id);

    req->ctrl_path_hapd = osw_drv_spf13_hostap_path_hostapd_ctrl_bss(phy_name, vif_name);
    req->vnd_list_sta_cmd = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_list_sta(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_list_sta(%" PRIu32 ":%" PRIi8 ")", netdev_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_sta_state_poll,
            req);

    return req;
}

osw_drv_spf13_request_sta_state_pool_t *osw_drv_spf13_request_sta_state_pool_new(
        struct osw_drv *drv,
        uint32_t nl80211_family_id)
{
    if (drv == NULL) return NULL;

    osw_drv_spf13_request_sta_state_pool_t *pool = CALLOC(1, sizeof(*pool));
    ds_tree_init(
            &pool->requests,
            (ds_key_cmp_t *)osw_drv_spf13_request_sta_state_id_cmp,
            osw_drv_spf13_request_sta_state_t,
            node);
    pool->drv = drv;
    pool->nl80211_family_id = nl80211_family_id;
    return pool;
}

static void osw_drv_spf13_request_sta_state_pool_flush_requests(osw_drv_spf13_request_sta_state_pool_t *pool)
{
    osw_drv_spf13_request_sta_state_t *req;
    while ((req = ds_tree_head(&pool->requests)) != NULL)
    {
        osw_drv_spf13_request_sta_state_drop(req);
    }
}

void osw_drv_spf13_request_sta_state_pool_drop(osw_drv_spf13_request_sta_state_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_sta_state_pool_flush_requests(pool);
    FREE(pool);
}

static void osw_drv_spf13_request_sta_state_report_empty(
        struct osw_drv *drv,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr)
{
    if (drv == NULL || phy_name == NULL || vif_name == NULL || mac_addr == NULL) return;

    LOGI(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "reporting empty sta state"));
    struct osw_drv_sta_state sta_state = {
        .connected = false,
    };
    osw_drv_report_sta_state(drv, phy_name, vif_name, mac_addr, &sta_state);
}

void osw_drv_spf13_request_sta_state(
        osw_drv_spf13_request_sta_state_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr)
{
    if (WARN_ON(phy_name == NULL)) return;
    if (WARN_ON(vif_name == NULL)) return;
    if (WARN_ON(mac_addr == NULL)) return;

    struct osw_drv_spf13_request_sta_state_id id = {
        .phy_name = strdupa(phy_name),
        .vif_name = strdupa(vif_name),
        .mac_addr = *mac_addr,
    };
    osw_drv_spf13_request_sta_state_t *req = ds_tree_find(&pool->requests, &id);
    if (req != NULL)
    {
        LOGI(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "cancelling existing sta request"));
        osw_drv_spf13_request_sta_state_drop(req);
        req = NULL;
    }

    req = osw_drv_spf13_request_sta_state_new(pool, phy_name, vif_name, mac_addr);
    if (req == NULL)
    {
        LOGE(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "failed to create sta request"));
        osw_drv_spf13_request_sta_state_report_empty(pool->drv, phy_name, vif_name, mac_addr);
        return;
    }

    osw_drv_spf13_request_sta_state_poll(req);
}
