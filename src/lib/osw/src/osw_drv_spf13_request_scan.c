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

/* 3rd party */
#include <ev.h>

/* opensync */
#include <ds_tree.h>
#include <memutil.h>
#include <const.h>
#include <log.h>

/* osw */
#include <osw_types.h>

/* local */
#include "osw_drv.h"
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_nl_cmd.h"
#include "osw_drv_spf13_nl_80211.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_request_scan.h"

#define OSW_DRV_SPF13_REQUEST_SCAN_TIMEOUT_SEC 5

struct osw_drv_spf13_request_scan_id
{
    char *phy_name;
    char *vif_name;
};
typedef struct osw_drv_spf13_request_scan_id osw_drv_spf13_request_scan_id_t;

struct osw_drv_spf13_request_scan
{
    ds_tree_node_t node_pool;
    osw_drv_spf13_request_scan_id_t id;
    osw_drv_spf13_request_scan_pool_t *pool;
    osw_drv_spf13_nl_cmd_t *cmd;
    ev_timer timeout;
    bool started;
    bool completed;
    bool aborted;
};
typedef struct osw_drv_spf13_request_scan osw_drv_spf13_request_scan_t;

struct osw_drv_spf13_request_scan_pool
{
    ds_tree_t requests;
    uint32_t nl80211_family_id;
    struct osw_drv *drv;
};

static int osw_drv_spf13_request_scan_id_cmp(
        const osw_drv_spf13_request_scan_id_t *a,
        const osw_drv_spf13_request_scan_id_t *b)
{
    if (a == NULL || b == NULL) return 0;
    if (a->phy_name == NULL || b->phy_name == NULL) return 0;
    if (a->vif_name == NULL || b->vif_name == NULL) return 0;

    const int phy_cmp = strcmp(a->phy_name, b->phy_name);
    const int vif_cmp = strcmp(a->vif_name, b->vif_name);

    if (phy_cmp != 0) return phy_cmp;
    if (vif_cmp != 0) return vif_cmp;

    return 0;
}

static const uint64_t *osw_drv_spf13_request_scan_get_cookie(osw_drv_spf13_request_scan_t *req)
{
    struct nl_msg *msg = osw_drv_spf13_nl_cmd_get_first_resp_only(req->cmd);
    if (msg == NULL) return NULL;

    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    const int err = nlmsg_parse(nlmsg_hdr(msg), 0, tb, NL80211_ATTR_MAX, NULL);
    if (err) return NULL;

    struct nlattr *cookie_attr = tb[NL80211_ATTR_COOKIE];
    if (cookie_attr == NULL) return NULL;
    if ((size_t)nla_len(cookie_attr) < sizeof(uint64_t)) return NULL;

    return nla_data(cookie_attr);
}

static bool osw_drv_spf13_request_scan_same_cookie(osw_drv_spf13_request_scan_t *req, struct nlattr *cookie_attr)
{
    if (cookie_attr == NULL) return false;
    if ((size_t)nla_len(cookie_attr) < sizeof(uint64_t)) return false;
    const uint64_t *cookie = nla_data(cookie_attr);

    const uint64_t *req_cookie = osw_drv_spf13_request_scan_get_cookie(req);
    if (req_cookie == NULL) return false;

    return *cookie == *req_cookie;
}

static void osw_drv_spf13_request_scan_drop(osw_drv_spf13_request_scan_t *req)
{
    if (req == NULL) return;
    if (WARN_ON(req->pool == NULL)) return;

    osw_drv_spf13_nl_cmd_drop(req->cmd);
    ev_timer_stop(EV_DEFAULT, &req->timeout);
    ds_tree_remove(&req->pool->requests, req);
    req->pool = NULL;
    FREE(req->id.phy_name);
    FREE(req->id.vif_name);
    FREE(req);
}

static void osw_drv_spf13_request_scan_report(osw_drv_spf13_request_scan_t *req)
{
    enum osw_drv_scan_complete_reason reason = OSW_DRV_SCAN_FAILED;
    const bool timed_out = ev_is_active(&req->timeout) == false;

    if (req->started == false)
    {
        LOGI(LOG_PREFIX_VIF(req->id.phy_name, req->id.vif_name, "scan request never started"));
    }

    if (req->completed)
    {
        if (req->aborted)
        {
            reason = OSW_DRV_SCAN_ABORTED;
        }
        else if (req->started)
        {
            reason = OSW_DRV_SCAN_DONE;
        }
        else
        {
            LOGI(LOG_PREFIX_VIF(req->id.phy_name, req->id.vif_name, "scan request completed but never started?"));
            reason = OSW_DRV_SCAN_FAILED;
        }
    }
    else if (timed_out)
    {
        reason = OSW_DRV_SCAN_TIMED_OUT;
    }
    else
    {
        reason = OSW_DRV_SCAN_FAILED;
    }

    osw_drv_report_scan_completed(req->pool->drv, req->id.phy_name, req->id.vif_name, reason);
}

static bool osw_drv_spf13_request_scan_is_busy(osw_drv_spf13_request_scan_t *req)
{
    if (req == NULL) return false;
    if (req->cmd == NULL) return false;

    if (ev_is_active(&req->timeout) == false) return false;
    if (osw_drv_spf13_nl_cmd_is_done(req->cmd) == false) return true;
    if (req->completed == false) return true;

    return false;
}

static void osw_drv_spf13_request_scan_poll(void *priv)
{
    osw_drv_spf13_request_scan_t *req = priv;
    if (req == NULL) return;

    if (osw_drv_spf13_request_scan_is_busy(req))
    {
        return;
    }

    osw_drv_spf13_request_scan_report(req);
    osw_drv_spf13_request_scan_drop(req);
}

static void osw_drv_spf13_request_scan_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_request_scan_t *req = w->data;
    osw_drv_spf13_request_scan_poll(req);
}

static osw_drv_spf13_request_scan_t *osw_drv_spf13_request_scan_new(
        osw_drv_spf13_request_scan_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_channel *channel,
        int dwell_time_msec)
{
    if (pool == NULL) return NULL;
    if (phy_name == NULL) return NULL;
    if (vif_name == NULL) return NULL;

    const char *netdev_name = osw_drv_spf13_netdev_from_phy_and_vif(phy_name, vif_name);
    if (netdev_name == NULL)
    {
        LOGE("osw_drv_spf13_request_scan_new: failed to get netdev name for phy %s vif %s", phy_name, vif_name);
        return NULL;
    }

    const uint32_t family_id = pool->nl80211_family_id;
    const uint32_t ifindex = osw_drv_spf13_netdev_get_ifindex(netdev_name);
    const int8_t mlo_link_id =
            osw_drv_spf13_netdev_is_qca_vap_legacy(netdev_name) ? -1 : osw_drv_spf13_netdev_get_hw_link_id(phy_name);

    osw_drv_spf13_request_scan_t *req = CALLOC(1, sizeof(*req));
    req->pool = pool;
    req->id.phy_name = STRDUP(phy_name);
    req->id.vif_name = STRDUP(vif_name);
    ds_tree_insert(&pool->requests, req, &req->id);

    ev_timer_init(&req->timeout, osw_drv_spf13_request_scan_timeout_cb, OSW_DRV_SPF13_REQUEST_SCAN_TIMEOUT_SEC, 0);
    req->timeout.data = req;

    req->cmd = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_80211_msg_roc(family_id, ifindex, mlo_link_id, channel, dwell_time_msec),
            strfmta("%s: scan(%" PRIu32 ":%" PRIi8 ")", netdev_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_scan_poll,
            req);

    if (req->cmd == NULL)
    {
        LOGW(LOG_PREFIX_VIF(phy_name, vif_name, "failed to create scan command"));
        osw_drv_spf13_request_scan_drop(req);
        return NULL;
    }

    return req;
}

osw_drv_spf13_request_scan_pool_t *osw_drv_spf13_request_scan_pool_new(struct osw_drv *drv, uint32_t nl80211_family_id)
{
    osw_drv_spf13_request_scan_pool_t *pool = CALLOC(1, sizeof(*pool));
    ds_tree_init(
            &pool->requests,
            (ds_key_cmp_t *)osw_drv_spf13_request_scan_id_cmp,
            osw_drv_spf13_request_scan_t,
            node_pool);
    pool->nl80211_family_id = nl80211_family_id;
    pool->drv = drv;
    return pool;
}

static void osw_drv_spf13_request_scan_pool_flush(osw_drv_spf13_request_scan_pool_t *pool)
{
    osw_drv_spf13_request_scan_t *req;
    while ((req = ds_tree_head(&pool->requests)) != NULL)
    {
        osw_drv_spf13_request_scan_drop(req);
    }
}

void osw_drv_spf13_request_scan_pool_drop(osw_drv_spf13_request_scan_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_scan_pool_flush(pool);
    FREE(pool);
}

void osw_drv_spf13_request_scan(
        osw_drv_spf13_request_scan_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_drv_scan_params *scan_param)
{
    if (pool == NULL) goto err;
    if (phy_name == NULL) goto err;
    if (vif_name == NULL) goto err;
    if (scan_param == NULL) goto err;

    if (scan_param->n_channels != 1)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "scan request with %zu channels not supported, expected 1"),
             scan_param->n_channels);
        goto err;
    }

    if (scan_param->passive == false)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "scan request with active scan not supported, expected passive"));
        goto err;
    }

    const osw_drv_spf13_request_scan_id_t id = {
        .phy_name = strdupa(phy_name),
        .vif_name = strdupa(vif_name),
    };
    osw_drv_spf13_request_scan_t *req = ds_tree_find(&pool->requests, &id);
    if (req != NULL)
    {
        LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "scan request already in progress, dropping"));
        osw_drv_spf13_request_scan_drop(req);
        return;
    }

    req = osw_drv_spf13_request_scan_new(
            pool,
            phy_name,
            vif_name,
            &scan_param->channels[0],
            scan_param->dwell_time_msec);
    if (req == NULL) goto err;
    return;

err:
    osw_drv_report_scan_completed(pool->drv, phy_name, vif_name, OSW_DRV_SCAN_FAILED);
}

static osw_drv_spf13_request_scan_t *osw_drv_spf13_request_scan_find(
        osw_drv_spf13_request_scan_pool_t *pool,
        const char *phy_name,
        const char *vif_name)
{
    if (pool == NULL) return NULL;
    if (phy_name == NULL) return NULL;
    if (vif_name == NULL) return NULL;

    const osw_drv_spf13_request_scan_id_t id = {
        .phy_name = strdupa(phy_name),
        .vif_name = strdupa(vif_name),
    };
    return ds_tree_find(&pool->requests, &id);
}

static osw_drv_spf13_request_scan_t *osw_drv_spf13_request_scan_find_with_cookie(
        osw_drv_spf13_request_scan_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        struct nlattr *cookie_attr)
{
    osw_drv_spf13_request_scan_t *req = osw_drv_spf13_request_scan_find(pool, phy_name, vif_name);
    if (req == NULL) return NULL;

    if (osw_drv_spf13_request_scan_same_cookie(req, cookie_attr) == false)
    {
        LOGW(LOG_PREFIX_VIF(phy_name, vif_name, "scan request with different cookie found"));
        return NULL;
    }

    return req;
}

void osw_drv_spf13_request_scan_started(
        osw_drv_spf13_request_scan_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        struct nlattr *cookie_attr)
{
    osw_drv_spf13_request_scan_t *req =
            osw_drv_spf13_request_scan_find_with_cookie(pool, phy_name, vif_name, cookie_attr);
    if (req == NULL) return;

    req->started = true;
}

void osw_drv_spf13_request_scan_completed(
        osw_drv_spf13_request_scan_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        struct nlattr *cookie_attr)
{
    osw_drv_spf13_request_scan_t *req =
            osw_drv_spf13_request_scan_find_with_cookie(pool, phy_name, vif_name, cookie_attr);
    if (req == NULL) return;

    req->completed = true;
    osw_drv_spf13_request_scan_poll(req);
}

void osw_drv_spf13_request_scan_aborted(
        osw_drv_spf13_request_scan_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        struct nlattr *cookie_attr)
{
    osw_drv_spf13_request_scan_t *req =
            osw_drv_spf13_request_scan_find_with_cookie(pool, phy_name, vif_name, cookie_attr);
    if (req == NULL) return;

    req->completed = true;
    req->aborted = true;
    osw_drv_spf13_request_scan_poll(req);
}
