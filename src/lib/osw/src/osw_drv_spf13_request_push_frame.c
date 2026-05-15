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

/* 3rd party */
#include <ev.h>

/* opensync */
#include <ds_tree.h>
#include <memutil.h>
#include <util.h>
#include <log.h>

/* osw */
#include <osw_types.h>
#include <osw_drv.h>
#include <osw_drv_common.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_nl_cmd.h"
#include "osw_drv_spf13_nl_80211.h"
#include "osw_drv_spf13_request_push_frame.h"

#define OSW_DRV_SPF13_REQUEST_PUSH_FRAME_TIMEOUT_SEC 5.0

struct osw_drv_spf13_request_push_frame_id
{
    char *phy_name;
    char *vif_name;
};
typedef struct osw_drv_spf13_request_push_frame_id osw_drv_spf13_request_push_frame_id_t;

struct osw_drv_spf13_request_push_frame
{
    ds_tree_node_t node_pool;
    osw_drv_spf13_request_push_frame_id_t id;
    osw_drv_spf13_request_push_frame_pool_t *pool;
    osw_drv_spf13_nl_cmd_t *tx_cmd;
    ev_timer timeout;
};
typedef struct osw_drv_spf13_request_push_frame osw_drv_spf13_request_push_frame_t;

struct osw_drv_spf13_request_push_frame_pool
{
    ds_tree_t requests;
    uint32_t nl80211_family_id;
    struct osw_drv *drv;
};

static int osw_drv_spf13_request_push_frame_id_cmp(
        const osw_drv_spf13_request_push_frame_id_t *a,
        const osw_drv_spf13_request_push_frame_id_t *b)
{
    if (a == NULL || b == NULL) return 0;
    if (a != NULL && b == NULL) return 1;
    if (a == NULL && b != NULL) return -1;

    const int phy_cmp = strcmp(a->phy_name, b->phy_name);
    const int vif_cmp = strcmp(a->vif_name, b->vif_name);

    if (phy_cmp != 0) return phy_cmp;
    if (vif_cmp != 0) return vif_cmp;

    return 0;
}

static void osw_drv_spf13_request_push_frame_report(osw_drv_spf13_request_push_frame_t *req)
{
    struct osw_drv *drv = req->pool->drv;
    const bool timed_out = ev_is_active(&req->timeout) == false;
    const bool completed = osw_drv_spf13_nl_cmd_is_done(req->tx_cmd);
    const bool errored_out = osw_drv_spf13_nl_cmd_get_error(req->tx_cmd) != 0;

    if (completed)
    {
        if (errored_out)
        {
            LOGE(LOG_PREFIX_VIF(req->id.phy_name, req->id.vif_name, "push frame request errored out"));
            osw_drv_report_frame_tx_state_failed(drv);
        }
        else
        {
            LOGD(LOG_PREFIX_VIF(req->id.phy_name, req->id.vif_name, "push frame request completed successfully"));
            osw_drv_report_frame_tx_state_submitted(drv);
        }
    }
    else if (timed_out)
    {
        LOGI(LOG_PREFIX_VIF(req->id.phy_name, req->id.vif_name, "push frame request timed out"));
        osw_drv_report_frame_tx_state_failed(drv);
    }
    else
    {
        /* This shouldn't get here, but hey */
        LOGI(LOG_PREFIX_VIF(req->id.phy_name, req->id.vif_name, "push frame request still pending, faking failure"));
        osw_drv_report_frame_tx_state_failed(drv);
    }
}

static void osw_drv_spf13_request_push_frame_drop(osw_drv_spf13_request_push_frame_t *req)
{
    if (req == NULL) return;
    if (WARN_ON(req->pool == NULL)) return;

    ds_tree_remove(&req->pool->requests, req);
    req->pool = NULL;

    ev_timer_stop(EV_DEFAULT_ & req->timeout);
    osw_drv_spf13_nl_cmd_drop(req->tx_cmd);
    FREE(req->id.phy_name);
    FREE(req->id.vif_name);
    FREE(req);
}

static bool osw_drv_spf13_request_push_frame_is_busy(osw_drv_spf13_request_push_frame_t *req)
{
    if (req == NULL) return false;

    if (ev_is_active(&req->timeout) == false) return false;
    if (osw_drv_spf13_nl_cmd_is_done(req->tx_cmd) == false) return true;
    return false;
}

static void osw_drv_spf13_request_push_frame_poll(void *priv)
{
    osw_drv_spf13_request_push_frame_t *req = priv;

    if (osw_drv_spf13_request_push_frame_is_busy(req))
    {
        return;
    }

    osw_drv_spf13_request_push_frame_report(req);
    osw_drv_spf13_request_push_frame_drop(req);
}

static void osw_drv_spf13_request_push_frame_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_request_push_frame_t *req = w->data;
    if (req == NULL) return;

    osw_drv_spf13_request_push_frame_poll(req);
}

static osw_drv_spf13_request_push_frame_t *osw_drv_spf13_request_push_frame_new(
        osw_drv_spf13_request_push_frame_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_channel *c,
        const void *frame_buf,
        size_t frame_len)
{
    if (pool == NULL || phy_name == NULL || vif_name == NULL) return NULL;

    const char *netdev_name = strdupafree(osw_drv_spf13_netdev_from_phy_and_vif(phy_name, vif_name));
    if (netdev_name == NULL)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to get netdev name for vif"));
        return NULL;
    }

    osw_drv_spf13_request_push_frame_t *req = CALLOC(1, sizeof(*req));
    req->pool = pool;
    req->id.phy_name = STRDUP(phy_name);
    req->id.vif_name = STRDUP(vif_name);
    ds_tree_insert(&pool->requests, req, &req->id);

    ev_timer_init(
            &req->timeout,
            osw_drv_spf13_request_push_frame_timeout_cb,
            OSW_DRV_SPF13_REQUEST_PUSH_FRAME_TIMEOUT_SEC,
            0.0);
    req->timeout.data = req;

    const uint32_t family_id = pool->nl80211_family_id;
    const uint32_t ifindex = osw_drv_spf13_netdev_get_ifindex(netdev_name);
    const int8_t mlo_link_id =
            osw_drv_spf13_netdev_is_qca_vap_legacy(netdev_name) ? -1 : osw_drv_spf13_netdev_get_hw_link_id(phy_name);

    req->tx_cmd = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_80211_msg_frame(family_id, ifindex, mlo_link_id, c, frame_buf, frame_len),
            strfmta("%s: push_frame(%" PRIu32 ":%" PRIi8 ")", netdev_name, ifindex, mlo_link_id),
            NULL,
            req);

    if (req->tx_cmd == NULL)
    {
        osw_drv_spf13_request_push_frame_drop(req);
        return NULL;
    }

    ev_timer_start(EV_DEFAULT, &req->timeout);
    return req;
}

osw_drv_spf13_request_push_frame_pool_t *osw_drv_spf13_request_push_frame_pool_new(
        struct osw_drv *drv,
        uint32_t family_id)
{
    if (drv == NULL) return NULL;

    osw_drv_spf13_request_push_frame_pool_t *pool = CALLOC(1, sizeof(*pool));
    pool->nl80211_family_id = family_id;
    pool->drv = drv;
    ds_tree_init(
            &pool->requests,
            (ds_key_cmp_t *)osw_drv_spf13_request_push_frame_id_cmp,
            osw_drv_spf13_request_push_frame_t,
            node_pool);
    return pool;
}

static void osw_drv_spf13_request_push_frame_pool_flush(osw_drv_spf13_request_push_frame_pool_t *pool)
{
    osw_drv_spf13_request_push_frame_t *req;
    while ((req = ds_tree_head(&pool->requests)) != NULL)
    {
        osw_drv_spf13_request_push_frame_drop(req);
    }
}

void osw_drv_spf13_request_push_frame_pool_drop(osw_drv_spf13_request_push_frame_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_push_frame_pool_flush(pool);
    FREE(pool);
}

void osw_drv_spf13_request_push_frame(
        osw_drv_spf13_request_push_frame_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        struct osw_drv_frame_tx_desc *desc)
{
    if (pool == NULL) goto err;
    if (phy_name == NULL) goto err;
    if (vif_name == NULL) goto err;
    if (desc == NULL) goto err;

    const uint8_t *frame_buf = osw_drv_frame_tx_desc_get_frame(desc);
    const size_t frame_len = osw_drv_frame_tx_desc_get_frame_len(desc);
    const struct osw_channel *channel =
            osw_drv_frame_tx_desc_has_channel(desc) ? osw_drv_frame_tx_desc_get_channel(desc) : NULL;

    if (frame_buf == NULL) goto err;

    osw_drv_spf13_request_push_frame_t *req =
            osw_drv_spf13_request_push_frame_new(pool, phy_name, vif_name, channel, frame_buf, frame_len);
    if (WARN_ON(req == NULL)) goto err;

    return;

err:
    osw_drv_report_frame_tx_state_failed(pool->drv);
}
