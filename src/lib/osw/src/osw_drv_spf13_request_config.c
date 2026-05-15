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
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>

/* opensync */
#include <os_nif.h>
#include <os_time.h>
#include <ds_tree.h>
#include <memutil.h>
#include <log.h>
#include <util.h>
#include <ff_lib.h>

/* osw */
#include <osw_drv.h>
#include <osw_hostap_common.h>
#include <osw_hostap_conf.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_invalidations.h"
#include "osw_drv_spf13_request_config.h"
#include "osw_drv_spf13_nl_80211.h"
#include "osw_drv_spf13_nl_cmd.h"
#include "osw_drv_spf13_nl_vnd.h"
#include "osw_drv_spf13_hostap_cmd.h"
#include "osw_drv_spf13_hostap_sock.h"
#include "osw_drv_spf13_hostap_path.h"
#include "osw_drv_spf13_hostap_neigh.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_types.h"

/* osw_confsync retry timeout is 30s. This needs to be at least shorter than
 * that.
 *
 * The driver in its state can take a few seconds to confiugre a vap in some
 * cases. Typically when radio goes through a reset.
 *
 * If this timeout is reached chances are something else needs fixing. The
 * timeout really should never be reached, nor changed.
 */
#define OSW_DRV_SPF13_REQUEST_CONFIG_TIMEOUT_SEC 20

/* This is the standard Opensync has used since forever. This amounts to 1.5 or
 * 3s (for 100 and 200msec beacon interval respectively) giving ample time to
 * propagate CSA downstream to extenders and their extenders.
 */
#define OSW_DRV_SPF13_REQUEST_CONFIG_CHANSWITCH_TBTT_DEFAULT 15

/* The driver does not signal in any way if tx power has been set. The driver
 * applies tx power after a non-predictable 0-1s delay.
 */
#define OSW_DRV_SPF13_REQUEST_CONFIG_VIF_TX_POWER_TIMEOUT_SEC 5
#define OSW_DRV_SPF13_REQUEST_CONFIG_VIF_TX_POWER_CHECK_SEC   0.1

/* This uses array+enum to group commands instead of regular
 * struct member pointers.
 *
 * This makes it less error prone to manage memory of
 * command buffers, as well as their completion states.
 *
 * This is also used to plan which commands will need to be instantiated.
 * Commands are staged into planning (nl_cmds_planned), creation/execution and
 * awaiting through nl_cmds.
 */
enum osw_drv_spf13_request_config_phy_nl_cmd
{
    OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_TX_CHAINMASK,
    OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_RX_CHAINMASK,
    OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_FREQ,
    OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_WIDTH,
    OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_CHANSWITCH,

    /* keep last */
    OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_MAX,
};
typedef enum osw_drv_spf13_request_config_phy_nl_cmd osw_drv_spf13_request_config_phy_nl_cmd_t;

struct osw_drv_spf13_request_config_phy;
typedef struct osw_drv_spf13_request_config_phy osw_drv_spf13_request_config_phy_t;

struct osw_drv_spf13_request_config_vif;
typedef struct osw_drv_spf13_request_config_vif osw_drv_spf13_request_config_vif_t;

struct osw_drv_spf13_request_config;
typedef struct osw_drv_spf13_request_config osw_drv_spf13_request_config_t;

struct osw_drv_spf13_request_config_phy
{
    ds_tree_node_t node;
    char *phy_name;
    osw_drv_spf13_request_config_t *config_req;
    ds_tree_t vif_requests; /* osw_drv_spf13_request_config_vif_t */
    osw_drv_spf13_nl_cmd_t *nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_MAX];
    bool nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_MAX];
    struct osw_drv_phy_config *phy_conf;
    struct osw_channel channel;
    struct
    {
        bool down;
        bool up;
    } tasks;
    // change tasks into flags?
};

/* Just like osw_drv_spf13_request_config_phy_t, but for vifs.
 */
enum osw_drv_spf13_request_config_vif_nl_cmd
{
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ACL_POLICY,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCN_RATE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MGMT_RATE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST_RATE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCAST_RATE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_AP_BRIDGE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_UAPSD,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_RRM,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST2UCAST,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MBO,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_DBM,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_EN,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_RETRY_DELAY_SEC,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MAX_STA,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_DL_MU_OFDMA,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_UL_MU_OFDMA,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_DL_MU_OFDMA,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_UL_MU_OFDMA,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ATHNEWIND,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_POWERSAVE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_SET_TX_POWER,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_GET_INTERFACE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD,

    // these are todo. once done, move upward.
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_WDS,  // necessary? todo for ap_vlan?
    // OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_PUNCTURE_BITMAP, // maybe unnecessary? just use standard nl80211?
    //  proxy arp?
    //  dgaf?
    //  frame fwd
    //  frame mask
    //  ol stats
    //  dbdc enable?
    //  dbdc samessiddisable?
    //  mode upgrade?
    //  dcs on 6ghz? it can auto-channel change suddenly

    /* keep last */
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_MAX,
};
typedef enum osw_drv_spf13_request_config_vif_nl_cmd osw_drv_spf13_request_config_vif_nl_cmd_t;

enum osw_drv_spf13_request_config_vif_hostap_cmd
{
    // Might want/need to reconsider optimizing this to use more proper MLD
    // reconfiguration commands but need to do research on that first.
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_REMOVE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_ADD,
    // Doing DISABLE+ENABLE might be quicker to re-up downed interfaces when
    // reconfiguring MLD/MBSS
    // OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_DISABLE,
    // OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_ENABLE,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_LOG_LEVEL,
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_RELOAD_PSK,

    /* keep last */
    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_MAX,
};
typedef enum osw_drv_spf13_request_config_vif_hostap_cmd osw_drv_spf13_request_config_vif_hostap_cmd_t;

struct osw_drv_spf13_request_config_vif
{
    ds_tree_node_t node;
    osw_drv_spf13_request_config_phy_t *phy_req;
    osw_drv_spf13_hostap_neigh_waiter_t *neigh_waiter;
    char *vif_name;
    uint32_t ifindex;
    int8_t mlo_link_id;
    struct osw_drv_vif_config *vif_conf;
    osw_drv_spf13_hostap_cmd_t *hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_MAX];
    osw_drv_spf13_nl_cmd_t **acls;
    osw_drv_spf13_nl_cmd_t *nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_MAX];
    bool nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_MAX];
    struct
    {
        bool remove;
        bool add;
        bool log_level;
        bool reload_psk;
        bool neigh;
        bool acl;
    } tasks;
    // change tasks into flags? just like nl_cmd_planned?

    /* Tx power in the driver isn't set immediately and there's no indication
     * from the driver when it is done doing it.
     *
     * This requires polling the driver to check if the change has been applied.
     *
     * This could work off a separate worker job to poll for the change and
     * simply call osw_drv_report_vif_changed() later. Having it in the
     * request_config makes it nicer because it gives a better idea when
     * configuration _truly_ is finished (and how long it took), and should
     * prevent some unnecessary ping-pong and re-reconfigurations.
     */
    ev_timer tx_power_timeout;
    ev_timer tx_power_check;
};

struct osw_drv_spf13_request_config_neigh
{
    ds_tree_node_t node;
    char *phy_name;
    char *vif_name;
    osw_drv_spf13_hostap_neigh_syncer_t *syncer;
    osw_drv_spf13_hostap_neigh_waiter_t *resync_waiter;
    osw_drv_spf13_request_config_pool_t *pool;
};
typedef struct osw_drv_spf13_request_config_neigh osw_drv_spf13_request_config_neigh_t;

struct osw_drv_spf13_request_config_pool
{
    osw_drv_spf13_request_config_t *req;
    osw_drv_spf13_invalidations_t *invalidations;
    ds_tree_t neigh_syncers; /* osw_drv_spf13_request_config_neigh_t */
    uint32_t nl80211_family_id;
};

struct osw_drv_spf13_request_config
{
    ds_tree_node_t node;
    ds_tree_t phy_requests; /* osw_drv_spf13_request_config_phy_t */
    osw_drv_spf13_request_config_pool_t *pool;
    osw_drv_spf13_invalidations_lock_t *invalidations_lock;
    struct osw_drv_conf *drv_conf;
    int64_t started_on;
    ev_timer timeout;
};

static bool osw_drv_spf13_request_config_mu_ofdma_enabled(void)
{
    return ff_is_flag_enabled("enable_ofdma");
}

static osw_drv_spf13_request_config_neigh_t *osw_drv_spf13_request_config_neigh_new(
        osw_drv_spf13_request_config_pool_t *pool,
        const char *phy_name,
        const char *vif_name)
{
    if (pool == NULL) return NULL;
    if (phy_name == NULL || vif_name == NULL) return NULL;

    const char *ctrl_path = strdupafree(osw_drv_spf13_hostap_path_hostapd_ctrl_bss(phy_name, vif_name));
    osw_drv_spf13_request_config_neigh_t *neigh_req = CALLOC(1, sizeof(*neigh_req));
    neigh_req->pool = pool;
    neigh_req->phy_name = STRDUP(phy_name);
    neigh_req->vif_name = STRDUP(vif_name);
    neigh_req->syncer = osw_drv_spf13_hostap_neigh_syncer_new(ctrl_path);
    ds_tree_insert(&pool->neigh_syncers, neigh_req, neigh_req->vif_name);
    return neigh_req;
}

static void osw_drv_spf13_request_config_neigh_drop(osw_drv_spf13_request_config_neigh_t *neigh_req)
{
    if (neigh_req == NULL) return;

    ds_tree_remove(&neigh_req->pool->neigh_syncers, neigh_req);
    osw_drv_spf13_hostap_neigh_waiter_drop(neigh_req->resync_waiter);
    osw_drv_spf13_hostap_neigh_syncer_drop(neigh_req->syncer);
    FREE(neigh_req->phy_name);
    FREE(neigh_req->vif_name);
    FREE(neigh_req);
}

static osw_drv_spf13_request_config_neigh_t *osw_drv_spf13_request_config_neigh_get(
        osw_drv_spf13_request_config_pool_t *pool,
        const char *phy_name,
        const char *vif_name)
{
    if (pool == NULL) return NULL;
    if (phy_name == NULL || vif_name == NULL) return NULL;

    return ds_tree_find(&pool->neigh_syncers, vif_name)
                   ?: osw_drv_spf13_request_config_neigh_new(pool, phy_name, vif_name);
}

static void osw_drv_spf13_request_config_neigh_unset(
        osw_drv_spf13_request_config_pool_t *pool,
        const char *phy_name,
        const char *vif_name)
{
    osw_drv_spf13_request_config_neigh_t *neigh = ds_tree_find(&pool->neigh_syncers, vif_name);
    if (neigh == NULL) return;
    osw_drv_spf13_request_config_neigh_drop(neigh);
}

static osw_drv_spf13_request_config_phy_t *osw_drv_spf13_request_config_phy_new(
        osw_drv_spf13_request_config_t *req,
        const char *phy_name)
{
    if (req == NULL || phy_name == NULL) return NULL;

    osw_drv_spf13_request_config_phy_t *phy_req = CALLOC(1, sizeof(*phy_req));
    phy_req->phy_name = STRDUP(phy_name);
    phy_req->config_req = req;
    ds_tree_init(&phy_req->vif_requests, ds_str_cmp, osw_drv_spf13_request_config_vif_t, node);
    ds_tree_insert(&req->phy_requests, phy_req, phy_req->phy_name);
    return phy_req;
}

// FIXME: this needs to avoid forward decl like this
static void osw_drv_spf13_request_config_poll(void *priv);

static void osw_drv_spf13_request_config_vif_tx_power_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_request_config_vif_t *vif_req = w->data;
    if (vif_req == NULL) return;

    LOGI(LOG_PREFIX_VIF(vif_req->phy_req->phy_name, vif_req->vif_name, "tx power request timed out"));
    ev_timer_stop(EV_DEFAULT_ & vif_req->tx_power_check);
    osw_drv_spf13_request_config_poll(vif_req->phy_req->config_req);
}

static void osw_drv_spf13_request_config_vif_tx_power_check_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_request_config_vif_t *vif_req = w->data;
    if (vif_req == NULL) return;

    if (!ev_is_active(&vif_req->tx_power_timeout)) return;

    const bool still_running =
            osw_drv_spf13_nl_cmd_is_done(vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_GET_INTERFACE])
            == false;
    if (still_running)
    {
        return;
    }

    const char *phy_name = vif_req->phy_req->phy_name;
    const char *vif_name = vif_req->vif_name;

    osw_drv_spf13_nl_cmd_t *cmd = vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_GET_INTERFACE];
    if (osw_drv_spf13_nl_cmd_is_done(cmd))
    {
        const int8_t mlo_link_id = vif_req->mlo_link_id;
        struct nl_msg *resp = osw_drv_spf13_nl_cmd_get_first_resp_only(cmd);
        const uint32_t *mbm = osw_drv_spf13_nl_80211_get_tx_power_level(resp, mlo_link_id);
        if (mbm != NULL)
        {
            const int dbm = *mbm / 100;
            if (dbm == vif_req->vif_conf->tx_power_dbm)
            {
                LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "tx power confirmed set to configured %d dBm", dbm));
                ev_timer_stop(EV_DEFAULT_ & vif_req->tx_power_timeout);
                ev_timer_stop(EV_DEFAULT_ & vif_req->tx_power_check);
                osw_drv_spf13_request_config_poll(vif_req->phy_req->config_req);
                return;
            }
        }
    }

    osw_drv_spf13_nl_cmd_drop(vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_GET_INTERFACE]);
    vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_GET_INTERFACE] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_80211_msg_get_interface(
                    vif_req->phy_req->config_req->pool->nl80211_family_id,
                    vif_req->ifindex),
            strfmta("%s: get_interface(%" PRIu32 ")", vif_name, vif_req->ifindex),
            osw_drv_spf13_request_config_poll,
            vif_req->phy_req->config_req);
}

static osw_drv_spf13_request_config_vif_t *osw_drv_spf13_request_config_vif_new(
        osw_drv_spf13_request_config_phy_t *phy_req,
        const char *vif_name)
{
    if (phy_req == NULL || vif_name == NULL) return NULL;

    osw_drv_spf13_request_config_vif_t *vif_req = CALLOC(1, sizeof(*vif_req));
    ev_timer_init(
            &vif_req->tx_power_timeout,
            osw_drv_spf13_request_config_vif_tx_power_timeout_cb,
            OSW_DRV_SPF13_REQUEST_CONFIG_VIF_TX_POWER_TIMEOUT_SEC,
            0);
    vif_req->tx_power_timeout.data = vif_req;
    ev_timer_init(
            &vif_req->tx_power_check,
            osw_drv_spf13_request_config_vif_tx_power_check_cb,
            OSW_DRV_SPF13_REQUEST_CONFIG_VIF_TX_POWER_CHECK_SEC,
            OSW_DRV_SPF13_REQUEST_CONFIG_VIF_TX_POWER_CHECK_SEC);
    vif_req->tx_power_check.data = vif_req;
    vif_req->phy_req = phy_req;
    vif_req->vif_name = STRDUP(vif_name);
    ds_tree_insert(&phy_req->vif_requests, vif_req, vif_req->vif_name);
    return vif_req;
}

static osw_drv_spf13_request_config_phy_t *osw_drv_spf13_request_config_phy_find(
        osw_drv_spf13_request_config_t *req,
        const char *phy_name)
{
    if (req == NULL || phy_name == NULL) return NULL;

    osw_drv_spf13_request_config_phy_t *phy_req = ds_tree_find(&req->phy_requests, phy_name);
    return phy_req;
}

static osw_drv_spf13_request_config_phy_t *osw_drv_spf13_request_config_phy_find_or_new(
        osw_drv_spf13_request_config_t *req,
        const char *phy_name)
{
    return osw_drv_spf13_request_config_phy_find(req, phy_name) ?: osw_drv_spf13_request_config_phy_new(req, phy_name);
}

static osw_drv_spf13_request_config_vif_t *osw_drv_spf13_request_config_vif_find(
        osw_drv_spf13_request_config_phy_t *phy_req,
        const char *vif_name)
{
    if (phy_req == NULL || vif_name == NULL) return NULL;

    osw_drv_spf13_request_config_vif_t *vif_req = ds_tree_find(&phy_req->vif_requests, vif_name);
    return vif_req;
}

static osw_drv_spf13_request_config_vif_t *osw_drv_spf13_request_config_vif_find_or_new(
        osw_drv_spf13_request_config_phy_t *phy_req,
        const char *vif_name)
{
    return osw_drv_spf13_request_config_vif_find(phy_req, vif_name)
                   ?: osw_drv_spf13_request_config_vif_new(phy_req, vif_name);
}

static bool osw_drv_spf13_request_config_any_vif_task_is_still_remove(osw_drv_spf13_request_config_t *req)
{
    if (req == NULL) return false;

    osw_drv_spf13_request_config_phy_t *phy_req;
    ds_tree_foreach (&req->phy_requests, phy_req)
    {
        osw_drv_spf13_request_config_vif_t *vif_req;
        ds_tree_foreach (&phy_req->vif_requests, vif_req)
        {
            if (vif_req->tasks.remove)
            {
                return true;
            }
        }
    }

    return false;
}

static bool osw_drv_spf13_request_config_vif_needs_restart(osw_drv_spf13_request_config_vif_t *vif_req)
{
    if (vif_req == NULL) return false;

    const struct osw_drv_vif_config *vif_conf = vif_req->vif_conf;
    const struct osw_drv_phy_config *phy_conf = vif_req->phy_req->phy_conf;

    if (vif_conf->vif_type != OSW_VIF_AP) return false;

    // FIXME: make this a helper in osw_hostap_conf, and share across osw_hostap and here
    //
    const bool has_sae = vif_conf->u.ap.wpa.akm_sae;
    const bool psk_changed = vif_conf->u.ap.psk_list_changed;
    const bool channel_changed = vif_conf->u.ap.channel_changed;
    const bool not_csa = (vif_conf->u.ap.csa_required == false);

    bool invalidated = vif_conf->enabled_changed;
    invalidated |= has_sae && psk_changed;
    invalidated |= channel_changed && not_csa;
    invalidated |= vif_conf->u.ap.bridge_if_name_changed;
    invalidated |= vif_conf->u.ap.nas_identifier_changed;
    invalidated |= vif_conf->u.ap.beacon_interval_tu_changed;
    invalidated |= vif_conf->u.ap.ssid_hidden_changed;
    invalidated |= vif_conf->u.ap.isolated_changed;
    invalidated |= vif_conf->u.ap.mcast2ucast_changed;
    invalidated |= vif_conf->u.ap.mode_changed;
    invalidated |= vif_conf->u.ap.ssid_changed;
    invalidated |= vif_conf->u.ap.wpa_changed;
    invalidated |= vif_conf->u.ap.radius_list_changed;
    invalidated |= vif_conf->u.ap.acct_list_changed;
    invalidated |= vif_conf->u.ap.passpoint_changed;
    invalidated |= vif_conf->u.ap.multi_ap_changed;
    invalidated |= vif_conf->u.ap.ft_encr_key_changed;
    invalidated |= vif_conf->u.ap.ft_over_ds_changed;
    invalidated |= vif_conf->u.ap.ft_pmk_r0_key_lifetime_sec_changed;
    invalidated |= vif_conf->u.ap.ft_pmk_r1_max_key_lifetime_sec_changed;
    invalidated |= vif_conf->u.ap.ft_pmk_r1_push_changed;
    invalidated |= vif_conf->u.ap.ft_psk_generate_local_changed;
    invalidated |= vif_conf->u.ap.ft_mobility_domain_changed;
    invalidated |= phy_conf->reg_domain_changed;

    invalidated |= vif_conf->u.ap.mbss_mode_changed;

    return invalidated;
}

static const char *osw_drv_spf13_request_config_phy_nl_cmd_to_cstr(osw_drv_spf13_request_config_phy_nl_cmd_t cmd)
{
    switch (cmd)
    {
        case OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_TX_CHAINMASK:
            return "tx_chainmask";
        case OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_RX_CHAINMASK:
            return "rx_chainmask";
        case OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_FREQ:
            return "next_radar_freq";
        case OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_WIDTH:
            return "next_radar_width";
        case OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_CHANSWITCH:
            return "vnd_chanswitch";
        case OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_MAX:
            break;
    }
    return "max";
}

static const char *osw_drv_spf13_request_config_vif_nl_cmd_to_cstr(osw_drv_spf13_request_config_vif_nl_cmd_t cmd)
{
    switch (cmd)
    {
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ACL_POLICY:
            return "set_acl_policy";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCN_RATE:
            return "set_bcn_rate";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MGMT_RATE:
            return "set_mgmt_rate";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST_RATE:
            return "set_mcast_rate";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCAST_RATE:
            return "set_bcast_rate";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_AP_BRIDGE:
            return "set_ap_bridge";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_UAPSD:
            return "set_uapsd";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_RRM:
            return "set_rrm";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST2UCAST:
            return "set_mcast2ucast";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_WDS:
            return "vnd_set_wds";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MBO:
            return "vnd_set_mbo";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE:
            return "vnd_set_oce";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_DBM:
            return "vnd_set_oce_min_rssi_dbm";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_EN:
            return "vnd_set_oce_min_rssi_en";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_RETRY_DELAY_SEC:
            return "vnd_set_oce_retry_delay_sec";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MAX_STA:
            return "vnd_set_max_sta";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_DL_MU_OFDMA:
            return "vnd_set_he_dl_ofdma";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_UL_MU_OFDMA:
            return "vnd_set_he_ul_ofdma";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_DL_MU_OFDMA:
            return "vnd_set_eht_dl_ofdma";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_UL_MU_OFDMA:
            return "vnd_set_eht_ul_ofdma";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ATHNEWIND:
            return "vnd_set_athnewind";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_POWERSAVE:
            return "vnd_set_powersave";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_SET_TX_POWER:
            return "set_tx_power";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_GET_INTERFACE:
            return "get_interface";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD:
            return "link_add";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_MAX:
            break;
    }
    return "max";
}

static bool osw_drv_spf13_request_config_nl_cmds_planned_set(
        osw_drv_spf13_request_config_vif_t *vif_req,
        osw_drv_spf13_request_config_vif_nl_cmd_t cmd)
{
    if (vif_req == NULL || cmd >= OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_MAX) return false;
    if (vif_req->nl_cmds_planned[cmd] == true) return false;
    vif_req->nl_cmds_planned[cmd] = true;
    LOGD(LOG_PREFIX_VIF(
            vif_req->phy_req->phy_name,
            vif_req->vif_name,
            "planning nl cmd %s",
            osw_drv_spf13_request_config_vif_nl_cmd_to_cstr(cmd)));
    return true;
}

static bool osw_drv_spf13_request_config_nl_cmds_planned_consume(
        osw_drv_spf13_request_config_vif_t *vif_req,
        osw_drv_spf13_request_config_vif_nl_cmd_t cmd)
{
    if (vif_req == NULL || cmd >= OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_MAX) return false;
    if (vif_req->nl_cmds_planned[cmd] == false) return false;
    vif_req->nl_cmds_planned[cmd] = false;
    LOGD(LOG_PREFIX_VIF(
            vif_req->phy_req->phy_name,
            vif_req->vif_name,
            "consuming nl cmd %s",
            osw_drv_spf13_request_config_vif_nl_cmd_to_cstr(cmd)));
    return true;
}

static void osw_drv_spf13_request_config_vif_derive_tasks(osw_drv_spf13_request_config_vif_t *vif_req)
{
    if (vif_req == NULL) return;

    // Dependency calculation is recursive. This drives the termination
    // condition - once the tasks on a vif are derived they will no longer
    // allow for recursion.
    bool changed = false;

    if (vif_req->vif_conf->enabled_changed || osw_drv_spf13_request_config_vif_needs_restart(vif_req))
    {
        if (vif_req->tasks.remove == false)
        {
            LOGI(LOG_PREFIX_VIF(vif_req->phy_req->phy_name, vif_req->vif_name, "planinng remove"));
            changed = true;
            vif_req->tasks.remove = true;
        }
    }

    if ((vif_req->vif_conf->enabled_changed || vif_req->tasks.remove) && vif_req->vif_conf->enabled)
    {
        if (vif_req->tasks.add == false)
        {
            LOGI(LOG_PREFIX_VIF(vif_req->phy_req->phy_name, vif_req->vif_name, "planning add"));
            changed = true;
            vif_req->tasks.add = true;
        }
    }

    if (vif_req->tasks.add)
    {
        if (vif_req->tasks.log_level == false)
        {
            LOGI(LOG_PREFIX_VIF(vif_req->phy_req->phy_name, vif_req->vif_name, "planning log level"));
            changed = true;
            vif_req->tasks.log_level = true;
        }
    }

    if (vif_req->tasks.add || vif_req->vif_conf->tx_power_dbm_changed)
    {
        changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_SET_TX_POWER);
    }

    if (vif_req->tasks.add)
    {
        changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_DL_MU_OFDMA);
        changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_UL_MU_OFDMA);
        changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_DL_MU_OFDMA);
        changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_UL_MU_OFDMA);
        changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ATHNEWIND);
        changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_POWERSAVE);
        changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD);
    }

    switch (vif_req->vif_conf->vif_type)
    {
        case OSW_VIF_AP:
            /* Can't tell if RRM changed in u.ap.mode or not. If it did, then
             * neigh list may need to be re-synced. */
            if (vif_req->tasks.add || vif_req->vif_conf->u.ap.neigh_list_changed
                || vif_req->vif_conf->u.ap.mode_changed)
            {
                if (vif_req->tasks.neigh == false)
                {
                    LOGI(LOG_PREFIX_VIF(vif_req->phy_req->phy_name, vif_req->vif_name, "planning neigh sync"));
                    changed = true;
                    vif_req->tasks.neigh = true;
                }
            }

            if (vif_req->vif_conf->u.ap.csa_required)
            {
                if (vif_req->tasks.add || vif_req->vif_conf->u.ap.channel_changed)
                {
                    if (vif_req->phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_CHANSWITCH]
                        == false)
                    {
                        LOGI(LOG_PREFIX_VIF(vif_req->phy_req->phy_name, vif_req->vif_name, "planning phy chanswitch"));
                        changed = true;
                        vif_req->phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_CHANSWITCH] =
                                true;
                        vif_req->phy_req->channel = vif_req->vif_conf->u.ap.channel;
                    }
                }
            }

            if (vif_req->tasks.add || vif_req->vif_conf->u.ap.acl_changed)
            {
                if (vif_req->tasks.acl == false)
                {
                    LOGI(LOG_PREFIX_VIF(vif_req->phy_req->phy_name, vif_req->vif_name, "planning acl sync"));
                    changed = true;
                    vif_req->tasks.acl = true;
                }
            }

            if (vif_req->vif_conf->enabled && (vif_req->tasks.add == false && vif_req->vif_conf->u.ap.psk_list_changed))
            {
                // reload psks only if the bss isnt getting reloaded already
                // if its getting reloaded it makes no sense to issue reload psk
                if (vif_req->tasks.add == false)
                {
                    if (vif_req->tasks.reload_psk == false)
                    {
                        LOGI(LOG_PREFIX_VIF(vif_req->phy_req->phy_name, vif_req->vif_name, "planning psk reload"));
                        changed = true;
                        vif_req->tasks.reload_psk = true;
                    }
                }
            }

            if (vif_req->vif_conf->enabled && (vif_req->tasks.add || vif_req->vif_conf->u.ap.mode_changed))
            {
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_UAPSD);
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_RRM);
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCN_RATE);
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MGMT_RATE);
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST_RATE);
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCAST_RATE);
            }

            if (vif_req->vif_conf->enabled && (vif_req->tasks.add || vif_req->vif_conf->u.ap.acl_policy_changed))
            {
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ACL_POLICY);
            }

            if (vif_req->vif_conf->enabled && (vif_req->tasks.add || vif_req->vif_conf->u.ap.isolated_changed))
            {
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_AP_BRIDGE);
            }

            if (vif_req->vif_conf->enabled && (vif_req->tasks.add || vif_req->vif_conf->u.ap.mcast2ucast_changed))
            {
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST2UCAST);
            }

            if (vif_req->vif_conf->enabled && (vif_req->tasks.add || vif_req->vif_conf->u.ap.mbo_changed))
            {
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MBO);
            }

            if (vif_req->vif_conf->enabled && (vif_req->tasks.add || vif_req->vif_conf->u.ap.oce_changed))
            {
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE);
            }

            if (vif_req->vif_conf->enabled && (vif_req->tasks.add || vif_req->vif_conf->u.ap.oce_min_rssi_dbm_changed))
            {
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_EN);
                if (vif_req->vif_conf->u.ap.oce_min_rssi_enable)
                {
                    changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                            vif_req,
                            OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_DBM);
                }
            }

            if (vif_req->vif_conf->enabled
                && (vif_req->tasks.add || vif_req->vif_conf->u.ap.oce_retry_delay_sec_changed))
            {
                changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                        vif_req,
                        OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_RETRY_DELAY_SEC);
            }

            if (vif_req->vif_conf->enabled && (vif_req->tasks.add || vif_req->vif_conf->u.ap.max_sta_changed))
            {
                if (vif_req->vif_conf->u.ap.max_sta > 0)
                {
                    changed |= osw_drv_spf13_request_config_nl_cmds_planned_set(
                            vif_req,
                            OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MAX_STA);
                }
            }
            break;
        case OSW_VIF_AP_VLAN:
            break;
        case OSW_VIF_STA:
            break;
        case OSW_VIF_UNDEFINED:
            break;
    }

    // FIXME: To test. Not sure if this is still necessary in SPF13.
    //  In SPF12 toggling mbss state would down all mbss siblings, and then
    //  those siblings' Affiliated APs (MLD) in cascade.
    //  Downing Affiliated APs would result in a ping-pong and a livelock due
    //  to how SPF12 expected all AP MLDs to be started/stopped in tandem,
    //  never adhoc.
    // Perhaps only the mbss needs special handling and the mld not anymore?
    // Better safe then sorry for now. That's an optimization of service
    // downtime during (seldom) configuration reloads.
    if (changed)
    {
        if (vif_req->vif_conf->vif_type == OSW_VIF_AP &&
            // vif_req->vif_conf->u.ap.mbss_mode != OSW_MBSS_NONE &&
            (vif_req->tasks.add || vif_req->tasks.remove))
        {
            struct osw_drv_phy_config *phy_conf = vif_req->phy_req->phy_conf;
            size_t vif_i;
            for (vif_i = 0; vif_i < phy_conf->vif_list.count; vif_i++)
            {
                struct osw_drv_vif_config *sibling_vif_conf = &phy_conf->vif_list.list[vif_i];
                if (sibling_vif_conf == vif_req->vif_conf) continue;
                if (sibling_vif_conf->vif_type != vif_req->vif_conf->vif_type) continue;
                if (sibling_vif_conf->enabled == false) continue;
                if (sibling_vif_conf->u.ap.mbss_mode == OSW_MBSS_NONE) continue;
                if (sibling_vif_conf->u.ap.mbss_group != vif_req->vif_conf->u.ap.mbss_group) continue;

                osw_drv_spf13_request_config_vif_t *sibling_vif_req =
                        osw_drv_spf13_request_config_vif_find(vif_req->phy_req, sibling_vif_conf->vif_name);
                if (sibling_vif_req == NULL) continue;
                if (sibling_vif_req->tasks.remove == false)
                {
                    LOGI(LOG_PREFIX_VIF(
                            vif_req->phy_req->phy_name,
                            sibling_vif_conf->vif_name,
                            "planning remove: sibling mbss"));
                    sibling_vif_req->tasks.remove = true;
                    osw_drv_spf13_request_config_vif_derive_tasks(sibling_vif_req);
                }
            }
        }

        const char *netdev_name =
                strdupafree(osw_drv_spf13_netdev_from_phy_and_vif(vif_req->phy_req->phy_name, vif_req->vif_name));
        const bool is_mld = osw_drv_spf13_netdev_is_qca_vap_mld(netdev_name);
        if (vif_req->vif_conf->vif_type == OSW_VIF_AP && is_mld && (vif_req->tasks.add || vif_req->tasks.remove))
        {
            struct osw_drv_conf *drv_conf = vif_req->phy_req->config_req->drv_conf;
            size_t phy_i;
            for (phy_i = 0; phy_i < drv_conf->n_phy_list; phy_i++)
            {
                struct osw_drv_phy_config *phy_conf = &drv_conf->phy_list[phy_i];
                if (phy_conf == vif_req->phy_req->phy_conf) continue;

                osw_drv_spf13_request_config_phy_t *sibling_phy_req =
                        osw_drv_spf13_request_config_phy_find(vif_req->phy_req->config_req, phy_conf->phy_name);
                if (sibling_phy_req == NULL) continue;

                size_t vif_i;
                for (vif_i = 0; vif_i < phy_conf->vif_list.count; vif_i++)
                {
                    struct osw_drv_vif_config *sibling_vif_conf = &phy_conf->vif_list.list[vif_i];
                    if (sibling_vif_conf->vif_type != vif_req->vif_conf->vif_type) continue;

                    const char *sibling_netdev_name = strdupafree(
                            osw_drv_spf13_netdev_from_phy_and_vif(phy_conf->phy_name, sibling_vif_conf->vif_name));
                    const bool sibling_is_mld = osw_drv_spf13_netdev_is_qca_vap_mld(sibling_netdev_name);
                    if (sibling_is_mld == false) continue;
                    const bool different_mld = strcmp(sibling_netdev_name, netdev_name) != 0;
                    if (different_mld) continue;

                    osw_drv_spf13_request_config_vif_t *sibling_vif_req =
                            osw_drv_spf13_request_config_vif_find(sibling_phy_req, sibling_vif_conf->vif_name);
                    if (sibling_vif_req == NULL) continue;
                    if (sibling_vif_req->tasks.remove == false)
                    {
                        LOGI(LOG_PREFIX_VIF(
                                sibling_phy_req->phy_name,
                                sibling_vif_conf->vif_name,
                                "planning remove: sibling mld"));
                        sibling_vif_req->tasks.remove = true;
                        osw_drv_spf13_request_config_vif_derive_tasks(sibling_vif_req);
                    }
                }
            }
        }
    }
}

static void osw_drv_spf13_request_config_vif_gen_supplicant(osw_drv_spf13_request_config_vif_t *vif_req)
{
    if (vif_req->vif_conf->vif_type != OSW_VIF_STA)
    {
        return;
    }

    // FIXME
}

static void osw_drv_spf13_request_config_vif_gen_hostap(osw_drv_spf13_request_config_vif_t *vif_req)
{
    const char *phy_name = vif_req->phy_req->phy_name;
    const char *vif_name = vif_req->vif_name;

    if (vif_req->vif_conf->vif_type != OSW_VIF_AP)
    {
        return;
    }

    struct osw_hostap_conf_ap_config conf = {0};
    const bool ok = osw_hostap_conf_fill_ap_config(vif_req->phy_req->config_req->drv_conf, phy_name, vif_name, &conf);
    if (ok == false)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to fill AP config"));
        return;
    }

    const char *conf_path = strdupafree(osw_drv_spf13_hostap_path_hostapd_config(vif_name));
    const char *psks_path = strdupafree(osw_drv_spf13_hostap_path_hostapd_pskfile(vif_name));
    const char *rxkh_path = strdupafree(osw_drv_spf13_hostap_path_hostapd_rxkh(vif_name));
    OSW_HOSTAP_CONF_SET_BUF(conf.wpa_psk_file, psks_path);
    OSW_HOSTAP_CONF_SET_BUF(conf.rxkh_file, rxkh_path);
    OSW_HOSTAP_CONF_SET_BUF(conf.ctrl_interface, strdupafree(osw_drv_spf13_hostap_path_hostapd_ctrl_base(phy_name)));

    // customize as per qca specifics, eg. mld link id, etc.
    {
        const char *vap_name = strdupafree(osw_drv_spf13_netdev_from_phy_and_vif(phy_name, vif_name));
        const bool is_mld = osw_drv_spf13_netdev_is_qca_vap_mld(vap_name);
        const int hw_link_id = osw_drv_spf13_netdev_get_hw_link_id(phy_name);
        if (is_mld && hw_link_id >= 0)
        {
            STRSCAT(conf.extra_buf, strfmta("mld_ap=1\n"));
            STRSCAT(conf.extra_buf, strfmta("mld_link_id=%d\n", hw_link_id));
            OSW_HOSTAP_CONF_SET_BUF(conf.interface, vap_name);

            {
                const char *link_addr_path =
                        strfmta("/sys/class/net/%s/link%d/address_link%d", vap_name, hw_link_id, hw_link_id);
                char *bssid_str = file_geta(link_addr_path);
                /* If the following check fails it suggests that adding the
                 * link prior to starting hostapd might've failed.
                 */
                WARN_ON(bssid_str == NULL);

                if (bssid_str != NULL)
                {
                    strchomp(bssid_str, " \r\n");
                    OSW_HOSTAP_CONF_SET_BUF(conf.bssid, bssid_str);
                }
            }
        }

        /* HT and VHT capabs require a legacy VAP to be present, or at least 1
         * link of each radio attached to an MLD VAP. If neither of this is
         * fulfilled then caps are unknown. Logging it is useful to know
         * something didn't exactly go as planned. This isn't critical. It
         * might just end up not providing max theoretical phyrates to clients.
         */

        const char *htcaps = strdupafree(osw_drv_spf13_netdev_phy_get_caps(phy_name, "htcaps"));
        if (htcaps != NULL)
        {
            OSW_HOSTAP_CONF_SET_BUF(conf.ht_capab, htcaps);
        }
        else
        {
            LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "htcaps not found, not setting HT capabilities"));
        }

        const char *vhtcaps = strdupafree(osw_drv_spf13_netdev_phy_get_caps(phy_name, "vhtcaps"));
        if (vhtcaps != NULL)
        {
            OSW_HOSTAP_CONF_SET_BUF(conf.vht_capab, vhtcaps);
        }
        else
        {
            LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "vhtcaps not found, not setting VHT capabilities"));
        }

        OSW_HOSTAP_CONF_UNSET(conf.country_code);
        OSW_HOSTAP_CONF_UNSET(conf.ieee80211d);
        OSW_HOSTAP_CONF_UNSET(conf.ieee80211h);
        OSW_HOSTAP_CONF_SET_VAL(conf.send_probe_response, 0);
        OSW_HOSTAP_CONF_UNSET(conf.beacon_rate);
    }

    osw_hostap_conf_generate_ap_config_bufs(&conf);
    osw_hostap_conf_list_free(&conf);

    file_put(conf_path, conf.conf_buf);
    file_put(psks_path, conf.psks_buf);
    file_put(rxkh_path, conf.rxkh_buf);
}

static void osw_drv_spf13_request_config_prep_configs(
        osw_drv_spf13_request_config_t *req,
        void (*done_cb)(void *priv),
        void *done_priv)
{
    if (req == NULL) return;

    size_t phy_i;
    for (phy_i = 0; phy_i < req->drv_conf->n_phy_list; phy_i++)
    {
        struct osw_drv_phy_config *phy_conf = &req->drv_conf->phy_list[phy_i];
        const char *phy_name = phy_conf->phy_name;
        if (phy_name == NULL) continue;

        osw_drv_spf13_request_config_phy_t *phy_req = osw_drv_spf13_request_config_phy_find_or_new(req, phy_name);
        phy_req->phy_conf = phy_conf;

        size_t vif_i;
        for (vif_i = 0; vif_i < phy_conf->vif_list.count; vif_i++)
        {
            struct osw_drv_vif_config *vif_conf = &phy_conf->vif_list.list[vif_i];
            const char *vif_name = vif_conf->vif_name;
            if (vif_name == NULL) continue;

            osw_drv_spf13_request_config_vif_t *vif_req =
                    osw_drv_spf13_request_config_vif_find_or_new(phy_req, vif_name);
            vif_req->vif_conf = vif_conf;

            if (0) osw_drv_spf13_request_config_vif_gen_hostap(vif_req);
            osw_drv_spf13_request_config_vif_gen_supplicant(vif_req);
        }
    }
}

static void osw_drv_spf13_request_config_phy_derive_tasks(osw_drv_spf13_request_config_phy_t *phy_req)
{
    if (phy_req == NULL) return;

    if (phy_req->phy_conf->enabled_changed && phy_req->phy_conf->enabled == false)
    {
        if (phy_req->tasks.down == false)
        {
            LOGI(LOG_PREFIX_PHY(phy_req->phy_name, "phy enabled changed, downing phy"));
            phy_req->tasks.down = true;
        }
    }

    if (phy_req->phy_conf->enabled_changed && phy_req->phy_conf->enabled == true)
    {
        if (phy_req->tasks.up == false)
        {
            LOGI(LOG_PREFIX_PHY(phy_req->phy_name, "phy enabled changed, uping phy"));
            phy_req->tasks.up = true;
        }
    }

    if (phy_req->phy_conf->tx_chainmask_changed)
    {
        if (phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_TX_CHAINMASK] == false)
        {
            LOGD(LOG_PREFIX_PHY(phy_req->phy_name, "tx chainmask changed, planning tx chainmask nl cmd"));
            phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_TX_CHAINMASK] = true;
        }

        if (phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_RX_CHAINMASK] == false)
        {
            LOGD(LOG_PREFIX_PHY(phy_req->phy_name, "tx chainmask changed, planning rx chainmask nl cmd"));
            phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_RX_CHAINMASK] = true;
        }
    }

    if (phy_req->phy_conf->radar_next_channel_changed)
    {
        if (phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_FREQ] == false)
        {
            LOGD(LOG_PREFIX_PHY(phy_req->phy_name, "next radar channel changed, planning next radar freq nl cmd"));
            phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_FREQ] = true;
        }

        if (phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_WIDTH] == false)
        {
            LOGD(LOG_PREFIX_PHY(phy_req->phy_name, "next radar channel changed, planning next radar width nl cmd"));
            phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_WIDTH] = true;
        }
    }

    size_t vif_i;
    for (vif_i = 0; vif_i < phy_req->phy_conf->vif_list.count; vif_i++)
    {
        struct osw_drv_vif_config *vif_conf = &phy_req->phy_conf->vif_list.list[vif_i];
        const char *vif_name = vif_conf->vif_name;
        if (vif_name == NULL) continue;

        /* TODO: OSW_VIF_STA is supposed to be handled by osw_drv_spf13_request_config_mldsta */
        if (vif_conf->vif_type == OSW_VIF_AP)
        {
            osw_drv_spf13_request_config_vif_t *vif_req =
                    osw_drv_spf13_request_config_vif_find_or_new(phy_req, vif_name);
            osw_drv_spf13_request_config_vif_derive_tasks(vif_req);
        }
    }
}

static void osw_drv_spf13_request_config_derive_tasks(osw_drv_spf13_request_config_t *req)
{
    if (req == NULL) return;

    size_t phy_i;
    for (phy_i = 0; phy_i < req->drv_conf->n_phy_list; phy_i++)
    {
        struct osw_drv_phy_config *phy_conf = &req->drv_conf->phy_list[phy_i];
        const char *phy_name = phy_conf->phy_name;
        if (phy_name == NULL) continue;

        osw_drv_spf13_request_config_phy_t *phy_req = osw_drv_spf13_request_config_phy_find_or_new(req, phy_name);
        osw_drv_spf13_request_config_phy_derive_tasks(phy_req);
    }
}

static bool osw_drv_spf13_request_config_vif_is_any_task_still_planned(osw_drv_spf13_request_config_vif_t *vif_req)
{
    if (vif_req == NULL) return false;

    return false || vif_req->tasks.remove || vif_req->tasks.add || vif_req->tasks.log_level || vif_req->tasks.reload_psk
           || vif_req->tasks.acl;
}

static bool osw_drv_spf13_request_config_vif_is_any_hostap_cmd_still_running(
        osw_drv_spf13_request_config_vif_t *vif_req)
{
    if (vif_req == NULL) return false;

    return false
           || osw_drv_spf13_hostap_cmd_is_done_array(
                      vif_req->hostap_cmds,
                      OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_MAX)
                      == false;
}

static bool osw_drv_spf13_request_config_vif_is_any_nl_cmd_still_running(osw_drv_spf13_request_config_vif_t *vif_req)
{
    return false || osw_drv_spf13_nl_cmd_is_done_all(vif_req->acls) == false
           || osw_drv_spf13_nl_cmd_is_done_array(vif_req->nl_cmds, OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_MAX)
                      == false;
}

static bool osw_drv_spf13_request_config_vif_is_busy(osw_drv_spf13_request_config_vif_t *vif_req)
{
    return false || osw_drv_spf13_request_config_vif_is_any_task_still_planned(vif_req)
           || osw_drv_spf13_request_config_vif_is_any_hostap_cmd_still_running(vif_req)
           || osw_drv_spf13_request_config_vif_is_any_nl_cmd_still_running(vif_req)
           || osw_drv_spf13_hostap_neigh_waiter_is_done(vif_req->neigh_waiter) == false
           || ev_is_active(&vif_req->tx_power_timeout);
}

static bool osw_drv_spf13_request_config_any_vif_task_is_tx_vdev_not_ready_yet(
        osw_drv_spf13_request_config_vif_t *vif_req)
{
    if (vif_req == NULL) return false;

    osw_drv_spf13_request_config_phy_t *phy_req = vif_req->phy_req;
    if (phy_req == NULL) return false;

    const bool is_ap = vif_req->vif_conf->vif_type == OSW_VIF_AP;
    const bool is_tx_vap = vif_req->vif_conf->u.ap.mbss_mode == OSW_MBSS_TX_VAP;
    const bool is_not_mbss = vif_req->vif_conf->u.ap.mbss_mode == OSW_MBSS_NONE;
    const bool i_am_the_tx_vap = is_ap && (is_tx_vap || is_not_mbss);
    if (i_am_the_tx_vap) return false;
    if (is_ap == false) return false;

    osw_drv_spf13_request_config_vif_t *other_vif_req;
    ds_tree_foreach (&phy_req->vif_requests, other_vif_req)
    {
        if (other_vif_req == vif_req) continue;

        osw_drv_spf13_hostap_cmd_t *add_cmd =
                other_vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_ADD];
        const bool is_ap = other_vif_req->vif_conf->vif_type == OSW_VIF_AP;
        const bool is_tx_vap = other_vif_req->vif_conf->u.ap.mbss_mode == OSW_MBSS_TX_VAP;
        const bool task_add = other_vif_req->tasks.add;
        const bool add_cmd_not_done = osw_drv_spf13_hostap_cmd_is_done(add_cmd) == false;
        const bool add_not_done = task_add || add_cmd_not_done;
        if (is_ap && is_tx_vap && add_not_done)
        {
            return true;
        }
    }

    return false;
}

static void osw_drv_spf13_request_config_vif_ap_work(
        osw_drv_spf13_request_config_vif_t *vif_req,
        void (*done_cb)(void *priv),
        void *done_priv)
{
    if (vif_req == NULL) return;

    if (vif_req->vif_conf->vif_type != OSW_VIF_AP)
    {
        return;
    }

    osw_drv_spf13_request_config_pool_t *pool = vif_req->phy_req->config_req->pool;
    const char *phy_name = vif_req->phy_req->phy_name;
    const char *vif_name = vif_req->vif_name;
    const char *ctrl_path = strdupafree(osw_drv_spf13_hostap_path_hostapd_ctrl_bss(phy_name, vif_name));
    if (ctrl_path == NULL)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to get hostapd ctrl path"));
        return;
    }

    const char *group_name = vif_name;
    const char *conf_path = strdupafree(osw_drv_spf13_hostap_path_hostapd_config(vif_name));
    if (conf_path == NULL)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to get hostapd config path"));
        return;
    }

    const char *netdev_name = strdupafree(osw_drv_spf13_netdev_from_phy_and_vif(phy_name, vif_name));
    if (netdev_name == NULL)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to get netdev name"));
        return;
    }

    osw_drv_spf13_invalidations_t *invalidations = pool->invalidations;
    const uint32_t nl80211_family_id = vif_req->phy_req->config_req->pool->nl80211_family_id;
    const uint32_t ifindex = osw_drv_spf13_netdev_get_ifindex(netdev_name);
    const int mlo_link_id = osw_drv_spf13_netdev_get_hw_link_id(phy_name);
    const char *ctrl_name = osw_drv_spf13_netdev_is_qca_vap_legacy(netdev_name)
                                    ? netdev_name
                                    : strfmta("%s:%d", netdev_name, mlo_link_id);

    // FIXME: this should be done on request creation time, all of the above too
    vif_req->ifindex = ifindex;
    vif_req->mlo_link_id = mlo_link_id;

    if (vif_req->tasks.remove)
    {
        const bool is_running = access(ctrl_path, F_OK) == 0;
        osw_drv_spf13_request_config_neigh_unset(pool, phy_name, vif_name);
        if (vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_REMOVE] == NULL && is_running)
        {
            vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_REMOVE] = osw_drv_spf13_hostap_cmd_new(
                    osw_drv_spf13_hostap_sock_open(),
                    osw_drv_spf13_hostap_path_hostapd_global(),
                    strfmta("REMOVE %s", ctrl_name),
                    done_cb,
                    done_priv);
            WARN_ON(vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_REMOVE] == NULL);
            osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        }
        if (osw_drv_spf13_hostap_cmd_is_done(vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_REMOVE])
            == false)
        {
            return;
        }
        osw_drv_spf13_hostap_cmd_expect_ok(vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_REMOVE]);
        vif_req->tasks.remove = false;
        LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "removed"));
    }

    /* FIXME: This could be optimized to just wait for the sibling/associated
     * interfaces. For example, MBSS+MLD. However this is much simpler and
     * won't increase configuration time _that_ much.
     */
    if (osw_drv_spf13_request_config_any_vif_task_is_still_remove(vif_req->phy_req->config_req))
    {
        return;
    }

    /* FIXME: In order to properly add AP interfaces here all links needs to be
     * instantiated explicitly here. Then, their link addresses need to be read
     * out and use when constructing the hostapd config file (bssid= entry).
     *
     * This is a driver quirk / requirement. Without that AP will seemingly
     * run, but will not accept clients.
     */
    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(vif_req, OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD))
    {
        /* Actually any address is ignored anyway because the driver itself
         * decides what link address it will assign to the newly spawned link.
         * The address needs to be read from sysfs, or otherwise.
         */
        const struct osw_hwaddr dummy_addr = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
        if (vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD] == NULL)
        {
            vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD] = osw_drv_spf13_nl_cmd_new(
                    osw_drv_spf13_nl_80211_msg_link_add(nl80211_family_id, vif_req->ifindex, mlo_link_id, &dummy_addr),
                    strfmta("%s(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
                    done_cb,
                    done_priv);
            WARN_ON(vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD] == NULL);
            osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        }
    }

    if (osw_drv_spf13_nl_cmd_is_done(vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD]) == false)
    {
        return;
    }

    if (vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD] != NULL)
    {
        const int err =
                osw_drv_spf13_nl_cmd_get_error(vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_LINK_ADD]);
        if (err != 0)
        {
            LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to add link: %d", err));
            return;
        }
    }

    if (vif_req->tasks.add)
    {
        if (osw_drv_spf13_request_config_any_vif_task_is_tx_vdev_not_ready_yet(vif_req))
        {
            return;
        }

        if (vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_ADD] == NULL)
        {
            osw_drv_spf13_request_config_vif_gen_hostap(vif_req);

            vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_ADD] = osw_drv_spf13_hostap_cmd_new(
                    osw_drv_spf13_hostap_sock_open(),
                    osw_drv_spf13_hostap_path_hostapd_global(),
                    strfmta("ADD bss_config=%s:%s", group_name, conf_path),
                    done_cb,
                    done_priv);
            WARN_ON(vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_ADD] == NULL);
            osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        }
        if (osw_drv_spf13_hostap_cmd_is_done(vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_ADD])
            == false)
        {
            return;
        }
        osw_drv_spf13_hostap_cmd_expect_ok(vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_ADD]);
        vif_req->tasks.add = false;
        LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "added"));
    }

    if (vif_req->tasks.neigh)
    {
        if (vif_req->neigh_waiter == NULL)
        {
            osw_drv_spf13_request_config_neigh_t *neigh =
                    osw_drv_spf13_request_config_neigh_get(pool, phy_name, vif_name);
            const struct osw_ssid *ssid = &vif_req->vif_conf->u.ap.ssid;
            const struct osw_neigh_list *neigh_list = &vif_req->vif_conf->u.ap.neigh_list;
            vif_req->neigh_waiter =
                    osw_drv_spf13_hostap_neigh_syncer_set(neigh->syncer, ssid, neigh_list, done_cb, done_priv);
        }
        if (osw_drv_spf13_hostap_neigh_waiter_is_done(vif_req->neigh_waiter) == false)
        {
            return;
        }
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->tasks.neigh = false;
        LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "neigh synced"));
    }

    if (vif_req->tasks.log_level)
    {
        if (vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_LOG_LEVEL] == NULL)
        {
            vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_LOG_LEVEL] = osw_drv_spf13_hostap_cmd_new(
                    osw_drv_spf13_hostap_sock_open(),
                    ctrl_path,
                    "LOG_LEVEL DEBUG",
                    done_cb,
                    done_priv);
            WARN_ON(vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_LOG_LEVEL] == NULL);
            osw_drv_spf13_invalidations_vif(vif_req->phy_req->config_req->pool->invalidations, phy_name, vif_name);
        }
        if (osw_drv_spf13_hostap_cmd_is_done(
                    vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_LOG_LEVEL])
            == false)
        {
            return;
        }
        osw_drv_spf13_hostap_cmd_expect_ok(vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_LOG_LEVEL]);
        vif_req->tasks.log_level = false;
        LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "set log level to DEBUG"));
    }

    if (vif_req->tasks.reload_psk)
    {
        if (vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_RELOAD_PSK] == NULL)
        {
            vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_RELOAD_PSK] = osw_drv_spf13_hostap_cmd_new(
                    osw_drv_spf13_hostap_sock_open(),
                    ctrl_path,
                    "RELOAD_PSK",
                    done_cb,
                    done_priv);
            WARN_ON(vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_RELOAD_PSK] == NULL);
            osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        }
        if (osw_drv_spf13_hostap_cmd_is_done(
                    vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_RELOAD_PSK])
            == false)
        {
            return;
        }
        osw_drv_spf13_hostap_cmd_expect_ok(
                vif_req->hostap_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_RELOAD_PSK]);
        vif_req->tasks.reload_psk = false;
        LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "reloaded PSK"));
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_UAPSD))
    {
        const bool uapsd = vif_req->vif_conf->u.ap.mode.wmm_uapsd_enabled;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_UAPSD] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_uapsd_set(nl80211_family_id, ifindex, mlo_link_id, uapsd),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): uapsd: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        uapsd ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_RRM))
    {
        const bool rrm = vif_req->vif_conf->u.ap.mode.rrm_neighbor_report;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_RRM] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_rrm_set(nl80211_family_id, ifindex, mlo_link_id, rrm),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): rrm: %s", vif_name, ifindex, mlo_link_id, rrm ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_AP_BRIDGE))
    {
        const bool ap_bridge = !vif_req->vif_conf->u.ap.isolated;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_AP_BRIDGE] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_ap_bridge_set(nl80211_family_id, ifindex, mlo_link_id, ap_bridge),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): ap bridge: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        ap_bridge ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST2UCAST))
    {
        const bool mcast2ucast = vif_req->vif_conf->u.ap.mcast2ucast;
        const bool tunneling = mcast2ucast;
        const bool translating = false;
        const bool no_snooping = mcast2ucast;
        const uint32_t me = osw_drv_spf13_nl_vnd_vap_param_me_build(tunneling, translating, no_snooping);
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST2UCAST] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_me_set(nl80211_family_id, ifindex, mlo_link_id, me),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): me: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        mcast2ucast ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MBO))
    {
        const bool mbo = vif_req->vif_conf->u.ap.mbo;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MBO] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_mbo_set(nl80211_family_id, ifindex, mlo_link_id, mbo),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): mbo: %s", vif_name, ifindex, mlo_link_id, mbo ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE))
    {
        const bool oce = vif_req->vif_conf->u.ap.oce;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_oce_set(nl80211_family_id, ifindex, mlo_link_id, oce),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): oce: %s", vif_name, ifindex, mlo_link_id, oce ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_EN))
    {
        const bool oce_min_rssi_en = vif_req->vif_conf->u.ap.oce_min_rssi_enable;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_EN] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_oce_assoc_reject_set(
                        nl80211_family_id,
                        ifindex,
                        mlo_link_id,
                        oce_min_rssi_en),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): oce min rssi enable: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        oce_min_rssi_en ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_nl_cmd_is_done(vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_EN]))
    {
        if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                    vif_req,
                    OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_DBM))
        {
            const int oce_min_rssi_dbm = vif_req->vif_conf->u.ap.oce_min_rssi_dbm;
            osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
            vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_MIN_RSSI_DBM] =
                    osw_drv_spf13_nl_cmd_new(
                            osw_drv_spf13_nl_vnd_vap_param_oce_assoc_min_rssi_set(
                                    nl80211_family_id,
                                    ifindex,
                                    mlo_link_id,
                                    oce_min_rssi_dbm),
                            strfmta("%s(%" PRIu32 ":%" PRIi8 "): oce min rssi dbm: %d",
                                    vif_name,
                                    ifindex,
                                    mlo_link_id,
                                    oce_min_rssi_dbm),
                            done_cb,
                            done_priv);
        }
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_RETRY_DELAY_SEC))
    {
        const int oce_retry_delay_secs = vif_req->vif_conf->u.ap.oce_retry_delay_sec;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_OCE_RETRY_DELAY_SEC] =
                osw_drv_spf13_nl_cmd_new(
                        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_retry_delay_set(
                                nl80211_family_id,
                                ifindex,
                                mlo_link_id,
                                oce_retry_delay_secs),
                        strfmta("%s(%" PRIu32 ":%" PRIi8 "): oce retry delay secs: %d",
                                vif_name,
                                ifindex,
                                mlo_link_id,
                                oce_retry_delay_secs),
                        done_cb,
                        done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MAX_STA))
    {
        const uint32_t max_sta = vif_req->vif_conf->u.ap.max_sta;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MAX_STA] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_max_sta_set(nl80211_family_id, ifindex, mlo_link_id, max_sta),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): max sta: %d", vif_name, ifindex, mlo_link_id, max_sta),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_DL_MU_OFDMA))
    {
        const bool ofdma_enabled = osw_drv_spf13_request_config_mu_ofdma_enabled();
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_DL_MU_OFDMA] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_he_dl_mu_ofdma_set(
                        nl80211_family_id,
                        ifindex,
                        mlo_link_id,
                        ofdma_enabled),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): HE DL MU OFDMA: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        ofdma_enabled ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_UL_MU_OFDMA))
    {
        const bool ofdma_enabled = osw_drv_spf13_request_config_mu_ofdma_enabled();
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_HE_UL_MU_OFDMA] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_he_ul_mu_ofdma_set(
                        nl80211_family_id,
                        ifindex,
                        mlo_link_id,
                        ofdma_enabled),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): HE UL MU OFDMA: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        ofdma_enabled ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_DL_MU_OFDMA))
    {
        const bool ofdma_enabled = osw_drv_spf13_request_config_mu_ofdma_enabled();
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_DL_MU_OFDMA] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_eht_dl_mu_ofdma_set(
                        nl80211_family_id,
                        ifindex,
                        mlo_link_id,
                        ofdma_enabled),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): EHT DL MU OFDMA: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        ofdma_enabled ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_UL_MU_OFDMA))
    {
        const bool ofdma_enabled = osw_drv_spf13_request_config_mu_ofdma_enabled();
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_EHT_UL_MU_OFDMA] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_eht_ul_mu_ofdma_set(
                        nl80211_family_id,
                        ifindex,
                        mlo_link_id,
                        ofdma_enabled),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): EHT UL MU OFDMA: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        ofdma_enabled ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ATHNEWIND))
    {
        const bool athnewind_enabled = true;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ATHNEWIND] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_athnewind_set(
                        nl80211_family_id,
                        ifindex,
                        mlo_link_id,
                        athnewind_enabled),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): athnewind: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        athnewind_enabled ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_POWERSAVE))
    {
        const bool powersave_enabled = false;
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_POWERSAVE] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_powersave_set(
                        nl80211_family_id,
                        ifindex,
                        mlo_link_id,
                        powersave_enabled),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): power save: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        powersave_enabled ? "true" : "false"),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_SET_TX_POWER))
    {
        const int dbm = vif_req->vif_conf->tx_power_dbm;
        const int mbm = dbm * 100;
        const bool automatic = mbm == 0;
        struct nl_msg *msg =
                automatic ? osw_drv_spf13_nl_80211_msg_set_tx_power_auto(nl80211_family_id, ifindex, mlo_link_id)
                          : osw_drv_spf13_nl_80211_msg_set_tx_power_fixed(nl80211_family_id, ifindex, mlo_link_id, mbm);
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_SET_TX_POWER] = osw_drv_spf13_nl_cmd_new(
                msg,
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): tx power: %d dBm (%s)",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        dbm,
                        automatic ? "automatic" : "fixed"),
                done_cb,
                done_priv);

        ev_timer_start(EV_DEFAULT_ & vif_req->tx_power_check);
        ev_timer_start(EV_DEFAULT_ & vif_req->tx_power_timeout);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCN_RATE))
    {
        const int bcn_kbps = osw_rate_legacy_to_kbps(vif_req->vif_conf->u.ap.mode.beacon_rate.u.legacy);
        switch (vif_req->vif_conf->u.ap.mode.beacon_rate.type)
        {
            case OSW_BEACON_RATE_UNSPEC:
                return;
            case OSW_BEACON_RATE_ABG:
                osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
                vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCN_RATE] = osw_drv_spf13_nl_cmd_new(
                        osw_drv_spf13_nl_vnd_vap_param_bcn_rate_set(nl80211_family_id, ifindex, mlo_link_id, bcn_kbps),
                        strfmta("%s(%" PRIu32 ":%" PRIi8 "): beacon rate: %d kbps",
                                vif_name,
                                ifindex,
                                mlo_link_id,
                                bcn_kbps),
                        done_cb,
                        done_priv);
                break;
            case OSW_BEACON_RATE_HT:
                LOGW(LOG_PREFIX_VIF(phy_name, vif_name, "beacon rate is HT, not supported"));
                break;
            case OSW_BEACON_RATE_VHT:
                LOGW(LOG_PREFIX_VIF(phy_name, vif_name, "beacon rate is VHT, not supported"));
                break;
            case OSW_BEACON_RATE_HE:
                LOGW(LOG_PREFIX_VIF(phy_name, vif_name, "beacon rate is HE, not supported"));
                break;
        }
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MGMT_RATE))
    {
        const uint32_t mgmt_kbps = osw_rate_legacy_to_kbps(vif_req->vif_conf->u.ap.mode.mgmt_rate);
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MGMT_RATE] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_mgmt_rate_set(nl80211_family_id, ifindex, mlo_link_id, mgmt_kbps),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): mgmt rate: %d kbps", vif_name, ifindex, mlo_link_id, mgmt_kbps),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST_RATE))
    {
        const uint32_t mcast_kbps = osw_rate_legacy_to_kbps(vif_req->vif_conf->u.ap.mode.mcast_rate);
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_MCAST_RATE] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_mcast_rate_set(nl80211_family_id, ifindex, mlo_link_id, mcast_kbps),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): mcast rate: %d kbps", vif_name, ifindex, mlo_link_id, mcast_kbps),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCAST_RATE))
    {
        const uint32_t mcast_kbps = osw_rate_legacy_to_kbps(vif_req->vif_conf->u.ap.mode.mcast_rate);
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_BCAST_RATE] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_vap_param_bcast_rate_set(nl80211_family_id, ifindex, mlo_link_id, mcast_kbps),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): bcast rate: %d kbps", vif_name, ifindex, mlo_link_id, mcast_kbps),
                done_cb,
                done_priv);
    }

    if (osw_drv_spf13_request_config_nl_cmds_planned_consume(
                vif_req,
                OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ACL_POLICY))
    {
        const uint32_t acl_policy = osw_drv_spf13_nl_vnd_acl_policy_to_u32(vif_req->vif_conf->u.ap.acl_policy);
        osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
        vif_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_VND_SET_ACL_POLICY] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_acl_policy_set(nl80211_family_id, ifindex, mlo_link_id, acl_policy),
                strfmta("%s(%" PRIu32 ":%" PRIi8 "): acl policy: %s",
                        vif_name,
                        ifindex,
                        mlo_link_id,
                        osw_acl_policy_to_str(acl_policy)),
                done_cb,
                done_priv);
    }

    if (vif_req->tasks.acl)
    {
        vif_req->tasks.acl = false;
        LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "updating acls"));
        const struct osw_hwaddr_list *acl_to_del = &vif_req->vif_conf->u.ap.acl_del;
        const struct osw_hwaddr_list *acl_to_add = &vif_req->vif_conf->u.ap.acl_add;
        for (size_t i = 0; i < acl_to_del->count; i++)
        {
            const struct osw_hwaddr *addr = &acl_to_del->list[i];
            osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
            vif_req->acls = osw_drv_spf13_nl_cmd_extend(
                    vif_req->acls,
                    osw_drv_spf13_nl_cmd_new(
                            osw_drv_spf13_nl_vnd_acl_del(nl80211_family_id, ifindex, mlo_link_id, addr),
                            strfmta("%s(%" PRIu32 ":%" PRIi8 "): acl: -" OSW_HWADDR_FMT,
                                    vif_name,
                                    ifindex,
                                    mlo_link_id,
                                    OSW_HWADDR_ARG(addr)),
                            done_cb,
                            done_priv));
        }
        for (size_t i = 0; i < acl_to_add->count; i++)
        {
            const struct osw_hwaddr *addr = &acl_to_add->list[i];
            osw_drv_spf13_invalidations_vif(invalidations, phy_name, vif_name);
            vif_req->acls = osw_drv_spf13_nl_cmd_extend(
                    vif_req->acls,
                    osw_drv_spf13_nl_cmd_new(
                            osw_drv_spf13_nl_vnd_acl_add(nl80211_family_id, ifindex, mlo_link_id, addr),
                            strfmta("%s(%" PRIu32 ":%" PRIi8 "): acl: +" OSW_HWADDR_FMT,
                                    vif_name,
                                    ifindex,
                                    mlo_link_id,
                                    OSW_HWADDR_ARG(addr)),
                            done_cb,
                            done_priv));
        }
    }
}

static void osw_drv_spf13_request_config_vif_sta_work(osw_drv_spf13_request_config_vif_t *vif_req)
{
    if (vif_req == NULL) return;
    if (vif_req->vif_conf->vif_type != OSW_VIF_STA)
    {
        return;
    }

    // FIXME
}

static bool osw_drv_spf13_request_config_phy_vifs_are_busy(osw_drv_spf13_request_config_phy_t *phy_req)
{
    if (phy_req == NULL) return false;

    osw_drv_spf13_request_config_vif_t *vif_req;
    ds_tree_foreach (&phy_req->vif_requests, vif_req)
    {
        if (osw_drv_spf13_request_config_vif_is_busy(vif_req))
        {
            return true;
        }
    }

    return false;
}
static void osw_drv_spf13_request_config_phy_work(
        osw_drv_spf13_request_config_phy_t *phy_req,
        void (*done_cb)(void *priv),
        void *done_priv)
{
    if (phy_req == NULL) return;

    const char *phy_name = phy_req->phy_name;
    const uint32_t ifindex = osw_drv_spf13_netdev_get_ifindex(phy_name);
    const uint32_t nl80211_family_id = phy_req->config_req->pool->nl80211_family_id;

    if (phy_req->tasks.down)
    {
        LOGI(LOG_PREFIX_PHY(phy_name, "bringing down phy"));
        /* FIXME: Ideally should be async, but this is simpler for now. */
        os_nif_up(phy_name, false);
        phy_req->tasks.down = false;
        osw_drv_spf13_invalidations_phy(phy_req->config_req->pool->invalidations, phy_name);
    }

    if (phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_FREQ])
    {
        phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_FREQ] = false;
        const int freq_mhz = phy_req->phy_conf->radar_next_channel.control_freq_mhz;
        osw_drv_spf13_invalidations_phy(phy_req->config_req->pool->invalidations, phy_name);
        phy_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_FREQ] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_radio_param_next_radar_freq_set(nl80211_family_id, ifindex, freq_mhz),
                strfmta("%s(%" PRIu32 "): next radar freq: %d MHz", phy_name, ifindex, freq_mhz),
                done_cb,
                done_priv);
    }

    if (phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_WIDTH])
    {
        phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_WIDTH] = false;
        const int width_mhz = osw_channel_width_to_mhz(phy_req->phy_conf->radar_next_channel.width);
        osw_drv_spf13_invalidations_phy(phy_req->config_req->pool->invalidations, phy_name);
        phy_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_SET_NEXT_RADAR_WIDTH] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_radio_param_next_radar_width_set(nl80211_family_id, ifindex, width_mhz),
                strfmta("%s(%" PRIu32 "): next radar width: %d MHz", phy_name, ifindex, width_mhz),
                done_cb,
                done_priv);
    }

    if (phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_TX_CHAINMASK])
    {
        phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_TX_CHAINMASK] = false;
        const int chainmask = phy_req->phy_conf->tx_chainmask;
        osw_drv_spf13_invalidations_phy(phy_req->config_req->pool->invalidations, phy_name);
        phy_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_TX_CHAINMASK] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_radio_param_tx_chainmask_set(nl80211_family_id, ifindex, chainmask),
                strfmta("%s(%" PRIu32 "): tx chainmask: 0x%04x", phy_name, ifindex, chainmask),
                done_cb,
                done_priv);
    }

    if (phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_RX_CHAINMASK])
    {
        phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_RX_CHAINMASK] = false;
        const int chainmask = phy_req->phy_conf->tx_chainmask;
        osw_drv_spf13_invalidations_phy(phy_req->config_req->pool->invalidations, phy_name);
        phy_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VNC_SET_RX_CHAINMASK] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_radio_param_rx_chainmask_set(nl80211_family_id, ifindex, chainmask),
                strfmta("%s(%" PRIu32 "): rx chainmask: 0x%04x", phy_name, ifindex, chainmask),
                done_cb,
                done_priv);
    }

    if (phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_CHANSWITCH])
    {
        phy_req->nl_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_CHANSWITCH] = false;
        const struct osw_channel *c = &phy_req->channel;
        const int tbtt = OSW_DRV_SPF13_REQUEST_CONFIG_CHANSWITCH_TBTT_DEFAULT;
        phy_req->nl_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_VND_CHANSWITCH] = osw_drv_spf13_nl_cmd_new(
                osw_drv_spf13_nl_vnd_radio_chanswitch(nl80211_family_id, ifindex, c, tbtt),
                strfmta("%s(%" PRIu32 "): channel switch: " OSW_CHANNEL_FMT, phy_name, ifindex, OSW_CHANNEL_ARG(c)),
                done_cb,
                done_priv);
    }

    if (phy_req->tasks.up)
    {
        LOGI(LOG_PREFIX_PHY(phy_name, "bringing up phy"));
        /* FIXME: Ideally should be async, but this is simpler for now. */
        os_nif_up(phy_name, true);
        phy_req->tasks.up = false;
        osw_drv_spf13_invalidations_phy(phy_req->config_req->pool->invalidations, phy_name);
    }

    size_t vif_i;
    for (vif_i = 0; vif_i < phy_req->phy_conf->vif_list.count; vif_i++)
    {
        struct osw_drv_vif_config *vif_conf = &phy_req->phy_conf->vif_list.list[vif_i];
        const char *vif_name = vif_conf->vif_name;
        if (vif_name == NULL) continue;

        osw_drv_spf13_request_config_vif_t *vif_req = osw_drv_spf13_request_config_vif_find_or_new(phy_req, vif_name);
        vif_req->vif_conf = vif_conf;

        osw_drv_spf13_request_config_vif_ap_work(vif_req, done_cb, done_priv);
        osw_drv_spf13_request_config_vif_sta_work(vif_req);
    }

    if (osw_drv_spf13_request_config_phy_vifs_are_busy(phy_req))
    {
        return;
    }

    if (osw_drv_spf13_nl_cmd_is_done_array(phy_req->nl_cmds, OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_MAX) == false)
    {
        return;
    }

    /* For some reason the wifiX interfaces are not always up after
     * (re)configuring vifs.
     *
     * For good measure make sure the phy interfaces are up to avoid confsync
     * re-configuring soon after again.
     *
     * FIXME: This should ideally be async.
     */
    {
        bool is_up = false;
        os_nif_is_up(phy_name, &is_up);
        if (is_up != phy_req->phy_conf->enabled)
        {
            LOGI(LOG_PREFIX_PHY(
                    phy_name,
                    "bringing %s phy because it's %s",
                    phy_req->phy_conf->enabled ? "up" : "down",
                    is_up ? "up" : "down"));
            os_nif_up(phy_name, phy_req->phy_conf->enabled);
            osw_drv_spf13_invalidations_phy(phy_req->config_req->pool->invalidations, phy_name);
        }
    }
}

static void osw_drv_spf13_request_config_work(
        osw_drv_spf13_request_config_t *req,
        void (*done_cb)(void *priv),
        void *done_priv)
{
    if (req == NULL) return;

    size_t phy_i;
    for (phy_i = 0; phy_i < req->drv_conf->n_phy_list; phy_i++)
    {
        struct osw_drv_phy_config *phy_conf = &req->drv_conf->phy_list[phy_i];
        const char *phy_name = phy_conf->phy_name;
        if (phy_name == NULL) continue;

        osw_drv_spf13_request_config_phy_t *phy_req = osw_drv_spf13_request_config_phy_find_or_new(req, phy_name);
        osw_drv_spf13_request_config_phy_work(phy_req, done_cb, done_priv);
    }
}

static void osw_drv_spf13_request_config_vif_drop(osw_drv_spf13_request_config_vif_t *vif_req)
{
    if (vif_req == NULL) return;

    ev_timer_stop(EV_DEFAULT, &vif_req->tx_power_check);
    ev_timer_stop(EV_DEFAULT, &vif_req->tx_power_timeout);
    osw_drv_spf13_hostap_neigh_waiter_drop(vif_req->neigh_waiter);
    osw_drv_spf13_hostap_cmd_drop_array(vif_req->hostap_cmds, OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_MAX);
    osw_drv_spf13_nl_cmd_drop_all(vif_req->acls);
    osw_drv_spf13_nl_cmd_drop_array(vif_req->nl_cmds, OSW_DRV_SPF13_REQUEST_CONFIG_VIF_NL_CMD_MAX);
    ds_tree_remove(&vif_req->phy_req->vif_requests, vif_req);
    FREE(vif_req->vif_name);
    FREE(vif_req);
}

static void osw_drv_spf13_request_config_phy_drop(osw_drv_spf13_request_config_phy_t *phy_req)
{
    if (phy_req == NULL) return;

    osw_drv_spf13_request_config_vif_t *vif_req;
    while ((vif_req = ds_tree_head(&phy_req->vif_requests)) != NULL)
    {
        osw_drv_spf13_request_config_vif_drop(vif_req);
    }

    osw_drv_spf13_nl_cmd_drop_array(phy_req->nl_cmds, OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_MAX);
    ds_tree_remove(&phy_req->config_req->phy_requests, phy_req);
    FREE(phy_req->phy_name);
    FREE(phy_req);
}

static void osw_drv_spf13_request_config_drop(osw_drv_spf13_request_config_t *req)
{
    if (req == NULL) return;
    if (WARN_ON(req->pool == NULL)) return;

    ev_timer_stop(EV_DEFAULT, &req->timeout);

    osw_drv_spf13_request_config_phy_t *phy_req;
    while ((phy_req = ds_tree_head(&req->phy_requests)) != NULL)
    {
        osw_drv_spf13_request_config_phy_drop(phy_req);
    }

    osw_drv_spf13_invalidations_lock_drop(req->invalidations_lock);
    req->invalidations_lock = NULL;

    req->pool->req = NULL;

    osw_drv_conf_free(req->drv_conf);
    FREE(req);
}

static void osw_drv_spf13_request_config_log_errors(osw_drv_spf13_request_config_t *req)
{
    if (req == NULL) return;

    /* These use LOGN because it makes little sense to splat LOGE and
     * TRACEBACK. The relevant context is long gone. This is intended to serve
     * as a summary in case something didn't go as expected.
     */

    osw_drv_spf13_request_config_phy_t *phy_req;
    ds_tree_foreach (&req->phy_requests, phy_req)
    {
        const char *phy_name = phy_req->phy_name;
        if (phy_name == NULL) continue;

        for (size_t i = 0; i < ARRAY_SIZE(phy_req->nl_cmds); i++)
        {
            const int nl_err = osw_drv_spf13_nl_cmd_get_error(phy_req->nl_cmds[i]);
            if (nl_err != 0)
            {
                LOGN(LOG_PREFIX_PHY(
                        phy_name,
                        "nl_cmd: %s: %s: error: %d (%s)",
                        osw_drv_spf13_request_config_phy_nl_cmd_to_cstr(i),
                        osw_drv_spf13_nl_cmd_get_id(phy_req->nl_cmds[i]),
                        nl_err,
                        nl_geterror(nl_err)));
            }
        }

        osw_drv_spf13_request_config_vif_t *vif_req;
        ds_tree_foreach (&phy_req->vif_requests, vif_req)
        {
            const char *vif_name = vif_req->vif_name;
            if (vif_name == NULL) continue;

            for (size_t i = 0; i < ARRAY_SIZE(vif_req->nl_cmds); i++)
            {
                const int nl_err = osw_drv_spf13_nl_cmd_get_error(vif_req->nl_cmds[i]);
                if (nl_err != 0)
                {
                    LOGN(LOG_PREFIX_VIF(
                            phy_name,
                            vif_name,
                            "nl_cmd: %s: %s: error: %d (%s)",
                            osw_drv_spf13_request_config_vif_nl_cmd_to_cstr(i),
                            osw_drv_spf13_nl_cmd_get_id(vif_req->nl_cmds[i]),
                            nl_err,
                            nl_geterror(nl_err)));
                }
            }

            osw_drv_spf13_nl_cmd_t **acls;
            for (acls = vif_req->acls; acls != NULL && *acls != NULL; acls++)
            {
                const int nl_err = osw_drv_spf13_nl_cmd_get_error(*acls);
                if (nl_err != 0)
                {
                    LOGN(LOG_PREFIX_VIF(
                            phy_name,
                            vif_name,
                            "acl nl_cmd: %s: error: %d (%s)",
                            osw_drv_spf13_nl_cmd_get_id(*acls),
                            nl_err,
                            nl_geterror(nl_err)));
                }
            }
        }
    }
}

static void osw_drv_spf13_request_config_complete(osw_drv_spf13_request_config_t *req)
{
    if (req == NULL) return;

    const int64_t elapsed = clock_mono_ms() - req->started_on;
    LOGI(LOG_PREFIX("config request completed in %" PRIi64 " ms", elapsed));

    osw_drv_spf13_request_config_log_errors(req);
    osw_drv_spf13_request_config_drop(req);
}

static bool osw_drv_spf13_request_config_phy_is_any_task_still_planned(osw_drv_spf13_request_config_phy_t *phy_req)
{
    if (phy_req == NULL) return false;

    for (size_t i = 0; i < ARRAY_SIZE(phy_req->nl_cmds_planned); i++)
    {
        if (phy_req->nl_cmds_planned[i])
        {
            return true;
        }
    }

    return false || phy_req->tasks.down || phy_req->tasks.up;
}

static bool osw_drv_spf13_request_config_phy_is_any_nl_cmd_still_running(osw_drv_spf13_request_config_phy_t *phy_req)
{
    if (phy_req == NULL) return false;

    return false
           || osw_drv_spf13_nl_cmd_is_done_array(phy_req->nl_cmds, OSW_DRV_SPF13_REQUEST_CONFIG_PHY_NL_CMD_MAX)
                      == false;
}

static bool osw_drv_spf13_request_config_is_ready(osw_drv_spf13_request_config_t *req)
{
    if (req == NULL) return true;

    osw_drv_spf13_request_config_phy_t *phy_req;
    ds_tree_foreach (&req->phy_requests, phy_req)
    {
        const bool busy = false || osw_drv_spf13_request_config_phy_is_any_task_still_planned(phy_req)
                          || osw_drv_spf13_request_config_phy_is_any_nl_cmd_still_running(phy_req)
                          || osw_drv_spf13_request_config_phy_vifs_are_busy(phy_req);
        if (busy) return false;
    }

    return true;
}

static void osw_drv_spf13_request_config_poll(void *priv)
{
    osw_drv_spf13_request_config_t *req = priv;
    if (req == NULL) return;
    osw_drv_spf13_request_config_work(req, osw_drv_spf13_request_config_poll, req);
    if (osw_drv_spf13_request_config_is_ready(req) == false) return;
    osw_drv_spf13_request_config_complete(req);
}

static void osw_drv_spf13_request_config_kickoff(osw_drv_spf13_request_config_t *req)
{
    req->started_on = clock_mono_ms();
    osw_drv_spf13_request_config_prep_configs(req, osw_drv_spf13_request_config_poll, req);
    osw_drv_spf13_request_config_derive_tasks(req);
    osw_drv_spf13_request_config_poll(req);
}

static const char *osw_drv_spf13_request_config_vif_hostap_cmd_to_cstr(
        osw_drv_spf13_request_config_vif_hostap_cmd_t cmd)
{
    switch (cmd)
    {
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_REMOVE:
            return "remove";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_ADD:
            return "add";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_LOG_LEVEL:
            return "log_level";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_RELOAD_PSK:
            return "reload_psk";
        case OSW_DRV_SPF13_REQUEST_CONFIG_VIF_HOSTAP_CMD_MAX:
            break;
    }
    return "unknown";
}

static void osw_drv_spf13_request_config_log_timeout(osw_drv_spf13_request_config_t *req)
{
    if (req == NULL) return;

    osw_drv_spf13_request_config_phy_t *phy_req;
    ds_tree_foreach (&req->phy_requests, phy_req)
    {
        const char *phy_name = phy_req->phy_name;
        if (phy_name == NULL) continue;

        for (size_t i = 0; i < ARRAY_SIZE(phy_req->nl_cmds); i++)
        {
            const int not_done = osw_drv_spf13_nl_cmd_is_done(phy_req->nl_cmds[i]) == false;
            if (not_done)
            {
                LOGI(LOG_PREFIX_PHY(
                        phy_name,
                        "nl_cmd: %s: %s: timed out",
                        osw_drv_spf13_request_config_phy_nl_cmd_to_cstr(i),
                        osw_drv_spf13_nl_cmd_get_id(phy_req->nl_cmds[i])));
            }
        }

        if (phy_req->tasks.up)
        {
            LOGI(LOG_PREFIX_PHY(phy_name, "up task: timed out"));
        }

        if (phy_req->tasks.down)
        {
            LOGI(LOG_PREFIX_PHY(phy_name, "down task: timed out"));
        }

        osw_drv_spf13_request_config_vif_t *vif_req;
        ds_tree_foreach (&phy_req->vif_requests, vif_req)
        {
            const char *vif_name = vif_req->vif_name;
            if (vif_name == NULL) continue;

            if (vif_req->tasks.remove)
            {
                LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "remove task: timed out"));
            }

            if (vif_req->tasks.add)
            {
                LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "add task: timed out"));
            }

            if (vif_req->tasks.reload_psk)
            {
                LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "reload psk task: timed out"));
            }

            if (vif_req->tasks.log_level)
            {
                LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "log level task: timed out"));
            }

            if (vif_req->tasks.neigh)
            {
                LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "neigh task: timed out"));
            }

            if (vif_req->tasks.acl)
            {
                LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "acl task: timed out"));
            }

            for (size_t i = 0; i < ARRAY_SIZE(vif_req->nl_cmds); i++)
            {
                const int not_done = osw_drv_spf13_nl_cmd_is_done(vif_req->nl_cmds[i]) == false;
                if (not_done)
                {
                    LOGI(LOG_PREFIX_VIF(
                            phy_name,
                            vif_name,
                            "nl_cmd: %s: %s: timed out",
                            osw_drv_spf13_request_config_vif_nl_cmd_to_cstr(i),
                            osw_drv_spf13_nl_cmd_get_id(vif_req->nl_cmds[i])));
                }
            }

            osw_drv_spf13_nl_cmd_t **acls;
            for (acls = vif_req->acls; acls != NULL && *acls != NULL; acls++)
            {
                const int not_done = osw_drv_spf13_nl_cmd_is_done(*acls) == false;
                if (not_done)
                {
                    LOGI(LOG_PREFIX_VIF(
                            phy_name,
                            vif_name,
                            "acl nl_cmd: %s: timed out",
                            osw_drv_spf13_nl_cmd_get_id(*acls)));
                }
            }

            for (size_t i = 0; i < ARRAY_SIZE(vif_req->hostap_cmds); i++)
            {
                const int not_done = osw_drv_spf13_hostap_cmd_is_done(vif_req->hostap_cmds[i]) == false;
                if (not_done)
                {
                    LOGI(LOG_PREFIX_VIF(
                            phy_name,
                            vif_name,
                            "hostap cmd: %s: timed out",
                            osw_drv_spf13_request_config_vif_hostap_cmd_to_cstr(i)));
                }
            }
        }
    }
}

static void osw_drv_spf13_request_config_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_request_config_t *req = w->data;
    if (req == NULL) return;

    osw_drv_spf13_request_config_pool_t *pool = req->pool;
    if (WARN_ON(pool == NULL)) return;

    LOGN(LOG_PREFIX("config request timed out, dropping"));
    osw_drv_spf13_request_config_log_timeout(req);
    osw_drv_spf13_request_config_drop(req);
}

osw_drv_spf13_request_config_t *osw_drv_spf13_request_config_new(
        osw_drv_spf13_request_config_pool_t *pool,
        struct osw_drv_conf *drv_conf)
{
    if (drv_conf == NULL)
    {
        LOGW(LOG_PREFIX("config request with NULL conf, ignoring"));
        return NULL;
    }

    osw_drv_spf13_request_config_t *req = CALLOC(1, sizeof(*req));
    ev_timer_init(&req->timeout, osw_drv_spf13_request_config_timeout_cb, OSW_DRV_SPF13_REQUEST_CONFIG_TIMEOUT_SEC, 0);
    req->timeout.data = req;
    req->pool = pool;
    req->drv_conf = drv_conf;
    ds_tree_init(&req->phy_requests, ds_str_cmp, osw_drv_spf13_request_config_phy_t, node);
    req->invalidations_lock = osw_drv_spf13_invalidations_lock(req->pool->invalidations);
    ev_timer_start(EV_DEFAULT_ & req->timeout);
    return req;
}

void osw_drv_spf13_request_config(osw_drv_spf13_request_config_pool_t *pool, struct osw_drv_conf *drv_conf)
{
    if (pool == NULL)
    {
        LOGW(LOG_PREFIX("config pool with NULL, ignoring"));
        return;
    }

    if (drv_conf == NULL)
    {
        LOGW(LOG_PREFIX("config request with NULL conf, ignoring"));
        return;
    }

    if (pool->req != NULL)
    {
        LOGW(LOG_PREFIX("config request already in progress, dropping old request"));
        osw_drv_spf13_request_config_drop(pool->req);
    }

    pool->req = osw_drv_spf13_request_config_new(pool, drv_conf);
    if (pool->req == NULL)
    {
        LOGW(LOG_PREFIX("failed to create config request, dropping"));
        return;
    }

    osw_drv_spf13_request_config_kickoff(pool->req);
}

osw_drv_spf13_request_config_pool_t *osw_drv_spf13_request_config_pool_new(
        osw_drv_spf13_invalidations_t *invalidations,
        uint32_t nl80211_family_id)
{
    if (invalidations == NULL)
    {
        LOGW(LOG_PREFIX("config pool with NULL invalidations, ignoring"));
        return NULL;
    }

    osw_drv_spf13_request_config_pool_t *pool = CALLOC(1, sizeof(*pool));
    ds_tree_init(&pool->neigh_syncers, ds_str_cmp, osw_drv_spf13_request_config_neigh_t, node);
    pool->invalidations = invalidations;
    pool->nl80211_family_id = nl80211_family_id;
    return pool;
}

static void osw_drv_spf13_request_config_pool_sync_neigh_done_cb(void *priv)
{
    osw_drv_spf13_request_config_neigh_t *neigh = priv;
    if (neigh == NULL) return;

    LOGD(LOG_PREFIX_VIF(neigh->phy_name, neigh->vif_name, "neigh sync done"));
    osw_drv_spf13_hostap_neigh_waiter_drop(neigh->resync_waiter);
    neigh->resync_waiter = NULL;
}

void osw_drv_spf13_request_config_pool_sync_neigh(osw_drv_spf13_request_config_pool_t *pool, const char *vif_name)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_config_neigh_t *neigh = ds_tree_find(&pool->neigh_syncers, vif_name);
    osw_drv_spf13_hostap_neigh_waiter_drop(neigh->resync_waiter);
    neigh->resync_waiter = osw_drv_spf13_hostap_neigh_syncer_resync(
            neigh->syncer,
            osw_drv_spf13_request_config_pool_sync_neigh_done_cb,
            neigh);
}

void osw_drv_spf13_request_config_pool_sync_neigh_all(osw_drv_spf13_request_config_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_config_neigh_t *neigh;
    ds_tree_foreach (&pool->neigh_syncers, neigh)
    {
        osw_drv_spf13_request_config_pool_sync_neigh(pool, neigh->vif_name);
    }
}

void osw_drv_spf13_request_config_pool_drop(osw_drv_spf13_request_config_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_config_drop(pool->req);
    FREE(pool);
}
