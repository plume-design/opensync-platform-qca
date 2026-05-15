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
#include <os_nif.h>

/* 3rd party */
#include <ev.h>
#include <netlink/genl/genl.h>

/* osw */
#include <osw_drv.h>
#include <osw_hostap_common.h>
#include <osw_hostap_conf.h>
#include <osw_wpas_conf.h>

/* local */
#include "os_time.h"
#include "osw_drv_spf13_hostap_cmd.h"
#include "osw_drv_spf13_hostap_path.h"
#include "osw_drv_spf13_hostap_sock.h"
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_nl_80211.h"
#include "osw_drv_spf13_nl_cmd.h"
#include "osw_drv_spf13_nl_vnd.h"
#include "osw_types.h"
#include "osw_drv_spf13_request_vif_state.h"
#include "osw_drv_spf13_request_config_mldsta.h"

#define OSW_DRV_SPF13_VIF_REQUEST_TIMEOUT_SEC 10

struct osw_drv_spf13_request_vif_state_pool
{
    ds_tree_t requests; /* osw_drv_spf13_request_vif_state_t */
    struct osw_drv *drv;
    uint32_t nl80211_family_id;
};

enum osw_drv_spf13_request_vif_state_nl_cmd
{
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_GET_INTERFACE,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_DUMP_SCAN,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_ACL,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_ACL_POLICY,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_BCN_RATE,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MGMT_RATE,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MCAST_RATE,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_BCAST_RATE,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_RRM,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MCAST2UCAST,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBSS_EN,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBSS_TX_VDEV,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBSS_GROUP,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_AP_BRIDGE,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_UAPSD,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_VDEV_UP,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBO,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE_MIN_RSSI_DBM,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE_MIN_RSSI_EN,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE_RETRY_DELAY_SEC,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MAX_STA,

    // These are todo. once done, move upward.
    // OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_CAC_STATE, // might be unnecessary, VDEV_UP probably is enough?
    // OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MAX_RATE, // maybe unnecessary, VDEV_UP probably is enough?
    // OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_WDS,
    // OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_PUNCTURE_BITMAP, // maybe unnecessary?
    // proxy arp?
    // dgaf?

    /* keep last */
    OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_MAX
};
typedef enum osw_drv_spf13_request_vif_state_nl_cmd osw_drv_spf13_request_vif_state_nl_cmd_t;

enum osw_drv_spf13_request_vif_state_hostap_cmd
{
    OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_STATUS,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_GET_CONFIG,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_SHOW_NEIGHBOR,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_GET_RXKHS,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_WPS_GET_STATUS,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_MIB,

    /* keep last */
    OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_MAX
};
typedef enum osw_drv_spf13_request_vif_state_hostap_cmd osw_drv_spf13_request_vif_state_hostap_cmd_t;

enum osw_drv_spf13_request_vif_state_wpas_cmd
{
    OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_STATUS,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_MLO_STATUS,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_LIST_NETWORKS,
    OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_MIB,

    /* keep last */
    OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_MAX
};
typedef enum osw_drv_spf13_request_vif_state_wpas_cmd osw_drv_spf13_request_vif_state_wpas_cmd_t;

struct osw_drv_spf13_request_vif_state
{
    ds_tree_node_t node;
    osw_drv_spf13_request_vif_state_pool_t *pool;
    char *phy_name;
    char *vif_name;
    char *ctrl_path_wpas;
    osw_drv_spf13_nl_cmd_t *nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_MAX];
    osw_drv_spf13_hostap_cmd_t *hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_MAX];
    osw_drv_spf13_hostap_cmd_t *wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_MAX];
    osw_drv_spf13_hostap_cmd_t **wpas_get_id_str;
    ev_timer timeout;
    int64_t started_on;
};

typedef struct osw_drv_spf13_request_vif_state osw_drv_spf13_request_vif_state_t;

static void osw_drv_spf13_request_vif_state_drop(osw_drv_spf13_request_vif_state_t *req)
{
    if (req == NULL) return;
    if (WARN_ON(req->pool == NULL)) return;

    ds_tree_remove(&req->pool->requests, req);
    req->pool = NULL;
    ev_timer_stop(EV_DEFAULT_ & req->timeout);
    osw_drv_spf13_nl_cmd_drop_array(req->nl_cmds, OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_MAX);
    osw_drv_spf13_hostap_cmd_drop_array(req->hostap_cmds, OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_MAX);
    osw_drv_spf13_hostap_cmd_drop_array(req->wpas_cmds, OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_MAX);
    FREE(req->phy_name);
    FREE(req->vif_name);
    FREE(req->ctrl_path_wpas);
    FREE(req);
}

static void osw_drv_spf13_vif_fill_dump_scan(struct osw_drv_vif_state *vif_state, osw_drv_spf13_nl_cmd_t *dump_scan)
{
    if (vif_state == NULL || dump_scan == NULL) return;

    // FIXME
}

static void osw_drv_spf13_hostap_fill_status(
        struct osw_drv_vif_state *vif_state,
        osw_drv_spf13_request_vif_state_t *req)
{
    if (vif_state == NULL || req == NULL) return;
    if (vif_state->vif_type != OSW_VIF_AP) return;

    LOGT(LOG_PREFIX_VIF(req->phy_name, req->vif_name, "filling hostap status"));

    const char *vif_name = req->vif_name;
    const char *conf_path = strdupafree(osw_drv_spf13_hostap_path_hostapd_config(vif_name));
    const char *psks_path = strdupafree(osw_drv_spf13_hostap_path_hostapd_pskfile(vif_name));

    osw_drv_spf13_hostap_cmd_t *hostap_status = req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_STATUS];
    osw_drv_spf13_hostap_cmd_t *hostap_get_config =
            req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_GET_CONFIG];
    osw_drv_spf13_hostap_cmd_t *hostap_show_neighbor =
            req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_SHOW_NEIGHBOR];
    osw_drv_spf13_hostap_cmd_t *hostap_get_rxkhs =
            req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_GET_RXKHS];
    osw_drv_spf13_hostap_cmd_t *hostap_wps_get_status =
            req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_WPS_GET_STATUS];
    osw_drv_spf13_hostap_cmd_t *hostap_mib = req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_MIB];

    const struct osw_hostap_conf_ap_state_bufs bufs = {
        .status = osw_drv_spf13_hostap_cmd_get_reply(hostap_status),
        .get_config = osw_drv_spf13_hostap_cmd_get_reply(hostap_get_config),
        .show_neighbor = osw_drv_spf13_hostap_cmd_get_reply(hostap_show_neighbor),
        .show_rxkhs = osw_drv_spf13_hostap_cmd_get_reply(hostap_get_rxkhs),
        .wps_get_status = osw_drv_spf13_hostap_cmd_get_reply(hostap_wps_get_status),
        .mib = osw_drv_spf13_hostap_cmd_get_reply(hostap_mib),
        .config = file_geta(conf_path),
        .wpa_psk_file = file_geta(psks_path),
    };

    osw_hostap_conf_fill_ap_state(&bufs, vif_state);
}

static void osw_drv_spf13_wpas_fill_status(
        struct osw_drv_vif_state *vif_state,
        const int8_t mlo_link_id,
        osw_drv_spf13_request_vif_state_t *req)
{
    if (vif_state == NULL || req == NULL) return;
    if (vif_state->vif_type != OSW_VIF_STA) return;

    LOGT(LOG_PREFIX_VIF(req->phy_name, req->vif_name, "filling wpas status"));

    osw_drv_spf13_hostap_cmd_t *wpas_get_status = req->wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_STATUS];
    osw_drv_spf13_hostap_cmd_t *wpas_get_mlo_status =
            req->wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_MLO_STATUS];
    osw_drv_spf13_hostap_cmd_t *wpas_get_mib = req->wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_MIB];

    const struct osw_hostap_conf_sta_state_bufs bufs = {
        .status = osw_drv_spf13_hostap_cmd_get_reply(wpas_get_status),
        .mib = osw_drv_spf13_hostap_cmd_get_reply(wpas_get_mib),
    };

    /* FIXME: This provides some rudimentary stuff like AKM, Pairwise, etc.
     * decoding, not necessarily MLO-aware yet.
     */
    osw_hostap_conf_fill_sta_state(&bufs, vif_state);

    {
        /* Eg. output:
         *
         * bssid=02:03:7f:12:5d:5d
         * freq=5220
         * ssid=OpenWrt
         * id=1
         * mode=station
         * pairwise_cipher=GCMP
         * group_cipher=GCMP
         * key_mgmt=SAE
         * pmf=1
         * mgmt_group_cipher=BIP
         * sae_group=19
         * sae_h2e=1
         * sae_pk=0
         * wpa_state=COMPLETED
         * address=00:11:22:33:44:55
         * ap_mld_addr=00:22:22:33:33:44
         * uuid=6e7876b9-6355-525c-8fa9-d623cf06a415
         * ieee80211ac=1
         * ssid_verified=1
         */
        char *status = strdupa(osw_drv_spf13_hostap_cmd_get_reply(wpas_get_status) ?: "");
        char *line;
        while ((line = strsep(&status, "\n")) != NULL)
        {
            const char *k = strsep(&line, "=");
            const char *v = strsep(&line, "\n");
            if (strcmp(k, "bssid") == 0)
            {
                struct osw_hwaddr bssid;
                const bool ok = osw_hwaddr_from_cstr(v, &bssid);
                /* This is intended to work only for non-MLO associations. MLO
                 * associations will have MLO_STATUS present and that
                 * should/will overwrite whatever is found here. The bssid= in
                 * STATUS for MLO associations reports the BSSID where the
                 * association itself happened, not necessarily the BSSID of
                 * the PHY+VIF in question.
                 */
                if (ok)
                {
                    vif_state->u.sta.link.bssid = bssid;
                }
            }
            else if (strcmp(k, "ap_mld_addr") == 0)
            {
                struct osw_hwaddr ap_mld_addr;
                const bool ok = osw_hwaddr_from_cstr(v, &ap_mld_addr);
                if (ok)
                {
                    vif_state->u.sta.link.mld_addr = ap_mld_addr;
                }
            }
            else if (strcmp(k, "id_str") == 0)
            {
                const char *id_str = v;
                struct osw_drv_vif_sta_network *net =
                        osw_drv_spf13_request_config_mldsta_configured_networks(id_str, req->phy_name, req->vif_name);
                if (net != NULL)
                {
                    const char *psk = NULL;
                    struct osw_drv_vif_sta_network *n;
                    for (n = net; n != NULL; n = n->next)
                    {
                        if (psk == NULL) psk = n->psk.str;
                        const bool mismatched_psk = strcmp(n->psk.str, psk) != 0;
                        if (mismatched_psk)
                        {
                            psk = NULL;
                            break;
                        }
                    }
                    WARN_ON(psk == NULL);
                    if (psk != NULL)
                    {
                        STRSCPY_WARN(vif_state->u.sta.link.psk.str, psk);
                    }
                }
                while (net != NULL)
                {
                    struct osw_drv_vif_sta_network *next = net->next;
                    FREE(net);
                    net = next;
                }
            }
        }
    }

    {
        /* Eg. output:
         *
         * link_id=0
         * freq=2412
         * ap_link_addr=02:03:7f:12:35:35
         * sta_link_addr=00:03:7f:12:cb:cb
         * link_id=1
         * freq=5220
         * ap_link_addr=02:03:7f:12:5d:5d
         * sta_link_addr=00:03:7f:12:42:42
         */
        char *mlo_status = strdupa(osw_drv_spf13_hostap_cmd_get_reply(wpas_get_mlo_status) ?: "");
        char *line;
        int current_link_id = -1;
        while ((line = strsep(&mlo_status, "\n")) != NULL)
        {
            const char *k = strsep(&line, "=");
            const char *v = strsep(&line, "\n");
            if (strcmp(k, "link_id") == 0)
            {
                current_link_id = atoi(v);
            }
            else if (strcmp(k, "ap_link_addr") == 0)
            {
                if (current_link_id == mlo_link_id)
                {
                    struct osw_hwaddr bssid;
                    const bool ok = osw_hwaddr_from_cstr(v, &bssid);
                    if (ok)
                    {
                        vif_state->u.sta.link.bssid = bssid;
                    }
                }
            }
        }
    }

    {
        struct osw_drv_vif_sta_network **tail = &vif_state->u.sta.network;
        osw_drv_spf13_hostap_cmd_t **cmd_id_str;
        for (cmd_id_str = req->wpas_get_id_str; cmd_id_str != NULL && *cmd_id_str != NULL; cmd_id_str++)
        {
            const char *reply = osw_drv_spf13_hostap_cmd_get_reply(*cmd_id_str);
            if (reply == NULL) continue;

            /* Each of the id_str outputs is quoted with " */
            const bool len = (strlen(reply) > 0);
            const bool starts_with_quote = (reply[0] == '"');
            const bool ends_with_quote = len > 0 && (reply[len - 1] == '"');
            if (starts_with_quote && ends_with_quote)
            {
                char *copy = strdupa(reply);
                copy[len - 1] = '\0'; /* remove the trailing " */
                copy++;               /* skip the leading " */
                const char *id_str = copy;
                /* Move tail to always point to the last element's next
                 * pointer so that we can append to it.
                 */
                while (*tail != NULL && (*tail)->next != NULL)
                {
                    tail = &(*tail)->next;
                }
                *tail = osw_drv_spf13_request_config_mldsta_configured_networks(id_str, req->phy_name, req->vif_name);
                /* This can leave the `tail` mid way, but we always move to
                 * true tail before appending, see above.
                 */
            }
        }
    }
}

static void osw_drv_spf13_vif_fill_ap_acl(
        struct osw_drv_vif_state *vif_state,
        osw_drv_spf13_nl_cmd_t *vnd_get_acl,
        osw_drv_spf13_nl_cmd_t *vnd_get_acl_policy)
{
    if (vif_state == NULL) return;
    if (vif_state->vif_type != OSW_VIF_AP) return;

    struct nl_msg *msg_policy = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_acl_policy);
    if (msg_policy != NULL)
    {
        const uint32_t *policy_u32 = osw_drv_spf13_nl_vnd_u32_from_msg(msg_policy);
        if (policy_u32 != NULL)
        {
            vif_state->u.ap.acl_policy = osw_drv_spf13_nl_vnd_acl_policy_from_u32(*policy_u32);
        }
    }

    struct nl_msg **msg_acls = osw_drv_spf13_nl_cmd_get_resps(vnd_get_acl);
    struct nl_msg **msg;
    for (msg = msg_acls; msg != NULL && *msg != NULL; msg++)
    {
        uint32_t len = 0;
        uint32_t flags = 0;
        const void *acl_ptr = osw_drv_spf13_nl_vnd_generic_from_msg(*msg, &len, &flags);
        if (acl_ptr != NULL && len > 0)
        {
            const struct osw_hwaddr *addr = osw_hwaddr_from_cptr(acl_ptr, len);
            if (addr != NULL)
            {
                osw_hwaddr_list_append(&vif_state->u.ap.acl, addr);
            }
        }
    }
}

static void osw_drv_spf13_vif_fill_rates(
        struct osw_drv_vif_state *vif_state,
        osw_drv_spf13_nl_cmd_t *vnd_get_bcn_rate,
        osw_drv_spf13_nl_cmd_t *vnd_get_mgmt_rate,
        osw_drv_spf13_nl_cmd_t *vnd_get_mcast_rate,
        osw_drv_spf13_nl_cmd_t *vnd_get_bcast_rate)
{
    if (vif_state == NULL) return;
    if (vif_state->vif_type != OSW_VIF_AP) return;

    struct nl_msg *msg_bcn = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_bcn_rate);
    struct nl_msg *msg_mgmt = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_mgmt_rate);
    struct nl_msg *msg_mcast = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_mcast_rate);
    struct nl_msg *msg_bcast = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_bcast_rate);

    const uint32_t *bcn_rate_kbps = osw_drv_spf13_nl_vnd_u32_from_msg(msg_bcn);
    const uint32_t *mgmt_rate_kbps = osw_drv_spf13_nl_vnd_u32_from_msg(msg_mgmt);
    const uint32_t *mcast_rate_kbps = osw_drv_spf13_nl_vnd_u32_from_msg(msg_mcast);
    const uint32_t *bcast_rate_kbps = osw_drv_spf13_nl_vnd_u32_from_msg(msg_bcast);

    if (bcn_rate_kbps != NULL)
    {
        const enum osw_rate_legacy rate = osw_rate_legacy_from_kbps(*bcn_rate_kbps);
        if (osw_rate_is_valid(rate))
        {
            vif_state->u.ap.mode.beacon_rate.type = OSW_BEACON_RATE_ABG;
            vif_state->u.ap.mode.beacon_rate.u.legacy = rate;
        }
    }

    if (mgmt_rate_kbps != NULL)
    {
        const enum osw_rate_legacy rate = osw_rate_legacy_from_kbps(*mgmt_rate_kbps);
        if (osw_rate_is_valid(rate))
        {
            vif_state->u.ap.mode.mgmt_rate = rate;
        }
    }

    if (mcast_rate_kbps != NULL && bcast_rate_kbps != NULL)
    {
        const bool identical = (*mcast_rate_kbps == *bcast_rate_kbps);
        if (identical)
        {
            vif_state->u.ap.mode.mcast_rate = osw_rate_legacy_from_kbps(*mcast_rate_kbps);
        }
    }
}

static void osw_drv_spf13_vif_fill_mbss(
        struct osw_drv_vif_state *vif_state,
        osw_drv_spf13_nl_cmd_t *vnd_get_mbss_en,
        osw_drv_spf13_nl_cmd_t *vnd_get_mbss_tx_vdev,
        osw_drv_spf13_nl_cmd_t *vnd_get_mbss_group)
{
    if (vif_state == NULL) return;
    if (vif_state->vif_type != OSW_VIF_AP) return;

    struct nl_msg *msg_mbss_en = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_mbss_en);
    struct nl_msg *msg_mbss_tx_vdev = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_mbss_tx_vdev);
    struct nl_msg *msg_mbss_group = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_mbss_group);

    const uint32_t *mbss_en = osw_drv_spf13_nl_vnd_u32_from_msg(msg_mbss_en);
    const uint32_t *mbss_tx_vdev = osw_drv_spf13_nl_vnd_u32_from_msg(msg_mbss_tx_vdev);
    const uint32_t *mbss_group = osw_drv_spf13_nl_vnd_u32_from_msg(msg_mbss_group);

    if (mbss_en == NULL) return;
    if (*mbss_en == 0) return;

    vif_state->u.ap.mbss_mode =
            mbss_tx_vdev ? (*mbss_tx_vdev ? OSW_MBSS_TX_VAP : OSW_MBSS_NON_TX_VAP) : OSW_MBSS_NON_TX_VAP;
    vif_state->u.ap.mbss_group = mbss_group ? *mbss_group : 0;
}

static void osw_drv_spf13_vif_fill_mcast2ucast(
        struct osw_drv_vif_state *vif_state,
        osw_drv_spf13_nl_cmd_t *vnd_get_mcast2ucast)
{
    if (vif_state == NULL) return;
    if (vif_state->vif_type != OSW_VIF_AP) return;

    struct nl_msg *msg = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_mcast2ucast);
    if (msg == NULL)
    {
        LOGW(LOG_PREFIX("failed to get netlink response for mcast2ucast"));
        return;
    }

    const uint32_t *value = osw_drv_spf13_nl_vnd_u32_from_msg(msg);
    bool is_tunneling = false;
    bool is_translating = false;
    bool no_snooping = false;
    const bool parsed = osw_drv_spf13_nl_vnd_vap_param_me_parse(value, &is_tunneling, &is_translating, &no_snooping);
    if (parsed == false)
    {
        LOGW(LOG_PREFIX("failed to parse mcast2ucast value"));
        return;
    }

    const bool enabled = is_tunneling && no_snooping;
    vif_state->u.ap.mcast2ucast = enabled;
}

static void osw_drv_spf13_vif_fill_rrm(struct osw_drv_vif_state *vif_state, osw_drv_spf13_nl_cmd_t *vnd_get_rrm)
{
    if (vif_state == NULL) return;
    if (vif_state->vif_type != OSW_VIF_AP) return;

    struct nl_msg *msg = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_rrm);
    if (msg == NULL)
    {
        LOGW(LOG_PREFIX("failed to get netlink response for rrm"));
        return;
    }

    const uint32_t *value = osw_drv_spf13_nl_vnd_u32_from_msg(msg);
    if (value == NULL)
    {
        LOGW(LOG_PREFIX("failed to get rrm value from netlink response"));
        return;
    }

    vif_state->u.ap.mode.rrm_neighbor_report = !!*value;
}

static void osw_drv_spf13_vif_fill_ap_bridge(
        struct osw_drv_vif_state *vif_state,
        osw_drv_spf13_nl_cmd_t *vnd_get_ap_bridge)
{
    if (vif_state == NULL) return;
    if (vif_state->vif_type != OSW_VIF_AP) return;

    struct nl_msg *msg = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_ap_bridge);
    if (msg == NULL)
    {
        LOGW(LOG_PREFIX("failed to get netlink response for ap bridge"));
        return;
    }

    const uint32_t *value = osw_drv_spf13_nl_vnd_u32_from_msg(msg);
    if (value == NULL)
    {
        LOGW(LOG_PREFIX("failed to get ap bridge value from netlink response"));
        return;
    }

    const bool bridging = !!*value;
    const bool isolating = bridging == false;
    vif_state->u.ap.isolated = isolating;
}

static void osw_drv_spf13_vif_fill_uapsd(struct osw_drv_vif_state *vif_state, osw_drv_spf13_nl_cmd_t *vnd_get_uapsd)
{
    if (vif_state == NULL) return;
    if (vif_state->vif_type != OSW_VIF_AP) return;

    struct nl_msg *msg = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_uapsd);
    if (msg == NULL)
    {
        LOGW(LOG_PREFIX("failed to get netlink response for uapsd"));
        return;
    }

    const uint32_t *value = osw_drv_spf13_nl_vnd_u32_from_msg(msg);
    if (value == NULL)
    {
        LOGW(LOG_PREFIX("failed to get uapsd value from netlink response"));
        return;
    }

    vif_state->u.ap.mode.wmm_uapsd_enabled = !!*value;
}

static void osw_drv_spf13_request_vif_state_complete(osw_drv_spf13_request_vif_state_t *req)
{
    if (req == NULL) return;

    struct osw_drv *drv = req->pool->drv;
    const char *phy_name = strdupa(req->phy_name);
    const char *vif_name = strdupa(req->vif_name);

    const char *netdev_name = strdupafree(osw_drv_spf13_netdev_from_phy_and_vif(phy_name, vif_name));
    const int8_t mlo_link_id =
            osw_drv_spf13_netdev_is_qca_vap_legacy(netdev_name) ? -1 : osw_drv_spf13_netdev_get_hw_link_id(phy_name);
    const bool is_legacy_vap = osw_drv_spf13_netdev_is_qca_vap_legacy(netdev_name);
    const bool is_mld_vap = osw_drv_spf13_netdev_is_qca_vap_mld(netdev_name);
    const bool vif_exists = is_legacy_vap || is_mld_vap;
    // FIXME: netdev status for MLD vaps isn't really a good idea: multiple VIFs (as far as OSW is concerned) share the
    // same state that will break status reports for,eg. h-24 being up, h-50 being down; the mldX will must be UP, so
    // h-50 would be "broken"
    // bool is_up = false;
    // if (netdev_name != NULL) {
    // os_nif_is_up(netdev_name, &is_up);
    //}
    // const enum osw_vif_status status = is_legacy_vap ? is_up : OSW_VIF_UNKNOWN;
    struct osw_drv_vif_state vif_state = {
        .exists = vif_exists,
        .status = OSW_VIF_UNKNOWN,
    };

    osw_drv_spf13_nl_cmd_t *nl_get_interface = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_GET_INTERFACE];
    osw_drv_spf13_nl_cmd_t *nl_dump_scan = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_DUMP_SCAN];
    osw_drv_spf13_nl_cmd_t *vnd_get_acl = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_ACL];
    osw_drv_spf13_nl_cmd_t *vnd_get_acl_policy =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_ACL_POLICY];
    osw_drv_spf13_nl_cmd_t *vnd_get_bcn_rate = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_BCN_RATE];
    osw_drv_spf13_nl_cmd_t *vnd_get_mgmt_rate = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MGMT_RATE];
    osw_drv_spf13_nl_cmd_t *vnd_get_mcast_rate =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MCAST_RATE];
    osw_drv_spf13_nl_cmd_t *vnd_get_bcast_rate =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_BCAST_RATE];
    osw_drv_spf13_nl_cmd_t *vnd_get_rrm = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_RRM];
    osw_drv_spf13_nl_cmd_t *vnd_get_mcast2ucast =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MCAST2UCAST];
    osw_drv_spf13_nl_cmd_t *vnd_get_mbss_en = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBSS_EN];
    osw_drv_spf13_nl_cmd_t *vnd_get_mbss_tx_vdev =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBSS_TX_VDEV];
    osw_drv_spf13_nl_cmd_t *vnd_get_mbss_group =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBSS_GROUP];
    osw_drv_spf13_nl_cmd_t *vnd_get_ap_bridge = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_AP_BRIDGE];
    osw_drv_spf13_nl_cmd_t *vnd_get_uapsd = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_UAPSD];
    osw_drv_spf13_nl_cmd_t *vnd_get_vdev_up = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_VDEV_UP];
    osw_drv_spf13_nl_cmd_t *vnd_get_mbo = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBO];
    osw_drv_spf13_nl_cmd_t *vnd_get_oce = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE];
    osw_drv_spf13_nl_cmd_t *vnd_get_oce_min_rssi_dbm =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE_MIN_RSSI_DBM];
    osw_drv_spf13_nl_cmd_t *vnd_get_oce_min_rssi_en =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE_MIN_RSSI_EN];
    osw_drv_spf13_nl_cmd_t *vnd_get_oce_retry_delay_sec =
            req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE_RETRY_DELAY_SEC];
    osw_drv_spf13_nl_cmd_t *vnd_get_max_sta = req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MAX_STA];

    struct nl_msg *msg_get_interface = osw_drv_spf13_nl_cmd_get_first_resp_only(nl_get_interface);

    const uint32_t *mbo = osw_drv_spf13_nl_vnd_u32_from_msg(osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_mbo));
    const uint32_t *oce = osw_drv_spf13_nl_vnd_u32_from_msg(osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_oce));
    const int32_t *oce_min_rssi_dbm = (const int32_t *)osw_drv_spf13_nl_vnd_u32_from_msg(
            osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_oce_min_rssi_dbm));
    const uint32_t *oce_min_rssi_en =
            osw_drv_spf13_nl_vnd_u32_from_msg(osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_oce_min_rssi_en));
    const uint32_t *oce_retry_delay_sec =
            osw_drv_spf13_nl_vnd_u32_from_msg(osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_oce_retry_delay_sec));
    const uint32_t *max_sta =
            osw_drv_spf13_nl_vnd_u32_from_msg(osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_max_sta));

    struct nl_msg *msg_get_vdev_up = osw_drv_spf13_nl_cmd_get_first_resp_only(vnd_get_vdev_up);
    const uint32_t *vdev_up = osw_drv_spf13_nl_vnd_u32_from_msg(msg_get_vdev_up);
    const bool vdev_is_up = vdev_up != NULL && *vdev_up != 0;

    const enum osw_vif_status status = vdev_is_up ? OSW_VIF_ENABLED : OSW_VIF_DISABLED;
    osw_vif_status_set(&vif_state.status, status);

    /* This needs to be first as it determines the vif_type. vif_type is used
     * as a guard in subsequent fills. */
    osw_drv_spf13_nl_80211_fill_interface(&vif_state, msg_get_interface, mlo_link_id);

    /* This needs to be second. It provides much of the baseline of the report.
     * Anything that hostapd can't fill in is filled in by the (vendor) nl80211
     * netlink commands. */
    osw_drv_spf13_hostap_fill_status(&vif_state, req);
    osw_drv_spf13_wpas_fill_status(&vif_state, mlo_link_id, req);

    osw_drv_spf13_vif_fill_dump_scan(&vif_state, nl_dump_scan);

    /* Vendor specific overrides */
    if (vdev_is_up)
    {
        osw_drv_spf13_vif_fill_uapsd(&vif_state, vnd_get_uapsd);
        osw_drv_spf13_vif_fill_ap_bridge(&vif_state, vnd_get_ap_bridge);
        osw_drv_spf13_vif_fill_rrm(&vif_state, vnd_get_rrm);
        osw_drv_spf13_vif_fill_mcast2ucast(&vif_state, vnd_get_mcast2ucast);
        osw_drv_spf13_vif_fill_ap_acl(&vif_state, vnd_get_acl, vnd_get_acl_policy);
        osw_drv_spf13_vif_fill_rates(
                &vif_state,
                vnd_get_bcn_rate,
                vnd_get_mgmt_rate,
                vnd_get_mcast_rate,
                vnd_get_bcast_rate);

        if (mbo != NULL)
        {
            vif_state.u.ap.mbo = !!*mbo;
        }

        if (oce != NULL)
        {
            vif_state.u.ap.oce = !!*oce;
        }

        if (oce_min_rssi_en != NULL && !!*oce_min_rssi_en)
        {
            if (oce_min_rssi_dbm != NULL)
            {
                vif_state.u.ap.oce_min_rssi_dbm = *oce_min_rssi_dbm;
            }
        }

        if (oce_retry_delay_sec != NULL)
        {
            vif_state.u.ap.oce_retry_delay_sec = *oce_retry_delay_sec;
        }

        if (max_sta != NULL)
        {
            vif_state.u.ap.max_sta = *max_sta;
        }
    }

    osw_drv_spf13_vif_fill_mbss(&vif_state, vnd_get_mbss_en, vnd_get_mbss_tx_vdev, vnd_get_mbss_group);

    if (is_mld_vap)
    {
        switch (vif_state.vif_type)
        {
            case OSW_VIF_AP:
                STRSCPY_WARN(vif_state.u.ap.mld.if_name.buf, netdev_name);
                os_nif_macaddr_get(netdev_name, (os_macaddr_t *)&vif_state.u.ap.mld.addr);
                break;
            case OSW_VIF_STA:
                STRSCPY_WARN(vif_state.u.sta.mld.if_name.buf, netdev_name);
                os_nif_macaddr_get(netdev_name, (os_macaddr_t *)&vif_state.u.sta.mld.addr);
                break;
            case OSW_VIF_AP_VLAN:
                break;
            case OSW_VIF_UNDEFINED:
                break;
        }
    }

    const int64_t elapsed = clock_mono_ms() - req->started_on;
    LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "vif state request completed in %" PRId64 " ms"), elapsed);

    osw_drv_spf13_request_vif_state_drop(req);

    osw_drv_report_vif_state(drv, phy_name, vif_name, &vif_state);
    osw_drv_vif_state_report_free(&vif_state);
}

static bool osw_drv_spf13_request_vif_state_is_ready(osw_drv_spf13_request_vif_state_t *req)
{
    if (req == NULL) return true;
    const bool timed_out = ev_is_active(&req->timeout) == false;
    if (timed_out) return true;
    return true
           && osw_drv_spf13_hostap_cmd_is_done_array(req->hostap_cmds, OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_MAX)
           && osw_drv_spf13_hostap_cmd_is_done_array(req->wpas_cmds, OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_MAX)
           && osw_drv_spf13_hostap_cmd_is_done_all(req->wpas_get_id_str)
           && osw_drv_spf13_nl_cmd_is_done_array(req->nl_cmds, OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_MAX);
}

static void osw_drv_spf13_request_vif_state_poll(void *priv)
{
    osw_drv_spf13_request_vif_state_t *req = priv;

    if (osw_drv_spf13_hostap_cmd_is_done(req->wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_LIST_NETWORKS]))
    {
        const char *reply = osw_drv_spf13_hostap_cmd_get_reply(
                req->wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_LIST_NETWORKS]);
        const bool not_started_yet = req->wpas_get_id_str == NULL;
        if (reply != NULL && not_started_yet)
        {
            // const char *ctrl_path = strdupafree(osw_drv_spf13_hostap_path_supplicant_ctrl_bss(req->phy_name,
            // req->vif_name));
            const char *ctrl_path = req->ctrl_path_wpas;
            char *copy = strdupa(reply);
            char *line;
            /* Eg. output:
             *
             * > network id / ssid / bssid / flags
             * 2       OpenWrt any     [CURRENT]
             */
            while ((line = strsep(&copy, "\n")) != NULL)
            {
                const bool is_header = (strncmp(line, "> network id", 12) == 0);
                if (is_header) continue;

                const char *id_str = strsep(&line, " ");
                if (id_str == NULL) continue;

                const int id = atoi(id_str);

                osw_drv_spf13_hostap_cmd_extend(
                        req->wpas_get_id_str,
                        osw_drv_spf13_hostap_cmd_new(
                                osw_drv_spf13_hostap_sock_open(),
                                ctrl_path,
                                strfmta("GET_NETWORK %d id_str", id),
                                osw_drv_spf13_request_vif_state_poll,
                                req));
            }
        }
    }

    if (osw_drv_spf13_request_vif_state_is_ready(req) == false) return;
    osw_drv_spf13_request_vif_state_complete(req);
}

static void osw_drv_spf13_request_vif_state_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_request_vif_state_t *req = w->data;
    if (req == NULL) return;

    LOGI(LOG_PREFIX_VIF(req->phy_name, req->vif_name, "vif state request timed out"));
    osw_drv_spf13_request_vif_state_poll(req);
}

static osw_drv_spf13_request_vif_state_t *osw_drv_spf13_request_vif_state_new(
        osw_drv_spf13_request_vif_state_pool_t *pool,
        const char *phy_name,
        const char *vif_name)
{
    if (pool == NULL) return NULL;
    if (phy_name == NULL) return NULL;
    if (vif_name == NULL) return NULL;
    if (WARN_ON(ds_tree_find(&pool->requests, vif_name) != NULL)) return NULL;

    const char *ctrl_path_hapd = strdupafree(osw_drv_spf13_hostap_path_hostapd_ctrl_bss(phy_name, vif_name));
    if (ctrl_path_hapd == NULL)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to get hostapd ctrl path for vif"));
        return NULL;
    }

    const char *netdev_name = strdupafree(osw_drv_spf13_netdev_from_phy_and_vif(phy_name, vif_name));
    if (netdev_name == NULL)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to get netdev name for vif"));
        return NULL;
    }
    const uint32_t family_id = pool->nl80211_family_id;
    const unsigned int ifindex = osw_drv_spf13_netdev_get_ifindex(netdev_name);
    const unsigned int phy_ifindex = osw_drv_spf13_netdev_get_ifindex(phy_name);
    if (phy_ifindex == 0)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to get phy ifindex for %s"), phy_name);
        return NULL;
    }

    const char *ctrl_path_wpas = strdupafree(osw_drv_spf13_hostap_path_supplicant_ctrl_bss(netdev_name));
    if (ctrl_path_wpas == NULL)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to get wpas ctrl path for vif"));
        return NULL;
    }

    const int8_t mlo_link_id =
            osw_drv_spf13_netdev_is_qca_vap_legacy(netdev_name) ? -1 : osw_drv_spf13_netdev_get_hw_link_id(phy_name);

    LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "requesting vif state for %s(%" PRIu32 ":%" PRIi8 ")"),
         netdev_name,
         ifindex,
         mlo_link_id);

    osw_drv_spf13_request_vif_state_t *req = CALLOC(1, sizeof(*req));
    req->pool = pool;
    req->phy_name = STRDUP(phy_name);
    req->vif_name = STRDUP(vif_name);
    req->ctrl_path_wpas = STRDUP(ctrl_path_wpas);
    req->started_on = clock_mono_ms();
    ds_tree_insert(&pool->requests, req, req->vif_name);

    ev_timer_init(&req->timeout, osw_drv_spf13_request_vif_state_timeout_cb, OSW_DRV_SPF13_VIF_REQUEST_TIMEOUT_SEC, 0);
    req->timeout.data = req;
    ev_timer_start(EV_DEFAULT, &req->timeout);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_GET_INTERFACE] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_80211_msg_get_interface(family_id, ifindex),
            strfmta("%s: get_interface(%" PRIu32 ")", vif_name, ifindex),
            osw_drv_spf13_request_vif_state_poll,
            req);

#if 0
    // its not used yet, and it'll be needed only for stats and STA iftype_attr
    // skip for now.
    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_DUMP_SCAN] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_80211_msg_dump_scan(family_id, ifindex),
            strfmta("%s: dump_scan(%"PRIu32")", vif_name, ifindex),
            osw_drv_spf13_request_vif_state_poll,
            req);
#endif

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_ACL] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_acl_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_acl(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_ACL_POLICY] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_acl_policy_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_acl_policy(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_BCN_RATE] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_bcn_rate_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_bcn_rate(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MGMT_RATE] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_mgmt_rate_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_mgmt_rate(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MCAST_RATE] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_mcast_rate_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_mcast_rate(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_BCAST_RATE] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_bcast_rate_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_bcast_rate(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_RRM] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_rrm_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_rrm(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MCAST2UCAST] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_me_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_mcast2ucast(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBSS_EN] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_mbss_en_get(family_id, phy_ifindex, mlo_link_id),
            strfmta("%s: vnd_get_mbss_en(%" PRIu32 ":%" PRIi8 ")", vif_name, phy_ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBSS_TX_VDEV] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_mbss_tx_vdev_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_mbss_tx_vdev(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBSS_GROUP] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_mbss_group_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_mbss_group(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_AP_BRIDGE] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_ap_bridge_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_ap_bridge(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_UAPSD] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_uapsd_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_uapsd(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_VDEV_UP] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_vdev_up_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_vdev_id(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MBO] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_mbo_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_mbo(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_oce_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_oce(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE_MIN_RSSI_DBM] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_oce_assoc_min_rssi_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_oce_min_rssi_dbm(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE_MIN_RSSI_EN] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_oce_assoc_reject_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_oce_min_rssi_en(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_OCE_RETRY_DELAY_SEC] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_oce_assoc_retry_delay_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_oce_retry_delay_sec(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->nl_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_NL_CMD_VND_GET_MAX_STA] = osw_drv_spf13_nl_cmd_new(
            osw_drv_spf13_nl_vnd_vap_param_max_sta_get(family_id, ifindex, mlo_link_id),
            strfmta("%s: vnd_get_max_sta(%" PRIu32 ":%" PRIi8 ")", vif_name, ifindex, mlo_link_id),
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_STATUS] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_hapd,
            "STATUS",
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_GET_CONFIG] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_hapd,
            "GET_CONFIG",
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_SHOW_NEIGHBOR] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_hapd,
            "SHOW_NEIGHBOR",
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_GET_RXKHS] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_hapd,
            "GET_RXKHS",
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_WPS_GET_STATUS] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_hapd,
            "WPS_GET_STATUS",
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->hostap_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_HOSTAP_CMD_MIB] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_hapd,
            "MIB",
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_STATUS] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_wpas,
            "STATUS",
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_MLO_STATUS] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_wpas,
            "MLO_STATUS",
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_LIST_NETWORKS] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_wpas,
            "LIST_NETWORKS",
            osw_drv_spf13_request_vif_state_poll,
            req);

    req->wpas_cmds[OSW_DRV_SPF13_REQUEST_VIF_STATE_WPAS_CMD_GET_MIB] = osw_drv_spf13_hostap_cmd_new(
            osw_drv_spf13_hostap_sock_open(),
            ctrl_path_wpas,
            "MIB",
            osw_drv_spf13_request_vif_state_poll,
            req);

    return req;
}

static void osw_drv_spf13_request_vif_state_report_empty(
        struct osw_drv *drv,
        const char *phy_name,
        const char *vif_name)
{
    if (drv == NULL) return;
    if (phy_name == NULL) return;
    if (vif_name == NULL) return;

    LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "reporting empty vif state"));
    const struct osw_drv_vif_state vif_state = {
        .exists = false,
    };
    osw_drv_report_vif_state(drv, phy_name, vif_name, &vif_state);
}

osw_drv_spf13_request_vif_state_pool_t *osw_drv_spf13_request_vif_state_pool_new(
        struct osw_drv *drv,
        uint32_t family_id)
{
    if (drv == NULL) return NULL;
    osw_drv_spf13_request_vif_state_pool_t *pool = CALLOC(1, sizeof(*pool));
    pool->nl80211_family_id = family_id;
    pool->drv = drv;
    ds_tree_init(&pool->requests, ds_str_cmp, osw_drv_spf13_request_vif_state_t, node);
    return pool;
}

static void osw_drv_spf13_request_vif_state_pool_flush(osw_drv_spf13_request_vif_state_pool_t *pool)
{
    osw_drv_spf13_request_vif_state_t *req;
    while ((req = ds_tree_head(&pool->requests)) != NULL)
    {
        LOGD(LOG_PREFIX_VIF(req->phy_name, req->vif_name, "flushing vif state request"));
        osw_drv_spf13_request_vif_state_report_empty(pool->drv, req->phy_name, req->vif_name);
        osw_drv_spf13_request_vif_state_drop(req);
    }
}

void osw_drv_spf13_request_vif_state_pool_drop(osw_drv_spf13_request_vif_state_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_vif_state_pool_flush(pool);
    FREE(pool);
}

void osw_drv_spf13_request_vif_state(
        osw_drv_spf13_request_vif_state_pool_t *pool,
        const char *phy_name,
        const char *vif_name)
{
    if (pool == NULL) return;
    if (phy_name == NULL) return;
    if (vif_name == NULL) return;

    osw_drv_spf13_request_vif_state_t *req = ds_tree_find(&pool->requests, vif_name);
    const bool already_exists = (req != NULL);
    if (already_exists)
    {
        LOGI(LOG_PREFIX_VIF(phy_name, vif_name, "vif state request already exists, cancelling"));
        osw_drv_spf13_request_vif_state_drop(req);
        req = NULL;
    }

    req = osw_drv_spf13_request_vif_state_new(pool, phy_name, vif_name);
    if (req == NULL)
    {
        LOGE(LOG_PREFIX_VIF(phy_name, vif_name, "failed to create vif state request"));
        osw_drv_spf13_request_vif_state_report_empty(pool->drv, phy_name, vif_name);
        return;
    }

    osw_drv_spf13_request_vif_state_poll(req);
}
