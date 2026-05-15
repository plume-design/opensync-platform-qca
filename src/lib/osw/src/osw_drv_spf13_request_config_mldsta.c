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
#include <stdbool.h>
#include <net/if.h>
#include <errno.h>
#include <dirent.h>

/* 3rd party */
#include <zlib.h>
#include <jansson.h>

/* opensync */
#include <log.h>
#include <util.h>
#include <const.h>
#include <memutil.h>

/* osw */
#include <osw_types.h>
#include <osw_drv.h>
#include <osw_hostap_common.h>

/* local */
#include "osw_drv_spf13_hostap_path.h"
#include "osw_drv_spf13_hostap_sock.h"
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_hostap_cmd.h"
#include "osw_drv_spf13_invalidations.h"
#include "osw_drv_spf13_request_config_mldsta.h"

/**
 * TODO
 *
 *  - test this..
 *  - any vendor specific commands?
 *    a. powersave
 *    b. uapsd
 *    c. add/del link commands?
 *  - generate configs in tmp based on hashid
 *  - expose config->state helpers (from hashid saved configs) for state reporting
 *    that will be required to make _any_ sense out of the merged configs to
 *    report them back to OSW properly
 */

#define LOG_PREFIX_REQ(mldsta_req, fmt, ...) \
    LOG_PREFIX("mldsta_req: %s: " fmt, (mldsta_req) != NULL ? (mldsta_req)->netdev_name : "NULL", ##__VA_ARGS__)

#define OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_BRIDGE_PREFIX "/tmp/osw_drv_spf13_mldsta_runtime_bridge."
#define OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_PREFIX        "/tmp/osw_drv_spf13_mldsta_network"
#define OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_PATH_FMT \
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_PREFIX "/%s.%s.%s.bin"
#define OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_PATH_ARG(hash_id, phy_name, vif_name) \
    strfmta(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_PATH_FMT, hash_id, phy_name, vif_name)

struct osw_drv_spf13_request_config_mldsta_pool
{
    ds_tree_t mldsta_requests; /* osw_drv_spf13_request_config_mldsta_t */
    osw_drv_spf13_invalidations_t *invalidations;
    void (*done_cb)(void *priv);
    void *done_priv;
};

enum osw_drv_spf13_request_config_mldsta_wpas_cmd
{
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LOG_LEVEL,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG,

    /* keep last */
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_MAX,
};
typedef enum osw_drv_spf13_request_config_mldsta_wpas_cmd osw_drv_spf13_request_config_mldsta_wpas_cmd_t;

enum osw_drv_spf13_request_config_mldsta_network_wpas_cmd
{
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ADD_NETWORK,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_ID_STR,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ENABLE_RECONNECT,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_SSID,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_KEY_MGMT,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_BSSID_ACCEPT,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_IEEE80211W,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PSK,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_SCAN_SSID,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_MULTI_AP_BACKHAUL_STA,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PRIORITY,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_BEACON_PROTECTION,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PAIRWISE,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PROTO,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ENABLE,

    /* keep last */
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_MAX,
};
typedef enum osw_drv_spf13_request_config_mldsta_network_wpas_cmd
        osw_drv_spf13_request_config_mldsta_network_wpas_cmd_t;

enum osw_drv_spf13_request_config_mldsta_runtime_network_wpas_cmd
{
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_GET_ID_STR,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_REMOVE,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_DISABLE_RECONNECT,

    /* keep last */
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_MAX,
};
typedef enum osw_drv_spf13_request_config_mldsta_runtime_network_wpas_cmd
        osw_drv_spf13_request_config_mldsta_runtime_network_wpas_cmd_t;

enum osw_drv_spf13_request_config_mldsta_runtime_network_update
{
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_REMOVE,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_KEEP,
    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_ALREADY_CONFIGURED,
};
typedef enum osw_drv_spf13_request_config_mldsta_runtime_network_update
        osw_drv_spf13_request_config_mldsta_runtime_network_update_t;

struct osw_drv_spf13_request_config_mldsta_runtime_network
{
    int id;
    bool keep;
    bool wanted;
    char *id_str;
    osw_drv_spf13_hostap_cmd_t *cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_MAX];
    osw_drv_spf13_request_config_mldsta_runtime_network_update_t update;
};
typedef struct osw_drv_spf13_request_config_mldsta_runtime_network
        osw_drv_spf13_request_config_mldsta_runtime_network_t;

struct osw_drv_spf13_request_config_mldsta_network
{
    struct osw_hwaddr_list bssids;
    struct osw_ssid ssid;
    struct osw_psk psk;
    struct osw_wpa wpa;
    bool multi_ap;
    int priority;
    char *bridge_name;
    char *id_str;
    int id;
    bool already_programmed;
    osw_drv_spf13_hostap_cmd_t *wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_MAX];
    /* This is a nested:
     * {
     *    "phy1": {
     *      "vif1": [
     *        { .. network1 .. },
     *        { .. network2 .. }
     *      ],
     *      "vif2": [
     *        { .. network1 .. },
     *        { .. network2 .. }
     *      ]
     *    },
     *    "phy2": {
     *      "vif3": [
     *        { .. network1 .. },
     *        { .. network2 .. }
     *      ],
     *      "vif4": [
     *        { .. network1 .. },
     *        { .. network2 .. }
     *      ]
     *    }
     * }
     */
    json_t *phy_vif_links;
};
typedef struct osw_drv_spf13_request_config_mldsta_network osw_drv_spf13_request_config_mldsta_network_t;

#define OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR "/tmp/osw_drv_spf13_mldsta_link"

struct osw_drv_spf13_request_config_mldsta
{
    ds_tree_node_t node_pool;
    osw_drv_spf13_request_config_mldsta_pool_t *pool;
    char *netdev_name;
    char *phys_vifs; /**< for logging purposes */
    char *ctrl_path;
    uint32_t netdev_ifindex;
    bool wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_MAX];
    osw_drv_spf13_hostap_cmd_t *wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_MAX];
    osw_drv_spf13_request_config_mldsta_network_t *networks;
    size_t n_networks;
    osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_networks;
    size_t n_runtime_networks;
    bool is_mld;
    bool enabled;
    bool done;
};
typedef struct osw_drv_spf13_request_config_mldsta osw_drv_spf13_request_config_mldsta_t;

static const char *osw_drv_spf13_request_config_mldsta_wpas_cmd_to_cstr(
        osw_drv_spf13_request_config_mldsta_wpas_cmd_t cmd)
{
    switch (cmd)
    {
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE:
            return "remove";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD:
            return "add";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LOG_LEVEL:
            return "log_level";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS:
            return "status";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS:
            return "list_networks";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT:
            return "disconnect";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE:
            return "reassociate";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG:
            return "save_config";
        default:
            return "unknown";
    }
}

static const char *osw_drv_spf13_request_config_mldsta_network_wpas_cmd_to_cstr(
        osw_drv_spf13_request_config_mldsta_network_wpas_cmd_t cmd)
{
    switch (cmd)
    {
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ADD_NETWORK:
            return "add_network";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_ID_STR:
            return "set_id_str";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ENABLE_RECONNECT:
            return "enable_reconnect";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_SSID:
            return "set_ssid";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_KEY_MGMT:
            return "set_key_mgmt";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_BSSID_ACCEPT:
            return "set_bssid_accept";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_IEEE80211W:
            return "set_ieee80211w";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PSK:
            return "set_psk";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_SCAN_SSID:
            return "set_scan_ssid";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_MULTI_AP_BACKHAUL_STA:
            return "set_multi_ap_backhaul_sta";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PRIORITY:
            return "set_priority";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_BEACON_PROTECTION:
            return "set_beacon_protection";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PAIRWISE:
            return "set_pairwise";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PROTO:
            return "set_proto";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ENABLE:
            return "enable";
        default:
            return "unknown";
    }
}

static const char *osw_drv_spf13_request_config_mldsta_runtime_network_wpas_cmd_to_cstr(
        osw_drv_spf13_request_config_mldsta_runtime_network_wpas_cmd_t cmd)
{
    switch (cmd)
    {
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_GET_ID_STR:
            return "get_id_str";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_REMOVE:
            return "remove";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_DISABLE_RECONNECT:
            return "disable_reconnect";
        default:
            return "unknown";
    }
}

static const char *osw_drv_spf13_request_config_mldsta_runtime_network_update_to_cstr(
        osw_drv_spf13_request_config_mldsta_runtime_network_update_t update)
{
    switch (update)
    {
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_REMOVE:
            return "remove";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_KEEP:
            return "keep";
        case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_ALREADY_CONFIGURED:
            return "already_configured";
        default:
            return "unknown";
    }
}

static json_t *osw_drv_spf13_request_config_mldsta_osw_network_serialize_to_json(
        const struct osw_drv_vif_sta_network *osw_network)
{
    if (osw_network == NULL) return NULL;

    json_t *json = json_object();
    json_object_set_new(json, "multi_ap", json_boolean(osw_network->multi_ap));
    json_object_set_new(json, "priority", json_integer(osw_network->priority));
    json_object_set_new(json, "bridge_name", json_string(osw_network->bridge_if_name.buf));

    struct osw_ssid_hex ssid_hex;
    const char *ssid_hexstr = osw_ssid_into_hex(&ssid_hex, &osw_network->ssid);
    if (ssid_hexstr != NULL)
    {
        json_object_set_new(json, "ssid_hex", json_string(ssid_hexstr));
    }

    const char *psk = osw_network->psk.str;
    const size_t psk_len = strlen(psk);
    char psk_hex[psk_len * 2 + 1];
    if (bin2hex((const void *)psk, psk_len, psk_hex, sizeof(psk_hex)) == 0)
    {
        json_object_set_new(json, "psk_hex", json_string(psk_hex));
    }

    struct osw_hwaddr_str bssid_str;
    const char *bssid = osw_hwaddr2str(&osw_network->bssid, &bssid_str);
    if (bssid != NULL)
    {
        json_object_set_new(json, "bssid", json_string(bssid));
    }

    json_t *wpa = json_object();
    {
        json_object_set_new(wpa, "wpa", json_boolean(osw_network->wpa.wpa));
        json_object_set_new(wpa, "rsn", json_boolean(osw_network->wpa.rsn));
        json_object_set_new(wpa, "akm_eap", json_boolean(osw_network->wpa.akm_eap));
        json_object_set_new(wpa, "akm_eap_sha256", json_boolean(osw_network->wpa.akm_eap_sha256));
        json_object_set_new(wpa, "akm_eap_sha384", json_boolean(osw_network->wpa.akm_eap_sha384));
        json_object_set_new(wpa, "akm_eap_suite_b", json_boolean(osw_network->wpa.akm_eap_suite_b));
        json_object_set_new(wpa, "akm_eap_suite_b192", json_boolean(osw_network->wpa.akm_eap_suite_b192));
        json_object_set_new(wpa, "akm_psk", json_boolean(osw_network->wpa.akm_psk));
        json_object_set_new(wpa, "akm_psk_sha256", json_boolean(osw_network->wpa.akm_psk_sha256));
        json_object_set_new(wpa, "akm_sae", json_boolean(osw_network->wpa.akm_sae));
        json_object_set_new(wpa, "akm_sae_ext", json_boolean(osw_network->wpa.akm_sae_ext));
        json_object_set_new(wpa, "akm_ft_eap", json_boolean(osw_network->wpa.akm_ft_eap));
        json_object_set_new(wpa, "akm_ft_eap_sha384", json_boolean(osw_network->wpa.akm_ft_eap_sha384));
        json_object_set_new(wpa, "akm_ft_psk", json_boolean(osw_network->wpa.akm_ft_psk));
        json_object_set_new(wpa, "akm_ft_sae", json_boolean(osw_network->wpa.akm_ft_sae));
        json_object_set_new(wpa, "akm_ft_sae_ext", json_boolean(osw_network->wpa.akm_ft_sae_ext));
        json_object_set_new(wpa, "pairwise_tkip", json_boolean(osw_network->wpa.pairwise_tkip));
        json_object_set_new(wpa, "pairwise_ccmp", json_boolean(osw_network->wpa.pairwise_ccmp));
        json_object_set_new(wpa, "pairwise_ccmp256", json_boolean(osw_network->wpa.pairwise_ccmp256));
        json_object_set_new(wpa, "pairwise_gcmp", json_boolean(osw_network->wpa.pairwise_gcmp));
        json_object_set_new(wpa, "pairwise_gcmp256", json_boolean(osw_network->wpa.pairwise_gcmp256));
        json_object_set_new(wpa, "pmf", json_integer(osw_network->wpa.pmf));
        json_object_set_new(wpa, "beacon_protection", json_boolean(osw_network->wpa.beacon_protection));
    }
    json_object_set_new(json, "wpa", wpa);

    return json;
}

static bool  // true on success, false on failure
osw_drv_spf13_request_config_mldsta_osw_network_deserialize_from_json(
        struct osw_drv_vif_sta_network *osw_network,
        const json_t *json)
{
    if (osw_network == NULL || json == NULL) return false;

    json_t *multi_ap = json_object_get(json, "multi_ap");
    if (json_is_boolean(multi_ap))
    {
        osw_network->multi_ap = json_boolean_value(multi_ap);
    }

    json_t *priority = json_object_get(json, "priority");
    if (json_is_integer(priority))
    {
        osw_network->priority = (int)json_integer_value(priority);
    }

    json_t *bridge_name = json_object_get(json, "bridge_name");
    if (json_is_string(bridge_name))
    {
        STRSCPY_WARN(osw_network->bridge_if_name.buf, json_string_value(bridge_name));
    }

    json_t *ssid_hex = json_object_get(json, "ssid_hex");
    if (json_is_string(ssid_hex))
    {
        const char *hex_str = json_string_value(ssid_hex);
        ssize_t str_len =
                hex2bin(hex_str,
                        strlen(hex_str),
                        (unsigned char *)osw_network->ssid.buf,
                        sizeof(osw_network->ssid.buf));
        if (str_len >= 0)
        {
            osw_network->ssid.len = (size_t)str_len;
        }
    }

    json_t *psk_hex = json_object_get(json, "psk_hex");
    if (json_is_string(psk_hex))
    {
        const char *hex_str = json_string_value(psk_hex);
        if (hex2bin(hex_str, strlen(hex_str), (unsigned char *)osw_network->psk.str, sizeof(osw_network->psk.str)) < 0)
        {
            LOGE(LOG_PREFIX("failed to parse psk from hex '%s'"), hex_str);
            return false;
        }
    }

    json_t *bssid = json_object_get(json, "bssid");
    if (json_is_string(bssid))
    {
        if (osw_hwaddr_from_cstr(json_string_value(bssid), &osw_network->bssid) == false)
        {
            LOGE(LOG_PREFIX("failed to parse bssid '%s'"), json_string_value(bssid));
            return false;
        }
    }

    json_t *wpa_json = json_object_get(json, "wpa");
    if (!json_is_object(wpa_json))
    {
        LOGE(LOG_PREFIX("missing 'wpa' object in JSON"));
        return false;
    }

    memset(&osw_network->wpa, 0, sizeof(osw_network->wpa));
    {
        osw_network->wpa.wpa = json_boolean_value(json_object_get(wpa_json, "wpa"));
        osw_network->wpa.rsn = json_boolean_value(json_object_get(wpa_json, "rsn"));
        osw_network->wpa.akm_eap = json_boolean_value(json_object_get(wpa_json, "akm_eap"));
        osw_network->wpa.akm_eap_sha256 = json_boolean_value(json_object_get(wpa_json, "akm_eap_sha256"));
        osw_network->wpa.akm_eap_sha384 = json_boolean_value(json_object_get(wpa_json, "akm_eap_sha384"));
        osw_network->wpa.akm_eap_suite_b = json_boolean_value(json_object_get(wpa_json, "akm_eap_suite_b"));
        osw_network->wpa.akm_eap_suite_b192 = json_boolean_value(json_object_get(wpa_json, "akm_eap_suite_b192"));
        osw_network->wpa.akm_psk = json_boolean_value(json_object_get(wpa_json, "akm_psk"));
        osw_network->wpa.akm_psk_sha256 = json_boolean_value(json_object_get(wpa_json, "akm_psk_sha256"));
        osw_network->wpa.akm_sae = json_boolean_value(json_object_get(wpa_json, "akm_sae"));
        osw_network->wpa.akm_sae_ext = json_boolean_value(json_object_get(wpa_json, "akm_sae_ext"));
        osw_network->wpa.akm_ft_eap = json_boolean_value(json_object_get(wpa_json, "akm_ft_eap"));
        osw_network->wpa.akm_ft_eap_sha384 = json_boolean_value(json_object_get(wpa_json, "akm_ft_eap_sha384"));
        osw_network->wpa.akm_ft_psk = json_boolean_value(json_object_get(wpa_json, "akm_ft_psk"));
        osw_network->wpa.akm_ft_sae = json_boolean_value(json_object_get(wpa_json, "akm_ft_sae"));
        osw_network->wpa.akm_ft_sae_ext = json_boolean_value(json_object_get(wpa_json, "akm_ft_sae_ext"));
        osw_network->wpa.pairwise_tkip = json_boolean_value(json_object_get(wpa_json, "pairwise_tkip"));
        osw_network->wpa.pairwise_ccmp = json_boolean_value(json_object_get(wpa_json, "pairwise_ccmp"));
        osw_network->wpa.pairwise_ccmp256 = json_boolean_value(json_object_get(wpa_json, "pairwise_ccmp256"));
        osw_network->wpa.pairwise_gcmp = json_boolean_value(json_object_get(wpa_json, "pairwise_gcmp"));
        osw_network->wpa.pairwise_gcmp256 = json_boolean_value(json_object_get(wpa_json, "pairwise_gcmp256"));
        osw_network->wpa.pmf = (enum osw_pmf)json_integer_value(json_object_get(wpa_json, "pmf"));
        osw_network->wpa.beacon_protection = json_boolean_value(json_object_get(wpa_json, "beacon_protection"));
    }

    return true;
}

static void osw_drv_spf13_request_config_mldsta_network_save_links(
        osw_drv_spf13_request_config_mldsta_network_t *network)
{
    const char *link_path = strfmta(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR "/%s", network->id_str);
    FILE *f = fopen(link_path, "wb");
    if (f == NULL)
    {
        LOGE(LOG_PREFIX("failed to open link file '%s': %d (%s)", link_path, errno, strerror(errno)));
        return;
    }

    char *json_str = json_dumps(network->phy_vif_links, JSON_COMPACT);
    if (json_str == NULL)
    {
        LOGE(LOG_PREFIX("failed to serialize links for network '%s.%s' to JSON"),
             network->ssid.buf,
             network->bridge_name);
        fclose(f);
        return;
    }

    const size_t len = strlen(json_str);
    if (fwrite(json_str, 1, len, f) != len)
    {
        LOGE(LOG_PREFIX("failed to write links for network '%s.%s' to file '%s': %d (%s)"),
             network->ssid.buf,
             network->bridge_name,
             link_path,
             errno,
             strerror(errno));
    }

    FREE(json_str);
    fclose(f);
}

struct osw_drv_vif_sta_network *osw_drv_spf13_request_config_mldsta_configured_networks(
        const char *id_str,
        const char *phy_name,
        const char *vif_name)
{
    const char *link_path = strfmta(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR "/%s", id_str);
    FILE *f = fopen(link_path, "rb");
    if (f == NULL)
    {
        LOGE(LOG_PREFIX("failed to open link file '%s': %d (%s)"), link_path, errno, strerror(errno));
        return NULL;
    }

    json_t *phy_vif_links = json_loadf(f, 0, NULL);
    fclose(f);

    if (phy_vif_links == NULL)
    {
        LOGE(LOG_PREFIX("failed to load links from file '%s': %d (%s)"), link_path, errno, strerror(errno));
        return NULL;
    }

    json_t *vifs = json_object_get(phy_vif_links, phy_name);
    if (vifs == NULL || !json_is_object(vifs))
    {
        LOGE(LOG_PREFIX("no links found for phy '%s' in file '%s'"), phy_name, link_path);
        json_decref(phy_vif_links);
        return NULL;
    }

    json_t *networks = json_object_get(vifs, vif_name);
    if (networks == NULL || !json_is_array(networks))
    {
        LOGE(LOG_PREFIX("no links found for vif '%s' in file '%s'"), vif_name, link_path);
        json_decref(phy_vif_links);
        return NULL;
    }

    struct osw_drv_vif_sta_network *head = NULL;
    struct osw_drv_vif_sta_network **tail = &head;
    size_t i;
    json_t *network;
    json_array_foreach(networks, i, network)
    {
        *tail = CALLOC(1, sizeof(**tail));
        if (*tail == NULL)
        {
            LOGE(LOG_PREFIX("failed to allocate memory for osw_network"));
            break;
        }

        if (osw_drv_spf13_request_config_mldsta_osw_network_deserialize_from_json(*tail, network) == false)
        {
            LOGE(LOG_PREFIX("failed to deserialize osw_network from JSON in file '%s'"), link_path);
            FREE(*tail);
            *tail = NULL;
            break;
        }

        tail = &(*tail)->next;
    }

    json_decref(phy_vif_links);
    return head;
}

static uint32_t osw_drv_spf13_request_config_mldsta_network_hash_crc32(
        osw_drv_spf13_request_config_mldsta_network_t *network)
{
    if (network == NULL) return 0;
    uint32_t hash = 0;
    hash = crc32(hash, (const void *)&network->wpa, sizeof(network->wpa));
    hash = crc32(hash, (const void *)&network->priority, sizeof(network->priority));
    hash = crc32(hash, (const void *)&network->multi_ap, sizeof(network->multi_ap));
    hash = crc32(hash, (const void *)&network->ssid.buf, network->ssid.len);
    hash = crc32(hash, (const void *)&network->psk.str, strlen(network->psk.str));
    if (network->bridge_name != NULL)
    {
        hash = crc32(hash, (const void *)network->bridge_name, strlen(network->bridge_name));
    }

    /* Sort is essential to ensure that the hash is consistent regardless of
     * the order of BSSIDs */
    qsort(network->bssids.list, network->bssids.count, sizeof(struct osw_hwaddr), (void *)osw_hwaddr_cmp);

    for (size_t i = 0; i < network->bssids.count; i++)
    {
        const struct osw_hwaddr *bssid = &network->bssids.list[i];
        hash = crc32(hash, (const void *)bssid->octet, sizeof(bssid->octet));
    }
    return hash;
}

static osw_drv_spf13_request_config_mldsta_network_t *osw_drv_spf13_request_config_mldsta_network_find_by_id_str(
        osw_drv_spf13_request_config_mldsta_t *mldsta_req,
        const char *id_str)
{
    if (mldsta_req == NULL) return NULL;
    if (mldsta_req->networks == NULL) return NULL;

    for (size_t i = 0; mldsta_req->n_networks > i; i++)
    {
        osw_drv_spf13_request_config_mldsta_network_t *network = &mldsta_req->networks[i];
        if (WARN_ON(network->id_str == NULL)) continue;

        const bool match = strcmp(network->id_str, id_str) == 0;
        if (match)
        {
            return network;
        }
    }
    return NULL;
}

static int osw_drv_spf13_request_config_mldsta_bridge_cmp(const char *a, const char *b)
{
    if (a == NULL && b == NULL) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;
    return strcmp(a, b);
}

static bool osw_drv_spf13_request_config_mldsta_network_can_merge(
        const osw_drv_spf13_request_config_mldsta_network_t *a,
        const osw_drv_spf13_request_config_mldsta_network_t *b)
{
    if (a == NULL || b == NULL) return true;
    const bool priority_is_different = a->priority != b->priority;
    const bool ssid_is_different = osw_ssid_cmp(&a->ssid, &b->ssid) != 0;
    const bool multi_ap_is_different = a->multi_ap != b->multi_ap;
    const bool psk_is_different = strcmp(a->psk.str, b->psk.str) != 0;
    const bool a_is_wildcard_bssid = (a->bssids.count == 0);
    const bool b_is_wildcard_bssid = (b->bssids.count == 0);
    const bool bssid_wildcard_mismatch = (a_is_wildcard_bssid != b_is_wildcard_bssid);
    const bool bridge_name_is_different =
            osw_drv_spf13_request_config_mldsta_bridge_cmp(a->bridge_name, b->bridge_name) != 0;
    if (priority_is_different) return false;
    if (ssid_is_different) return false;
    if (multi_ap_is_different) return false;
    if (psk_is_different) return false;
    if (bssid_wildcard_mismatch) return false;
    if (bridge_name_is_different) return false;
    return true;
}

static enum osw_pmf osw_drv_spf13_request_config_merge_pmf(enum osw_pmf dst, enum osw_pmf src)
{
    if (dst == OSW_PMF_DISABLED && src == OSW_PMF_DISABLED)
    {
        return OSW_PMF_DISABLED;
    }
    else if (dst == OSW_PMF_DISABLED && src == OSW_PMF_OPTIONAL)
    {
        return OSW_PMF_OPTIONAL;
    }
    else if (dst == OSW_PMF_DISABLED && src == OSW_PMF_REQUIRED)
    {
        return OSW_PMF_REQUIRED;
    }
    else if (dst == OSW_PMF_OPTIONAL && src == OSW_PMF_DISABLED)
    {
        return OSW_PMF_OPTIONAL;
    }
    else if (dst == OSW_PMF_OPTIONAL && src == OSW_PMF_OPTIONAL)
    {
        return OSW_PMF_OPTIONAL;
    }
    else if (dst == OSW_PMF_OPTIONAL && src == OSW_PMF_REQUIRED)
    {
        return OSW_PMF_OPTIONAL;
    }
    else if (dst == OSW_PMF_REQUIRED && src == OSW_PMF_DISABLED)
    {
        return OSW_PMF_REQUIRED;
    }
    else if (dst == OSW_PMF_REQUIRED && src == OSW_PMF_OPTIONAL)
    {
        return OSW_PMF_OPTIONAL;
    }
    else if (dst == OSW_PMF_REQUIRED && src == OSW_PMF_REQUIRED)
    {
        return OSW_PMF_REQUIRED;
    }
    return OSW_PMF_DISABLED;  // should never happen, but just in case
}

static void osw_drv_spf13_request_config_merge_wpa(struct osw_wpa *dst, const struct osw_wpa *src)
{
    if (WARN_ON(dst == NULL)) return;
    if (WARN_ON(src == NULL)) return;

    dst->wpa |= src->wpa;
    dst->rsn |= src->rsn;
    dst->akm_eap |= src->akm_eap;
    dst->akm_eap_sha256 |= src->akm_eap_sha256;
    dst->akm_eap_sha384 |= src->akm_eap_sha384;
    dst->akm_eap_suite_b |= src->akm_eap_suite_b;
    dst->akm_eap_suite_b192 |= src->akm_eap_suite_b192;
    dst->akm_psk |= src->akm_psk;
    dst->akm_psk_sha256 |= src->akm_psk_sha256;
    dst->akm_sae |= src->akm_sae;
    dst->akm_sae_ext |= src->akm_sae_ext;
    dst->akm_ft_eap |= src->akm_ft_eap;
    dst->akm_ft_eap_sha384 |= src->akm_ft_eap_sha384;
    dst->akm_ft_psk |= src->akm_ft_psk;
    dst->akm_ft_sae |= src->akm_ft_sae;
    dst->akm_ft_sae_ext |= src->akm_ft_sae_ext;
    dst->pairwise_tkip |= src->pairwise_tkip;
    dst->pairwise_ccmp |= src->pairwise_ccmp;
    dst->pairwise_ccmp256 |= src->pairwise_ccmp256;
    dst->pairwise_gcmp |= src->pairwise_gcmp;
    dst->pairwise_gcmp256 |= src->pairwise_gcmp256;
    dst->beacon_protection |= src->beacon_protection;
    dst->pmf = osw_drv_spf13_request_config_merge_pmf(dst->pmf, src->pmf);
    // group_rekey_seconds isn't used by supplicant
}

static void osw_drv_spf13_request_config_merge_bssids(
        osw_drv_spf13_request_config_mldsta_network_t *dst,
        const osw_drv_spf13_request_config_mldsta_network_t *src)
{
    if (dst == NULL || src == NULL) return;
    if (!osw_drv_spf13_request_config_mldsta_network_can_merge(dst, src)) return;

    for (size_t i = 0; i < src->bssids.count; i++)
    {
        const struct osw_hwaddr *bssid = &src->bssids.list[i];
        const bool not_found = (osw_hwaddr_list_contains(dst->bssids.list, dst->bssids.count, bssid) == false);
        if (not_found)
        {
            osw_hwaddr_list_append(&dst->bssids, bssid);
        }
    }
}

static void osw_drv_spf13_request_config_mldsta_network_merge_json(
        osw_drv_spf13_request_config_mldsta_network_t *dst,
        const osw_drv_spf13_request_config_mldsta_network_t *src)
{
    json_t *src_phy;
    const char *phy_name;
    json_object_foreach(src->phy_vif_links, phy_name, src_phy)
    {
        json_t *dst_phy = json_object_get(dst->phy_vif_links, phy_name);
        if (dst_phy == NULL)
        {
            dst_phy = json_object();
            json_object_set_new(dst->phy_vif_links, phy_name, dst_phy);
        }

        json_t *src_vif_networks;
        const char *vif_name;
        json_object_foreach(src_phy, vif_name, src_vif_networks)
        {
            json_t *dst_vif_networks = json_object_get(dst_phy, vif_name);
            if (dst_vif_networks == NULL)
            {
                dst_vif_networks = json_array();
                json_object_set_new(dst_phy, vif_name, dst_vif_networks);
            }

            /* Doing this is slightly more efficient than caling
             * json_array_extend() since it doesn't copy but just refs
             * the network objects.
             */
            json_t *src_network;
            size_t i;
            json_array_foreach(src_vif_networks, i, src_network)
            {
                json_array_append(dst_vif_networks, src_network);
            }
        }
    }
}

static void osw_drv_spf13_request_config_mldsta_network_update_id_str(
        osw_drv_spf13_request_config_mldsta_network_t *mldsta_network)
{
    if (mldsta_network == NULL) return;

    const uint32_t crc32 = osw_drv_spf13_request_config_mldsta_network_hash_crc32(mldsta_network);
    FREE(mldsta_network->id_str);
    mldsta_network->id_str = strfmta("%" PRIx32, crc32);
}

static void osw_drv_spf13_request_config_mldsta_network_merge(
        osw_drv_spf13_request_config_mldsta_network_t *dst,
        const osw_drv_spf13_request_config_mldsta_network_t *src)
{
    if (WARN_ON(dst == NULL)) return;
    if (WARN_ON(src == NULL)) return;
    if (osw_drv_spf13_request_config_mldsta_network_can_merge(dst, src) == false) return;

    osw_drv_spf13_request_config_merge_bssids(dst, src);
    osw_drv_spf13_request_config_merge_wpa(&dst->wpa, &src->wpa);
    FREE(dst->bridge_name);
    dst->bridge_name = STRDUP(src->bridge_name ?: "");
    dst->ssid = src->ssid;
    dst->psk = src->psk;
    dst->multi_ap = src->multi_ap;

    osw_drv_spf13_request_config_mldsta_network_merge_json(dst, src);
    osw_drv_spf13_request_config_mldsta_network_update_id_str(dst);
}

static void osw_drv_spf13_request_config_mldsta_network_fini(
        osw_drv_spf13_request_config_mldsta_network_t *mldsta_network)
{
    if (mldsta_network == NULL) return;

    FREE(mldsta_network->bssids.list);
    FREE(mldsta_network->bridge_name);
    FREE(mldsta_network->id_str);
    osw_drv_spf13_hostap_cmd_drop_array(
            mldsta_network->wpas_cmds,
            OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_MAX);
    json_decref(mldsta_network->phy_vif_links);
}

static void osw_drv_spf13_request_config_mldsta_runtime_network_fini(
        osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network)
{
    if (runtime_network == NULL) return;

    FREE(runtime_network->id_str);
    osw_drv_spf13_hostap_cmd_drop_array(
            runtime_network->cmds,
            OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_MAX);
}

static osw_drv_spf13_request_config_mldsta_network_t *osw_drv_spf13_request_config_mldsta_network_from_osw(
        const char *phy_name,
        const char *vif_name,
        const struct osw_drv_vif_sta_network *osw_network)
{
    osw_drv_spf13_request_config_mldsta_network_t *mldsta_network = CALLOC(1, sizeof(*mldsta_network));

    mldsta_network->bssids.count = 0;
    mldsta_network->bssids.list = NULL;
    const bool bssid_is_not_zero = !osw_hwaddr_is_zero(&osw_network->bssid);
    if (bssid_is_not_zero)
    {
        osw_hwaddr_list_append(&mldsta_network->bssids, &osw_network->bssid);
    }

    const char *bridge_name = osw_network->bridge_if_name.buf;
    mldsta_network->bridge_name = STRDUP(bridge_name);

    json_t *json_network = osw_drv_spf13_request_config_mldsta_osw_network_serialize_to_json(osw_network);
    if (json_network == NULL)
    {
        LOGE(LOG_PREFIX("failed to serialize network '%s.%s' to JSON"), phy_name, vif_name);
        osw_drv_spf13_request_config_mldsta_network_fini(mldsta_network);
        FREE(mldsta_network);
        return NULL;
    }

    json_t *vif_networks = json_array();
    json_array_append_new(vif_networks, json_network);

    json_t *phy_vifs = json_object();
    json_object_set_new(phy_vifs, vif_name, vif_networks);

    json_t *phys = json_object();
    json_object_set_new(phys, phy_name, phy_vifs);

    mldsta_network->ssid = osw_network->ssid;
    mldsta_network->psk = osw_network->psk;
    mldsta_network->wpa = osw_network->wpa;
    mldsta_network->multi_ap = osw_network->multi_ap;
    mldsta_network->priority = osw_network->priority;
    mldsta_network->phy_vif_links = phys;
    osw_drv_spf13_request_config_mldsta_network_update_id_str(mldsta_network);

    return mldsta_network;
}

static void osw_drv_spf13_request_config_mldsta_add_conf(
        osw_drv_spf13_request_config_mldsta_t *mldsta_req,
        const char *phy_name,
        const char *vif_name,
        const struct osw_drv_vif_config_sta *sta_conf)
{
    if (mldsta_req == NULL) return;
    if (vif_name == NULL) return;
    if (sta_conf == NULL) return;

    for (const struct osw_drv_vif_sta_network *osw_network = sta_conf->network; osw_network != NULL;
         osw_network = osw_network->next)
    {
        osw_drv_spf13_request_config_mldsta_network_t *mldsta_network =
                osw_drv_spf13_request_config_mldsta_network_from_osw(phy_name, vif_name, osw_network);

        for (size_t i = 0; mldsta_req->n_networks > i; i++)
        {
            osw_drv_spf13_request_config_mldsta_network_t *existing_network = &mldsta_req->networks[i];
            if (osw_drv_spf13_request_config_mldsta_network_can_merge(existing_network, mldsta_network))
            {
                osw_drv_spf13_request_config_mldsta_network_merge(existing_network, mldsta_network);
                osw_drv_spf13_request_config_mldsta_network_fini(mldsta_network);
                FREE(mldsta_network);
                mldsta_network = NULL;
                break;
            }
        }

        if (mldsta_network != NULL)
        {
            const size_t sz = sizeof(*mldsta_network);
            const size_t new_n = mldsta_req->n_networks + 1;
            mldsta_req->networks = REALLOC(mldsta_req->networks, new_n * sz);
            mldsta_req->networks[mldsta_req->n_networks] = *mldsta_network;
            mldsta_req->n_networks++;
        }
    }
}

static const char *osw_drv_spf13_request_config_mldsta_get_bridge_name(
        const osw_drv_spf13_request_config_mldsta_t *mldsta_req)
{
    if (mldsta_req == NULL) return NULL;

    const char *bridge_name = NULL;
    for (size_t i = 0; mldsta_req->n_networks > i; i++)
    {
        const osw_drv_spf13_request_config_mldsta_network_t *network = &mldsta_req->networks[i];
        if (bridge_name == NULL)
        {
            bridge_name = network->bridge_name;
        }

        const bool bridge_mismatch = strcmp(bridge_name, network->bridge_name);
        if (bridge_mismatch)
        {
            bridge_name = NULL;
            break;
        }
    }

    return bridge_name;
}

static void osw_drv_spf13_request_config_mldsta_build_runtime_networks(
        osw_drv_spf13_request_config_mldsta_t *mldsta_req,
        void (*done_cb)(void *priv),
        void *priv)
{
    if (mldsta_req == NULL) return;

    const bool already_built = (mldsta_req->runtime_networks != NULL);
    if (already_built) return;

    const char *reply = osw_drv_spf13_hostap_cmd_get_reply(
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS]);
    if (reply == NULL) return;

    char *lines = strdupa(reply);
    {
        char *line;
        while ((line = strsep(&lines, "\n")) != NULL)
        {
            const char *id_str = strsep(&line, " \t");
            if (id_str == NULL || *id_str == '\0') continue;
            const int id = atoi(id_str);
            const size_t new_n = mldsta_req->n_runtime_networks + 1;
            const size_t sz = sizeof(*mldsta_req->runtime_networks);
            const osw_drv_spf13_request_config_mldsta_runtime_network_t runtime_network = {
                .id = id,
            };
            mldsta_req->runtime_networks = REALLOC(mldsta_req->runtime_networks, new_n * sz);
            mldsta_req->runtime_networks[mldsta_req->n_runtime_networks] = runtime_network;
            mldsta_req->n_runtime_networks++;
        }
    }
}

static void osw_drv_spf13_request_config_mldsta_mark_keep_runtime_network(
        osw_drv_spf13_request_config_mldsta_t *mldsta_req)
{
    if (mldsta_req == NULL) return;

    const char *reply = osw_drv_spf13_hostap_cmd_get_reply(
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS]);
    if (reply == NULL) return;

    char *lines = strdupa(reply);
    char *line;
    const char *ptr_id_str = NULL;
    const char *ptr_id = NULL;
    while ((line = strsep(&lines, "\n")) != NULL)
    {
        const char *k = strsep(&line, "=");
        const char *v = strsep(&line, "\n");
        if (strcmp(k, "id_str") == 0)
        {
            ptr_id_str = v;
        }
        else if (strcmp(k, "id") == 0)
        {
            ptr_id = v;
        }
    }

    if (ptr_id_str == NULL) return;
    if (ptr_id == NULL) return;

    const int id = atoi(ptr_id);
    const bool connecting = mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE];
    const bool disconnecting = mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT];
    const bool reconnecting = connecting || disconnecting;
    if (reconnecting == false)
    {
        for (size_t i = 0; i < mldsta_req->n_runtime_networks; i++)
        {
            osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];
            if (runtime_network->id == id)
            {
                runtime_network->update = OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_KEEP;
            }
        }
    }
}

static void osw_drv_spf13_request_config_mldsta_parse_runtime_network_id_strs(
        osw_drv_spf13_request_config_mldsta_t *mldsta_req)
{
    if (mldsta_req == NULL) return;

    for (size_t i = 0; i < mldsta_req->n_runtime_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];

        if (runtime_network->id_str != NULL)
        {
            /* already parsed */
            continue;
        }

        osw_drv_spf13_hostap_cmd_t *cmd =
                runtime_network->cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_GET_ID_STR];
        const char *request = osw_drv_spf13_hostap_cmd_get_request(cmd);
        const char *reply = osw_drv_spf13_hostap_cmd_get_reply(cmd);

        if (reply == NULL)
        {
            LOGW(LOG_PREFIX_REQ(mldsta_req, "%s: no reply for runtime network ID", request));
            continue;
        }

        if (strncmp(reply, "FAIL", 4) == 0)
        {
            LOGW(LOG_PREFIX_REQ(mldsta_req, "%s: failed to get network ID: '%s'", request, reply));
            continue;
        }

        char *reply_copy = strdupa(reply);
        char *first_quote = strchr(reply_copy, '"');
        char *last_quote = strrchr(reply_copy, '"');
        if (first_quote == NULL || last_quote == NULL || first_quote >= last_quote)
        {
            LOGW(LOG_PREFIX_REQ(mldsta_req, "%s: unexpected reply format: '%s'", request, reply));
            continue;
        }

        *last_quote = '\0';                    // strip the last quote
        const char *id_str = first_quote + 1;  // skip the first quote

        runtime_network->id_str = STRDUP(id_str);
    }
}

static void osw_drv_spf13_request_config_mldsta_mark_found_networks(osw_drv_spf13_request_config_mldsta_t *mldsta_req)
{
    if (mldsta_req == NULL) return;

    for (size_t i = 0; i < mldsta_req->n_runtime_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];

        if (runtime_network->id_str == NULL)
        {
            LOGW(LOG_PREFIX_REQ(mldsta_req, "runtime network %d: no valid id_str", runtime_network->id));
            continue;
        }

        // FIXME: This could be a hash lookup?
        osw_drv_spf13_request_config_mldsta_network_t *network =
                osw_drv_spf13_request_config_mldsta_network_find_by_id_str(mldsta_req, runtime_network->id_str);
        if (network != NULL)
        {
            network->already_programmed = true;
            network->id = runtime_network->id;
            runtime_network->update = OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_KEEP;
        }
    }
}

static bool osw_drv_spf13_request_config_mldsta_poll_update_networks(
        osw_drv_spf13_request_config_mldsta_t *mldsta_req,
        void (*done_cb)(void *priv),
        void *priv)
{
    if (mldsta_req == NULL) return true;

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG] == false)
    {
        return false;
    }

    const char *ctrl_path = mldsta_req->ctrl_path;

    for (size_t i = 0; i < mldsta_req->n_runtime_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];
        switch (runtime_network->update)
        {
            case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_KEEP:
                if (runtime_network
                            ->cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_DISABLE_RECONNECT]
                    == NULL)
                {
                    /* DISABLE_NETWORK would immediatelly disconnect. That's not
                     * desired. The idea is to keep the current network if it's not
                     * clearly indicated to disconnect.
                     *
                     * But the network should not be re-used after connection is
                     * lost. Setting the BSSID filter to a relatively unlikely
                     * value should achieve this. Once that happens, the network
                     * will (eventually) get cleaned up.
                     */
                    runtime_network
                            ->cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_DISABLE_RECONNECT] =
                            osw_drv_spf13_hostap_cmd_new(
                                    osw_drv_spf13_hostap_sock_open(),
                                    ctrl_path,
                                    strfmta("SET_NETWORK %d bssid 00:00:00:00:00:01", runtime_network->id),
                                    done_cb,
                                    priv);
                }
                break;
            case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_REMOVE:
                if (runtime_network->cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_REMOVE] == NULL)
                {
                    runtime_network->cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_REMOVE] =
                            osw_drv_spf13_hostap_cmd_new(
                                    osw_drv_spf13_hostap_sock_open(),
                                    ctrl_path,
                                    strfmta("REMOVE_NETWORK %d", runtime_network->id),
                                    done_cb,
                                    priv);
                }
                break;
            case OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_UPDATE_ALREADY_CONFIGURED:
                /* nothing to do here, the network is already configured */
                break;
        }
    }

    for (size_t i = 0; mldsta_req->n_networks > i; i++)
    {
        osw_drv_spf13_request_config_mldsta_network_t *network = &mldsta_req->networks[i];
        if (network->already_programmed)
        {
            if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ENABLE_RECONNECT] != NULL)
            {
                /* If the network is already programmed, we don't need to
                 * re-program from scratch it. But we still need to set the
                 * BSSID filter to undo the unlikely case of re-adding a
                 * network that was previously removed without disconnection.
                 */
                network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ENABLE_RECONNECT] =
                        osw_drv_spf13_hostap_cmd_new(
                                osw_drv_spf13_hostap_sock_open(),
                                ctrl_path,
                                strfmta("SET_NETWORK %d bssid any", network->id),
                                done_cb,
                                priv);
            }
            continue;
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ADD_NETWORK] == NULL)
        {
            network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ADD_NETWORK] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            "ADD_NETWORK",
                            done_cb,
                            priv);
        }

        if (osw_drv_spf13_hostap_cmd_is_done(
                    network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ADD_NETWORK])
            == false)
        {
            continue;  // wait for ADD_NETWORK to complete, in the meantime check other network entries
        }

        const char *reply = osw_drv_spf13_hostap_cmd_get_reply(
                network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ADD_NETWORK]);
        if (reply == NULL)
        {
            continue;  // we can't add a new network, oops, will be signalled later FIXME
        }

        const int id = atoi(reply);

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_SSID] == NULL)
        {
            struct osw_ssid_hex ssid_hex;
            const char *ssid_hexstr = osw_ssid_into_hex(&ssid_hex, &network->ssid);
            if (ssid_hexstr != NULL)
            {
                network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_SSID] =
                        osw_drv_spf13_hostap_cmd_new(
                                osw_drv_spf13_hostap_sock_open(),
                                ctrl_path,
                                strfmta("SET_NETWORK %d ssid %s", id, ssid_hexstr),
                                done_cb,
                                priv);
            }
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_KEY_MGMT] == NULL)
        {
            const struct osw_wpa *wpa = &network->wpa;
            const char *key_mgmt = strdupafree(osw_hostap_conf_wpa_key_mgmt_from_osw(wpa));
            network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_KEY_MGMT] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            strfmta("SET_NETWORK %d key_mgmt %s", id, key_mgmt),
                            done_cb,
                            priv);
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_BSSID_ACCEPT] == NULL)
        {
            char *bssids = NULL;
            for (size_t i = 0; i < network->bssids.count; i++)
            {
                const struct osw_hwaddr *bssid = &network->bssids.list[i];
                strgrow(&bssids, OSW_HWADDR_FMT " ", OSW_HWADDR_ARG(bssid));
            }
            bssids = strdupafree(bssids);
            if (bssids != NULL)
            {
                network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_BSSID_ACCEPT] =
                        osw_drv_spf13_hostap_cmd_new(
                                osw_drv_spf13_hostap_sock_open(),
                                ctrl_path,
                                strfmta("SET_NETWORK %d bssid_accept %s", id, bssids),
                                done_cb,
                                priv);
            }
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_IEEE80211W] == NULL)
        {
            const enum osw_hostap_conf_pmf ieee80211w = osw_hostap_conf_pmf_from_osw(&network->wpa);
            network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_IEEE80211W] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            strfmta("SET_NETWORK %d ieee80211w %d", id, ieee80211w),
                            done_cb,
                            priv);
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PSK] == NULL)
        {
            // FIXME: This could compute PMK to be completely binary-safe. The
            // regular "" string can't have psk[i]<32 nor psk[i]==127.
            network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PSK] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            strfmta("SET_NETWORK %d psk \"%s\"", id, network->psk.str),
                            done_cb,
                            priv);
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PAIRWISE] == NULL)
        {
            const struct osw_wpa *wpa = &network->wpa;
            const char *pairwise = strdupafree(osw_hostap_conf_pairwise_from_osw(wpa));
            if (pairwise != NULL)
            {
                network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PAIRWISE] =
                        osw_drv_spf13_hostap_cmd_new(
                                osw_drv_spf13_hostap_sock_open(),
                                ctrl_path,
                                strfmta("SET_NETWORK %d pairwise %s", id, pairwise),
                                done_cb,
                                priv);
            }
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PROTO] == NULL)
        {
            const struct osw_wpa *wpa = &network->wpa;
            const char *proto = strdupafree(osw_hostap_conf_proto_from_osw(wpa));
            if (proto != NULL)
            {
                network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PROTO] =
                        osw_drv_spf13_hostap_cmd_new(
                                osw_drv_spf13_hostap_sock_open(),
                                ctrl_path,
                                strfmta("SET_NETWORK %d proto %s", id, proto),
                                done_cb,
                                priv);
            }
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_SCAN_SSID] == NULL)
        {
            network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_SCAN_SSID] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            strfmta("SET_NETWORK %d scan_ssid 1", id),
                            done_cb,
                            priv);
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_BEACON_PROTECTION] == NULL)
        {
            const struct osw_wpa *wpa = &network->wpa;
            if (network->wpa.pmf != OSW_PMF_DISABLED && wpa->beacon_protection == 1)
            {
                network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_BEACON_PROTECTION] =
                        osw_drv_spf13_hostap_cmd_new(
                                osw_drv_spf13_hostap_sock_open(),
                                ctrl_path,
                                strfmta("SET_NETWORK %d beacon_prot 1", id),
                                done_cb,
                                priv);
            }
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PRIORITY] == NULL)
        {
            network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_PRIORITY] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            strfmta("SET_NETWORK %d priority %d", id, network->priority),
                            done_cb,
                            priv);
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_MULTI_AP_BACKHAUL_STA] == NULL)
        {
            if (network->multi_ap)
            {
                network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_MULTI_AP_BACKHAUL_STA] =
                        osw_drv_spf13_hostap_cmd_new(
                                osw_drv_spf13_hostap_sock_open(),
                                ctrl_path,
                                strfmta("SET_NETWORK %d multi_ap_backhaul_sta 1", id),
                                done_cb,
                                priv);
            }
        }

        if (osw_drv_spf13_hostap_cmd_is_done_array(
                    network->wpas_cmds,
                    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_MAX)
            == false)
        {
            continue;  // wait for all (most) commands to complete before enabling
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ENABLE] == NULL)
        {
            network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_ENABLE] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            strfmta("ENABLE_NETWORK %d", id),
                            done_cb,
                            priv);
        }

        if (osw_drv_spf13_hostap_cmd_is_done_array(
                    network->wpas_cmds,
                    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_MAX)
            == false)
        {
            continue;  // wait for all commands to complete before comitting the id_str
                       // as its used to infer if a network is configured (fully) or not
        }

        if (network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_ID_STR] == NULL)
        {
            WARN_ON(network->id_str == NULL);
            const char *id_str = network->id_str ?: "";
            network->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_SET_ID_STR] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            strfmta("SET_NETWORK %d id_str \"%s\"", network->id, id_str),
                            done_cb,
                            priv);
        }
    }

    for (size_t i = 0; mldsta_req->n_runtime_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];
        if (osw_drv_spf13_hostap_cmd_is_done_array(
                    runtime_network->cmds,
                    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_MAX)
            == false)
        {
            return false;
        }
    }

    for (size_t i = 0; mldsta_req->n_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_network_t *network = &mldsta_req->networks[i];
        if (osw_drv_spf13_hostap_cmd_is_done_array(
                    network->wpas_cmds,
                    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_MAX)
            == false)
        {
            return false;
        }
    }

    return true;
}

bool osw_drv_spf13_request_config_mldsta_pool_is_done(osw_drv_spf13_request_config_mldsta_pool_t *pool)
{
    if (pool == NULL) return true;

    osw_drv_spf13_request_config_mldsta_t *mldsta_req = NULL;
    ds_tree_foreach (&pool->mldsta_requests, mldsta_req)
    {
        if (mldsta_req->done == false)
        {
            return false;  // at least one MLD STA request is not done
        }
    }

    return true;
}

static void osw_drv_spf13_request_config_mldsta_save_configs(osw_drv_spf13_request_config_mldsta_t *mldsta_req)
{
    for (size_t i = 0; mldsta_req->n_networks > i; i++)
    {
        osw_drv_spf13_request_config_mldsta_network_t *network = &mldsta_req->networks[i];
        osw_drv_spf13_request_config_mldsta_network_save_links(network);
    }
}

static void osw_drv_spf13_request_config_mldsta_gc_configs(osw_drv_spf13_request_config_mldsta_t *mldsta_req)
{
    DIR *dir = opendir(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR);
    if (dir == NULL)
    {
        LOGE(LOG_PREFIX_REQ(
                mldsta_req,
                "failed to open directory '%s': %s",
                OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR,
                strerror(errno)));
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        const bool current_dir = (strcmp(entry->d_name, ".") == 0);
        const bool parent_dir = (strcmp(entry->d_name, "..") == 0);
        if (current_dir || parent_dir)
        {
            continue;
        }

        const char *id_str = entry->d_name;
        bool keep = false;

        for (size_t i = 0; mldsta_req->n_networks > i; i++)
        {
            osw_drv_spf13_request_config_mldsta_network_t *network = &mldsta_req->networks[i];
            if (network->id_str == NULL) continue;

            const bool match = strcmp(network->id_str, id_str) == 0;
            if (match)
            {
                keep = true;
                break;
            }
        }

        for (size_t i = 0; i < mldsta_req->n_runtime_networks; i++)
        {
            osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];
            if (runtime_network->keep == false) continue;
            if (runtime_network->id_str == NULL) continue;

            const bool match = strcmp(runtime_network->id_str, id_str) == 0;
            if (match)
            {
                keep = true;
                break;
            }
        }

        if (keep == false)
        {
            const char *path = strfmta(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR "/%s", id_str);
            if (unlink(path) < 0)
            {
                LOGE(LOG_PREFIX_REQ(mldsta_req, "failed to unlink '%s': %s", path, strerror(errno)));
            }
            else
            {
                LOGD(LOG_PREFIX_REQ(mldsta_req, "deleted stale link file '%s'", path));
            }
        }
    }

    closedir(dir);
}

static void osw_drv_spf13_request_config_mldsta_log_summary(osw_drv_spf13_request_config_mldsta_t *mldsta_req)
{
    if (mldsta_req == NULL) return;

    LOGI(LOG_PREFIX_REQ(mldsta_req, "MLD STA request summary:"));
    LOGI(LOG_PREFIX_REQ(mldsta_req, "  netdev_name: %s", mldsta_req->netdev_name ?: "(null)"));
    LOGI(LOG_PREFIX_REQ(mldsta_req, "  ctrl_path: %s", mldsta_req->ctrl_path ?: "(null)"));
    LOGI(LOG_PREFIX_REQ(mldsta_req, "  enabled: %s", mldsta_req->enabled ? "true" : "false"));
    LOGI(LOG_PREFIX_REQ(mldsta_req, "  is_mld: %s", mldsta_req->is_mld ? "true" : "false"));
    LOGI(LOG_PREFIX_REQ(mldsta_req, "  phys_vifs: %s", mldsta_req->phys_vifs ?: "(null)"));
    LOGI(LOG_PREFIX_REQ(mldsta_req, "  n_networks: %zu", mldsta_req->n_networks));
    LOGI(LOG_PREFIX_REQ(mldsta_req, "  n_runtime_networks: %zu", mldsta_req->n_runtime_networks));

    for (size_t i = 0; i < OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_MAX; i++)
    {
        if (mldsta_req->wpas_cmds_planned[i])
        {
            LOGI(LOG_PREFIX_REQ(
                    mldsta_req,
                    "  wpas_cmds[%zu]: %s: %p: %s",
                    i,
                    osw_drv_spf13_request_config_mldsta_wpas_cmd_to_cstr(i),
                    mldsta_req->wpas_cmds[i],
                    osw_drv_spf13_hostap_cmd_get_reply(mldsta_req->wpas_cmds[i]) ?: "(null)"));
        }
    }

    for (size_t i = 0; i < mldsta_req->n_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_network_t *network = &mldsta_req->networks[i];
        char *wpa = NULL;
        {
            if (network->wpa.wpa) strgrow(&wpa, "wpa,");
            if (network->wpa.rsn) strgrow(&wpa, "rsn,");
            if (network->wpa.akm_eap) strgrow(&wpa, "akm_eap,");
            if (network->wpa.akm_eap_sha256) strgrow(&wpa, "akm_eap_sha256,");
            if (network->wpa.akm_eap_sha384) strgrow(&wpa, "akm_eap_sha384,");
            if (network->wpa.akm_eap_suite_b) strgrow(&wpa, "akm_eap_suite_b,");
            if (network->wpa.akm_eap_suite_b192) strgrow(&wpa, "akm_eap_suite_b192,");
            if (network->wpa.akm_psk) strgrow(&wpa, "akm_psk,");
            if (network->wpa.akm_psk_sha256) strgrow(&wpa, "akm_psk_sha256,");
            if (network->wpa.akm_sae) strgrow(&wpa, "akm_sae,");
            if (network->wpa.akm_sae_ext) strgrow(&wpa, "akm_sae_ext,");
            if (network->wpa.akm_ft_eap) strgrow(&wpa, "akm_ft_eap,");
            if (network->wpa.akm_ft_eap_sha384) strgrow(&wpa, "akm_ft_eap_sha384,");
            if (network->wpa.akm_ft_psk) strgrow(&wpa, "akm_ft_psk,");
            if (network->wpa.akm_ft_sae) strgrow(&wpa, "akm_ft_sae,");
            if (network->wpa.akm_ft_sae_ext) strgrow(&wpa, "akm_ft_sae_ext,");
            if (network->wpa.pairwise_tkip) strgrow(&wpa, "pairwise_tkip,");
            if (network->wpa.pairwise_ccmp) strgrow(&wpa, "pairwise_ccmp,");
            if (network->wpa.pairwise_ccmp256) strgrow(&wpa, "pairwise_ccmp256,");
            if (network->wpa.pairwise_gcmp) strgrow(&wpa, "pairwise_gcmp,");
            if (network->wpa.pairwise_gcmp256) strgrow(&wpa, "pairwise_gcmp256,");
            switch (network->wpa.pmf)
            {
                case OSW_PMF_DISABLED:
                    strgrow(&wpa, "pmf_disabled,");
                    break;
                case OSW_PMF_OPTIONAL:
                    strgrow(&wpa, "pmf_optional,");
                    break;
                case OSW_PMF_REQUIRED:
                    strgrow(&wpa, "pmf_required,");
                    break;
            }
            if (network->wpa.beacon_protection) strgrow(&wpa, "beacon_protection,");

            strchomp(wpa, ",");
        }

        LOGI(LOG_PREFIX_REQ(mldsta_req, "  network[%zu]:", i));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    id: %d", network->id));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    id_str: %s", network->id_str ?: "(null)"));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    bridge_name: %s", network->bridge_name ?: "(null)"));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    ssid: " OSW_SSID_FMT, OSW_SSID_ARG(&network->ssid)));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    bssids:"));
        for (size_t j = 0; j < network->bssids.count; j++)
        {
            const struct osw_hwaddr *bssid = &network->bssids.list[j];
            LOGI(LOG_PREFIX_REQ(mldsta_req, "      " OSW_HWADDR_FMT, OSW_HWADDR_ARG(bssid)));
        }
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    wpa: %s", wpa ?: "(null)"));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    priority: %d", network->priority));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    multi_ap: %s", network->multi_ap ? "true" : "false"));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    already_programmed: %s", network->already_programmed ? "true" : "false"));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    wpas_cmds:"));
        for (size_t j = 0; j < OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_NETWORK_WPAS_CMD_MAX; j++)
        {
            if (network->wpas_cmds[j] != NULL)
            {
                LOGI(LOG_PREFIX_REQ(
                        mldsta_req,
                        "      %s: %p: %s",
                        osw_drv_spf13_request_config_mldsta_network_wpas_cmd_to_cstr(j),
                        network->wpas_cmds[j],
                        osw_drv_spf13_hostap_cmd_get_reply(network->wpas_cmds[j]) ?: "(null)"));
            }
        }
    }

    for (size_t i = 0; i < mldsta_req->n_runtime_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];
        LOGI(LOG_PREFIX_REQ(mldsta_req, "  runtime_network[%zu]:", i));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    id: %d", runtime_network->id));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    id_str: %s", runtime_network->id_str ?: "(null)"));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    keep: %s", runtime_network->keep ? "true" : "false"));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    wanted: %s", runtime_network->wanted ? "true" : "false"));
        LOGI(LOG_PREFIX_REQ(
                mldsta_req,
                "    update: %s",
                osw_drv_spf13_request_config_mldsta_runtime_network_update_to_cstr(runtime_network->update)));
        LOGI(LOG_PREFIX_REQ(mldsta_req, "    cmds:"));
        for (size_t j = 0; j < OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_MAX; j++)
        {
            if (runtime_network->cmds[j] != NULL)
            {
                LOGI(LOG_PREFIX_REQ(
                        mldsta_req,
                        "      %s: %p: %s",
                        osw_drv_spf13_request_config_mldsta_runtime_network_wpas_cmd_to_cstr(j),
                        runtime_network->cmds[j],
                        osw_drv_spf13_hostap_cmd_get_reply(runtime_network->cmds[j]) ?: "(null)"));
            }
        }
    }

    {
        LOGI(LOG_PREFIX_REQ(mldsta_req, "  links in directory '%s':", OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR));
        DIR *dir = opendir(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR);
        if (dir == NULL)
        {
            LOGE(LOG_PREFIX_REQ(
                    mldsta_req,
                    "failed to open directory '%s': %s",
                    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR,
                    strerror(errno)));
        }
        else
        {
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL)
            {
                const bool current_dir = (strcmp(entry->d_name, ".") == 0);
                const bool parent_dir = (strcmp(entry->d_name, "..") == 0);
                if (current_dir || parent_dir) continue;

                LOGI(LOG_PREFIX_REQ(mldsta_req, "    link file: %s", entry->d_name));
            }
            closedir(dir);
        }
    }

    {
        const char *runtime_bridge_path =
                strfmta(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR "/%s", mldsta_req->netdev_name);
        const char *runtime_bridge_name = file_geta(runtime_bridge_path);
        LOGI(LOG_PREFIX_REQ(
                mldsta_req,
                "  runtime bridge link: %s -> %s",
                runtime_bridge_path,
                runtime_bridge_name ?: "(null)"));
    }
}

static void osw_drv_spf13_request_config_mldsta_poll(void *priv)
{
    osw_drv_spf13_request_config_mldsta_t *mldsta_req = priv;
    if (mldsta_req == NULL) return;
    if (mldsta_req->done) return;

    const char *glob_path = osw_drv_spf13_hostap_path_supplicant_global();
    const char *ctrl_path = mldsta_req->ctrl_path;

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE])
    {
        if (mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE] != NULL)
        {
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE] = osw_drv_spf13_hostap_cmd_new(
                    osw_drv_spf13_hostap_sock_open(),
                    glob_path,
                    strfmta("REMOVE_INTERFACE %s", mldsta_req->netdev_name),
                    osw_drv_spf13_request_config_mldsta_poll,
                    mldsta_req);

            const char *runtime_bridge_path =
                    strfmta(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR "/%s", mldsta_req->netdev_name);
            const int err = unlink(runtime_bridge_path);
            if (err < 0 && errno != ENOENT)
            {
                LOGE(LOG_PREFIX_REQ(mldsta_req, "failed to unlink '%s': %s", runtime_bridge_path, strerror(errno)));
            }
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done(mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE])
        == false)
    {
        return;  // wait for remove to complete
    }

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD])
    {
        if (mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD] != NULL)
        {
            const char *drv_name = "nl80211";
            const char *drv_param = "";
            const char *bridge_name = osw_drv_spf13_request_config_mldsta_get_bridge_name(mldsta_req) ?: "";
            const char *ctrl_base = osw_drv_spf13_hostap_path_supplicant_ctrl_base();
            const char *conf_path = "/var/run/supplicant.conf";
            // FIXME: add mlo skip time, need to test if its even still necessary
            file_put(
                    conf_path,
                    strfmta("ctrl_interface=%s\n"
                            "update_config=1\n"
                            "mld_sta=1\n",
                            ctrl_base));
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD] = osw_drv_spf13_hostap_cmd_new(
                    osw_drv_spf13_hostap_sock_open(),
                    glob_path,
                    strfmta("INTERFACE_ADD %s\t%s\t%s\t%s\t%s\t%s",
                            mldsta_req->netdev_name,
                            conf_path,
                            drv_name,
                            ctrl_base,
                            drv_param,
                            bridge_name),
                    osw_drv_spf13_request_config_mldsta_poll,
                    mldsta_req);
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done(mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD])
        == false)
    {
        return;  // wait for add to complete
    }

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD])
    {
        const char *runtime_bridge_path =
                strfmta(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR "/%s", mldsta_req->netdev_name);
        const char *bridge_name = osw_drv_spf13_request_config_mldsta_get_bridge_name(mldsta_req);
        if (bridge_name == NULL)
        {
            LOGE(LOG_PREFIX_REQ(mldsta_req, "failed to get bridge name after ADD"));
            return;
        }
        file_put(runtime_bridge_path, bridge_name);
    }

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LOG_LEVEL])
    {
        if (mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LOG_LEVEL] != NULL)
        {
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LOG_LEVEL] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            "LOG_LEVEL DEBUG",
                            osw_drv_spf13_request_config_mldsta_poll,
                            mldsta_req);
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done(mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LOG_LEVEL])
        == false)
    {
        return;  // wait for log level to complete
    }

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT])
    {
        if (mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT] != NULL)
        {
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            "DISCONNECT",
                            osw_drv_spf13_request_config_mldsta_poll,
                            mldsta_req);
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done(mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT])
        == false)
    {
        return;  // wait for disconnect to complete
    }

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS])
    {
        if (mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS] != NULL)
        {
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS] = osw_drv_spf13_hostap_cmd_new(
                    osw_drv_spf13_hostap_sock_open(),
                    ctrl_path,
                    "STATUS",
                    osw_drv_spf13_request_config_mldsta_poll,
                    mldsta_req);
        }
    }

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS])
    {
        if (mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS] != NULL)
        {
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            "LIST_NETWORKS",
                            osw_drv_spf13_request_config_mldsta_poll,
                            mldsta_req);
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done(
                mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS])
        == false)
    {
        return;  // wait for list networks to complete
    }

    osw_drv_spf13_request_config_mldsta_build_runtime_networks(
            mldsta_req,
            osw_drv_spf13_request_config_mldsta_poll,
            mldsta_req);

    for (size_t i = 0; i < mldsta_req->n_runtime_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];
        if (runtime_network->cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_GET_ID_STR] == NULL)
        {
            runtime_network->cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_GET_ID_STR] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            strfmta("GET_NETWORK %d id_str", runtime_network->id),
                            osw_drv_spf13_request_config_mldsta_poll,
                            mldsta_req);
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done(mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS])
        == false)
    {
        return;  // wait for status to complete
    }

    for (size_t i = 0; i < mldsta_req->n_runtime_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];
        if (osw_drv_spf13_hostap_cmd_is_done_array(
                    runtime_network->cmds,
                    OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_RUNTIME_NETWORK_WPAS_CMD_MAX)
            == false)
        {
            return;  // wait for get id_str to complete
        }
    }

    osw_drv_spf13_request_config_mldsta_parse_runtime_network_id_strs(mldsta_req);
    osw_drv_spf13_request_config_mldsta_mark_keep_runtime_network(mldsta_req);
    osw_drv_spf13_request_config_mldsta_mark_found_networks(mldsta_req);

    const bool done = osw_drv_spf13_request_config_mldsta_poll_update_networks(
            mldsta_req,
            osw_drv_spf13_request_config_mldsta_poll,
            mldsta_req);
    if (done == false)
    {
        return;  // wait for update networks to complete
    }

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE])
    {
        if (mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE] != NULL)
        {
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            "REASSOCIATE",
                            osw_drv_spf13_request_config_mldsta_poll,
                            mldsta_req);
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done(
                mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE])
        == false)
    {
        return;  // wait for reassociate to complete
    }

    if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG])
    {
        if (mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG] != NULL)
        {
            mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG] =
                    osw_drv_spf13_hostap_cmd_new(
                            osw_drv_spf13_hostap_sock_open(),
                            ctrl_path,
                            "SAVE_CONFIG",
                            osw_drv_spf13_request_config_mldsta_poll,
                            mldsta_req);
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done(
                mldsta_req->wpas_cmds[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG])
        == false)
    {
        return;  // wait for save config to complete
    }

    mldsta_req->done = true;

    if (osw_drv_spf13_request_config_mldsta_pool_is_done(mldsta_req->pool))
    {
        // FIXME: This should only be done if all relevant commands were successful.
        osw_drv_spf13_request_config_mldsta_save_configs(mldsta_req);
        osw_drv_spf13_request_config_mldsta_gc_configs(mldsta_req);
        osw_drv_spf13_request_config_mldsta_log_summary(mldsta_req);
        if (mldsta_req->pool->done_cb != NULL)
        {
            mldsta_req->pool->done_cb(mldsta_req->pool->done_priv);
        }
    }
}

static void osw_drv_spf13_request_config_mldsta_drop(osw_drv_spf13_request_config_mldsta_t *mldsta_req)
{
    if (mldsta_req == NULL) return;

    ds_tree_remove(&mldsta_req->pool->mldsta_requests, mldsta_req);

    for (size_t i = 0; mldsta_req->n_networks > i; i++)
    {
        osw_drv_spf13_request_config_mldsta_network_t *network = &mldsta_req->networks[i];
        osw_drv_spf13_request_config_mldsta_network_fini(network);
    }

    for (size_t i = 0; i < mldsta_req->n_runtime_networks; i++)
    {
        osw_drv_spf13_request_config_mldsta_runtime_network_t *runtime_network = &mldsta_req->runtime_networks[i];
        osw_drv_spf13_request_config_mldsta_runtime_network_fini(runtime_network);
    }

    osw_drv_spf13_hostap_cmd_drop_array(mldsta_req->wpas_cmds, OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_MAX);
    FREE(mldsta_req->runtime_networks);
    FREE(mldsta_req->networks);
    FREE(mldsta_req->netdev_name);
    FREE(mldsta_req->ctrl_path);
    FREE(mldsta_req);
}

static osw_drv_spf13_request_config_mldsta_t *osw_drv_spf13_request_config_mldsta_find_or_new(
        osw_drv_spf13_request_config_mldsta_pool_t *pool,
        const char *netdev_name)
{
    if (pool == NULL) return NULL;
    if (netdev_name == NULL) return NULL;

    osw_drv_spf13_request_config_mldsta_t *mldsta_req = ds_tree_find(&pool->mldsta_requests, netdev_name);
    if (mldsta_req != NULL)
    {
        return mldsta_req;
    }

    const uint32_t netdev_ifindex = osw_drv_spf13_netdev_get_ifindex(netdev_name);
    if (netdev_ifindex == 0)
    {
        LOGE(LOG_PREFIX("failed to get ifindex for netdev %s", netdev_name));
        return NULL;
    }

    mldsta_req = CALLOC(1, sizeof(*mldsta_req));
    mldsta_req->netdev_ifindex = netdev_ifindex;
    mldsta_req->netdev_name = STRDUP(netdev_name);
    mldsta_req->ctrl_path = osw_drv_spf13_hostap_path_supplicant_ctrl_bss(netdev_name);
    mldsta_req->pool = pool;
    ds_tree_insert(&pool->mldsta_requests, mldsta_req, mldsta_req->netdev_name);

    return mldsta_req;
}

void osw_drv_spf13_request_config_mldsta_pool_flush(osw_drv_spf13_request_config_mldsta_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_config_mldsta_t *mldsta_req = NULL;
    while ((mldsta_req = ds_tree_head(&pool->mldsta_requests)) != NULL)
    {
        osw_drv_spf13_request_config_mldsta_drop(mldsta_req);
    }
}

void osw_drv_spf13_request_config_mldsta_pool_drop(osw_drv_spf13_request_config_mldsta_pool_t *pool)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_config_mldsta_pool_flush(pool);
    FREE(pool);
}

osw_drv_spf13_request_config_mldsta_pool_t *osw_drv_spf13_request_config_mldsta_pool_new(
        void (*done_cb)(void *priv),
        void *done_priv)
{
    osw_drv_spf13_request_config_mldsta_pool_t *pool = CALLOC(1, sizeof(*pool));
    pool->done_cb = done_cb;
    pool->done_priv = done_priv;
    ds_tree_init(&pool->mldsta_requests, (ds_key_cmp_t *)strcmp, osw_drv_spf13_request_config_mldsta_t, node_pool);
    return pool;
}

void osw_drv_spf13_request_config_mldsta_pool_populate(
        osw_drv_spf13_request_config_mldsta_pool_t *pool,
        const struct osw_drv_conf *drv_conf)
{
    if (pool == NULL) return;

    osw_drv_spf13_request_config_mldsta_pool_flush(pool);

    for (size_t phy_i = 0; phy_i < drv_conf->n_phy_list; phy_i++)
    {
        struct osw_drv_phy_config *phy_conf = &drv_conf->phy_list[phy_i];
        const char *phy_name = phy_conf->phy_name;

        for (size_t vif_i = 0; vif_i < phy_conf->vif_list.count; vif_i++)
        {
            const struct osw_drv_vif_config *vif_conf = &phy_conf->vif_list.list[vif_i];
            const struct osw_drv_vif_config_sta *sta_conf = &vif_conf->u.sta;
            const char *vif_name = vif_conf->vif_name;

            if (vif_conf->vif_type != OSW_VIF_STA) continue;

            /* OSW maintains VIF=link semantics. Therefore it may have multiple
             * VIFs across different PHYs and constitute a single MLD.
             *
             * In other words this possibly squashes multiple VIFs into a
             * single MLDSTA request. */
            const char *netdev_name = strdupafree(osw_drv_spf13_netdev_from_phy_and_vif(phy_name, vif_name));
            osw_drv_spf13_request_config_mldsta_t *mldsta_req =
                    osw_drv_spf13_request_config_mldsta_find_or_new(pool, netdev_name);

            mldsta_req->is_mld = osw_drv_spf13_netdev_is_qca_vap_mld(netdev_name);
            mldsta_req->enabled |= vif_conf->enabled;

            if (mldsta_req->phys_vifs != NULL)
            {
                strgrow(&mldsta_req->phys_vifs, ",");
            }

            strgrow(&mldsta_req->phys_vifs, "%s:%s", phy_name, vif_name);

            if (vif_conf->enabled_changed)
            {
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE] = true;
                if (vif_conf->enabled)
                {
                    mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD] = true;
                    mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LOG_LEVEL] = true;
                }
            }

            switch (sta_conf->operation)
            {
                case OSW_DRV_VIF_CONFIG_STA_DISCONNECT:
                    mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT] = true;
                    break;
                case OSW_DRV_VIF_CONFIG_STA_CONNECT:
                    mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE] = true;
                    break;
                case OSW_DRV_VIF_CONFIG_STA_RECONNECT:
                    mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT] = true;
                    mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE] = true;
                    break;
                case OSW_DRV_VIF_CONFIG_STA_NOP:
                    break;
            }

            if (sta_conf->network_changed)
            {
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS] = true;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS] = true;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG] = true;
            }

            /* Some actions have side-effects that invalidate the state that
             * was being reported until now. Instead of cherry-picking which,
             * just invalidate the VIF on any. This reduces chance of missing
             * something and re-reading the same thing is harmless
             * functionally. Perhaps slightly taxing on the CPU. Likely
             * insignificant given number of (re)configurations system
             * experiences normally.
             */
            for (size_t i = 0; i < OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_MAX; i++)
            {
                if (mldsta_req->wpas_cmds_planned[i])
                {
                    osw_drv_spf13_invalidations_vif(pool->invalidations, phy_name, vif_name);
                    break;
                }
            }

            osw_drv_spf13_request_config_mldsta_add_conf(mldsta_req, phy_name, vif_name, sta_conf);
        }
    }

    osw_drv_spf13_request_config_mldsta_t *mldsta_req = NULL;
    ds_tree_foreach (&pool->mldsta_requests, mldsta_req)
    {
        if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE] == true)
        {
            continue;
        }

        if (mldsta_req->n_networks == 0)
        {
            continue;
        }

        const char *bridge_name = osw_drv_spf13_request_config_mldsta_get_bridge_name(mldsta_req);
        if (bridge_name == NULL)
        {
            LOGE(LOG_PREFIX_REQ(mldsta_req, "failed to get bridge name for netdev %s", mldsta_req->netdev_name));
            continue;
        }

        const char *runtime_bridge_path =
                strfmta(OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_LINK_DIR "/%s", mldsta_req->netdev_name);
        const char *runtime_bridge_name = file_geta(runtime_bridge_path);
        if (runtime_bridge_name == NULL || strcmp(runtime_bridge_name, bridge_name) != 0)
        {
            LOGD(LOG_PREFIX_REQ(
                    mldsta_req,
                    "runtime bridge name '%s' does not match expected '%s', updating",
                    runtime_bridge_name,
                    bridge_name));

            mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE] = true;
            if (mldsta_req->enabled)
            {
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD] = true;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LOG_LEVEL] = true;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS] = true;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS] = true;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG] = true;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE] = true;
            }
        }
    }

    osw_drv_spf13_request_config_mldsta_t *tmp;
    ds_tree_foreach_safe (&pool->mldsta_requests, mldsta_req, tmp)
    {
        if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REMOVE])
        {
            /* When removing the MLD STA, we don't need to do anything else
             * because the supplicant will remove all networks and the
             * MLD STA itself. However the OSW signalling may implicitly signal
             * clearing of the network lists, etc.
             */
            if (mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_ADD] == false)
            {
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LOG_LEVEL] = true;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_STATUS] = false;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_LIST_NETWORKS] = false;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_DISCONNECT] = false;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_REASSOCIATE] = false;
                mldsta_req->wpas_cmds_planned[OSW_DRV_SPF13_REQUEST_CONFIG_MLDSTA_WPAS_CMD_SAVE_CONFIG] = false;
            }
        }

        osw_drv_spf13_request_config_mldsta_poll(mldsta_req);
    }
}
