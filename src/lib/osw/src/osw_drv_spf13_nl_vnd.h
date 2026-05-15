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

#ifndef OSW_DRV_SPF13_NL_VND_H_INCLUDED
#define OSW_DRV_SPF13_NL_VND_H_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <netlink/netlink.h>

#include <osw_types.h>
#include <osw_tlv.h>

#define DECLARE_VAP_PARAM_U32(GET, SET)                                                   \
    struct nl_msg *GET(uint32_t nl80211_family_id, uint32_t ifindex, int8_t mlo_link_id); \
    struct nl_msg *SET(uint32_t nl80211_family_id, uint32_t ifindex, int8_t mlo_link_id, uint32_t value);

#define DECLARE_RADIO_PARAM_U32(GET, SET)                             \
    struct nl_msg *GET(uint32_t nl80211_family_id, uint32_t ifindex); \
    struct nl_msg *SET(uint32_t nl80211_family_id, uint32_t ifindex, uint32_t value);

struct osw_drv_spf13_nl_vnd_generic
{
    uint32_t nl80211_family_id;
    uint32_t ifindex;
    int8_t mlo_link_id;
    uint32_t vendor_cmd;
    uint32_t generic_cmd;
    uint32_t value;
    uint32_t flags;
    const void *data_ptr;
    size_t data_len;
};

struct osw_drv_spf13_nl_vnd_wifi_param_get
{
    uint32_t nl80211_family_id;
    uint32_t ifindex;
    int8_t mlo_link_id;
    uint32_t param_id;
};

struct osw_drv_spf13_nl_vnd_wifi_param_set
{
    uint32_t nl80211_family_id;
    uint32_t ifindex;
    int8_t mlo_link_id;
    uint32_t param_id;
    const void *data_ptr;
    size_t data_len;
};

struct osw_drv_spf13_nl_vnd_wifi_param_set_u32
{
    uint32_t nl80211_family_id;
    uint32_t ifindex;
    int8_t mlo_link_id;
    uint32_t param_id;
    uint32_t value;
};

typedef struct osw_drv_spf13_nl_vnd_generic osw_drv_spf13_nl_vnd_generic_t;
typedef struct osw_drv_spf13_nl_vnd_wifi_param_get osw_drv_spf13_nl_vnd_wifi_param_get_t;
typedef struct osw_drv_spf13_nl_vnd_wifi_param_set osw_drv_spf13_nl_vnd_wifi_param_set_t;
typedef struct osw_drv_spf13_nl_vnd_wifi_param_set_u32 osw_drv_spf13_nl_vnd_wifi_param_set_u32_t;

const void *osw_drv_spf13_nl_vnd_generic_from_msg(struct nl_msg *msg, uint32_t *len, uint32_t *flags);

const uint32_t *osw_drv_spf13_nl_vnd_u32_from_msg(struct nl_msg *msg);

struct nl_msg *osw_drv_spf13_nl_vnd_acl_del(
        uint32_t nl80211_family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_hwaddr *mac_addr);

struct nl_msg *osw_drv_spf13_nl_vnd_acl_add(
        uint32_t nl80211_family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_hwaddr *mac_addr);

enum osw_acl_policy osw_drv_spf13_nl_vnd_acl_policy_from_u32(uint32_t value);

uint32_t osw_drv_spf13_nl_vnd_acl_policy_to_u32(enum osw_acl_policy acl_policy);

struct nl_msg *osw_drv_spf13_nl_vnd_acl_get(uint32_t nl80211_family_id, uint32_t ifindex, int8_t mlo_link_id);

struct nl_msg *osw_drv_spf13_nl_vnd_acl_policy_get(uint32_t nl80211_family_id, uint32_t ifindex, int8_t mlo_link_id);

struct nl_msg *osw_drv_spf13_nl_vnd_acl_policy_set(
        uint32_t nl80211_family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        enum osw_acl_policy acl_policy);

struct osw_channel_state *osw_drv_spf13_nl_vnd_chaninfo_parse(struct nl_msg *msg, size_t *count);

struct nl_msg *osw_drv_spf13_nl_vnd_chaninfo_get(uint32_t nl80211_family_id, uint32_t ifindex);

struct nl_msg *osw_drv_spf13_nl_vnd_radio_country_get(uint32_t nl80211_family_id, uint32_t ifindex);

bool osw_drv_spf13_nl_vnd_radio_country_parse(struct nl_msg *msg, char *country_code, size_t country_code_len);

DECLARE_RADIO_PARAM_U32(  // bitmask
        osw_drv_spf13_nl_vnd_radio_param_rx_chainmask_get,
        osw_drv_spf13_nl_vnd_radio_param_rx_chainmask_set);

DECLARE_RADIO_PARAM_U32(  // bitmask
        osw_drv_spf13_nl_vnd_radio_param_tx_chainmask_get,
        osw_drv_spf13_nl_vnd_radio_param_tx_chainmask_set);

DECLARE_RADIO_PARAM_U32(  // code only get
        osw_drv_spf13_nl_vnd_radio_param_reg_domain_get,
        osw_drv_spf13_nl_vnd_radio_param_reg_domain_set);

DECLARE_RADIO_PARAM_U32(  // iso3166 number, only get
        osw_drv_spf13_nl_vnd_radio_param_country_id_get,
        osw_drv_spf13_nl_vnd_radio_param_country_id_set);

DECLARE_RADIO_PARAM_U32(  // freq mhz
        osw_drv_spf13_nl_vnd_radio_param_next_radar_freq_get,
        osw_drv_spf13_nl_vnd_radio_param_next_radar_freq_set);

DECLARE_RADIO_PARAM_U32(  // width in MHz
        osw_drv_spf13_nl_vnd_radio_param_next_radar_width_get,
        osw_drv_spf13_nl_vnd_radio_param_next_radar_width_set);

DECLARE_RADIO_PARAM_U32(  // only set, needs "1"
        osw_drv_spf13_nl_vnd_radio_param_flush_peer_rate_stats_get,
        osw_drv_spf13_nl_vnd_radio_param_flush_peer_rate_stats_set);

DECLARE_VAP_PARAM_U32(  // kbps
        osw_drv_spf13_nl_vnd_vap_param_bcn_rate_get,
        osw_drv_spf13_nl_vnd_vap_param_bcn_rate_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_mgmt_rate_get,
        osw_drv_spf13_nl_vnd_vap_param_mgmt_rate_set);

DECLARE_VAP_PARAM_U32(  // kbps
        osw_drv_spf13_nl_vnd_vap_param_mcast_rate_get,
        osw_drv_spf13_nl_vnd_vap_param_mcast_rate_set);

DECLARE_VAP_PARAM_U32(  // kbps
        osw_drv_spf13_nl_vnd_vap_param_bcast_rate_get,
        osw_drv_spf13_nl_vnd_vap_param_bcast_rate_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_rrm_get,
        osw_drv_spf13_nl_vnd_vap_param_rrm_set);

DECLARE_VAP_PARAM_U32(  // bitmask, see osw_drv_spf13_nl_vnd_me_parse(), osw_drv_spf13_nl_vnd_me_build()
        osw_drv_spf13_nl_vnd_vap_param_me_get,
        osw_drv_spf13_nl_vnd_vap_param_me_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_mbss_en_get,
        osw_drv_spf13_nl_vnd_vap_param_mbss_en_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_mbss_tx_vdev_get,
        osw_drv_spf13_nl_vnd_vap_param_mbss_tx_vdev_set);

DECLARE_VAP_PARAM_U32(  // int
        osw_drv_spf13_nl_vnd_vap_param_mbss_group_get,
        osw_drv_spf13_nl_vnd_vap_param_mbss_group_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_ap_bridge_get,
        osw_drv_spf13_nl_vnd_vap_param_ap_bridge_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_uapsd_get,
        osw_drv_spf13_nl_vnd_vap_param_uapsd_set);

DECLARE_VAP_PARAM_U32(  // bool, settter unusable
        osw_drv_spf13_nl_vnd_vap_param_vdev_up_get,
        osw_drv_spf13_nl_vnd_vap_param_vdev_up_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_mbo_get,
        osw_drv_spf13_nl_vnd_vap_param_mbo_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_oce_get,
        osw_drv_spf13_nl_vnd_vap_param_oce_set);

DECLARE_VAP_PARAM_U32(  // dbm
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_min_rssi_get,
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_min_rssi_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_reject_get,
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_reject_set);

DECLARE_VAP_PARAM_U32(  // seconds
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_retry_delay_get,
        osw_drv_spf13_nl_vnd_vap_param_oce_assoc_retry_delay_set);

DECLARE_VAP_PARAM_U32(  // number of stations
        osw_drv_spf13_nl_vnd_vap_param_max_sta_get,
        osw_drv_spf13_nl_vnd_vap_param_max_sta_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_he_dl_mu_ofdma_get,
        osw_drv_spf13_nl_vnd_vap_param_he_dl_mu_ofdma_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_he_ul_mu_ofdma_get,
        osw_drv_spf13_nl_vnd_vap_param_he_ul_mu_ofdma_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_eht_dl_mu_ofdma_get,
        osw_drv_spf13_nl_vnd_vap_param_eht_dl_mu_ofdma_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_eht_ul_mu_ofdma_get,
        osw_drv_spf13_nl_vnd_vap_param_eht_ul_mu_ofdma_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_powersave_get,
        osw_drv_spf13_nl_vnd_vap_param_powersave_set);

DECLARE_VAP_PARAM_U32(  // bool
        osw_drv_spf13_nl_vnd_vap_param_athnewind_get,
        osw_drv_spf13_nl_vnd_vap_param_athnewind_set);

bool osw_drv_spf13_nl_vnd_vap_param_me_parse(
        const uint32_t *value,
        bool *tunneling,
        bool *translating,
        bool *no_snooping);

uint32_t osw_drv_spf13_nl_vnd_vap_param_me_build(bool tunneling, bool translating, bool no_snooping);

struct nl_msg *osw_drv_spf13_nl_vnd_radio_chanswitch(
        uint32_t nl80211_family_id,
        uint32_t wifi_ifindex,
        const struct osw_channel *c,
        int tbtt);

struct nl_msg *osw_drv_spf13_nl_vnd_vap_list_sta(uint32_t family_id, uint32_t ifindex, int8_t mlo_link_id);

typedef void *osw_drv_spf13_nl_vnd_sta_info_t;

const osw_drv_spf13_nl_vnd_sta_info_t *osw_drv_spf13_nl_vnd_sta_info_get_first(struct nl_msg *msg, size_t *len);

const osw_drv_spf13_nl_vnd_sta_info_t *osw_drv_spf13_nl_vnd_sta_info_get_next(
        const osw_drv_spf13_nl_vnd_sta_info_t *info,
        size_t *remaining);

const struct osw_hwaddr *osw_drv_spf13_nl_vnd_sta_info_get_addr(const osw_drv_spf13_nl_vnd_sta_info_t *info);

const struct osw_hwaddr *osw_drv_spf13_nl_vnd_sta_info_get_mld_addr(const osw_drv_spf13_nl_vnd_sta_info_t *info);

enum osw_drv_spf13_nl_vnd_vap_kickmac_action
{
    OSW_DRV_SPF13_NL_VND_VAP_KICKMAC_ACTION_NO_TX = 0,
    OSW_DRV_SPF13_NL_VND_VAP_KICKMAC_ACTION_WITH_TX = 1,
};
typedef enum osw_drv_spf13_nl_vnd_vap_kickmac_action osw_drv_spf13_nl_vnd_vap_kickmac_action_t;

struct nl_msg *osw_drv_spf13_nl_vnd_vap_kickmac(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_hwaddr *mac_addr,
        osw_drv_spf13_nl_vnd_vap_kickmac_action_t action);

struct nl_msg *osw_drv_spf13_nl_vnd_radio_get_survey(uint32_t family_id, uint32_t ifindex);

void osw_drv_spf13_nl_vnd_fill_survey_stats(struct nl_msg **msgs, const char *phy_name, struct osw_tlv *t);

bool osw_drv_spf13_nl_vnd_event_subcmd_is_stats_flush(uint32_t subcmd);

bool osw_drv_spf13_nl_vnd_fill_rate_stats(
        const void *data,
        size_t len,
        const char *phy_name,
        const char *(*get_vif_name_cb)(const char *phy_name, const struct osw_hwaddr *sta_addr),
        struct osw_tlv *t);

#endif /* OSW_DRV_SPF13_NL_VND_H_INCLUDED */
