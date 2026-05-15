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

#ifndef OSW_DRV_SPF13_NL_80211_H_INCLUDED
#define OSW_DRV_SPF13_NL_80211_H_INCLUDED

#include <stdint.h>
#include <nl80211_copy.h>
#include <netlink/netlink.h>
#include <osw_types.h>
#include <osw_drv.h>

struct nl_msg *osw_drv_spf13_nl_80211_msg_get_wiphy(const uint32_t family_id, const uint32_t wiphy);
struct nl_msg *osw_drv_spf13_nl_80211_msg_get_interface(const uint32_t family_id, const uint32_t ifindex);
struct nl_msg *osw_drv_spf13_nl_80211_msg_dump_scan(const uint32_t family_id, const uint32_t ifindex);
struct nl_msg *osw_drv_spf13_nl_80211_msg_set_tx_power_auto(uint32_t family_id, uint32_t ifindex, int8_t mlo_link_id);
struct nl_msg *osw_drv_spf13_nl_80211_msg_set_tx_power_fixed(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        int32_t mbm);

struct nl_msg *osw_drv_spf13_nl_80211_msg_frame(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_channel *c,
        const void *frame_buf,
        size_t frame_len);

struct nl_msg *osw_drv_spf13_nl_80211_msg_roc(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_channel *c,
        const uint32_t duration_msec);

struct nl_msg *osw_drv_spf13_nl_80211_msg_link_add(
        uint32_t family_id,
        uint32_t ifindex,
        int8_t mlo_link_id,
        const struct osw_hwaddr *addr);

void osw_drv_spf13_nl_80211_fill_bss_stats(
        struct nl_msg *msg,
        const char *phy_name,
        uint32_t *freq_mhz,
        struct osw_tlv *t);

/* Checks generic netlink to resolve "nl80211" and returns the family ID.
 * Returns -1 on failure.
 * Is a blocking call.
 */
int osw_drv_spf13_nl_80211_get_family_id(void);

/* Returns true if it succeeds in finding all the necessary attributes in the provided `tb` array.
 * If it succeeds, it fills the `c` structure with the channel information.
 * If it fails, it returns false and leaves `c` zeroed.
 */
bool osw_drv_spf13_nl_80211_try_into_chan(struct osw_channel *c, struct nlattr *tb[NL80211_ATTR_MAX + 1]);

/* Fills the `phy_state` with the information from the netlink messages
 * received from NL80211_CMD_GET_WIPHY.
 *
 * This is expected to be fed result of NLM_F_DUMP and NL80211_ATTR_SPLIT_WIPHY_DUMP.
 */
void osw_drv_spf13_nl_80211_fill_wiphy(struct osw_drv_phy_state *phy_state, int wiphy_idx, struct nl_msg **msgs);

/* Fills the `vif_state` with the information from the netlink messages
 * received from NL80211_CMD_GET_INTERFACE.
 */
void osw_drv_spf13_nl_80211_fill_interface(
        struct osw_drv_vif_state *vif_state,
        struct nl_msg *msg,
        const int8_t mlo_link_id);

/* Extracts the tx power level in millibel (mbm) from the netlink message.
 * Returns NULL if the message does not contain the tx power level.
 * If the message contains multiple MLO links, it returns the tx power level for the specified `mlo_link_id`.
 */
const uint32_t *osw_drv_spf13_nl_80211_get_tx_power_level(struct nl_msg *msg, const int8_t mlo_link_id);

/* Returns a netlink socket that listens for nl80211 events, all known
 * multicast groups are subscribed to.
 * The `recv_cb` callback is called when a message is received.
 * The `arg` argument is passed to the `recv_cb`.
 * The returned socket must be freed with nl_socket_free() when no longer needed.
 */
struct nl_sock *osw_drv_spf13_nl_80211_listen(int (*recv_cb)(struct nl_msg *msg, void *arg), void *arg);

#endif /* OSW_DRV_SPF13_NL_80211_H_INCLUDED */
