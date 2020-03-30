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

#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <ev.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <dp_rate_stats_pub.h>

#include "log.h"
#include "os.h"

#include "ioctl80211.h"
#include "ioctl80211_client.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL

#define IOCTL80211_DATA_RATE_LEN    (32)
#define PEER_RX_STATS 1
#define PEER_TX_STATS 0

#define OSYNC_IOCTL_LIB 1

/* Copied from  qca/src/qca-wifi/umac/include/ieee80211_node.h */
#define IEEE80211_NODE_AUTH             0x00000001          /* authorized for data */
#define IEEE80211_NODE_QOS              0x00000002          /* QoS enabled */
#define IEEE80211_NODE_ERP              0x00000004          /* ERP enabled */
#define IEEE80211_NODE_HT               0x00000008          /* HT enabled */

/*global structure to maintain stats*/
#define PEER_STATS_FLAG 0x0001
#define PEER_CLI_MAX 32

static struct ps_uapi_ioctl  g_peer_rx_ioctl_stats[PEER_CLI_MAX];
static struct ps_uapi_ioctl  g_peer_tx_ioctl_stats[PEER_CLI_MAX];
uint16_t g_stainfo_len;
uint8_t bsal_clients[IOCTL80211_CLIENTS_SIZE];

#include "osync_nl80211_11ax.h"

#ifndef PROC_NET_WIRELESS
#define PROC_NET_WIRELESS       "/proc/net/wireless"
#endif
typedef struct iw_statistics    iwstats;

typedef struct
{
    struct ieee80211req_sta_info        sta_info;
    int32_t                             padding[3]; /* Apparently driver adds 12 Bytes!!!*/
} ieee80211req_sta_info_t;

#define LIST_STATION_CFG_ALLOC_SIZE 3*1024
#define	QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION 74

extern struct   socket_context sock_ctx;
uint8_t         ieee80211_clients[IOCTL80211_CLIENTS_SIZE];
uint16_t        g_cli_len;

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#else
#error confilicting defs of min
#endif

#define PRINT(fmt, ...) \
    do { \
        LOGI(fmt, ##__VA_ARGS__); \
    } while (0)

#ifdef OPENSYNC_NL_SUPPORT
int get_cli_mac_index(mac_address_t mac_addr, int peer_stats_flag)
{
    int i;
    int index = 0;
    if (peer_stats_flag == 1)
    {
        for (i = 0; i < PEER_CLI_MAX; i++)
        {
            if (g_peer_rx_ioctl_stats[i].flags & PEER_STATS_FLAG)
            {
                if ((g_peer_rx_ioctl_stats[i].u.peer_rx_stats.set.addr[0] == (u8)mac_addr[0]) && (g_peer_rx_ioctl_stats[i].u.peer_rx_stats.set.addr[1] == (u8)mac_addr[1]) &&
                    (g_peer_rx_ioctl_stats[i].u.peer_rx_stats.set.addr[2] == (u8)mac_addr[2]) && (g_peer_rx_ioctl_stats[i].u.peer_rx_stats.set.addr[3] == (u8)mac_addr[3]) &&
                    (g_peer_rx_ioctl_stats[i].u.peer_rx_stats.set.addr[4] == (u8)mac_addr[4]) && (g_peer_rx_ioctl_stats[i].u.peer_rx_stats.set.addr[5] == (u8)mac_addr[5]))
                {
                    index = i;
                    break;
                }
            } else {
                index = i;
                break;
            }
        }
    } else {
        for (i = 0; i < PEER_CLI_MAX; i++)
        {
            if (g_peer_tx_ioctl_stats[i].flags & PEER_STATS_FLAG)
            {
                if ((g_peer_tx_ioctl_stats[i].u.peer_tx_stats.set.addr[0] == (u8)mac_addr[0]) && (g_peer_tx_ioctl_stats[i].u.peer_tx_stats.set.addr[1] == (u8)mac_addr[1]) &&
                    (g_peer_tx_ioctl_stats[i].u.peer_tx_stats.set.addr[2] == (u8)mac_addr[2]) && (g_peer_tx_ioctl_stats[i].u.peer_tx_stats.set.addr[3] == (u8)mac_addr[3]) &&
                    (g_peer_tx_ioctl_stats[i].u.peer_tx_stats.set.addr[4] == (u8)mac_addr[4]) && (g_peer_tx_ioctl_stats[i].u.peer_tx_stats.set.addr[5] == (u8)mac_addr[5]))
                {
                    index = i;
                    break;
                }
            } else {
                index = i;
                break;
            }
        }
    }
    return index;
    }

static void dp_peer_rx_rate_stats(uint8_t *peer_mac,
                    uint64_t peer_cookie,
                    void *buffer,
                    uint32_t buffer_len)
{
    int index;
    int i;
    uint8_t is_lithium;
    uint8_t chain, bw, max_chain, max_bw;
    struct wlan_rx_rate_stats *rx_stats;
    struct wlan_rx_rate_stats *tmp_rx_stats;;

    rx_stats = tmp_rx_stats = (struct wlan_rx_rate_stats *)buffer;

    index = get_cli_mac_index(peer_mac, PEER_RX_STATS);
    memcpy(g_peer_rx_ioctl_stats[index].u.peer_rx_stats.set.addr, peer_mac, sizeof(g_peer_rx_ioctl_stats[index].u.peer_rx_stats.set.addr));
    g_peer_rx_ioctl_stats[index].flags |= PEER_STATS_FLAG;
    g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.cookie = (peer_cookie & 0xFFFFFFFF00000000) >> WLANSTATS_PEER_COOKIE_LSB;

    is_lithium = (peer_cookie & WLANSTATS_COOKIE_PLATFORM_OFFSET) >> WLANSTATS_PEER_COOKIE_LSB;
    if (is_lithium) {
        max_chain = 8;
        max_bw = 8;
    } else {
        max_chain = 4;
        max_bw = 4;
    }
    for (i = 0; i < WLANSTATS_CACHE_SIZE; i++)
    {
        if ((int)(rx_stats->rix) != INVALID_CACHE_IDX) {
            g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_bytes = rx_stats -> num_bytes;
            g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_msdus = rx_stats -> num_msdus;
            g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_mpdus = rx_stats -> num_mpdus;
            g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_ppdus = rx_stats -> num_ppdus;
            g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_retries = rx_stats -> num_retries;
            g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_sgi = rx_stats -> num_sgi;
            g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].ave_rssi = rx_stats -> avg_rssi;
        }
        if ((int)(tmp_rx_stats->rix) != INVALID_CACHE_IDX) {
            for (chain = 0; chain < max_chain; chain++) {
                for (bw = 0; bw < max_bw; bw++) {
                    g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].ave_rssi_ant[chain][bw]= tmp_rx_stats -> avg_rssi_ant[chain][bw];
                }
            }
        }
        rx_stats = rx_stats + 1;
        tmp_rx_stats = tmp_rx_stats + 1;
    }
}
static void
dp_peer_tx_sojourn_stats(uint8_t *peer_mac,
                   uint64_t peer_cookie,
                   struct wlan_tx_sojourn_stats *sojourn_stats)
{
    uint8_t tid;
    int index = 0;

    index = get_cli_mac_index(peer_mac, PEER_TX_STATS);
    for (tid = 0; tid < WLAN_DATA_TID_MAX; tid++) {
                /* change sum_sojourn_msdu data type to u64 */
        g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.sojourn[tid].ave_sojourn_msec = sojourn_stats->avg_sojourn_msdu[tid];
        g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.sojourn[tid].sum_sojourn_msec = sojourn_stats->sum_sojourn_msdu[tid];
        g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.sojourn[tid].num_sojourn_mpdus = sojourn_stats->num_msdus[tid];
    }
}

static void dp_peer_tx_rate_stats(uint8_t *peer_mac,
                    uint64_t peer_cookie,
                    void *buffer,
                    uint32_t buffer_len)
{
    int index;
    int i = 0;

    struct wlan_tx_rate_stats *tx_stats;
    struct wlan_tx_sojourn_stats *sojourn_stats;

    if (buffer_len < (WLANSTATS_CACHE_SIZE *
              sizeof(struct wlan_tx_rate_stats))
              + sizeof(struct wlan_tx_sojourn_stats)) {
        LOGI("invalid buffer len, return");
        return;
    }
    tx_stats = (struct wlan_tx_rate_stats *)buffer;

    index = get_cli_mac_index(peer_mac, PEER_TX_STATS);

    memcpy(g_peer_tx_ioctl_stats[index].u.peer_tx_stats.set.addr, peer_mac, sizeof(g_peer_tx_ioctl_stats[index].u.peer_tx_stats.set.addr));
    g_peer_tx_ioctl_stats[index].flags |= PEER_STATS_FLAG;
    g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.cookie = (peer_cookie & 0xFFFFFFFF00000000) >> WLANSTATS_PEER_COOKIE_LSB;

    for (i = 0; i < WLANSTATS_CACHE_SIZE; i++)
    {
        if ((int)(tx_stats->rix) != INVALID_CACHE_IDX) {
            g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.stats[i].attempts = tx_stats->mpdu_attempts;
            g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.stats[i].success = tx_stats->mpdu_success;
            g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.stats[i].ppdus= tx_stats->num_ppdus;
        }
        tx_stats = tx_stats + 1;
    }
    sojourn_stats = (struct wlan_tx_sojourn_stats *)((uint8_t *)buffer + (WLANSTATS_CACHE_SIZE + sizeof(struct wlan_tx_rate_stats)));
    dp_peer_tx_sojourn_stats(peer_mac, peer_cookie, sojourn_stats);
    return;
}

#endif
static void dp_peer_stats_handler(uint32_t cache_type,
                 uint8_t *peer_mac,
                 uint64_t peer_cookie,
                 void *buffer,
                 uint32_t buffer_len)
{
    switch (cache_type) {
    case DP_PEER_RX_RATE_STATS:
        dp_peer_rx_rate_stats(peer_mac, peer_cookie,
                        buffer, buffer_len);
        break;
    case DP_PEER_TX_RATE_STATS:
        dp_peer_tx_rate_stats(peer_mac, peer_cookie,
                        buffer, buffer_len);
        break;
    }
}

void osync_peer_stats_event_callback(char *ifname,
							uint32_t cmdid,
							uint8_t *data,
							size_t len)
{
    struct nlattr *tb_array[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_MAX + 1];
    struct nlattr *tb;
    void *buffer = NULL;
    uint32_t buffer_len = 0;
    uint8_t *peer_mac;
    uint32_t cache_type;
    uint64_t peer_cookie;

    if (cmdid != QCA_NL80211_VENDOR_SUBCMD_PEER_STATS_CACHE_FLUSH) {
        /* ignore anyother events*/
        return;
    }

    if (nla_parse(tb_array, QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_MAX,
                (struct nlattr *)data, len, NULL)) {
        return;
    }

    tb = tb_array[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_TYPE];
    if (!tb) {
        return;
    }
    cache_type = nla_get_u32(tb);

    tb = tb_array[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_PEER_MAC];
    if (!tb) {
        return;
    }
    peer_mac = (uint8_t *)nla_data(tb);

    tb = tb_array[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_DATA];
    if (tb) {
        buffer = (void *)nla_data(tb);
        buffer_len = nla_len(tb);
    }

    tb = tb_array[QCA_WLAN_VENDOR_ATTR_PEER_STATS_CACHE_PEER_COOKIE];
    if (!tb) {
        return;
    }
    peer_cookie = nla_get_u64(tb);
    if (!buffer) {
        return;
    }

    dp_peer_stats_handler(cache_type, peer_mac, peer_cookie,
            buffer, buffer_len);

}

static
ioctl_status_t ioctl80211_client_stats_rx_calculate(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_record)
{
    struct ps_uapi_ioctl           *new_stats_rx = NULL;
    struct ps_uapi_ioctl           *old_stats_rx = NULL;
    dpp_client_stats_rx_t          *client_stats_rx = NULL;

    uint32_t                        mcs;
    uint32_t                        nss;
    uint32_t                        bw;

    uint32_t                        stats_index = 0;

    radio_type_t                    radio_type =
        radio_cfg->type;

    /* MCS/NSS/BW rate table and indexes that should be used for supported rates
       ----------------------------------------------
       | type | bw         | nss        |  mcs
       ----------------------------------------------
       | OFDM | 0 (20MHz)  | 0 (legacy) |  0 - 6M
       |      |            |            |  1 - 9M
       |      |            |            |  2 - 12M
       |      |            |            |  3 - 18M
       |      |            |            |  4 - 24M
       |      |            |            |  5 - 36M
       |      |            |            |  6 - 48M
       |      |            |            |  7 - 54M
       ----------------------------------------------
       | CCK  | 0 (20MHz)  | 0 (legacy) |  8 - L1M
       |      |            |            |  9 - L2M
       |      |            |            | 10 - L5.5M
       |      |            |            | 11 - L11M
       |      |            |            | 12 - S2M
       |      |            |            | 13 - S5.5M
       |      |            |            | 14 - S11M"
       ----------------------------------------------
       | VHT  | 0 (20MHz)  | 1 (chain1) |  1 - HT/VHT
       |      | 1 (40MHz)  | ...        |  2 - HT/VHT
       |      | 2 (80MHz)  | 8 (chain8) |  3 - HT/VHT
       |      | 3 (160MHz) |            |  4 - HT/VHT
       |      |            |            |  5 - HT/VHT
       |      |            |            |  6 - HT/VHT
       |      |            |            |  7 - HT/VHT
       |      |            |            |  8 - VHT
       |      |            |            |  9 - VHT
       ----------------------------------------------
       NOTE: The size of this table on 4x4 can be big - we could send only non zero elements!
     */
    for (stats_index = 0; stats_index < PS_MAX_ALL; stats_index++)
    {
        new_stats_rx = &data_new->stats_rx;
        old_stats_rx = &data_old->stats_rx;

        /* Skip unchanged entries*/
        if (    !(STATS_DELTA(
                        new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_bytes,
                        old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_bytes))
                && !(STATS_DELTA(
                        new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_msdus,
                        old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_msdus))
                && !(STATS_DELTA(
                        new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus,
                        old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus))
                && !(STATS_DELTA(
                        new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_ppdus,
                        old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_ppdus))
                && !(STATS_DELTA(
                        new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_retries,
                        old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_retries))
           ) {
            continue;
        }

        if (stats_index < PS_MAX_LEGACY) {
            mcs = stats_index;
            nss = 0;
            bw  = 0;
        }
        else {
            bw  = ((stats_index - PS_MAX_LEGACY) / (PS_MAX_MCS * PS_MAX_NSS));
            nss = (((stats_index - PS_MAX_LEGACY) / PS_MAX_MCS) % PS_MAX_NSS) + 1;
            mcs = (stats_index - PS_MAX_LEGACY) % PS_MAX_MCS;
        }

        client_stats_rx =
            dpp_client_stats_rx_record_alloc();
        if (NULL == client_stats_rx) {
            LOG(ERR,
                    "Updating %s interface client stats rx"
                    "(Failed to allocate memory)",
                    radio_get_name_from_type(radio_type));
            return IOCTL_STATUS_ERROR;
        }

        client_stats_rx->mcs = mcs;
        client_stats_rx->nss = nss;
        client_stats_rx->bw  = bw;

        client_stats_rx->bytes =
            STATS_DELTA(
                    new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_bytes,
                    old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_bytes);
        LOG(TRACE,
            "Calculated %s client delta stats_rx for "MAC_ADDRESS_FORMAT" "
            "index=%d [%d, %d, %d] bytes=%"PRIu64" (delta=%u=new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            stats_index, client_stats_rx->bw, client_stats_rx->nss, client_stats_rx->mcs,
            client_stats_rx->bytes,
            STATS_DELTA(
                new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_bytes,
                old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_bytes),
            new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_bytes,
            old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_bytes);

        client_stats_rx->msdu =
            STATS_DELTA(
                    new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_msdus,
                    old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_msdus);
        LOG(TRACE,
            "Calculated %s client delta stats_rx for "MAC_ADDRESS_FORMAT" "
            "index=%d [%d, %d, %d] msdu=%"PRIu64" (delta=%u=new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            stats_index, client_stats_rx->bw, client_stats_rx->nss, client_stats_rx->mcs,
            client_stats_rx->msdu,
            STATS_DELTA(
                new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_msdus,
                old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_msdus),
            new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_msdus,
            old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_msdus);

        client_stats_rx->mpdu =
            STATS_DELTA(
                    new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus,
                    old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus);
        LOG(TRACE,
            "Calculated %s client delta stats_rx for "MAC_ADDRESS_FORMAT" "
            "index=%d [%d, %d, %d] mpdu=%"PRIu64" (delta=%u=new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            stats_index, client_stats_rx->bw, client_stats_rx->nss, client_stats_rx->mcs,
            client_stats_rx->mpdu,
            STATS_DELTA(
                new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus,
                old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus),
            new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus,
            old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus);

        client_stats_rx->ppdu =
            STATS_DELTA(
                    new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_ppdus,
                    old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_ppdus);
        LOG(TRACE,
            "Calculated %s client delta stats_rx for "MAC_ADDRESS_FORMAT" "
            "index=%d [%d, %d, %d] ppdu=%"PRIu64" (delta=%u=new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            stats_index, client_stats_rx->bw, client_stats_rx->nss, client_stats_rx->mcs,
            client_stats_rx->ppdu,
            STATS_DELTA(
                new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_ppdus,
                old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_ppdus),
            new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_ppdus,
            old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_ppdus);

        client_stats_rx->retries =
            STATS_DELTA(
                    new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_retries,
                    old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_retries);
        LOG(TRACE,
            "Calculated %s client delta stats_rx for "MAC_ADDRESS_FORMAT" "
            "index=%d [%d, %d, %d] retries=%"PRIu64" (delta=%u=new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            stats_index, client_stats_rx->bw, client_stats_rx->nss, client_stats_rx->mcs,
            client_stats_rx->retries,
            STATS_DELTA(
                new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_retries,
                old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_retries),
            new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_retries,
            old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_retries);

        /* We are not collecting them currently */
        client_stats_rx->errors = 0;

        /* RSSI is already averaged by driver */
        client_stats_rx->rssi = new_stats_rx->u.peer_rx_stats.get.stats[stats_index].ave_rssi;
        if ( ! IOCTL80211_IS_RSSI_VALID(client_stats_rx->rssi))
        {
            LOG(WARNING, "Invalid RSSI value received from driver: %d. "
                         "Will assume new RSSI == old RSSI.",
                          client_stats_rx->rssi);

            client_stats_rx->rssi = 0;
        }

        LOG(TRACE,
            "Calculated %s client delta stats_rx for "MAC_ADDRESS_FORMAT
            " index=%d [%d, %d, %d] rssi=%d (new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            stats_index, client_stats_rx->bw, client_stats_rx->nss, client_stats_rx->mcs,
            client_stats_rx->rssi,
            new_stats_rx->u.peer_rx_stats.get.stats[stats_index].ave_rssi,
            old_stats_rx->u.peer_rx_stats.get.stats[stats_index].ave_rssi);

        ds_dlist_insert_tail(&client_record->stats_rx, client_stats_rx);
    }

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_clients_stats_rx_fetch(
        radio_type_t                    radio_type,
        char                           *phyName,
        ioctl80211_client_record_t     *client_entry)
{
    int index;
    int i;
    uint8_t chain, bw, max_chain, max_bw;
    uint8_t is_lithium;
    struct ps_uapi_ioctl               *ioctl_stats = &client_entry->stats_rx;

    memset (ioctl_stats, 0, sizeof(*ioctl_stats));
#ifdef OPENSYNC_NL_SUPPORT
    index = get_cli_mac_index(client_entry->info.mac, PEER_RX_STATS);
    if (!g_peer_rx_ioctl_stats[index].flags)
        return IOCTL_STATUS_ERROR;
#endif

    ioctl_stats->u.peer_rx_stats.set.addr[0] = (u8)client_entry->info.mac[0];
    ioctl_stats->u.peer_rx_stats.set.addr[1] = (u8)client_entry->info.mac[1];
    ioctl_stats->u.peer_rx_stats.set.addr[2] = (u8)client_entry->info.mac[2];
    ioctl_stats->u.peer_rx_stats.set.addr[3] = (u8)client_entry->info.mac[3];
    ioctl_stats->u.peer_rx_stats.set.addr[4] = (u8)client_entry->info.mac[4];
    ioctl_stats->u.peer_rx_stats.set.addr[5] = (u8)client_entry->info.mac[5];
#ifdef OPENSYNC_NL_SUPPORT
    is_lithium = ((g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.cookie) & WLANSTATS_COOKIE_PLATFORM_OFFSET) >> WLANSTATS_PEER_COOKIE_LSB;
    //is_lithium = (peer_cookie & WLANSTATS_COOKIE_PLATFORM_OFFSET) >> WLANSTATS_PEER_COOKIE_LSB;
    if (is_lithium) {
        max_chain = 8;
        max_bw = 8;
    } else {
        max_chain = 4;
        max_bw = 4;
    }
    for (i = 0; i < WLANSTATS_CACHE_SIZE; i++)
    {
        ioctl_stats->flags = g_peer_rx_ioctl_stats[index].flags;
        ioctl_stats->u.peer_rx_stats.get.stats[i].num_bytes = g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_bytes;
        ioctl_stats->u.peer_rx_stats.get.stats[i].num_msdus = g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_msdus;
        ioctl_stats->u.peer_rx_stats.get.stats[i].num_mpdus = g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_mpdus;
        ioctl_stats->u.peer_rx_stats.get.stats[i].num_ppdus = g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_ppdus;
        ioctl_stats->u.peer_rx_stats.get.stats[i].num_retries = g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_retries;
        ioctl_stats->u.peer_rx_stats.get.stats[i].num_sgi = g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].num_sgi;
        ioctl_stats->u.peer_rx_stats.get.stats[i].ave_rssi = g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].ave_rssi;
        for (chain = 0; chain < max_chain; chain++) {
            for (bw = 0; bw < max_bw; bw++) {
                ioctl_stats->u.peer_rx_stats.get.stats[i].ave_rssi_ant[chain][bw] = g_peer_rx_ioctl_stats[index].u.peer_rx_stats.get.stats[i].ave_rssi_ant[chain][bw];
            }
        }
    }
#else
    int32_t                             rc;
    struct iwreq                        request;
    memset (&request, 0, sizeof(request));
	request.u.data.pointer = ioctl_stats;
	request.u.data.length = PS_UAPI_IOCTL_SIZE;
	ioctl_stats->cmd = PS_UAPI_IOCTL_CMD_PEER_RX_STATS;
    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                phyName,
                PS_UAPI_IOCTL_SET,
                &request);
    if (0 > rc)
    {
        LOG(WARNING,
            "Skipping parsing %s client stats_rx "
            "(Failed to prepare them from driver '%s')",
            radio_get_name_from_type(radio_type),
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                phyName,
                PS_UAPI_IOCTL_GET,
                &request);
    if (0 > rc)
    {
        LOG(WARNING,
            "Skipping parsing %s client stats_rx "
            "(Failed to retrieve them from driver '%s')",
            radio_get_name_from_type(radio_type),
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }
#endif
    /* Set current stats cookie () */
    client_entry->stats_cookie = ioctl_stats->u.peer_rx_stats.get.cookie;

    return IOCTL_STATUS_OK;
}

/* There are 4 TIDS mapped to each Access category */
static radio_queue_type_t ioctl80211_tid_ac_index_get[CLIENT_MAX_TID_RECORDS] = {
    RADIO_QUEUE_TYPE_BE,      /* 0 */
    RADIO_QUEUE_TYPE_BK,      /* 1 */
    RADIO_QUEUE_TYPE_BK,      /* 2 */
    RADIO_QUEUE_TYPE_BE,      /* 3 */
    RADIO_QUEUE_TYPE_VI,      /* 4 */
    RADIO_QUEUE_TYPE_VI,      /* 5 */
    RADIO_QUEUE_TYPE_VO,      /* 6 */
    RADIO_QUEUE_TYPE_VO,      /* 7 */

    RADIO_QUEUE_TYPE_BE,      /* 8 */
    RADIO_QUEUE_TYPE_BK,      /* 9 */
    RADIO_QUEUE_TYPE_BK,      /* 10 */
    RADIO_QUEUE_TYPE_BE,      /* 11 */
    RADIO_QUEUE_TYPE_VI,      /* 12 */
    RADIO_QUEUE_TYPE_VI,      /* 13 */
    RADIO_QUEUE_TYPE_VO,      /* 14 */
    RADIO_QUEUE_TYPE_VO,      /* 15 */
};

static
ioctl_status_t ioctl80211_client_stats_tx_calculate(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_record)
{
    struct ps_uapi_ioctl           *new_stats_tx = NULL;
    struct ps_uapi_ioctl           *old_stats_tx = NULL;
    dpp_client_stats_tx_t          *client_stats_tx = NULL;

    uint32_t                        mcs;
    uint32_t                        nss;
    uint32_t                        bw;

    uint32_t                        stats_index = 0;

    radio_type_t                    radio_type = 
        radio_cfg->type;

    /* MCS/NSS/BW rate table and indexes that should be used for supported rates
       ----------------------------------------------
       | type | bw         | nss        |  mcs
       ----------------------------------------------
       | OFDM | 0 (20MHz)  | 0 (legacy) |  0 - 6M
       |      |            |            |  1 - 9M
       |      |            |            |  2 - 12M
       |      |            |            |  3 - 18M
       |      |            |            |  4 - 24M
       |      |            |            |  5 - 36M
       |      |            |            |  6 - 48M
       |      |            |            |  7 - 54M
       ----------------------------------------------
       | CCK  | 0 (20MHz)  | 0 (legacy) |  8 - L1M
       |      |            |            |  9 - L2M
       |      |            |            | 10 - L5.5M
       |      |            |            | 11 - L11M
       |      |            |            | 12 - S2M
       |      |            |            | 13 - S5.5M
       |      |            |            | 14 - S11M"
       ----------------------------------------------
       | VHT  | 0 (20MHz)  | 1 (chain1) |  1 - HT/VHT
       |      | 1 (40MHz)  | ...        |  2 - HT/VHT
       |      | 2 (80MHz)  | 8 (chain8) |  3 - HT/VHT
       |      | 3 (160MHz) |            |  4 - HT/VHT
       |      |            |            |  5 - HT/VHT
       |      |            |            |  6 - HT/VHT
       |      |            |            |  7 - HT/VHT
       |      |            |            |  8 - VHT
       |      |            |            |  9 - VHT
       ----------------------------------------------
       NOTE: The size of this table on 4x4 can be big - we could send only non zero elements!
     */
    for (stats_index = 0; stats_index < PS_MAX_ALL; stats_index++)
    {
        new_stats_tx = &data_new->stats_tx;
        old_stats_tx = &data_old->stats_tx;

        /* Skip unchanged entries*/
        if (    !(STATS_DELTA(
                        new_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts,
                        old_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts))
                && !(STATS_DELTA(
                        new_stats_tx->u.peer_tx_stats.get.stats[stats_index].success,
                        old_stats_tx->u.peer_tx_stats.get.stats[stats_index].success))
           )
        {
            continue;
        }

        if (stats_index < PS_MAX_LEGACY) {
            mcs = stats_index;
            nss = 0;
            bw  = 0;
        }
        else {
            bw  = ((stats_index - PS_MAX_LEGACY) / (PS_MAX_MCS * PS_MAX_NSS));
            nss = (((stats_index - PS_MAX_LEGACY) / PS_MAX_MCS) % PS_MAX_NSS) + 1;
            mcs = (stats_index - PS_MAX_LEGACY) % PS_MAX_MCS;
        }

        client_stats_tx =
            dpp_client_stats_tx_record_alloc();
        if (NULL == client_stats_tx) {
            LOG(ERR,
                    "Updating %s interface client stats tx"
                    "(Failed to allocate memory)",
                    radio_get_name_from_type(radio_type));
            return IOCTL_STATUS_ERROR;
        }

        client_stats_tx->mcs = mcs;
        client_stats_tx->nss = nss;
        client_stats_tx->bw  = bw;

        /* Tx stats collected are approximation due to driver Tx handling :

           We send to the driver a
           - list of rates (lets use just 2 for example) that the driver should use
           - how many times each rate should be tried and (we shall make it 1)
           - the list of MPDUs that should be sent (lets say 10)

           1. Firstly it sends 10 frames but succeeds to send (ack) only 2
           (real attempts 10, success 2)
           2. Because try is 1 it goes to the next rate and succeeds to send i
           remaining 8 (real attempts 18, success 10 )
           3. Since we get completion at the end with report tries_count 1,
           success 10 we can only estimate what was happening on each rate
           based on what was send and retrieved to/from driver

           Because try was 1 rate was changed (we configured it to 1) and based on number
           of sent packets (10) we mark first rate attempts 10 and success 0
           (worst case since we do not know what happened. Then we move to next rate where
           success reported is 10 and we mark attempts also as 10 (we do not know how many
           successes were in previous rate)

           rate     estimated               real
           attempts    success     attempts    success
           1        10          0           10          2
           2        10          10          8           8
           total    20                      18

           Same example but different success count in reality gives us different counts
           but we estimated it the same

           rate     estimated               real
           attempts    success     attempts    success
           1        10          0           10          8
           2        10          10          2           2
           total    20                      12
           stats_entry->mpdu =
           ioctl_stats->u.peer_tx_stats.get.stats[stats_index].attempts;
           stats_entry->ppdu =
           ioctl_stats->u.peer_tx_stats.get.stats[stats_index].ppdus;

         */
        /* We are not collecting them currently */
        client_stats_tx->bytes = 0;
        client_stats_tx->msdu = 0;
        client_stats_tx->errors = 0;

        client_stats_tx->mpdu =
            STATS_DELTA(
                    new_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts,
                    old_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts);
        LOG(TRACE,
            "Calculated %s client delta stats_tx for "MAC_ADDRESS_FORMAT" "
            "index=%d [%d, %d, %d] mpdu=%"PRIu64" (delta=%u=new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            stats_index, client_stats_tx->bw, client_stats_tx->nss, client_stats_tx->mcs,
            client_stats_tx->mpdu,
            STATS_DELTA(
                new_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts,
                old_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts),
            new_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts,
            old_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts);

        client_stats_tx->ppdu =
            STATS_DELTA(
                    new_stats_tx->u.peer_tx_stats.get.stats[stats_index].ppdus,
                    old_stats_tx->u.peer_tx_stats.get.stats[stats_index].ppdus);
        LOG(TRACE,
            "Calculated %s client delta stats_tx for "MAC_ADDRESS_FORMAT" "
            "index=%d [%d, %d, %d] ppdu=%"PRIu64" (delta=%u=new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            stats_index, client_stats_tx->bw, client_stats_tx->nss, client_stats_tx->mcs,
            client_stats_tx->ppdu,
            STATS_DELTA(
                new_stats_tx->u.peer_tx_stats.get.stats[stats_index].ppdus,
                old_stats_tx->u.peer_tx_stats.get.stats[stats_index].ppdus),
            new_stats_tx->u.peer_tx_stats.get.stats[stats_index].ppdus,
            old_stats_tx->u.peer_tx_stats.get.stats[stats_index].ppdus);

        /* Retry is worst case estimation between each attempts and successes */
        client_stats_tx->retries =
            STATS_DELTA(
                    (new_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts -
                     new_stats_tx->u.peer_tx_stats.get.stats[stats_index].success),
                    (old_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts -
                     old_stats_tx->u.peer_tx_stats.get.stats[stats_index].success));

        LOG(TRACE,
            "Calculated %s client delta stats_tx for "MAC_ADDRESS_FORMAT" "
            "index=%d [%d, %d, %d] retries=%"PRIu64" (delta=%u=new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            stats_index, client_stats_tx->bw, client_stats_tx->nss, client_stats_tx->mcs,
            client_stats_tx->retries,
            STATS_DELTA(
                (new_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts -
                 new_stats_tx->u.peer_tx_stats.get.stats[stats_index].success),
                (old_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts -
                 old_stats_tx->u.peer_tx_stats.get.stats[stats_index].success)),
            (new_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts -
             new_stats_tx->u.peer_tx_stats.get.stats[stats_index].success),
            (old_stats_tx->u.peer_tx_stats.get.stats[stats_index].attempts -
             old_stats_tx->u.peer_tx_stats.get.stats[stats_index].success));

        ds_dlist_insert_tail(&client_record->stats_tx, client_stats_tx);
    }

    dpp_client_tid_record_list_t   *record = NULL;
    dpp_client_stats_tid_t         *client_stats_tid = NULL;

    /* Add new measurement for every convert */
    record =
        dpp_client_tid_record_alloc();
    if (NULL == record)
    {
        LOG(ERR,
                "Updating %s interface client tid stats "
                "(Failed to allocate memory)",
                radio_get_name_from_type(radio_type));
        return IOCTL_STATUS_ERROR;
    }

    for (stats_index = 0; stats_index < PS_MAX_TID; stats_index++)
    {
        new_stats_tx = &data_new->stats_tx;
        old_stats_tx = &data_old->stats_tx;
        client_stats_tid = &record->entry[stats_index];

        /* Skip unchanged entries*/
        if (    !(STATS_DELTA(
                        new_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].sum_sojourn_msec,
                        old_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].sum_sojourn_msec))
                && !(STATS_DELTA(
                        new_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].num_sojourn_mpdus,
                        old_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].num_sojourn_mpdus))
           )
        {
            continue;
        }

        client_stats_tid->ac = ioctl80211_tid_ac_index_get[stats_index];
        client_stats_tid->tid = stats_index;
        client_stats_tid->ewma_time_ms = 
            new_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].ave_sojourn_msec;

        LOG(TRACE,
            "Calculated %s client delta stats_tid for "MAC_ADDRESS_FORMAT" "
            "index [%d] %s ewma %"PRIu64" ",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_stats_tid->tid,
            radio_get_queue_name_from_type(client_stats_tid->ac),
            client_stats_tid->ewma_time_ms);

        client_stats_tid->sum_time_ms =
            STATS_DELTA(
                    new_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].sum_sojourn_msec,
                    old_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].sum_sojourn_msec);
        LOG(TRACE,
            "Calculated %s client delta stats_tid for "MAC_ADDRESS_FORMAT" "
            "index [%d] %s time %"PRIu64" (delta=%"PRIu64"=new=%"PRIu64"-old=%"PRIu64")",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_stats_tid->tid,
            radio_get_queue_name_from_type(client_stats_tid->ac),
            client_stats_tid->sum_time_ms,
            STATS_DELTA(
                new_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].sum_sojourn_msec,
                old_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].sum_sojourn_msec),
            new_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].sum_sojourn_msec,
            old_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].sum_sojourn_msec);

        client_stats_tid->num_msdus =
            STATS_DELTA(
                    new_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].num_sojourn_mpdus,
                    old_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].num_sojourn_mpdus);
        LOG(TRACE,
            "Calculated %s client delta stats_tid for "MAC_ADDRESS_FORMAT" "
            "index [%d] %s num %"PRIu64" (delta=%u=new=%u-old=%u)",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_stats_tid->tid,
            radio_get_queue_name_from_type(client_stats_tid->ac),
            client_stats_tid->num_msdus,
            STATS_DELTA(
                new_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].num_sojourn_mpdus,
                old_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].num_sojourn_mpdus),
            new_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].num_sojourn_mpdus,
            old_stats_tx->u.peer_tx_stats.get.sojourn[stats_index].num_sojourn_mpdus);
    }

    record->timestamp_ms = get_timestamp();

    ds_dlist_insert_tail(&client_record->tid_record_list, record);

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_clients_stats_tx_fetch(
        radio_type_t                    radio_type,
        char                           *phyName,
        ioctl80211_client_record_t      *client_entry)
{
    int                                 index;
    uint8_t                             tid;
    int                                 i;
    struct ps_uapi_ioctl               *ioctl_stats = &client_entry->stats_tx;

    memset (ioctl_stats, 0, sizeof(*ioctl_stats));
#ifdef OPENSYNC_NL_SUPPORT
    index = get_cli_mac_index(client_entry->info.mac, PEER_TX_STATS);
    if (!(g_peer_tx_ioctl_stats[index].flags & PEER_STATS_FLAG))
        return IOCTL_STATUS_ERROR;
#endif

    ioctl_stats->u.peer_tx_stats.set.addr[0] = (u8)client_entry->info.mac[0];
    ioctl_stats->u.peer_tx_stats.set.addr[1] = (u8)client_entry->info.mac[1];
    ioctl_stats->u.peer_tx_stats.set.addr[2] = (u8)client_entry->info.mac[2];
    ioctl_stats->u.peer_tx_stats.set.addr[3] = (u8)client_entry->info.mac[3];
    ioctl_stats->u.peer_tx_stats.set.addr[4] = (u8)client_entry->info.mac[4];
    ioctl_stats->u.peer_tx_stats.set.addr[5] = (u8)client_entry->info.mac[5];

#ifdef OPENSYNC_NL_SUPPORT
    for (i = 0; i < WLANSTATS_CACHE_SIZE; i++)
    {
        ioctl_stats->flags = g_peer_tx_ioctl_stats[index].flags;
        ioctl_stats->u.peer_tx_stats.get.stats[i].attempts = g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.stats[i].attempts;
        ioctl_stats->u.peer_tx_stats.get.stats[i].success = g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.stats[i].success;
        ioctl_stats->u.peer_tx_stats.get.stats[i].ppdus = g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.stats[i].ppdus;
    }

    for (tid = 0; tid < WLAN_DATA_TID_MAX; tid++)
    {
        ioctl_stats->u.peer_tx_stats.get.sojourn[tid].ave_sojourn_msec = g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.sojourn[tid].ave_sojourn_msec;
        ioctl_stats->u.peer_tx_stats.get.sojourn[tid].sum_sojourn_msec = g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.sojourn[tid].sum_sojourn_msec;
        ioctl_stats->u.peer_tx_stats.get.sojourn[tid].num_sojourn_mpdus = g_peer_tx_ioctl_stats[index].u.peer_tx_stats.get.sojourn[tid].num_sojourn_mpdus;
    }
#else

    int32_t                             rc;
    struct iwreq                        request;
    memset (&request, 0, sizeof(request));
	request.u.data.pointer = ioctl_stats;
	request.u.data.length = PS_UAPI_IOCTL_SIZE;

    ioctl_stats->cmd = PS_UAPI_IOCTL_CMD_PEER_TX_STATS;

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                phyName,
                PS_UAPI_IOCTL_SET,
                &request);
    if (0 > rc)
    {
        LOG(WARNING,
            "IOCTL: Skipping parsing %s client stats_tx "
            "(Failed to prepare them from driver '%s')",
            radio_get_name_from_type(radio_type),
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                phyName,
                PS_UAPI_IOCTL_GET,
                &request);
    if (0 > rc)
    {
        LOG(WARNING,
            "IOCTL: Skipping parsing %s client stats_tx "
            "(Failed to retrieve them from driver '%s')",
            radio_get_name_from_type(radio_type),
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }
#endif

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_client_stats_calculate(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_record)
{
    ioctl80211_client_stats_t      *old_stats = NULL;
    ioctl80211_client_stats_t      *new_stats = NULL;

    radio_type_t                    radio_type = 
        radio_cfg->type;

    new_stats = &data_new->stats.client;
    old_stats = &data_old->stats.client;

    /* Some drivers reset stats at reconnect and we do not notice that. Until
       they add connection cookie or some other way of reconnect indication
       we shall assume that if all stats are overlapped it is reconnect
     */
    if (    (new_stats->bytes_tx < old_stats->bytes_tx)
         && (new_stats->bytes_rx < old_stats->bytes_rx)
         && (new_stats->frames_tx < old_stats->frames_tx)
         && (new_stats->frames_rx < old_stats->frames_rx)
        )
    {
        memset(old_stats, 0, sizeof(ioctl80211_peer_stats_t));
    }

    client_record->stats.bytes_tx =
        STATS_DELTA(
                new_stats->bytes_tx,
                old_stats->bytes_tx);
    LOG(TRACE,
        "Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
        "bytes_tx=%"PRIu64" (delta=%"PRIu64"=new=%"PRIu64"-old=%"PRIu64")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_record->stats.bytes_tx,
        STATS_DELTA(
            new_stats->bytes_tx,
            old_stats->bytes_tx),
        new_stats->bytes_tx,
        old_stats->bytes_tx);

    client_record->stats.bytes_rx =
        STATS_DELTA(
                new_stats->bytes_rx,
                old_stats->bytes_rx);
    LOG(TRACE,
        "Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
        "bytes_rx=%"PRIu64" (delta=%"PRIu64"=new=%"PRIu64"-old=%"PRIu64")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_record->stats.bytes_rx,
        STATS_DELTA(
            new_stats->bytes_rx,
            old_stats->bytes_rx),
        new_stats->bytes_rx,
        old_stats->bytes_rx);

    client_record->stats.frames_tx =
        STATS_DELTA(
                new_stats->frames_tx,
                old_stats->frames_tx);
    LOG(TRACE,
        "Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
        "frames_tx=%"PRIu64" (delta=%u=new=%u-old=%u)",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_record->stats.frames_tx,
        STATS_DELTA(
            new_stats->frames_tx,
            old_stats->frames_tx),
        new_stats->frames_tx,
        old_stats->frames_tx);

    client_record->stats.frames_rx =
        STATS_DELTA(
                new_stats->frames_rx,
                old_stats->frames_rx);
    LOG(TRACE,
        "Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
        "frames_rx=%"PRIu64" (delta=%u=new=%u-old=%u)",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_record->stats.frames_rx,
        STATS_DELTA(
            new_stats->frames_rx,
            old_stats->frames_rx),
        new_stats->frames_rx,
        old_stats->frames_rx);

    client_record->stats.retries_rx =
        STATS_DELTA(
                new_stats->retries_rx,
                old_stats->retries_rx);
    client_record->stats.retries_tx =
        STATS_DELTA(
                new_stats->retries_tx,
                old_stats->retries_tx);
    client_record->stats.errors_rx =
        STATS_DELTA(
                new_stats->errors_rx,
                old_stats->errors_rx);
    client_record->stats.errors_tx =
        STATS_DELTA(
                new_stats->errors_tx,
                old_stats->errors_tx);

    /* RSSI is value above the noise floor */
    if (new_stats->rssi)
    {
        client_record->stats.rssi = new_stats->rssi;
        LOG(TRACE,
            "Calculated %s client delta stats for "
            MAC_ADDRESS_FORMAT" rssi=%d",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_record->stats.rssi);
    }

    if (new_stats->rate_tx) {
        client_record->stats.rate_tx = new_stats->rate_tx;
        client_record->stats.rate_tx /= 1000;

        LOG(TRACE,
            "Calculated %s client delta stats for "
            MAC_ADDRESS_FORMAT" rate_tx=%0.2f",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_record->stats.rate_tx);
    }

    if (new_stats->rate_rx) {
        client_record->stats.rate_rx = new_stats->rate_rx;
        client_record->stats.rate_rx /= 1000;

        LOG(TRACE,
            "Calculated %s client delta stats for "
            MAC_ADDRESS_FORMAT" rate_rx=%0.2f",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_record->stats.rate_rx);
    }

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_peer_stats_calculate(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_record)
{
    ioctl80211_peer_stats_t        *old_stats = NULL;
    ioctl80211_peer_stats_t        *new_stats = NULL;

    radio_type_t                    radio_type = 
        radio_cfg->type;

    new_stats = &data_new->stats.peer;
    old_stats = &data_old->stats.peer;

    /* Some drivers reset stats at reconnect and we do not notice that. Until
       they add connection cookie or some other way of reconnect indication
       we shall assume that if all stats are overlapped it is reconnect
     */
    if (    (new_stats->bytes_tx < old_stats->bytes_tx)
         && (new_stats->bytes_rx < old_stats->bytes_rx)
         && (new_stats->frames_tx < old_stats->frames_tx)
         && (new_stats->frames_rx < old_stats->frames_rx)
        )
    {
        memset(old_stats, 0, sizeof(ioctl80211_peer_stats_t));
    }

    client_record->stats.bytes_tx =
        STATS_DELTA(
                new_stats->bytes_tx,
                old_stats->bytes_tx);
    LOG(TRACE,
        "Calculated %s peer delta stats for "MAC_ADDRESS_FORMAT" "
        "bytes_tx=%"PRIu64" (delta=%"PRIu64"=new=%"PRIu64"-old=%"PRIu64")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_record->stats.bytes_tx,
        STATS_DELTA(
            new_stats->bytes_tx,
            old_stats->bytes_tx),
        new_stats->bytes_tx,
        old_stats->bytes_tx);

    client_record->stats.bytes_rx =
        STATS_DELTA(
                new_stats->bytes_rx,
                old_stats->bytes_rx);
    LOG(TRACE,
        "Calculated %s peer delta stats for "MAC_ADDRESS_FORMAT" "
        "bytes_rx=%"PRIu64" (delta=%"PRIu64"=new=%"PRIu64"-old=%"PRIu64")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_record->stats.bytes_rx,
        STATS_DELTA(
            new_stats->bytes_rx,
            old_stats->bytes_rx),
        new_stats->bytes_rx,
        old_stats->bytes_rx);

    client_record->stats.frames_tx =
        STATS_DELTA(
                new_stats->frames_tx,
                old_stats->frames_tx);
    LOG(TRACE,
        "Calculated %s peer delta stats for "MAC_ADDRESS_FORMAT" "
        "frames_tx=%"PRIu64" (delta=%"PRIu64"=new=%"PRIu64"-old=%"PRIu64")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_record->stats.frames_tx,
        STATS_DELTA(
            new_stats->frames_tx,
            old_stats->frames_tx),
        new_stats->frames_tx,
        old_stats->frames_tx);

    client_record->stats.frames_rx =
        STATS_DELTA(
                new_stats->frames_rx,
                old_stats->frames_rx);
    LOG(TRACE,
        "Calculated %s peer delta stats for "MAC_ADDRESS_FORMAT" "
        "frames_rx=%"PRIu64" (delta=%"PRIu64"=new=%"PRIu64"-old=%"PRIu64")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_record->stats.frames_rx,
        STATS_DELTA(
            new_stats->frames_rx,
            old_stats->frames_rx),
        new_stats->frames_rx,
        old_stats->frames_rx);

    client_record->stats.retries_rx =
        STATS_DELTA(
                new_stats->retries_rx,
                old_stats->retries_rx);
    client_record->stats.retries_tx =
        STATS_DELTA(
                new_stats->retries_tx,
                old_stats->retries_tx);
    client_record->stats.errors_rx =
        STATS_DELTA(
                new_stats->errors_rx,
                old_stats->errors_rx);
    client_record->stats.errors_tx =
        STATS_DELTA(
                new_stats->errors_tx,
                old_stats->errors_tx);

    /* RSSI is value above the noise floor */
    if (new_stats->rssi)
    {
        /* Sliding window averaging */
        if (old_stats->rssi)
        {
            client_record->stats.rssi = new_stats->rssi;
            LOG(TRACE,
                "Calculated %s peer delta stats for "
                MAC_ADDRESS_FORMAT" rssi=%d",
                radio_get_name_from_type(radio_type),
                MAC_ADDRESS_PRINT(data_new->info.mac),
                client_record->stats.rssi);
        }
        else
        {
            client_record->stats.rssi = new_stats->rssi;
        }
    }

    if (new_stats->rate_tx) {
        client_record->stats.rate_tx = new_stats->rate_tx;
        client_record->stats.rate_tx /= 1000;

        LOG(TRACE,
            "Calculated %s peer delta stats for "
            MAC_ADDRESS_FORMAT" rate_tx=%0.2f",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_record->stats.rate_tx);
    }

    if (new_stats->rate_rx) {
        client_record->stats.rate_rx = new_stats->rate_rx;
        client_record->stats.rate_rx /= 1000;

        LOG(TRACE,
            "Calculated %s peer delta stats for "
            MAC_ADDRESS_FORMAT" rate_rx=%0.2f",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_record->stats.rate_rx);
    }

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_clients_stats_fetch(
        radio_type_t                radio_type,
        char                       *ifName,
        ioctl80211_client_record_t *client_entry)
{
    int32_t                         rc;
    ioctl80211_client_stats_t      *stats_entry = &client_entry->stats.client;

    struct ieee80211req_sta_stats   ieee80211_client_stats;

    rc = osync_nl80211_clients_stats_fetch(radio_type,ifName,client_entry,&ieee80211_client_stats);

    if (0 > rc)
    {
        LOG(WARNING,
            "Skipping parsing %s client stats "
            "(Failed to retrieve them from driver '%s')",
            radio_get_name_from_type(radio_type),
            strerror(errno));
        return IOCTL_STATUS_OK;
    }

    stats_entry->frames_tx = 
        (RADIO_TYPE_5G == radio_type) ? 
        ieee80211_client_stats.is_stats.ns_tx_data_success : 
        ieee80211_client_stats.is_stats.ns_tx_data;
    LOG(TRACE,
        "Parsed %s client tx_frames %u",
        radio_get_name_from_type(radio_type),
        stats_entry->frames_tx);

    stats_entry->bytes_tx = 
        (RADIO_TYPE_5G == radio_type) ? 
        ieee80211_client_stats.is_stats.ns_tx_bytes_success :
        ieee80211_client_stats.is_stats.ns_tx_bytes;
    LOG(TRACE,
        "Parsed %s client tx_bytes %"PRIu64"",
        radio_get_name_from_type(radio_type),
        stats_entry->bytes_tx);

    stats_entry->frames_rx = 
        ieee80211_client_stats.is_stats.ns_rx_data;
    LOG(TRACE,
        "Parsed %s client rx_frames %u",
        radio_get_name_from_type(radio_type),
        stats_entry->frames_rx);

    stats_entry->bytes_rx = 
        ieee80211_client_stats.is_stats.ns_rx_bytes;
    LOG(TRACE,
        "Parsed %s client rx_bytes %"PRIu64"",
        radio_get_name_from_type(radio_type),
        stats_entry->bytes_rx);

    /* TODO: Needs verification.

       Retry counter was taken from assumption from the following calculation:

       all queued packets were packets actually sent and not ok - retried!!
       packet_queued = tx_data_packets + ns_is_tx_not_ok
     */
    stats_entry->retries_tx = 
        ieee80211_client_stats.is_stats.ns_is_tx_not_ok;
    LOG(TRACE,
        "Parsed %s client tx retries %u",
        radio_get_name_from_type(radio_type),
        stats_entry->retries_tx);

    stats_entry->retries_rx =
        ieee80211_client_stats.is_stats.ns_rx_retries;
    LOG(TRACE,
        "Parsed %s client rx retries %u",
        radio_get_name_from_type(radio_type),
        stats_entry->retries_rx);

    stats_entry->errors_tx = 
        ieee80211_client_stats.is_stats.ns_tx_discard + 
        ieee80211_client_stats.is_stats.ns_is_tx_nobuf;
    LOG(TRACE,
        "Parsed %s client tx_errors %u",
        radio_get_name_from_type(radio_type),
        stats_entry->errors_tx);

    stats_entry->errors_rx =
        ieee80211_client_stats.is_stats.ns_rx_tkipmic +
        ieee80211_client_stats.is_stats.ns_rx_ccmpmic +
        ieee80211_client_stats.is_stats.ns_rx_wpimic  +
        ieee80211_client_stats.is_stats.ns_rx_tkipicv +
        ieee80211_client_stats.is_stats.ns_rx_decap +
        ieee80211_client_stats.is_stats.ns_rx_defrag +
        ieee80211_client_stats.is_stats.ns_rx_disassoc +
        ieee80211_client_stats.is_stats.ns_rx_deauth +
        ieee80211_client_stats.is_stats.ns_rx_decryptcrc +
        ieee80211_client_stats.is_stats.ns_rx_unauth;
    LOG(TRACE,
        "Parsed %s client rx_errors %u",
        radio_get_name_from_type(radio_type),
        stats_entry->errors_rx);

    return IOCTL_STATUS_OK;
}

void stainfo_cb(struct cfg80211_data *buffer)
{
    uint32_t    len = buffer->length;

    if (len < sizeof(struct ieee80211req_sta_info)) {
        return;
    }

    memcpy((ieee80211_clients + g_cli_len), buffer->data, len);
    g_cli_len += len;
}

static
ioctl_status_t ioctl80211_clients_list_fetch(
        radio_entry_t              *radio_cfg,
        char                       *ifName,
        radio_essid_t               essid,
        ds_dlist_t                 *client_list)
{
    ioctl_status_t                  status;
    int32_t                         rc;
    uint32_t                        length = 0;
    ioctl80211_client_record_t     *client_entry = NULL;
    radio_type_t                    radio_type;

    ssize_t                         ieee80211_client_offset = 0;
    struct ieee80211req_sta_info   *ieee80211_client = NULL;

    radio_type = radio_cfg->type;
    if (NULL == client_list)
    {
        return IOCTL_STATUS_ERROR;
    }
    memset (ieee80211_clients, 0, sizeof(ieee80211_clients));
    g_cli_len = 0;

#if OPENSYNC_NL_SUPPORT
    struct cfg80211_data            buffer;
    uint8_t                        *buf;

    buf = malloc(LIST_STATION_CFG_ALLOC_SIZE);
    if (!buf) {
        LOGI("%s: Unable to allocate memory for station list\n", __func__);
        return IOCTL_STATUS_ERROR;
    }

    buffer.data         = buf;
    buffer.length       = LIST_STATION_CFG_ALLOC_SIZE;
    buffer.callback     = &stainfo_cb;
    buffer.parse_data   = 0;
    rc = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_LIST_STA, ifName,
            (char *)&buffer, buffer.length);
    if (0 > rc) {
        free(buf);
        LOG(ERR,
            "Parsing %s %s client stats (Failed to get info '%s')",
            radio_get_name_from_type(radio_type),
            ifName,
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    length = buffer.length;
    LOGD("%s: length - %u\n", __func__, length);
    free(buf);
#else
    struct iwreq                    request;

    memset (&request, 0, sizeof(request));
    request.u.data.pointer = ieee80211_clients;
    request.u.data.length = sizeof(ieee80211_clients);
    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                ifName,
                IEEE80211_IOCTL_STA_INFO,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing %s %s client stats (Failed to get info '%s')",
            radio_get_name_from_type(radio_type),
            ifName,
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    length = request.u.data.length;
    LOGD("%s: length - %u\n", __func__, length);
#endif

    for (   ieee80211_client_offset = 0;
            length - ieee80211_client_offset >= (int)sizeof(*ieee80211_client);)
    {
        ieee80211_client =
            (struct ieee80211req_sta_info *)
            (ieee80211_clients + ieee80211_client_offset);

        client_entry = 
             ioctl80211_client_record_alloc();
        if (NULL == client_entry)
        {
            LOG(ERR,
                "Parsing %s interface client stats "
                "(Failed to allocate memory)",
                radio_get_name_from_type(radio_type));
            return IOCTL_STATUS_ERROR;
        }

        client_entry->is_client = true;

        client_entry->info.type = radio_type;

        memcpy (client_entry->info.mac,
                ieee80211_client->isi_macaddr,
                sizeof(client_entry->info.mac));
        LOG(TRACE,
            "Parsed %s client MAC "MAC_ADDRESS_FORMAT,
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(client_entry->info.mac));

        /* Driver might return -1 */
        client_entry->stats.client.rssi = 0;
        if (ieee80211_client->isi_rssi > 0)
        {
            client_entry->stats.client.rssi = ieee80211_client->isi_rssi;
        }

        LOG(TRACE,
            "Parsed %s client RSSI %d",
            radio_get_name_from_type(radio_type),
            client_entry->stats.client.rssi);

        strlcpy(client_entry->info.ifname,
                ifName,
                sizeof(client_entry->info.ifname));
        LOG(TRACE,
            "Parsed %s client IFNAME %s",
            radio_get_name_from_type(radio_type),
            client_entry->info.ifname);

        memcpy (client_entry->info.essid,
                essid,
                sizeof(client_entry->info.essid));
        LOG(TRACE,
            "Parsed %s client ESSID %s",
            radio_get_name_from_type(radio_type),
            client_entry->info.essid);

        client_entry->stats.client.rate_tx = 
            ieee80211_client->isi_txratekbps;
        LOG(TRACE,
            "Parsed %s client txrate %u",
            radio_get_name_from_type(radio_type),
            client_entry->stats.client.rate_tx);

        client_entry->stats.client.rate_rx =
            ieee80211_client->isi_rxratekbps;
        LOG(TRACE,
            "Parsed %s client rxrate %u",
            radio_get_name_from_type(radio_type),
            client_entry->stats.client.rate_rx);

        client_entry->uapsd =
            ieee80211_client->isi_uapsd;
        LOG(TRACE,
            "Parsed %s client uapsd %u",
            radio_get_name_from_type(radio_type),
            client_entry->uapsd);

        status = 
            ioctl80211_clients_stats_fetch (
                    radio_type,
                    ifName,
                    client_entry);
        if (IOCTL_STATUS_OK != status)
        {
            goto error;
        }

        status = 
            ioctl80211_clients_stats_rx_fetch (
                    radio_type,
                    radio_cfg->phy_name,
                    client_entry);
        if (IOCTL_STATUS_OK != status)
        {
            goto error;
        }

        status = 
            ioctl80211_clients_stats_tx_fetch (
                    radio_type,
                    radio_cfg->phy_name,
                    client_entry);
        if (IOCTL_STATUS_OK != status)
        {
            goto error;
        }

        ds_dlist_insert_tail(client_list, client_entry);

        /* Move to the next client */
        ieee80211_client_offset += ieee80211_client->isi_len;
        continue;

error:
        ioctl80211_client_record_free(client_entry);

        /* Move to the next client */
        ieee80211_client_offset += ieee80211_client->isi_len;
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_peer_stats_fetch(
        radio_type_t                radio_type,
        char                       *ifName,
        ioctl80211_client_record_t *client_entry)
{
    int32_t                         rc;
    ioctl80211_peer_stats_t        *stats_entry = &client_entry->stats.peer;

    struct ioctl80211_vap_stats     vap_stats;
    struct ieee80211_stats         *vap_stats_data;
    struct ieee80211_mac_stats     *vap_stats_ucast;
    struct ieee80211_mac_stats     *vap_stats_mcast;

    /* On one radio there could be multiple wireless interfaces - VAP's.
       The VAP stats seems to hold the values that we are interested in
       therefore sum all active VAP interfaces and get RADIO stats

       /proc/net/dev are network stats - essid stats?
     */
    memset (&vap_stats, 0, sizeof(vap_stats));

    rc = osync_nl80211_peer_stats_fetch(ifName,&vap_stats);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing %s %s client stats (Failed to get stats '%s')",
            radio_get_name_from_type(radio_type),
            ifName,
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    vap_stats_data = &vap_stats.vap_stats;
    vap_stats_ucast = (struct ieee80211_mac_stats*)
        (((unsigned char *)&vap_stats.vap_unicast_stats));
    vap_stats_mcast = (struct ieee80211_mac_stats*)
        (((unsigned char *)&vap_stats.vap_multicast_stats));

    stats_entry->bytes_tx = 
        vap_stats_ucast->ims_tx_data_bytes + vap_stats_mcast->ims_tx_data_bytes;
    LOG(TRACE,
        "Parsed %s peer tx_bytes %"PRIu64"",
        radio_get_name_from_type(radio_type),
        stats_entry->bytes_tx);

    stats_entry->frames_tx = 
        vap_stats_ucast->ims_tx_data_packets + vap_stats_mcast->ims_tx_data_packets;
    LOG(TRACE,
        "Parsed %s peer tx_frames %"PRIu64"",
        radio_get_name_from_type(radio_type),
        stats_entry->frames_tx);

    stats_entry->bytes_rx = 
        vap_stats_ucast->ims_rx_data_bytes + vap_stats_mcast->ims_rx_data_bytes;
    LOG(TRACE,
        "Parsed %s peer rx_bytes %"PRIu64"",
        radio_get_name_from_type(radio_type),
        stats_entry->bytes_rx);

    stats_entry->frames_rx = 
        vap_stats_ucast->ims_rx_data_packets + vap_stats_mcast->ims_rx_data_packets;
    LOG(TRACE,
        "Parsed %s peer rx_frames %"PRIu64"",
        radio_get_name_from_type(radio_type),
        stats_entry->frames_rx);

    stats_entry->errors_rx = 
        vap_stats_data->is_rx_tooshort +
        vap_stats_data->is_rx_decap +
        vap_stats_data->is_rx_nobuf +
        vap_stats_ucast->ims_rx_wpimic  +
        vap_stats_mcast->ims_rx_wpimic +
        vap_stats_ucast->ims_rx_ccmpmic +
        vap_stats_mcast->ims_rx_ccmpmic +
        vap_stats_ucast->ims_rx_tkipicv +
        vap_stats_mcast->ims_rx_tkipicv +
        vap_stats_ucast->ims_rx_wepfail +
        vap_stats_mcast->ims_rx_wepfail +
        vap_stats_ucast->ims_rx_fcserr +
        vap_stats_mcast->ims_rx_fcserr +
        vap_stats_ucast->ims_rx_tkipmic +
        vap_stats_mcast->ims_rx_tkipmic +
        vap_stats_ucast->ims_rx_decryptcrc +
        vap_stats_mcast->ims_rx_decryptcrc;
    LOG(TRACE,
        "Parsed %s peer rx_errors %"PRIu64"",
        radio_get_name_from_type(radio_type),
        stats_entry->errors_rx);

    stats_entry->errors_tx = 
        vap_stats_ucast->ims_tx_discard +
        vap_stats_mcast->ims_tx_discard+
        vap_stats_data->is_tx_nobuf +
        vap_stats_data->is_tx_not_ok;
    LOG(TRACE,
        "Parsed %s peer tx_errors %"PRIu64"",
        radio_get_name_from_type(radio_type),
        stats_entry->errors_tx);

    /* TODO: Needs verification.

       Retry counter was taken from assumption from the following calculation:

       all queued packets were packets actually sent and not ok - retried!!
       packet_queued = tx_data_packets + ns_is_tx_not_ok
     */
    stats_entry->retries_tx = 
        vap_stats_data->is_tx_not_ok;
    LOG(TRACE,
        "Parsed %s peer tx_retries %"PRIu64"",
        radio_get_name_from_type(radio_type),
        stats_entry->retries_tx);

    stats_entry->rate_tx = 
        vap_stats_ucast->ims_last_tx_rate;
    LOG(TRACE,
        "Parsed %s peer tx_rate %u",
        radio_get_name_from_type(radio_type),
        stats_entry->rate_tx);

    return IOCTL_STATUS_OK;
}
static
ioctl_status_t ioctl80211_peer_list_fetch(
        radio_entry_t              *radio_cfg,
        char                       *ifName,
        radio_essid_t               essid,
        mac_address_t               mac,
        ds_dlist_t                 *client_list)
{
    ioctl_status_t                  status;
    ioctl80211_client_record_t     *client_entry = NULL;
    radio_type_t                    radio_type;
    unsigned char                   sig8;

    radio_type = radio_cfg->type;

    client_entry = 
        ioctl80211_client_record_alloc();
    if (NULL == client_entry)
    {
        LOG(ERR,
            "Parsing %s interface peer stats "
            "(Failed to allocate memory)",
            radio_get_name_from_type(radio_type));
        return IOCTL_STATUS_ERROR;
    }

    client_entry->is_client = false;

    client_entry->info.type = radio_type;

    memcpy (client_entry->info.mac,
            mac,
            sizeof(client_entry->info.mac));

    LOG(TRACE,
        "Parsed %s peer MAC "MAC_ADDRESS_FORMAT,
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(client_entry->info.mac));

#ifdef OPENSYNC_NL_SUPPORT
    iwstats *          stats;
    FILE *    f;
    char      buf[256];
    char *    bp;
    int       t;

    f = fopen(PROC_NET_WIRELESS, "r");
    if(f==NULL)
        return -1;

    stats = (iwstats*)malloc(sizeof(iwstats));
    if(stats == NULL)
        return -1;
    while(fgets(buf,255,f))
    {
            bp=buf;
            while(*bp&&isspace(*bp))
                    bp++;
            if(strncmp(bp,radio_cfg->if_name,strlen(radio_cfg->if_name))==0 && bp[strlen(radio_cfg->if_name)]==':')
            {
                    bp=strchr(bp,':');
                    bp++;

                    bp = strtok(bp, " ");
                    sscanf(bp, "%X", &t);
                    stats->status = (unsigned short) t;
                    bp = strtok(NULL, " ");
                    if(strchr(bp,'.') != NULL)
                            stats->qual.updated |= 1;
                    sscanf(bp, "%d", &t);
                    stats->qual.qual = (unsigned char) t;
                    bp = strtok(NULL, " ");
                    if(strchr(bp,'.') != NULL)
                            stats->qual.updated |= 2;
                    sscanf(bp, "%d", &t);
                    stats->qual.level = (unsigned char) t;

                    bp = strtok(NULL, " ");
                    if(strchr(bp,'.') != NULL)
                            stats->qual.updated += 4;
                    sscanf(bp, "%d", &t);
                    stats->qual.noise = (unsigned char) t;
                    printf("%s \n",bp);

                    bp = strtok(NULL, " ");
                    sscanf(bp, "%d", &stats->discard.nwid);
                    bp = strtok(NULL, " ");
                    sscanf(bp, "%d", &stats->discard.code);
                    bp = strtok(NULL, " ");
                    sscanf(bp, "%d", &stats->discard.misc);
                    fclose(f);
            }
    }
    fclose(f);
    sig8  = stats->qual.level;
    sig8 -= stats->qual.noise;
#else
    struct  iw_statistics       request_stats;
    struct iwreq                request;
    int32_t                     rc;
    memset (&request_stats, 0, sizeof(request_stats));
    request.u.data.pointer = (caddr_t) &request_stats;
    request.u.data.length = sizeof(request_stats);
    request.u.data.flags = 1;     /* Clear updated flag */
    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                ifName,
                SIOCGIWSTATS,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing %s %s peer stats (Failed to get info '%s')",
            radio_get_name_from_type(radio_type),
            ifName,
            strerror(errno));
        goto error;
    }

    /* Note: This relies on 8-bit unsigned int wraparound */
    sig8 = request_stats.qual.level;
    sig8 -= request_stats.qual.noise;
#endif

    client_entry->stats.peer.rssi = sig8;

    LOG(TRACE,
        "Parsed %s peer RSSI %d",
        radio_get_name_from_type(radio_type),
        client_entry->stats.peer.rssi);

    strlcpy(client_entry->info.ifname,
            ifName,
            sizeof(client_entry->info.ifname));

    LOG(TRACE,
            "Parsed %s peer IFNAME %s",
            radio_get_name_from_type(radio_type),
            client_entry->info.ifname);

    memcpy (client_entry->info.essid,
            essid,
            sizeof(client_entry->info.essid));

    LOG(TRACE,
            "Parsed %s peer ESSID %s",
            radio_get_name_from_type(radio_type),
            client_entry->info.essid);

    status = 
        ioctl80211_peer_stats_fetch (
                radio_type,
                ifName,
                client_entry);
    if (IOCTL_STATUS_OK != status)
    {
        goto error;
    }

    status = 
        ioctl80211_clients_stats_rx_fetch (
                radio_type,
                radio_cfg->phy_name,
                client_entry);
    if (IOCTL_STATUS_OK != status)
    {
        goto error;
    }

    status = 
        ioctl80211_clients_stats_tx_fetch (
                radio_type,
                radio_cfg->phy_name,
                client_entry);
    if (IOCTL_STATUS_OK != status)
    {
        goto error;
    }

    ds_dlist_insert_tail(client_list, client_entry);
    return IOCTL_STATUS_OK;

error:
    ioctl80211_client_record_free(client_entry);
    return IOCTL_STATUS_ERROR;
}

ioctl_status_t ioctl80211_clients_list_get(
        radio_entry_t              *radio_cfg,
        radio_essid_t              *essid,
        ds_dlist_t                 *client_list)
{
    ioctl_status_t                  status;
    char                           *args[IOCTL80211_IFNAME_ARG_QTY];
    ioctl80211_interface_t         *interface = NULL;
    ioctl80211_interfaces_t         interfaces;
    uint32_t                        interface_index;

    if (NULL == client_list)
    {
        return IOCTL_STATUS_ERROR;
    }

    memset (&interfaces, 0, sizeof(interfaces));
    args[IOCTL80211_IFNAME_ARG] = (char *) &interfaces;

    ioctl80211_interfaces_find(
            ioctl80211_fd_get(),
            &ioctl80211_interfaces_get,
            args,
            radio_cfg->type);

    for (interface_index = 0; interface_index < interfaces.qty; interface_index++)
    {
        interface = &interfaces.phy[interface_index];

        /* If essid is defined skip the stats */
        if (    (NULL != essid)
             && (memcmp(interface->essid, essid, sizeof(*essid)))
           )
        {
            LOG(TRACE,
                "Skip parsing %s interface %s client list %s != %s",
                radio_get_name_from_type(radio_cfg->type),
                interface->ifname,
                interface->essid,
                (char *)essid);
            continue;
        }

        /* Adding plume STA stats as peer client */
        if (interface->sta)
        {
            LOG(TRACE,
                "Parsing %s interface %s peer list",
                radio_get_name_from_type(radio_cfg->type),
                interface->ifname);

            status = 
                ioctl80211_peer_list_fetch (
                        radio_cfg,
                        interface->ifname,
                        interface->essid,
                        interface->mac,
                        client_list);
            if (IOCTL_STATUS_OK != status)
            {
                LOG(ERR,
                    "Parsing %s interface %s peer stats",
                    radio_get_name_from_type(radio_cfg->type),
                    interface->ifname);
                return IOCTL_STATUS_ERROR;
            }
        }
        else
        {
            LOG(TRACE,
                "Parsing %s interface %s client list",
                radio_get_name_from_type(radio_cfg->type),
                interface->ifname);

            status = 
                ioctl80211_clients_list_fetch (
                        radio_cfg,
                        interface->ifname,
                        interface->essid,
                        client_list);
            if (IOCTL_STATUS_OK != status)
            {
                LOG(ERR,
                    "Parsing %s interface %s client list",
                    radio_get_name_from_type(radio_cfg->type),
                    interface->ifname);
                return IOCTL_STATUS_ERROR;
            }
        }
    }

    return IOCTL_STATUS_OK;
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

ioctl_status_t ioctl80211_client_list_get(
        radio_entry_t              *radio_cfg,
        radio_essid_t              *essid,
        ds_dlist_t                 *client_list)
{
    ioctl_status_t                  status;

    if (NULL == client_list)
    {
        return IOCTL_STATUS_ERROR;
    }

    status = 
        ioctl80211_clients_list_get(
                radio_cfg,
                essid,
                client_list);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_client_stats_convert(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_record)
{
    ioctl_status_t                  status;

    /* Update delta stats for clients/peers */
    if (data_new->is_client) {
        status =
            ioctl80211_client_stats_calculate (
                    radio_cfg,
                    data_new,
                    data_old,
                    client_record);
    } else {
        status =
            ioctl80211_peer_stats_calculate (
                    radio_cfg,
                    data_new,
                    data_old,
                    client_record);
    }
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    /* Copy uAPSD info (Debug purpose only) */
    client_record->uapsd = data_new->uapsd;

    status =
        ioctl80211_client_stats_rx_calculate (
            radio_cfg,
            data_new,
            data_old,
            client_record);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    /* TODO: recalculate rx_stats from stats_rx due to driver error */

    status =
        ioctl80211_client_stats_tx_calculate (
            radio_cfg,
            data_new,
            data_old,
            client_record);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}
