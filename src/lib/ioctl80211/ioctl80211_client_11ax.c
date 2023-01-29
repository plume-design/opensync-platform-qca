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

#include "const.h"
#include "log.h"
#include "os.h"
#include "kconfig.h"
#include "memutil.h"

#include "ioctl80211.h"
#include "ioctl80211_client.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL

#define IOCTL80211_DATA_RATE_LEN    (32)
#define PEER_RX_STATS 0
#define PEER_TX_STATS 1
#define PEER_AVG_STATS 2

#define OSYNC_IOCTL_LIB 1

/* Copied from  qca/src/qca-wifi/umac/include/ieee80211_node.h */
#define IEEE80211_NODE_AUTH             0x00000001          /* authorized for data */
#define IEEE80211_NODE_QOS              0x00000002          /* QoS enabled */
#define IEEE80211_NODE_ERP              0x00000004          /* ERP enabled */
#define IEEE80211_NODE_HT               0x00000008          /* HT enabled */

/*global structure to maintain stats*/
#define PEER_STATS_FLAG 0x0001
#define PEER_CLI_MAX 32

#ifdef CONFIG_PLATFORM_QCA_QSDK11_SUB_VER4
#define DP_PEER_AVG_RATE_STATS_SUPPORTED
#endif

typedef struct
{
    mac_address_t mac_addr;
    uint64_t cookie;
    uint32_t flags;
    uint64_t sum;
    uint64_t cnt;
    uint32_t mpdus;
    uint32_t retries;
    uint32_t success;
    uint32_t attempts;
} weighted_phyrate;

#ifndef DP_PEER_AVG_RATE_STATS_SUPPORTED
#define DP_PEER_AVG_RATE_STATS (1 << 31)
struct wlan_avg_rate_stats {};
#endif

struct avg_phyrate {
    mac_address_t mac_addr;
    uint32_t flags;
    struct wlan_avg_rate_stats stats;
};

static weighted_phyrate g_peer_rx_phyrate[PEER_CLI_MAX];
static weighted_phyrate g_peer_tx_phyrate[PEER_CLI_MAX];
static struct avg_phyrate g_peer_avg_phyrate[PEER_CLI_MAX];

#include "osync_nl80211_11ax.h"

#ifndef PROC_NET_WIRELESS
#define PROC_NET_WIRELESS       "/proc/net/wireless"
#endif
typedef struct iw_statistics    iwstats;

#define	QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION 74

extern struct   socket_context sock_ctx;

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#else
#error confilicting defs of min
#endif

#define PRINT(fmt, ...) \
    do { \
        LOGI(fmt, ##__VA_ARGS__); \
    } while (0)

struct weight_avg {
    uint64_t sum;
    uint64_t cnt;
};

enum guard_int {
    LONG_GUARD_INT,
    SHORT_GUARD_INT
};

static inline void weight_avg_add(struct weight_avg *avg,
                                  uint64_t value,
                                  uint64_t count)
{
    value *= count;
    avg->sum += value;
    avg->cnt += count;
}

static inline uint64_t weight_avg_get(const struct weight_avg *avg)
{
    return avg->cnt > 0 ? avg->sum / avg->cnt : 0;
}

#ifdef OPENSYNC_NL_SUPPORT
int get_cli_mac_index(mac_address_t mac_addr, int peer_stats_flag)
{
    int i;
    int index = 0;
    if (peer_stats_flag == PEER_RX_STATS)
    {
        for (i = 0; i < PEER_CLI_MAX; i++)
        {
            if (g_peer_rx_phyrate[i].flags & PEER_STATS_FLAG)
            {
                if ((g_peer_rx_phyrate[i].mac_addr[0] == (u8)mac_addr[0]) && (g_peer_rx_phyrate[i].mac_addr[1] == (u8)mac_addr[1]) &&
                    (g_peer_rx_phyrate[i].mac_addr[2] == (u8)mac_addr[2]) && (g_peer_rx_phyrate[i].mac_addr[3] == (u8)mac_addr[3]) &&
                    (g_peer_rx_phyrate[i].mac_addr[4] == (u8)mac_addr[4]) && (g_peer_rx_phyrate[i].mac_addr[5] == (u8)mac_addr[5]))
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
    else if (peer_stats_flag == PEER_TX_STATS)
    {
        for (i = 0; i < PEER_CLI_MAX; i++)
        {
            if (g_peer_tx_phyrate[i].flags & PEER_STATS_FLAG)
            {
                if ((g_peer_tx_phyrate[i].mac_addr[0] == (u8)mac_addr[0]) && (g_peer_tx_phyrate[i].mac_addr[1] == (u8)mac_addr[1]) &&
                    (g_peer_tx_phyrate[i].mac_addr[2] == (u8)mac_addr[2]) && (g_peer_tx_phyrate[i].mac_addr[3] == (u8)mac_addr[3]) &&
                    (g_peer_tx_phyrate[i].mac_addr[4] == (u8)mac_addr[4]) && (g_peer_tx_phyrate[i].mac_addr[5] == (u8)mac_addr[5]))
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
    else if (peer_stats_flag == PEER_AVG_STATS)
    {
        for (i = 0; i < PEER_CLI_MAX; i++)
        {
            if (g_peer_avg_phyrate[i].flags & PEER_STATS_FLAG)
            {
                if ((g_peer_avg_phyrate[i].mac_addr[0] == (u8)mac_addr[0]) && (g_peer_avg_phyrate[i].mac_addr[1] == (u8)mac_addr[1]) &&
                    (g_peer_avg_phyrate[i].mac_addr[2] == (u8)mac_addr[2]) && (g_peer_avg_phyrate[i].mac_addr[3] == (u8)mac_addr[3]) &&
                    (g_peer_avg_phyrate[i].mac_addr[4] == (u8)mac_addr[4]) && (g_peer_avg_phyrate[i].mac_addr[5] == (u8)mac_addr[5]))
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
    struct wlan_rx_rate_stats *rx_stats;

    rx_stats = (struct wlan_rx_rate_stats *)buffer;

    index = get_cli_mac_index(peer_mac, PEER_RX_STATS);
    memcpy(g_peer_rx_phyrate[index].mac_addr, peer_mac, sizeof(g_peer_rx_phyrate[index].mac_addr));
    g_peer_rx_phyrate[index].flags |= PEER_STATS_FLAG;
    g_peer_rx_phyrate[index].cookie = (peer_cookie & 0xFFFFFFFF00000000) >> WLANSTATS_PEER_COOKIE_LSB;

    for (i = 0; i < WLANSTATS_CACHE_SIZE; i++)
    {
#if defined(CONFIG_PLATFORM_QCA_QSDK110) && !defined(CONFIG_PLATFORM_QCA_QSDK120)
        if ((int)(rx_stats->rix) != INVALID_CACHE_IDX) {
#else
        if ((int)(rx_stats->ratecode) != INVALID_CACHE_IDX) {
#endif
            g_peer_rx_phyrate[index].sum += rx_stats->rate * rx_stats->num_ppdus;
            g_peer_rx_phyrate[index].cnt += rx_stats->num_ppdus;
            g_peer_rx_phyrate[index].mpdus += rx_stats->num_mpdus;
            g_peer_rx_phyrate[index].retries += rx_stats->num_retries;
        }
        rx_stats = rx_stats + 1;
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

    if (buffer_len < (WLANSTATS_CACHE_SIZE *
              sizeof(struct wlan_tx_rate_stats))
              + sizeof(struct wlan_tx_sojourn_stats)) {
        LOGI("invalid buffer len, return");
        return;
    }
    tx_stats = (struct wlan_tx_rate_stats *)buffer;

    index = get_cli_mac_index(peer_mac, PEER_TX_STATS);

    memcpy(g_peer_tx_phyrate[index].mac_addr, peer_mac, sizeof(g_peer_tx_phyrate[index].mac_addr));
    g_peer_tx_phyrate[index].flags |= PEER_STATS_FLAG;
    g_peer_tx_phyrate[index].cookie = (peer_cookie & 0xFFFFFFFF00000000) >> WLANSTATS_PEER_COOKIE_LSB;

    for (i = 0; i < WLANSTATS_CACHE_SIZE; i++)
    {
#if defined(CONFIG_PLATFORM_QCA_QSDK110) && !defined(CONFIG_PLATFORM_QCA_QSDK120)
        if ((int)(tx_stats->rix) != INVALID_CACHE_IDX) {
#else
        if ((int)(tx_stats->ratecode) != INVALID_CACHE_IDX) {
#endif
            g_peer_tx_phyrate[index].sum += tx_stats->rate * tx_stats->num_ppdus;
            g_peer_tx_phyrate[index].cnt += tx_stats->num_ppdus;
            g_peer_tx_phyrate[index].success += tx_stats->mpdu_success;
            g_peer_tx_phyrate[index].attempts += tx_stats->mpdu_attempts;
        }
        tx_stats = tx_stats + 1;
    }

    return;
}

#endif

static void dp_peer_avg_rate_stats(uint8_t *peer_mac,
                    uint64_t peer_cookie,
                    void *buffer,
                    uint32_t buffer_len)
{
#ifdef DP_PEER_AVG_RATE_STATS_SUPPORTED
    struct avg_phyrate *buf;
    uint32_t *src;
    uint32_t *dst;
    int index;
    int n;

    if (WARN_ON(buffer_len < sizeof(struct wlan_avg_rate_stats)))
        return;
    if (WARN_ON(buffer_len > sizeof(struct wlan_avg_rate_stats)))
        return;

    index = get_cli_mac_index(peer_mac, PEER_AVG_STATS);
    buf = &g_peer_avg_phyrate[index];
    memcpy(buf->mac_addr, peer_mac, sizeof(buf->mac_addr));
    buf->flags |= PEER_STATS_FLAG;

    /* The entire buffer is ultimately a set of 32
     * bit unsigned integers all around. That's
     * why it is possible to accumulate all
     * constituents by treating it as an array.
     */
    n = buffer_len / sizeof(*src);
    src = buffer;
    dst = (uint32_t *)&buf->stats;

    for (; n; n--, src++, dst++)
        *dst += *src;

    LOG(TRACE,
        "Accumulating avg rate stats for "MAC_ADDRESS_FORMAT,
        MAC_ADDRESS_PRINT(peer_mac));
#endif
}

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
    case DP_PEER_AVG_RATE_STATS:
        dp_peer_avg_rate_stats(peer_mac, peer_cookie,
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

static void
ioctl80211_client_stats_avg_rx_calc(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_record)
{
#ifdef DP_PEER_AVG_RATE_STATS_SUPPORTED
    struct avg_phyrate *avg;
    double mbps;
    double num;
    int index;

    index = get_cli_mac_index(data_new->info.mac, PEER_AVG_STATS);
    avg = &g_peer_avg_phyrate[index];
    if (avg->flags & PEER_STATS_FLAG) {
        if (avg->stats.rx[WLAN_RATE_SU].num_ppdu) {
            mbps = avg->stats.rx[WLAN_RATE_SU].sum_mbps;
            mbps /= avg->stats.rx[WLAN_RATE_SU].num_ppdu;

            LOG(TRACE,
                "Overriding rate_rx %lf with SU rate %lf for "MAC_ADDRESS_FORMAT,
                client_record->stats.rate_rx,
                mbps,
                MAC_ADDRESS_PRINT(data_new->info.mac));

            client_record->stats.rate_rx = mbps;
        }

        mbps = 0;
        mbps += avg->stats.rx[WLAN_RATE_SU].sum_mbps;
        mbps += avg->stats.rx[WLAN_RATE_MU_MIMO].sum_mbps;
        mbps += avg->stats.rx[WLAN_RATE_MU_OFDMA].sum_mbps;
        mbps += avg->stats.rx[WLAN_RATE_MU_OFDMA_MIMO].sum_mbps;

        num = 0;
        num += avg->stats.rx[WLAN_RATE_SU].num_ppdu;
        num += avg->stats.rx[WLAN_RATE_MU_MIMO].num_ppdu;
        num += avg->stats.rx[WLAN_RATE_MU_OFDMA].num_ppdu;
        num += avg->stats.rx[WLAN_RATE_MU_OFDMA_MIMO].num_ppdu;

        if (num != 0) {
            mbps /= num;
            client_record->stats.rate_rx_perceived = mbps;

            LOG(TRACE,
                "Calculated rate_rx_perceived %lf for "MAC_ADDRESS_FORMAT,
                mbps,
                MAC_ADDRESS_PRINT(data_new->info.mac));
        }

        memset(avg->stats.rx, 0, sizeof(avg->stats.rx));
    }
#endif
}

static
ioctl_status_t ioctl80211_client_stats_rx_calculate(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_record)
{
    int index;
    radio_type_t radio_type = radio_cfg->type;

    index = get_cli_mac_index(data_new->info.mac, PEER_RX_STATS);
    if (g_peer_rx_phyrate[index].cnt != 0)
    {
        /* This overrides the "last rx rate" */
        client_record->stats.rate_rx = ((g_peer_rx_phyrate[index].sum / g_peer_rx_phyrate[index].cnt) / 1000);

        LOG(TRACE,
            "Calculated %s client delta rx phyrate "MAC_ADDRESS_FORMAT
            " mbps=%f mpdus=%"PRIu64"",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_record->stats.rate_rx,
            g_peer_rx_phyrate[index].cnt);
        g_peer_rx_phyrate[index].sum = 0;
        g_peer_rx_phyrate[index].cnt = 0;

    }
    client_record->stats.frames_rx = g_peer_rx_phyrate[index].mpdus;
    client_record->stats.retries_rx = g_peer_rx_phyrate[index].retries;
    g_peer_rx_phyrate[index].mpdus = 0;
    g_peer_rx_phyrate[index].retries = 0;

    ioctl80211_client_stats_avg_rx_calc(radio_cfg, data_new, data_old,
                                        client_record);

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_clients_stats_rx_fetch(
        radio_type_t                    radio_type,
        char                           *phyName,
        ioctl80211_client_record_t     *client_entry)
{

#ifdef OPENSYNC_NL_SUPPORT
    int index;

    index = get_cli_mac_index(client_entry->info.mac, PEER_RX_STATS);
    if (g_peer_rx_phyrate[index].flags)
        client_entry->stats_cookie = g_peer_rx_phyrate[index].cookie;
#else
    int32_t                             rc;
    struct iwreq                        request;
    struct ps_uapi_ioctl               *ioctl_stats = &client_entry->stats_rx;

    memset(ioctl_stats, 0, sizeof(*ioctl_stats));
    ioctl_stats->u.peer_rx_stats.set.addr[0] = (u8)client_entry->info.mac[0];
    ioctl_stats->u.peer_rx_stats.set.addr[1] = (u8)client_entry->info.mac[1];
    ioctl_stats->u.peer_rx_stats.set.addr[2] = (u8)client_entry->info.mac[2];
    ioctl_stats->u.peer_rx_stats.set.addr[3] = (u8)client_entry->info.mac[3];
    ioctl_stats->u.peer_rx_stats.set.addr[4] = (u8)client_entry->info.mac[4];
    ioctl_stats->u.peer_rx_stats.set.addr[5] = (u8)client_entry->info.mac[5];

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
    /* Set current stats cookie () */
    client_entry->stats_cookie = ioctl_stats->u.peer_rx_stats.get.cookie;
#endif

    return IOCTL_STATUS_OK;
}

static void
ioctl80211_client_stats_avg_tx_calc(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_record)
{
#ifdef DP_PEER_AVG_RATE_STATS_SUPPORTED
    struct avg_phyrate             *avg;
#if 0
    int32_t                         snr;
#endif
    double                          mbps;
    double                          num;
    int                             index;

    index = get_cli_mac_index(data_new->info.mac, PEER_AVG_STATS);
    avg = &g_peer_avg_phyrate[index];
    if (avg->flags & PEER_STATS_FLAG) {
        if (avg->stats.tx[WLAN_RATE_SU].num_ppdu) {
            mbps = avg->stats.tx[WLAN_RATE_SU].sum_mbps;
            mbps /= avg->stats.tx[WLAN_RATE_SU].num_ppdu;

            LOG(TRACE,
                "Overriding rate_tx %lf with SU rate %lf for "MAC_ADDRESS_FORMAT,
                client_record->stats.rate_tx,
                mbps,
                MAC_ADDRESS_PRINT(data_new->info.mac));

            client_record->stats.rate_tx = mbps;
        }

        mbps = 0;
        mbps += avg->stats.tx[WLAN_RATE_SU].sum_mbps;
        mbps += avg->stats.tx[WLAN_RATE_MU_MIMO].sum_mbps;
        mbps += avg->stats.tx[WLAN_RATE_MU_OFDMA].sum_mbps;
        mbps += avg->stats.tx[WLAN_RATE_MU_OFDMA_MIMO].sum_mbps;

        num = 0;
        num += avg->stats.tx[WLAN_RATE_SU].num_ppdu;
        num += avg->stats.tx[WLAN_RATE_MU_MIMO].num_ppdu;
        num += avg->stats.tx[WLAN_RATE_MU_OFDMA].num_ppdu;
        num += avg->stats.tx[WLAN_RATE_MU_OFDMA_MIMO].num_ppdu;

        if (num != 0) {
            mbps /= num;
            client_record->stats.rate_tx_perceived = mbps;

            LOG(TRACE,
                "Calculated rate_tx_perceived %lf for "MAC_ADDRESS_FORMAT,
                mbps,
                MAC_ADDRESS_PRINT(data_new->info.mac));
        }

/* Sometimes SU rssi value is invalid,
 * disable it until find solution in the driver.
 */
#if 0
        /* Apparently the SU ack rssi is the most reliable
         * one. Others are all over the place.
         */
        if (avg->stats.tx[WLAN_RATE_SU].num_snr) {
            snr = avg->stats.tx[WLAN_RATE_SU].sum_snr;
            snr /= avg->stats.tx[WLAN_RATE_SU].num_snr;

            LOG(TRACE,
                "Overriding rssi %d with SU rssi %d for "MAC_ADDRESS_FORMAT,
                client_record->stats.rssi,
                snr,
                MAC_ADDRESS_PRINT(data_new->info.mac));

            client_record->stats.rssi = snr;
        }
#endif

        memset(avg->stats.tx, 0, sizeof(avg->stats.tx));
    }
#endif
}

static
ioctl_status_t ioctl80211_client_stats_tx_calculate(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_record)
{
    int                             index;
    radio_type_t                    radio_type = radio_cfg->type;

    index = get_cli_mac_index(data_new->info.mac, PEER_TX_STATS);
    if (g_peer_tx_phyrate[index].cnt != 0)
    {
        /* This overrides the "last tx rate" */
        client_record->stats.rate_tx = ((g_peer_tx_phyrate[index].sum / g_peer_tx_phyrate[index].cnt) / 1000);
        LOG(TRACE,
            "Calculated %s client delta tx phyrate "MAC_ADDRESS_FORMAT
            " mbps=%f ppdus=%"PRIu64"",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_record->stats.rate_tx,
            g_peer_tx_phyrate[index].cnt);
        g_peer_tx_phyrate[index].sum = 0;
        g_peer_tx_phyrate[index].cnt = 0;
    }
    client_record->stats.frames_tx = g_peer_tx_phyrate[index].success;
    client_record->stats.retries_tx = (g_peer_tx_phyrate[index].attempts - g_peer_tx_phyrate[index].success);
    g_peer_tx_phyrate[index].success = 0;
    g_peer_tx_phyrate[index].attempts = 0;

    ioctl80211_client_stats_avg_tx_calc(radio_cfg, data_new, data_old,
                                        client_record);

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_clients_stats_tx_fetch(
        radio_type_t                    radio_type,
        char                           *phyName,
        ioctl80211_client_record_t      *client_entry)
{
#ifndef OPENSYNC_NL_SUPPORT
    int                                 index;
    uint8_t                             tid;
    struct ps_uapi_ioctl               *ioctl_stats = &client_entry->stats_tx;
    int32_t                             rc;
    struct iwreq                        request;

    memset (ioctl_stats, 0, sizeof(*ioctl_stats));

    ioctl_stats->u.peer_tx_stats.set.addr[0] = (u8)client_entry->info.mac[0];
    ioctl_stats->u.peer_tx_stats.set.addr[1] = (u8)client_entry->info.mac[1];
    ioctl_stats->u.peer_tx_stats.set.addr[2] = (u8)client_entry->info.mac[2];
    ioctl_stats->u.peer_tx_stats.set.addr[3] = (u8)client_entry->info.mac[3];
    ioctl_stats->u.peer_tx_stats.set.addr[4] = (u8)client_entry->info.mac[4];
    ioctl_stats->u.peer_tx_stats.set.addr[5] = (u8)client_entry->info.mac[5];

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
        memset(old_stats, 0, sizeof(*old_stats));
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
        return IOCTL_STATUS_ERROR;
    }

    stats_entry->frames_tx = 
        ieee80211_client_stats.is_stats.ns_tx_data_success;
    LOG(TRACE,
        "Parsed %s client tx_frames %u",
        radio_get_name_from_type(radio_type),
        stats_entry->frames_tx);

    stats_entry->bytes_tx = 
        ieee80211_client_stats.is_stats.ns_tx_bytes_success;
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

struct stainfo_ctx {
    struct cfg80211_data data;
    void *buf;
    size_t size;
};

static void stainfo_cb(struct cfg80211_data *data)
{
    struct stainfo_ctx *ctx = container_of(data, struct stainfo_ctx, data);
    const void *src = data->data;
    const size_t src_size = data->length;
    const size_t dst_offset = ctx->size;

    LOGT("%s: Clients buffer dst_offset = %zu src_size = %zu",
         __func__, dst_offset, src_size);

    if (src_size == 0)
       return;

    if (WARN_ON(src_size < sizeof(struct ieee80211req_sta_info)))
        return;

    if (WARN_ON(src == NULL))
        return;

    /* Expected buffer allocated in the driver */
    if (WARN_ON(src_size > LIST_STATION_CFG_ALLOC_SIZE))
        return;

    LOGT("%s: ctx addr: %p ctx buf addr: %p", __func__, ctx, ctx->buf);

    ctx->size += src_size;
    ctx->buf = REALLOC(ctx->buf, ctx->size);
    memcpy(ctx->buf + dst_offset, src, src_size);
    /* Data is managed by NL helper,
     * needs to set length 0 to force always use new buffer
     */
    data->length = 0;
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
    if (f==NULL)
        return -1;

    stats = (iwstats*)MALLOC(sizeof(iwstats));
    while (fgets(buf, 255, f))
    {
        bp=buf;
        while (*bp&&isspace(*bp))
            bp++;
        if (strncmp(bp, radio_cfg->if_name, strlen(radio_cfg->if_name))==0 && bp[strlen(radio_cfg->if_name)]==':')
        {
            bp=strchr(bp, ':');
            bp++;

            bp = strtok(bp, " ");
            sscanf(bp, "%X", &t);
            stats->status = (unsigned short) t;
            bp = strtok(NULL, " ");
            if (strchr(bp, '.') != NULL)
                stats->qual.updated |= 1;
            sscanf(bp, "%d", &t);
            stats->qual.qual = (unsigned char) t;
            bp = strtok(NULL, " ");
            if (strchr(bp, '.') != NULL)
                stats->qual.updated |= 2;
            sscanf(bp, "%d", &t);
            stats->qual.level = (unsigned char) t;

            bp = strtok(NULL, " ");
            if (strchr(bp, '.') != NULL)
                stats->qual.updated += 4;
            sscanf(bp, "%d", &t);
            stats->qual.noise = (unsigned char) t;

            bp = strtok(NULL, " ");
            sscanf(bp, "%d", &stats->discard.nwid);
            bp = strtok(NULL, " ");
            sscanf(bp, "%d", &stats->discard.code);
            bp = strtok(NULL, " ");
            sscanf(bp, "%d", &stats->discard.misc);
        }
    }
    fclose(f);
    sig8  = stats->qual.level;
    sig8 -= stats->qual.noise;
    free((void*)stats);
#else
    struct  iw_statistics       request_stats;
    struct iwreq                request;
    int32_t                     rc;
    memset(&request_stats, 0, sizeof(request_stats));
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

    STRSCPY(client_entry->info.ifname,
            ifName);

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

static
void util_clients_buf_free(void *buf)
{
#if OPENSYNC_NL_SUPPORT
    FREE(buf);
#endif
}

static
ioctl_status_t ioctl80211_clients_list_fetch(
        radio_entry_t              *radio_cfg,
        char                       *ifName,
        radio_essid_t               essid,
        ds_dlist_t                 *client_list,
        mac_address_t               mac,
        bool                        is_sta)
{
    ioctl_status_t                  status;
    int32_t                         rc;
    uint32_t                        length = 0;
    ioctl80211_client_record_t     *client_entry = NULL;
    radio_type_t                    radio_type;

    void                            *ieee80211_clients_buf;
    ssize_t                         ieee80211_client_offset = 0;
    struct ieee80211req_sta_info   *ieee80211_client = NULL;
    int                            client_cnt = 0;

    radio_type = radio_cfg->type;
    if (NULL == client_list)
    {
        return IOCTL_STATUS_ERROR;
    }

#if OPENSYNC_NL_SUPPORT
    struct stainfo_ctx ctx = {0};

    /* Use default NL data buffer */
    ctx.buf              = NULL;
    ctx.data.length      = 0;
    ctx.data.callback    = &stainfo_cb;
    ctx.data.parse_data  = 0;

    rc = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_LIST_STA, ifName,
            (void *)&ctx.data, ctx.data.length);

    if (0 > rc) {
        FREE(ctx.buf);
        if (is_sta && (-EPERM == rc)) {
            // if we're STA *and* we got EPERM error, fall back to
            // previous implementation, as the qca-wifi patch is
            // probably not applied.
            LOG(NOTICE, "Stats for %s might be unreliable", ifName);
            return ioctl80211_peer_list_fetch(
                radio_cfg,
                ifName,
                essid,
                mac,
                client_list);
        } else {
            LOG(ERR,
                "Parsing %s %s client stats (Failed to get info '%s')",
                radio_get_name_from_type(radio_type),
                ifName,
                strerror(errno));
            return IOCTL_STATUS_ERROR;
        }
    }

    length = ctx.size;
    ieee80211_clients_buf = ctx.buf;
#else
    struct iwreq                    request;
    uint8_t                         ieee80211_clients[IOCTL80211_CLIENTS_SIZE];

    memset (ieee80211_clients, 0, sizeof(ieee80211_clients));
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
    ieee80211_clients_buf = ieee80211_clients;
#endif
    LOGD("%s: length - %d\n", __func__, length);

    for (   ieee80211_client_offset = 0;
            (ssize_t)length - ieee80211_client_offset >= (int)sizeof(*ieee80211_client);)
    {
        ieee80211_client =
            (struct ieee80211req_sta_info *)
            (ieee80211_clients_buf + ieee80211_client_offset);

        client_entry = 
             ioctl80211_client_record_alloc();
        if (NULL == client_entry)
        {
            util_clients_buf_free(ieee80211_clients_buf);
            LOG(ERR,
                "Parsing %s interface client stats "
                "(Failed to allocate memory)",
                radio_get_name_from_type(radio_type));
            return IOCTL_STATUS_ERROR;
        }

        client_cnt++;
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

        STRSCPY(client_entry->info.ifname,
                ifName);
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

#ifdef OPENSYNC_NL_SUPPORT
        client_entry->stats_cookie = ieee80211_client->isi_assoc_time;
#else
        status = 
            ioctl80211_clients_stats_rx_fetch (
                    radio_type,
                    radio_cfg->phy_name,
                    client_entry);
        if (IOCTL_STATUS_OK != status)
        {
            goto error;
        }
#endif

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
        if (!ieee80211_client->isi_len)
        {
            util_clients_buf_free(ieee80211_clients_buf);
            return IOCTL_STATUS_OK;
        }
        continue;

error:
        util_clients_buf_free(ieee80211_clients_buf);
        ioctl80211_client_record_free(client_entry);

        /* Move to the next client */
        ieee80211_client_offset += ieee80211_client->isi_len;
        return IOCTL_STATUS_ERROR;
    }
    util_clients_buf_free(ieee80211_clients_buf);
    LOGT("%s: clients number: %d", ifName , client_cnt);
    return IOCTL_STATUS_OK;
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

        LOG(TRACE,
            "Parsing %s interface %s client list",
            radio_get_name_from_type(radio_cfg->type),
            interface->ifname);

        status = 
            ioctl80211_clients_list_fetch (
                    radio_cfg,
                    interface->ifname,
                    interface->essid,
                    client_list,
                    interface->mac,
                    interface->sta);
        if (IOCTL_STATUS_OK != status)
        {
            LOG(ERR,
                "Parsing %s interface %s client list",
                radio_get_name_from_type(radio_cfg->type),
                interface->ifname);
            return IOCTL_STATUS_ERROR;
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
