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

#include "const.h"
#include "log.h"
#include "os.h"
#include "kconfig.h"

#include "ioctl80211.h"
#include "ioctl80211_client.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL

#define IOCTL80211_DATA_RATE_LEN    (32)

/* Copied from  qca/src/qca-wifi/umac/include/ieee80211_node.h */
#define IEEE80211_NODE_AUTH             0x00000001          /* authorized for data */
#define IEEE80211_NODE_QOS              0x00000002          /* QoS enabled */
#define IEEE80211_NODE_ERP              0x00000004          /* ERP enabled */
#define IEEE80211_NODE_HT               0x00000008          /* HT enabled */

typedef struct
{
    struct ieee80211req_sta_info        sta_info;
    int32_t                             padding[3]; /* Apparently driver adds 12 Bytes!!!*/
} ieee80211req_sta_info_t;

struct weight_avg {
    uint64_t sum;
    uint64_t cnt;
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

static uint32_t mcs_to_mbps(const int mcs, const int bw, const int nss)
{
    /* The following table is precomputed from:
     *
     * bpsk -> 1bit
     * qpsk -> 2bit
     * 16-qam -> 4bit
     * 64-qam -> 6bit
     * 256-qam -> 8bit
     *
     * 20mhz -> 52 tones
     * 40mhz -> 108 tones
     * 80mhz -> 234 tones
     * 160mhz -> 486 tones
     *
     * Once divided by 4 will get an long GI phyrate in mbps.
     */
    static const unsigned short bps[10][4] = {
        /* 20mhz 40mhz 80mhz  160mhz */
        {  26,   54,   117,   234   }, /* BPSK 1/2 */
        {  52,   108,  234,   468   }, /* QPSK 1/2 */
        {  78,   162,  351,   702   }, /* QPSK 3/4 */
        {  104,  216,  468,   936   }, /* 16-QAM 1/2 */
        {  156,  324,  702,   1404  }, /* 16-QAM 3/4 */
        {  208,  432,  936,   1248  }, /* 16-QAM 2/3 */
        {  234,  486,  1053,  2106  }, /* 64-QAM 3/4 */
        {  260,  540,  1170,  2340  }, /* 64-QAM 5/6 */
        {  312,  648,  1404,  2808  }, /* 256-QAM 3/4 */
        {  346,  720,  1560,  3120  }, /* 256-QAM 5/6 */
    };
    static const unsigned short legacy[] = {
        6, 9, 12, 18, 24, 36, 48, 54, /* OFDM */
        1, 2, 5, 11, 2, 5, 11, /* CCK */
    };
    const int i = mcs < 10 ? mcs : 9;
    const int j = bw < 4 ? bw : 3;
    if (nss == 0)
        return mcs < (int)ARRAY_SIZE(legacy) ? legacy[mcs] : legacy[0];
    else
        return (bps[i][j] * nss) / 4; /* hopefully compiler makes a bitshift */
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
    struct weight_avg               avgmbps = { .sum = 0, .cnt = 0 };

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

        if (kconfig_enabled(CONFIG_QCA_RATE_HISTO_TO_EXPECTED_TPUT)) {
            weight_avg_add(
                &avgmbps,
                mcs_to_mbps(mcs, bw, nss),
                STATS_DELTA(
                    new_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus,
                    old_stats_rx->u.peer_rx_stats.get.stats[stats_index].num_mpdus));

            continue;
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

    if (kconfig_enabled(CONFIG_QCA_RATE_HISTO_TO_EXPECTED_TPUT)) {
        if (avgmbps.cnt) {
            /* This overrides the "last rx rate" */
            client_record->stats.rate_rx = weight_avg_get(&avgmbps);
            LOG(TRACE,
                 "Calculated %s client delta rx phyrate "MAC_ADDRESS_FORMAT
                 " mbps=%f mpdus=%llu",
                 radio_get_name_from_type(radio_type),
                 MAC_ADDRESS_PRINT(data_new->info.mac),
                 client_record->stats.rate_rx,
                 avgmbps.cnt);
        }
    }

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_clients_stats_rx_fetch(
        radio_type_t                    radio_type,
        char                           *phyName,
        ioctl80211_client_record_t     *client_entry)
{
    int32_t                             rc;

    struct iwreq                        request;
    struct ps_uapi_ioctl               *ioctl_stats = &client_entry->stats_rx;

    memset (ioctl_stats, 0, sizeof(*ioctl_stats));
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = ioctl_stats;
    request.u.data.length = PS_UAPI_IOCTL_SIZE;

    ioctl_stats->cmd = PS_UAPI_IOCTL_CMD_PEER_RX_STATS;
    ioctl_stats->u.peer_rx_stats.set.addr[0] = (u8)client_entry->info.mac[0];
    ioctl_stats->u.peer_rx_stats.set.addr[1] = (u8)client_entry->info.mac[1];
    ioctl_stats->u.peer_rx_stats.set.addr[2] = (u8)client_entry->info.mac[2];
    ioctl_stats->u.peer_rx_stats.set.addr[3] = (u8)client_entry->info.mac[3];
    ioctl_stats->u.peer_rx_stats.set.addr[4] = (u8)client_entry->info.mac[4];
    ioctl_stats->u.peer_rx_stats.set.addr[5] = (u8)client_entry->info.mac[5];

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
    struct weight_avg               avgmbps = { .sum = 0, .cnt = 0 };

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

        if (kconfig_enabled(CONFIG_QCA_RATE_HISTO_TO_EXPECTED_TPUT)) {
            weight_avg_add(
                    &avgmbps,
                    mcs_to_mbps(mcs, bw, nss),
                    STATS_DELTA(
                        new_stats_tx->u.peer_tx_stats.get.stats[stats_index].ppdus,
                        old_stats_tx->u.peer_tx_stats.get.stats[stats_index].ppdus));

            continue;
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

    if (kconfig_enabled(CONFIG_QCA_RATE_HISTO_TO_EXPECTED_TPUT)) {
        if (avgmbps.cnt) {
            /* This overrides the "last tx rate" */
            client_record->stats.rate_tx = weight_avg_get(&avgmbps);
            LOG(TRACE,
                 "Calculated %s client delta tx phyrate "MAC_ADDRESS_FORMAT
                 " mbps=%f ppdus=%llu",
                 radio_get_name_from_type(radio_type),
                 MAC_ADDRESS_PRINT(data_new->info.mac),
                 client_record->stats.rate_tx,
                 avgmbps.cnt);
        }
    }

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_clients_stats_tx_fetch(
        radio_type_t                    radio_type,
        char                           *phyName,
        ioctl80211_client_record_t      *client_entry)
{
    int32_t                             rc;

    struct iwreq                        request;
    struct ps_uapi_ioctl               *ioctl_stats = &client_entry->stats_tx;

    memset (ioctl_stats, 0, sizeof(*ioctl_stats));
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = ioctl_stats;
    request.u.data.length = PS_UAPI_IOCTL_SIZE;

    ioctl_stats->cmd = PS_UAPI_IOCTL_CMD_PEER_TX_STATS;
    ioctl_stats->u.peer_tx_stats.set.addr[0] = (u8)client_entry->info.mac[0];
    ioctl_stats->u.peer_tx_stats.set.addr[1] = (u8)client_entry->info.mac[1];
    ioctl_stats->u.peer_tx_stats.set.addr[2] = (u8)client_entry->info.mac[2];
    ioctl_stats->u.peer_tx_stats.set.addr[3] = (u8)client_entry->info.mac[3];
    ioctl_stats->u.peer_tx_stats.set.addr[4] = (u8)client_entry->info.mac[4];
    ioctl_stats->u.peer_tx_stats.set.addr[5] = (u8)client_entry->info.mac[5];

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
        /* Can be overridden with histogram derived average phyrate */
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
        /* Can be overridden with histogram derived average phyrate */
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

    struct iwreq                    request;
    struct ieee80211req_sta_stats   ieee80211_client_stats;

    memset (&ieee80211_client_stats, 0, sizeof(ieee80211_client_stats));
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = &ieee80211_client_stats;
    request.u.data.length = sizeof(ieee80211_client_stats);

    memcpy (ieee80211_client_stats.is_u.macaddr,
            client_entry->info.mac,
            sizeof(ieee80211_client_stats.is_u.macaddr));

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                ifName,
                IEEE80211_IOCTL_STA_STATS,
                &request);
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

/* Max size we support is 100 clients */
#define IOCTL80211_CLIENTS_SIZE \
    (100 * sizeof(struct ieee80211req_sta_info))

static
ioctl_status_t ioctl80211_clients_list_fetch(
        radio_entry_t              *radio_cfg,
        char                       *ifName,
        radio_essid_t               essid,
        ds_dlist_t                 *client_list)
{
    ioctl_status_t                  status;
    int32_t                         rc;
    ioctl80211_client_record_t     *client_entry = NULL;
    radio_type_t                    radio_type;

    struct iwreq                    request;

    uint8_t                         ieee80211_clients[IOCTL80211_CLIENTS_SIZE];
    ssize_t                         ieee80211_client_offset = 0;
    struct ieee80211req_sta_info   *ieee80211_client = NULL;

    radio_type = radio_cfg->type;
    if (NULL == client_list)
    {
        return IOCTL_STATUS_ERROR;
    }
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

    for (   ieee80211_client_offset = 0;
            request.u.data.length - ieee80211_client_offset >= (int)sizeof(*ieee80211_client);)
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

        STRSCPY(client_entry->info.ifname, ifName);
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

struct ioctl80211_vap_stats
{   
    struct ieee80211_stats          vap_stats;
    struct ieee80211_mac_stats      vap_unicast_stats;
    struct ieee80211_mac_stats      vap_multicast_stats;
};

static
ioctl_status_t ioctl80211_peer_stats_fetch(
        radio_type_t                radio_type,
        char                       *ifName,
        ioctl80211_client_record_t *client_entry)
{
    int32_t                         rc;
    struct ifreq                    if_req;
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

    memset (&if_req, 0, sizeof(if_req));
    STRSCPY(if_req.ifr_name, ifName);
    if_req.ifr_data = (caddr_t) &vap_stats;

    /* Initiate Atheros stats fetch */
    rc =
        ioctl(
                ioctl80211_fd_get(),
                SIOCG80211STATS,
                &if_req);
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
    int32_t                         rc;
    ioctl80211_client_record_t     *client_entry = NULL;
    radio_type_t                    radio_type;
    unsigned char                   sig8;
    struct iwreq                    request;

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

    struct  iw_statistics       request_stats;
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

    client_entry->stats.peer.rssi = sig8;

    LOG(TRACE,
        "Parsed %s peer RSSI %d",
        radio_get_name_from_type(radio_type),
        client_entry->stats.peer.rssi);

    STRSCPY(client_entry->info.ifname, ifName);

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
