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

#ifndef IOCTL80211_CLIENT_H_INCLUDED
#define IOCTL80211_CLIENT_H_INCLUDED

#include "ds.h"
#include "ds_dlist.h"

#include "dpp_client.h"

#include "ioctl80211_api.h"

/* Max size we support is 100 clients */
#define IOCTL80211_CLIENTS_SIZE \
    (100 * sizeof(struct ieee80211req_sta_info))

typedef struct
{
    uint64_t                        bytes_tx;
    uint64_t                        bytes_rx;
    uint32_t                        frames_tx;
    uint32_t                        frames_rx;
    uint32_t                        retries_rx;
    uint32_t                        retries_tx;
    uint32_t                        errors_rx;
    uint32_t                        errors_tx;
    uint32_t                        rate_rx;
    uint32_t                        rate_tx;
    int32_t                         rssi;
} ioctl80211_client_stats_t;

typedef struct
{
    uint64_t                        bytes_tx;
    uint64_t                        bytes_rx;
    uint64_t                        frames_tx;
    uint64_t                        frames_rx;
    uint64_t                        retries_rx;
    uint64_t                        retries_tx;
    uint64_t                        errors_rx;
    uint64_t                        errors_tx;
    uint32_t                        rate_rx;
    uint32_t                        rate_tx;
    int32_t                         rssi;
} ioctl80211_peer_stats_t;

typedef struct
{
    /* General client data (upper layer cache key) */
    dpp_client_info_t               info;
    uint64_t                        stats_cookie;

    // TODO: move to stats
    uint32_t                        uapsd;

    /* Target specific client data */
    bool                            is_client;
    union {
        ioctl80211_client_stats_t   client;
        ioctl80211_peer_stats_t     peer;
    } stats;
    struct ps_uapi_ioctl            stats_rx;
    struct ps_uapi_ioctl            stats_tx;

    /* Linked list client data */
    ds_dlist_node_t                 node;
} ioctl80211_client_record_t;

static inline
ioctl80211_client_record_t *ioctl80211_client_record_alloc()
{
    ioctl80211_client_record_t *record = NULL;

    record = malloc(sizeof(ioctl80211_client_record_t));
    if (record) {
        memset(record, 0, sizeof(ioctl80211_client_record_t));
    }

    return record;
}

static inline
void ioctl80211_client_record_free(ioctl80211_client_record_t *record)
{
    if (NULL != record) {
        free(record);
    }
}

ioctl_status_t ioctl80211_client_list_get(
        radio_entry_t              *radio_cfg,
        radio_essid_t              *essid,
        ds_dlist_t                 *client_list);

ioctl_status_t ioctl80211_client_stats_convert(
        radio_entry_t              *radio_cfg,
        ioctl80211_client_record_t *data_new,
        ioctl80211_client_record_t *data_old,
        dpp_client_record_t        *client_result);

ioctl_status_t ioctl80211_client_stats_get(
        radio_type_t                radio_type,
        char                       *ifName,
        char                       *phyName,
        mac_address_t               mac,
        dpp_client_stats_t         *stats);

#endif /* IOCTL80211_CLIENT_H_INCLUDED */
