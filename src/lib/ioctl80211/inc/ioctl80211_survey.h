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

#ifndef IOCTL80211_SURVEY_H_INCLUDED
#define IOCTL80211_SURVEY_H_INCLUDED

#include "dpp_survey.h"
#include "memutil.h"

#include "ioctl80211_api.h"

// on-channel survey
typedef struct
{
    uint64_t                        chan_active;
    uint64_t                        chan_busy;
    uint64_t                        chan_busy_ext;
    uint64_t                        chan_self;
    uint64_t                        chan_rx;
    uint64_t                        chan_tx;
    int16_t                         chan_noise;
} ioctl80211_survey_bss_t;

// off-channel survey
typedef struct
{
    uint32_t                        chan_active;
    uint32_t                        chan_busy;
    uint32_t                        chan_busy_ext;
    uint32_t                        chan_self;
    uint32_t                        chan_rx;
    uint32_t                        chan_tx;
    int16_t                         chan_noise;
} ioctl80211_survey_obss_t;

typedef struct
{
    /* General survey data (upper layer cache key) */
    dpp_survey_info_t               info;

    /* Target specific survey data */
    union {
        ioctl80211_survey_bss_t     survey_bss;
        ioctl80211_survey_obss_t    survey_obss;
    } stats;

    /* Linked list survey data */
    ds_dlist_node_t                 node;
} ioctl80211_survey_record_t;

static inline
ioctl80211_survey_record_t *ioctl80211_survey_record_alloc()
{
    ioctl80211_survey_record_t *record = NULL;

    record = MALLOC(sizeof(ioctl80211_survey_record_t));
    memset(record, 0, sizeof(ioctl80211_survey_record_t));

    return record;
}

static inline
void ioctl80211_survey_record_free(ioctl80211_survey_record_t *record)
{
    if (NULL != record) {
        FREE(record);
    }
}

ioctl_status_t ioctl80211_survey_results_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        ds_dlist_t                 *survey_list);

ioctl_status_t ioctl80211_survey_results_convert(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type,
        ioctl80211_survey_record_t *data_new,
        ioctl80211_survey_record_t *data_old,
        dpp_survey_record_t        *survey_record);

#endif /* IOCTL80211_SURVEY_H_INCLUDED */
