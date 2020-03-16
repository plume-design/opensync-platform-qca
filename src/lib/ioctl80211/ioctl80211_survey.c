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
#include <inttypes.h>
#include <sys/socket.h>
#include <linux/types.h>

#include "log.h"
#include "const.h"

#include "ioctl80211.h"
#include "ioctl80211_survey.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL


/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

ioctl_status_t ioctl80211_survey_results_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        ds_dlist_t                 *survey_list)
{
    int32_t                         rc;
    struct iwreq                    request;
    struct ps_uapi_ioctl            data;
    radio_type_t                    radio_type = radio_cfg->type;
    ioctl80211_survey_record_t     *survey_record;

    memset (&data, 0, sizeof(data));
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = &data;
    request.u.data.length = PS_UAPI_IOCTL_SIZE;

    data.cmd = 
        (RADIO_SCAN_TYPE_ONCHAN == scan_type) ?
        PS_UAPI_IOCTL_CMD_SURVEY_BSS :
        PS_UAPI_IOCTL_CMD_SURVEY_CHAN;

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                PS_UAPI_IOCTL_SET,
                &request);
    if (0 > rc) {
        LOGE("Processing %s %s survey for chan %u "
             " (Failed to set params '%s')",
             radio_get_name_from_type(radio_type),
             radio_get_scan_name_from_type(scan_type),
             chan_list[0],
             strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                PS_UAPI_IOCTL_GET,
                &request);
    if (0 > rc) {
        LOGE("Processing %s %s survey for chan %u "
             " (Failed to get params '%s')",
             radio_get_name_from_type(radio_type),
             radio_get_scan_name_from_type(scan_type),
             chan_list[0],
             strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    uint32_t    chan_index = 0;
    for (chan_index = 0; chan_index < chan_num; chan_index++) {
        survey_record = 
            ioctl80211_survey_record_alloc();
        if (NULL == survey_record) {
            LOGE("Processing %s %s survey report "
                 "(Failed to allocate memory)",
                 radio_get_name_from_type(radio_type),
                 radio_get_scan_name_from_type(scan_type));
            return IOCTL_STATUS_ERROR;
        }

        if (RADIO_SCAN_TYPE_ONCHAN == scan_type) {
            survey_record->info.chan = chan_list[chan_index];
            survey_record->info.timestamp_ms = get_timestamp();

            survey_record->stats.survey_bss.chan_active   = data.u.survey_bss.get.total;
            survey_record->stats.survey_bss.chan_busy     = data.u.survey_bss.get.busy;
            survey_record->stats.survey_bss.chan_tx       = data.u.survey_bss.get.tx;
            survey_record->stats.survey_bss.chan_self     = data.u.survey_bss.get.rx_bss;
            survey_record->stats.survey_bss.chan_rx       = data.u.survey_bss.get.rx;
            survey_record->stats.survey_bss.chan_busy_ext = data.u.survey_bss.get.busy_ext;

            LOGT("Fetched %s %s %u survey "
                 "{active=%"PRIu64" busy=%"PRIu64" tx=%"PRIu64" self=%"PRIu64" rx=%"PRIu64" ext=%"PRIu64"}",
                 radio_get_name_from_type(radio_type),
                 radio_get_scan_name_from_type(scan_type),
                 survey_record->info.chan,
                 survey_record->stats.survey_bss.chan_active,
                 survey_record->stats.survey_bss.chan_busy,
                 survey_record->stats.survey_bss.chan_tx,
                 survey_record->stats.survey_bss.chan_self,
                 survey_record->stats.survey_bss.chan_rx,
                 survey_record->stats.survey_bss.chan_busy_ext);
        }
        else {
            uint32_t    stats_chan = 0;
            uint32_t    stats_index = 0;

            for (   stats_index = 0;
                    stats_index < ARRAY_SIZE(data.u.survey_chan.get.channels);
                    stats_index++) {
                if (data.u.survey_chan.get.channels[stats_index].freq == 0) {
                    continue;
                }

                stats_chan = 
                    radio_get_chan_from_mhz(
                        data.u.survey_chan.get.channels[stats_index].freq);

                if (chan_list[chan_index] != stats_chan) {
                    continue;
                }

                survey_record->info.chan = chan_list[chan_index];
                survey_record->info.timestamp_ms = get_timestamp();

                survey_record->stats.survey_obss.chan_active  = data.u.survey_chan.get.channels[stats_index].total,
                survey_record->stats.survey_obss.chan_busy    = data.u.survey_chan.get.channels[stats_index].busy,
                survey_record->stats.survey_obss.chan_tx      = data.u.survey_chan.get.channels[stats_index].tx,
                survey_record->stats.survey_obss.chan_self    = 0,
                survey_record->stats.survey_obss.chan_rx      = data.u.survey_chan.get.channels[stats_index].rx,
                survey_record->stats.survey_obss.chan_busy_ext = 0;

                LOGT("Fetched %s %s %u survey "
                     "{active=%u busy=%u tx=%u self=%u rx=%u ext=%u}",
                     radio_get_name_from_type(radio_type),
                     radio_get_scan_name_from_type(scan_type),
                     survey_record->info.chan,
                     survey_record->stats.survey_obss.chan_active,
                     survey_record->stats.survey_obss.chan_busy,
                     survey_record->stats.survey_obss.chan_tx,
                     survey_record->stats.survey_obss.chan_self,
                     survey_record->stats.survey_obss.chan_rx,
                     survey_record->stats.survey_obss.chan_busy_ext);
                // channel found, exit loop
                break;
            }
        }

        if (survey_record->info.chan != 0) {
            ds_dlist_insert_tail(survey_list, survey_record);
        }
        else {
            LOGE("Processing %s %s survey for chan %u"
                 " (Unsupported channel)",
                 radio_get_name_from_type(radio_type),
                 radio_get_scan_name_from_type(scan_type),
                 chan_list[chan_index]);
            ioctl80211_survey_record_free(survey_record);
        }
    }

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_survey_results_convert(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type,
        ioctl80211_survey_record_t *data_new,
        ioctl80211_survey_record_t *data_old,
        dpp_survey_record_t        *survey_record)
{
    radio_type_t                    radio_type;

    if (    (NULL == data_new)
         || (NULL == data_old)
         || (NULL == survey_record)
       ) {
        return IOCTL_STATUS_ERROR;
    }
    radio_type = radio_cfg->type;

    /* Loop through all configured channels */
    if (scan_type == RADIO_SCAN_TYPE_ONCHAN) {
        ioctl80211_survey_bss_t     data;


        data.chan_active = STATS_DELTA(
                data_new->stats.survey_bss.chan_active,
                data_old->stats.survey_bss.chan_active);
        data.chan_tx = STATS_DELTA(
                data_new->stats.survey_bss.chan_tx,
                data_old->stats.survey_bss.chan_tx);
        data.chan_rx = STATS_DELTA(
                data_new->stats.survey_bss.chan_rx,
                data_old->stats.survey_bss.chan_rx);
        data.chan_busy = STATS_DELTA(
                data_new->stats.survey_bss.chan_busy,
                data_old->stats.survey_bss.chan_busy);
        data.chan_busy_ext = STATS_DELTA(
                data_new->stats.survey_bss.chan_busy_ext,
                data_old->stats.survey_bss.chan_busy_ext);
        data.chan_self = STATS_DELTA(
                data_new->stats.survey_bss.chan_self,
                data_old->stats.survey_bss.chan_self);

        LOGT("Processed %s %s %u survey delta "
             "{active=%llu busy=%llu tx=%llu self=%llu rx=%llu ext=%llu}",
             radio_get_name_from_type(radio_type),
             radio_get_scan_name_from_type(scan_type),
             data_new->info.chan,
             data.chan_active,
             data.chan_busy,
             data.chan_tx,
             data.chan_self,
             data.chan_rx,
             data.chan_busy_ext);

        /* Repeat the measurement */
        if (!data.chan_active) {
            return IOCTL_STATUS_ERROR;
        }

        survey_record->chan_busy     =
            STATS_PERCENT(data.chan_busy, data.chan_active);
        survey_record->chan_tx       =
            STATS_PERCENT(data.chan_tx, data.chan_active);
        survey_record->chan_rx       =
            STATS_PERCENT(data.chan_rx, data.chan_active);
        survey_record->chan_self     =
            STATS_PERCENT(data.chan_self, data.chan_active);
        survey_record->chan_busy_ext =
            STATS_PERCENT(data.chan_busy_ext, data.chan_active);
        survey_record->duration_ms   = data.chan_active / 1000;
    } else { /* OFF and FULL */
        ioctl80211_survey_obss_t     data;

        data.chan_active = STATS_DELTA(
                data_new->stats.survey_obss.chan_active,
                data_old->stats.survey_obss.chan_active);
        data.chan_tx = STATS_DELTA(
                data_new->stats.survey_obss.chan_tx,
                data_old->stats.survey_obss.chan_tx);
        data.chan_rx = STATS_DELTA(
                data_new->stats.survey_obss.chan_rx,
                data_old->stats.survey_obss.chan_rx);
        data.chan_busy = STATS_DELTA(
                data_new->stats.survey_obss.chan_busy,
                data_old->stats.survey_obss.chan_busy);
        data.chan_self = 0;
        data.chan_busy_ext = 0;

        LOGT("Processed %s %s %u survey delta "
             "{active=%u busy=%u tx=%u self=%u rx=%u ext=%u}",
             radio_get_name_from_type(radio_type),
             radio_get_scan_name_from_type(scan_type),
             data_new->info.chan,
             data.chan_active,
             data.chan_busy,
             data.chan_tx,
             data.chan_self,
             data.chan_rx,
             data.chan_busy_ext);

        /* Repeat the measurement */
        if (!data.chan_active) {
            return IOCTL_STATUS_ERROR;
        }

        survey_record->chan_busy     =
            STATS_PERCENT(data.chan_busy, data.chan_active);
        survey_record->chan_tx       =
            STATS_PERCENT(data.chan_tx, data.chan_active);
        survey_record->chan_rx       =
            STATS_PERCENT(data.chan_rx, data.chan_active);
        survey_record->duration_ms   = data.chan_active / 1000;
    }

    return IOCTL_STATUS_OK;
}
