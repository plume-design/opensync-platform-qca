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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "log.h"
#include "os.h"
#include "os_nif.h"
#include "os_regex.h"
#include "os_types.h"
#include "os_util.h"
#include "target.h"
#include "util.h"

#include "ioctl80211.h"

#define MODULE_ID LOG_MODULE_ID_TARGET


/******************************************************************************
 *  INTERFACE definitions
 *****************************************************************************/

bool target_is_radio_interface_ready(char *phy_name)
{
    bool rc;
    rc = os_nif_is_interface_ready(phy_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}

bool target_is_interface_ready(char *if_name)
{
    bool rc;
    rc = os_nif_is_interface_ready(if_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}


/******************************************************************************
 *  STATS definitions
 *****************************************************************************/

bool target_radio_tx_stats_enable(radio_entry_t *radio_cfg, bool enable)
{
    ioctl_status_t rc;
    rc = ioctl80211_radio_tx_stats_enable(radio_cfg, enable);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}

bool target_radio_fast_scan_enable(radio_entry_t *radio_cfg, ifname_t if_name)
{
    ioctl_status_t rc;
    rc = ioctl80211_radio_fast_scan_enable(radio_cfg, if_name);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}


/******************************************************************************
 *  CLIENT definitions
 *****************************************************************************/

target_client_record_t *target_client_record_alloc()
{
    return ioctl80211_client_record_alloc();
}

void target_client_record_free(target_client_record_t *result)
{
    ioctl80211_client_record_free(result);
}

bool target_stats_clients_get(radio_entry_t *radio_cfg,
                              radio_essid_t *essid,
                              target_stats_clients_cb_t *client_cb,
                              ds_dlist_t *client_list,
                              void *client_ctx)
{
    ioctl_status_t rc;
    rc = ioctl80211_client_list_get(radio_cfg, essid, client_list);
    if (IOCTL_STATUS_OK != rc)
    {
        (*client_cb)(client_list, client_ctx, false);
        return false;
    }

    (*client_cb)(client_list, client_ctx, true);

    return true;
}

bool target_stats_clients_convert(radio_entry_t *radio_cfg,
                                  target_client_record_t *data_new,
                                  target_client_record_t *data_old,
                                  dpp_client_record_t *client_record)
{
    ioctl_status_t rc;
    rc = ioctl80211_client_stats_convert(radio_cfg,
                                         data_new,
                                         data_old,
                                         client_record);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}


/******************************************************************************
 *  SURVEY definitions
 *****************************************************************************/

target_survey_record_t *target_survey_record_alloc()
{
    return ioctl80211_survey_record_alloc();
}

void target_survey_record_free(target_survey_record_t *result)
{
    ioctl80211_survey_record_free(result);
}

bool target_stats_survey_get(radio_entry_t *radio_cfg,
                             uint32_t *chan_list,
                             uint32_t chan_num,
                             radio_scan_type_t scan_type,
                             target_stats_survey_cb_t *survey_cb,
                             ds_dlist_t *survey_list,
                             void *survey_ctx)
{
    ioctl_status_t rc;

    rc = ioctl80211_survey_results_get(radio_cfg,
                                       chan_list,
                                       chan_num,
                                       scan_type,
                                       survey_list);
    if (IOCTL_STATUS_OK != rc)
    {
        (*survey_cb)(survey_list, survey_ctx, false);
        return false;
    }

    (*survey_cb)(survey_list, survey_ctx, true);

    return true;
}

bool target_stats_survey_convert(radio_entry_t *radio_cfg,
                                 radio_scan_type_t scan_type,
                                 target_survey_record_t *data_new,
                                 target_survey_record_t *data_old,
                                 dpp_survey_record_t *survey_record)
{
    ioctl_status_t rc;

    rc = ioctl80211_survey_results_convert(radio_cfg,
                                           scan_type,
                                           data_new,
                                           data_old,
                                           survey_record);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}


/******************************************************************************
 *  NEIGHBORS definitions
 *****************************************************************************/

bool target_stats_scan_start(radio_entry_t *radio_cfg,
                             uint32_t *chan_list,
                             uint32_t chan_num,
                             radio_scan_type_t scan_type,
                             int32_t dwell_time,
                             target_scan_cb_t *scan_cb,
                             void *scan_ctx)
{
    ioctl_status_t rc;

    rc = ioctl80211_scan_channel(radio_cfg,
                                 chan_list,
                                 chan_num,
                                 scan_type,
                                 dwell_time,
                                 scan_cb,
                                 scan_ctx);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}

bool target_stats_scan_stop(radio_entry_t *radio_cfg,
                            radio_scan_type_t scan_type)
{
    ioctl_status_t rc;

    rc = ioctl80211_scan_stop(radio_cfg, scan_type);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}

bool target_stats_scan_get(radio_entry_t *radio_cfg,
                           uint32_t *chan_list,
                           uint32_t chan_num,
                           radio_scan_type_t scan_type,
                           dpp_neighbor_report_data_t *scan_results)
{
    ioctl_status_t rc;

    rc = ioctl80211_scan_results_get(radio_cfg,
                                     chan_list,
                                     chan_num,
                                     scan_type,
                                     scan_results);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}


/******************************************************************************
 *  DEVICE definitions
 *****************************************************************************/

bool target_stats_device_temp_get(radio_entry_t *radio_cfg,
                                  dpp_device_temp_t *temp_entry)
{
    ioctl_status_t rc;

    rc = ioctl80211_device_temp_results_get(radio_cfg, temp_entry);
    if (IOCTL_STATUS_OK != rc)
    {
        LOG(ERR, "Sending device %s temp report (failed to retrieve device"
                 " status)", radio_get_name_from_cfg(radio_cfg));
        return false;
    }

    if (temp_entry->value < 0)
    {
        LOG(WARN, "%s: Driver reporting negative temperature: %d. Skipping.",
                  radio_get_name_from_cfg(radio_cfg), temp_entry->value);
        return false;
    }

    return true;
}

bool target_stats_device_txchainmask_get(
        radio_entry_t              *radio_cfg,
        dpp_device_txchainmask_t   *txchainmask_entry)
{
    ioctl_status_t                  rc;

    rc =
        ioctl80211_device_txchainmask_results_get(
                radio_cfg,
                txchainmask_entry);
    if (IOCTL_STATUS_OK != rc)
    {
        LOG(ERR,
            "Sending device %s txchainmask report "
            "(failed to retrieve device status",
            radio_get_name_from_cfg(radio_cfg));
        return false;
    }

    return true;
}


/******************************************************************************
 *  CAPACITY definitions
 *****************************************************************************/

bool target_stats_capacity_enable(radio_entry_t *radio_cfg, bool enabled)
{
#if defined CONFIG_SM_CAPACITY_QUEUE_STATS
    ioctl_status_t rc;

    rc = ioctl80211_capacity_enable(radio_cfg, enabled);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }
#endif

    return true;
}

bool target_stats_capacity_get(radio_entry_t *radio_cfg,
                               target_capacity_data_t *capacity_new)
{
#if defined CONFIG_SM_CAPACITY_QUEUE_STATS
    ioctl_status_t rc;

    rc = ioctl80211_capacity_results_get(radio_cfg, capacity_new);
    if (IOCTL_STATUS_OK != rc)
    {
        LOG(ERR, "Processing %s capacity",
            radio_get_name_from_type(radio_cfg->type));
        return false;
    }
#endif

    return true;
}

bool target_stats_capacity_convert(target_capacity_data_t *capacity_new,
                                   target_capacity_data_t *capacity_old,
                                   dpp_capacity_record_t *capacity_entry)
{
#if defined CONFIG_SM_CAPACITY_QUEUE_STATS
    target_capacity_data_t capacity_delta;
    int32_t queue_index = 0;

    /* Calculate time deltas and derive percentage per sample */
    memset(&capacity_delta, 0, sizeof(capacity_delta));
    capacity_delta.chan_active =
        STATS_DELTA(capacity_new->chan_active,
                    capacity_old->chan_active);

    capacity_delta.chan_tx =
        STATS_DELTA(capacity_new->chan_tx,
                    capacity_old->chan_tx);

    for (queue_index = 0; queue_index < RADIO_QUEUE_MAX_QTY; queue_index++)
    {
        capacity_delta.queue[queue_index] =
            STATS_DELTA(capacity_new->queue[queue_index],
                        capacity_old->queue[queue_index]);
    }

    capacity_entry->busy_tx =
        STATS_PERCENT(capacity_delta.chan_tx,
                      capacity_delta.chan_active);

    capacity_entry->bytes_tx =
        STATS_DELTA(capacity_new->bytes_tx,
                    capacity_old->bytes_tx);

    capacity_entry->samples =
        STATS_DELTA(capacity_new->samples,
                    capacity_old->samples);

    for (queue_index = 0; queue_index < RADIO_QUEUE_MAX_QTY; queue_index++)
    {
        capacity_entry->queue[queue_index] =
            STATS_PERCENT(capacity_delta.queue[queue_index],
                          capacity_entry->samples);
    }
#endif

    return true;
}
