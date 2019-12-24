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
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <inttypes.h>

#include "log.h"

#include "ioctl80211.h"
#include "ioctl80211_capacity.h"
#include "ioctl80211_survey.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL


/******************************************************************************
 *                          CLIENT DEBUG
 *****************************************************************************/

/* Qualcomm driver Access category to HW queue mapping */
static radio_queue_type_t ioctl80211_queue_entry_index_get[PS_MAX_Q_UTIL] = {
    RADIO_QUEUE_TYPE_BK,      /* 0 */
    RADIO_QUEUE_TYPE_BE,      /* 1 */
    RADIO_QUEUE_TYPE_VI,      /* 2 */
    RADIO_QUEUE_TYPE_VO,      /* 3 */
    RADIO_QUEUE_TYPE_NONE,    /* 4 */
    RADIO_QUEUE_TYPE_VO,      /* 5 */
    RADIO_QUEUE_TYPE_NONE,    /* 6 */
    RADIO_QUEUE_TYPE_NONE,    /* 7 */
    RADIO_QUEUE_TYPE_CAB,     /* 8 */
    RADIO_QUEUE_TYPE_BCN      /* 9 */
};


/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

struct vap_user_stats
{
    struct ieee80211_stats          vap_stats;
    struct ieee80211_mac_stats      vap_unicast_stats;
    struct ieee80211_mac_stats      vap_multicast_stats;
};

static
ioctl_status_t ioctl80211_capacity_radio_stats_get(
        radio_entry_t              *radio_cfg,
        ioctl80211_capacity_data_t *capacity_result)
{
    int32_t                         rc;

    char                           *args[IOCTL80211_IFNAME_ARG_QTY];
    ioctl80211_interface_t         *interface = NULL;
    ioctl80211_interfaces_t         interfaces;
    uint32_t                        interface_index;

    struct ifreq                    if_req;
    struct vap_user_stats           vap_stats;
    struct ieee80211_mac_stats     *vap_stats_ucast;
    struct ieee80211_mac_stats     *vap_stats_mcast;

    if (NULL == capacity_result)
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

        /* On one radio there could be multiple wireless interfaces - VAP's.
           The VAP stats seems to hold the values that we are interested in
           therefore sum all active VAP interfaces and get RADIO stats

           /proc/net/dev are network stats - essid stats?
         */
        memset (&vap_stats, 0, sizeof(vap_stats));

        memset (&if_req, 0, sizeof(if_req));
        strncpy(if_req.ifr_name, interface->ifname, sizeof(if_req.ifr_name));
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
                "Processing %s capacity for "
                " (Failed to get stats '%s')",
                radio_get_name_from_type(radio_cfg->type),
                strerror(errno));
            return IOCTL_STATUS_ERROR;
        }

        /* ieee80211_stats  has even number of 32 elements
           and since ieee80211_mac_stats has 64 bit elements
           the compiler shifts the ucast for */
        vap_stats_ucast = (struct ieee80211_mac_stats*)
#if 0
            (((unsigned char *)&vap_stats.vap_unicast_stats));
#else
            (((unsigned char *)&vap_stats.vap_unicast_stats) - sizeof(uint32_t));
#endif
        vap_stats_mcast = (struct ieee80211_mac_stats*)
#if 0
            (((unsigned char *)&vap_stats.vap_multicast_stats));
#else
            (((unsigned char *)&vap_stats.vap_multicast_stats) - sizeof(uint32_t));
#endif


        capacity_result->bytes_tx += 
            vap_stats_ucast->ims_tx_data_bytes + vap_stats_mcast->ims_tx_data_bytes;
    }

    LOG(TRACE,
        "Parsed %s capacity stats bytes %"PRIu64"",
        radio_get_name_from_type(radio_cfg->type),
        capacity_result->bytes_tx);

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_capacity_survey_stats_get(
        radio_entry_t              *radio_cfg,
        ioctl80211_capacity_data_t *capacity_result)
{
    ioctl_status_t                  status;
    ioctl80211_survey_data_t        results;

    /* Set buffer and callback function to be called after results are ready */
    memset(&results, 0, sizeof (results));
    status =
        ioctl80211_survey_results_get(
                radio_cfg,
                &radio_cfg->chan,
                1,
                RADIO_SCAN_TYPE_ONCHAN,
                &results);
    if (IOCTL_STATUS_OK != status) {
        return IOCTL_STATUS_ERROR;
    }

    capacity_result->chan_active = results.data.u.survey_bss.get.total;
    capacity_result->chan_tx = results.data.u.survey_bss.get.tx;

    LOG(TRACE,
        "Parsed %s capacity stats survey active %"PRIu64" tx %"PRIu64"",
        radio_get_name_from_type(radio_cfg->type),
        capacity_result->chan_active,
        capacity_result->chan_tx);

    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_capacity_queue_stats_get(
        radio_entry_t              *radio_cfg,
        ioctl80211_capacity_data_t *capacity_result)
{
    int32_t                         rc;

    struct iwreq                    request;
    struct ps_uapi_ioctl            ieee80211_queue_stats;

    int32_t                         queue_index = 0;
    int32_t                         txq_index = 0;

    memset (&ieee80211_queue_stats, 0, sizeof(ieee80211_queue_stats));
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = &ieee80211_queue_stats;
    request.u.data.length = PS_UAPI_IOCTL_SIZE;

    ieee80211_queue_stats.cmd = PS_UAPI_IOCTL_CMD_Q_UTIL;

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                PS_UAPI_IOCTL_SET,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing %s capacity queues "
            " (Failed to set params '%s')",
            radio_get_name_from_type(radio_cfg->type),
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                PS_UAPI_IOCTL_GET,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing %s capacity queues "
            " (Failed to get params '%s')",
            radio_get_name_from_type(radio_cfg->type),
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    capacity_result->samples =
        ieee80211_queue_stats.u.q_util.get.cnt;

    LOG(TRACE,
        "Parsed %s capacity stats queue total count %"PRIu64"",
        radio_get_name_from_type(radio_cfg->type),
        capacity_result->samples);

    for (txq_index = 0; txq_index < PS_MAX_Q_UTIL; txq_index++)
    {
        queue_index = ioctl80211_queue_entry_index_get[txq_index];

        /* Skip queues that we are not interested in */
        if (RADIO_QUEUE_TYPE_NONE == queue_index)
        {
            continue;
        }

        capacity_result->queue[queue_index] += 
            ieee80211_queue_stats.u.q_util.get.q[txq_index];

        LOG(TRACE,
            "Parsed %s capacity stats queue %s count %"PRIu64" (%d)",
            radio_get_name_from_type(radio_cfg->type),
            radio_get_queue_name_from_type(queue_index),
            capacity_result->queue[queue_index],
            txq_index);
    }

    return IOCTL_STATUS_OK;
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

ioctl_status_t ioctl80211_capacity_results_get(
        radio_entry_t               *radio_cfg,
        ioctl80211_capacity_data_t  *capacity_result)
{
    ioctl_status_t                   status;

    if (NULL == capacity_result)
    {
        return IOCTL_STATUS_ERROR;
    }

    status = 
        ioctl80211_capacity_radio_stats_get(
                radio_cfg,
                capacity_result);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    status = 
        ioctl80211_capacity_survey_stats_get(
                radio_cfg,
                capacity_result);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    status = 
        ioctl80211_capacity_queue_stats_get(
                radio_cfg,
                capacity_result);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_capacity_enable(
        radio_entry_t              *radio_cfg,
        bool                        enabled)
{
    int32_t                         rc;

    struct iwreq                    request;
    struct ps_uapi_ioctl            ioctl_stats;

    memset (&ioctl_stats, 0, sizeof(ioctl_stats));
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = &ioctl_stats;
    request.u.data.length = PS_UAPI_IOCTL_SIZE;

    ioctl_stats.cmd = PS_UAPI_IOCTL_CMD_SVC;
    ioctl_stats.u.svc.set.modify = 1;
    ioctl_stats.u.svc.set.svc = PS_UAPI_IOCTL_SVC_Q_UTIL;
    ioctl_stats.u.svc.set.enabled = enabled;

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                PS_UAPI_IOCTL_SET,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing %s capacity queues "
            " (Failed to set params '%s')",
            radio_get_name_from_type(radio_cfg->type),
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                PS_UAPI_IOCTL_GET,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing %s capacity queues "
            " (Failed to get params '%s')",
            radio_get_name_from_type(radio_cfg->type),
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    if (ioctl_stats.u.svc.set.enabled != enabled)
    {
        LOG(WARNING,
            "Parsing %s capacity queues "
            " (Failed to enable polling)",
            radio_get_name_from_type(radio_cfg->type));
    }

    return IOCTL_STATUS_OK;
}
