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
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "log.h"

#include "ioctl80211.h"
#include "ioctl80211_radio.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL


/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

static void ioctl80211_radio_stats_set_iwparam(
        const char *ifname,
        const char *iwpname,
        unsigned int arg)
{
    struct iwreq request;
    int rc;

    memset(&request, 0, sizeof(request));

    rc = ioctl80211_get_priv_ioctl(ifname, iwpname, &request.u.mode);
    if (!rc)
        return;

    request.u.data.length = 1;
    memcpy(request.u.name + sizeof(arg), &arg, sizeof(arg));
    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                ifname,
                IEEE80211_IOCTL_SETPARAM,
                &request);
    if (rc) {
        LOG(WARNING, "%s: iwpriv '%s' (0x%04x) = %d failed",
                ifname, iwpname, request.u.mode, arg);
        return;
    }

    LOG(DEBUG, "%s: iwpriv '%s' (0x%04x) = %d",
            ifname, iwpname, request.u.mode, arg);
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

ioctl_status_t ioctl80211_radio_tx_stats_enable(
        radio_entry_t              *radio_cfg,
        bool                        status)
{
    ioctl80211_radio_stats_set_iwparam(radio_cfg->phy_name, "enable_ol_stats", status ? 1 : 0);
    ioctl80211_radio_stats_set_iwparam(radio_cfg->phy_name, "disablestats", status ? 0 : 1);
    ioctl80211_radio_stats_set_iwparam(radio_cfg->phy_name, "enable_statsv2", status ? 0xf : 0);

    return IOCTL_STATUS_OK;
}

#define IOCTL80211_MIN_DWELL_TIME   10  /* ms */

ioctl_status_t ioctl80211_radio_fast_scan_enable(
        radio_entry_t              *radio_cfg,
        ifname_t                    if_name)
{
    ioctl80211_radio_stats_set_iwparam(if_name, "srssicombfix", 3);
    ioctl80211_radio_stats_set_iwparam(if_name, "suniformrssi", 1);
#ifdef QCA_10_4
    /* 10.4 has this reachable via different ioctl:
     *  - IEEE80211_IOCTL_DBGREQ
     *  - IEEE80211_DBGREQ_SCAN_REPEAT_PROBE_TIME
     */
    struct ieee80211req_athdbg      athdbg;
    struct iwreq                    iwreq;
    int32_t                         rc;

    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_SCAN_REPEAT_PROBE_TIME;
    athdbg.data.param[0] = 0;   // 0 = get
    memset(&iwreq,  0, sizeof(iwreq));
    iwreq.u.data.pointer = (void *)&athdbg;
    iwreq.u.data.length  = sizeof(athdbg);

    rc = ioctl80211_request_send(
                ioctl80211_fd_get(),
                if_name,
                IEEE80211_IOCTL_DBGREQ,
                &iwreq);
    if (rc < 0) {
        return IOCTL_STATUS_ERROR;
    }

    if (athdbg.data.param[1] == IOCTL80211_MIN_DWELL_TIME) {
        LOGD("Skip updating %s fast scanning on %s (Already configured %d)",
             radio_get_name_from_type(radio_cfg->type),
             if_name,
             IOCTL80211_MIN_DWELL_TIME);
        return IOCTL_STATUS_OK;
    }

    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_SCAN_REPEAT_PROBE_TIME;
    athdbg.data.param[0] = 1;   // 1 = set
    athdbg.data.param[1] = IOCTL80211_MIN_DWELL_TIME;
    memset(&iwreq,  0, sizeof(iwreq));
    iwreq.u.data.pointer = (void *)&athdbg;
    iwreq.u.data.length  = sizeof(athdbg);

    rc = ioctl80211_request_send(
                ioctl80211_fd_get(),
                if_name,
                IEEE80211_IOCTL_DBGREQ,
                &iwreq);
    if (rc < 0) {
        return IOCTL_STATUS_ERROR;
    }

#else
    int32_t                         rc;
    struct iwreq                    request;
    int32_t                         arg = IOCTL80211_MIN_DWELL_TIME;

    /* Ideally we should read the current status but the driver
       does not support fetching 2.4G tx stats status.
     */
    memset (&request, 0, sizeof(request));
    request.u.mode = IEEE80211_PARAM_SCAN_REPEAT_PROBE_TIME;

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                if_name,
                IEEE80211_IOCTL_GETPARAM,
                &request);
    if (0 > rc)
    {
        return IOCTL_STATUS_ERROR;
    }

    if (request.u.mode == IOCTL80211_MIN_DWELL_TIME)
    {
        LOG(DEBUG,
            "Skip updating %s fast scanning on %s (Already configured %d)",
            radio_get_name_from_type(radio_cfg->type),
            if_name,
            IOCTL80211_MIN_DWELL_TIME);
        return IOCTL_STATUS_OK;
    }

    memset (&request, 0, sizeof(request));
    request.u.mode = IEEE80211_PARAM_SCAN_REPEAT_PROBE_TIME;
    request.u.data.length = 1;
    memcpy(request.u.name + sizeof(arg), &arg, sizeof(arg));

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                if_name,
                IEEE80211_IOCTL_SETPARAM,
                &request);
    if (0 > rc)
    {
        return IOCTL_STATUS_ERROR;
    }
#endif

    LOG(DEBUG,
        "Updated %s fast scanning on %s",
        radio_get_name_from_type(radio_cfg->type),
        if_name);

    return IOCTL_STATUS_OK;
}
