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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "log.h"

#include "ioctl80211.h"
#include "ioctl80211_device.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL
#define OSYNC_IOCTL_LIB 4

#include "osync_nl80211_11ax.h"
/******************************************************************************
 *                          DEVICE STATS
 *****************************************************************************/

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

static
ioctl_status_t ioctl80211_device_temp_get(
        radio_entry_t              *radio_cfg,
        dpp_device_temp_t          *temp)
{
    char                            buf[128];
    int                             err;

    err = readcmd(buf, sizeof(buf), 0, "cat /sys/class/net/%s/thermal/temp",
                  radio_cfg->phy_name);
    if (err) {
        LOGW("%s: readcmd() failed: %d (%s)", radio_cfg->phy_name,
                errno, strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    LOG(TRACE, "Probed get_therm %x", atoi(buf));

    temp->type = radio_cfg->type;
    temp->value = atoi(buf);

    LOG(TRACE,
            "Parsed device %s temp %d",
            radio_get_name_from_type(temp->type),
            temp->value);
    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_device_txchainmask_get(
        radio_entry_t              *radio_cfg,
        dpp_device_txchainmask_t   *txchainmask)
{
	return nl80211_device_txchainmask_get(radio_cfg, txchainmask);
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

ioctl_status_t ioctl80211_device_temp_results_get(
        radio_entry_t              *radio_cfg,
        dpp_device_temp_t          *temp)
{
    ioctl_status_t                  status;

    status =
        ioctl80211_device_temp_get(
                radio_cfg,
                temp);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_device_txchainmask_results_get(
        radio_entry_t              *radio_cfg,
        dpp_device_txchainmask_t   *txchainmask)
{
    ioctl_status_t                  status;

    status =
        ioctl80211_device_txchainmask_get(
                radio_cfg,
                txchainmask);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}
