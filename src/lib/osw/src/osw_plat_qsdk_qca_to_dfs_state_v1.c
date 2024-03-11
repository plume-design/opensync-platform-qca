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

#include <stdbool.h>
#include <log.h>
#include <osw_types.h>

#define EXTERNAL_USE_ONLY
#define __bool_already_defined__
#ifndef __packed
#define __packed __attribute__((packed))
#endif

#include <ieee80211_external_config.h>
#include <qcatools_lib.h>
#include <ieee80211_defines.h>

enum osw_channel_state_dfs
osw_plat_qsdk_qca_to_dfs_state(enum wlan_channel_dfs_state state)
{
    switch (state) {
        case WLAN_CH_DFS_S_INVALID:
            /* Not sure if this is correct, but.. */
            return OSW_CHANNEL_DFS_CAC_POSSIBLE;
        case WLAN_CH_DFS_S_CAC_REQ:
            return OSW_CHANNEL_DFS_CAC_POSSIBLE;
        case WLAN_CH_DFS_S_CAC_STARTED:
            return OSW_CHANNEL_DFS_CAC_IN_PROGRESS;
        case WLAN_CH_DFS_S_CAC_COMPLETED:
            return OSW_CHANNEL_DFS_CAC_COMPLETED;
        case WLAN_CH_DFS_S_NOL:
            return OSW_CHANNEL_DFS_NOL;
        case WLAN_CH_DFS_S_PRECAC_STARTED:
            return OSW_CHANNEL_DFS_CAC_IN_PROGRESS;
        case WLAN_CH_DFS_S_PRECAC_COMPLETED:
            return OSW_CHANNEL_DFS_CAC_COMPLETED;
    }
    WARN_ON(1);
    return OSW_CHANNEL_NON_DFS;
}
