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

#ifndef OSW_DRV_SPF13_REQUEST_STA_LIST_H_INCLUDED
#define OSW_DRV_SPF13_REQUEST_STA_LIST_H_INCLUDED

#include <osw_drv.h>

struct osw_drv_spf13_request_sta_list_pool;
typedef struct osw_drv_spf13_request_sta_list_pool osw_drv_spf13_request_sta_list_pool_t;

/**
 * Schedules work to request a list of stations associated with a given
 * phy and vif. Once the request is complete, the list of stations
 * is reported to the OSW driver. This manages memory resources automatically
 * by binding through `pool`.
 */
void osw_drv_spf13_request_sta_list(
        osw_drv_spf13_request_sta_list_pool_t *pool,
        const char *phy_name,
        const char *vif_name);

/**
 * Serves to manage multiple requests for station lists.
 */
osw_drv_spf13_request_sta_list_pool_t *osw_drv_spf13_request_sta_list_pool_new(
        struct osw_drv *drv,
        uint32_t nl80211_family_id);

/**
 * Drops the pool. If there were any ongoing requests they will be simply
 * dropped without notifying OSW back.
 */
void osw_drv_spf13_request_sta_list_pool_drop(osw_drv_spf13_request_sta_list_pool_t *pool);

#endif /* OSW_DRV_SPF13_REQUEST_STA_LIST_H_INCLUDED */
