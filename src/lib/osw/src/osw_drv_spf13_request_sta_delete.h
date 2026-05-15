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

#ifndef OSW_DRV_SPF13_REQUEST_STA_DELETE_H_INCLUDED
#define OSW_DRV_SPF13_REQUEST_STA_DELETE_H_INCLUDED

#include "osw_drv_spf13_invalidations.h"

struct osw_drv_spf13_request_sta_delete_pool;
typedef struct osw_drv_spf13_request_sta_delete_pool osw_drv_spf13_request_sta_delete_pool_t;

osw_drv_spf13_request_sta_delete_pool_t *osw_drv_spf13_request_sta_delete_pool_new(
        osw_drv_spf13_invalidations_t *invalidations,
        uint32_t nl80211_family_id);
void osw_drv_spf13_request_sta_delete_pool_drop(osw_drv_spf13_request_sta_delete_pool_t *pool);

void osw_drv_spf13_request_sta_delete(
        osw_drv_spf13_request_sta_delete_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr);

void osw_drv_spf13_request_sta_deauth(
        osw_drv_spf13_request_sta_delete_pool_t *pool,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr);

#endif /* OSW_DRV_SPF13_REQUEST_STA_DELETE_H_INCLUDED */
