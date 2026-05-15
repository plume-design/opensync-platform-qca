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

#ifndef OSW_DRV_SPF13_INVALIDATIONS_H
#define OSW_DRV_SPF13_INVALIDATIONS_H

/**
 * This is intended to be used instead of
 * osw_drv_report_XXX_changed(). This allows
 * pausing/unpausing reports. The main use-case is to
 * prevent immediate changed reports during things like
 * reconfiguration.
 */

#include <osw_drv.h>
#include <osw_types.h>

struct osw_drv_spf13_invalidations;
struct osw_drv_spf13_invalidations_lock;
typedef struct osw_drv_spf13_invalidations osw_drv_spf13_invalidations_t;
typedef struct osw_drv_spf13_invalidations_lock osw_drv_spf13_invalidations_lock_t;

osw_drv_spf13_invalidations_t *osw_drv_spf13_invalidations_new(struct osw_drv *drv);

void osw_drv_spf13_invalidations_drop(osw_drv_spf13_invalidations_t *invalidations);

void osw_drv_spf13_invalidations_all(osw_drv_spf13_invalidations_t *invalidations);

void osw_drv_spf13_invalidations_phy(osw_drv_spf13_invalidations_t *invalidations, const char *phy_name);

void osw_drv_spf13_invalidations_vif(
        osw_drv_spf13_invalidations_t *invalidations,
        const char *phy_name,
        const char *vif_name);

void osw_drv_spf13_invalidations_sta(
        osw_drv_spf13_invalidations_t *invalidations,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr);

osw_drv_spf13_invalidations_lock_t *osw_drv_spf13_invalidations_lock(osw_drv_spf13_invalidations_t *invalidations);

void osw_drv_spf13_invalidations_lock_drop(osw_drv_spf13_invalidations_lock_t *lock);

#endif /* OSW_DRV_SPF13_INVALIDATIONS_H */
