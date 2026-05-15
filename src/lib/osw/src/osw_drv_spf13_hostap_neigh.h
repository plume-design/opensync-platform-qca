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

#ifndef OSW_DRV_SPF13_HOSTAP_NEIGH_H_INCLUDED
#define OSW_DRV_SPF13_HOSTAP_NEIGH_H_INCLUDED

#include <osw_types.h>

struct osw_drv_spf13_hostap_neigh_sync;
struct osw_drv_spf13_hostap_neigh_syncer;
struct osw_drv_spf13_hostap_neigh_waiter;
typedef struct osw_drv_spf13_hostap_neigh_sync osw_drv_spf13_hostap_neigh_sync_t;
typedef struct osw_drv_spf13_hostap_neigh_syncer osw_drv_spf13_hostap_neigh_syncer_t;
typedef struct osw_drv_spf13_hostap_neigh_waiter osw_drv_spf13_hostap_neigh_waiter_t;

osw_drv_spf13_hostap_neigh_sync_t *osw_drv_spf13_hostap_neigh_sync_new(
        const char *ctrl_path,
        const struct osw_neigh_list *neigh_list,
        const struct osw_ssid *ssid,
        void (*done_cb)(void *priv),
        void *done_priv);

void osw_drv_spf13_hostap_neigh_sync_drop(osw_drv_spf13_hostap_neigh_sync_t *sync);

osw_drv_spf13_hostap_neigh_syncer_t *osw_drv_spf13_hostap_neigh_syncer_new(const char *ctrl_path);

void osw_drv_spf13_hostap_neigh_syncer_drop(osw_drv_spf13_hostap_neigh_syncer_t *syncer);

osw_drv_spf13_hostap_neigh_waiter_t *osw_drv_spf13_hostap_neigh_syncer_resync(
        osw_drv_spf13_hostap_neigh_syncer_t *syncer,
        void (*done_cb)(void *priv),
        void *done_priv);

osw_drv_spf13_hostap_neigh_waiter_t *osw_drv_spf13_hostap_neigh_syncer_set(
        osw_drv_spf13_hostap_neigh_syncer_t *syncer,
        const struct osw_ssid *ssid,
        const struct osw_neigh_list *neigh_list,
        void (*done_cb)(void *priv),
        void *done_priv);

void osw_drv_spf13_hostap_neigh_waiter_drop(osw_drv_spf13_hostap_neigh_waiter_t *waiter);

bool osw_drv_spf13_hostap_neigh_waiter_is_done(osw_drv_spf13_hostap_neigh_waiter_t *waiter);

#endif /* OSW_DRV_SPF13_HOSTAP_NEIGH_H_INCLUDED */
