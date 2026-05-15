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

#ifndef OSW_DRV_SPF13_HOSTAP_LISTEN_H_INCLUDED
#define OSW_DRV_SPF13_HOSTAP_LISTEN_H_INCLUDED

typedef void osw_drv_spf13_hostap_listen_recv_fn_t(
        void *priv,
        const char *if_name,
        int level,
        const char *event_name,
        const char *event_data);

typedef void osw_drv_spf13_hostap_listen_attached_fn_t(void *priv);

struct osw_drv_spf13_hostap_listen;
typedef struct osw_drv_spf13_hostap_listen osw_drv_spf13_hostap_listen_t;

osw_drv_spf13_hostap_listen_t *osw_drv_spf13_hostap_listen_new(
        osw_drv_spf13_hostap_listen_recv_fn_t *recv_cb,
        void *recv_priv,
        osw_drv_spf13_hostap_listen_attached_fn_t *attached_cb,
        void *attached_priv);

void osw_drv_spf13_hostap_listen_drop(osw_drv_spf13_hostap_listen_t *listen);

#endif /* OSW_DRV_SPF13_HOSTAP_LISTEN_H_INCLUDED */
