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

#ifndef OSW_DRV_SPF13_HOSTAP_PATH_H_INCLUDED
#define OSW_DRV_SPF13_HOSTAP_PATH_H_INCLUDED

const char *osw_drv_spf13_hostap_path_hostapd_global(void);

const char *osw_drv_spf13_hostap_path_supplicant_global(void);

char *osw_drv_spf13_hostap_path_hostapd_config(const char *vif_name);

char *osw_drv_spf13_hostap_path_hostapd_pskfile(const char *vif_name);

char *osw_drv_spf13_hostap_path_hostapd_rxkh(const char *vif_name);

char *osw_drv_spf13_hostap_path_supplicant_config(const char *vif_name);

char *osw_drv_spf13_hostap_path_hostapd_ctrl_base(const char *phy_name);

char *osw_drv_spf13_hostap_path_supplicant_ctrl_base(void);

char *osw_drv_spf13_hostap_path_hostapd_ctrl_bss(const char *phy_name, const char *vif_name);

char *osw_drv_spf13_hostap_path_supplicant_ctrl_bss(const char *nedev_name);

#endif /* OSW_DRV_SPF13_HOSTAP_PATH_H_INCLUDED */
