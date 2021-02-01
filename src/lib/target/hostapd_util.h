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

#ifndef HOSTAPD_UTIL_H_INCLUDED
#define HOSTAPD_UTIL_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#define HOSTAPD_CONTROL_PATH_DEFAULT "/var/run"

bool hostapd_client_disconnect(const char *path, const char *interface, const char *disc_type,
                               const char *mac_str, uint8_t reason);
bool hostapd_btm_request(const char *path, const char *interface, const char *btm_req_cmd);
bool hostapd_rrm_set_neighbor(const char *path, const char *interface, const char *bssid, const char *nr);
bool hostapd_rrm_remove_neighbor(const char *path, const char *interface, const char *bssid);

bool hostapd_dpp_stop(const char *path, const char *interface, const char *command, const char *conf_num, int timeout_seconds);
bool hostapd_dpp_add(const char *path, const char *interface, const char *command, const char *value, const char *curve, int timeout_seconds);
bool hostapd_dpp_auth_init(const char *path, const char *interface, const char *configurator_conf_role, const char *configurator_conf_ssid_hex, const char *configurator_conf_psk_hex, int bi_id, int timeout_seconds);
bool hostapd_dpp_chirp_or_listen(const char *path, const char *interface, const char *command, int freq, int bi_id, int timeout_seconds);
bool hostapd_dpp_set_configurator_params(const char *path, const char *interface, const char *configurator_conf_role, const char *configurator_conf_ssid_hex, const char *configurator_conf_psk_hex, int timeout_seconds);

#endif /* HOSTAPD_UTIL_H_INCLUDED */
