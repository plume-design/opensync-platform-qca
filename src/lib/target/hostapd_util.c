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

#include <stdio.h>

#include "os.h"
#include "log.h"
#include "kconfig.h"
#include "hostapd_util.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

#if CONFIG_HOSTAP_TIMEOUT_T_SWITCH
#define CMD_TIMEOUT "timeout -t"
#else
#define CMD_TIMEOUT "timeout"
#endif

bool hostapd_client_disconnect(const char *path, const char *interface,
                               const char *disc_type, const char *mac_str, uint8_t reason)
{
    char hostapd_cmd[512];
    bool ret = false;

    if (!is_input_shell_safe(path)
        || !is_input_shell_safe(interface)
        || !is_input_shell_safe(disc_type)
        || !is_input_shell_safe(mac_str))
    {
        return false;
    }

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
             "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s %s %s reason=%hhu",
             CMD_TIMEOUT, path, interface, interface, disc_type, mac_str, reason);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_btm_request(const char *path, const char *interface, const char *btm_req_cmd)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    if (!is_input_shell_safe(path)
        || !is_input_shell_safe(interface)
        || !is_input_shell_safe(btm_req_cmd))
    {
        return false;
    }

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s bss_tm_req %s",
            CMD_TIMEOUT, path, interface, interface, btm_req_cmd);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }


    return ret;
}

bool hostapd_rrm_set_neighbor(const char *path, const char *interface, const char *bssid, const char *nr)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    if (!is_input_shell_safe(path)
        || !is_input_shell_safe(interface)
        || !is_input_shell_safe(bssid)
        || !is_input_shell_safe(nr))
    {
        return false;
    }

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s "
            "set_neighbor %s nr=%s",
            CMD_TIMEOUT, path, interface, interface, bssid, nr);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_rrm_remove_neighbor(const char *path, const char *interface, const char *bssid)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    if (!is_input_shell_safe(path)
        || !is_input_shell_safe(interface)
        || !is_input_shell_safe(bssid))
    {
        return false;
    }

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s "
            "remove_neighbor %s ",
            CMD_TIMEOUT, path, interface, interface, bssid);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_rrm_get_neighbors(const char *path, const char *interface, char *buf, const size_t buf_len)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    if (!is_input_shell_safe(interface)) return false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s "
            "show_neighbor",
            CMD_TIMEOUT, path, interface, interface);

    ret = !cmd_buf(hostapd_cmd, buf, buf_len);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

/* To use it first check if tx=0 is supprted for your hostapd version */
bool hostapd_remove_station(const char *path, const char *interface, const char *mac_str)
{
    char hostapd_cmd[512];
    bool ret = false;

    if (!is_input_shell_safe(path)
        || !is_input_shell_safe(interface)
        || !is_input_shell_safe(mac_str))
    {
        return false;
    }

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
             /* Send frame anyway. QCA driver won't report ATH_EVENT_BSTEERING_CLIENT_DISCONNECTED when
              * tx=0. Mentioned event is handled by OWM and lack of it in this scenario can cause steering problems.
              */
             "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s deauthenticate %s \"reason=1\"",
             CMD_TIMEOUT, path, interface, interface, mac_str);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}
