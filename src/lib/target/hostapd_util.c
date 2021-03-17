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

bool hostapd_client_disconnect(const char *path, const char *interface, const
                               const char *disc_type, const char *mac_str, uint8_t reason)
{
    char hostapd_cmd[512];
    bool ret = false;

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

static const char *hostapd_cli_cmd(const char *interface)
{
    /* This is dirty hack, it shouldnt be based on intf names */
    if (strstr(interface, "bhaul-sta"))
        return "wpa_cli";
    else
        return "hostapd_cli";
}

static const char *hostapd_cli_dir(const char *interface)
{
    /* This is dirty hack, it shouldnt be based on intf names */
    if (strstr(interface, "bhaul-sta"))
        return "wpa_supplicant";
    else
        return "hostapd";
}

const char *
hostapd_dpp_conf_role(const char *conf)
{
    if (!strcmp(conf, "sta-dpp-sae")) return "sta-sae-dpp";
    if (!strcmp(conf, "sta-dpp-psk-sae")) return "sta-psk-sae-dpp";
    if (!strcmp(conf, "ap-dpp-sae")) return "ap-sae-dpp";
    if (!strcmp(conf, "ap-dpp-psk-sae")) return "ap-psk-sae-dpp";
    return conf;
}

bool hostapd_dpp_stop(const char *path,
                      const char *interface,
                      const char *command,
                      const char *conf_num,
                      int timeout_seconds)
{
    const char *cmd = hostapd_cli_cmd(interface);
    const char *dir = hostapd_cli_dir(interface);
    char    hostapd_cmd[1024];
    bool    ret = false;

    if (!strcmp(command, "dpp_bootstrap_remove") || !strcmp(command, "dpp_configurator_remove"))
    {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "%s %s ",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface, command, conf_num);
    }
    else if (!strcmp(command, "dpp_stop_listen") || !strcmp(command, "dpp_stop_chirp"))
    {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "%s ",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface, command);
    }

    ret = cmd_log(hostapd_cmd);
    if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
        return false;
    }

    return true;
}

bool hostapd_dpp_add(const char *path,
                     const char *interface,
                     const char *command,
                     const char *value,
                     const char *curve,
                     int timeout_seconds)
{
    const char *cmd = hostapd_cli_cmd(interface);
    const char *dir = hostapd_cli_dir(interface);
    const char *type;
    char    hostapd_cmd[1024];
    bool    ret = false;

    if (!strcmp(command, "dpp_configurator_add") || !strcmp(command, "dpp_bootstrap_gen"))
    {
        type = strcmp(command, "dpp_bootstrap_gen") ? "" : " type=qrcode";
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "%s curve=%s key=%s%s",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface, command, curve, value, type);
    }
    else if (!strcmp(command, "dpp_qr_code"))
    {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "%s \"%s\"",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface, command, value);
    }

    ret = cmd_log(hostapd_cmd);
    if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
        return false;
    }

    return true;
}

bool hostapd_dpp_auth_init(const char *path,
                           const char *interface,
                           const char *configurator_conf_role,
                           const char *configurator_conf_ssid_hex,
                           const char *configurator_conf_psk_hex,
                           int bi_id,
                           int timeout_seconds)
{
    const char *cmd = hostapd_cli_cmd(interface);
    const char *dir = hostapd_cli_dir(interface);
    char    hostapd_cmd[1024];
    bool    ret = false;

    configurator_conf_role = hostapd_dpp_conf_role(configurator_conf_role);

    if (!strcmp(configurator_conf_psk_hex, "")) {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "dpp_auth_init peer=%d conf=%s ssid=%s configurator=1",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface, bi_id, configurator_conf_role, configurator_conf_ssid_hex);
    }
    else {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "dpp_auth_init peer=%d conf=%s ssid=%s pass=%s configurator=1",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface, bi_id, configurator_conf_role, configurator_conf_ssid_hex, configurator_conf_psk_hex);
    }

    ret = cmd_log(hostapd_cmd);
    if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
        return false;
    }

    return true;
}

bool hostapd_dpp_chirp_or_listen(const char *path,
                                 const char *interface,
                                 const char *command,
                                 int freq,
                                 int bi_id,
                                 int timeout_seconds)
{
    const char *cmd = hostapd_cli_cmd(interface);
    const char *dir = hostapd_cli_dir(interface);
    char    hostapd_cmd[1024];
    bool    ret = false;

    if (!strcmp(command, "dpp_chirp"))
    {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "%s own=%d iter=2",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface, command, bi_id);
    }
    else if (!strcmp(command, "dpp_listen"))
    {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "%s %d",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface, command, freq);
    }

    ret = cmd_log(hostapd_cmd);
    if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
        return false;
    }

    return true;
}

bool hostapd_dpp_set_configurator_params(const char *path,
                                         const char *interface,
                                         const char *configurator_conf_role,
                                         const char *configurator_conf_ssid_hex,
                                         const char *configurator_conf_psk_hex,
                                         int timeout_seconds)
{
    const char *cmd = hostapd_cli_cmd(interface);
    const char *dir = hostapd_cli_dir(interface);
    char    hostapd_cmd[1024];
    bool    ret = false;

    configurator_conf_role = hostapd_dpp_conf_role(configurator_conf_role);

    if (!strcmp(configurator_conf_psk_hex, "")) {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "raw SET dpp_configurator_params conf=%s ssid=%s configurator=1",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface,
            configurator_conf_role, configurator_conf_ssid_hex);
    }
    else {
        snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s %d %s -p %s/%s-$(cat /sys/class/net/%s/parent) -i %s "
            "raw SET dpp_configurator_params conf=%s ssid=%s pass=%s configurator=1",
            CMD_TIMEOUT, timeout_seconds, cmd, path, dir, interface, interface,
            configurator_conf_role, configurator_conf_ssid_hex, configurator_conf_psk_hex);
    }


    ret = cmd_log(hostapd_cmd);
    if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
        return false;
    }

    return true;
}
