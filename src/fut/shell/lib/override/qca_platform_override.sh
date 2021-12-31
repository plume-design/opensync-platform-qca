#!/bin/sh

# Copyright (c) 2015, Plume Design Inc. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#    3. Neither the name of the Plume Design Inc. nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


####################### INFORMATION SECTION - START ###########################
#
#   Qualcomm (QCA) platform overrides
#
####################### INFORMATION SECTION - STOP ############################

echo "${FUT_TOPDIR}/shell/lib/override/qca_platform_override.sh sourced"

###############################################################################
# DESCRIPTION:
#   Function starts qca-hostapd.
#   Uses qca-hostapd tool.
# INPUT PARAMETER(S):
#   None.
# RETURNS:
#   None.
# USAGE EXAMPLE(S):
#   start_qca_hostapd
###############################################################################
start_qca_hostapd()
{
    log -deb "qca_platform_override:start_qca_hostapd - Starting qca-hostapd"
    /etc/init.d/qca-hostapd boot
    sleep 2
}

###############################################################################
# DESCRIPTION:
#   Function starts qca-wpa-supplicant.
#   Uses qca-wpa-supplicant tool.
# INPUT PARAMETER(S):
#   None.
# RETURNS:
#   None.
# USAGE EXAMPLE(S):
#   start_qca_wpa_supplicant
###############################################################################
start_qca_wpa_supplicant()
{
    log -deb "qca_platform_override:start_qca_wpa_supplicant - Starting qca-wpa-supplicant"
    /etc/init.d/qca-wpa-supplicant boot
    sleep 2
}

###############################################################################
# DESCRIPTION:
#   Function starts wireless driver on a device.
#   Raises exception on fail.
# INPUT PARAMETER(S):
#   None.
# RETURNS:
#   None.
#   See DESCRIPTION.
# USAGE EXAMPLE(S):
#   start_wireless_driver
###############################################################################
start_wireless_driver()
{
    start_qca_hostapd &&
        log -deb "qca_platform_override:start_wireless_driver - start_qca_hostapd - Success" ||
        raise "FAIL: start_qca_hostapd - Could not start qca host" -l "qca_platform_override:start_wireless_driver" -ds
    start_qca_wpa_supplicant &&
        log -deb "qca_platform_override:start_wireless_driver - start_qca_wpa_supplicant - Success" ||
        raise "FAIL: start_qca_wpa_supplicant - Could not start wpa supplicant" -l "qca_platform_override:start_wireless_driver" -ds
}

###############################################################################
# DESCRIPTION:
#   Function retrieves interface regulatory domain.
# INPUT PARAMETER(S):
#   $1  Physical Radio interface name for which to retrieve regulatory domain (string, required)
# ECHOES:
#   Interface regulatory domain - defaults to US if any failure occurs
# NOTE:
#   Function first checks Wifi_Radio_State interface 'country' field, if it is not populated, it retrieves
#   Wifi_Radio_State 'hw_params' field and looks for 'reg_domain' entry
# USAGE EXAMPLE(S):
#   get_iface_regulatory_domain wifi0
###############################################################################
get_iface_regulatory_domain()
{
    local NARGS=1
    [ $# -ne ${NARGS} ] &&
        raise "wm2_lib:get_iface_regulatory_domain requires ${NARGS} input argument(s), $# given" -arg
    # shellcheck disable=SC2034
    if_name="${1}"
    country_found=1
    country=$(get_ovsdb_entry_value Wifi_Radio_State country -w if_name "${if_name}")
    if [ "${country}" == "[\"set\",[]]" ]; then
        log -deb "wm2_lib:get_iface_regulatory_domain - Country is not set in Wifi_Radio_State."
        hw_params_reg_domain=$(get_ovsdb_entry_value Wifi_Radio_State hw_params -w if_name "${if_name}" -json_value reg_domain)
        log -deb "wm2_lib:get_iface_regulatory_domain - Trying to acquire country region trough hw_params: ${hw_params_reg_domain}"
        # 58 (3a hex) US | 55 (37 hex) EU
        if [ ${?} == 0 ]; then
            if [ ${hw_params_reg_domain} == '"58"' ]; then
                country='US'
            elif [ ${hw_params_reg_domain} == '"55"' ]; then
                country='EU'
            else
                log -deb "wm2_lib:get_iface_regulatory_domain - Failed to retrieve device regulatory domain. Defaulting to US regulatory rules!"
                country='US'
            fi
        else
            log -deb "wm2_lib:get_iface_regulatory_domain - Failed to retrieve device regulatory domain. Defaulting to US regulatory rules!"
            country='US'
        fi
        country_found=0
    else
        country_found=0
    fi
    if [ "${country_found}" == 1 ];then
        log -deb "wm2_lib:get_iface_regulatory_domain - Failed to retrieve device regulatory domain. Defaulting to US regulatory rules!"
        country='US'
    fi
    echo "${country}"
}

###############################################################################
# DESCRIPTION:
#   Function checks if country is applied at OS - LEVEL2.
#   Uses iwpriv to get Tx Power info.
#   Provide override function if iwpriv not available on device.
#   Raises exception on fail.
# INPUT PARAMETER(S):
#   $1  Country (string, required)
#   $2  Interface name (string, required)
# RETURNS:
#   0   Country is as expected.
#   See DESCRIPTION.
# USAGE EXAMPLE(S):
#   check_country_at_os_level US <IF_NAME>
###############################################################################
check_country_at_os_level()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "qca_platform_override:check_country_at_os_level requires ${NARGS} input argument(s), $# given" -arg
    wm2_country=$1
    wm2_if_name=$2

    log -deb "qca_platform_override:check_country_at_os_level - Checking 'country' at OS - LEVEL2"
    wait_for_function_response 0 "iwpriv $wm2_if_name getCountryID | grep -F getCountryID:$wm2_country"
    if [ $? = 0 ]; then
        log -deb "qca_platform_override:check_country_at_os_level - Country '$wm2_country' is set at OS - LEVEL2"
        return 0
    else
        raise "FAIL: Country '$wm2_country' is not set at OS - LEVEL2" -l "qca_platform_override:check_country_at_os_level" -tc
    fi
}

###############################################################################
# DESCRIPTION:
#   Function simulates DFS (Dynamic Frequency Shift) radar event on interface.
# INPUT PARAMETER(S):
#   $1  channel (int, required)
# RETURNS:
#   0   Simulation was a success.
# USAGE EXAMPLE(S):
#   simulate_dfs_radar <IF_NAME>
###############################################################################
simulate_dfs_radar()
{
    local NARGS=1
    [ $# -ne ${NARGS} ] &&
        raise "qca_platform_override:simulate_dfs_radar requires ${NARGS} input argument(s), $# given" -arg
    wm2_if_name=$1

    log -deb "qca_platform_override:simulate_dfs_radar - Triggering DFS radar event on ${wm2_if_name}"
    wait_for_function_response 0 "radartool -i $wm2_if_name bangradar"
    if [ $? = 0 ]; then
        log -deb "qca_platform_override:simulate_dfs_radar - DFS event: $wm2_if_name simulation was SUCCESSFUL"
        return 0
    else
        log -err "qca_platform_override:simulate_dfs_radar - DFS event: $wm2_if_name simulation was UNSUCCESSFUL"
    fi
}

###############################################################################
# DESCRIPTION:
#   Function returns Tx Power set at OS - LEVEL2.
#   Uses iwconfig to get Tx Power info from VIF interface.
# INPUT PARAMETER(S):
#   $1  VIF interface name (required)
# RETURNS:
#   0   on successful Tx Power retrieval, fails otherwise
# ECHOES:
#   Tx Power from OS
# USAGE EXAMPLE(S):
#   get_tx_power_from_os home-ap-24
###############################################################################
get_tx_power_from_os()
{
    local NARGS=1
    [ $# -ne ${NARGS} ] &&
        raise "qca_platform_override:get_tx_power_from_os requires ${NARGS} input argument(s), $# given" -arg
    wm2_vif_if_name=$1

    iwconfig $wm2_vif_if_name | grep "Tx-Power" | awk '{print $4}' | awk -F '=' '{print $2}'
}

###############################################################################
# DESCRIPTION:
#   Function checks if Tx Chainmask is applied at OS - LEVEL2.
#   Uses iwconfig to get Tx Chainmask info.
# INPUT PARAMETER(S):
#   $1  Tx Chainmask (int, required)
#   $2  Interface name (string, required)
# RETURNS:
#   0   Tx Chainmask is as expected.
# USAGE EXAMPLE(S):
#   check_tx_chainmask_at_os_level 5 wifi0
###############################################################################
check_tx_chainmask_at_os_level()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "qca_platform_override:check_tx_chainmask_at_os_level requires ${NARGS} input argument(s), $# given" -arg
    wm2_tx_chainmask=$1
    wm2_if_name=$2

    log -deb "qca_platform_override:check_tx_chainmask_at_os_level - Checking Tx Chainmask at OS - LEVEL2"
    wait_for_function_response 0 "iwpriv $wm2_if_name get_txchainsoft | grep -F get_txchainsoft:$wm2_tx_chainmask"
    if [ $? = 0 ]; then
        log -deb "qca_platform_override:check_tx_chainmask_at_os_level - Tx Chainmask $wm2_tx_chainmask is set at OS - LEVEL2"
        return 0
    else
        wait_for_function_response 0 "iwpriv $wm2_if_name get_txchainmask | grep -F get_txchainmask:$wm2_tx_chainmask"
        if [ $? = 0 ]; then
            log -deb "qca_platform_override:check_tx_chainmask_at_os_level - Tx Chainmask '$wm2_tx_chainmask' is set at OS - LEVEL2 - Success"
            return 0
        else
            raise "FAIL: Tx Chainmask '$wm2_tx_chainmask' is not set at OS - LEVEL2" -l "qca_platform_override:check_tx_chainmask_at_os_level" -tc
        fi
    fi
}

###############################################################################
# DESCRIPTION:
#   Function checks if Beacon interval is applied at OS - LEVEL2.
#   Raises exception on fail.
# INPUT PARAMETER(S):
#   $1  Beacon interval (int, required)
#   $2  Interface name (string, required)
# RETURNS:
#   0   Beacon interval is as expected.
#   See DESCRIPTION.
# USAGE EXAMPLE(S):
#   check_beacon_interval_at_os_level 600 home-ap-U50
###############################################################################
check_beacon_interval_at_os_level()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "qca_platform_override:check_beacon_interval_at_os_level requires ${NARGS} input argument(s), $# given" -arg
    wm2_bcn_int=$1
    wm2_vif_if_name=$2

    log -deb "qca_platform_override:check_beacon_interval_at_os_level - Checking Beacon interval at OS - LEVEL2"
    wait_for_function_response 0 "iwpriv $wm2_vif_if_name get_bintval | grep -F get_bintval:$wm2_bcn_int"
    if [ $? = 0 ]; then
        log -deb "qca_platform_override:check_beacon_interval_at_os_level - Beacon interval '$wm2_bcn_int' for '$wm2_vif_if_name' is set at OS - LEVEL2 - Success"
        return 0
    else
        raise "FAIL: Beacon interval '$wm2_bcn_int' for '$wm2_vif_if_name' is not set at OS - LEVEL2" -l "qca_platform_override:check_beacon_interval_at_os_level" -tc
    fi
}

###############################################################################
# DESCRIPTION:
#   Function returns channel set at OS - LEVEL2.
# INPUT PARAMETER(S):
#   $1  VIF interface name (string, required)
# RETURNS:
#   0   on successful channel retrieval, fails otherwise
# ECHOES:
#   Channel from OS
# USAGE EXAMPLE(S):
#   get_channel_from_os home-ap-24
###############################################################################
get_channel_from_os()
{
    local NARGS=1
    [ $# -ne ${NARGS} ] &&
        raise "qca_platform_override:get_channel_from_os requires ${NARGS} input argument(s), $# given" -arg
    wm2_vif_if_name=$1

    iwlist $wm2_vif_if_name channel | grep -F "Current" | grep -F "Channel" | sed 's/)//g' | awk '{ print $5 }'
}

###############################################################################
# DESCRIPTION:
#   Function returns HT mode set at OS - LEVEL2.
# INPUT PARAMETER(S):
#   $1  vif_if_name (string, required)
#   $2  channel (not used, but still required, do not optimize)
# RETURNS:
#   0   on successful channel retrieval, fails otherwise
# ECHOES:
#   HT mode from OS in format: HT20, HT40 (examples)
# USAGE EXAMPLE(S):
#   get_ht_mode_from_os home-ap-24 1
###############################################################################
get_ht_mode_from_os()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "qca_platform_override:get_ht_mode_from_os requires ${NARGS} input argument(s), $# given" -arg
    wm2_vif_if_name=$1
    wm2_channel=$2

    iwpriv $wm2_vif_if_name get_mode | sed 's/HT/ HT/g' | sed 's/PLUS$//' | sed 's/MINUS$//' | awk '{ print $3 }'
}

###############################################################################
# DESCRIPTION:
#   Function checks vlan interface existence at OS - LEVEL2.
# INPUT PARAMETER(S):
#   $1  parent_ifname (string, required)
#   $2  vlan_id (int, required)
# RETURNS:
#   0   On success.
# USAGE EXAMPLE(S):
#  check_vlan_iface eth0 100
###############################################################################
check_vlan_iface()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "qca_platform_override:check_vlan_iface requires ${NARGS} input argument(s), $# given" -arg
    parent_ifname=$1
    vlan_id=$2

    if_name="$parent_ifname.$vlan_id"
    vlan_pid="/proc/net/vlan/${if_name}"

    log "qca_platform_override:check_vlan_iface: Checking for '${vlan_pid}' existence - LEVEL2"
    wait_for_function_response 0 "[ -f ${vlan_pid} ]" &&
        log "qca_platform_override:check_vlan_iface: LEVEL2 - PID '${vlan_pid}' is runinng - Success" ||
        raise "FAIL: LEVEL2 - PID ${vlan_pid} is NOT running" -l "qca_platform_override:check_vlan_iface" -tc

    log "qca_platform_override:check_vlan_iface: Output PID ${vlan_pid} info:"
    cat "${vlan_pid}"

    log "qca_platform_override:check_vlan_iface: Validating PID VLAN config - vlan_id == ${vlan_id} - LEVEL2"
    wait_for_function_response 0 "cat "${vlan_pid}" | grep 'VID: ${vlan_id}'" &&
        log "qca_platform_override:check_vlan_iface: LEVEL2 - VID is set to 100 - Success" ||
        raise "FAIL: LEVEL2 - VID is not set" -l "qca_platform_override:check_vlan_iface" -tc

    log "qca_platform_override:check_vlan_iface: Check parent device for VLAN - LEVEL2"
    wait_for_function_response 0 "cat "${vlan_pid}" | grep 'Device: ${parent_ifname}'" &&
        log "qca_platform_override:check_vlan_iface: LEVEL2 - Device is set to '${parent_ifname}' - Success" ||
        raise "FAIL: LEVEL2 - Device is not set to '${parent_ifname}'" -l "qca_platform_override:check_vlan_iface" -tc

    return 0
}

###############################################################################
# DESCRIPTION:
#   Function checks for CSA(Channel Switch Announcement) msg on the LEAF device
#   sent by GW on channel change.
# INPUT PARAMETER(S):
#   $1  mac address of GW (string, required)
#   $2  CSA channel GW switches to (int, required)
#   $3  HT mode of the channel (string, required)
# RETURNS:
#   0   CSA message is found in LEAF device var logs, fail otherwise.
# USAGE EXAMPLE(S):
#   check_sta_send_csa_message 1A:2B:3C:4D:5E:6F 6 HT20
###############################################################################
check_sta_send_csa_message()
{
    local NARGS=3
    [ $# -ne ${NARGS} ] &&
        raise "qca_platform_override:check_sta_send_csa_message requires ${NARGS} input argument(s), $# given" -arg
    gw_vif_mac=$1
    gw_csa_channel=$2
    ht_mode=$3

    # Example log:
    # Mar 18 10:29:06 WM[19842]: <INFO> TARGET: wifi0: csa rx to bssid d2:b4:f7:f0:23:26 chan 6 width 0MHz sec 0 cfreq2 0 valid 1 supported 1
    wm_csa_log_grep="$LOGREAD | grep -i 'csa' | grep -i '${gw_vif_mac} chan ${gw_csa_channel}'"
    wait_for_function_response 0 "${wm_csa_log_grep}" 30 &&
        log "qca_platform_override:check_sta_send_csa_message : 'csa completed' message found in logs for channel:${gw_csa_channel} with HT mode: ${ht_mode} - Success" ||
        raise "FAIL: Failed to find 'csa completed' message in logs for channel: ${gw_csa_channel} with HT mode: ${ht_mode}" -l "qca_platform_override:check_sta_send_csa_message" -tc
    return 0
}

####################### Qualcomm(QCA) PLATFORM OVERRIDE SECTION - STOP #########################


####################### Qualcomm(QCA) UPGRADE OVERRIDE SECTION - START #########################

###############################################################################
# DESCRIPTION:
#   Function echoes upgrade manager's numerical code of identifier.
#   Raises exception if identifier not found.
# INPUT PARAMETER(S):
#   $1  upgrade_identifier (string) (required)
# RETURNS:
#   Echoes code.
#   See DESCRIPTION.
# USAGE EXAMPLE(S):
#   get_um_code UPG_ERR_DL_FW
#   get_um_code UPG_STS_FW_DL_END
###############################################################################
get_um_code()
{
    local NARGS=1
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:get_um_code requires ${NARGS} input argument(s), $# given" -arg
    upgrade_identifier=$1

    case "$upgrade_identifier" in
        "UPG_ERR_ARGS")
            echo  "-1"
            ;;
        "UPG_ERR_URL")
            echo  "-3"
            ;;
        "UPG_ERR_DL_FW")
            echo  "-4"
            ;;
        "UPG_ERR_DL_MD5")
            echo  "-5"
            ;;
        "UPG_ERR_MD5_FAIL")
            echo  "-6"
            ;;
        "UPG_ERR_IMG_FAIL")
            echo  "-7"
            ;;
        "UPG_ERR_FL_ERASE")
            echo  "-8"
            ;;
        # WAR specific for QCA platforms
        "UPG_ERR_FL_WRITE")
            echo  "-7"
            ;;
        "UPG_ERR_FL_CHECK")
            echo  "-10"
            ;;
        "UPG_ERR_BC_SET")
            echo  "-11"
            ;;
        "UPG_ERR_APPLY")
            echo  "-12"
            ;;
        "UPG_ERR_BC_ERASE")
            echo  "-14"
            ;;
        "UPG_ERR_SU_RUN ")
            echo  "-15"
            ;;
        "UPG_ERR_DL_NOFREE")
            echo  "-16"
            ;;
        "UPG_STS_FW_DL_START")
            echo  "10"
            ;;
        "UPG_STS_FW_DL_END")
            echo  "11"
            ;;
        "UPG_STS_FW_WR_START")
            echo  "20"
            ;;
        "UPG_STS_FW_WR_END")
            echo  "21"
            ;;
        "UPG_STS_FW_BC_START")
            echo  "30"
            ;;
        "UPG_STS_FW_BC_END")
            echo  "31"
            ;;
        *)
            raise "FAIL: Unknown upgrade_identifier {given:=$upgrade_identifier}" -l "bcm_platform_override:get_um_code" -arg
            ;;
    esac
}

####################### Qualcomm(QCA) UPGRADE OVERRIDE SECTION - STOP ##########################
