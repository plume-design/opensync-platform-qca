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
#   IPQ807X_AP_HK09 libraries overrides
#
####################### INFORMATION SECTION - STOP ############################

echo "${FUT_TOPDIR}/shell/lib/override/ipq807x_ap_hk09_lib_override.sh sourced"

####################### UNIT OVERRIDE SECTION - START #########################

###############################################################################
# DESCRIPTION:
#   Function initializes device for use in FUT.
#   It disables watchdog to prevent the device from rebooting.
#   It stops healthcheck service to prevent the device from rebooting.
#   It calls a function that instructs CM to prevent the device from rebooting.
#   It stops all managers.
# INPUT PARAMETER(S):
#   None.
# RETURNS:
#   Last exit status.
# USAGE EXAMPLE(S):
#   device_init
###############################################################################
device_init()
{
    stop_managers &&
        log -deb "ipq807x_ap_hk09_lib_override:device_init - Managers stopped - Success" ||
        raise "FAIL: stop_managers - Could not stop managers" -l "ipq807x_ap_hk09_lib_override:device_init" -ds

    stop_healthcheck &&
        log -deb "ipq807x_ap_hk09_lib_override:device_init - Healthcheck stopped - Success" ||
        raise "FAIL: stop_healthcheck - Could not stop healthcheck" -l "ipq807x_ap_hk09_lib_override:device_init" -ds

    disable_fatal_state_cm &&
        log -deb "ipq807x_ap_hk09_lib_override:device_init - CM fatal state disabled - Success" ||
        raise "FAIL: disable_fatal_state_cm - Could not disable CM fatal state" -l "ipq807x_ap_hk09_lib_override:device_init" -ds

    return $?
}

###############################################################################
# DESCRIPTION:
#   Function echoes actual chainmask of the radio. Actual chainmask info
#   is stored in the higher nibble.
# INPUT PARAMETER(S):
#   $1  chainmask of the radio (int, required)
#   $2  Frequency band of the radio interface (string, required)
# ECHOES:
#   Actual chainmask of the radio.
# USAGE EXAMPLE(S):
#   get_actual_chainmask 15 5GU
###############################################################################
get_actual_chainmask()
{
    local NARGS=2
    [ $# -lt ${NARGS} ] &&
        raise "Requires at least '${NARGS}' input argument(s)" -arg
    chainmask=${1}
    freq_band=${2}

    if [ "${freq_band}" == "5G" ]; then
        actual_chainmask=$((${chainmask} << 4))
        echo "${actual_chainmask}"
    else
        echo "${chainmask}"
    fi
}

####################### UNIT OVERRIDE SECTION - STOP ##########################
