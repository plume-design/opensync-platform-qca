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

#
# Collect QCA info
#
. "$LOGPULL_LIB"

collect_qcawl()
{
    collect_cmd iwconfig
    collect_cmd apstats -R

    # Collect list of STA clients
    for IF in $(cat /proc/net/wireless | sed 1,2d | grep -v wifi | cut -d : -f 1); do
        collect_cmd wlanconfig $IF list sta
        collect_cmd iwlist $IF scan last
    done

    # Collect radio dumps
    for radio in $(cat /proc/net/wireless | grep -o wifi.); do
        collect_cmd athstats -i $radio
        collect_cmd exttool --interface $radio --list
        collect_cmd exttool --interface $radio --list_chan_info
        collect_cmd exttool --interface $radio --list_chan_state
        collect_cmd cat /proc/$radio/ic_config
        collect_cmd cat /proc/$radio/dump_mbss_cache
        collect_cmd cat /proc/$radio/dump_mbss_cache_attributes
        collect_cmd cat /proc/$radio/dump_mbss_bssid_idx_pool
    done

    # Collect OL radio firmware stats
    #
    # This dmesg is intentional. txrx_fw_stats output to kernel log, so in order
    # to keep it fairly tidy, clean up all messages until now.
    collect_cmd sh -c "echo ol stats dump klog flush; dmesg -c"
    for radio in $(cat /proc/net/wireless | grep -o wifi.)
    do
        # txrx_fw_stats iwpriv is reachable via vap netdevs, not radio netdevs even though stats are radio-wise
        ifname=$(find /sys -name parent \
            | xargs grep -H $radio \
            | sed 1q \
            | xargs -n1 dirname \
            | xargs -n1 basename)
        # FIXME: wave2 hw / 10.4 supports more, e.g. for fetch requests/peer flow control
        for arg in 1 2 3 5 6 7 8; do
            # There's no guarantee that requests stats will be available in
            # kernel log after iwpriv returns hence the crude sleep.
            collect_cmd sh -c "iwpriv $ifname txrx_fw_stats $arg; sleep 1 ; dmesg -c"
        done
    done

    # Collect mcs tx/rx stats
    if [ -x "$(command -v plume)" ]; then
        for IF in $(cat /proc/net/wireless | sed 1,2d | grep -v wifi | cut -d : -f 1)
        do
            PHY=$(cat /sys/class/net/$IF/parent)
            for STA in $(wlanconfig $IF list sta | sed 1d | awk '{print $1}'); do
                collect_cmd plume $PHY peer_tx_stats $STA
                collect_cmd plume $PHY peer_rx_stats $STA
            done
            if iwconfig $IF | grep -q Mode:Managed; then
                BSSID=$(iwconfig $IF | awk '/Access Point/{print $NF}')
                collect_cmd plume $PHY peer_tx_stats $BSSID
                collect_cmd plume $PHY peer_rx_stats $BSSID
            fi
        done
    fi

    # Collect mcsd conifgs
    pgrep mcsd > /dev/null && collect_file /tmp/mcs.conf
}

collect_acceleration()
{
    [ -e /sys/kernel/debug/ecm/ecm_nss_ipv4 ] && collect_cmd ecm_dump.sh
    [ -e /sys/kernel/debug/ecm/ecm_sfe_ipv4 ] && collect_cmd sfe_dump
}

collect_switch()
{
    for s in $(swconfig list | grep Found: | awk '{ print $2 }'); do
        collect_cmd swconfig dev $s show
    done
}

collect_platform_qca()
{
    collect_qcawl
    collect_acceleration
    collect_switch
}

collect_platform_qca
