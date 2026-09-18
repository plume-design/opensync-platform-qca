#!/bin/sh
#
# Collect QCA info
#
. "$LOGPULL_LIB"

collect_qcawl()
{
    collect_cmd iwconfig

    # Collect list of STA clients
    for IF in $(cat /proc/net/wireless | sed 1,2d | grep -v wifi | cut -d : -f 1); do
        collect_cmd wlanconfig $IF list sta
        collect_cmd iw dev $IF scan dump
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
            collect_cmd sh -c "cfg80211tool $ifname txrx_fw_stats $arg; sleep 1 ; dmesg -c"
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
            if iw $IF info | grep -q managed; then
		BSSID=$(iw $IF info | awk '/addr/{print $NF}')
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
    which ecm_dump.sh >/dev/null 2>&1 && collect_cmd ecm_dump.sh
    which sfe_dump >/dev/null 2>&1 && collect_cmd sfe_dump
    which ppe_dump >/dev/null 2>&1 && collect_cmd ppe_dump
    which ppe_if_map >/dev/null 2>&1 && collect_cmd ppe_if_map
}

collect_switch()
{
    for s in $(swconfig list | grep Found: | awk '{ print $2 }'); do
        collect_cmd swconfig dev $s show
    done
}

collect_wifi_fw_ramdump_flag_file()
{
    collect_file /tmp/wifi-fw-ramdump.txt
}

collect_platform_qca()
{
    collect_qcawl
    collect_acceleration
    collect_switch
    collect_wifi_fw_ramdump_flag_file
}

collect_platform_qca
