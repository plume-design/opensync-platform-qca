#!/bin/sh
#
# Collect QCA info
#
. "$LOGPULL_LIB"

collect_qca_wifistats()
{
    for radio in $(cat /proc/net/wireless | grep -o wifi.)
    do
        # various wlan stats
        # wifistats wifiX 1: Transmit Stats
        # wifistats wifiX 2: Receive Stats
        # wifistats wifiX 3: Transmit HardwareQ Stats
        # wifistats wifiX 5: Error Stats / HW WAR stats
        # wifistats wifiX 6: TQM Stats (PDEV level)
        # wifistats wifiX 8: Transmit DE Stats
        # wifistats wifiX 9: Transmit Rate Stats
        # wifistats wifiX 9 1: 11be DL OFDMA Rate Stats
        # wifistats wifiX 10: Receive Rate Stats
        # wifistats wifiX 12: Transmit Selfgen Stats
        # wifistats wifiX 19: CCA Stats
        # wifistats wifiX 26: RX 11ax UL OFDMA
        # wifistats wifiX 26 1: RX 11be UL OFDMA
        # wifistats wifiX 40: PER stats
        # wifistats wifiX 41: AST entries
        for arg in 1 2 3 5 6 8 9 '9 1' 10 12 19 26 '26 1' 40 41; do
            collect_cmd wifistats $radio $arg
        done
    done
}

collect_qca_wifistats
