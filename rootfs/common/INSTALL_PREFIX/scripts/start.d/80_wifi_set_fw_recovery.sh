#!/bin/sh

# Enable fw_recovery; this prevents an immediate reboot after a Wifi firmware
# crash. The crash will be handled by OpenSync and it will result in a reboot
# in the end, but this gives us time to collect logs and update the reboot
# status

for wifidev in /sys/class/net/wifi?
do
    wifi=$(basename $wifidev)
    cfg80211tool $wifi 2>&1 | grep -q set_fw_recovery || continue
    cfg80211tool $wifi set_fw_recovery 1
done

