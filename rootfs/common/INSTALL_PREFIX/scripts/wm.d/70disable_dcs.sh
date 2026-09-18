#!/bin/sh
# While driver re-initializes internal structures with default
# values (dcs_enable = 1 on DA) when last vap is stopped/destroyed,
# then this option can be ovveride during onboarding.
# Because of that we set this here instead of using wifi.sh script.
if command -v cfg80211tool > /dev/null; then
    cfg80211tool $(cat /sys/class/net/$1/parent) dcs_enable 0
else
    iwpriv $(cat /sys/class/net/$1/parent) dcs_enable 0
fi
