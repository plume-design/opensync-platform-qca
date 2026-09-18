#!/bin/sh -e
# Checks if BSS is up using platform-specific tools.
#
# 1. Ensures the VAP is managed by the driver
# 2. Checks if channels are available in this regulatory domain
# 3. Validates the presence of the association


vap=$1

if ! iwconfig $vap >/dev/null 2>/dev/null
then
    # Possibly handled by a different driver.
    exit 0
fi

out_of_channels()
{
    radio=$(cat /sys/class/net/$1/parent)
    if exttool --help | grep -q 'list_chan_state '; then
        chan_cnt=$(exttool --list_chan_state --interface $radio | grep chan | wc -l)
        nop_cnt=$(exttool --list_chan_state --interface $radio | grep DFS_NOL | wc -l)
    else
        chan_cnt=$(exttool --list --interface $1 | wc -l)
        nop_cnt=$(exttool --list --interface $1 | grep NOP_STARTED | wc -l)
    fi

    test \
        $chan_cnt -gt 0 -a \
        $chan_cnt -eq $nop_cnt
}

if out_of_channels "$vap"
then
    log_warn "$vap($radio): all channels happen to be dfs in this regdomain and all are unavailable"
    exit 0
fi

if ! iwconfig "$vap" | grep -q 'Access Point: ..:..:..:..:..:..'
then
    log_warn "$vap: bss is not associated: no ap"
    exit 1
fi

if iwconfig "$vap" | grep -q 'Access Point: 00:00:00:00:00:00'
then
    log_warn "$vap: bss is not associated: null ap"
    exit 1
fi

if ! iwconfig "$vap" | grep -q 'Access Point:'; then
    log_warn "$vap: bss is not associated: missing Access Point field"
    exit 1
fi

exit 0
