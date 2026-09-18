#!/bin/sh

wait_insmod()
{
    # Wait until wifi interfaces show up
    local phys=$(for PHY in $CONFIG_OVSDB_BOOTSTRAP_WIFI_PHY_LIST; do echo -n "${PHY%%:*} "; done)
    $timeout 90 sh -c "cd /sys/class/net; while ! ls -d $phys >/dev/null 2>&1; do sleep 1; done" && return 0

    # Critical error
    logger -t opensync -p daemon.crit "ERROR: Wifi modules failed to load. Unable to start OpenSync managers."
    exit 1
}

wait_insmod

