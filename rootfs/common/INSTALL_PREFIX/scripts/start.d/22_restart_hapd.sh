#!/bin/sh

wait_proc()
{
    for i in $(seq 1 5); do pidof "$@" || return 0; sleep 1; done
    return 1
}

kill_proc()
{
    echo TERM "$@" ...; killall -TERM "$@"; wait_proc "$@" && return 0
    echo KILL "$@" ...; killall -KILL "$@"; wait_proc "$@" && return 0
}

qca_wpa_hapd_stop()
{
    kill_proc hostapd wpa_supplicant
    rm -rf /var/run/hostapd*
    rm -rf /var/run/wpa_supplicant*
}

qca_wpa_hapd_start()
{
    /etc/init.d/qca-hostapd boot
    /etc/init.d/qca-wpa-supplicant boot
}

qca_wpa_hapd_stop
qca_wpa_hapd_start

