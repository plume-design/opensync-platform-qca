#!/bin/sh

#minimum number of initial packets per flow to be force onto slow path
NUM_DEFERRED_PACKETS=15

# don't accelerate packets for these udp ports:
UDP_SLOW_PATH_PORTS="53 67 68"

configure_packet_deferral() {
    echo $NUM_DEFERRED_PACKETS > /sys/kernel/debug/ecm/ecm_classifier_default/accel_delay_pkts
}

udp_deny_ports() {
    echo "add $UDP_SLOW_PATH_PORTS" > /proc/sys/net/ecm/udp_denied_ports
}

configure_miami() {
    udp_deny_ports
    configure_packet_deferral
}

configure_alder() {
    udp_deny_ports
    configure_packet_deferral
}

configure_dakota() {
    echo "n/a"
}

configure_hawkeye() {
    echo "n/a"
}

configure_unsupported() {
    echo "WARNING: Unsupported board"
}

board=$(grep -o "IPQ.*" /proc/device-tree/model | awk -F/ '{print $1}')
echo "Configuring board: $board"

case "$board" in
    IPQ5332) configure_miami ;;
    IPQ9574) configure_alder ;;
    IPQ40xx) configure_dakota ;;
    IPQ807x) configure_hawkeye ;;
    IPQ8074) configure_hawkeye ;;
    IPQ6018) configure_unsupported ;;
    IPQ5018) configure_unsupported ;;
    IPQ5332) configure_unsupported ;;
    *) configure_unsupported ;;
esac
