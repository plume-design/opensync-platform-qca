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


#minimum number of initial packets per flow to be force onto slow path
NUM_DEFERRED_PACKETS=15

# don't accelerate packets for these udp ports:
UDP_SLOW_PATH_PORTS="53 67 68"

configure_packet_deferral() {
    echo $NUM_DEFERRED_PACKETS > /sys/kernel/debug/ecm/ecm_classifier_default/accel_delay_pkts
}

disable_fdb_forward() {
    ssdk_sh fdb learnctrl set disable
    ssdk_sh fdb entry flush 1
}

udp_deny_ports() {
    echo "add $UDP_SLOW_PATH_PORTS" > /proc/sys/net/ecm/udp_denied_ports
}

configure_miami() {
    udp_deny_ports
    disable_fdb_forward
    configure_packet_deferral
}

configure_alder() {
    udp_deny_ports
    disable_fdb_forward
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
