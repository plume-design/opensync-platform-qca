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
