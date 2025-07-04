#!/bin/sh -e

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
