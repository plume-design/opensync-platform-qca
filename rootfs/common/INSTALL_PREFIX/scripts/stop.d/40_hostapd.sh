
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

# {# jinja-parse #}

{%- if CONFIG_OVSDB_BOOTSTRAP_WIFI_STA_LIST is not none %}
    {%- set phy_sta_list =  CONFIG_OVSDB_BOOTSTRAP_WIFI_STA_LIST.split(' ') %}
    {%- set sta_list = [] %}
    {%- for phy_sta in phy_sta_list %}
        {%- set sta_list = sta_list.append(phy_sta.split(':')[1]) %}
    {%- endfor %}
sta_list="{{sta_list|join(' ')}}"
{%- else %}
sta_list="bhaul-sta-24 bhaul-sta-50 bhaul-sta-l50 bhaul-sta-u50 bhaul-sta-60"
{%- endif %}

# Kindly ask wpa_s/hostap to terminate. Driver gets angry if
# you're too bold.
for i in ${sta_list}
do
    sockpath=/var/run/wpa_supplicant-$(cat /sys/class/net/$i/parent)
    test -e $sockpath/$i || continue
    $timeout 3 wpa_cli -p $sockpath -i $i disc
    $timeout 10 sh -x <<-.
            while ! wpa_cli -p $sockpath -i $i stat | egrep 'wpa_state=(DISCONNECTED|INACTIVE|INTERFACE_DISABLED)'
            do
                sleep 1
            done
.
done
killall -s SIGTERM hostapd wpa_supplicant
$timeout 10 sh -x <<-.
    while pidof hostapd || pidof wpa_supplicant
    do
        sleep 1
    done
.
killall -s SIGKILL hostapd wpa_supplicant
rm -vf /tmp/wpa_ctrl*

