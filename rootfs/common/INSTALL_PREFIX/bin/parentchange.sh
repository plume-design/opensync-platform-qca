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

self=$0
radio=$1
parent=$(echo "$2" | tr A-Z a-z)
chan=$3

die() {
	echo die: "$@"
	exit 1
}

uuid_in() {
	grep -o '"[^"]*-[^"]*"'
}

uuid_out() {
	echo -n '["set",['
	sed 's/^/["uuid",/; s/$/]/' | tr '\n' ',' | sed 's/,$//'
	echo ']]'
}

uuid_del() {
	uuid_in | grep -vF "$1" | uuid_out
}

uuid_add() {
	( uuid_in; printf '"%s"\n' "$1"; ) | uuid_out
}

rtrim() {
	# Apparently some columns have trailing spaces
	# in "raw" ovsh output, causing search failures.
	sed 's/ $//'
}

ovsh() {
	command "$(dirname "$self")/../tools/ovsh" "$@"
}

usage() {
	test -n "$radio" || {
		echo "Usage: $self <radio> [parent] [channel]"
		echo "       $self wifi0"
		echo "       $self wifi1 42:B4:F7:01:EE:F6"
		echo "       $self wifi1 42:B4:F7:01:EE:F6 44"
		echo "       $self wifi2 '' 44"
		die "Invalid arguments"
	}
}

prep() {
	band=$(grep "^$radio\$" /sys/class/net/*/parent \
		| sed 1q \
		| xargs dirname \
		| xargs basename \
		| tr '-' '\n' \
		| tail -n1) || die "Failed to infer band suffix"
}

sanity() {
	# This isn't guaranteed to prevent races but it's
	# better than nothing.
	num=$(ovsh s -Ur Wifi_VIF_Config ssid -w mode==sta | wc -l)
	test $num -eq 1 || die "Unsupported number of sta vaps: $num (only 1 is supported)"
}

update_channel() {
	test -n "$chan" && ovsh u Wifi_Radio_Config channel:=$chan -w if_name==$radio -w "channel!=$chan"
}

is_parent_identical() {
	ovsh s -Ur Wifi_Radio_Config vif_configs -w if_name==$radio \
		| uuid_in \
		| grep -q "^$(ovsh s -Ur Wifi_VIF_Config _uuid -w mode==sta $(test -n "$parent" && echo "-w parent==$parent") | uuid_in)$" \
	&& test "$(ovsh s -Ur Wifi_VIF_Config parent -w mode==sta | rtrim)" = "$parent"
}

recreate_sta_vap() {
	ssid=$(ovsh s -Ur Wifi_VIF_Config ssid -w mode==sta | sed 1q | rtrim | grep .) || die "Failed to get ssid"
	security=$(ovsh s -Ur Wifi_VIF_Config security -w mode==sta | sed 1q | rtrim | grep .) || die "Failed to get security"

	for i in $(ovsh s -Ur Wifi_Radio_Config if_name)
	do
		ovsh u Wifi_Radio_Config -w if_name==$i vif_configs::"$(
			ovsh s -Ur Wifi_Radio_Config -w if_name==$i vif_configs \
				| uuid_del "$(ovsh s -Ur Wifi_VIF_Config -w mode==sta _uuid | uuid_in)"
		)"
	done

	ovsh d Wifi_Inet_Config -w "gre_ifname==$(ovsh s -Ur Wifi_Inet_Config gre_ifname -w if_type==gre | grep -- -sta- | sed 1q)"
	ovsh d Wifi_VIF_Config -w mode==sta
	uuid=$(ovsh i Wifi_VIF_Config \
		"ssid:=$ssid" \
		if_name:=bhaul-sta-$band \
		$(test -z "$parent" || echo parent:=$parent) \
		mode:=sta \
		enabled:=true \
		"security::$security" \
		vif_radio_idx:=0)

	ovsh u Wifi_Radio_Config -w if_name==$radio vif_configs::"$(
		ovsh s -Ur Wifi_Radio_Config -w if_name==$radio vif_configs \
			| uuid_add "$uuid"
	)"
}

usage
prep
sanity
update_channel
is_parent_identical && exit 0
recreate_sta_vap
