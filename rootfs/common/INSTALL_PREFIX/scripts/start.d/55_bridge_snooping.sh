#!/bin/sh
# {# jinja-parse #}

echo -n 'Disabling system snooping ...'
echo 0 > /sys/devices/virtual/net/{{CONFIG_TARGET_LAN_BRIDGE_NAME}}/bridge/multicast_snooping
