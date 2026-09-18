#!/bin/sh
# {# jinja-parse #}

echo -n 'Starting Open vSwitch ...'
# start openvswitch
{% if CONFIG_PLATFORM_QCA_QSDK110 or CONFIG_PLATFORM_QCA_QSDK120 %}
cp ${INSTALL_PREFIX}/etc/conf.db.bck /etc/openvswitch/conf.db
uci set openvswitch.ovs.disabled=0
uci set openvswitch.north.disabled=0
uci set openvswitch.controller.disabled=0
uci commit
/etc/init.d/openvswitch restart
{% else %}
/etc/init.d/openvswitch start
{% endif %}

# Wait until ovsdb is ready
while ! ovsdb-client list-dbs > /dev/null 2>&1
do
    sleep 1
    echo -n .
done

