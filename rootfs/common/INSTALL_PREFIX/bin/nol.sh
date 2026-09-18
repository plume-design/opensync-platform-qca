#!/bin/sh

NOL_PATH="/tmp"
IFACES=$(ls /sys/class/net/ | grep ^wifi)

restore()
{
    for IFACE in $IFACES
    do
        FILE=$NOL_PATH/nol_$IFACE.bin
        test -f $FILE || continue
        test -s $FILE || continue
        radartool -i $IFACE setnol $FILE
    done
}

save()
{
    for IFACE in $IFACES
    do
        if grep -q . /sys/class/net/$IFACE/5g_maxchwidth
        then
            FILE=$NOL_PATH/nol_$IFACE.bin
            radartool -i $IFACE getnol $FILE
        fi
    done
}

"$@"
