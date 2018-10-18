#!/bin/bash

RET=0

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo"
    exit 1
fi

rmmod rootkit

make clean

rm -f ./sysgen.h
