#!/bin/bash -       
#title           : netpps.sh
#description     : This program is used in order to monitor the incoming and outcoming packets per second in real time.
#author          : Federico Marinelli
#bash_version    : 4.1.5(1)-release
#==============================================================================

INTERVAL="1"  # update interval in seconds

if [ -z "$1" ]; then
        echo
        echo usage: $0 [network-interface]
        echo
        echo e.g. $0 eth0
        echo
        echo shows packets-per-second
        exit
fi

IF=$1

while true
do
        R1=`cat /sys/class/net/$1/statistics/rx_packets`
        T1=`cat /sys/class/net/$1/statistics/tx_packets`
        sleep $INTERVAL
        R2=`cat /sys/class/net/$1/statistics/rx_packets`
        T2=`cat /sys/class/net/$1/statistics/tx_packets`
        TXPPS=`expr $T2 - $T1`
        RXPPS=`expr $R2 - $R1`
        echo "TX $1: $TXPPS pkts/s RX $1: $RXPPS pkts/s"
done
