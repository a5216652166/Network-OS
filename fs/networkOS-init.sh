#!/bin/sh


echo "NetworkOS .... Initializing ....."

mkdir -p /opt/NetworkOS/etc/
touch /opt/NetworkOS/etc/ospfd.conf
touch /opt/NetworkOS/etc/zebra.conf
touch /opt/NetworkOS/etc/bgpd.conf


/opt/NetworkOS/sbin/nosMgr &
while [ ! -f  /opt/NetworkOS/NwtMgrDone ];
do
	sleep 1
done

echo "NetworkOS .... Initialized"

echo "Starting CLI session"
sleep 1

/opt/NetworkOS/sbin/cli
