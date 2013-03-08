#!/bin/sh
echo "##############################"
echo "        Network OS 0.1        "
echo "##############################"
echo "                            "

echo "-> NetworkOS ... Cleaning up"

echo "-> Please wait ......"

RESULT=`ps -a | sed -n /nosMgr/p`

if [ "${RESULT:-null}" = null ]; then
	sleep 1
else
	pkill -TERM nosMgr

	while [ -f  /opt/NetworkOS/NwtMgrDone ];
	do
		sleep 1
	done
fi

echo "-> NetworkOS .... Initializing ....."

useradd -groot -d/home/cli -ccli_created -s/opt/NetworkOS/sbin/cli cli &>/dev/null

mkdir -p /opt/NetworkOS/etc/
touch /opt/NetworkOS/etc/ospfd.conf
touch /opt/NetworkOS/etc/zebra.conf
touch /opt/NetworkOS/etc/bgpd.conf
touch /opt/NetworkOS/etc/ospf6d.conf
touch /opt/NetworkOS/etc/ripd.conf
touch /opt/NetworkOS/etc/ripngd.conf
touch /opt/NetworkOS/etc/stpd.conf


/opt/NetworkOS/sbin/nosMgr &
while [ ! -f  /opt/NetworkOS/NwtMgrDone ];
do
	sleep 1
done

echo "-> NetworkOS .... Initialized"

#echo "-> Starting CLI session"
sleep 1

#/opt/NetworkOS/sbin/cli
