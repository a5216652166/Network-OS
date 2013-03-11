include ${TOPDIR}/.config
#  --disable-zebra         do not build zebra daemon
#  --disable-bgpd          do not build bgpd
#  --disable-ripd          do not build ripd
#  --disable-ripngd        do not build ripngd
#  --disable-ospfd         do not build ospfd
#  --disable-ospf6d        do not build ospf6d
#  --disable-babeld        do not build babeld
#  --disable-watchquagga   do not build watchquagga
#  --enable-isisd          build isisd
#  --disable-bgp-announce, turn off BGP route announcement
#  --enable-netlink        force to use Linux netlink interface
#  --enable-broken-aliases enable aliases as distinct interfaces for Linux 2.2.X
#  --enable-snmp=ARG       enable SNMP support (smux or agentx)
#  --enable-tcp-zebra      enable TCP/IP socket connection between zebra and protocol daemon
#  --disable-opaque-lsa    do not build OSPF Opaque-LSA with OSPFAPI support
#                          (RFC2370)
#  --disable-ospfapi       do not build OSPFAPI to access the OSPF LSA Database
#  --disable-ospfclient    do not build OSPFAPI client for OSPFAPI,

ifndef CONFIG_OSPF
MODULES_DISABLE += --disable-ospfd --disable-ospf6d --disable-ospfapi --disable-ospfclient --disable-opaque-lsa
endif
ifndef CONFIG_BGP
MODULES_DISABLE += --disable-bgpd --disable-bgp-announce
endif

ifndef CONFIG_RIP
MODULES_DISABLE += --disable-ripd --disable-ripngd
endif

ifdef CONFIG_ISISD
MODULES_DISABLE += --enable-isisd
endif

ifndef CONFIG_BABELD
MODULES_DISABLE += --disable-babeld
endif

all:build

build:
	cd quagga-0.99.22 && ./configure --prefix=/opt/NetworkOS/ --enable-vtysh --enable-fpm --enable-user=root --enable-group=root --enable-netlink --disable-doc --disable-tests  --enable-vty-group=root $(MODULES_DISABLE) && make && make install DESTDIR=${TOPDIR}/final/

clean:
	cd  quagga-0.99.22 && make distclean
