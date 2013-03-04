include ${TOPDIR}/.config

all:
ifdef CONFIG_NTP
	cd ntp-4.2.6p5 && ./configure --prefix=/opt/NetworkOS/ && make && make install DESTDIR=${TOPDIR}/final/
endif
ifdef CONFIG_DHCP
	cd dhcp-4.2.5 && ./configure --prefix=/opt/NetworkOS/ && make && make install DESTDIR=${TOPDIR}/final/
endif
ifdef CONFIG_TELNET
	cd  netkit-telnet-0.17 && ./configure  --prefix=${TOPDIR}/final/opt/NetworkOS/ && make && make install DESTDIR=${TOPDIR}/final/
endif

ifdef CONFIG_TFTP
	cd netkit-tftp-0.17 && ./configure  --prefix=${TOPDIR}/final/opt/NetworkOS/ && make && make install DESTDIR=${TOPDIR}/final/
endif

clean:
ifdef CONFIG_NTP
	cd ntp-4.2.6p5 &&  make distclean
endif
ifdef CONFIG_DHCP
	cd  dhcp-4.2.5 && make distclean
endif
ifdef CONFIG_TELNET
	cd  netkit-telnet-0.17 && make distclean 
endif

ifdef CONFIG_TFTP
	cd netkit-tftp-0.17 &&  make distclean
endif

