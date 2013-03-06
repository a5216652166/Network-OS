include ${TOPDIR}/.config

all:
	cd quagga-0.99.22 && ./configure --prefix=/opt/NetworkOS/ --enable-vtysh && make && make install DESTDIR=${TOPDIR}/final/

clean:
	cd  quagga-0.99.22 && make distclean
