include ${TOPDIR}/.config

all:
	cd quagga-0.99.22 && ./configure --prefix=/opt/NetworkOS/ --enable-vtysh --enable-fpm --enable-user=root --enable-group=root --enable-netlink --enable-isisd --disable-doc --disable-tests  --enable-vty-group=root --enable-irdp && make && make install DESTDIR=${TOPDIR}/final/

clean:
	cd  quagga-0.99.22 && make distclean
