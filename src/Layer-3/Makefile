include ${TOPDIR}/.config

all:
	cd quagga-0.99.22 && ./configure && make && make install DESTDIR=${TOPDIR}/final/

clean:
	cd  quagga-0.99.22 && make distclean