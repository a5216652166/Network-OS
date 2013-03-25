include ${TOPDIR}/.config

all:
	mkdir -p ${TOPDIR}/src/.libs/
ifdef CONFIG_LAYER3
	make -C Layer-3 libs
endif
ifdef CONFIG_LAYER2
	make -C Layer-2/
endif
ifdef CONFIG_APPS
	make -C Apps
endif
	make -C System/
	make -C IfMgr
ifdef CONFIG_LAYER3
	make -C Layer-3
endif
	make -C cli
	make -C logger
clean:
	rm -rf ${TOPDIR}/src/.libs/
	make -C cli clean
	make -C System/ clean
ifdef CONFIG_LAYER3
	make -C Layer-3/ clean
endif
ifdef CONFIG_LAYER2
	make -C Layer-2/ clean
endif
ifdef CONFIG_APPS
	make -C Apps clean
endif

	make -C IfMgr clean
