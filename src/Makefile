include ${TOPDIR}/.config

all:
	make -C System/
ifndef CONFIG_LAYER3
	make -C Layer-3/
endif
ifdef CONFIG_LAYER2
	make -C Layer-2/
endif
ifdef CONFIG_APPS
	make -C Apps
endif
	make -C cli
clean:
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

