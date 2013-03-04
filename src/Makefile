#include ../.config

all:
ifdef CONFIG_LAYER3
	make -C Layer-3/
endif
ifdef CONFIG_LAYER2
	make -C Layer-2/
endif
ifdef CONFIG_APPS
	make -C Apps
endif
ifdef CONFIG_SYSTEM
	make -C System/
endif
