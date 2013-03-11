include ${TOPDIR}/.config

all: LIB1 LIB2 LIB3 LIB4 LIB5

LIB_TOP_DIR=${TOPDIR}/src/System/Lib

LIB1_src=${LIB_TOP_DIR}/hash/hashlib.c
LIB2_src=${LIB_TOP_DIR}/mempool/mem_main.c 
LIB3_src=${LIB_TOP_DIR}/task/arch_os.c
LIB3_src+=${LIB_TOP_DIR}/task/msg_queue.c
LIB3_src+=${LIB_TOP_DIR}/task/multi-core.c
LIB3_src+=${LIB_TOP_DIR}/task/tsk_main.c
LIB4_src+=${LIB_TOP_DIR}/timers/lwtimers.c
LIB5_src+=${LIB_TOP_DIR}/zclient/zclient.c

LIB1_OBJ = $(LIB1_src:.c=.o)
LIB2_OBJ = $(LIB2_src:.c=.o)
LIB3_OBJ = $(LIB3_src:.c=.o)
LIB4_OBJ = $(LIB4_src:.c=.o)
LIB5_OBJ = $(LIB5_src:.c=.o)

LIB1: $(LIB1_OBJ)
	$(AR) -crs libhash.a $(LIB1_OBJ)

LIB2: $(LIB2_OBJ)
	$(AR) -crs libmempool.a $(LIB2_OBJ)

LIB3: $(LIB3_OBJ)
	$(AR) -crs libtask.a $(LIB3_OBJ)

LIB4: $(LIB4_OBJ)
	$(AR) -crs libtimers.a $(LIB4_OBJ)

LIB5: $(LIB5_OBJ)
	$(AR) -crs libclient.a $(LIB5_OBJ)


CFLAGS += -I${TOPDIR}/src/Layer-3/quagga-0.99.22 -I${TOPDIR}/src/Layer-3/quagga-0.99.22/lib
CFLAGS += -include ${TOPDIR}/src/Layer-3/quagga-0.99.22/config.h

include libmake.mk
