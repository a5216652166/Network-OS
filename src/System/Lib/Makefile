include ${TOPDIR}/.config

all: LIB1 LIB2

LIB_TOP_DIR=${TOPDIR}/src/System/Lib

LIB1_src=${LIB_TOP_DIR}/hash/hashlib.c
LIB2_src=${LIB_TOP_DIR}/mempool/mem_main.c 
LIB3_src=${LIB_TOP_DIR}/task/arch_os.c
LIB3_src+=${LIB_TOP_DIR}/task/msg_queue.c
LIB3_srci+=${LIB_TOP_DIR}/task/multi-core.c


LIB1_OBJ = $(LIB1_src:.c=.o)
LIB2_OBJ = $(LIB2_src:.c=.o)
LIB3_OBJ = $(LIB3_src:.c=.o)

LIB1: $(LIB1_OBJ)
	$(AR) -crs libhash.a $(LIB1_OBJ)

LIB2: $(LIB2_OBJ)
	$(AR) -crs libmempool.a $(LIB2_OBJ)

LIB3: $(LIB3_OBJ)
	$(AR) -crs libtask.a $(LIB3_OBJ)

include libmake.mk
