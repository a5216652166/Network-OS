include ${TOPDIR}/.config

all: LIB1 LIB2 LIB3 LIB4 LIB5 LIB6 LIB7

LIB_TOP_DIR=${TOPDIR}/src/System/Lib

LIB1_src=${LIB_TOP_DIR}/hash/hashlib.c
LIB2_src=${LIB_TOP_DIR}/mempool/mem_main.c 
LIB3_src=${LIB_TOP_DIR}/task/arch_os.c
LIB3_src+=${LIB_TOP_DIR}/task/msg_queue.c
LIB3_src+=${LIB_TOP_DIR}/task/multi-core.c
LIB3_src+=${LIB_TOP_DIR}/task/tsk_main.c
LIB4_src+=${LIB_TOP_DIR}/timers/lwtimers.c
LIB5_src+=${LIB_TOP_DIR}/zclient/zclient.c

LIB6_src+=${LIB_TOP_DIR}/qlib/agentx.c
LIB6_src+=${LIB_TOP_DIR}/qlib/buffer.c
LIB6_src+=${LIB_TOP_DIR}/qlib/checksum.c
LIB6_src+=${LIB_TOP_DIR}/qlib/command.c
LIB6_src+=${LIB_TOP_DIR}/qlib/daemon.c
LIB6_src+=${LIB_TOP_DIR}/qlib/distribute.c
LIB6_src+=${LIB_TOP_DIR}/qlib/filter.c
LIB6_src+=${LIB_TOP_DIR}/qlib/getopt1.c
LIB6_src+=${LIB_TOP_DIR}/qlib/getopt.c
LIB6_src+=${LIB_TOP_DIR}/qlib/hash.c
LIB6_src+=${LIB_TOP_DIR}/qlib/if.c
LIB6_src+=${LIB_TOP_DIR}/qlib/if_rmap.c
LIB6_src+=${LIB_TOP_DIR}/qlib/jhash.c
LIB6_src+=${LIB_TOP_DIR}/qlib/keychain.c
LIB6_src+=${LIB_TOP_DIR}/qlib/linklist.c
LIB6_src+=${LIB_TOP_DIR}/qlib/log.c
LIB6_src+=${LIB_TOP_DIR}/qlib/md5.c
LIB6_src+=${LIB_TOP_DIR}/qlib/memory.c
LIB6_src+=${LIB_TOP_DIR}/qlib/memtypes.c
LIB6_src+=${LIB_TOP_DIR}/qlib/network.c
LIB6_src+=${LIB_TOP_DIR}/qlib/pid_output.c
LIB6_src+=${LIB_TOP_DIR}/qlib/plist.c
LIB6_src+=${LIB_TOP_DIR}/qlib/pqueue.c
LIB6_src+=${LIB_TOP_DIR}/qlib/prefix.c
LIB6_src+=${LIB_TOP_DIR}/qlib/privs.c
LIB6_src+=${LIB_TOP_DIR}/qlib/regex.c
LIB6_src+=${LIB_TOP_DIR}/qlib/routemap.c
LIB6_src+=${LIB_TOP_DIR}/qlib/sigevent.c
LIB6_src+=${LIB_TOP_DIR}/qlib/smux.c
LIB6_src+=${LIB_TOP_DIR}/qlib/snmp.c
LIB6_src+=${LIB_TOP_DIR}/qlib/sockopt.c
LIB6_src+=${LIB_TOP_DIR}/qlib/sockunion.c
LIB6_src+=${LIB_TOP_DIR}/qlib/str.c
LIB6_src+=${LIB_TOP_DIR}/qlib/stream.c
LIB6_src+=${LIB_TOP_DIR}/qlib/table.c
LIB6_src+=${LIB_TOP_DIR}/qlib/thread.c
LIB6_src+=${LIB_TOP_DIR}/qlib/vector.c
LIB6_src+=${LIB_TOP_DIR}/qlib/vty.c
LIB6_src+=${LIB_TOP_DIR}/qlib/workqueue.c
LIB6_src+=${LIB_TOP_DIR}/qlib/zclient.c


LIB7_src+=${LIB_TOP_DIR}/zserv/zserv.c


LIB1_OBJ = $(LIB1_src:.c=.o)
LIB2_OBJ = $(LIB2_src:.c=.o)
LIB3_OBJ = $(LIB3_src:.c=.o)
LIB4_OBJ = $(LIB4_src:.c=.o)
LIB5_OBJ = $(LIB5_src:.c=.o)
LIB6_OBJ = $(LIB6_src:.c=.o)
LIB7_OBJ = $(LIB7_src:.c=.o)

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

LIB6: $(LIB6_OBJ)
	$(AR) -crs libqlib.a $(LIB6_OBJ)

LIB7: $(LIB7_OBJ)
	$(AR) -crs libserver.a $(LIB7_OBJ)

CFLAGS += -I${TOPDIR}/src/Layer-3/quagga-0.99.22 -I${TOPDIR}/src/System/Lib/qlib/
CFLAGS += -include ${TOPDIR}/src/Layer-3/quagga-0.99.22/config.h

include libmake.mk
