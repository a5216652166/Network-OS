include ${TOPDIR}/.config

CODE_DIR=${TOPDIR}/src

IFMGRS_CODE_DIR = $(CODE_DIR)/IfMgr
IFMGRS_INC_DIR =  $(IFMGRS_CODE_DIR)/ 
IFMGRS_SRCC_DIR = $(IFMGRS_CODE_DIR)
IFMGRS_SRCS += $(IFMGRS_SRCC_DIR)/main.c
IFMGRS_SRCS += $(IFMGRS_SRCC_DIR)/ifMgr_interface.c
IFMGRS_SRCS += $(IFMGRS_SRCC_DIR)/if.c
IFMGRS_SRCS += $(IFMGRS_SRCC_DIR)/if_netlink.c
IFMGRS_SRCS += $(IFMGRS_SRCC_DIR)/rt_netlink.c

IFMGRS_LIB_SRCS +=  $(IFMGRS_SRCC_DIR)/if_client.c

IFMGRS_LIB_OBJ  = $(IFMGRS_LIB_SRCS:.c=.o)
IFMGR_OBJ = $(IFMGRS_SRCS:.c=.o)

CFLAGS +=   -I${TOPDIR}/src/System/Lib/qlib/  -DHAVE_INET_NTOP -DHAVE_SOCKLEN_T -DSYSCONFDIR=/opt/NetworkOS/etc -DHAVE_NETLINK

IFMGR_LIBS = $(TOPDIR)/src/.libs/libqlib.a $(TOPDIR)/src/.libs/libserver.a

all:  $(IFMGR_OBJ) ifMgrd libifmgr.a

$(IFMGR_OBJ) : %.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

$(IFMGRS_LIB_OBJ) : %.o : %.c Makefile
	$(CC) -c -fPIC $(CFLAGS) $< -o $@
ifMgrd: $(IFMGRS_OBJ)
	$(CC) $(LD_FLAGS) -o ifMgrd $(IFMGR_OBJ) $(IFMGR_LIBS) -lcap -lrt -lcrypt
	mkdir -p  ${TOPDIR}/final/opt/NetworkOS/sbin/
	cp ifMgrd ${TOPDIR}/final/opt/NetworkOS/sbin/
	#install -m755 ifMgrd ${TOPDIR}/final/opt/NetworkOS/sbin/	
libifmgr.a: $(IFMGRS_LIB_OBJ)
	$(AR) -crs ${TOPDIR}/src/.libs/libifmgr.a  $(IFMGRS_LIB_OBJ)
clean:
	rm -f $(IFMGRS_SRCC_DIR)/*.o ifMgrd
