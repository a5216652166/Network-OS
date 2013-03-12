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

IFMGR_OBJ = $(IFMGRS_SRCS:.c=.o)

CFLAGS +=   -I../Layer-3/quagga-0.99.22  -I${TOPDIR}/src/System/Lib/qlib/  -DHAVE_INET_NTOP -DHAVE_SOCKLEN_T -DSYSCONFDIR=/opt/NetworkOS/etc -DHAVE_NETLINK

IFMGR_LIBS = $(TOPDIR)/src/System/Lib/libqlib.a

all:  $(IFMGR_OBJ) ifMgrd

$(IFMGR_OBJ) : %.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

ifMgrd: $(IFMGRS_OBJ)
	$(CC) $(LD_FLAGS) -o ifMgrd $(IFMGR_OBJ) $(IFMGR_LIBS) -lcap -lrt -lcrypt
	mkdir -p  ${TOPDIR}/final/opt/NetworkOS/sbin/
	cp ifMgrd ${TOPDIR}/final/opt/NetworkOS/sbin/
	#install -m755 ifMgrd ${TOPDIR}/final/opt/NetworkOS/sbin/	
clean:
	rm -f $(IFMGRS_SRCC_DIR)/*.o ifMgrd
