include ${TOPDIR}/.config

NtwOSMGRS_CODE_DIR = $(TOPDIR)/src/System/NtwOSMgr
NtwOSMGRS_SRCC_DIR = $(NtwOSMGRS_CODE_DIR)

NtwOSMGRS_SRCS += $(NtwOSMGRS_SRCC_DIR)/main.c
NtwOSMGRS_SRCS += $(NtwOSMGRS_SRCC_DIR)/cpu.c

NtwOSMGR_OBJ = $(NtwOSMGRS_SRCS:.c=.o)


CFLAGS +=   -I${TOPDIR}/src/System/Lib/qlib/  -DHAVE_INET_NTOP -DHAVE_SOCKLEN_T -DSYSCONFDIR=/opt/NetworkOS/etc -DHAVE_NETLINK

LIBS = $(TOPDIR)/src/.libs/libqlib.a

all: $(NtwOSMGR_OBJ) nosMgr

$(NtwOSMGR_OBJ) : %.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

nosMgr: $(NtwOSMGRS_OBJ)
	$(CC) $(LD_FLAGS) -o nosMgr $(NtwOSMGRS_SRCC_DIR)/*.o ${LIBS}  -lcap -lrt -lcrypt
	mkdir -p ${TOPDIR}/final/opt/NetworkOS/sbin/
	cp  nosMgr ${TOPDIR}/final/opt/NetworkOS/sbin/	
	#install -s -m755 nosMgr ${TOPDIR}/final/opt/NetworkOS/sbin/	
clean:
	rm -f $(NtwOSMGRS_SRCC_DIR)/*.o nosMgr
