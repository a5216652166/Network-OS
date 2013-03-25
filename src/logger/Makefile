include ${TOPDIR}/.config

LOGGERS_CODE_DIR = $(TOPDIR)/src/logger
LOGGERS_SRCC_DIR = $(LOGGERS_CODE_DIR)

LOGGERS_SRCS += $(LOGGERS_SRCC_DIR)/main.c

LOGGER_OBJ = $(LOGGERS_SRCS:.c=.o)


CFLAGS +=   -I${TOPDIR}/src/System/Lib/qlib/  -DHAVE_INET_NTOP -DHAVE_SOCKLEN_T -DSYSCONFDIR=/opt/NetworkOS/etc -DHAVE_NETLINK

LIBS = $(TOPDIR)/src/.libs/libqlib.a

all: $(LOGGER_OBJ) nosMgr

$(LOGGER_OBJ) : %.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

nosMgr: $(LOGGERS_OBJ)
	$(CC) $(LD_FLAGS) -o logger $(LOGGERS_SRCC_DIR)/*.o ${LIBS}  -lcap -lrt -lcrypt
	mkdir -p ${TOPDIR}/final/opt/NetworkOS/sbin/
	cp  logger ${TOPDIR}/final/opt/NetworkOS/sbin/	
	#install -s -m755 nosMgr ${TOPDIR}/final/opt/NetworkOS/sbin/	
clean:
	rm -f $(LOGGERS_SRCC_DIR)/*.o logger
