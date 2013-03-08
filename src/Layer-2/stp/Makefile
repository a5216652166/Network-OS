include ${TOPDIR}/.config

CODE_DIR=${TOPDIR}/src

STPS_CODE_DIR = $(CODE_DIR)/Layer-2/stp
STPS_INC_DIR =  $(STPS_CODE_DIR)/ 
STPS_SRCC_DIR = $(STPS_CODE_DIR)
STPS_SRCS += $(STPS_SRCC_DIR)/main.c
STPS_SRCS += $(STPS_SRCC_DIR)/stp_main.c
STPS_SRCS += $(STPS_SRCC_DIR)/stp_interface.c

STP_OBJ = $(STPS_SRCS:.c=.o)

CFLAGS +=   -I../../Layer-3/quagga-0.99.22 -I../../Layer-3/quagga-0.99.22/lib -DHAVE_INET_NTOP -DHAVE_SOCKLEN_T -DSYSCONFDIR=/opt/NetworkOS/etc

STP_LIBS = $(TOPDIR)//src/Layer-3/quagga-0.99.22/lib/.libs/libzebra.a

all:  $(STP_OBJ) stpd

$(STP_OBJ) : %.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

stpd: $(STPS_OBJ)
	$(CC) $(LD_FLAGS) -o stpd $(STP_OBJ) $(STP_LIBS) -lcap -lrt -lcrypt
	mkdir -p  ${TOPDIR}/final/opt/NetworkOS/sbin/
	install -m755 stpd ${TOPDIR}/final/opt/NetworkOS/sbin/	
clean:
	rm -f $(STPS_SRCC_DIR)/*.o stpd
