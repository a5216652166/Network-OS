include ${TOPDIR}/.config

CODE_DIR=${TOPDIR}/src

RSTPS_CODE_DIR = $(CODE_DIR)/Layer-2/rstp
RSTPS_INC_DIR =  $(RSTPS_CODE_DIR)/ 
RSTPS_SRCC_DIR = $(RSTPS_CODE_DIR)
RSTPS_SRCS += $(RSTPS_SRCC_DIR)/bridgestp.c

RSTP_OBJ = $(RSTPS_SRCS:.c=.o)

all:  $(RSTP_OBJ) rstp

$(RSTP_OBJ) : %.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

rstp: $(RSTPS_OBJ)
	$(CC) $(LD_FLAGS) -o rstp $(RSTP_OBJ)
	mkdir -p  ${TOPDIR}/final/opt/NetworkOS/sbin/
	install -m755 rstp ${TOPDIR}/final/opt/NetworkOS/sbin/	
clean:
	rm -f $(RSTPS_SRCC_DIR)/*.o rstp 
