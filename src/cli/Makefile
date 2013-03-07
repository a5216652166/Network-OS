include ${TOPDIR}/.config

CODE_DIR=${TOPDIR}/src

CLIS_CODE_DIR = $(CODE_DIR)/cli
CLIS_INC_DIR =  $(CLIS_CODE_DIR)/ 
CLIS_SRCC_DIR = $(CLIS_CODE_DIR)
CLIS_SRCS += $(CLIS_SRCC_DIR)/vty.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/vtysh.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/vtysh_config.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/vtysh_main.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/vtysh_user.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/vtysh_cmd.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/command.c

CFLAGS += -I$(CLIS_INC_DIR) -I../Layer-3/quagga-0.99.22 -I../Layer-3/quagga-0.99.22/lib
CFLAGS +=  -DSYSCONFDIR=\"/opt/NetworkOS/etc/\" -include ${TOPDIR}/src/Layer-3/quagga-0.99.22/config.h

CLI_OBJ = $(CLIS_SRCS:.c=.o)

CLI_LIBS = $(TOPDIR)/src/Layer-3/quagga-0.99.22/ripngd/libripng.a  \
	$(TOPDIR)/src/Layer-3/quagga-0.99.22/babeld/libbabel.a \
	$(TOPDIR)/src/Layer-3/quagga-0.99.22/lib/.libs/libzebra.a \
	$(TOPDIR)/src/Layer-3/quagga-0.99.22/ripd/librip.a \
	$(TOPDIR)/src/Layer-3/quagga-0.99.22/bgpd/libbgp.a \
	$(TOPDIR)/src/Layer-3/quagga-0.99.22/ospfd/.libs/libospf.a \
	$(TOPDIR)/src/Layer-3/quagga-0.99.22/ospf6d/libospf6.a \
	$(TOPDIR)/src/Layer-3/quagga-0.99.22/ospfclient/.libs/libospfapiclient.a

all:  $(CLI_OBJ) cli

$(CLI_OBJ) : %.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@
cli: $(CLIS_OBJ)
	$(CC) $(LD_FLAGS) -o cli $(CLI_OBJ) $(CLI_LIBS) -lreadline -lrt -lcrypt  -lcap
	mkdir -p  ${TOPDIR}/final/opt/NetworkOS/sbin/
	install -m755 cli ${TOPDIR}/final/opt/NetworkOS/sbin/	
	chmod u+s ${TOPDIR}/final/opt/NetworkOS/sbin/cli
clean:
	rm -f $(CLIS_SRCC_DIR)/*.o cli $(CLIS_SRCC_DIR)/cparser_tree.*
