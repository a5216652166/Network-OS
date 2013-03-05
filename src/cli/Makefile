include ${TOPDIR}/.config

CODE_DIR=${TOPDIR}/src

CLIS_CODE_DIR = $(CODE_DIR)/cli
CLIS_INC_DIR =  $(CLIS_CODE_DIR)/ 
CLIS_SRCC_DIR = $(CLIS_CODE_DIR)

CLIS_SRCS += $(CLIS_SRCC_DIR)/cparser.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/cparser_token.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/cparser_token_tbl.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/cparser_io_unix.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/cparser_fsm.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/cparser_line.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/cparser_tree.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/login.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/user_mgmt.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/cli_main.c
CLIS_SRCS += $(CLIS_SRCC_DIR)/cli_action.c

CFLAGS += -I$(CLIS_INC_DIR)

CLI_OBJ = $(CLIS_SRCS:.c=.o)

all: PARSE_TREE $(CLI_OBJ) cli

PARSE_TREE:
	$(CLIS_CODE_DIR)/mk_parser.py -o ./ $(CLIS_SRCC_DIR)/clicmds/cmd.cli

$(CLI_OBJ) : %.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@
cli: $(CLIS_OBJ)
	$(CC) $(LD_FLAGS) -o cli $(CLIS_SRCC_DIR)/*.o $(TOPDIR)/src/System/Lib/libmempool.a $(TOPDIR)/src/System/Lib/libtask.a -lrt -lpthread
	mkdir -p  ${TOPDIR}/final/opt/NetworkOS/sbin/
	install -s -m755 cli ${TOPDIR}/final/opt/NetworkOS/sbin/	
clean:
	rm -f $(CLIS_SRCC_DIR)/*.o cli $(CLIS_SRCC_DIR)/cparser_tree.*
