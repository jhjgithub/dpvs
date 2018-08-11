
CC = gcc
CFLAGS = -Wall -g
OBJ_DIR = obj

include ../../src/dpdk.mk
include ../../src/config.mk

HSLIB_DIR=../libhypersplit

INCDIRS +=  -I ../../include -I ../../src/netshield/include -I ./
INCDIRS += -I ../keepalived/keepalived/libipvs-2.6
INCDIRS += -I$(HSLIB_DIR)
CFLAGS += $(INCDIRS)

LIB_DIR+= -L$(HSLIB_DIR)
#LIBS = -lhs -ljson-c -lnuma
LIBS = -ljson-c -lnuma $(HSLIB_DIR)/libhs.a

LDFLAGS += $(LIB_DIR) -Wl,-rpath=$(HSLIB_DIR)

BIN  = nsctl
MYSRC = build_hs.c  io.c  main.c  parse_policy_json.c
SRC  = $(MYSRC) common.c sockopt.c

DEP = $(patsubst %.c, $(OBJ_DIR)/%.d, $(SRC))
OBJ = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRC))


all: $(BIN) # run_pc

custom: tag #upload

ifneq "$(MAKECMDGOALS)" "clean"
    -include $(DEP)
endif

$(OBJ_DIR)/%.o: %.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.d: %.c
	@set -e; rm -f $@; [ ! -e $(dir $@) ] & mkdir -p $(dir $@); \
	$(CC) -M -MT $(patsubst %.d, %.o, $@) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$;

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

common.c:
	ln -s ../../src/common.c ./common.c

sockopt.c:
	ln -s ../keepalived/keepalived/libipvs-2.6/sockopt.c ./sockopt.c

clean:
	rm -rf $(OBJ_DIR);
	rm -f $(BIN) tags
	rm -f common.c sockopt.c

tag:
	ctags -R

run_grp:
	./bin/pc_plat -g rfg -f wustl -r rule_trace/rules/origin/fw1_10K

upload:
	sshpass -proot123 scp -o StrictHostKeyChecking=no ${BIN} root@10.1.1.3:~/

run_pc:
#	./bin/pc_plat -p hs -f wustl_g -r rule_trace/rules/rfg/fw1_10K -t rule_trace/traces/fw1_10K_trace
#	./bin/pc_plat -g rfg -f wustl -r rule_trace/rules/origin/fw1_10K
#	./bin/pc_plat -p hs -f wustl -r rule_trace/rules/origin/acl1_10K -t rule_trace/traces/acl1_10K_trace
#	$(BIN) -r rule_trace/rules/origin/fw1_10K -t rule_trace/traces/fw1_10K_trace
#	./$(BIN) -p hs -f wustl -r rule_trace/rules/origin/fw2 -t rule_trace/traces/fw2_trace
#	gdb -ex=r --args ./bin/pc_plat -p hs -f wustl -r rule_trace/rules/origin/fw2 -t rule_trace/traces/origin/fw2_trace
#	gdb -ex=r --args $(BIN) -r rule_trace/rules/origin/fw1_10K -k
#	$(BIN) -r rule_trace/rules/origin/fw1_10K -k
#	$(BIN) -r rule_trace/rules/origin/fw2 -k
#	$(BIN) -r rule_trace/rules/origin/fw2
#	$(BIN) -r ns_rule.txt
	$(BIN) -f -n -r ns_rule.json
#	$(BIN) -r ns_rule1.txt

format: $(MYSRC)
	 uncrustify --no-backup --mtime -c ./formatter.cfg $^
