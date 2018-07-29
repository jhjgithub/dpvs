CC = gcc
OUTPUT_OPTION=-MMD -MP -o $@
CFLAGS = -fPIC -Wall -Wextra -O2 -g
LDFLAGS = -shared
RM = rm -rf
TARGET_SO = libhs.so
TARGET_AR = libhs.a

INC=-I.
CFLAGS += $(INC)

SRCS = hypersplit.c  impl.c  mpool.c  point_range.c  
SRCS+=rfg.c  rule_trace.c  sort.c  utils.c

OBJDIR=obj
$(shell mkdir -p $(OBJDIR) >/dev/null)

OBJS = $(SRCS:%.c=$(OBJDIR)/%.o)
DEPS = $(SRCS:%.c=$(OBJDIR)/%.d)

.PHONY: all

all: ${TARGET_SO} $(TARGET_AR)

$(TARGET_SO): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(TARGET_AR): $(OBJS)
	ar rcu $@ $+
	ranlib $@

$(OBJDIR)/%.o: %.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.d: %.c
	@set -e; rm -f $@; [ ! -e $(dir $@) ] & mkdir -p $(dir $@); \
	$(CC) -M -MT $(patsubst %.d, %.o, $@) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$;

tag:
	ctags -R

custom: clean

.PHONY: clean

clean:
	-${RM} ${TARGET_SO} ${TARGET_AR} ${OBJDIR}

ifneq "$(MAKECMDGOALS)" "clean"
-include $(DEPS)
endif


