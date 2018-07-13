#
# DPVS is a software load balancer (Virtual Server) based on DPDK.
#
# Copyright (C) 2017 iQIYI (www.iqiyi.com).
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

#
# Makefile for dpvs (DPVS main program).
#

QUITE= @
ifeq ("$(origin V)", "command line")
	QUITE=
endif

DEBUG := 1		# enable for debug

TARGET := dpvs
OBJDIR := obj

VERSION_STRING := $(shell ./VERSION)
DATE_STRING := $(shell date +%Y.%m.%d.%H:%M:%S)

# same path of THIS Makefile
#SRCDIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
SRCDIR := .

include $(SRCDIR)/dpdk.mk
include $(SRCDIR)/config.mk

INCDIRS += -I $(SRCDIR)/../include

# for dpvs main program.
CFLAGS += -D __DPVS__ -DDPVS_VERSION=\"$(VERSION_STRING)\" -DDPVS_BUILD_DATE=\"$(DATE_STRING)\"

#CFLAGS += -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes -mcmodel=medium
CFLAGS += -Werror -Wstrict-prototypes  -mcmodel=medium

ifeq ($(shell test $(GCC_VERSION) -ge 70 && echo 1), 1)
	CFLAGS += -Wno-format-truncation
	CFLAGS += -Wno-stringop-truncation
	CFLAGS += -Wstringop-overflow=0
endif

ifeq ($(DEBUG),)
	CFLAGS += -O3
else
	CFLAGS += -g -O0 -D DEBUG
endif

LIBS += -lpthread -lnuma
CFLAGS += $(INCDIRS)

SRCS    = $(shell find $(SRCDIR) -name '*.c' | sort)
SRCDIRS = $(shell find $(SRCDIR) -name '*.c' -printf '%h\0' | sort -zu | tr '\0' '\n')
OBJS    = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
DEPS    = $(OBJS:%.o=%.d)

#########################

all: buildrepo $(TARGET)

$(TARGET): $(OBJS)
	$(QUITE)echo "  $(notdir $@)"
	$(QUITE)$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

buildrepo: 
	@$(call make-repo)

# Create obj directory structure
define make-repo
	mkdir -p $(OBJDIR)
	for dir in $(SRCDIRS); \
	do \
		mkdir -p $(OBJDIR)/$$dir; \
	done
endef

$(OBJDIR)/%.o: %.c ./config.mk
	$(QUITE)$(CC) $(CFLAGS) -MM -MT $@ -MF $(patsubst %.o,%.d,$@) $<
	$(QUITE)$(CC) -DMY_DBG_NAME=$(basename $(notdir $<)) -c $(CFLAGS) $< -o $@
	$(QUITE)echo "  $(notdir $@)"

clean:
	rm -rf $(OBJDIR)
	rm -f ./$(TARGET)

install:
#	install -m 744 $(TARGET) $(INSDIR)

custom:
	cd ..;ctags -R

FMT_SRC=ns_cmds.c  ns_main.c   netlink.c debug_ctl.c

format:
	uncrustify --no-backup --mtime -c ./formatter.cfg $(FMT_SRC)

-include $(DEPS)
