CC=gcc
COMMON_CFLAGS=-W -Wall -Wextra -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE -O2
INCLUDE=-I$(PWD)
LDFLAGS=-lgit2

PROGS=order-commits find-fixes

all: $(PROGS)

tools_configurator_configurator: tools_configurator_configurator.c
	$(CC) -o $@ $<

config.h: tools_configurator_configurator
	./tools_configurator_configurator >config.h

ccan/list/list.o: ccan/list/list.c config.h
	$(CC) $(INCLUDE) -c -o $@ $<

common.o: common.c common.h
	$(CC) $(COMMON_CFLAGS) $(INCLUDE) -c common.c

order-commits: order-commits.c ccan/list/list.o common.o
	$(CC) $(COMMON_CFLAGS) $(INCLUDE) -o $@ $^ $(LDFLAGS)

find-fixes: find-fixes.c ccan/list/list.o common.o
	$(MAKE) -C ccan/ciniparser
	$(CC) $(COMMON_CFLAGS) $(INCLUDE) -o $@ $^ ccan/ciniparser/ciniparser.o ccan/ciniparser/dictionary.o $(LDFLAGS)

clean:
	$(MAKE) -C ccan/ciniparser $@
	@rm -f $(PROGS) *.o ccan/list/list.o

distclean: clean
	@rm -f tools_configurator_configurator *~ *.orig config.h
