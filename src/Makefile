# project config
CC           = gcc
CFLAGS      += -std=gnu99 -pedantic -Wall -Wextra -pthread
CDEFS       += -DLEVEL1_DCACHE_LINESIZE=`getconf LEVEL1_DCACHE_LINESIZE`
# debug is slow but helpful during development
#CDEFS       += -DRAT_DEBUG
# tracing is slow and spams the logs. use with care!
#CDEFS       += -DRAT_DEBUG_TRACING
LDFLAGS     +=
DESTDIR      = ../bin/

# generic build instructions
.PHONY:     all clean
.DEFAULT:   all

all: 		ractl rad

%.o:	%.c %.h ratools.h
	$(CC) $(CFLAGS) $(CDEFS) -c $<

ractl: \
	library.o       \
	log.o           \
	module.o        \
	ra.o            \
	opt_mtu.o       \
	opt_sll.o       \
	opt_pi.o        \
	opt_rdnss.o     \
	ractl.o
	[ -d "$(DESTDIR)" ] || mkdir ../bin/
	$(CC) $(CFLAGS) $(CDEFS) $(LDFLAGS) -o $(DESTDIR)$@ $^

rad: \
	library.o       \
	log.o           \
	database.o      \
	module.o        \
	multicast.o     \
	netlink.o       \
	proc.o          \
	packetset.o     \
	ra.o            \
	opt_mtu.o       \
	opt_sll.o       \
	opt_pi.o        \
	opt_rdnss.o     \
	rad.o
	[ -d "$(DESTDIR)" ] || mkdir ../bin/
	$(CC) $(CFLAGS) $(CDEFS) $(LDFLAGS) -o $(DESTDIR)$@ $^

racomplete-ractl: \
	library.o       \
	log.o           \
	module.o        \
	ra.o            \
	opt_mtu.o       \
	opt_sll.o       \
	opt_pi.o        \
	opt_rdnss.o     \
	racomplete-ractl.o
	[ -d "$(DESTDIR)" ] || mkdir ../bin/
	$(CC) $(CFLAGS) $(CDEFS) $(LDFLAGS) -o $(DESTDIR)$@ $^

clean:
	rm -f     *.o
	rm -f     ../bin/*


