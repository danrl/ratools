# project config
CC           = gcc
CFLAGS      += -std=gnu99 -pedantic -Wall -Wextra -pthread
CDEFS       += -DLEVEL1_DCACHE_LINESIZE=`getconf LEVEL1_DCACHE_LINESIZE`
# debug is slow but helpful during development
#CDEFS       += -DRAT_DEBUG
# tracing is slow and spams the logs. use with care!
#CDEFS       += -DRAT_DEBUG_TRACING
LDFLAGS     +=
BINDIR       = ../bin
BASHDIR      = ../bash-completion.d

# generic build instructions
.PHONY:     all clean
.DEFAULT:   all

all: 		rad ractl racomplete-ractl bash-completion

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
	opt_exp.o       \
	ractl.o
	[ -d "$(BINDIR)" ] || mkdir "$(BINDIR)"
	$(CC) $(CFLAGS) $(CDEFS) $(LDFLAGS) -o $(BINDIR)/$@ $^

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
	opt_exp.o       \
	rad.o
	[ -d "$(BINDIR)" ] || mkdir "$(BINDIR)"
	$(CC) $(CFLAGS) $(CDEFS) $(LDFLAGS) -o $(BINDIR)/$@ $^

racomplete-ractl: \
	library.o       \
	log.o           \
	module.o        \
	ra.o            \
	opt_mtu.o       \
	opt_sll.o       \
	opt_pi.o        \
	opt_rdnss.o     \
	opt_exp.o       \
	racomplete-ractl.o
	[ -d "$(BINDIR)" ] || mkdir "$(BINDIR)"
	$(CC) $(CFLAGS) $(CDEFS) $(LDFLAGS) -o $(BINDIR)/$@ $^

bash-completion: \
	$(BINDIR)/racomplete-ractl
	[ -d "$(BASHDIR)" ] || mkdir "$(BASHDIR)"
	$(BINDIR)/racomplete-ractl > $(BASHDIR)/ractl.sh


clean:
	rm -f     *.o
	rm -rf    "$(BINDIR)"
	rm -rf    "$(BASHDIR)"


