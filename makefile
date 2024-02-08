CC = gcc
LD=$(CC)
CFLAGS = -Wall -g
WINCFLAGS = -I /usr/include/pcap
WINLIBS = -lwpcap

# uncomment one
PLATFORM=linux
#PLATFORM=bsd
#PLATFORM=solaris
#PLATFORM=windows

SBINDIR = /usr/sbin
MANDIR = /usr/share/man

OFILES=\
	cec.o\
	${PLATFORM}.o \
	hba.o \
	utils.o 

HFILES=cec.h

cec: $(OFILES)
	@wl=; if test "${PLATFORM}" = "windows"; then \
		wl='${WINLIBS}'; \
	fi; set -x; $(LD) $(LDFLAGS) -o cec $(OFILES) $(LIBS) $$wl

%.o: %.c $(HFILES)
	@wc=; if test "${PLATFORM}" = "windows"; then \
		wc='${WINCFLAGS}'; \
	fi; set -x; $(CC) $(CFLAGS) $$wc -c $*.c

clean:
	rm -f *.o cec cec.exe

install : cec
	mkdir -p ${SBINDIR}
	cp cec ${SBINDIR}
	@if test "${PLATFORM}" = "solaris"; then \
		d=${MANDIR}/man1m; \
		t=cec.1m; \
	else \
		d=${MANDIR}/man8; \
		t=cec.8; \
	fi; set -x; mkdir -p $$d \
	  && cp cec.8 $$d/$$t
