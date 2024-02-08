#
# Copyright (c) 2013 Coraid, Inc.
# All rights reserved.
#

CC		= cc
CFLAGS		= -g -xO3 -Xa -xspace -errwarn=%all
PLATFORM	= solaris

PACKAGE		= CORDcec
ROOT		= root

# cec-{N} defined in cec.h VERSION
VERSION		:sh = awk -F- '/\#define.*VERSION/{print $NF}' ../cec.h | sed 's!.$!!'

ARCHIVE		= $(PACKAGE)-$(VERSION).tar.gz

all:	$(ARCHIVE)

clean:
	@cd ..; $(MAKE) $@
	-$(RM) $(ARCHIVE) copyright pkginfo
	-$(RM) -r $(PACKAGE) $(ROOT)

cec:
	@cd ..; $(MAKE) $@ \
	    CC="$(CC)" CFLAGS="$(CFLAGS)" PLATFORM="$(PLATFORM)"
	install -s -d $(ROOT)/usr/sbin
	install -s -f $(ROOT)/usr/sbin ../$@

cec.1m:
	install -s -d $(ROOT)/usr/share/man/man1m
	@sed -e "s/^\.TH cec 8$$/.TH cec 1m/" ../cec.8 > $(ROOT)/usr/share/man/man1m/$@

$(PACKAGE):	cec cec.1m pkgmk

copyright:	FRC
	@cp ../COPYING $@ 2> /dev/null

pkginfo:	FRC
	@sed -e "s/PKGVERS/$(VERSION)/" pkginfo.tmpl > $@

pkgmk:	copyright pkginfo
	pkgmk -f prototype -r $(ROOT) -d . -o

$(ARCHIVE):	$(PACKAGE)
	tar cf - $(PACKAGE) | gzip > $@

FRC:
