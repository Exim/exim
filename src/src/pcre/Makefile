# $Cambridge: exim/src/src/pcre/Makefile,v 1.2 2005/05/17 09:53:35 ph10 Exp $

# Makefile for PCRE (Perl-Compatible Regular Expression) library for use by
# Exim. This is a tailored Makefile, not the normal one that comes with the
# PCRE distribution.

# These variables are in practice overridden from the Exim Makefile.

AR = ar cq
CC = gcc -O2 -Wall
CFLAGS =
RANLIB = @true

##############################################################################

OBJ = maketables.o get.o pcre.o study.o

all:            libpcre.a ../pcretest

../pcretest: libpcre.a pcretest.o
		@echo "$(CC) -o pcretest"
		$(FE)$(CC) $(CFLAGS) -o ../pcretest pcretest.o libpcre.a

libpcre.a:      $(OBJ)
		-rm -f libpcre.a
		@echo "$(AR) libpcre.a"
		$(FE)$(AR) libpcre.a $(OBJ)
		$(RANLIB) libpcre.a

pcre.o:         chartables.c pcre.c config.h pcre.h internal.h Makefile
		@echo "$(CC) pcre.c"
		$(FE)$(CC) -c $(CFLAGS) pcre.c

maketables.o:   maketables.c config.h pcre.h internal.h Makefile
		@echo "$(CC) maketables.c"
		$(FE)$(CC) -c $(CFLAGS) maketables.c

get.o:          get.c pcre.h config.h internal.h Makefile
		@echo "$(CC) get.c"
		$(FE)$(CC) -c $(CFLAGS) get.c

study.o:        study.c pcre.h config.h internal.h Makefile
		@echo "$(CC) study.c"
		$(FE)$(CC) -c $(CFLAGS) study.c

pcretest.o:     pcretest.c config.h pcre.h internal.h Makefile
		@echo "$(CC) pcretest.c"
		$(FE)$(CC) -c -DNOPOSIX $(CFLAGS) -I. pcretest.c

# An auxiliary program makes the default character table source

chartables.c:   dftables
		./dftables chartables.c

dftables:       dftables.c maketables.c config.h pcre.h internal.h Makefile
		@echo "$(CC) -o dftables dftables.c"
		$(FE)$(CC) -o dftables $(CFLAGS) dftables.c

# End
