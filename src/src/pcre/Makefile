# $Cambridge: exim/src/src/pcre/Makefile,v 1.5 2005/10/03 09:56:42 ph10 Exp $

# Makefile for PCRE (Perl-Compatible Regular Expression) library for use by
# Exim. This is a tailored Makefile, not the normal one that comes with the
# PCRE distribution.

# These variables are in practice overridden from the Exim Makefile.

AR = ar cq
CC = gcc -O2 -Wall
CFLAGS =
RANLIB = @true

##############################################################################

OBJ = pcre_maketables.o chartables.o pcre_fullinfo.o pcre_get.o \
      pcre_globals.o pcre_compile.o pcre_config.o pcre_exec.o pcre_printint.o \
      pcre_study.o pcre_tables.o pcre_try_flipped.o pcre_version.o

all:            libpcre.a ../pcretest

../pcretest: libpcre.a pcretest.o
		@echo "$(CC) -o ../pcretest pcretest.o libpcre.a"
		$(FE)$(CC) $(CFLAGS) -o ../pcretest pcretest.o libpcre.a

libpcre.a:      $(OBJ)
		-rm -f libpcre.a
		@echo "$(AR) libpcre.a"
		$(FE)$(AR) libpcre.a $(OBJ)
		$(RANLIB) libpcre.a

chartables.o:   chartables.c pcre_compile.c config.h pcre.h pcre_internal.h Makefile
		@echo "$(CC) chartables.c"
		$(FE)$(CC) -c $(CFLAGS) chartables.c

pcre_compile.o: pcre_compile.c config.h pcre.h pcre_internal.h Makefile
		@echo "$(CC) pcre_compile.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_compile.c

pcre_config.o:  pcre_config.c config.h pcre.h pcre_internal.h Makefile
		@echo "$(CC) pcre_config.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_config.c

pcre_exec.o:    chartables.c pcre_exec.c config.h pcre.h pcre_internal.h Makefile
		@echo "$(CC) pcre_exec.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_exec.c

pcre_maketables.o: pcre_maketables.c config.h pcre.h pcre_internal.h Makefile
		@echo "$(CC) pcre_maketables.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_maketables.c

pcre_fullinfo.o: pcre_fullinfo.c pcre.h config.h pcre_internal.h Makefile
		@echo "$(CC) pcre_fullinfo.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_fullinfo.c

pcre_get.o:     pcre_get.c pcre.h config.h pcre_internal.h Makefile
		@echo "$(CC) pcre_get.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_get.c

pcre_globals.o: pcre_globals.c pcre.h config.h pcre_internal.h Makefile
		@echo "$(CC) pcre_globals.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_globals.c

pcre_printint.o: pcre_printint.c pcre.h config.h pcre_internal.h Makefile
		@echo "$(CC) pcre_printint.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_printint.c

pcre_study.o:   pcre_study.c pcre.h config.h pcre_internal.h Makefile
		@echo "$(CC) pcre_study.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_study.c

pcre_tables.o:  pcre_tables.c pcre.h config.h pcre_internal.h Makefile
		@echo "$(CC) pcre_tables.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_tables.c

pcre_try_flipped.o: pcre_try_flipped.c pcre.h config.h pcre_internal.h Makefile
		@echo "$(CC) pcre_try_flipped.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_try_flipped.c

pcre_version.o: pcre_version.c config.h pcre.h pcre_internal.h Makefile
		@echo "$(CC) pcre_version.c"
		$(FE)$(CC) -c $(CFLAGS) pcre_version.c

pcretest.o:     pcretest.c config.h pcre.h pcre_internal.h Makefile
		@echo "$(CC) pcretest.c"
		$(FE)$(CC) -c -DNOPOSIX -DNODFA -DNOUTF8 -DNOINFOCHECK $(CFLAGS) -I. pcretest.c

# An auxiliary program makes the default character table source

chartables.c:   dftables
		./dftables chartables.c

dftables:       dftables.c pcre_maketables.c config.h pcre.h pcre_internal.h Makefile
		@echo "$(CC) dftables.c"
		$(FE)$(CC) -o dftables $(CFLAGS) dftables.c

# End
