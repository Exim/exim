# Make file for building a library containing all the available routers and
# calling it routers.a. This is called from the main make file, after cd'ing
# to the directors subdirectory. The library also contains functions that
# are called only from within the individual routers.
#
# Copyright (c) The Exim Maintainers 2021 - 2024

# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below. This is done by scripts/drivers-Makefile with
#     definitions from scripts/Configure-Makefile.

# MAGIC-TAG-MODS-OBJ-RULES-GO-HERE

all:             routers.a $(MODS)

routers.a:       $(OBJ)
		 @$(RM_COMMAND) -f routers.a
		 @echo "$(AR) routers.a"
		 @$(AR) routers.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c .so
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

.c.so:;          @echo "$(CC) -shared $*.c"
		 $(FE)$(CC) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) $(INCLUDE) $(DLFLAGS) $*.c -o $@



$(OBJ) $(MOD): $(HDRS) rf_functions.h

accept.o accept.so:             accept.c       accept.h
dnslookup.o dnslookup.so:       dnslookup.c    dnslookup.h
ipliteral.o ipliteral.so:       ipliteral.c    ipliteral.h
iplookup.o iplookup.so:         iplookup.c     iplookup.h
manualroute.o manualroute.so:   manualroute.c  manualroute.h
queryprogram.o queryprogram.so: queryprogram.c queryprogram.h
redirect.o redirect.so:         redirect.c     redirect.h

# End
