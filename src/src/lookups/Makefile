# $Cambridge: exim/src/src/lookups/Makefile,v 1.9 2009/06/10 07:34:05 tom Exp $
#
# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below.

# Make file for building all the available lookups.
# This is called from the main make file, after cd'ing
# to the lookups subdirectory.

# because the variable is EXPERIMENTAL_SPF and not LOOKUP_SPF
# we put this one here by default and compile a dummy if
# EXPERIMENTAL_SPF is not defined
OBJ=spf.o
MODS=

# MAGIC-TAG-MODS-OBJ-RULES-GO-HERE


all:             lookups.a lf_quote.o lf_check_file.o lf_sqlperform.o $(MODS)

lookups.a:       $(OBJ)
		 @$(RM_COMMAND) -f lookups.a
		 @echo "$(AR) lookups.a"
		 @$(AR) lookups.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c .so
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

.c.so:;          @echo "$(CC) -shared $*.c"
		 $(FE)$(CC) $(LOOKUP_$*_INCLUDE) $(LOOKUP_$*_LIBS) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) $(INCLUDE) $(DLFLAGS) $*.c -o $@

lf_check_file.o: $(HDRS) lf_check_file.c  lf_functions.h
lf_quote.o:      $(HDRS) lf_quote.c       lf_functions.h
lf_sqlperform.o: $(HDRS) lf_sqlperform.c  lf_functions.h

cdb.o:           $(HDRS) cdb.c
dbmdb.o:         $(HDRS) dbmdb.c
dnsdb.o:         $(HDRS) dnsdb.c
dsearch.o:       $(HDRS) dsearch.c
ibase.o:         $(HDRS) ibase.c
ldap.o:          $(HDRS) ldap.c
lsearch.o:       $(HDRS) lsearch.c
mysql.o:         $(HDRS) mysql.c
nis.o:           $(HDRS) nis.c
nisplus.o:       $(HDRS) nisplus.c
oracle.o:        $(HDRS) oracle.c
passwd.o:        $(HDRS) passwd.c
pgsql.o:         $(HDRS) pgsql.c
spf.o:           $(HDRS) spf.c
sqlite.o:        $(HDRS) sqlite.c
testdb.o:        $(HDRS) testdb.c
whoson.o:        $(HDRS) whoson.c

cdb.so:           $(HDRS) cdb.c
dbmdb.so:         $(HDRS) dbmdb.c
dnsdb.so:         $(HDRS) dnsdb.c
dsearch.so:       $(HDRS) dsearch.c
ibase.so:         $(HDRS) ibase.c
ldap.so:          $(HDRS) ldap.c
lsearch.so:       $(HDRS) lsearch.c
mysql.so:         $(HDRS) mysql.c
nis.so:           $(HDRS) nis.c
nisplus.so:       $(HDRS) nisplus.c
oracle.so:        $(HDRS) oracle.c
passwd.so:        $(HDRS) passwd.c
pgsql.so:         $(HDRS) pgsql.c
spf.so:           $(HDRS) spf.c
sqlite.so:        $(HDRS) sqlite.c
testdb.so:        $(HDRS) testdb.c
whoson.so:        $(HDRS) whoson.c

# End
