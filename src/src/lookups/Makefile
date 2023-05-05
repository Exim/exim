# Make file for building Exim's lookup modules.
# This is called from the main make file, after cd'ing
# to the lookups subdirectory.
#
# Copyright (c) The Exim Maintainers 2021

# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below.

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

cdb.o:           $(HDRS) cdb.c            lf_functions.h
dbmdb.o:         $(HDRS) dbmdb.c          lf_functions.h
dnsdb.o:         $(HDRS) dnsdb.c          lf_functions.h
dsearch.o:       $(HDRS) dsearch.c        lf_functions.h
ibase.o:         $(HDRS) ibase.c          lf_functions.h
ldap.o:          $(HDRS) ldap.c           lf_functions.h
lmdb.o:          $(HDRS) lmdb.c
json.o:          $(HDRS) json.c           lf_functions.h
lsearch.o:       $(HDRS) lsearch.c        lf_functions.h
mysql.o:         $(HDRS) mysql.c          lf_functions.h
nis.o:           $(HDRS) nis.c            lf_functions.h
nisplus.o:       $(HDRS) nisplus.c        lf_functions.h
oracle.o:        $(HDRS) oracle.c
passwd.o:        $(HDRS) passwd.c
pgsql.o:         $(HDRS) pgsql.c          lf_functions.h
readsock.o:      $(HDRS) readsock.c       lf_functions.h
redis.o:         $(HDRS) redis.c          lf_functions.h
spf.o:           $(HDRS) spf.c            lf_functions.h
sqlite.o:        $(HDRS) sqlite.c         lf_functions.h
testdb.o:        $(HDRS) testdb.c         lf_functions.h
whoson.o:        $(HDRS) whoson.c

cdb.so:           $(HDRS) cdb.c           lf_functions.h
dbmdb.so:         $(HDRS) dbmdb.c         lf_functions.h
dnsdb.so:         $(HDRS) dnsdb.c         lf_functions.h
dsearch.so:       $(HDRS) dsearch.c       lf_functions.h
ibase.so:         $(HDRS) ibase.c         lf_functions.h
json.so:          $(HDRS) json.c          lf_functions.h
ldap.so:          $(HDRS) ldap.c
lmdb.so:          $(HDRS) lmdb.c          lf_functions.h
lsearch.so:       $(HDRS) lsearch.c       lf_functions.h
mysql.so:         $(HDRS) mysql.c         lf_functions.h
nis.so:           $(HDRS) nis.c           lf_functions.h
nisplus.so:       $(HDRS) nisplus.c       lf_functions.h
oracle.so:        $(HDRS) oracle.c
passwd.so:        $(HDRS) passwd.c
pgsql.so:         $(HDRS) pgsql.c         lf_functions.h
redis.so:         $(HDRS) redis.c         lf_functions.h
spf.so:           $(HDRS) spf.c           lf_functions.h
sqlite.so:        $(HDRS) sqlite.c        lf_functions.h
testdb.so:        $(HDRS) testdb.c        lf_functions.h
whoson.so:        $(HDRS) whoson.c

# End
