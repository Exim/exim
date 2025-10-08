# Make file for building Exim's lookup modules.
# This is called from the main make file, after cd'ing
# to the lookups subdirectory.
#
# Copyright (c) The Exim Maintainers 2021 - 2025

# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below. This is done by scripts/lookups-Makefile.

# When adding a new driver here, attend also to scripts/lookups-Makefile,
# scripts/MakeLinks and src/drtables.c

# MAGIC-TAG-MODS-OBJ-RULES-GO-HERE

all:             Makefile lookups.a $(MODS)

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

cdb.o cdb.so:           $(HDRS) cdb.c
dbmdb.o dbmdb.so:       $(HDRS) dbmdb.c
dnsdb.o dnsdb.so:       $(HDRS) dnsdb.c
dsearch.o dsearch.so:   $(HDRS) dsearch.c
ldap.o ldap.so:         $(HDRS) ldap.c
lmdb.o lmdb.so:         $(HDRS) lmdb.c
json.o json.so:         $(HDRS) json.c
lsearch.o lsearch.so:   $(HDRS) lsearch.c
mysql.o mysql.so:       $(HDRS) mysql.c
nis.o nis.so:           $(HDRS) nis.c
nisplus.o nisplus.so:   $(HDRS) nisplus.c
nmh.o nmh.so:		$(HDRS) nmh.c
oracle.o oracle.so:     $(HDRS) oracle.c
passwd.o passwd.so:     $(HDRS) passwd.c
pgsql.o pgsql.so:       $(HDRS) pgsql.c
psl.o psl.so:       	$(HDRS) psl.c
readsock.o readsock.so: $(HDRS) readsock.c
redis.o redis.so:       $(HDRS) redis.c
spf.o spf.so:           $(HDRS) spf.c
sqlite.o sqlite.so:     $(HDRS) sqlite.c
testdb.o testdb.so:     $(HDRS) testdb.c
whoson.o whoson.so:     $(HDRS) whoson.c

Makefile: ../../src/lookups/Makefile
	@echo " "
	@echo "*** lookups/Makefile needs rebuilding"
	@echo "*** Please run \"make makefile\" at top level"
	@echo " "
	@false

# End
