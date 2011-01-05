# $Cambridge: exim/src/src/lookups/Makefile,v 1.9 2009/06/10 07:34:05 tom Exp $

# Make file for building all the available lookups.
# This is called from the main make file, after cd'ing
# to the lookups subdirectory.

# because the variable is EXPERIMENTAL_SPF and not LOOKUP_SPF
# we put this one here by default and compile a dummy if
# EXPERIMENTAL_SPF is not defined
OBJ=spf.o
MODS=

ifeq ($(LOOKUP_CDB),2)
MODS += cdb.so
LOOKUP_cdb_INCLUDE = $(LOOKUP_CDB_INCLUDE)
LOOKUP_cdb_LIBS = $(LOOKUP_CDB_LIBS)
else
ifneq ($(LOOKUP_CDB),)
OBJ += cdb.o
endif
endif

ifeq ($(LOOKUP_DBM),2)
MODS += dbmdb.so
LOOKUP_dbmdb_INCLUDE = $(LOOKUP_DBM_INCLUDE)
LOOKUP_dbmdb_LIBS = $(LOOKUP_DBM_LIBS)
else
ifneq ($(LOOKUP_DBM),)
OBJ += dbmdb.o
endif
endif

ifeq ($(LOOKUP_DNSDB),2)
MODS += dnsdb.so
LOOKUP_dnsdb_INCLUDE = $(LOOKUP_DNSDB_INCLUDE)
LOOKUP_dnsdb_LIBS = $(LOOKUP_DNSDB_LIBS)
else
ifneq ($(LOOKUP_DNSDB),)
OBJ += dnsdb.o
endif
endif

ifeq ($(LOOKUP_DSEARCH),2)
MODS += dsearch.so
LOOKUP_dsearch_INCLUDE = $(LOOKUP_DSEARCH_INCLUDE)
LOOKUP_dsearch_LIBS = $(LOOKUP_DSEARCH_LIBS)
else
ifneq ($(LOOKUP_DSEARCH),)
OBJ += dsearch.o
endif
endif

ifeq ($(LOOKUP_IBASE),2)
MODS += ibase.so
LOOKUP_ibase_INCLUDE = $(LOOKUP_IBASE_INCLUDE)
LOOKUP_ibase_LIBS = $(LOOKUP_IBASE_LIBS)
else
ifneq ($(LOOKUP_IBASE),)
OBJ += ibase.o
endif
endif

ifneq ($(LOOKUP_LDAP),)
OBJ += ldap.o
endif

ifeq ($(LOOKUP_LSEARCH),2)
MODS += lsearch.so
LOOKUP_lsearch_INCLUDE = $(LOOKUP_LSEARCH_INCLUDE)
LOOKUP_lsearch_LIBS = $(LOOKUP_LSEARCH_LIBS)
else
ifneq ($(LOOKUP_LSEARCH),)
OBJ += lsearch.o
endif
endif

ifeq ($(LOOKUP_MYSQL),2)
MODS += mysql.so
LOOKUP_mysql_INCLUDE = $(LOOKUP_MYSQL_INCLUDE)
LOOKUP_mysql_LIBS = $(LOOKUP_MYSQL_LIBS)
else
ifneq ($(LOOKUP_MYSQL),)
OBJ += mysql.o
endif
endif

ifeq ($(LOOKUP_NIS),2)
MODS += nis.so
LOOKUP_nis_INCLUDE = $(LOOKUP_NIS_INCLUDE)
LOOKUP_nis_LIBS = $(LOOKUP_NIS_LIBS)
else
ifneq ($(LOOKUP_NIS),)
OBJ += nis.o
endif
endif

ifeq ($(LOOKUP_NISPLUS),2)
MODS += nisplus.so
LOOKUP_nisplus_INCLUDE = $(LOOKUP_NISPLUS_INCLUDE)
LOOKUP_nisplus_LIBS = $(LOOKUP_NISPLUS_LIBS)
else
ifneq ($(LOOKUP_NISPLUS),)
OBJ += nisplus.o
endif
endif

ifeq ($(LOOKUP_ORACLE),2)
MODS += oracle.so
LOOKUP_oracle_INCLUDE = $(LOOKUP_ORACLE_INCLUDE)
LOOKUP_oracle_LIBS = $(LOOKUP_ORACLE_LIBS)
else
ifneq ($(LOOKUP_ORACLE),)
OBJ += oracle.o
endif
endif

ifeq ($(LOOKUP_PASSWD),2)
MODS += passwd.so
LOOKUP_passwd_INCLUDE = $(LOOKUP_PASSWD_INCLUDE)
LOOKUP_passwd_LIBS = $(LOOKUP_PASSWD_LIBS)
else
ifneq ($(LOOKUP_PASSWD),)
OBJ += passwd.o
endif
endif

ifeq ($(LOOKUP_PGSQL),2)
MODS += pgsql.so
LOOKUP_pgsql_INCLUDE = $(LOOKUP_PGSQL_INCLUDE)
LOOKUP_pgsql_LIBS = $(LOOKUP_PGSQL_LIBS)
else
ifneq ($(LOOKUP_PGSQL),)
OBJ += pgsql.o
endif
endif

ifeq ($(LOOKUP_SQLITE),2)
MODS += sqlite.so
LOOKUP_sqlite_INCLUDE = $(LOOKUP_SQLITE_INCLUDE)
LOOKUP_sqlite_LIBS = $(LOOKUP_SQLITE_LIBS)
else
ifneq ($(LOOKUP_SQLITE),)
OBJ += sqlite.o
endif
endif

ifeq ($(LOOKUP_TESTDB),2)
MODS += testdb.so
LOOKUP_testdb_INCLUDE = $(LOOKUP_TESTDB_INCLUDE)
LOOKUP_testdb_LIBS = $(LOOKUP_TESTDB_LIBS)
else
ifneq ($(LOOKUP_TESTDB),)
OBJ += testdb.o
endif
endif

ifeq ($(LOOKUP_WHOSON),2)
MODS += whoson.so
LOOKUP_whoson_INCLUDE = $(LOOKUP_WHOSON_INCLUDE)
LOOKUP_whoson_LIBS = $(LOOKUP_WHOSON_LIBS)
else
ifneq ($(LOOKUP_WHOSON),)
OBJ += whoson.o
endif
endif


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
		 $(FE)$(CC) $(LOOKUP_$*_INCLUDE) $(LOOKUP_$*_LIBS) -DDYNLOOKUP -shared -rdynamic $(CFLAGS) $(INCLUDE) $(DLFLAGS) $*.c -o $@

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
