/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This header file contains macro definitions so that a variety of DBM
libraries can be used by Exim. Nigel Metheringham provided the original set for
Berkeley DB 1.x in native mode and ndbm. Subsequently, versions for Berkeley DB
2.x and 3.x were added. Later still, support for tdb was added, courtesy of
James Antill. Most recently, support for native mode gdbm was added, with code
from Pierre A. Humblet, so Exim could be made to work with Cygwin.

For convenience, the definitions of the structures used in the various hints
databases are also kept in this file, which is used by the maintenance
utilities as well as the main Exim binary.

A key/value store is supported (only).  Keys are strings; values arbitrary
binary blobs.

The API is:
  Functions:
    exim_lockfile_needed 	API semantics predicate
    exim_dbopen
    exim_dbclose
    exim_dbget
    exim_dbput
    exim_dbputb			non-overwriting put
    exim_dbdel
    exim_dbcreate_cursor
    exim_dbscan			get, and bump cursor
    exim_dbdelete_cursor
    exim_datum_init
    exim_datum_size_get/set
    exim_datum_data_get/set
    exim_datum_free
  Defines:
    EXIM_DB		access handle
    EXIM_CURSOR		datatype for cursor
    EXIM_DATUM		datatype for "value"
    EXIM_DBTYPE		text for logging & debuug

Selection of the shim layer implementation, and backend, is by #defines.

The users of this API are:
  hintsdb interface	dbfn.c
  hintsdb utilities	exim_dbutil.c and exim_dbmvuild.c
  dbmdb lookup		lookups/dbmdb,c
  autoreply transport	transports/autoreply.c

Note that the dbmdb lookup use, bypassing the dbfn.c layer,
means that no file-locking is done.
XXX This feels like a layering violation; I don't see it commented on
anywhere.

Future: consider re-architecting to support caching of the open-handle
for hintsdb uses (the dbmdb use gets that already).  This would need APIs
for transaction locks.  Perhaps merge the implementation with the lookups
layer, in some way, for the open-handle caching (since that manages closes
required by Exim's process transisitions)?
*/

#ifndef HINTSDB_H
#define HINTSDB_H


#ifdef USE_SQLITE
# if defined(USE_DB) || defined(USE_GDBM) || defined(USE_TDB)
#  error USE_SQLITE conflict with alternate definition
# endif

/* ********************* sqlite3 interface ************************ */

# include <sqlite3.h>

/* Basic DB type */
# define EXIM_DB sqlite3

# define EXIM_CURSOR int

# /* The datum type used for queries */
# define EXIM_DATUM blob

/* Some text for messages */
# define EXIM_DBTYPE "sqlite3"

# /* Access functions */

static inline BOOL
exim_lockfile_needed(void)
{
return FALSE;	/* We do transaction; no extra locking needed */
}

/* EXIM_DBOPEN - return pointer to an EXIM_DB, NULL if failed */
static inline EXIM_DB *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
EXIM_DB * dbp;
int ret, sflags = flags & O_RDWR ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY;
if (flags & O_CREAT) sflags |= SQLITE_OPEN_CREATE;
if ((ret = sqlite3_open_v2(CCS name, &dbp, sflags, NULL)) == SQLITE_OK)
  {
  sqlite3_busy_timeout(dbp, 5000);
  ret = sqlite3_exec(dbp, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  if (ret == SQLITE_OK && flags & O_CREAT)
    ret = sqlite3_exec(dbp,
	    "CREATE TABLE IF NOT EXISTS tbl (ky TEXT PRIMARY KEY, dat BLOB);",
	    NULL, NULL, NULL);
  if (ret != SQLITE_OK)
    sqlite3_close(dbp);
  }
//else
//  fprintf(stderr, "sqlite3_open_v2: %s\n", sqlite3_errmsg(dbp));
return ret == SQLITE_OK ? dbp : NULL;
}

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
/* note we alloc'n'copy - the caller need not do so */
/* result has a NUL appended, but the length is as per the DB */

static inline BOOL
exim_dbget__(EXIM_DB * dbp, const uschar * s, EXIM_DATUM * res)
{
sqlite3_stmt * statement;
int ret;

res->len = (size_t) -1;
/* fprintf(stderr, "exim_dbget__(%s)\n", s); */
if ((ret = sqlite3_prepare_v2(dbp, CCS s, -1, &statement, NULL)) != SQLITE_OK)
  {
/* fprintf(stderr, "prepare fail: %s\n", sqlite3_errmsg(dbp)); */
  return FALSE;
  }
if (sqlite3_step(statement) != SQLITE_ROW)
  {
/* fprintf(stderr, "step fail: %s\n", sqlite3_errmsg(dbp)); */
  sqlite3_finalize(statement);
  return FALSE;
  }

res->len = sqlite3_column_bytes(statement, 0);
# ifdef COMPILE_UTILITY
if (!(res->data = malloc(res->len +1)))
  { sqlite3_finalize(statement); return FALSE; }
# else
res->data = store_get(res->len +1, GET_TAINTED);
# endif
memcpy(res->data, sqlite3_column_blob(statement, 0), res->len);
res->data[res->len] = '\0';
/* fprintf(stderr, "res %d bytes: '%.*s'\n", (int)res->len, (int)res->len, res->data); */
sqlite3_finalize(statement);
return TRUE;
}

static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
# define FMT "SELECT dat FROM tbl WHERE ky = '%.*s';"
uschar * qry;
int i;
BOOL ret;

# ifdef COMPILE_UTILITY
/* fprintf(stderr, "exim_dbget(k len %d '%.*s')\n", (int)key->len, (int)key->len, key->data); */
i = snprintf(NULL, 0, FMT, (int) key->len, key->data)+1;
if (!(qry = malloc(i)))
  return FALSE;
snprintf(CS qry, i, FMT, (int) key->len, key->data);
ret = exim_dbget__(dbp, qry, res);
free(qry);
# else
/* fprintf(stderr, "exim_dbget(k len %d '%.*s')\n", (int)key->len, (int)key->len, key->data); */
qry = string_sprintf(FMT, (int) key->len, key->data);
ret = exim_dbget__(dbp, qry, res);
# endif

return ret;
# undef FMT
}

/**/
# define EXIM_DBPUTB_OK  0
# define EXIM_DBPUTB_DUP (-1)

static inline int
exim_s_dbp(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data, const uschar * alt)
{
int hlen = data->len * 2, off = 0, res;
# define FMT "INSERT OR %s INTO tbl (ky,dat) VALUES ('%.*s', X'%.*s');"
uschar * qry;
# ifdef COMPILE_UTILITY
uschar * hex = malloc(hlen+1);
if (!hex) return EXIM_DBPUTB_DUP;	/* best we can do */
# else
uschar * hex = store_get(hlen+1, data->data);
# endif

for (const uschar * s = data->data, * t = s + data->len; s < t; s++, off += 2)
  sprintf(CS hex + off, "%02X", *s);

# ifdef COMPILE_UTILITY
res = snprintf(CS hex, 0, FMT, alt, (int) key->len, key->data, hlen, hex) +1;
if (!(qry = malloc(res))) return EXIM_DBPUTB_DUP;
snprintf(CS qry, res, FMT, alt, (int) key->len, key->data, hlen, hex);
/* fprintf(stderr, "exim_s_dbp(%s)\n", qry); */
res = sqlite3_exec(dbp, CS qry, NULL, NULL, NULL);
free(qry);
free(hex);
# else
qry = string_sprintf(FMT, alt, (int) key->len, key->data, hlen, hex);
/* fprintf(stderr, "exim_s_dbp(%s)\n", qry); */
res = sqlite3_exec(dbp, CS qry, NULL, NULL, NULL);
/* fprintf(stderr, "exim_s_dbp res %d\n", res); */
# endif

if (res != SQLITE_OK)
  fprintf(stderr, "sqlite3_exec: %s\n", sqlite3_errmsg(dbp));

return res == SQLITE_OK ? EXIM_DBPUTB_OK : EXIM_DBPUTB_DUP;
# undef FMT
}

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */

static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
/* fprintf(stderr, "exim_dbput()\n"); */
(void) exim_s_dbp(dbp, key, data, US"REPLACE");
return 0;
}

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */

/* Returns from EXIM_DBPUTB */

static inline int
exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
return exim_s_dbp(dbp, key, data, US"ABORT");
}

/* EXIM_DBDEL */
static inline int
exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key)
{
# define FMT "DELETE FROM tbl WHERE ky = '%.*s';"
uschar * qry;
int res;

# ifdef COMPILE_UTILITY
res = snprintf(NULL, 0, FMT, (int) key->len, key->data) +1; /* res includes nul */
if (!(qry = malloc(res))) return SQLITE_NOMEM;
snprintf(CS qry, res, FMT, (int) key->len, key->data);
res = sqlite3_exec(dbp, CS qry, NULL, NULL, NULL);
free(qry);
# else
qry = string_sprintf(FMT, (int) key->len, key->data);
res = sqlite3_exec(dbp, CS qry, NULL, NULL, NULL);
# endif

return res;
# undef FMT
}


/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */
/* Cursors are inefficiently emulated by repeating searches */

static inline EXIM_CURSOR *
exim_dbcreate_cursor(EXIM_DB * dbp)
{
# ifdef COMPILE_UTILITY
EXIM_CURSOR * c = malloc(sizeof(int));
if (!c) return NULL;
# else
EXIM_CURSOR * c = store_malloc(sizeof(int));
# endif
*c = 0;
return c;
}

/* EXIM_DBSCAN */
/* Note that we return the (next) key, not the record value */
static inline BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res, BOOL first,
  EXIM_CURSOR * cursor)
{
# define FMT "SELECT ky FROM tbl ORDER BY ky LIMIT 1 OFFSET %d;"
uschar * qry;
int i;
BOOL ret;

# ifdef COMPILE_UTILITY
i = snprintf(NULL, 0, FMT, *cursor)+1;
if (!(qry = malloc(i))) return FALSE;
snprintf(CS qry, i, FMT, *cursor);
/* fprintf(stderr, "exim_dbscan(%s)\n", qry); */
ret = exim_dbget__(dbp, qry, key);
free(qry);
/* fprintf(stderr, "exim_dbscan ret %c\n", ret ? 'T':'F'); */
# else
qry = string_sprintf(FMT, *cursor);
/* fprintf(stderr, "exim_dbscan(%s)\n", qry); */
ret = exim_dbget__(dbp, qry, key);
/* fprintf(stderr, "exim_dbscan ret %c\n", ret ? 'T':'F'); */
# endif
if (ret) *cursor = *cursor + 1;
return ret;
# undef FMT
}

/* EXIM_DBDELETE_CURSOR - terminate scanning operation. */
static inline void
exim_dbdelete_cursor(EXIM_CURSOR * cursor)
{
# ifdef COMPILE_UTILITY
free(cursor);
# else
store_free(cursor);
# endif
}


/* EXIM_DBCLOSE */
static void
exim_dbclose__(EXIM_DB * dbp)
{
(void) sqlite3_exec(dbp, "COMMIT TRANSACTION;", NULL, NULL, NULL);
sqlite3_close(dbp);
}


/* Datum access */

static uschar *
exim_datum_data_get(EXIM_DATUM * dp)
{ return US dp->data; }
static void
exim_datum_data_set(EXIM_DATUM * dp, void * s)
{ dp->data = s; }
 
static unsigned
exim_datum_size_get(EXIM_DATUM * dp)
{ return dp->len; }
static void
exim_datum_size_set(EXIM_DATUM * dp, unsigned n)
{ dp->len = n; }



static inline void
exim_datum_init(EXIM_DATUM * dp)
{ dp->data = NULL; }			/* compiler quietening */

/* No free needed for a datum */

static inline void
exim_datum_free(EXIM_DATUM * dp)
{ }

/* size limit */

# define EXIM_DB_RLIMIT	150






#elif defined(USE_TDB)

# if defined(USE_DB) || defined(USE_GDBM) || defined(USE_SQLITE)
#  error USE_TDB conflict with alternate definition
# endif

/* ************************* tdb interface ************************ */
/*XXX https://manpages.org/tdb/3 mentions concurrent writes.
Could we lose the file lock? */

# include <tdb.h>

/* Basic DB type */
# define EXIM_DB TDB_CONTEXT

/* Cursor type: tdb uses the previous "key" in _nextkey() (really it wants
tdb_traverse to be called) */
# define EXIM_CURSOR TDB_DATA

/* The datum type used for queries */
# define EXIM_DATUM TDB_DATA

/* Some text for messages */
# define EXIM_DBTYPE "tdb"

/* Access functions */

static inline BOOL
exim_lockfile_needed(void)
{
return TRUE;
}

/* EXIM_DBOPEN - return pointer to an EXIM_DB, NULL if failed */
static inline EXIM_DB *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
return tdb_open(CS name, 0, TDB_DEFAULT, flags, mode);
}

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
*res = tdb_fetch(dbp, *key);	/* A struct arg and return!! */
return res->dptr != NULL;
}

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{ return tdb_store(dbp, *key, *data, TDB_REPLACE); }

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
static inline int
exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{ return tdb_store(dbp, *key, *data, TDB_INSERT); }

/* Returns from EXIM_DBPUTB */

# define EXIM_DBPUTB_OK  0
# define EXIM_DBPUTB_DUP (-1)

/* EXIM_DBDEL */
static inline int
exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key)
{ return tdb_delete(dbp, *key); }

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */
static inline EXIM_CURSOR *
exim_dbcreate_cursor(EXIM_DB * dbp)
{
# ifdef COMPILE_UTILITY
EXIM_CURSOR * c = malloc(sizeof(TDB_DATA));
# else
EXIM_CURSOR * c = store_malloc(sizeof(TDB_DATA));
# endif
c->dptr = NULL;
return c;
}

/* EXIM_DBSCAN - This is complicated because we have to free the last datum
free() must not die when passed NULL */

static inline BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res, BOOL first,
  EXIM_CURSOR * cursor)
{
*key = first ? tdb_firstkey(dbp) : tdb_nextkey(dbp, *cursor);
free(cursor->dptr);
*cursor = *key;
return key->dptr != NULL;
}

/* EXIM_DBDELETE_CURSOR - terminate scanning operation. */
static inline void
exim_dbdelete_cursor(EXIM_CURSOR * cursor)
{ store_free(cursor); }

/* EXIM_DBCLOSE */
static inline void
exim_dbclose__(EXIM_DB * db)
{ tdb_close(db); }

/* Datum access */

static inline uschar *
exim_datum_data_get(EXIM_DATUM * dp)
{ return US dp->dptr; }
static inline void
exim_datum_data_set(EXIM_DATUM * dp, void * s)
{ dp->dptr = s; }

static inline unsigned
exim_datum_size_get(EXIM_DATUM * dp)
{ return dp->dsize; }
static inline void
exim_datum_size_set(EXIM_DATUM * dp, unsigned n)
{ dp->dsize = n; }

/* No initialization is needed. */

static inline void
exim_datum_init(EXIM_DATUM * d)
{ }

/* Free the stuff inside the datum. */

static inline void
exim_datum_free(EXIM_DATUM * d)
{
free(d->dptr);
d->dptr = NULL;
}

/* size limit */

# define EXIM_DB_RLIMIT	150






/********************* Berkeley db native definitions **********************/

#elif defined USE_DB

# if defined(USE_TDB) || defined(USE_GDBM) || defined(USE_SQLITE)
#  error USE_DB conflict with alternate definition
# endif

# include <db.h>

/* 1.x did no locking
   2.x had facilities, but exim does it's own
   3.x+ unknown
*/

/* We can distinguish between versions 1.x and 2.x/3.x by looking for a
definition of DB_VERSION_STRING, which is present in versions 2.x onwards. */

# ifdef DB_VERSION_STRING

#  if DB_VERSION_MAJOR >= 6
#   error Version 6 and later BDB API is not supported
#  endif

/* The API changed (again!) between the 2.x and 3.x versions */

# if DB_VERSION_MAJOR >= 3

/***************** Berkeley db 3.x/4.x native definitions ******************/

/* Basic DB type */
#  if DB_VERSION_MAJOR > 4 || (DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 1)
#   define EXIM_DB       DB_ENV
/* Cursor type, for scanning */
#   define EXIM_CURSOR   DBC

/* The datum type used for queries */
#   define EXIM_DATUM    DBT

/* Some text for messages */
#   define EXIM_DBTYPE   "db (v4.1+)"

/* Only more-recent versions.  5+ ? */
#   ifndef DB_FORCESYNC
#    define DB_FORCESYNC 0
#   endif

/* Error callback */
/* For Berkeley DB >= 2, we can define a function to be called in case of DB
errors. This should help with debugging strange DB problems, e.g. getting "File
exists" when you try to open a db file. The API for this function was changed
at DB release 4.3. */

static inline void
dbfn_bdb_error_callback(const DB_ENV * dbenv, const char * pfx, const char * msg)
{
#ifndef MACRO_PREDEF 
log_write(0, LOG_MAIN, "Berkeley DB error: %s", msg);
#endif
}



/* Access functions (BDB 4.1+) */

static inline BOOL
exim_lockfile_needed(void)
{
return TRUE;
}

/* EXIM_DBOPEN - return pointer to an EXIM_DB, NULL if failed */
/* The API changed for DB 4.1. - and we also starting using the "env" with a
specified working dir, to avoid the DBCONFIG file trap. */

#   define ENV_TO_DB(env) ((DB *)(((EXIM_DB *)env)->app_private))

static inline EXIM_DB *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
EXIM_DB * dbp;
DB * b;
if (  db_env_create(&dbp, 0) != 0
   || (dbp->set_errcall(dbp, dbfn_bdb_error_callback), 0)
   || dbp->open(dbp, CS dirname, DB_CREATE|DB_INIT_MPOOL|DB_PRIVATE, 0) != 0
   )
  return NULL;
if (db_create(&b, dbp, 0) == 0)
  {
  dbp->app_private = b;
  if (b->open(b, NULL, CS name, NULL,
	      flags & O_CREAT ? DB_HASH : DB_UNKNOWN,
	      flags & O_CREAT ? DB_CREATE
	      : flags & (O_WRONLY|O_RDWR) ? 0 : DB_RDONLY,
	      mode) == 0
	  )
    return dbp;

  b->close(b, 0);
  }
dbp->close(dbp, 0);
return NULL;
}

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
DB * b = ENV_TO_DB(dbp);
return b->get(b, NULL, key, res, 0) == 0;
}

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
DB * b = ENV_TO_DB(dbp);
return b->put(b, NULL, key, data, 0);
}

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
static inline int
exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
DB * b = ENV_TO_DB(dbp);
return b->put(b, NULL, key, data, DB_NOOVERWRITE);
}

/* Return values from EXIM_DBPUTB */

#   define EXIM_DBPUTB_OK  0
#   define EXIM_DBPUTB_DUP DB_KEYEXIST

/* EXIM_DBDEL */
static inline int
exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key)
{
DB * b = ENV_TO_DB(dbp);
return b->del(b, NULL, key, 0);
}

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */

static inline EXIM_CURSOR *
exim_dbcreate_cursor(EXIM_DB * dbp)
{
DB * b = ENV_TO_DB(dbp);
EXIM_CURSOR * c;
b->cursor(b, NULL, &c, 0);
return c;
}

/* EXIM_DBSCAN - returns TRUE if data is returned, FALSE at end */
static inline BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data, BOOL first,
  EXIM_CURSOR * cursor)
{
return cursor->c_get(cursor, key, data, first ? DB_FIRST : DB_NEXT) == 0;
}

/* EXIM_DBDELETE_CURSOR - terminate scanning operation */
static inline void
exim_dbdelete_cursor(EXIM_CURSOR * cursor)
{ cursor->c_close(cursor); }

/* EXIM_DBCLOSE */
static inline void
exim_dbclose__(EXIM_DB * dbp_o)
{
DB_ENV * dbp = dbp_o;
DB * b = ENV_TO_DB(dbp);
b->close(b, 0);
dbp->close(dbp, DB_FORCESYNC);
}

/* Datum access */

static inline uschar *
exim_datum_data_get(EXIM_DATUM * dp)
{ return dp->data; }
static inline void
exim_datum_data_set(EXIM_DATUM * dp, void * s)
{ dp->data = s; }

static inline unsigned
exim_datum_size_get(EXIM_DATUM * dp)
{ return dp->size; }
static inline void
exim_datum_size_set(EXIM_DATUM * dp, unsigned n)
{ dp->size = n; }

/* The whole datum structure contains other fields that must be cleared
before use, but we don't have to free anything after reading data. */

static inline void
exim_datum_init(EXIM_DATUM * d)
{ memset(d, 0, sizeof(*d)); }

static inline void
exim_datum_free(EXIM_DATUM * d)
{ }

#  else	/* pre- 4.1 */

#   define EXIM_DB       DB

/* Cursor type, for scanning */
#   define EXIM_CURSOR   DBC

/* The datum type used for queries */
#   define EXIM_DATUM    DBT

/* Some text for messages */
#   define EXIM_DBTYPE   "db (v3/4)"

/* Access functions (BDB 3/4) */

static inline BOOL
exim_lockfile_needed(void)
{
return TRUE;
}

/* EXIM_DBOPEN - return pointer to an EXIM_DB, NULL if failed */
static inline EXIM_DB *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
EXIM_DB * dbp;
return db_create(&dbp, NULL, 0) == 0
  && (  dbp->set_errcall(dbp, dbfn_bdb_error_callback),
	dbp->open(dbp, CS name, NULL,
	  flags & O_CREAT ? DB_HASH : DB_UNKNOWN,
	  flags & O_CREAT ? DB_CREATE
	  : flags & (O_WRONLY|O_RDWR) ? 0 : DB_RDONLY,
	  mode)
     ) == 0
  ? dbp : NULL;
}

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{ return dbp->get(dbp, NULL, key, res, 0) == 0; }

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{ return dbp->put(dbp, NULL, key, data, 0); }

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
static inline int
exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{ return dbp->put(dbp, NULL, key, data, DB_NOOVERWRITE); }

/* Return values from EXIM_DBPUTB */

#   define EXIM_DBPUTB_OK  0
#   define EXIM_DBPUTB_DUP DB_KEYEXIST

/* EXIM_DBDEL */
static inline int
exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key)
{ return dbp->del(dbp, NULL, key, 0); }

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */

static inline EXIM_CURSOR *
exim_dbcreate_cursor(EXIM_DB * dbp)
{
EXIM_CURSOR * c;
dbp->cursor(dbp, NULL, &c, 0);
return c;
}

/* EXIM_DBSCAN - returns TRUE if data is returned, FALSE at end */
static inline BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data, BOOL first,
  EXIM_CURSOR * cursor)
{
return cursor->c_get(cursor, key, data, first ? DB_FIRST : DB_NEXT) == 0;
}

/* EXIM_DBDELETE_CURSOR - terminate scanning operation */
static inline void
exim_dbdelete_cursor(EXIM_CURSOR * cursor)
{ cursor->c_close(cursor); }

/* EXIM_DBCLOSE */
static inline void
exim_dbclose__(EXIM_DB * dbp)
{ dbp->close(dbp, 0); }

/* Datum access */

static inline uschar *
exim_datum_data_get(EXIM_DATUM * dp)
{ return US dp->dptr; }
static inline void
exim_datum_data_set(EXIM_DATUM * dp, void * s)
{ dp->dptr = s; }

static inline uschar *
exim_datum_size_get(EXIM_DATUM * dp)
{ return US dp->size; }
static inline void
exim_datum_size_set(EXIM_DATUM * dp, uschar * s)
{ dp->size = CS s; }

/* The whole datum structure contains other fields that must be cleared
before use, but we don't have to free anything after reading data. */

static inline void
exim_datum_init(EXIM_DATUM * d)
{ memset(d, 0, sizeof(*d)); }

static inline void
exim_datum_free(EXIM_DATUM * d)
{ }

#  endif


#  else /* DB_VERSION_MAJOR >= 3 */
#   error Berkeley DB versions earlier than 3 are not supported */
#  endif /* DB_VERSION_MAJOR */
# else
#  error Berkeley DB version 1 is no longer supported
# endif /* DB_VERSION_STRING */


/* all BDB versions */
/* size limit */

# define EXIM_DB_RLIMIT	150






/********************* gdbm interface definitions **********************/

#elif defined USE_GDBM
/*XXX TODO: exim's lockfile not needed? */

# if defined(USE_TDB) || defined(USE_DB) || defined(USE_SQLITE)
#  error USE_GDBM conflict with alternate definition
# endif

# include <gdbm.h>

/* Basic DB type */
typedef struct {
       GDBM_FILE gdbm;  /* Database */
       datum lkey;      /* Last key, for scans */
} EXIM_DB;

/* Cursor type, not used with gdbm: just set up a dummy */
# define EXIM_CURSOR int

/* The datum type used for queries */
# define EXIM_DATUM datum

/* Some text for messages */

# define EXIM_DBTYPE "gdbm"

/* Access functions (gdbm) */

static inline BOOL
exim_lockfile_needed(void)
{
return TRUE;
}

/* EXIM_DBOPEN - return pointer to an EXIM_DB, NULL if failed */
static inline EXIM_DB *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
EXIM_DB * dbp = malloc(sizeof(EXIM_DB));	/*XXX why not exim mem-mgmt? */
if (dbp)
  {
  dbp->lkey.dptr = NULL;
  dbp->gdbm = gdbm_open(CS name, 0,
    flags & O_CREAT ? GDBM_WRCREAT
    : flags & (O_RDWR|O_WRONLY) ? GDBM_WRITER : GDBM_READER,
    mode, 0);
  if (dbp->gdbm) return dbp;
  free(dbp);
  }
return NULL;
}

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
*res = gdbm_fetch(dbp->gdbm, *key);	/* A struct arg & return! */
return res->dptr != NULL;
}

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{ return gdbm_store(dbp->gdbm, *key, *data, GDBM_REPLACE); }

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
static inline int
exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{ return gdbm_store(dbp->gdbm, *key, *data, GDBM_INSERT); }

/* Returns from EXIM_DBPUTB */

# define EXIM_DBPUTB_OK  0
# define EXIM_DBPUTB_DUP 1

/* EXIM_DBDEL */
static inline int
exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key)
{ return gdbm_delete(dbp->gdbm, *key); }

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation (null) */
static inline EXIM_CURSOR *
exim_dbcreate_cursor(EXIM_DB * dbp)
{ return NULL; }

/* EXIM_DBSCAN */
static inline BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data, BOOL first,
  EXIM_CURSOR * cursor)
{
char * s;
*key = first ? gdbm_firstkey(dbp->gdbm) : gdbm_nextkey(dbp->gdbm, dbp->lkey);
if ((s = dbp->lkey.dptr)) free(s);
dbp->lkey = *key;
return key->dptr != NULL;
}

/* EXIM_DBDELETE_CURSOR - terminate scanning operation (null). */
static inline void
exim_dbdelete_cursor(EXIM_CURSOR * cursor)
{ }

/* EXIM_DBCLOSE */
static inline void
exim_dbclose__(EXIM_DB * dbp)
{
char * s;
gdbm_close(dbp->gdbm);
if ((s = dbp->lkey.dptr)) free(s);
free(dbp);
}

/* Datum access types */

static inline uschar *
exim_datum_data_get(EXIM_DATUM * dp)
{ return US dp->dptr; }
static inline void
exim_datum_data_set(EXIM_DATUM * dp, void * s)
{ dp->dptr = s; }

static inline unsigned
exim_datum_size_get(EXIM_DATUM * dp)
{ return dp->dsize; }
static inline void
exim_datum_size_set(EXIM_DATUM * dp, unsigned n)
{ dp->dsize = n; }

/* There's no clearing required before use, but we have to free the dptr
after reading data. */

static inline void
exim_datum_init(EXIM_DATUM * d)
{ }

static inline void
exim_datum_free(EXIM_DATUM * d)
{ free(d->dptr); }

/* size limit. GDBM is int-max limited, but we want to be less silly */

# define EXIM_DB_RLIMIT	150

#else  /* USE_GDBM */






/* If none of USE_DB, USG_GDBM, USE_SQLITE or USE_TDB are set,
the default is the NDBM interface (which seems to be a wrapper for GDBM) */


/********************* ndbm interface definitions **********************/

# include <ndbm.h>

/* Basic DB type */
# define EXIM_DB DBM

/* Cursor type, not used with ndbm: just set up a dummy */
# define EXIM_CURSOR int

/* The datum type used for queries */
# define EXIM_DATUM datum

/* Some text for messages */

# define EXIM_DBTYPE "ndbm"

/* Access functions (ndbm) */

static inline BOOL
exim_lockfile_needed(void)
{
return TRUE;
}

/* EXIM_DBOPEN - returns a EXIM_DB *, NULL if failed */
/* Check that the name given is not present. This catches
a directory name; otherwise we would create the name.pag and
name.dir files in the directory's parent. */

static inline EXIM_DB *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
struct stat st;
if (!(flags & O_CREAT) || lstat(CCS name, &st) != 0 && errno == ENOENT)
  return dbm_open(CS name, flags, mode);
#ifndef COMPILE_UTILITY
debug_printf("%s %d errno %s\n", __FUNCTION__, __LINE__, strerror(errno));
#endif
errno = (st.st_mode & S_IFMT) == S_IFDIR ? EISDIR : EEXIST;
return NULL;
}

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
*res = dbm_fetch(dbp, *key);	/* A struct arg & return! */
return res->dptr != NULL;
}

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{ return dbm_store(dbp, *key, *data, DBM_REPLACE); }

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
static inline int
exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{ return dbm_store(dbp, *key, *data, DBM_INSERT); }

/* Returns from EXIM_DBPUTB */

# define EXIM_DBPUTB_OK  0
# define EXIM_DBPUTB_DUP 1

/* EXIM_DBDEL */
static inline int
exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key)
{ return dbm_delete(dbp, *key); }

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation (null) */
static inline EXIM_CURSOR *
exim_dbcreate_cursor(EXIM_DB * dbp)
{ return NULL; }

/* EXIM_DBSCAN */
static inline BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data, BOOL first,
  EXIM_CURSOR * cursor)
{
*key = first ? dbm_firstkey(dbp) : dbm_nextkey(dbp);
return key->dptr != NULL;
}

/* EXIM_DBDELETE_CURSOR - terminate scanning operation (null). */
static inline void
exim_dbdelete_cursor(EXIM_CURSOR * cursor)
{ }

/* EXIM_DBCLOSE */
static inline void
exim_dbclose__(EXIM_DB * dbp)
{ dbm_close(dbp); }

/* Datum access types */

static inline uschar *
exim_datum_data_get(EXIM_DATUM * dp)
{ return US dp->dptr; }
static inline void
exim_datum_data_set(EXIM_DATUM * dp, void * s)
{ dp->dptr = s; }

static inline unsigned
exim_datum_size_get(EXIM_DATUM * dp)
{ return dp->dsize; }
static inline void
exim_datum_size_set(EXIM_DATUM * dp, unsigned n)
{ dp->dsize = n; }

/* There's no clearing required before use, and we don't have to free anything
after reading data. */

static inline void
exim_datum_init(EXIM_DATUM * d)
{ }

static inline void
exim_datum_free(EXIM_DATUM * d)
{ }

/* size limit */

# define EXIM_DB_RLIMIT	150

#endif /* !USE_GDBM */





#if defined(COMPILE_UTILITY) || defined(MACRO_PREDEF)

static inline EXIM_DB *
exim_dbopen(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
return exim_dbopen__(name, dirname, flags, mode);
}

static inline void
exim_dbclose(EXIM_DB * dbp)
{ exim_dbclose__(dbp); }

#else	/*  exim mainline code */

/* Wrappers for open/close with debug tracing */

extern void debug_printf_indent(const char *, ...);
static inline BOOL is_tainted(const void *);

static inline EXIM_DB *
exim_dbopen(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
void * dbp;
DEBUG(D_hints_lookup)
  debug_printf_indent("EXIM_DBOPEN: file <%s> dir <%s> flags=%s\n",
    name, dirname,
    flags == O_RDONLY ? "O_RDONLY"
    : flags == O_RDWR ? "O_RDWR"
    : flags == (O_RDWR|O_CREAT) ? "O_RDWR|O_CREAT"
    : "??");
if (is_tainted(name) || is_tainted(dirname))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "Tainted name for DB file not permitted");
  dbp = NULL;
  }
else
  dbp = exim_dbopen__(name, dirname, flags, mode);

DEBUG(D_hints_lookup) debug_printf_indent("returned from EXIM_DBOPEN: %p\n", dbp);
return dbp;
}

static inline void
exim_dbclose(EXIM_DB * dbp)
{
DEBUG(D_hints_lookup) debug_printf_indent("EXIM_DBCLOSE(%p)\n", dbp);
exim_dbclose__(dbp);
}

# endif		/* defined(COMPILE_UTILITY) || defined(MACRO_PREDEF) */

/********************* End of dbm library definitions **********************/


#endif	/* whole file */
/* End of hintsdb.h */
/* vi: aw ai sw=2
*/
