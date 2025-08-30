/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************* Berkeley db native definitions **********************/

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



/* Berkeley DB uses a callback function to pass back error details. Its API
changed at release 4.3. */

#if defined(DB_VERSION_STRING)
# if DB_VERSION_MAJOR > 4 || (DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 3)
static void     dbfn_bdb_error_callback(const DB_ENV *, const char *, const char *);
# else
static void     dbfn_bdb_error_callback(const char *, char *);
# endif
#endif



/* Error callback */
/* For Berkeley DB >= 2, we can define a function to be called in case of DB
errors. This should help with debugging strange DB problems, e.g. getting "File
exists" when you try to open a db file. The API for this function was changed
at DB release 4.3. */

static inline void
dbfn_bdb_error_callback(const DB_ENV * dbenv, const char * pfx, const char * msg)
{
log_write(0, LOG_MAIN, "Berkeley DB error: %s", msg);
}



/* Access functions (BDB 4.1+) */

static inline BOOL
exim_lockfile_needed(void)
{
return TRUE;
}

static inline EXIM_DB *
exim_dbopen_multi__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode) { return NULL; }
static inline void exim_dbclose_multi__(EXIM_DB * dbp) {}
static inline BOOL exim_dbtransaction_start(EXIM_DB * dbp) { return FALSE; }
static inline void exim_dbtransaction_commit(EXIM_DB * dbp) {}

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
  else DEBUG(D_hints_lookup)
    debug_printf_indent("bdb_open(flags 0x%x mode %04o) %s\n",
	      flags, mode, strerror(errno));

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

static inline EXIM_DB *
exim_dbopen_multi__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode) { return NULL; }
static inline void exim_dbclose_multi__(EXIM_DB * dbp) {}
static inline BOOL exim_dbtransaction_start(EXIM_DB * dbp) { return FALSE; }
static inline void exim_dbtransaction_commit(EXIM_DB * dbp) {}

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

/* End of hintsdb/hints_bdb.h */
/* vi: aw ai sw=2
*/
