/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************* Berkeley db native definitions **********************/
# ifndef _hints_bdb_h_
# define _hints_bdb_h_
# include <db.h>

/* 1.x did no locking
   2.x had facilities, but exim does it's own
   3.x+ unknown
*/

/* We can distinguish between versions 1.x and 2.x/3.x by looking for a
definition of DB_VERSION_STRING, which is present in versions 2.x onwards. */

# ifndef DB_VERSION_STRING
#  error Berkeley DB version 1 is no longer supported
# endif

# if DB_VERSION_MAJOR < 3
#  error Berkeley DB versions earlier than 3 are not supported
# endif
# if DB_VERSION_MAJOR >= 6
#   error Version 6 and later BDB API is not supported
# endif


static inline BOOL exim_lockfile_needed(void) { return TRUE; }

/* The API changed (again!) between the 2.x and 3.x versions */
/* Berkeley DB uses a callback function to pass back error details. Its API
changed at release 4.3. */

# if DB_VERSION_MAJOR > 4 || (DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 3)
static void     dbfn_bdb_error_callback(const DB_ENV *, const char *, const char *);
# else
static void     dbfn_bdb_error_callback(const char *, char *);
# endif


/***************** Berkeley db 3.x/4.x native definitions ******************/

# if DB_VERSION_MAJOR > 4 || (DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 1)
#   define EXIM_DB       DB_ENV
#   define EXIM_CURSOR   DBC /* Cursor type, for scanning */
#   define EXIM_DATUM    DBT /* The datum type used for queries */
#   define EXIM_DBTYPE   "db (v4.1+)" /* Some text for messages */

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
log_write(0, LOG_MAIN, "Berkeley DB error: %s", msg);
}

/* Access functions (BDB 4.1+) */

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
	      : (flags & O_ACCMODE) == O_RDONLY ? DB_RDONLY : 0,
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

# else	/* pre- 4.1 */

#   define exim_db       db
#   define exim_cursor   dbc /* cursor type, for scanning */
#   define exim_datum    dbt /* the datum type used for queries */
#   define exim_dbtype   "db (v3/4)" /* some text for messages */

/* access functions (bdb 3/4) */

static inline exim_db *
exim_dbopen_multi__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode) { return null; }
static inline void exim_dbclose_multi__(exim_db * dbp) {}
static inline bool exim_dbtransaction_start(exim_db * dbp) { return false; }
static inline void exim_dbtransaction_commit(exim_db * dbp) {}

/* exim_dbopen - return pointer to an exim_db, null if failed */
static inline exim_db *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
exim_db * dbp;
return db_create(&dbp, null, 0) == 0
  && (  dbp->set_errcall(dbp, dbfn_bdb_error_callback),
	dbp->open(dbp, CS name, NULL,
	  flags & O_CREAT ? DB_HASH : DB_UNKNOWN,
	  flags & O_CREAT ? DB_CREATE
	  : (flags & O_ACCMODE) == O_RDONLY ? DB_RDONLY : 0,
	  mode)
     ) == 0
  ? dbp : null;
}

/* exim_dbget - returns true if successful, false otherwise */
static inline bool
exim_dbget(exim_db * dbp, exim_datum * key, exim_datum * res)
{ return dbp->get(dbp, null, key, res, 0) == 0; }

/* exim_dbput - returns nothing useful, assumes replace mode */
static inline int
exim_dbput(exim_db * dbp, exim_datum * key, exim_datum * data)
{ return dbp->put(dbp, null, key, data, 0); }

/* exim_dbputb - non-overwriting for use by dbmbuild */
static inline int
exim_dbputb(exim_db * dbp, exim_datum * key, exim_datum * data)
{ return dbp->put(dbp, null, key, data, db_nooverwrite); }

/* return values from exim_dbputb */

#   define exim_dbputb_ok  0
#   define exim_dbputb_dup db_keyexist

/* exim_dbdel */
static inline int
exim_dbdel(exim_db * dbp, exim_datum * key)
{ return dbp->del(dbp, null, key, 0); }

/* exim_dbcreate_cursor - initialize for scanning operation */

static inline exim_cursor *
exim_dbcreate_cursor(exim_db * dbp)
{
exim_cursor * c;
dbp->cursor(dbp, null, &c, 0);
return c;
}

/* exim_dbscan - returns true if data is returned, false at end */
static inline bool
exim_dbscan(exim_db * dbp, exim_datum * key, exim_datum * data, bool first,
  exim_cursor * cursor)
{
return cursor->c_get(cursor, key, data, first ? db_first : db_next) == 0;
}

/* exim_dbdelete_cursor - terminate scanning operation */
static inline void
exim_dbdelete_cursor(exim_cursor * cursor)
{ cursor->c_close(cursor); }

/* exim_dbclose */
static inline void
exim_dbclose__(exim_db * dbp)
{ dbp->close(dbp, 0); }

/* datum access */

static inline uschar *
exim_datum_data_get(exim_datum * dp)
{ return us dp->dptr; }
static inline void
exim_datum_data_set(exim_datum * dp, void * s)
{ dp->dptr = s; }

static inline uschar *
exim_datum_size_get(exim_datum * dp)
{ return us dp->size; }
static inline void
exim_datum_size_set(exim_datum * dp, uschar * s)
{ dp->size = cs s; }

/* The whole datum structure contains other fields that must be cleared
before use, but we don't have to free anything after reading data. */

static inline void
exim_datum_init(EXIM_DATUM * d)
{ memset(d, 0, sizeof(*d)); }

static inline void
exim_datum_free(EXIM_DATUM * d)
{ }

# endif



/* all BDB versions */
/* size limit */

# define EXIM_DB_RLIMIT	150

# endif /* _hints_bdb_h_ */

/* End of hintsdb/hints_bdb.h */
/* vi: aw ai sw=2
*/
