/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This header file contains macro definitions for one possible hintsdb
backend provider. */

/* ************************* tdb interface ************************ */
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
return FALSE;		/* Transactions are supported */
}


/* EXIM_DBOPEN - return pointer to an EXIM_DB, NULL if failed */
static inline EXIM_DB *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
EXIM_DB * db = tdb_open(CS name, 0, TDB_DEFAULT, flags, mode);
int e;

DEBUG(D_hints_lookup) if (!db)
  debug_printf_indent("tdb_open(flags 0x%x mode %04o) %s\n",
	      flags, mode, strerror(errno));
if (!db || tdb_transaction_start(db) == 0) return db;
e = errno;
DEBUG(D_hints_lookup) if (db)
  debug_printf_indent("tdb_transaction_start: %s\n", tdb_errorstr(db));
tdb_close(db);
errno = e;
return NULL;
}

static inline EXIM_DB *
exim_dbopen_multi__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
EXIM_DB * db = tdb_open(CS name, 0, TDB_DEFAULT, flags, mode);
DEBUG(D_hints_lookup) if (!db)
  debug_printf_indent("tdb_open(flags 0x%x mode %04o) %s\n",
	      flags, mode, strerror(errno));
return db;
}

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
*res = tdb_fetch(dbp, *key);	/* A struct arg and return!! */
return res->dptr != NULL;
}


static inline BOOL
exim_dbtransaction_start(EXIM_DB * db)
{
BOOL ok = tdb_transaction_start(db) == 0;
DEBUG(D_hints_lookup) if (!ok)
  debug_printf_indent("tdb_transaction_start: %s\n", tdb_errorstr(db));
return ok;
}

static inline void
exim_dbtransaction_commit(EXIM_DB * db)
{
BOOL ok = tdb_transaction_commit(db) == 0;
DEBUG(D_hints_lookup) if (!ok)
  debug_printf_indent("tdb_transaction_commit: %s\n", tdb_errorstr(db));
return;
}



/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
int rc = tdb_store(dbp, *key, *data, TDB_REPLACE);
DEBUG(D_hints_lookup) if (rc != 0)
  debug_printf_indent("tdb_store: %s\n", tdb_errorstr(dbp));
return rc;
}

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
{
#ifdef COMPILE_UTILITY
free(cursor);
#else
store_free(cursor);
#endif
}

/* EXIM_DBCLOSE */
static inline void
exim_dbclose_multi__(EXIM_DB * db)
{
int rc = tdb_close(db);
DEBUG(D_hints_lookup) if (rc != 0)
  debug_printf_indent("tdb_close: %s\n", tdb_errorstr(db));
}

static inline void
exim_dbclose__(EXIM_DB * db)
{
int rc = tdb_transaction_commit(db);
DEBUG(D_hints_lookup) if (rc != 0)
  debug_printf_indent("tdb_transaction_commit: %s\n", tdb_errorstr(db));
rc = tdb_close(db);
DEBUG(D_hints_lookup) if (rc != 0)
  debug_printf_indent("tdb_close: %s\n", tdb_errorstr(db));
}

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

/* End of hints_tdb.h */
/* vi: aw ai sw=2
*/
