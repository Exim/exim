/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This header file contains macro definitions for one possible hintsdb
backend provider. */

/* ********************* sqlite3 interface ************************ */

# include <sqlite3.h>

/* Basic DB type */
# define EXIM_DB sqlite3

# define EXIM_CURSOR sqlite3_stmt

# /* The datum type used for queries */
# define EXIM_DATUM blob

/* Some text for messages */
# define EXIM_DBTYPE "sqlite3"

/* Access functions */

static inline BOOL
exim_lockfile_needed(void)
{
return FALSE;	/* We do transaction; no extra locking needed */
}

/* EXIM_DBOPEN - return pointer to an EXIM_DB, NULL if failed */
static inline EXIM_DB *
exim_dbopen_multi__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
EXIM_DB * dbp;
int ret, sflags = (flags & O_ACCMODE) == O_RDONLY
		  ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE;

if (flags & O_CREAT) sflags |= SQLITE_OPEN_CREATE;
if ((ret = sqlite3_open_v2(CCS name, &dbp, sflags, NULL)) == SQLITE_OK)
  {
  sqlite3_busy_timeout(dbp, 5000);
  if (flags & O_CREAT)
    ret = sqlite3_exec(dbp,
	    "CREATE TABLE IF NOT EXISTS tblblob (ky BLOB PRIMARY KEY, dat BLOB);",
	    NULL, NULL, NULL);
  if (ret != SQLITE_OK)
    sqlite3_close(dbp);
  /* in case we are migrating, drop the old table, return code not needed */
  (void) sqlite3_exec(dbp, "DROP TABLE IF EXISTS tbl;", NULL, NULL, NULL);
  }
else DEBUG(D_hints_lookup)
  debug_printf_indent("sqlite_open(flags 0x%x mode %04o) %s\n",
		      flags, mode, sqlite3_errmsg(dbp));
return ret == SQLITE_OK ? dbp : NULL;
}

static inline BOOL
exim_dbtransaction_start(EXIM_DB * dbp)
{
return sqlite3_exec(dbp, "BEGIN TRANSACTION;", NULL, NULL, NULL) == SQLITE_OK;
}

static inline EXIM_DB *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
EXIM_DB * dbp = exim_dbopen_multi__(name, dirname, flags, mode);
if (!dbp || exim_dbtransaction_start(dbp))
  return dbp;
sqlite3_close(dbp);
return NULL;
}

static inline sqlite3_stmt *
exim_sqlbind_blob(EXIM_DB * dbp, sqlite3_stmt *stmt, int *bindcolp, EXIM_DATUM *data )
{
if (data && stmt)
  {
  if (SQLITE_OK != sqlite3_bind_blob(stmt, *bindcolp, data->data, data->len, SQLITE_STATIC))
    {
# ifdef SQL_DEBUG
    fprintf(stderr, EXIM_DBTYPE " bind to value %d: %s\n", *bindcolp, sqlite3_errmsg(dbp));
# endif
    sqlite3_finalize(stmt);
    stmt = NULL;
    }
  else
    {
    (*bindcolp)++;
    }
  }
return stmt;
}

/* We use a common prepare/bind mechanism with optional value binding */
static inline sqlite3_stmt *
exim_sqlprep(EXIM_DB * dbp, const char *query, EXIM_DATUM *key, EXIM_DATUM *data )
{
sqlite3_stmt * stmt = NULL; /* don't make it static, as it depends on the dbp */
int bindcol = 1;

if (SQLITE_OK != sqlite3_prepare_v2(dbp, query, strlen(query), &stmt, NULL))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " prepare %s: %s\n", query, sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("prepared SQL: %s\n", sqlite3_sql(stmt));
# endif

stmt = exim_sqlbind_blob(dbp, stmt, &bindcol, key);
stmt = exim_sqlbind_blob(dbp, stmt, &bindcol, data);

# ifdef SQL_DEBUG
if (stmt)
  {
  DEBUG(D_hints_lookup) debug_printf_indent("expanded SQL: %s\n", sqlite3_expanded_sql(stmt));
  }
# endif

DONE:

return stmt;
}


static inline int
exim_sqlstep(EXIM_DB * dbp, sqlite3_stmt * stmt, EXIM_DATUM *res )
{
int rv = SQLITE_MISUSE;

switch ((rv = sqlite3_step(stmt)))
  {
    case SQLITE_DONE: /* might want to call sqlite3_reset(stmt); here */
                      goto DONE;
    case SQLITE_ROW:  if (!res)
                      {
                        /* allow for fetch but didn't want data (existence check ?) */
                        goto DONE;
                      }
                      res->len = sqlite3_column_bytes(stmt, 0);
# ifdef COMPILE_UTILITY
                      res->data = malloc(res->len +1);
                      if (! res->data ) goto DONE;
# else
                      res->data = store_get(res->len +1, GET_TAINTED);
# endif
                      memcpy(res->data, sqlite3_column_blob(stmt, 0), res->len);
                      res->data[res->len] = '\0';
                      goto DONE;
    default:
# ifdef SQL_DEBUG
                      fprintf(stderr, EXIM_DBTYPE " step: %s: %s\n", sqlite3_expanded_sql(stmt), sqlite3_errmsg(dbp));
# endif
                      goto DONE;
  }

DONE:
return rv;
}


/* simplest case when updating a single row or fetching a single row */
static inline int
exim_sqlprep_step(EXIM_DB * dbp, const char *query, EXIM_DATUM *key, EXIM_DATUM *data, EXIM_DATUM *res )
{
int more = SQLITE_ERROR;
sqlite3_stmt * stmt = NULL; /* don't make it static, as it depends on the dbp */

if ((stmt = exim_sqlprep(dbp, query, key, data )))
  {
    more = exim_sqlstep(dbp, stmt, res );
    sqlite3_finalize(stmt);
    stmt = NULL;
  }
return more;
}

/* EXIM_DBGET - returns the value associated with the key. */
static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
const char query[] = "SELECT dat FROM tblblob WHERE ky = ?";
return (exim_sqlprep_step(dbp, query, key, NULL, res ) == SQLITE_ROW);
}


/* Note that we return claiming a duplicate record for any error.
 * It seem not uncommon to get a "database is locked" error.
*/
# define EXIM_DBPUTB_OK  0
# define EXIM_DBPUTB_DUP (-1)

static inline int
exim_s_dbp(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data, const char * sql)
{
return (SQLITE_DONE == exim_sqlprep_step(dbp, sql, key, data, NULL )) ? EXIM_DBPUTB_OK : EXIM_DBPUTB_DUP;
}

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent(EXIM_DBTYPE " put: key:%.*W data:%.*W\n", key->len, key->data, data->len, data->data );
# endif
(void) exim_s_dbp(dbp, key, data, "INSERT OR REPLACE INTO tblblob (ky, dat) VALUES(?, ?)");
return 0;
}

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */

/* Returns from EXIM_DBPUTB */

static inline int
exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
return exim_s_dbp(dbp, key, data, "INSERT OR ABORT INTO tblblob (ky, dat) VALUES(?, ?)");
}

/* EXIM_DBDEL */
static inline int
exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key)
{
const char query[] = "DELETE FROM tblblob WHERE ky = ?";
return (SQLITE_DONE == exim_sqlprep_step(dbp, query, key, NULL, NULL )) ? 0 : -1;
}

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */

static inline EXIM_CURSOR *
exim_dbcreate_cursor(EXIM_DB * dbp)
{
EXIM_CURSOR * cursor;

cursor = exim_sqlprep(dbp, "SELECT ky FROM tblblob ORDER BY ky", NULL, NULL );
if (!cursor) return NULL;
# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("prepared query: %s\n", sqlite3_sql(cursor));
# endif

return cursor;
}

/* EXIM_DBSCAN */
/* Note that we return the (next) key into the key parameter, not the res parameter. */
static inline BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res /* unused */, BOOL first /*unused*/, EXIM_CURSOR * cursor)
{
return (exim_sqlstep(dbp, cursor, key )==SQLITE_ROW);
}

/* EXIM_DBDELETE_CURSOR - terminate scanning operation. */
static inline void
exim_dbdelete_cursor(EXIM_CURSOR * cursor)
{
if(cursor)
  sqlite3_finalize(cursor);
}

/* EXIM_DBCLOSE */
static inline void
exim_dbclose_multi__(EXIM_DB *dbp)
{
sqlite3_close(dbp);
}
static inline void
exim_dbtransaction_commit(EXIM_DB * dbp)
{
(void) sqlite3_exec(dbp, "COMMIT TRANSACTION;", NULL, NULL, NULL);
}
static inline void
exim_dbclose__(EXIM_DB * dbp)
{
exim_dbtransaction_commit(dbp);
exim_dbclose_multi__(dbp);
}


/* Datum access */

static inline uschar *
exim_datum_data_get(EXIM_DATUM * dp)
{ return US dp->data; }

static void
exim_datum_data_set(EXIM_DATUM * dp, void * s)
{ dp->data = s; }

static unsigned
exim_datum_size_get(EXIM_DATUM * dp)
{ return dp->len; }

static inline void
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

/* End of hints_sqlite.h */
/* vi: aw ai sw=2
 *
*/
