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

# define EXIM_CURSOR int

# /* The datum type used for queries */
# define EXIM_DATUM blob

/* Some text for messages */
# define EXIM_DBTYPE "sqlite3"

/* Utility functions */

extern uschar *xtextencode(const uschar *, int);
extern int xtextdecode(const uschar *, uschar**);


/* Access functions */

/* The key must be zero terminated, an empty key has len == 1. */
static inline BOOL
is_cstring(EXIM_DATUM *key)
{
if (key->len < 1)
  {
# ifdef SQL_DEBUG
  fprintf(stderr, "invalid key length %d (must be >= 1)\n", key->len);
# endif
  return FALSE;
  }
if (key->data[key->len-1] != '\0')
  {
# ifdef SQL_DEBUG
  fprintf(stderr, "key %.*s is not zero terminated\n", key->len, key->data);
# endif
  return FALSE;
  }
return TRUE;
}

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
int ret, sflags = flags & O_RDWR ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY;

if (flags & O_CREAT) sflags |= SQLITE_OPEN_CREATE;
if ((ret = sqlite3_open_v2(CCS name, &dbp, sflags, NULL)) == SQLITE_OK)
  {
  sqlite3_busy_timeout(dbp, 5000);
  if (flags & O_CREAT)
    ret = sqlite3_exec(dbp,
	    "CREATE TABLE IF NOT EXISTS tbl (ky TEXT PRIMARY KEY, dat BLOB);",
	    NULL, NULL, NULL);
  if (ret != SQLITE_OK)
    sqlite3_close(dbp);
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

static inline BOOL
exim_dbget__(EXIM_DB * dbp, uschar *key, EXIM_DATUM * res)
{
int ret = FALSE;
sqlite3_stmt * stmt = NULL; /* don't make it static, as it depends on the dbp */
const char query[] = "SELECT dat FROM tbl WHERE ky = ?";

if (SQLITE_OK != sqlite3_prepare_v2(dbp, query, sizeof(query)-1, &stmt, NULL))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " prepare %s: %s\n", query, sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("prepared SQL: %s\n", sqlite3_sql(stmt));
# endif

if (SQLITE_OK != sqlite3_bind_text(stmt, 1, CCS key, strlen(key), SQLITE_STATIC))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " bind text (%s): %s\n", sqlite3_sql(stmt), sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("expanded SQL: %s\n", sqlite3_expanded_sql(stmt));
# endif

if (SQLITE_ROW != sqlite3_step(stmt))
  {
# ifdef SQL_DEBUG
  DEBUG(D_hints_lookup) debug_printf_indent("step (%s): %s\n", sqlite3_expanded_sql(stmt), sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

res->len = sqlite3_column_bytes(stmt, 0);

# ifdef COMPILE_UTILITY
if (!(res->data = malloc(res->len +1))) goto DONE;
# else
res->data = store_get(res->len +1, GET_TAINTED);
# endif

memcpy(res->data, sqlite3_column_blob(stmt, 0), res->len);
res->data[res->len] = '\0';
/* fprintf(stderr, "res %d bytes: '%.*s'\n", (int)res->len, (int)res->len, res->data); */

ret = TRUE;

DONE:
sqlite3_finalize(stmt);

return ret;
}

/* EXIM_DBGET - returns the value associated with the key. The key must
be zero terminated, an empty key has len == 1. */
static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
uschar * encoded_key;
BOOL ret;

encoded_key = xtextencode(key->data, key->len);
# ifdef COMPILE_UTILITY
if (!encoded_key) return FALSE;
#endif
/* DEBUG(D_hints_lookup) debug_printf_indent("exim_dbget(k len %d '%s')\n",
				  (int)key->len, encoded_key); */

ret = exim_dbget__(dbp, encoded_key, res);

# ifdef COMPILE_UTILITY
free(encoded_key);
# endif
return ret;
}


/* Note that we return claiming a duplicate record for any error.
It seem not uncommon to get a "database is locked" error.

Keys are stored xtext-encoded (which is mostly readable, for plaintext).
Values are stored in a BLOB type in the DB, for which the SQL interface
is hex-encoded. */
# define EXIM_DBPUTB_OK  0
# define EXIM_DBPUTB_DUP (-1)

static inline int
exim_s_dbp(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data, const uschar * alt)
{
const char sql[] = "INSERT OR %s INTO tbl (ky, dat) VALUES(?, ?)";
uschar * query;
int ret = EXIM_DBPUTB_DUP;
sqlite3_stmt *stmt = NULL;
uschar * encoded_key;

if (!(encoded_key = xtextencode(key->data, key->len))) return EXIM_DBPUTB_DUP;

# ifdef COMPILE_UTILITY
int i = 1 + snprintf(NULL, 0, sql, alt);
if (NULL == (query = US malloc(i)))
  {
  fprintf(stderr, "can't allocate memory for %s", sql);
  return EXIM_DBPUTB_DUP;
  }
snprintf(CS query, i, sql, alt);
# else
query = string_sprintf(sql, alt);
# endif

if (SQLITE_OK != sqlite3_prepare_v2(dbp, CCS query, -1, &stmt, NULL))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " prepare %s: %s\n", query, sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("prepared SQL: %s\n", sqlite3_sql(stmt));
# endif

if (SQLITE_OK != sqlite3_bind_text(stmt, 1, encoded_key, strlen(encoded_key), NULL))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " bind to value 1: %s\n", sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

if (SQLITE_OK != sqlite3_bind_blob(stmt, 2, data->data, data->len, NULL))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " bind to value 2: %s\n", sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("expanded SQL: %s\n", sqlite3_expanded_sql(stmt));
# endif

if (SQLITE_DONE != sqlite3_step(stmt))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " step (%s): %s\n", sqlite3_expanded_sql(stmt), sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

ret = EXIM_DBPUTB_OK;

DONE:
sqlite3_finalize(stmt);
# ifdef COMPILE_UTILITY
free(query);
# endif

return ret;
}

/* EXIM_DBPUT - returns nothing useful, assumes replace mode
The key must be zero terminated. An empty key has len == 1. */
static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent(EXIM_DBTYPE " put: key: len=%d, strlen=%d, key=%.*s\n", key->len, Ustrlen(key->data), key->len, key->data);
# endif
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
int res = -1;
sqlite3_stmt *stmt = NULL; /* don't make it static, because it depends on the dbp */
const char query[] = "DELETE FROM tbl WHERE ky = ?";
uschar * encoded_key;

if (!(encoded_key = xtextencode(key->data, key->len))) return EXIM_DBPUTB_DUP;

DEBUG(D_hints_lookup) debug_printf_indent(EXIM_DBTYPE " del key: len=%d, strlen=%d, key=%.*s\n", key->len, Ustrlen(key->data), key->len, key->data);

if (SQLITE_OK != sqlite3_prepare_v2(dbp, query, sizeof(query)-1, &stmt, NULL))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " prepare %s: %s\n", query, sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("query: %s\n", sqlite3_sql(stmt));
# endif

if (SQLITE_OK != sqlite3_bind_text(stmt, 1, CCS encoded_key, strlen(encoded_key), SQLITE_STATIC))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " bind value 1: %s\n", sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("expanded query: %s\n", sqlite3_expanded_sql(stmt));
# endif

if (SQLITE_DONE != sqlite3_step(stmt))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " step: %s: %s\n", sqlite3_expanded_sql(stmt), sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

res = 0;

DONE:
sqlite3_finalize(stmt);
return res;
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
/* Note that we return the (next) key, not the record value.
We allocate memory for the return. */
static inline BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res /* unusied */, BOOL first /*unused*/, EXIM_CURSOR * cursor)
{
BOOL more = FALSE;
sqlite3_stmt *stmt = NULL;
const char query[] = "SELECT ky FROM tbl ORDER BY ky LIMIT 1 OFFSET ?";
EXIM_DATUM encoded_key;

if (SQLITE_OK != sqlite3_prepare_v2(dbp, query, sizeof(query)-1, &stmt, NULL))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " prepare %s: %s\n", query, sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("prepared query: %s\n", sqlite3_sql(stmt));
# endif

if (SQLITE_OK != sqlite3_bind_int(stmt, 1, *cursor))
  {
# ifdef SQL_DEBUG
  fprintf(stderr, EXIM_DBTYPE " bind value 1: %s\n", query, sqlite3_errmsg(dbp));
# endif
  goto DONE;
  }

# ifdef SQL_DEBUG
DEBUG(D_hints_lookup) debug_printf_indent("expanded query: %s\n", sqlite3_expanded_sql(stmt));
# endif

switch (sqlite3_step(stmt))
  {
    case SQLITE_DONE: goto DONE;
    case SQLITE_ROW: (*cursor)++;
                      encoded_key.len = sqlite3_column_bytes(stmt, 0);
#ifdef COMPILE_UTILITY
                      if (!(encoded_key.data = malloc(encoded_key.len+1))) goto DONE;
#else
                      encoded_key.data = store_get(encoded_key.len+1, GET_TAINTED); // TAINTED? We're talking about the key!
#endif
                      memcpy(encoded_key.data, sqlite3_column_blob(stmt, 0), encoded_key.len);
                      key->len = xtextdecode(encoded_key.data, &key->data);
# ifdef SQL_DEBUG
                      DEBUG(D_hints_lookup) debug_printf_indent("key length=%d, val=%s\n", key->len, key->data);
# endif
                      more = TRUE;
                      goto DONE;
    default:
# ifdef SQL_DEBUG
                      fprintf(stderr, EXIM_DBTYPE " step: %s: %s\n", sqlite3_expanded_sql(stmt), sqlite3_errmsg(dbp));
# endif
                      goto DONE;
  }

DONE:
sqlite3_finalize(stmt);
return more;
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

/* End of hints_sqlite.h */
/* vi: aw ai sw=2
 *
*/
