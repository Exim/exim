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

/* Utility functionss */

extern uschar *xtextencode(const uschar *, int);
extern int xtextdecode(const uschar *, uschar**);


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

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
/* note we alloc'n'copy - the caller need not do so */
/* result has a NUL appended, but the length is as per the DB */

static inline BOOL
exim_dbget__(EXIM_DB * dbp, const uschar * s, EXIM_DATUM * res)
{
sqlite3_stmt * statement;
int ret;

res->len = (size_t) -1;
/* DEBUG(D_hints_lookup) debug_printf_indent("exim_dbget__(%s)\n", s); */
if ((ret = sqlite3_prepare_v2(dbp, CCS s, -1, &statement, NULL)) != SQLITE_OK)
  {
  DEBUG(D_hints_lookup)
    debug_printf_indent("prepare fail: %s\n", sqlite3_errmsg(dbp));
  return FALSE;
  }
if (sqlite3_step(statement) != SQLITE_ROW)
  {
  /* DEBUG(D_hints_lookup)
    debug_printf_indent("step fail: %s\n", sqlite3_errmsg(dbp)); */
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
/* DEBUG(D_hints_lookup) debug_printf_indent("res %d bytes: '%.*s'\n",
				  (int)res->len, (int)res->len, res->data); */
sqlite3_finalize(statement);
return TRUE;
}

static inline BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
# define FMT "SELECT dat FROM tbl WHERE ky = '%s';"
uschar * encoded_key, * qry;
int i;
BOOL ret;

# ifdef COMPILE_UTILITY
if (!(encoded_key = xtextencode(key->data, key->len)))
  return FALSE;
# else
encoded_key = xtextencode(key->data, key->len);
# endif
/* DEBUG(D_hints_lookup) debug_printf_indent("exim_dbget(k len %d '%s')\n",
				  (int)key->len, encoded_key); */

# ifdef COMPILE_UTILITY
i = snprintf(NULL, 0, FMT, encoded_key) + 1;
if (!(qry = malloc(i)))
  return FALSE;
snprintf(CS qry, i, FMT, encoded_key);
ret = exim_dbget__(dbp, qry, res);
free(qry);
free(encoded_key);
# else
qry = string_sprintf(FMT, encoded_key);
ret = exim_dbget__(dbp, qry, res);
# endif

return ret;
# undef FMT
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
int hlen = data->len * 2, off = 0, res;
# define FMT "INSERT OR %s INTO tbl (ky,dat) VALUES ('%s', X'%.*s');"
uschar * encoded_key, * qry;
# ifdef COMPILE_UTILITY
uschar * hex = malloc(hlen+1);
if (!hex) return EXIM_DBPUTB_DUP;	/* best we can do */
# else
uschar * hex = store_get(hlen+1, data->data);
# endif

/* Encode the value for the SQL API */

for (const uschar * s = data->data, * t = s + data->len; s < t; s++, off += 2)
  sprintf(CS hex + off, "%02X", *s);

# ifdef COMPILE_UTILITY
if (!(encoded_key = xtextencode(key->data, key->len)))
  return EXIM_DBPUTB_DUP;
res = snprintf(CS hex, 0, FMT, alt, encoded_key, hlen, hex) +1;
if (!(qry = malloc(res))) return EXIM_DBPUTB_DUP;
snprintf(CS qry, res, FMT, alt, encoded_key, hlen, hex);
DEBUG(D_hints_lookup) debug_printf_indent("exim_s_dbp(%s)\n", qry);

res = sqlite3_exec(dbp, CS qry, NULL, NULL, NULL);
free(qry);
free(encoded_key);
free(hex);

# else
encoded_key = xtextencode(key->data, key->len);
qry = string_sprintf(FMT, alt, encoded_key, hlen, hex);
/* DEBUG(D_hints_lookup) debug_printf_indent("exim_s_dbp(%s)\n", qry); */

res = sqlite3_exec(dbp, CS qry, NULL, NULL, NULL);
/* DEBUG(D_hints_lookup) debug_printf_indent("exim_s_dbp res %d\n", res); */
# endif

# ifdef COMPILE_UTILITY
if (res != SQLITE_OK)
  DEBUG(D_hints_lookup)
    debug_printf_indent("sqlite3_exec: %s\n", sqlite3_errmsg(dbp));
# endif

return res == SQLITE_OK ? EXIM_DBPUTB_OK : EXIM_DBPUTB_DUP;
# undef FMT
}

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */

static inline int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
/* DEBUG(D_hints_lookup) debug_printf_indent("exim_dbput()\n"); */
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
# define FMT "DELETE FROM tbl WHERE ky = '%s';"
uschar * encoded_key, * qry;
int res;

# ifdef COMPILE_UTILITY
if (!(encoded_key = xtextencode(key->data, key->len)))
  return EXIM_DBPUTB_DUP;
res = snprintf(NULL, 0, FMT, encoded_key) +1;		/* res includes nul */
if (!(qry = malloc(res))) return SQLITE_NOMEM;
snprintf(CS qry, res, FMT, encoded_key);
res = sqlite3_exec(dbp, CS qry, NULL, NULL, NULL);
free(qry);

# else
encoded_key = xtextencode(key->data, key->len);
qry = string_sprintf(FMT, encoded_key);
res = sqlite3_exec(dbp, CS qry, NULL, NULL, NULL);

# endif

return res == SQLITE_OK ? EXIM_DBPUTB_OK : EXIM_DBPUTB_DUP;
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
/* Note that we return the (next) key, not the record value.
We allocate memory for the return. */

static inline BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res, BOOL first,
  EXIM_CURSOR * cursor)
{
# define FMT "SELECT ky FROM tbl ORDER BY ky LIMIT 1 OFFSET %d;"
uschar * qry;
EXIM_DATUM encoded_key;
BOOL ret;

# ifdef COMPILE_UTILITY
int i = snprintf(NULL, 0, FMT, *cursor)+1;

if (!(qry = malloc(i))) return FALSE;
snprintf(CS qry, i, FMT, *cursor);
DEBUG(D_hints_lookup) debug_printf_indent("exim_dbscan(%s)\n", qry);
ret = exim_dbget__(dbp, qry, &encoded_key);
free(qry);

# else	/*!COMPILE_UTILITY*/
qry = string_sprintf(FMT, *cursor);
DEBUG(D_hints_lookup) debug_printf_indent("exim_dbscan(%s)\n", qry);
ret = exim_dbget__(dbp, qry, &encoded_key);

# endif	/*COMPILE_UTILITY*/

DEBUG(D_hints_lookup)
  debug_printf_indent("exim_dbscan ret %c\n", ret ? 'T':'F');

if (ret)
  {
  key->len = xtextdecode(encoded_key.data, &key->data);
  *cursor = *cursor + 1;
  }
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
static inline void
exim_dbclose_multi__(EXIM_DB * dbp)
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
*/
