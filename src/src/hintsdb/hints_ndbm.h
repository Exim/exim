/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This header file contains macro definitions for one possible hintsdb
backend provider. */

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

static inline EXIM_DB *
exim_dbopen_multi__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode) { return NULL; }
static inline void exim_dbclose_multi__(EXIM_DB * dbp) {}
static inline BOOL exim_dbtransaction_start(EXIM_DB * dbp) { return FALSE; }
static inline void exim_dbtransaction_commit(EXIM_DB * dbp) {}

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

DEBUG(D_hints_lookup)
  debug_printf_indent("ndbm_open(flags 0x%x mode %04o) %s\n",
	      flags, mode, strerror(errno));
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

/* End of hintsdb/hints_ndbm.h */
/* vi: aw ai sw=2
*/
