/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This header file contains macro definitions for one possible hintsdb
backend provider. */

/********************* gdbm interface definitions **********************/

/*XXX TODO: exim's lockfile not needed? */

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

static inline EXIM_DB *
exim_dbopen_multi(const uschar * name, const uschar * dirname, int flags,
  unsigned mode) { return NULL; }
static inline void exim_dbclose_multi(EXIM_DB * dbp) {}
static inline BOOL exim_dbtransaction_start(EXIM_DB * dbp) { return FALSE; }
static inline void exim_dbtransaction_commit(EXIM_DB * dbp) {}

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

/* End of hintsdb/hints_gdbm.h */
/* vi: aw ai sw=2
*/
