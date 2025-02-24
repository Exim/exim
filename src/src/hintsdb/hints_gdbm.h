/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This header file contains macro definitions for one possible hintsdb
backend provider. */

/********************* gdbm interface definitions **********************/

/*XXX TODO: exim's lockfile not needed? */
# ifndef _hints_gdbm_h_
# define _hints_gdbm_h_
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

# define EXIM_DBPUTB_OK  0
# define EXIM_DBPUTB_DUP 1
# define EXIM_DB_RLIMIT	150

/* trivial functions are here, the rest is in hints_gdbm.c */
static inline BOOL exim_lockfile_needed(void) { return TRUE; }

static inline EXIM_DB * exim_dbopen_multi__(const uschar * name, const uschar * dirname, int flags, unsigned mode) { return NULL; }
static inline void exim_dbclose_multi__(EXIM_DB * dbp) {}

static inline int exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data) { return gdbm_store(dbp->gdbm, *key, *data, GDBM_REPLACE); }
static inline int exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data) { return gdbm_store(dbp->gdbm, *key, *data, GDBM_INSERT); }
static inline int exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key) { return gdbm_delete(dbp->gdbm, *key); }

static inline BOOL exim_dbtransaction_start(EXIM_DB * dbp) { return FALSE; }
static inline void exim_dbtransaction_commit(EXIM_DB * dbp) {}

static inline EXIM_CURSOR * exim_dbcreate_cursor(EXIM_DB * dbp) { return NULL; }
static inline void exim_dbdelete_cursor(EXIM_CURSOR * cursor) { }

static inline void exim_datum_init(EXIM_DATUM * d) { }
static inline void exim_datum_free(EXIM_DATUM * d) { free(d->dptr); }
static inline void exim_datum_data_set(EXIM_DATUM * dp, void * s) { dp->dptr = s; }
static inline void exim_datum_size_set(EXIM_DATUM * dp, unsigned n) { dp->dsize = n; }
static inline uschar * exim_datum_data_get(EXIM_DATUM * dp) { return US dp->dptr; }
static inline unsigned exim_datum_size_get(EXIM_DATUM * dp) { return dp->dsize; }

# endif /* _hints_gdbm_h_ */

/* End of hintsdb/hints_gdbm.h */
/* vi: aw ai sw=2
*/

