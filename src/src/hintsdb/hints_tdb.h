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
# ifndef _hints_tdb_h_
# define _hints_tdb_h_
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

/* Transactions are supported */

static inline BOOL exim_lockfile_needed(void) { return FALSE; }

# define EXIM_DB_RLIMIT	150

/* Returns from EXIM_DBPUTB */

# define EXIM_DBPUTB_OK  0
# define EXIM_DBPUTB_DUP (-1)

/* EXIM_DBDEL */
static inline int exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key) { return tdb_delete(dbp, *key); }

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
/* Datum access */

static inline uschar * exim_datum_data_get(EXIM_DATUM * dp) { return US dp->dptr; }
static inline void exim_datum_data_set(EXIM_DATUM * dp, void * s) { dp->dptr = s; }

static inline unsigned exim_datum_size_get(EXIM_DATUM * dp) { return dp->dsize; }
static inline void exim_datum_size_set(EXIM_DATUM * dp, unsigned n) { dp->dsize = n; }

/* No initialization is needed. */
static inline void exim_datum_init(EXIM_DATUM * d) { }

# endif /* _hints_tdb_h_ */

/* End of hints_tdb.h */
/* vi: aw ai sw=2
*/
