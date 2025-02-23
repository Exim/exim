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
# ifndef _hints_sqlite_h
# define _hints_sqlite_h

# include <sqlite3.h>

/* Basic DB type */
# define EXIM_DB sqlite3

# define EXIM_CURSOR int

# /* The datum type used for queries */
# define EXIM_DATUM blob

/* Some text for messages */
# define EXIM_DBTYPE "sqlite3"

# define EXIM_DBPUTB_OK  0
# define EXIM_DBPUTB_DUP (-1)

/* Utility functions */

extern uschar *xtextencode(const uschar *, int);
extern int xtextdecode(const uschar *, uschar**);

extern unsigned exim_datum_size_get(EXIM_DATUM * dp);
int exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data);
EXIM_DB * exim_dbopen__(const uschar * name, const uschar * dirname, int flags, unsigned mode);
EXIM_DB * exim_dbopen_multi__(const uschar * name, const uschar * dirname, int flags, unsigned mode);
void exim_dbclose__(EXIM_DB * dbp);
void exim_dbclose_multi__(EXIM_DB * dbp);
void exim_datum_init(EXIM_DATUM * dp);
void exim_datum_data_set(EXIM_DATUM * dp, void * s);
unsigned exim_datum_size_get(EXIM_DATUM * dp);
void exim_datum_size_set(EXIM_DATUM * dp, unsigned n);
int exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data);
void exim_dbdelete_cursor(EXIM_CURSOR * cursor);
BOOL exim_lockfile_needed(void);
BOOL exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res);
uschar * exim_datum_data_get(EXIM_DATUM * dp);
void exim_datum_free(EXIM_DATUM * dp);
EXIM_CURSOR * exim_dbcreate_cursor(EXIM_DB * dbp);
BOOL exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res, BOOL first, EXIM_CURSOR * cursor);
int exim_dbdel(EXIM_DB * dbp, EXIM_DATUM * key);
BOOL exim_dbtransaction_start(EXIM_DB * dbp);
void exim_dbtransaction_commit(EXIM_DB * dbp);

/* size limit */

# define EXIM_DB_RLIMIT	150

# endif /* _hints_sqlite_h_
/* End of hints_sqlite.h */
/* vi: aw ai sw=2
*/
