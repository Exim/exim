/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This header file contains macro definitions so that a variety of DBM
libraries can be used by Exim. Nigel Metheringham provided the original set for
Berkeley DB 1.x in native mode and ndbm. Subsequently, versions for Berkeley DB
2.x and 3.x were added. Later still, support for tdb was added, courtesy of
James Antill. More recently, support for native mode gdbm was added, with code
from Pierre A. Humblet, so Exim could be made to work with Cygwin.
Most recently, sqlite3 was added.

For convenience, the definitions of the structures used in the various hints
databases are also kept in this file, which is used by the maintenance
utilities as well as the main Exim binary.

A key/value store is supported (only).  Keys are strings; values arbitrary
binary blobs.

The API is:
  Functions:
    exim_lockfile_needed 	API semantics predicate
    exim_dbopen
    exim_dbopen_multi		only for no-lockfile-needed
    exim_dbclose
    exim_dbclose_multi		only for no-lockfile-needed
    exim_dbtransaction_start	only for no-lockfile-needed
    exim_dbtransaction_commit	only for no-lockfile-needed
    exim_dbget
    exim_dbput
    exim_dbputb			non-overwriting put
    exim_dbdel
    exim_dbcreate_cursor
    exim_dbscan			get, and bump cursor
    exim_dbdelete_cursor
    exim_datum_init
    exim_datum_size_get/set
    exim_datum_data_get/set
    exim_datum_free
  Defines:
    EXIM_DB		access handle
    EXIM_CURSOR		datatype for cursor
    EXIM_DATUM		datatype for "value"
    EXIM_DBTYPE		text for logging & debuug

Selection of the shim layer implementation, and backend, is by #defines.

The users of this API are:
  hintsdb interface	dbfn.c
  hintsdb utilities	exim_dbutil.c and exim_dbmvuild.c
  autoreply transport	transports/autoreply.c

Future: consider re-architecting to support caching of the open-handle
for hintsdb uses (the dbmdb use gets that already).  This would need APIs
for transaction locks.  Perhaps merge the implementation with the lookups
layer, in some way, for the open-handle caching (since that manages closes
required by Exim's process transitions)?
*/

#ifndef HINTSDB_H
#define HINTSDB_H

/* Include file ordering problem */
extern void    debug_printf_indent(const char *, ...) PRINTF_FUNCTION(1,2);


#ifdef USE_SQLITE
# if defined(USE_DB) || defined(USE_GDBM) || defined(USE_TDB)
#  error USE_SQLITE conflict with alternate definition
# endif
# include "hintsdb/hints_sqlite.h"

#elif defined(USE_TDB)
# if defined(USE_DB) || defined(USE_GDBM) || defined(USE_SQLITE)
#  error USE_TDB conflict with alternate definition
# endif
# include "hintsdb/hints_tdb.h"

#elif defined USE_DB
# if defined(USE_TDB) || defined(USE_GDBM) || defined(USE_SQLITE)
#  error USE_DB conflict with alternate definition
# endif
# include "hintsdb/hints_bdb.h"

#elif defined USE_GDBM
# if defined(USE_TDB) || defined(USE_DB) || defined(USE_SQLITE)
#  error USE_GDBM conflict with alternate definition
# endif
# include "hintsdb/hints_gdbm.h"

#else

/* If none of USE_{DB,GDBM,SQLITE,TDB} are set
the default is the NDBM interface (which seems to be a wrapper for GDBM) */

# include "hintsdb/hints_ndbm.h"
#endif /* !USE_GDBM */






/* Wrappers for open/close with debug tracing */

extern void debug_printf_indent(const char *, ...);
static inline BOOL is_tainted(const void *);

static inline EXIM_DB *
exim_dbopen(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
void * dbp;
DEBUG(D_hints_lookup)
  debug_printf_indent("EXIM_DBOPEN: file <%s> dir <%s> flags=%s\n",
    name, dirname,
    flags == O_RDONLY ? "O_RDONLY"
    : flags == O_RDWR ? "O_RDWR"
    : flags == (O_RDWR|O_CREAT) ? "O_RDWR|O_CREAT"
    : "??");
if (is_tainted(name) || is_tainted(dirname))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "Tainted name for DB file not permitted");
  dbp = NULL;
  }
else
  dbp = exim_dbopen__(name, dirname, flags, mode);

DEBUG(D_hints_lookup) debug_printf_indent("returned from EXIM_DBOPEN: %p\n", dbp);
return dbp;
}

static inline EXIM_DB *
exim_dbopen_multi(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
void * dbp;
DEBUG(D_hints_lookup)
  debug_printf_indent("EXIM_DBOPEN_MULTI: file <%s> dir <%s> flags=%s\n",
    name, dirname,
    flags == O_RDONLY ? "O_RDONLY"
    : flags == O_RDWR ? "O_RDWR"
    : flags == (O_RDWR|O_CREAT) ? "O_RDWR|O_CREAT"
    : "??");
if (is_tainted(name) || is_tainted(dirname))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "Tainted name for DB file not permitted");
  dbp = NULL;
  }
else
  dbp = exim_dbopen_multi__(name, dirname, flags, mode);

DEBUG(D_hints_lookup) debug_printf_indent("returned from EXIM_DBOPEN_MULTI: %p\n", dbp);
return dbp;
}

static inline void
exim_dbclose(EXIM_DB * dbp)
{
DEBUG(D_hints_lookup) debug_printf_indent("EXIM_DBCLOSE(%p)\n", dbp);
exim_dbclose__(dbp);
}
static inline void
exim_dbclose_multi(EXIM_DB * dbp)
{
DEBUG(D_hints_lookup) debug_printf_indent("EXIM_DBCLOSE_MULTI(%p)\n", dbp);
exim_dbclose_multi__(dbp);
}


/********************* End of dbm library definitions **********************/

#endif	/* whole file */
/* End of hintsdb.h */
/* vi: aw ai sw=2
*/
