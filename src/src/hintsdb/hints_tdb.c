# include "config.h"
# ifdef USE_TDB

# include "exim.h"
# include "hints_tdb.h"

/* EXIM_DBOPEN - return pointer to an EXIM_DB, NULL if failed */
EXIM_DB *
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

EXIM_DB *
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
BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
*res = tdb_fetch(dbp, *key);	/* A struct arg and return!! */
return res->dptr != NULL;
}


BOOL
exim_dbtransaction_start(EXIM_DB * db)
{
BOOL ok = tdb_transaction_start(db) == 0;
DEBUG(D_hints_lookup) if (!ok)
  debug_printf_indent("tdb_transaction_start: %s\n", tdb_errorstr(db));
return ok;
}

void
exim_dbtransaction_commit(EXIM_DB * db)
{
BOOL ok = tdb_transaction_commit(db) == 0;
DEBUG(D_hints_lookup) if (!ok)
  debug_printf_indent("tdb_transaction_commit: %s\n", tdb_errorstr(db));
return;
}


/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
int
exim_dbput(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{
int rc = tdb_store(dbp, *key, *data, TDB_REPLACE);
DEBUG(D_hints_lookup) if (rc != 0)
  debug_printf_indent("tdb_store: %s\n", tdb_errorstr(dbp));
return rc;
}

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
int
exim_dbputb(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data)
{ return tdb_store(dbp, *key, *data, TDB_INSERT); }

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */
EXIM_CURSOR *
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

BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res, BOOL first,
  EXIM_CURSOR * cursor)
{
*key = first ? tdb_firstkey(dbp) : tdb_nextkey(dbp, *cursor);
free(cursor->dptr);
*cursor = *key;
return key->dptr != NULL;
}


/* Free the stuff inside the datum. */

void
exim_datum_free(EXIM_DATUM * d)
{
free(d->dptr);
d->dptr = NULL;
}

/* EXIM_DBCLOSE */
void
exim_dbclose_multi__(EXIM_DB * db)
{
int rc = tdb_close(db);
DEBUG(D_hints_lookup) if (rc != 0)
  debug_printf_indent("tdb_close: %s\n", tdb_errorstr(db));
}

void
exim_dbclose__(EXIM_DB * db)
{
int rc = tdb_transaction_commit(db);
DEBUG(D_hints_lookup) if (rc != 0)
  debug_printf_indent("tdb_transaction_commit: %s\n", tdb_errorstr(db));
rc = tdb_close(db);
DEBUG(D_hints_lookup) if (rc != 0)
  debug_printf_indent("tdb_close: %s\n", tdb_errorstr(db));
}

# endif
