# include "config.h"
# ifdef USE_GDBM
# include "exim.h"
# include "hints_gdbm.h"

/* EXIM_DBOPEN - return pointer to an EXIM_DB, NULL if failed */
EXIM_DB *
exim_dbopen__(const uschar * name, const uschar * dirname, int flags,
  unsigned mode)
{
EXIM_DB * dbp = malloc(sizeof(EXIM_DB));	/*XXX why not exim mem-mgmt? */
if (dbp)
  {
  dbp->lkey.dptr = NULL;
  dbp->gdbm = gdbm_open(CS name, 0,
    flags & O_CREAT ? GDBM_WRCREAT
    : (flags & O_ACCMODE) == O_RDONLY ? GDBM_READER : GDBM_WRITER,
    mode, 0);
  if (dbp->gdbm)
    return dbp;

  DEBUG(D_hints_lookup)
    debug_printf_indent("gdbm_open(flags 0x%x mode %04o) %s\n",
	      flags, mode, strerror(errno));
  free(dbp);
  }
return NULL;
}

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
BOOL
exim_dbget(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * res)
{
*res = gdbm_fetch(dbp->gdbm, *key);	/* A struct arg & return! */
return res->dptr != NULL;
}

/* EXIM_DBSCAN */
BOOL
exim_dbscan(EXIM_DB * dbp, EXIM_DATUM * key, EXIM_DATUM * data, BOOL first,
  EXIM_CURSOR * cursor)
{
char * s;
*key = first ? gdbm_firstkey(dbp->gdbm) : gdbm_nextkey(dbp->gdbm, dbp->lkey);
if ((s = dbp->lkey.dptr)) free(s);
dbp->lkey = *key;
return key->dptr != NULL;
}

/* EXIM_DBCLOSE */
void
exim_dbclose__(EXIM_DB * dbp)
{
char * s;
gdbm_close(dbp->gdbm);
if ((s = dbp->lkey.dptr)) free(s);
free(dbp);
}

/* size limit. GDBM is int-max limited, but we want to be less silly */

# endif /* USE_GDBM */
