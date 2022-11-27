/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"
#include "lf_functions.h"


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */

static void *
dbmdb_open(const uschar * filename, uschar ** errmsg)
{
uschar * dirname = string_copy(filename);
uschar * s;
EXIM_DB * yield = NULL;

if ((s = Ustrrchr(dirname, '/'))) *s = '\0';
if (!(yield = exim_dbopen(filename, dirname, O_RDONLY, 0)))
  *errmsg = string_open_failed("%s as a %s file", filename, EXIM_DBTYPE);
return yield;
}



/*************************************************
*             Check entry point                  *
*************************************************/

/* This needs to know more about the underlying files than is good for it!
We need to know what the real file names are in order to check the owners and
modes. If USE_DB is set, we know it is Berkeley DB, which uses an unmodified
file name. If USE_TDB or USE_GDBM is set, we know it is tdb or gdbm, which do
the same. Otherwise, for safety, we have to check for x.db or x.dir and x.pag.
*/

static BOOL
dbmdb_check(void *handle, const uschar *filename, int modemask, uid_t *owners,
  gid_t *owngroups, uschar **errmsg)
{
int rc;

#if defined(USE_DB) || defined(USE_TDB) || defined(USE_GDBM)
rc = lf_check_file(-1, filename, S_IFREG, modemask, owners, owngroups,
  "dbm", errmsg);
#else
  {
  uschar filebuffer[256];
  (void)sprintf(CS filebuffer, "%.250s.db", filename);
  rc = lf_check_file(-1, filebuffer, S_IFREG, modemask, owners, owngroups,
    "dbm", errmsg);
  if (rc < 0)        /* stat() failed */
    {
    (void)sprintf(CS filebuffer, "%.250s.dir", filename);
    rc = lf_check_file(-1, filebuffer, S_IFREG, modemask, owners, owngroups,
      "dbm", errmsg);
    if (rc == 0)     /* x.dir was OK */
      {
      (void)sprintf(CS filebuffer, "%.250s.pag", filename);
      rc = lf_check_file(-1, filebuffer, S_IFREG, modemask, owners, owngroups,
        "dbm", errmsg);
      }
    }
  }
#endif

return rc == 0;
}



/*************************************************
*              Find entry point                  *
*************************************************/

/* See local README for interface description. This function adds 1 to
the keylength in order to include the terminating zero. */

static int
dbmdb_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
EXIM_DB *d = (EXIM_DB *)handle;
EXIM_DATUM key, data;

exim_datum_init(&key);               /* Some DBM libraries require datums to */
exim_datum_init(&data);              /* be cleared before use. */
length++;
exim_datum_data_set(&key,
  memcpy(store_get(length, keystring), keystring, length)); /* key can have embedded NUL */
exim_datum_size_set(&key, length);

if (exim_dbget(d, &key, &data))
  {
  *result = string_copyn(exim_datum_data_get(&data), exim_datum_size_get(&data));
  exim_datum_free(&data);            /* Some DBM libraries need a free() call */
  return OK;
  }
return FAIL;
}



/*************************************************
*      Find entry point - no zero on key         *
*************************************************/

/* See local README for interface description */

static int
dbmnz_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
return dbmdb_find(handle, filename, keystring, length-1, result, errmsg,
  do_cache, opts);
}



/*************************************************
*     Find entry point - zero-joined list key    *
*************************************************/

/*
 * The parameter passed as a key is a list in normal Exim list syntax.
 * The elements of that list are joined together on NUL, with no trailing
 * NUL, to form the key.
 */

static int
dbmjz_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
uschar *key_item, *key_buffer, *key_p;
const uschar *key_elems = keystring;
int buflen, bufleft, key_item_len, sep = 0;

/* To a first approximation, the size of the lookup key needs to be about,
or less than, the length of the delimited list passed in + 1. */

buflen = length + 3;
key_buffer = store_get(buflen, keystring);

key_buffer[0] = '\0';

key_p = key_buffer;
bufleft = buflen;

/* In all cases of an empty list item, we can set 1 and advance by 1 and then
pick up the trailing NUL from the previous list item, EXCEPT when at the
beginning of the output string, in which case we need to supply that NUL
ourselves.  */
while ((key_item = string_nextinlist(&key_elems, &sep, key_p, bufleft)) != NULL)
  {
  key_item_len = Ustrlen(key_item) + 1;
  if (key_item_len == 1)
    {
    key_p[0] = '\0';
    if (key_p == key_buffer)
      {
      key_p[1] = '\0';
      key_item_len += 1;
      }
    }

  bufleft -= key_item_len;
  if (bufleft <= 0)
    {
    /* The string_nextinlist() will stop at buffer size, but we should always
    have at least 1 character extra, so some assumption has failed. */
    *errmsg = string_copy(US"Ran out of buffer space for joining elements");
    return DEFER;
    }
  key_p += key_item_len;
  }

if (key_p == key_buffer)
  {
  *errmsg = string_copy(US"empty list key");
  return FAIL;
  }

/* We do not pass in the final NULL; if needed, the list should include an
empty element to put one in. Boundary: key length 1, is a NULL */
key_item_len = key_p - key_buffer - 1;

DEBUG(D_lookup) debug_printf_indent("NUL-joined key length: %d\n", key_item_len);

/* beware that dbmdb_find() adds 1 to length to get back terminating NUL, so
because we've calculated the real length, we need to subtract one more here */

return dbmdb_find(handle, filename, key_buffer, key_item_len - 1,
    result, errmsg, do_cache, opts);
}



/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

void
static dbmdb_close(void *handle)
{
exim_dbclose((EXIM_DB *)handle);
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
dbm_version_report(gstring * g)
{
#ifdef DYNLOOKUP
g = string_fmt_append(g, "Library version: DBM: Exim version %s\n", EXIM_VERSION_STR);
#endif
return g;
}


lookup_info dbm_lookup_info = {
  .name = US"dbm",			/* lookup name */
  .type = lookup_absfile,		/* uses absolute file name */
  .open = dbmdb_open,			/* open function */
  .check = dbmdb_check,			/* check function */
  .find = dbmdb_find,			/* find function */
  .close = dbmdb_close,			/* close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = dbm_version_report             /* version reporting */
};

lookup_info dbmz_lookup_info = {
  .name = US"dbmnz",			/* lookup name */
  .type = lookup_absfile,		/* uses absolute file name */
  .open = dbmdb_open,			/* sic */     /* open function */
  .check = dbmdb_check,			/* sic */     /* check function */
  .find = dbmnz_find,			/* find function */
  .close = dbmdb_close,			/* sic */     /* close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = NULL                           /* no version reporting (redundant) */
};

lookup_info dbmjz_lookup_info = {
  .name = US"dbmjz",			/* lookup name */
  .type = lookup_absfile,		/* uses absolute file name */
  .open = dbmdb_open,			/* sic */     /* open function */
  .check = dbmdb_check,			/* sic */     /* check function */
  .find = dbmjz_find,			/* find function */
  .close = dbmdb_close,			/* sic */     /* close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = NULL                           /* no version reporting (redundant) */
};

#ifdef DYNLOOKUP
#define dbmdb_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &dbm_lookup_info, &dbmz_lookup_info, &dbmjz_lookup_info };
lookup_module_info dbmdb_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 3 };

/* End of lookups/dbmdb.c */
