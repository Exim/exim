/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"
#include "lf_functions.h"

#include <sqlite3.h>

static uschar * sqlite_dbfile = NULL;	/* Filename for database */
static int	sqlite_lock_timeout = 5;/* Internal lock waiting timeout */


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *
sqlite_open(const uschar * filename, uschar ** errmsg)
{
sqlite3 *db = NULL;
int ret;

if (!filename || !*filename)
  {
  DEBUG(D_lookup) debug_printf_indent("Using sqlite_dbfile: %s\n", sqlite_dbfile);
  filename = sqlite_dbfile;
  }
if (!filename || *filename != '/')
  *errmsg = US"absolute file name expected for \"sqlite\" lookup";
else if ((ret = sqlite3_open(CCS filename, &db)) != 0)
  {
  *errmsg = string_copy(US sqlite3_errmsg(db));
  sqlite3_close(db);
  db = NULL;
  DEBUG(D_lookup) debug_printf_indent("Error opening database: %s\n", *errmsg);
  }

if (db)
  sqlite3_busy_timeout(db, 1000 * sqlite_lock_timeout);
return db;
}


/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. */

static int
sqlite_callback(void *arg, int argc, char **argv, char **azColName)
{
gstring * res = *(gstring **)arg;

/* For second and subsequent results, insert \n */

if (res)
  res = string_catn(res, US"\n", 1);

if (argc > 1)
  {
  /* For multiple fields, include the field name too */
  for (int i = 0; i < argc; i++)
    {
    uschar * value = US(argv[i] ? argv[i] : "<NULL>");
    res = lf_quote(US azColName[i], value, Ustrlen(value), res);
    }
  }

else
  res = string_cat(res, argv[0] ? US argv[0] : US "<NULL>");

/* always return a non-null gstring, even for a zero-length string result */
*(gstring **)arg = res ? res : string_get(1);
return 0;
}


static int
sqlite_find(void * handle, const uschar * filename, const uschar * query,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
int ret;
gstring * res = NULL;

ret = sqlite3_exec(handle, CS query, sqlite_callback, &res, CSS errmsg);
if (ret != SQLITE_OK)
  {
  debug_printf_indent("sqlite3_exec failed: %s\n", *errmsg);
  return FAIL;
  }

if (!res) *do_cache = 0;	/* on fail, wipe cache */

*result = string_from_gstring(res);
return OK;
}



/*************************************************
*               Close entry point                *
*************************************************/

/* See local README for interface description. */

static void sqlite_close(void *handle)
{
sqlite3_close(handle);
}



/*************************************************
*               Quote entry point                *
*************************************************/

/* From what I have found so far, the only character that needs to be quoted
for sqlite is the single quote, and it is quoted by doubling.

Arguments:
  s          the string to be quoted
  opt        additional option text or NULL if none
  idx	     lookup type index

Returns:     the processed string or NULL for a bad option
*/

static uschar *
sqlite_quote(uschar * s, uschar * opt, unsigned idx)
{
int c, count = 0;
uschar * t = s, * quoted;

if (opt) return NULL;     /* No options recognized */

while ((c = *t++)) if (c == '\'') count++;
count += t - s;

t = quoted = store_get_quoted(count + 1, s, idx, US"sqlite");

while ((c = *s++))
  {
  if (c == '\'') *t++ = '\'';
  *t++ = c;
  }

*t = 0;
return quoted;
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

gstring *
sqlite_version_report(gstring * g)
{
g = string_fmt_append(g,
  "Library version: SQLite: Compile: %s\n"
  "                         Runtime: %s\n",
        SQLITE_VERSION, sqlite3_libversion());
return g;
}

/******************************************************************************/
/* Module API */

static optionlist sqlite_options[] = {
  { "sqlite_dbfile",            opt_stringptr,   {&sqlite_dbfile} },
  { "sqlite_lock_timeout",      opt_int,         {&sqlite_lock_timeout} },
};

static lookup_info _lookup_info = {
  .name =	US"sqlite",			/* lookup name */
  .type =	lookup_absfilequery,		/* query-style lookup, starts with file name */
  .open =	sqlite_open,			/* open function */
  .check =	NULL,				/* no check function */
  .find =	sqlite_find,			/* find function */
  .close =	sqlite_close,			/* close function */
  .tidy =	NULL,				/* no tidy function */
  .quote =	sqlite_quote,			/* quoting function */
  .version_report = sqlite_version_report,	/* version reporting */

  .options =	sqlite_options,
  .options_count = nelem(sqlite_options),
};

#ifdef DYNLOOKUP
# define sqlite_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info sqlite_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/sqlite.c */
