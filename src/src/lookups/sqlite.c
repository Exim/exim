/* $Cambridge: exim/src/src/lookups/sqlite.c,v 1.5 2009/11/16 19:50:38 nm4 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"
#include "sqlite.h"

#ifndef LOOKUP_SQLITE
static void dummy(int x) { dummy(x-1); }
#else
#include <sqlite3.h>


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

void *
sqlite_open(uschar *filename, uschar **errmsg)
{
sqlite3 *db = NULL;
int ret;

ret = sqlite3_open((char *)filename, &db);
if (ret != 0)
  {
  *errmsg = (void *)sqlite3_errmsg(db);
  debug_printf("Error opening database: %s\n", *errmsg);
  }

sqlite3_busy_timeout(db, 1000 * sqlite_lock_timeout);
return db;
}


/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. */

struct strbuf {
  uschar *string;
  int size;
  int len;
};

static int sqlite_callback(void *arg, int argc, char **argv, char **azColName)
{
struct strbuf *res = arg;
int i;

/* For second and subsequent results, insert \n */

if (res->string != NULL)
  res->string = string_cat(res->string, &res->size, &res->len, US"\n", 1);

if (argc > 1)
  {
  /* For multiple fields, include the field name too */
  for (i = 0; i < argc; i++)
    {
    uschar *value = US((argv[i] != NULL)? argv[i]:"<NULL>");
    res->string = lf_quote(US azColName[i], value, Ustrlen(value), res->string,
      &res->size, &res->len);
    }
  }

else
  {
  res->string = string_append(res->string, &res->size, &res->len, 1,
    (argv[0] != NULL)? argv[0]:"<NULL>");
  }

res->string[res->len] = 0;
return 0;
}


int
sqlite_find(void *handle, uschar *filename, uschar *query, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
int ret;
struct strbuf res = { NULL, 0, 0 };

ret = sqlite3_exec(handle, (char *)query, sqlite_callback, &res, (char **)errmsg);
if (ret != SQLITE_OK)
  {
  debug_printf("sqlite3_exec failed: %s\n", *errmsg);
  return FAIL;
  }

if (res.string == NULL) *do_cache = FALSE;

*result = res.string;
return OK;
}



/*************************************************
*               Close entry point                *
*************************************************/

/* See local README for interface description. */

void sqlite_close(void *handle)
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

Returns:     the processed string or NULL for a bad option
*/

uschar *
sqlite_quote(uschar *s, uschar *opt)
{
register int c;
int count = 0;
uschar *t = s;
uschar *quoted;

if (opt != NULL) return NULL;     /* No options recognized */

while ((c = *t++) != 0) if (c == '\'') count++;

if (count == 0) return s;
t = quoted = store_get(Ustrlen(s) + count + 1);

while ((c = *s++) != 0)
  {
  if (c == '\'') *t++ = '\'';
  *t++ = c;
  }

*t = 0;
return quoted;
}

#endif /* LOOKUP_SQLITE */

/* End of lookups/sqlite.c */
