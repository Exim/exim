/* $Cambridge: exim/src/src/lookups/testdb.c,v 1.4 2007/01/08 10:50:19 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"
#include "testdb.h"


/* These are not real lookup functions; they are just a way of testing the
rest of Exim by providing an easy way of specifying particular yields from
the find function. */


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

void *
testdb_open(uschar *filename, uschar **errmsg)
{
filename = filename;   /* Keep picky compilers happy */
errmsg = errmsg;
return (void *)(1);    /* Just return something non-null */
}



/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. */

int
testdb_find(void *handle, uschar *filename, uschar *query, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
handle = handle;          /* Keep picky compilers happy */
filename = filename;
length = length;

if (Ustrcmp(query, "fail") == 0)
  {
  *errmsg = US"testdb lookup forced FAIL";
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return FAIL;
  }
if (Ustrcmp(query, "defer") == 0)
  {
  *errmsg = US"testdb lookup forced DEFER";
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return DEFER;
  }

if (Ustrcmp(query, "nocache") == 0) *do_cache = FALSE;

*result = string_copy(query);
return OK;
}

/* End of lookups/testdb.c */
