/* $Cambridge: exim/src/src/lookups/whoson.c,v 1.4 2007/01/08 10:50:19 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

/* This code originally came from Robert Wal. */

#include "../exim.h"


/* We can't just compile this code and allow the library mechanism to omit the
functions if they are not wanted, because we need to have the WHOSON headers
available for compiling. Therefore, compile these functions only if
LOOKUP_WHOSON is defined. However, some compilers don't like compiling empty
modules, so keep them happy with a dummy when skipping the rest. Make it
reference itself to stop picky compilers complaining that it is unused, and put
in a dummy argument to stop even pickier compilers complaining about infinite
loops. */

#ifndef LOOKUP_WHOSON
static void dummy(int x) { dummy(x-1); }
#else


#include <whoson.h>        /* Public header */
#include "whoson.h"        /* Local header */


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

void *
whoson_open(uschar *filename, uschar **errmsg)
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
whoson_find(void *handle, uschar *filename, uschar *query, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
uschar buffer[80];
handle = handle;          /* Keep picky compilers happy */
filename = filename;
length = length;
errmsg = errmsg;
do_cache = do_cache;

switch (wso_query(query, CS buffer, sizeof(buffer)))
  {
  case 0:
  *result = string_copy(buffer);    /* IP in database; return name of user */
  return OK;

  case +1:
  return FAIL;                      /* IP not in database */

  default:
  *errmsg = string_sprintf("WHOSON: failed to complete: %s", buffer);
  return DEFER;
  }
}

#endif  /* LOOKUP_WHOSON */

/* End of lookups/whoson.c */
