/* $Cambridge: exim/src/src/lookups/dkim.c,v 1.1.2.1 2009/02/24 15:57:55 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "dkim.h"



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */

void *
dkim_open(uschar *filename, uschar **errmsg)
{
filename = filename;     /* Keep picky compilers happy */
errmsg = errmsg;
return (void *)(-1);     /* Just return something non-null */
}




/*************************************************
*         Find entry point for passwd           *
*************************************************/

/* See local README for interface description */

int
dkim_find(void *handle, uschar *filename, uschar *keystring, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
#ifndef DISABLE_DKIM
  dkim_exim_verify_result(keystring,result,errmsg);
  return OK;
#else
  *errmsg = US"DKIM support not compiled.";
  *result = US"unverified";
  return FAIL;
#endif
}

/* End of lookups/dkim.c */
