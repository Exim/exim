/* $Cambridge: exim/src/src/lookups/nis.c,v 1.2 2005/01/04 10:00:44 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2005 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"
#include "nis.h"

/* We can't just compile this code and allow the library mechanism to omit the
functions if they are not wanted, because we need to have the NIS header
available for compiling. Therefore, compile these functions only if LOOKUP_NIS
is defined. However, some compilers don't like compiling empty modules, so keep
them happy with a dummy when skipping the rest. Make it reference itself to
stop picky compilers complaining that it is unused, and put in a dummy argument
to stop even pickier compilers complaining about infinite loops. */

#ifndef LOOKUP_NIS
static void dummy(int x) { dummy(x-1); }
#else

#include <rpcsvc/ypclnt.h>


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. This serves for both
the "nis" and "nis0" lookup types. */

void *
nis_open(uschar *filename, uschar **errmsg)
{
char *nis_domain;
if (yp_get_default_domain(&nis_domain) != 0)
  {
  *errmsg = string_sprintf("failed to get default NIS domain");
  return NULL;
  }
return nis_domain;
}



/*************************************************
*           Find entry point for nis             *
*************************************************/

/* See local README for interface description. A separate function is used
for nis0 because they are so short it isn't worth trying to use any common
code. */

int
nis_find(void *handle, uschar *filename, uschar *keystring, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
int rc;
uschar *nis_data;
int nis_data_length;
do_cache = do_cache;   /* Placate picky compilers */
if ((rc = yp_match(CS handle, CS filename, CS keystring, length,
    CSS &nis_data, &nis_data_length)) == 0)
  {
  *result = string_copy(nis_data);
  (*result)[nis_data_length] = 0;    /* remove final '\n' */
  return OK;
  }
return (rc == YPERR_KEY || rc == YPERR_MAP)? FAIL : DEFER;
}



/*************************************************
*           Find entry point for nis0            *
*************************************************/

/* See local README for interface description. */

int
nis0_find(void *handle, uschar *filename, uschar *keystring, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
int rc;
uschar *nis_data;
int nis_data_length;
do_cache = do_cache;   /* Placate picky compilers */
if ((rc = yp_match(CS handle, CS filename, CS keystring, length + 1,
    CSS &nis_data, &nis_data_length)) == 0)
  {
  *result = string_copy(nis_data);
  (*result)[nis_data_length] = 0;    /* remove final '\n' */
  return OK;
  }
return (rc == YPERR_KEY || rc == YPERR_MAP)? FAIL : DEFER;
}

#endif  /* LOOKUP_NIS */

/* End of lookups/nis.c */
