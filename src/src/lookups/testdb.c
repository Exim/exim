/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"
#include "lf_functions.h"


/* These are not real lookup functions; they are just a way of testing the
rest of Exim by providing an easy way of specifying particular yields from
the find function. */


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *
testdb_open(const uschar * filename, uschar ** errmsg)
{
return (void *)(1);    /* Just return something non-null */
}



/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. */

static int
testdb_find(void * handle, const uschar * filename, const uschar * query,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
if (Ustrcmp(query, "fail") == 0)
  {
  *errmsg = US"testdb lookup forced FAIL";
  DEBUG(D_lookup) debug_printf_indent("%s\n", *errmsg);
  return FAIL;
  }
if (Ustrcmp(query, "defer") == 0)
  {
  *errmsg = US"testdb lookup forced DEFER";
  DEBUG(D_lookup) debug_printf_indent("%s\n", *errmsg);
  return DEFER;
  }

if (Ustrcmp(query, "nocache") == 0) *do_cache = 0;

*result = string_copy(query);
return OK;
}


/* Don't actually alter the string; just copy to quoted-pool memory */

static uschar *
testdb_quote(uschar * s, uschar * opt, unsigned idx)
{
int len = Ustrlen(s) + 1;
uschar * quoted = store_get_quoted(len, s, idx, US"testdb");
memcpy(quoted, s, len);
return quoted;
}

/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
testdb_version_report(gstring * g)
{
#ifdef DYNLOOKUP
g = string_fmt_append(g, "Library version: TestDB: Exim version %s\n", EXIM_VERSION_STR);
#endif
return g;
}


static lookup_info testdb_lookup_info = {
  .name = US"testdb",			/* lookup name */
  .type = lookup_querystyle,		/* query-style lookup */
  .open = testdb_open,			/* open function */
  .check = NULL,			/* check function */
  .find = testdb_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = NULL,				/* no tidy function */
  .quote = testdb_quote,		/* quoting function */
  .version_report = testdb_version_report          /* version reporting */
};

static lookup_info testdb2_lookup_info = {
  .name = US"testdb2",			/* lookup name */
  .type = lookup_querystyle,		/* query-style lookup */
  .open = testdb_open,			/* open function */
  .check = NULL,			/* check function */
  .find = testdb_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = NULL,				/* no tidy function */
  .quote = testdb_quote,		/* same quoting function */
  .version_report = testdb_version_report          /* version reporting */
};

static lookup_info testdb3_lookup_info = {
  .name = US"testdb_nq",		/* lookup name */
  .type = lookup_querystyle,		/* query-style lookup */
  .open = testdb_open,			/* open function */
  .check = NULL,			/* check function */
  .find = testdb_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* NO quoting function */
  .version_report = testdb_version_report          /* version reporting */
};

#ifdef DYNLOOKUP
#define testdb_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = {
  &testdb_lookup_info,
  &testdb2_lookup_info,
  &testdb3_lookup_info
};

lookup_module_info testdb_lookup_module_info = {
  LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 3 };

/* End of lookups/testdb.c */
