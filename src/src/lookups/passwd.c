/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */

static void *
passwd_open(const uschar * filename, uschar ** errmsg)
{
return (void *)(1);     /* Just return something non-null */
}




/*************************************************
*         Find entry point for passwd           *
*************************************************/

/* See local README for interface description */

static int
passwd_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
struct passwd *pw;

if (!route_finduser(keystring, &pw, NULL)) return FAIL;
*result = string_sprintf("*:%d:%d:%s:%s:%s", (int)pw->pw_uid, (int)pw->pw_gid,
  pw->pw_gecos, pw->pw_dir, pw->pw_shell);
return OK;
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
passwd_version_report(gstring * g)
{
#ifdef DYNLOOKUP
g = string_fmt_append(g, "Library version: passwd: Exim version %s\n", EXIM_VERSION_STR);
#endif
return g;
}

static lookup_info _lookup_info = {
  .name = US"passwd",			/* lookup name */
  .type = lookup_querystyle,		/* query-style lookup */
  .open = passwd_open,			/* open function */
  .check = NULL,			/* no check function */
  .find = passwd_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = passwd_version_report          /* version reporting */
};

#ifdef DYNLOOKUP
#define passwd_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info passwd_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/passwd.c */
