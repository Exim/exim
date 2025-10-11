/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Exim - SPF lookup module using Exim's "miscmod" SPF support for ACL

Copyright (c) The Exim Maintainers 2020 - 2025
Copyright (c) 2005 Chris Webb, Arachsys Internet Services Ltd
SPDX-License-Identifier: GPL-2.0-or-later

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
*/

#include "../exim.h"
#include "lf_functions.h"

#ifndef EXPERIMENTAL_SPF_PERL

/*XXX are these really needed? */

# if !defined(HAVE_NS_TYPE) && defined(NS_INADDRSZ)
#  define HAVE_NS_TYPE
# endif
# include <spf2/spf.h>
# include <spf2/spf_dns_resolv.h>
# include <spf2/spf_dns_cache.h>

#endif


static void *
spf_open(const uschar * filename, uschar ** errmsg)
{
misc_module_info * mi;
DEBUG(D_lookup) debug_printf_indent("spf lookup spf_open\n");
if ((mi = misc_mod_find(US"spf", errmsg)))
  {
  typedef void * (*fn_t)(const uschar *, uschar **);
  return (((fn_t *) mi->functions)[SPF_OPEN]) (filename, errmsg);
  }
return NULL;
}


static void
spf_close(void * handle)
{
misc_module_info * mi = misc_mod_find(US"spf", NULL);
if (mi)
  {
  typedef void (*fn_t)(void *);
  return (((fn_t *) mi->functions)[SPF_CLOSE]) (handle);
  }
}


static int
spf_find(void * handle, const uschar * filename, const uschar * keystring,
  int key_len, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
misc_module_info * mi = misc_mod_find(US"spf", errmsg);
if (mi)
  {
  typedef int (*fn_t) (void *, const uschar *, const uschar *,
		      int, uschar **, uschar **, uint *, const uschar *);
  return (((fn_t *) mi->functions)[SPF_FIND])
				      (handle, filename, keystring, key_len,
				      result, errmsg, do_cache, opts);
  }
return FAIL;
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
spf_version_report(gstring * g)
{
#ifdef DYNLOOKUP
g = string_fmt_append(g, "Library version: SPF: Exim version %s\n", EXIM_VERSION_STR));
#endif
return g;
}


static lookup_info spf_lookup_info = {
  .name = US"spf",			/* lookup name */
  .type = 0,				/* not absfile, not query style */
  .open = spf_open,			/* open function */
  .check = NULL,			/* no check function */
  .find = spf_find,			/* find function */
  .close = spf_close,			/* close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = spf_version_report             /* version reporting */
};

#ifdef notdef_DYNLOOKUP
#define spf_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &spf_lookup_info };
lookup_module_info spf_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

