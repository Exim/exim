/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Exim - SPF lookup module using libspf2
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Copyright (c) 2005 Chris Webb, Arachsys Internet Services Ltd

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

Copyright (c) The Exim Maintainers 2020
*/

#include "../exim.h"

#ifndef SUPPORT_SPF
static void dummy(int x);
static void dummy2(int x) { dummy(x-1); }
static void dummy(int x) { dummy2(x-1); }
#else

#include "lf_functions.h"
#if !defined(HAVE_NS_TYPE) && defined(NS_INADDRSZ)
# define HAVE_NS_TYPE
#endif
#include <spf2/spf.h>
#include <spf2/spf_dns_resolv.h>
#include <spf2/spf_dns_cache.h>

extern SPF_dns_server_t * SPF_dns_exim_new(int);


static void *
spf_open(const uschar * filename, uschar ** errmsg)
{
SPF_dns_server_t * dc;
SPF_server_t *spf_server = NULL;
int debug = 0;

DEBUG(D_lookup) debug = 1;

if ((dc = SPF_dns_exim_new(debug)))
  if ((dc = SPF_dns_cache_new(dc, NULL, debug, 8)))
    spf_server = SPF_server_new_dns(dc, debug);

if (!spf_server)
  {
  *errmsg = US"SPF_dns_exim_nnew() failed";
  return NULL;
  }
return (void *) spf_server;
}


static void
spf_close(void *handle)
{
SPF_server_t *spf_server = handle;
if (spf_server) SPF_server_free(spf_server);
}

static int
spf_find(void * handle, const uschar * filename, const uschar * keystring,
  int key_len, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
SPF_server_t *spf_server = handle;
SPF_request_t *spf_request;
SPF_response_t *spf_response = NULL;

if (!(spf_request = SPF_request_new(spf_server)))
  {
  *errmsg = US"SPF_request_new() failed";
  return FAIL;
  }

#if HAVE_IPV6
switch (string_is_ip_address(filename, NULL))
#else
switch (4)
#endif
  {
  case 4:
    if (!SPF_request_set_ipv4_str(spf_request, CS filename))
      break;
    *errmsg = string_sprintf("invalid IPv4 address '%s'", filename);
    return FAIL;
#if HAVE_IPV6

  case 6:
    if (!SPF_request_set_ipv6_str(spf_request, CS filename))
      break;
    *errmsg = string_sprintf("invalid IPv6 address '%s'", filename);
    return FAIL;

  default:
    *errmsg = string_sprintf("invalid IP address '%s'", filename);
    return FAIL;
#endif
  }

if (SPF_request_set_env_from(spf_request, CS keystring))
    {
  *errmsg = string_sprintf("invalid envelope from address '%s'", keystring);
  return FAIL;
}

SPF_request_query_mailfrom(spf_request, &spf_response);
*result = string_copy(US SPF_strresult(SPF_response_result(spf_response)));

DEBUG(D_lookup) spf_response_debug(spf_response);

SPF_response_free(spf_response);
SPF_request_free(spf_request);
return OK;
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
spf_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: SPF: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


static lookup_info _lookup_info = {
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

#ifdef DYNLOOKUP
#define spf_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info spf_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

#endif /* SUPPORT_SPF */
