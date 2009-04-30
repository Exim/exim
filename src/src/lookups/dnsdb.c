/* $Cambridge: exim/src/src/lookups/dnsdb.c,v 1.17.2.1 2009/04/30 08:21:30 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"
#include "dnsdb.h"



/* Ancient systems (e.g. SunOS4) don't appear to have T_TXT defined in their
header files. */

#ifndef T_TXT
#define T_TXT 16
#endif

/* Table of recognized DNS record types and their integer values. */

static char *type_names[] = {
  "a",
#if HAVE_IPV6
  "aaaa",
  #ifdef SUPPORT_A6
  "a6",
  #endif
#endif
  "cname",
  "csa",
  "mx",
  "mxh",
  "ns",
  "ptr",
  "srv",
  "txt",
  "zns"
};

static int type_values[] = {
  T_A,
#if HAVE_IPV6
  T_AAAA,
  #ifdef SUPPORT_A6
  T_A6,
  #endif
#endif
  T_CNAME,
  T_CSA,     /* Private type for "Client SMTP Authorization". */
  T_MX,
  T_MXH,     /* Private type for "MX hostnames" */
  T_NS,
  T_PTR,
  T_SRV,
  T_TXT,
  T_ZNS      /* Private type for "zone nameservers" */
};


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

void *
dnsdb_open(uschar *filename, uschar **errmsg)
{
filename = filename;   /* Keep picky compilers happy */
errmsg = errmsg;       /* Ditto */
return (void *)(-1);   /* Any non-0 value */
}



/*************************************************
*           Find entry point for dnsdb           *
*************************************************/

/* See local README for interface description. The query in the "keystring" may
consist of a number of parts.

(a) If the first significant character is '>' then the next character is the
separator character that is used when multiple records are found. The default
separator is newline.

(b) If the next sequence of characters is 'defer_FOO' followed by a comma,
the defer behaviour is set to FOO. The possible behaviours are: 'strict', where
any defer causes the whole lookup to defer; 'lax', where a defer causes the
whole lookup to defer only if none of the DNS queries succeeds; and 'never',
where all defers are as if the lookup failed. The default is 'lax'.

(c) If the next sequence of characters is a sequence of letters and digits
followed by '=', it is interpreted as the name of the DNS record type. The
default is "TXT".

(d) Then there follows list of domain names. This is a generalized Exim list,
which may start with '<' in order to set a specific separator. The default
separator, as always, is colon. */

int
dnsdb_find(void *handle, uschar *filename, uschar *keystring, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
int rc;
int size = 256;
int ptr = 0;
int sep = 0;
int defer_mode = PASS;
int type = T_TXT;
int failrc = FAIL;
uschar *outsep = US"\n";
uschar *equals, *domain, *found;
uschar buffer[256];

/* Because we're the working in the search pool, we try to reclaim as much
store as possible later, so we preallocate the result here */

uschar *yield = store_get(size);

dns_record *rr;
dns_answer dnsa;
dns_scan dnss;

handle = handle;           /* Keep picky compilers happy */
filename = filename;
length = length;
do_cache = do_cache;

/* If the string starts with '>' we change the output separator */

while (isspace(*keystring)) keystring++;
if (*keystring == '>')
  {
  outsep = keystring + 1;
  keystring += 2;
  while (isspace(*keystring)) keystring++;
  }

/* Check for a defer behaviour keyword. */

if (strncmpic(keystring, US"defer_", 6) == 0)
  {
  keystring += 6;
  if (strncmpic(keystring, US"strict", 6) == 0)
    {
    defer_mode = DEFER;
    keystring += 6;
    }
  else if (strncmpic(keystring, US"lax", 3) == 0)
    {
    defer_mode = PASS;
    keystring += 3;
    }
  else if (strncmpic(keystring, US"never", 5) == 0)
    {
    defer_mode = OK;
    keystring += 5;
    }
  else
    {
    *errmsg = US"unsupported dnsdb defer behaviour";
    return DEFER;
    }
  while (isspace(*keystring)) keystring++;
  if (*keystring++ != ',')
    {
    *errmsg = US"dnsdb defer behaviour syntax error";
    return DEFER;
    }
  while (isspace(*keystring)) keystring++;
  }

/* If the keystring contains an = this must be preceded by a valid type name. */

if ((equals = Ustrchr(keystring, '=')) != NULL)
  {
  int i, len;
  uschar *tend = equals;

  while (tend > keystring && isspace(tend[-1])) tend--;
  len = tend - keystring;

  for (i = 0; i < sizeof(type_names)/sizeof(uschar *); i++)
    {
    if (len == Ustrlen(type_names[i]) &&
        strncmpic(keystring, US type_names[i], len) == 0)
      {
      type = type_values[i];
      break;
      }
    }

  if (i >= sizeof(type_names)/sizeof(uschar *))
    {
    *errmsg = US"unsupported DNS record type";
    return DEFER;
    }

  keystring = equals + 1;
  while (isspace(*keystring)) keystring++;
  }

/* Initialize the resolver in case this is the first time it has been used. */

dns_init(FALSE, FALSE);

/* The remainder of the string must be a list of domains. As long as the lookup
for at least one of them succeeds, we return success. Failure means that none
of them were found.

The original implementation did not support a list of domains. Adding the list
feature is compatible, except in one case: when PTR records are being looked up
for a single IPv6 address. Fortunately, we can hack in a compatibility feature
here: If the type is PTR and no list separator is specified, and the entire
remaining string is valid as an IP address, set an impossible separator so that
it is treated as one item. */

if (type == T_PTR && keystring[0] != '<' &&
    string_is_ip_address(keystring, NULL) != 0)
  sep = -1;

/* Now scan the list and do a lookup for each item */

while ((domain = string_nextinlist(&keystring, &sep, buffer, sizeof(buffer)))
        != NULL)
  {
  uschar rbuffer[256];
  int searchtype = (type == T_CSA)? T_SRV :         /* record type we want */
                   (type == T_MXH)? T_MX :
                   (type == T_ZNS)? T_NS : type;

  /* If the type is PTR or CSA, we have to construct the relevant magic lookup
  key if the original is an IP address (some experimental protocols are using
  PTR records for different purposes where the key string is a host name, and
  Exim's extended CSA can be keyed by domains or IP addresses). This code for
  doing the reversal is now in a separate function. */

  if ((type == T_PTR || type == T_CSA) &&
      string_is_ip_address(domain, NULL) != 0)
    {
    dns_build_reverse(domain, rbuffer);
    domain = rbuffer;
    }

  DEBUG(D_lookup) debug_printf("dnsdb key: %s\n", domain);

  /* Do the lookup and sort out the result. There are three special types that
  are handled specially: T_CSA, T_ZNS and T_MXH. The former two are handled in
  a special lookup function so that the facility could be used from other
  parts of the Exim code. The latter affects only what happens later on in
  this function, but for tidiness it is handled in a similar way. If the
  lookup fails, continue with the next domain. In the case of DEFER, adjust
  the final "nothing found" result, but carry on to the next domain. */

  found = domain;
  rc = dns_special_lookup(&dnsa, domain, type, &found);

  if (rc == DNS_NOMATCH || rc == DNS_NODATA) continue;
  if (rc != DNS_SUCCEED)
    {
    if (defer_mode == DEFER) return DEFER;          /* always defer */
      else if (defer_mode == PASS) failrc = DEFER;  /* defer only if all do */
    continue;                                       /* treat defer as fail */
    }

  /* Search the returned records */

  for (rr = dns_next_rr(&dnsa, &dnss, RESET_ANSWERS);
       rr != NULL;
       rr = dns_next_rr(&dnsa, &dnss, RESET_NEXT))
    {
    if (rr->type != searchtype) continue;

    /* There may be several addresses from an A6 record. Put the configured
    separator between them, just as for between several records. However, A6
    support is not normally configured these days. */

    if (type == T_A ||
        #ifdef SUPPORT_A6
        type == T_A6 ||
        #endif
        type == T_AAAA)
      {
      dns_address *da;
      for (da = dns_address_from_rr(&dnsa, rr); da != NULL; da = da->next)
        {
        if (ptr != 0) yield = string_cat(yield, &size, &ptr, outsep, 1);
        yield = string_cat(yield, &size, &ptr, da->address,
          Ustrlen(da->address));
        }
      continue;
      }

    /* Other kinds of record just have one piece of data each, but there may be
    several of them, of course. */

    if (ptr != 0) yield = string_cat(yield, &size, &ptr, outsep, 1);

    if (type == T_TXT)
      {
      int data_offset = 0;
      while (data_offset < rr->size)
        {
        uschar chunk_len = (rr->data)[data_offset++];
        yield = string_cat(yield, &size, &ptr,
                           (uschar *)((rr->data)+data_offset), chunk_len);
        data_offset += chunk_len;
        }
      }
    else   /* T_CNAME, T_CSA, T_MX, T_MXH, T_NS, T_PTR, T_SRV */
      {
      int priority, weight, port;
      uschar s[264];
      uschar *p = (uschar *)(rr->data);

      if (type == T_MXH)
        {
        /* mxh ignores the priority number and includes only the hostnames */
        GETSHORT(priority, p);
        }
      else if (type == T_MX)
        {
        GETSHORT(priority, p);
        sprintf(CS s, "%d ", priority);
        yield = string_cat(yield, &size, &ptr, s, Ustrlen(s));
        }
      else if (type == T_SRV)
        {
        GETSHORT(priority, p);
        GETSHORT(weight, p);
        GETSHORT(port, p);
        sprintf(CS s, "%d %d %d ", priority, weight, port);
        yield = string_cat(yield, &size, &ptr, s, Ustrlen(s));
        }
      else if (type == T_CSA)
        {
        /* See acl_verify_csa() for more comments about CSA. */

        GETSHORT(priority, p);
        GETSHORT(weight, p);
        GETSHORT(port, p);

        if (priority != 1) continue;      /* CSA version must be 1 */

        /* If the CSA record we found is not the one we asked for, analyse
        the subdomain assertions in the port field, else analyse the direct
        authorization status in the weight field. */

        if (found != domain)
          {
          if (port & 1) *s = 'X';         /* explicit authorization required */
          else *s = '?';                  /* no subdomain assertions here */
          }
        else
          {
          if (weight < 2) *s = 'N';       /* not authorized */
          else if (weight == 2) *s = 'Y'; /* authorized */
          else if (weight == 3) *s = '?'; /* unauthorizable */
          else continue;                  /* invalid */
          }

        s[1] = ' ';
        yield = string_cat(yield, &size, &ptr, s, 2);
        }

      /* GETSHORT() has advanced the pointer to the target domain. */

      rc = dn_expand(dnsa.answer, dnsa.answer + dnsa.answerlen, p,
        (DN_EXPAND_ARG4_TYPE)(s), sizeof(s));

      /* If an overlong response was received, the data will have been
      truncated and dn_expand may fail. */

      if (rc < 0)
        {
        log_write(0, LOG_MAIN, "host name alias list truncated: type=%s "
          "domain=%s", dns_text_type(type), domain);
        break;
        }
      else yield = string_cat(yield, &size, &ptr, s, Ustrlen(s));
      }
    }    /* Loop for list of returned records */
  }      /* Loop for list of domains */

/* Reclaim unused memory */

store_reset(yield + ptr + 1);

/* If ptr == 0 we have not found anything. Otherwise, insert the terminating
zero and return the result. */

if (ptr == 0) return failrc;
yield[ptr] = 0;
*result = yield;
return OK;
}

/* End of lookups/dnsdb.c */
