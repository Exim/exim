/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2023 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"
#include "lf_functions.h"



/* Ancient systems (e.g. SunOS4) don't appear to have T_TXT defined in their
header files. */

#ifndef T_TXT
# define T_TXT 16
#endif

/* Many systems do not have T_SPF. */
#ifndef T_SPF
# define T_SPF 99
#endif

/* New TLSA record for DANE */
#ifndef T_TLSA
# define T_TLSA 52
#endif

/* Table of recognized DNS record types and their integer values. */

static const char *type_names[] = {
  "a",
#if HAVE_IPV6
  "a+",
  "aaaa",
#endif
  "cname",
  "csa",
  "mx",
  "mxh",
  "ns",
  "ptr",
  "soa",
  "spf",
  "srv",
  "tlsa",
  "txt",
  "zns"
};

static int type_values[] = {
  T_A,
#if HAVE_IPV6
  T_ADDRESSES,     /* Private type for AAAA + A */
  T_AAAA,
#endif
  T_CNAME,
  T_CSA,     /* Private type for "Client SMTP Authorization". */
  T_MX,
  T_MXH,     /* Private type for "MX hostnames" */
  T_NS,
  T_PTR,
  T_SOA,
  T_SPF,
  T_SRV,
  T_TLSA,
  T_TXT,
  T_ZNS      /* Private type for "zone nameservers" */
};


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *
dnsdb_open(const uschar * filename, uschar **errmsg)
{
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

(b) If the next character is ',' then the next character is the separator
character used for multiple items of text in "TXT" records. Alternatively,
if the next character is ';' then these multiple items are concatenated with
no separator. With neither of these options specified, only the first item
is output.  Similarly for "SPF" records, but the default for joining multiple
items in one SPF record is the empty string, for direct concatenation.

(c) Options, all comma-terminated, in any order.  Any unrecognised option
terminates option processing.  Recognised options are:

- 'defer_FOO':  set the defer behaviour to FOO.  The possible behaviours are:
'strict', where any defer causes the whole lookup to defer; 'lax', where a defer
causes the whole lookup to defer only if none of the DNS queries succeeds; and
'never', where all defers are as if the lookup failed. The default is 'lax'.

- 'dnssec_FOO', with 'strict', 'lax' (default), and 'never'.  The meanings are
require, try and don't-try dnssec respectively.

- 'retrans_VAL', set the timeout value.  VAL is an Exim time specification
(eg "5s").  The default is set by the main configuration option 'dns_retrans'.

- 'retry_VAL', set the retry count on timeouts.  VAL is an integer.  The
default is set by the main configuration option "dns_retry".

(d) If the next sequence of characters is a sequence of letters and digits
followed by '=', it is interpreted as the name of the DNS record type. The
default is "TXT".

(e) Then there follows list of domain names. This is a generalized Exim list,
which may start with '<' in order to set a specific separator. The default
separator, as always, is colon. */

static int
dnsdb_find(void * handle, const uschar * filename, const uschar * keystring,
 int length, uschar ** result, uschar ** errmsg, uint * do_cache,
 const uschar * opts)
{
int rc;
int sep = 0;
int defer_mode = PASS, dnssec_mode = PASS;
int save_retrans = dns_retrans, save_retry =   dns_retry;
int type;
int failrc = FAIL;
const uschar * outsep = CUS"\n", * outsep2 = NULL;
uschar * equals, * domain, * found;

dns_answer * dnsa = store_get_dns_answer();
dns_scan dnss;

/* Because we're working in the search pool, we try to reclaim as much
store as possible later, so we preallocate the result here */

gstring * yield = string_get(256);

/* If the string starts with '>' we change the output separator.
If it's followed by ';' or ',' we set the TXT output separator. */

while (isspace(*keystring)) keystring++;
if (*keystring == '>')
  {
  outsep = keystring + 1;
  keystring += 2;
  if (*keystring == ',')
    {
    outsep2 = keystring + 1;
    keystring += 2;
    }
  else if (*keystring == ';')
    {
    outsep2 = US"";
    keystring++;
    }
  while (isspace(*keystring)) keystring++;
  }

/* Check for a modifier keyword. */

for (;;)
  {
  if (strncmpic(keystring, US"defer_", 6) == 0)
    {
    keystring += 6;
    if (strncmpic(keystring, US"strict", 6) == 0)
      { defer_mode = DEFER; keystring += 6; }
    else if (strncmpic(keystring, US"lax", 3) == 0)
      { defer_mode = PASS; keystring += 3; }
    else if (strncmpic(keystring, US"never", 5) == 0)
      { defer_mode = OK; keystring += 5; }
    else
      {
      *errmsg = US"unsupported dnsdb defer behaviour";
      rc = DEFER;
      goto out;
      }
    }
  else if (strncmpic(keystring, US"dnssec_", 7) == 0)
    {
    keystring += 7;
    if (strncmpic(keystring, US"strict", 6) == 0)
      { dnssec_mode = DEFER; keystring += 6; }
    else if (strncmpic(keystring, US"lax", 3) == 0)
      { dnssec_mode = PASS; keystring += 3; }
    else if (strncmpic(keystring, US"never", 5) == 0)
      { dnssec_mode = OK; keystring += 5; }
    else
      {
      *errmsg = US"unsupported dnsdb dnssec behaviour";
      rc = DEFER;
      goto out;
      }
    }
  else if (strncmpic(keystring, US"retrans_", 8) == 0)
    {
    int timeout_sec;
    if ((timeout_sec = readconf_readtime(keystring += 8, ',', FALSE)) <= 0)
      {
      *errmsg = US"unsupported dnsdb timeout value";
      rc = DEFER;
      goto out;
      }
    dns_retrans = timeout_sec;
    while (*keystring != ',') keystring++;
    }
  else if (strncmpic(keystring, US"retry_", 6) == 0)
    {
    int retries;
    if ((retries = (int)strtol(CCS keystring + 6, CSS &keystring, 0)) < 0)
      {
      *errmsg = US"unsupported dnsdb retry count";
      rc = DEFER;
      goto out;
      }
    dns_retry = retries;
    }
  else
    break;

  while (isspace(*keystring)) keystring++;
  if (*keystring++ != ',')
    {
    *errmsg = US"dnsdb modifier syntax error";
    rc = DEFER;
    goto out;
    }
  while (isspace(*keystring)) keystring++;
  }

/* Figure out the "type" value if it is not T_TXT.
If the keystring contains an = this must be preceded by a valid type name. */

type = T_TXT;
if ((equals = Ustrchr(keystring, '=')) != NULL)
  {
  int i, len;
  uschar *tend = equals;

  while (tend > keystring && isspace(tend[-1])) tend--;
  len = tend - keystring;

  for (i = 0; i < nelem(type_names); i++)
    if (len == Ustrlen(type_names[i]) &&
        strncmpic(keystring, US type_names[i], len) == 0)
      {
      type = type_values[i];
      break;
      }

  if (i >= nelem(type_names))
    {
    *errmsg = US"unsupported DNS record type";
    rc = DEFER;
    goto out;
    }

  keystring = equals + 1;
  while (isspace(*keystring)) keystring++;
  }

/* Initialize the resolver in case this is the first time it has been used. */

dns_init(FALSE, FALSE, dnssec_mode != OK);

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

/* SPF strings should be concatenated without a separator, thus make
it the default if not defined (see RFC 4408 section 3.1.3).
Multiple SPF records are forbidden (section 3.1.2) but are currently
not handled specially, thus they are concatenated with \n by default.
MX priority and value are space-separated by default.
SRV and TLSA record parts are space-separated by default. */

if (!outsep2) switch(type)
  {
  case T_SPF:                         outsep2 = US"";  break;
  case T_SRV: case T_MX: case T_TLSA: outsep2 = US" "; break;
  }

/* Now scan the list and do a lookup for each item */

while ((domain = string_nextinlist(&keystring, &sep, NULL, 0)))
  {
  int searchtype = type == T_CSA ? T_SRV :         /* record type we want */
                   type == T_MXH ? T_MX :
                   type == T_ZNS ? T_NS : type;

  /* If the type is PTR or CSA, we have to construct the relevant magic lookup
  key if the original is an IP address (some experimental protocols are using
  PTR records for different purposes where the key string is a host name, and
  Exim's extended CSA can be keyed by domains or IP addresses). This code for
  doing the reversal is now in a separate function. */

  if ((type == T_PTR || type == T_CSA) &&
      string_is_ip_address(domain, NULL) != 0)
    domain = dns_build_reverse(domain);

  do
    {
    DEBUG(D_lookup) debug_printf_indent("dnsdb key: %s\n", domain);

    /* Do the lookup and sort out the result. There are four special types that
    are handled specially: T_CSA, T_ZNS, T_ADDRESSES and T_MXH.
    The first two are handled in a special lookup function so that the facility
    could be used from other parts of the Exim code. T_ADDRESSES is handled by looping
    over the types of A lookup.  T_MXH affects only what happens later on in
    this function, but for tidiness it is handled by the "special". If the
    lookup fails, continue with the next domain. In the case of DEFER, adjust
    the final "nothing found" result, but carry on to the next domain. */

    found = domain;
#if HAVE_IPV6
    if (type == T_ADDRESSES)		/* NB cannot happen unless HAVE_IPV6 */
      {
      if (searchtype == T_ADDRESSES) searchtype = T_AAAA;
      else if (searchtype == T_AAAA) searchtype = T_A;
      rc = dns_special_lookup(dnsa, domain, searchtype, CUSS &found);
      }
    else
#endif
      rc = dns_special_lookup(dnsa, domain, type, CUSS &found);

    lookup_dnssec_authenticated = dnssec_mode==OK ? NULL
      : dns_is_secure(dnsa) ? US"yes" : US"no";

    if (rc == DNS_NOMATCH || rc == DNS_NODATA) continue;
    if (  rc != DNS_SUCCEED
       || (dnssec_mode == DEFER && !dns_is_secure(dnsa))
       )
      {
      if (defer_mode == DEFER)
	{
	dns_retrans = save_retrans;
	dns_retry = save_retry;
	dns_init(FALSE, FALSE, FALSE);			/* clr dnssec bit */
	rc = DEFER;					/* always defer */
	goto out;
	}
      if (defer_mode == PASS) failrc = DEFER;         /* defer only if all do */
      continue;                                       /* treat defer as fail */
      }


    /* Search the returned records */

    for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS); rr;
         rr = dns_next_rr(dnsa, &dnss, RESET_NEXT)) if (rr->type == searchtype)
      {
      if (*do_cache > rr->ttl)
	*do_cache = rr->ttl;

      if (type == T_A || type == T_AAAA || type == T_ADDRESSES)
        {
        for (dns_address * da = dns_address_from_rr(dnsa, rr); da; da = da->next)
	  yield = string_append_listele(yield, *outsep, da->address);
        continue;
        }

      /* Other kinds of record just have one piece of data each, but there may be
      several of them, of course. */

      if (yield->ptr) yield = string_catn(yield, outsep, 1);

      if (type == T_TXT || type == T_SPF)
        {
        if (!outsep2)			/* output only the first item of data */
	  {
	  uschar n = (rr->data)[0];
	  /* size byte + data bytes must not excced the RRs length */
	  if (n + 1 <= rr->size)
	    yield = string_catn(yield, US (rr->data+1), n);
	  }
        else
          for (unsigned data_offset = 0; data_offset < rr->size; )
            {
            uschar chunk_len = (rr->data)[data_offset];
	    int remain = rr->size - data_offset;

	    /* Apparently there are resolvers that do not check RRs before passing
	    them on, and glibc fails to do so.  So every application must...
	    Check for chunk len exceeding RR */

	    if (chunk_len > remain)
	      chunk_len = remain;

            if (*outsep2  && data_offset != 0)
              yield = string_catn(yield, outsep2, 1);
            yield = string_catn(yield, US ((rr->data) + ++data_offset), --chunk_len);
            data_offset += chunk_len;
            }
        }
      else if (type == T_TLSA)
	if (rr->size < 3)
	  continue;
	else
	  {
	  uint8_t usage, selector, matching_type;
	  uint16_t payload_length;
	  uschar s[MAX_TLSA_EXPANDED_SIZE];
	  uschar * sp = s;
	  uschar * p = US rr->data;

	  usage = *p++;
	  selector = *p++;
	  matching_type = *p++;
	  /* What's left after removing the first 3 bytes above */
	  payload_length = rr->size - 3;
	  sp += sprintf(CS s, "%d%c%d%c%d%c", usage, *outsep2,
		  selector, *outsep2, matching_type, *outsep2);
	  /* Now append the cert/identifier, one hex char at a time */
	  while (payload_length-- > 0 && sp-s < (MAX_TLSA_EXPANDED_SIZE - 4))
	    sp += sprintf(CS sp, "%02x", *p++);

	  yield = string_cat(yield, s);
	  }
      else   /* T_CNAME, T_CSA, T_MX, T_MXH, T_NS, T_PTR, T_SOA, T_SRV */
        {
        int priority, weight, port;
        uschar s[264];
        uschar * p = US rr->data;

	switch (type)
	  {
	  case T_MXH:
	    if (rr_bad_size(rr, sizeof(u_int16_t))) continue;
	    /* mxh ignores the priority number and includes only the hostnames */
	    GETSHORT(priority, p);
	    break;

	  case T_MX:
	    if (rr_bad_size(rr, sizeof(u_int16_t))) continue;
	    GETSHORT(priority, p);
	    sprintf(CS s, "%d%c", priority, *outsep2);
	    yield = string_cat(yield, s);
	    break;

	  case T_SRV:
	    if (rr_bad_size(rr, 3*sizeof(u_int16_t))) continue;
	    GETSHORT(priority, p);
	    GETSHORT(weight, p);
	    GETSHORT(port, p);
	    sprintf(CS s, "%d%c%d%c%d%c", priority, *outsep2,
			      weight, *outsep2, port, *outsep2);
	    yield = string_cat(yield, s);
	    break;

	  case T_CSA:
	    if (rr_bad_size(rr, 3*sizeof(u_int16_t))) continue;
	    /* See acl_verify_csa() for more comments about CSA. */
	    GETSHORT(priority, p);
	    GETSHORT(weight, p);
	    GETSHORT(port, p);

	    if (priority != 1) continue;      /* CSA version must be 1 */

	    /* If the CSA record we found is not the one we asked for, analyse
	    the subdomain assertions in the port field, else analyse the direct
	    authorization status in the weight field. */

	    if (Ustrcmp(found, domain) != 0)
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
	    yield = string_catn(yield, s, 2);
	    break;

	  default:
	    break;
	  }

        /* GETSHORT() has advanced the pointer to the target domain. */

        rc = dn_expand(dnsa->answer, dnsa->answer + dnsa->answerlen, p,
          (DN_EXPAND_ARG4_TYPE)s, sizeof(s));

        /* If an overlong response was received, the data will have been
        truncated and dn_expand may fail. */

        if (rc < 0)
          {
          log_write(0, LOG_MAIN, "host name alias list truncated: type=%s "
            "domain=%s", dns_text_type(type), domain);
          break;
          }
        else yield = string_cat(yield, s);

	if (type == T_SOA && outsep2 != NULL)
	  {
	  unsigned long serial = 0, refresh = 0, retry = 0, expire = 0, minimum = 0;

	  p += rc;
	  yield = string_catn(yield, outsep2, 1);

	  rc = dn_expand(dnsa->answer, dnsa->answer + dnsa->answerlen, p,
	    (DN_EXPAND_ARG4_TYPE)s, sizeof(s));
	  if (rc < 0)
	    {
	    log_write(0, LOG_MAIN, "responsible-mailbox truncated: type=%s "
	      "domain=%s", dns_text_type(type), domain);
	    break;
	    }
	  else yield = string_cat(yield, s);

	  p += rc;
	  if (!rr_bad_increment(rr, p, 5 * sizeof(u_int32_t)))
	    {
	    GETLONG(serial, p); GETLONG(refresh, p);
	    GETLONG(retry,  p); GETLONG(expire,  p); GETLONG(minimum, p);
	    }
	  sprintf(CS s, "%c%lu%c%lu%c%lu%c%lu%c%lu",
	    *outsep2, serial, *outsep2, refresh,
	    *outsep2, retry,  *outsep2, expire,  *outsep2, minimum);
	  yield = string_cat(yield, s);
	  }
        }
      }    /* Loop for list of returned records */

           /* Loop for set of A-lookup types */
    } while (type == T_ADDRESSES && searchtype != T_A);

  }        /* Loop for list of domains */

/* Reclaim unused memory */

gstring_release_unused(yield);

/* If yield NULL we have not found anything. Otherwise, insert the terminating
zero and return the result. */

dns_retrans = save_retrans;
dns_retry = save_retry;
dns_init(FALSE, FALSE, FALSE);	/* clear the dnssec bit for getaddrbyname */

if (!yield || !yield->ptr)
  rc = failrc;
else
  {
  *result = string_from_gstring(yield);
  rc = OK;
  }

out:

store_free_dns_answer(dnsa);
return rc;
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
dnsdb_version_report(gstring * g)
{
#ifdef DYNLOOKUP
g = string_fmt_append(g, "Library version: DNSDB: Exim version %s\n", EXIM_VERSION_STR);
#endif
return g;
}


static lookup_info _lookup_info = {
  .name = US"dnsdb",			/* lookup name */
  .type = lookup_querystyle,		/* query style */
  .open = dnsdb_open,			/* open function */
  .check = NULL,			/* check function */
  .find = dnsdb_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = dnsdb_version_report           /* version reporting */
};

#ifdef DYNLOOKUP
#define dnsdb_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info dnsdb_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* vi: aw ai sw=2
*/
/* End of lookups/dnsdb.c */
