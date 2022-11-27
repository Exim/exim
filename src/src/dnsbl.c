/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-only */

/* Functions concerned with dnsbls */


#include "exim.h"

/* Structure for caching DNSBL lookups */

typedef struct dnsbl_cache_block {
  time_t expiry;
  dns_address *rhs;
  uschar *text;
  int rc;
  BOOL text_set;
} dnsbl_cache_block;


/* Anchor for DNSBL cache */

static tree_node *dnsbl_cache = NULL;


/* Bits for match_type in one_check_dnsbl() */

#define MT_NOT 1
#define MT_ALL 2


/*************************************************
*          Perform a single dnsbl lookup         *
*************************************************/

/* This function is called from verify_check_dnsbl() below. It is also called
recursively from within itself when domain and domain_txt are different
pointers, in order to get the TXT record from the alternate domain.

Arguments:
  domain         the outer dnsbl domain
  domain_txt     alternate domain to lookup TXT record on success; when the
                   same domain is to be used, domain_txt == domain (that is,
                   the pointers must be identical, not just the text)
  keydomain      the current keydomain (for debug message)
  prepend        subdomain to lookup (like keydomain, but
                   reversed if IP address)
  iplist         the list of matching IP addresses, or NULL for "any"
  bitmask        true if bitmask matching is wanted
  match_type     condition for 'succeed' result
                   0 => Any RR in iplist     (=)
                   1 => No RR in iplist      (!=)
                   2 => All RRs in iplist    (==)
                   3 => Some RRs not in iplist (!==)
                   the two bits are defined as MT_NOT and MT_ALL
  defer_return   what to return for a defer

Returns:         OK if lookup succeeded
                 FAIL if not
*/

static int
one_check_dnsbl(uschar *domain, uschar *domain_txt, uschar *keydomain,
  uschar *prepend, uschar *iplist, BOOL bitmask, int match_type,
  int defer_return)
{
dns_answer * dnsa = store_get_dns_answer();
dns_scan dnss;
tree_node *t;
dnsbl_cache_block *cb;
int old_pool = store_pool;
uschar * query;
int qlen, yield;

/* Construct the specific query domainname */

query = string_sprintf("%s.%s", prepend, domain);
if ((qlen = Ustrlen(query)) >= 256)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "dnslist query is too long "
    "(ignored): %s...", query);
  yield = FAIL;
  goto out;
  }

/* Look for this query in the cache. */

if (  (t = tree_search(dnsbl_cache, query))
   && (cb = t->data.ptr)->expiry > time(NULL)
   )

/* Previous lookup was cached */

  {
  HDEBUG(D_dnsbl) debug_printf("dnslists: using result of previous lookup\n");
  }

/* If not cached from a previous lookup, we must do a DNS lookup, and
cache the result in permanent memory. */

else
  {
  uint ttl = 3600;	/* max TTL for positive cache entries */

  store_pool = POOL_PERM;

  if (t)
    {
    HDEBUG(D_dnsbl) debug_printf("cached data found but past valid time; ");
    }

  else
    {	/* Set up a tree entry to cache the lookup */
    t = store_get(sizeof(tree_node) + qlen + 1 + 1, query);
    Ustrcpy(t->name, query);
    t->data.ptr = cb = store_get(sizeof(dnsbl_cache_block), GET_UNTAINTED);
    (void)tree_insertnode(&dnsbl_cache, t);
    }

  /* Do the DNS lookup . */

  HDEBUG(D_dnsbl) debug_printf("new DNS lookup for %s\n", query);
  cb->rc = dns_basic_lookup(dnsa, query, T_A);
  cb->text_set = FALSE;
  cb->text = NULL;
  cb->rhs = NULL;

  /* If the lookup succeeded, cache the RHS address. The code allows for
  more than one address - this was for complete generality and the possible
  use of A6 records. However, A6 records are no longer supported. Leave the code
  here, just in case.

  Quite apart from one A6 RR generating multiple addresses, there are DNS
  lists that return more than one A record, so we must handle multiple
  addresses generated in that way as well.

  Mark the cache entry with the "now" plus the minimum of the address TTLs,
  or the RFC 2308 negative-cache value from the SOA if none were found. */

  switch (cb->rc)
    {
    case DNS_SUCCEED:
      {
      dns_address ** addrp = &cb->rhs;
      dns_address * da;
      for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS); rr;
	   rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
	if (rr->type == T_A && (da = dns_address_from_rr(dnsa, rr)))
	  {
	  *addrp = da;
	  while (da->next) da = da->next;
	  addrp = &da->next;
	  if (ttl > rr->ttl) ttl = rr->ttl;
	  }

      if (cb->rhs)
	{
	cb->expiry = time(NULL) + ttl;
	break;
	}

      /* If we didn't find any A records, change the return code. This can
      happen when there is a CNAME record but there are no A records for what
      it points to. */

      cb->rc = DNS_NODATA;
      }
      /*FALLTHROUGH*/

    case DNS_NOMATCH:
    case DNS_NODATA:
      {
      /* Although there already is a neg-cache layer maintained by
      dns_basic_lookup(), we have a dnslist cache entry allocated and
      tree-inserted. So we may as well use it. */

      time_t soa_negttl = dns_expire_from_soa(dnsa, T_A);
      cb->expiry = soa_negttl ? soa_negttl : time(NULL) + ttl;
      break;
      }

    default:
      cb->expiry = time(NULL) + ttl;
      break;
    }

  store_pool = old_pool;
  HDEBUG(D_dnsbl) debug_printf("dnslists: wrote cache entry, ttl=%d\n",
    (int)(cb->expiry - time(NULL)));
  }

/* We now have the result of the DNS lookup, either newly done, or cached
from a previous call. If the lookup succeeded, check against the address
list if there is one. This may be a positive equality list (introduced by
"="), a negative equality list (introduced by "!="), a positive bitmask
list (introduced by "&"), or a negative bitmask list (introduced by "!&").*/

if (cb->rc == DNS_SUCCEED)
  {
  dns_address * da = NULL;
  uschar *addlist = cb->rhs->address;

  /* For A and AAAA records, there may be multiple addresses from multiple
  records. For A6 records (currently not expected to be used) there may be
  multiple addresses from a single record. */

  for (da = cb->rhs->next; da; da = da->next)
    addlist = string_sprintf("%s, %s", addlist, da->address);

  HDEBUG(D_dnsbl) debug_printf("DNS lookup for %s succeeded (yielding %s)\n",
    query, addlist);

  /* Address list check; this can be either for equality, or via a bitmask.
  In the latter case, all the bits must match. */

  if (iplist)
    {
    for (da = cb->rhs; da; da = da->next)
      {
      int ipsep = ',';
      const uschar *ptr = iplist;
      uschar *res;

      /* Handle exact matching */

      if (!bitmask)
	{
        while ((res = string_nextinlist(&ptr, &ipsep, NULL, 0)))
          if (Ustrcmp(CS da->address, res) == 0)
	    break;
	}

      /* Handle bitmask matching */

      else
        {
        int address[4];
        int mask = 0;

        /* At present, all known DNS blocking lists use A records, with
        IPv4 addresses on the RHS encoding the information they return. I
        wonder if this will linger on as the last vestige of IPv4 when IPv6
        is ubiquitous? Anyway, for now we use paranoia code to completely
        ignore IPv6 addresses. The default mask is 0, which always matches.
        We change this only for IPv4 addresses in the list. */

        if (host_aton(da->address, address) == 1)
	  if ((address[0] & 0xff000000) != 0x7f000000)    /* 127.0.0.0/8 */
	    log_write(0, LOG_MAIN,
	      "DNS list lookup for %s at %s returned %s;"
	      " not in 127.0/8 and discarded",
	      keydomain, domain, da->address);

	  else
	    mask = address[0];

        /* Scan the returned addresses, skipping any that are IPv6 */

        while ((res = string_nextinlist(&ptr, &ipsep, NULL, 0)))
          if (host_aton(res, address) == 1)
	    if ((address[0] & mask) == address[0])
	      break;
        }

      /* If either

         (a) An IP address in an any ('=') list matched, or
         (b) No IP address in an all ('==') list matched

      then we're done searching. */

      if (((match_type & MT_ALL) != 0) == (res == NULL)) break;
      }

    /* If da == NULL, either

       (a) No IP address in an any ('=') list matched, or
       (b) An IP address in an all ('==') list didn't match

    so behave as if the DNSBL lookup had not succeeded, i.e. the host is not on
    the list. */

    if ((match_type == MT_NOT || match_type == MT_ALL) != (da == NULL))
      {
      HDEBUG(D_dnsbl)
        {
        uschar *res = NULL;
        switch(match_type)
          {
          case 0:
	    res = US"was no match"; break;
          case MT_NOT:
	    res = US"was an exclude match"; break;
          case MT_ALL:
	    res = US"was an IP address that did not match"; break;
          case MT_NOT|MT_ALL:
	    res = US"were no IP addresses that did not match"; break;
          }
        debug_printf("=> but we are not accepting this block class because\n");
        debug_printf("=> there %s for %s%c%s\n",
          res,
          match_type & MT_ALL ? "=" : "",
          bitmask ? '&' : '=', iplist);
        }
      yield = FAIL;
      goto out;
      }
    }

  /* No address list check; discard any illegal returns and give up if
  none remain. */

  else
    {
    BOOL ok = FALSE;
    for (da = cb->rhs; da; da = da->next)
      {
      int address[4];

      if (  host_aton(da->address, address) == 1		/* ipv4 */
	 && (address[0] & 0xff000000) == 0x7f000000	/* 127.0.0.0/8 */
	 )
	ok = TRUE;
      else
	log_write(0, LOG_MAIN,
	    "DNS list lookup for %s at %s returned %s;"
	    " not in 127.0/8 and discarded",
	    keydomain, domain, da->address);
      }
    if (!ok)
      {
      yield = FAIL;
      goto out;
      }
    }

  /* Either there was no IP list, or the record matched, implying that the
  domain is on the list. We now want to find a corresponding TXT record. If an
  alternate domain is specified for the TXT record, call this function
  recursively to look that up; this has the side effect of re-checking that
  there is indeed an A record at the alternate domain. */

  if (domain_txt != domain)
    {
    yield = one_check_dnsbl(domain_txt, domain_txt, keydomain, prepend, NULL,
      FALSE, match_type, defer_return);
    goto out;
    }

  /* If there is no alternate domain, look up a TXT record in the main domain
  if it has not previously been cached. */

  if (!cb->text_set)
    {
    cb->text_set = TRUE;
    if (dns_basic_lookup(dnsa, query, T_TXT) == DNS_SUCCEED)
      for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS); rr;
           rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
        if (rr->type == T_TXT)
	  {
	  int len = (rr->data)[0];
	  if (len > 511) len = 127;
	  store_pool = POOL_PERM;
	  cb->text = string_copyn_taint(CUS (rr->data+1), len, GET_TAINTED);
	  store_pool = old_pool;
	  break;
	  }
    }

  dnslist_value = addlist;
  dnslist_text = cb->text;
  yield = OK;
  goto out;
  }

/* There was a problem with the DNS lookup */

if (cb->rc != DNS_NOMATCH && cb->rc != DNS_NODATA)
  {
  log_write(L_dnslist_defer, LOG_MAIN,
    "DNS list lookup defer (probably timeout) for %s: %s", query,
    defer_return == OK ?   US"assumed in list" :
    defer_return == FAIL ? US"assumed not in list" :
                            US"returned DEFER");
  yield = defer_return;
  goto out;
  }

/* No entry was found in the DNS; continue for next domain */

HDEBUG(D_dnsbl)
  {
  debug_printf("DNS lookup for %s failed\n", query);
  debug_printf("=> that means %s is not listed at %s\n",
     keydomain, domain);
  }

yield = FAIL;

out:

store_free_dns_answer(dnsa);
return yield;
}




/*************************************************
*        Check host against DNS black lists      *
*************************************************/

/* This function runs checks against a list of DNS black lists, until one
matches. Each item on the list can be of the form

  domain=ip-address/key

The domain is the right-most domain that is used for the query, for example,
blackholes.mail-abuse.org. If the IP address is present, there is a match only
if the DNS lookup returns a matching IP address. Several addresses may be
given, comma-separated, for example: x.y.z=127.0.0.1,127.0.0.2.

If no key is given, what is looked up in the domain is the inverted IP address
of the current client host. If a key is given, it is used to construct the
domain for the lookup. For example:

  dsn.rfc-ignorant.org/$sender_address_domain

After finding a match in the DNS, the domain is placed in $dnslist_domain, and
then we check for a TXT record for an error message, and if found, save its
value in $dnslist_text. We also cache everything in a tree, to optimize
multiple lookups.

The TXT record is normally looked up in the same domain as the A record, but
when many lists are combined in a single DNS domain, this will not be a very
specific message. It is possible to specify a different domain for looking up
TXT records; this is given before the main domain, comma-separated. For
example:

  dnslists = http.dnsbl.sorbs.net,dnsbl.sorbs.net=127.0.0.2 : \
             socks.dnsbl.sorbs.net,dnsbl.sorbs.net=127.0.0.3

The caching ensures that only one lookup in dnsbl.sorbs.net is done.

Note: an address for testing RBL is 192.203.178.39
Note: an address for testing DUL is 192.203.178.4
Note: a domain for testing RFCI is example.tld.dsn.rfc-ignorant.org

Arguments:
  where        the acl type
  listptr      the domain/address/data list
  log_msgptr   log message on error

Returns:    OK      successful lookup (i.e. the address is on the list), or
                      lookup deferred after +include_unknown
            FAIL    name not found, or no data found for the given type, or
                      lookup deferred after +exclude_unknown (default)
            DEFER   lookup failure, if +defer_unknown was set
*/

int
verify_check_dnsbl(int where, const uschar ** listptr, uschar ** log_msgptr)
{
int sep = 0;
int defer_return = FAIL;
const uschar *list = *listptr;
uschar *domain;
uschar revadd[128];        /* Long enough for IPv6 address */

/* Indicate that the inverted IP address is not yet set up */

revadd[0] = 0;

/* In case this is the first time the DNS resolver is being used. */

dns_init(FALSE, FALSE, FALSE);	/*XXX dnssec? */

/* Loop through all the domains supplied, until something matches */

while ((domain = string_nextinlist(&list, &sep, NULL, 0)))
  {
  int rc;
  BOOL bitmask = FALSE;
  int match_type = 0;
  uschar *domain_txt;
  uschar *comma;
  uschar *iplist;
  uschar *key;

  HDEBUG(D_dnsbl) debug_printf("dnslists check: %s\n", domain);

  /* Deal with special values that change the behaviour on defer */

  if (domain[0] == '+')
    {
    if      (strcmpic(domain, US"+include_unknown") == 0) defer_return = OK;
    else if (strcmpic(domain, US"+exclude_unknown") == 0) defer_return = FAIL;
    else if (strcmpic(domain, US"+defer_unknown") == 0)   defer_return = DEFER;
    else
      log_write(0, LOG_MAIN|LOG_PANIC, "unknown item in dnslist (ignored): %s",
        domain);
    continue;
    }

  /* See if there's explicit data to be looked up */

  if ((key = Ustrchr(domain, '/'))) *key++ = 0;

  /* See if there's a list of addresses supplied after the domain name. This is
  introduced by an = or a & character; if preceded by = we require all matches
  and if preceded by ! we invert the result. */

  if (!(iplist = Ustrchr(domain, '=')))
    {
    bitmask = TRUE;
    iplist = Ustrchr(domain, '&');
    }

  if (iplist)				       /* Found either = or & */
    {
    if (iplist > domain && iplist[-1] == '!')  /* Handle preceding ! */
      {
      match_type |= MT_NOT;
      iplist[-1] = 0;
      }

    *iplist++ = 0;                             /* Terminate domain, move on */

    /* If we found = (bitmask == FALSE), check for == or =& */

    if (!bitmask && (*iplist == '=' || *iplist == '&'))
      {
      bitmask = *iplist++ == '&';
      match_type |= MT_ALL;
      }
    }


  /* If there is a comma in the domain, it indicates that a second domain for
  looking up TXT records is provided, before the main domain. Otherwise we must
  set domain_txt == domain. */

  domain_txt = domain;
  if ((comma = Ustrchr(domain, ',')))
    {
    *comma++ = 0;
    domain = comma;
    }

  /* Check that what we have left is a sensible domain name. There is no reason
  why these domains should in fact use the same syntax as hosts and email
  domains, but in practice they seem to. However, there is little point in
  actually causing an error here, because that would no doubt hold up incoming
  mail. Instead, I'll just log it. */

  for (uschar * s = domain; *s; s++)
    if (!isalnum(*s) && *s != '-' && *s != '.' && *s != '_')
      {
      log_write(0, LOG_MAIN, "dnslists domain \"%s\" contains "
        "strange characters - is this right?", domain);
      break;
      }

  /* Check the alternate domain if present */

  if (domain_txt != domain) for (uschar * s = domain_txt; *s; s++)
    if (!isalnum(*s) && *s != '-' && *s != '.' && *s != '_')
      {
      log_write(0, LOG_MAIN, "dnslists domain \"%s\" contains "
        "strange characters - is this right?", domain_txt);
      break;
      }

  /* If there is no key string, construct the query by adding the domain name
  onto the inverted host address, and perform a single DNS lookup. */

  if (!key)
    {
    if (where == ACL_WHERE_NOTSMTP_START || where == ACL_WHERE_NOTSMTP)
      {
      *log_msgptr = string_sprintf
	("cannot test auto-keyed dnslists condition in %s ACL",
	  acl_wherenames[where]);
      return ERROR;
      }
    if (!sender_host_address) return FAIL;    /* can never match */
    if (revadd[0] == 0) invert_address(revadd, sender_host_address);
    rc = one_check_dnsbl(domain, domain_txt, sender_host_address, revadd,
      iplist, bitmask, match_type, defer_return);
    if (rc == OK)
      {
      dnslist_domain = string_copy(domain_txt);
      dnslist_matched = string_copy(sender_host_address);
      HDEBUG(D_dnsbl) debug_printf("=> that means %s is listed at %s\n",
        sender_host_address, dnslist_domain);
      }
    if (rc != FAIL) return rc;     /* OK or DEFER */
    }

  /* If there is a key string, it can be a list of domains or IP addresses to
  be concatenated with the main domain. */

  else
    {
    int keysep = 0;
    BOOL defer = FALSE;
    uschar *keydomain;
    uschar keyrevadd[128];

    while ((keydomain = string_nextinlist(CUSS &key, &keysep, NULL, 0)))
      {
      uschar *prepend = keydomain;

      if (string_is_ip_address(keydomain, NULL) != 0)
        {
        invert_address(keyrevadd, keydomain);
        prepend = keyrevadd;
        }

      rc = one_check_dnsbl(domain, domain_txt, keydomain, prepend, iplist,
        bitmask, match_type, defer_return);
      if (rc == OK)
        {
        dnslist_domain = string_copy(domain_txt);
        dnslist_matched = string_copy(keydomain);
        HDEBUG(D_dnsbl) debug_printf("=> that means %s is listed at %s\n",
          keydomain, dnslist_domain);
        return OK;
        }

      /* If the lookup deferred, remember this fact. We keep trying the rest
      of the list to see if we get a useful result, and if we don't, we return
      DEFER at the end. */

      if (rc == DEFER) defer = TRUE;
      }    /* continue with next keystring domain/address */

    if (defer) return DEFER;
    }
  }        /* continue with next dnsdb outer domain */

return FAIL;
}

/* vi: aw ai sw=2
*/
/* End of dnsbl.c.c */
