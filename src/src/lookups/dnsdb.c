/* $Cambridge: exim/src/src/lookups/dnsdb.c,v 1.3 2004/11/19 15:18:57 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2004 */
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
  "mx",
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
  T_MX,
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

(b) If the next sequence of characters is a sequence of letters and digits 
followed by '=', it is interpreted as the name of the DNS record type. The 
default is "A".

(c) Then there follows list of domain names. This is a generalized Exim list, 
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
int type = T_TXT;
uschar *outsep = US"\n";
uschar *equals, *domain;
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
    string_is_ip_address(keystring, NULL) > 0) 
  sep = -1;

/* Now scan the list and do a lookup for each item */

while ((domain = string_nextinlist(&keystring, &sep, buffer, sizeof(buffer))) 
        != NULL)
  {       
  uschar rbuffer[256];

  /* If the type is PTR, we have to construct the relevant magic lookup
  key. This code is now in a separate function. */
  
  if (type == T_PTR)
    {
    dns_build_reverse(domain, rbuffer);
    domain = rbuffer;
    }
  
  DEBUG(D_lookup) debug_printf("dnsdb key: %s\n", domain);
  
  /* Do the lookup and sort out the result. We use the special 
  lookup function that knows about pseudo types like "zns". If the lookup 
  fails, continue with the next domain. */
  
  rc = dns_special_lookup(&dnsa, domain, type, NULL);
  
  if (rc == DNS_NOMATCH || rc == DNS_NODATA) continue;
  if (rc != DNS_SUCCEED) return DEFER;
  
  /* If the lookup was a pseudo-type, change it to the correct type for
  searching the returned records; then search for them. */
  
  if (type == T_ZNS) type = T_NS;
  for (rr = dns_next_rr(&dnsa, &dnss, RESET_ANSWERS);
       rr != NULL;
       rr = dns_next_rr(&dnsa, &dnss, RESET_NEXT))
    {
    if (rr->type != type) continue;
  
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
      yield = string_cat(yield, &size, &ptr, (uschar *)(rr->data+1),
        (rr->data)[0]);
      }
    else   /* T_CNAME, T_MX, T_NS, T_SRV, T_PTR */
      {
      uschar s[264];
      uschar *p = (uschar *)(rr->data);
      if (type == T_MX)
        {
        int num;
        GETSHORT(num, p);            /* pointer is advanced */
        sprintf(CS s, "%d ", num);
        yield = string_cat(yield, &size, &ptr, s, Ustrlen(s));
        }
      else if (type == T_SRV)
        {
        int num, weight, port;
        GETSHORT(num, p);            /* pointer is advanced */
        GETSHORT(weight, p);
        GETSHORT(port, p);
        sprintf(CS s, "%d %d %d ", num, weight, port);
        yield = string_cat(yield, &size, &ptr, s, Ustrlen(s));
        }
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

if (ptr == 0) return FAIL;
yield[ptr] = 0;
*result = yield;
return OK;
}

/* End of lookups/dnsdb.c */
