/* $Cambridge: exim/src/src/spf.h,v 1.5 2005/06/24 08:36:48 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Experimental SPF support.
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004
   License: GPL */

#ifdef EXPERIMENTAL_SPF

/* Yes, we do have ns_type. spf.h redefines it if we don't set this. Doh */
#define HAVE_NS_TYPE
#include <spf2/spf.h>


#include <spf2/spf_dns_resolv.h>
#include <spf2/spf_dns_cache.h>


typedef struct spf_result_id {
  uschar *name;
  int    value;
} spf_result_id;

/* must be kept in numeric order */
static spf_result_id spf_result_id_list[] = {
  { US"invalid", 0},
  { US"neutral", 1 },
  { US"pass", 2 },
  { US"fail", 3 },
  { US"softfail", 4 },
  { US"none", 5 },
  { US"err_temp", 6 },
  { US"err_perm", 7 }
};

static int spf_result_id_list_size = sizeof(spf_result_id_list)/sizeof(spf_result_id);

/* prototypes */
int spf_init(uschar *,uschar *);
int spf_process(uschar **, uschar *);

#endif
