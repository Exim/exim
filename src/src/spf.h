/* $Cambridge: exim/src/src/spf.h,v 1.3 2005/02/17 11:58:26 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Experimental SPF support.
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004
   License: GPL */

#ifdef EXPERIMENTAL_SPF

#include <spf2/spf.h>
#include <spf2/spf_dns_resolv.h>
#include <spf2/spf_dns_cache.h>

typedef struct spf_result_id {
  uschar *name;
  int    value;
} spf_result_id;

/* must be kept in numeric order */
static spf_result_id spf_result_id_list[] = {
  { US"pass", 0 },
  { US"fail", 1 },
  { US"softfail", 2 },
  { US"neutral", 3 },
  { US"err_perm", 4 },
  { US"err_temp", 5 },
  { US"none", 6 }
};

static int spf_result_id_list_size = sizeof(spf_result_id_list)/sizeof(spf_result_id);

/* prototypes */
int spf_init(uschar *,uschar *);
int spf_process(uschar **, uschar *);

#endif
