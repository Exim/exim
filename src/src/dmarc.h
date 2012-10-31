/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Experimental DMARC support.
   Copyright (c) Todd Lyons <tlyons@exim.org> 2012
   License: GPL */

#ifdef EXPERIMENTAL_DMARC

#ifdef EXPERIMENTAL_SPF
#include "spf2/spf.h"
#endif /* EXPERIMENTAL_SPF */

/* prototypes */
int dmarc_init();
int dmarc_store_data(header_line *);
int dmarc_process();
uschar *dmarc_exim_expand_query(int);
uschar *dmarc_exim_expand_defaults(int);
uschar *dmarc_auth_results_header(header_line *,uschar *);

#define DMARC_AR_HEADER        US"Authentication-Results:"
#define DMARC_VERIFY_STATUS    1

#endif
