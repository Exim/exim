/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Experimental DMARC support.
   Copyright (c) Todd Lyons <tlyons@exim.org> 2012
   License: GPL */

#ifdef EXPERIMENTAL_DMARC

#include "pdkim/pdkim.h"
#ifdef EXPERIMENTAL_SPF
#include "spf2/spf.h"
#endif /* EXPERIMENTAL_SPF */

/* prototypes */
int dmarc_init();
int dmarc_process(header_line *);

#endif
