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

typedef struct dmarc_result_id {
  uschar *name;
  int    value;
} dmarc_result_id;

/* prototypes */
//int dmarc_init(uschar *,uschar *);
//int dmarc_process(uschar **, uschar *, int);
int dmarc_init();
int dmarc_process(header_line *);

// Just for reference, likely just get rid of them
#define DMARC_PROCESS_NORMAL  0
#define DMARC_PROCESS_GUESS   1
#define DMARC_PROCESS_FALLBACK    2

#endif
