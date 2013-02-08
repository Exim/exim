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
int dmarc_write_history_file();

#define DMARC_AR_HEADER        US"Authentication-Results:"
#define DMARC_VERIFY_STATUS    1

#define DMARC_HIST_OK          1
#define DMARC_HIST_DISABLED    2
#define DMARC_HIST_EMPTY       3
#define DMARC_HIST_FILE_ERR    4
#define DMARC_HIST_WRITE_ERR   5

/* From opendmarc.c */
#define DMARC_RESULT_REJECT     0
#define DMARC_RESULT_DISCARD    1
#define DMARC_RESULT_ACCEPT     2
#define DMARC_RESULT_TEMPFAIL   3
#define DMARC_RESULT_QUARANTINE 4


#endif

// vim:sw=2 expandtab
