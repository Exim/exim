/* $Cambridge: exim/src/src/spf.c,v 1.1.2.1 2004/12/10 09:24:38 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/
 
/* Experimental SPF support.
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004
   License: GPL */
   
/* Code for calling spf checks via libspf-alt. Called from acl.c. */

#include "exim.h"
#ifdef EXPERIMENTAL_SPF

#include "spf.h"

SPF_config_t        spfcid = NULL;
SPF_dns_config_t    spfdcid_resolv = NULL;
SPF_dns_config_t    spfdcid = NULL;


/* spf_init sets up a context that can be re-used for several
   messages on the same SMTP connection (that come from the
   same host with the same HELO string) */
   
int spf_init(uschar *spf_helo_domain, uschar *spf_remote_addr) {
  uschar *p;
  
  /* paranoia */
  spfcid = NULL;
  spfdcid_resolv = NULL;
  spfdcid = NULL;
  
  spfcid = SPF_create_config();
  if ( spfcid == NULL ) {
    debug_printf("spf: SPF_create_config() failed.\n");
	  return 0;
  }

  /* set up resolver */
  spfdcid_resolv = SPF_dns_create_config_resolv(NULL, 0);
  spfdcid = SPF_dns_create_config_cache(spfdcid_resolv, 8, 0);

  if (spfdcid == NULL) {
    debug_printf("spf: SPF_dns_create_config_cache() failed.\n");
    spfcid = NULL;
    spfdcid_resolv = NULL;
	  return 0;
  }

  if (SPF_set_ip_str(spfcid, spf_remote_addr)) {
    debug_printf("spf: SPF_set_ip_str() failed.\n");
    spfcid = NULL;
    spfdcid_resolv = NULL;
	  return 0;
  }

  if (SPF_set_helo_dom(spfcid, spf_helo_domain)) {
    debug_printf("spf: SPF_set_helo_dom() failed.\n");
    spfcid = NULL;
    spfdcid_resolv = NULL;
	  return 0;
  }
  
  return 1;
}


/* spf_process adds the envelope sender address to the existing
   context (if any), retrieves the result, sets up expansion
   strings and evaluates the condition outcome. */

int spf_process(uschar **listptr, uschar *spf_envelope_sender) {
  int sep = 0;
  uschar *list = *listptr;
  uschar *spf_result_id;
  uschar spf_result_id_buffer[128];
  SPF_output_t spf_output;
  int rc = SPF_RESULT_ERROR;
 
  if (!(spfcid && spfdcid)) {
    /* no global context, assume temp error and skip to evaluation */
    rc = SPF_RESULT_ERROR;
    goto SPF_EVALUATE;
  };

  if (SPF_set_env_from(spfcid, spf_envelope_sender)) {
    /* Invalid sender address. This should be a real rare occurence */
    rc = SPF_RESULT_ERROR;
    goto SPF_EVALUATE;
  } 

  /* get SPF result */
  spf_output = SPF_result(spfcid, spfdcid);

  /* set up expansion items */
  spf_header_comment     = spf_output.header_comment ? (uschar *)spf_output.header_comment : NULL;
  spf_received           = spf_output.received_spf ? (uschar *)spf_output.received_spf : NULL;
  spf_result             = (uschar *)SPF_strresult(spf_output.result);
  spf_smtp_comment       = spf_output.smtp_comment ? (uschar *)spf_output.smtp_comment : NULL;

  rc = spf_output.result;

  /* We got a result. Now see if we should return OK or FAIL for it */
  SPF_EVALUATE:
  debug_printf("SPF result is %s (%d)\n", SPF_strresult(rc), rc);
  while ((spf_result_id = string_nextinlist(&list, &sep,
                                     spf_result_id_buffer,
                                     sizeof(spf_result_id_buffer))) != NULL) {
    int negate = 0;
    int result = 0;

    /* Check for negation */
    if (spf_result_id[0] == '!') {
      negate = 1;
      spf_result_id++;
    };

    /* Check the result identifier */
    result = Ustrcmp(spf_result_id, spf_result_id_list[rc].name);
    if (!negate && result==0) return OK;
    if (negate && result!=0) return OK;
  };

  /* no match */
  return FAIL;
}

#endif

