/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Experimental SPF support.
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004 - 2014
   License: GPL
   Copyright (c) The Exim Maintainers 2016
*/

/* Code for calling spf checks via libspf-alt. Called from acl.c. */

#include "exim.h"
#ifdef EXPERIMENTAL_SPF

/* must be kept in numeric order */
static spf_result_id spf_result_id_list[] = {
  { US"invalid", 0},
  { US"neutral", 1 },
  { US"pass", 2 },
  { US"fail", 3 },
  { US"softfail", 4 },
  { US"none", 5 },
  { US"err_temp", 6 },  /* Deprecated Apr 2014 */
  { US"err_perm", 7 },  /* Deprecated Apr 2014 */
  { US"temperror", 6 }, /* RFC 4408 defined */
  { US"permerror", 7 }  /* RFC 4408 defined */
};

SPF_server_t    *spf_server = NULL;
SPF_request_t   *spf_request = NULL;
SPF_response_t  *spf_response = NULL;
SPF_response_t  *spf_response_2mx = NULL;

/* spf_init sets up a context that can be re-used for several
   messages on the same SMTP connection (that come from the
   same host with the same HELO string) */

int spf_init(uschar *spf_helo_domain, uschar *spf_remote_addr) {

  spf_server = SPF_server_new(SPF_DNS_CACHE, 0);

  if ( spf_server == NULL ) {
    debug_printf("spf: SPF_server_new() failed.\n");
    return 0;
  }

  if (SPF_server_set_rec_dom(spf_server, CS primary_hostname)) {
    debug_printf("spf: SPF_server_set_rec_dom(\"%s\") failed.\n", primary_hostname);
    spf_server = NULL;
    return 0;
  }

  spf_request = SPF_request_new(spf_server);

  if (SPF_request_set_ipv4_str(spf_request, CS spf_remote_addr)
      && SPF_request_set_ipv6_str(spf_request, CS spf_remote_addr)) {
    debug_printf("spf: SPF_request_set_ipv4_str() and SPF_request_set_ipv6_str() failed [%s]\n", spf_remote_addr);
    spf_server = NULL;
    spf_request = NULL;
    return 0;
  }

  if (SPF_request_set_helo_dom(spf_request, CS spf_helo_domain)) {
    debug_printf("spf: SPF_set_helo_dom(\"%s\") failed.\n", spf_helo_domain);
    spf_server = NULL;
    spf_request = NULL;
    return 0;
  }

  return 1;
}


/* spf_process adds the envelope sender address to the existing
   context (if any), retrieves the result, sets up expansion
   strings and evaluates the condition outcome. */

int spf_process(const uschar **listptr, uschar *spf_envelope_sender, int action) {
  int sep = 0;
  const uschar *list = *listptr;
  uschar *spf_result_id;
  uschar spf_result_id_buffer[128];
  int rc = SPF_RESULT_PERMERROR;

  if (!(spf_server && spf_request)) {
    /* no global context, assume temp error and skip to evaluation */
    rc = SPF_RESULT_PERMERROR;
    goto SPF_EVALUATE;
  };

  if (SPF_request_set_env_from(spf_request, CS spf_envelope_sender)) {
    /* Invalid sender address. This should be a real rare occurence */
    rc = SPF_RESULT_PERMERROR;
    goto SPF_EVALUATE;
  }

  /* get SPF result */
  if (action == SPF_PROCESS_FALLBACK)
    SPF_request_query_fallback(spf_request, &spf_response, CS spf_guess);
  else
    SPF_request_query_mailfrom(spf_request, &spf_response);

  /* set up expansion items */
  spf_header_comment     = (uschar *)SPF_response_get_header_comment(spf_response);
  spf_received           = (uschar *)SPF_response_get_received_spf(spf_response);
  spf_result             = (uschar *)SPF_strresult(SPF_response_result(spf_response));
  spf_smtp_comment       = (uschar *)SPF_response_get_smtp_comment(spf_response);

  rc = SPF_response_result(spf_response);

  /* We got a result. Now see if we should return OK or FAIL for it */
  SPF_EVALUATE:
  debug_printf("SPF result is %s (%d)\n", SPF_strresult(rc), rc);

  if (action == SPF_PROCESS_GUESS && (!strcmp (SPF_strresult(rc), "none")))
    return spf_process(listptr, spf_envelope_sender, SPF_PROCESS_FALLBACK);

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
