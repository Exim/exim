/* $Cambridge: exim/src/src/dkim.c,v 1.1.2.6 2009/04/09 13:57:21 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* Code for DKIM support. Other DKIM relevant code is in
   receive.c, transport.c and transports/smtp.c */

#include "exim.h"

#ifndef DISABLE_DKIM

#include "pdkim/pdkim.h"

pdkim_ctx       *dkim_verify_ctx = NULL;
pdkim_signature *dkim_signatures = NULL;

int dkim_exim_query_dns_txt(char *name, char *answer) {
  dns_answer dnsa;
  dns_scan   dnss;
  dns_record *rr;

  if (dns_lookup(&dnsa, (uschar *)name, T_TXT, NULL) != DNS_SUCCEED) return 1;

  /* Search for TXT record */
  for (rr = dns_next_rr(&dnsa, &dnss, RESET_ANSWERS);
       rr != NULL;
       rr = dns_next_rr(&dnsa, &dnss, RESET_NEXT))
    if (rr->type == T_TXT) break;

  /* Copy record content to the answer buffer */
  if (rr != NULL) {
    int len = (rr->data)[0];
    //if (len > 511) len = 127; // ???
    snprintf(answer, PDKIM_DNS_TXT_MAX_RECLEN, "%.*s", len, (char *)(rr->data+1));
  }
  else return 1;

  return PDKIM_OK;
}


int dkim_exim_verify_init(void) {

  /* Free previous context if there is one */
  if (dkim_verify_ctx) pdkim_free_ctx(dkim_verify_ctx);

  /* Create new context */
  dkim_verify_ctx = pdkim_init_verify(PDKIM_INPUT_SMTP,
                                      &dkim_exim_query_dns_txt
                                     );

  if (dkim_verify_ctx != NULL) {
    dkim_collect_input = 1;
    pdkim_set_debug_stream(dkim_verify_ctx,debug_file);
    return 1;
  }
  else {
    dkim_collect_input = 0;
    return 0;
  }
}


int dkim_exim_verify_feed(uschar *data, int len) {
  if (pdkim_feed(dkim_verify_ctx,
                 (char *)data,
                 len) != PDKIM_OK) return 0;
  return 1;
}


int dkim_exim_verify_finish(void) {
  dkim_signatures = NULL;
  dkim_collect_input = 0;
  if (pdkim_feed_finish(dkim_verify_ctx,&dkim_signatures) != PDKIM_OK) return 0;

  while (dkim_signatures != NULL) {
    debug_printf("DKIM: Signature from domain '%s': ",dkim_signatures->domain);
    switch(dkim_signatures->verify_status) {
      case PDKIM_VERIFY_NONE:
        debug_printf("not verified\n");
        log_write(0, LOG_MAIN, "DKIM: Signature from domain '%s', selector '%s': "
                  "not verified", dkim_signatures->domain, dkim_signatures->selector);
      break;
      case PDKIM_VERIFY_INVALID:
        debug_printf("invalid\n");
        log_write(0, LOG_MAIN, "DKIM: Signature from domain '%s', selector '%s': "
                  "invalid", dkim_signatures->domain, dkim_signatures->selector);
      break;
      case PDKIM_VERIFY_FAIL:
        debug_printf("verification failed\n");
        log_write(0, LOG_MAIN, "DKIM: Signature from domain '%s', selector '%s': "
                  "verification failed", dkim_signatures->domain, dkim_signatures->selector);
      break;
      case PDKIM_VERIFY_PASS:
        debug_printf("verification succeeded\n");
        log_write(0, LOG_MAIN, "DKIM: Signature from domain '%s', selector '%s': "
                  "verification succeeded", dkim_signatures->domain, dkim_signatures->selector);
      break;
    }
    /* Try next signature */
    dkim_signatures = dkim_signatures->next;
  }

  return dkim_signatures?1:0;
}


int dkim_exim_verify_result(uschar *domain, uschar **result, uschar **error) {

  if (dkim_verify_ctx) {

  }

  return OK;
}


uschar *dkim_exim_sign(int dkim_fd,
                       uschar *dkim_private_key,
                       uschar *dkim_domain,
                       uschar *dkim_selector,
                       uschar *dkim_canon,
                       uschar *dkim_sign_headers) {
  pdkim_ctx *ctx = NULL;
  uschar *rc = NULL;
  pdkim_signature *signature;
  int pdkim_canon;
  int sread;
  char buf[4096];
  int save_errno = 0;
  int old_pool = store_pool;

  dkim_domain = expand_string(dkim_domain);
  if (dkim_domain == NULL) {
    /* expansion error, do not send message. */
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand "
          "dkim_domain: %s", expand_string_message);
    rc = NULL;
    goto CLEANUP;
  }
  /* Set up $dkim_domain expansion variable. */
  dkim_signing_domain = dkim_domain;

  /* Get selector to use. */
  dkim_selector = expand_string(dkim_selector);
  if (dkim_selector == NULL) {
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand "
      "dkim_selector: %s", expand_string_message);
    rc = NULL;
    goto CLEANUP;
  }
  /* Set up $dkim_selector expansion variable. */
  dkim_signing_selector = dkim_selector;

  /* Get canonicalization to use */
  dkim_canon = expand_string(dkim_canon?dkim_canon:US"relaxed");
  if (dkim_canon == NULL) {
    /* expansion error, do not send message. */
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand "
          "dkim_canon: %s", expand_string_message);
    rc = NULL;
    goto CLEANUP;
  }
  if (Ustrcmp(dkim_canon, "relaxed") == 0)
    pdkim_canon = PDKIM_CANON_RELAXED;
  else if (Ustrcmp(dkim_canon, "simple") == 0)
    pdkim_canon = PDKIM_CANON_RELAXED;
  else {
    log_write(0, LOG_MAIN, "DKIM: unknown canonicalization method '%s', defaulting to 'relaxed'.\n",dkim_canon);
    pdkim_canon = PDKIM_CANON_RELAXED;
  }

  /* Expand signing headers once */
  if (dkim_sign_headers != NULL) {
    dkim_sign_headers = expand_string(dkim_sign_headers);
    if (dkim_sign_headers == NULL) {
      log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand "
        "dkim_sign_headers: %s", expand_string_message);
      rc = NULL;
      goto CLEANUP;
    }
  }

  /* Get private key to use. */
  dkim_private_key = expand_string(dkim_private_key);
  if (dkim_private_key == NULL) {
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand "
      "dkim_private_key: %s", expand_string_message);
    rc = NULL;
    goto CLEANUP;
  }
  if ( (Ustrlen(dkim_private_key) == 0) ||
       (Ustrcmp(dkim_private_key,"0") == 0) ||
       (Ustrcmp(dkim_private_key,"false") == 0) ) {
    /* don't sign, but no error */
    rc = US"";
    goto CLEANUP;
  }

  if (dkim_private_key[0] == '/') {
    int privkey_fd = 0;
    /* Looks like a filename, load the private key. */
    memset(big_buffer,0,big_buffer_size);
    privkey_fd = open(CS dkim_private_key,O_RDONLY);
    (void)read(privkey_fd,big_buffer,16383);
    (void)close(privkey_fd);
    dkim_private_key = big_buffer;
  }

  ctx = pdkim_init_sign(PDKIM_INPUT_SMTP,
                        (char *)dkim_signing_domain,
                        (char *)dkim_signing_selector,
                        (char *)dkim_private_key
                       );

  pdkim_set_debug_stream(ctx,debug_file);

  pdkim_set_optional(ctx,
                     (char *)dkim_sign_headers,
                     NULL,
                     pdkim_canon,
                     pdkim_canon,
                     -1,
                     PDKIM_ALGO_RSA_SHA256,
                     0,
                     0);

  while((sread = read(dkim_fd,&buf,4096)) > 0) {
    if (pdkim_feed(ctx,buf,sread) != PDKIM_OK) {
      rc = NULL;
      goto CLEANUP;
    }
  }
  /* Handle failed read above. */
  if (sread == -1) {
    debug_printf("DKIM: Error reading -K file.\n");
    save_errno = errno;
    rc = NULL;
    goto CLEANUP;
  }

  if (pdkim_feed_finish(ctx,&signature) != PDKIM_OK)
    goto CLEANUP;

  rc = store_get(strlen(signature->signature_header)+3);
  Ustrcpy(rc,US signature->signature_header);
  Ustrcat(rc,US"\r\n");

  CLEANUP:
  if (ctx != NULL) {
    pdkim_free_ctx(ctx);
  }
  store_pool = old_pool;
  errno = save_errno;
  return rc;
};

#endif
