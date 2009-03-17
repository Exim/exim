/* $Cambridge: exim/src/src/dkim.c,v 1.1.2.4 2009/03/17 21:31:10 tom Exp $ */

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


void dkim_exim_verify_init(void) {
}

void dkim_exim_verify_finish(void) {
}

int dkim_exim_verify_result(uschar *domain, uschar **result, uschar **error) {
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
  char *signature;
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
                     0,
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

  rc = store_get(strlen(signature)+3);
  Ustrcpy(rc,US signature);
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
