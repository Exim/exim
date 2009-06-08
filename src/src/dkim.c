/* $Cambridge: exim/src/src/dkim.c,v 1.1.2.15 2009/06/08 21:06:31 tom Exp $ */

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
pdkim_signature *dkim_cur_sig    = NULL;

int dkim_exim_query_dns_txt(char *name, char *answer) {
  dns_answer dnsa;
  dns_scan   dnss;
  dns_record *rr;

  if (dns_lookup(&dnsa, (uschar *)name, T_TXT, NULL) != DNS_SUCCEED) return PDKIM_FAIL;

  /* Search for TXT record */
  for (rr = dns_next_rr(&dnsa, &dnss, RESET_ANSWERS);
       rr != NULL;
       rr = dns_next_rr(&dnsa, &dnss, RESET_NEXT))
    if (rr->type == T_TXT) break;

  /* Copy record content to the answer buffer */
  if (rr != NULL) {
    int rr_offset = 0;
    int answer_offset = 0;
    while (rr_offset < rr->size) {
      uschar len = (rr->data)[rr_offset++];
      snprintf(answer+(answer_offset),
               PDKIM_DNS_TXT_MAX_RECLEN-(answer_offset),
               "%.*s", (int)len, (char *)((rr->data)+rr_offset));
      rr_offset+=len;
      answer_offset+=len;
    }
  }
  else return PDKIM_FAIL;

  return PDKIM_OK;
}


void dkim_exim_verify_init(void) {

  /* Free previous context if there is one */
  if (dkim_verify_ctx) pdkim_free_ctx(dkim_verify_ctx);

  /* Create new context */
  dkim_verify_ctx = pdkim_init_verify(PDKIM_INPUT_SMTP,
                                      &dkim_exim_query_dns_txt
                                     );

  if (dkim_verify_ctx != NULL) {
    dkim_collect_input = TRUE;
    pdkim_set_debug_stream(dkim_verify_ctx,debug_file);
  }
  else dkim_collect_input = FALSE;

}


void dkim_exim_verify_feed(uschar *data, int len) {
  if (dkim_collect_input &&
      pdkim_feed(dkim_verify_ctx,
                 (char *)data,
                 len) != PDKIM_OK) dkim_collect_input = FALSE;
}


void dkim_exim_verify_finish(void) {
  pdkim_signature *sig = NULL;
  int dkim_signing_domains_size = 0;
  int dkim_signing_domains_ptr = 0;
  dkim_signing_domains = NULL;

  /* Delete eventual previous signature chain */
  dkim_signatures = NULL;

  /* If we have arrived here with dkim_collect_input == FALSE, it
     means there was a processing error somewhere along the way.
     Log the incident and disable futher verification. */
  if (!dkim_collect_input) {
    log_write(0, LOG_MAIN|LOG_PANIC, "DKIM: Error while running this message through validation, disabling signature verification.");
    dkim_disable_verify = TRUE;
    return;
  }
  dkim_collect_input = FALSE;

  /* Finish DKIM operation and fetch link to signatures chain */
  if (pdkim_feed_finish(dkim_verify_ctx,&dkim_signatures) != PDKIM_OK) return;

  sig = dkim_signatures;
  while (sig != NULL) {
    int size = 0;
    int ptr = 0;
    /* Log a line for each signature */
    uschar *logmsg = string_append(NULL, &size, &ptr, 5,

      string_sprintf( "DKIM: d=%s s=%s c=%s/%s a=%s ",
                      sig->domain,
                      sig->selector,
                      (sig->canon_headers == PDKIM_CANON_SIMPLE)?"simple":"relaxed",
                      (sig->canon_body    == PDKIM_CANON_SIMPLE)?"simple":"relaxed",
                      (sig->algo          == PDKIM_ALGO_RSA_SHA256)?"rsa-sha256":"rsa-sha1"
                    ),
      ((sig->identity != NULL)?
        string_sprintf("i=%s ", sig->identity)
        :
        US""
      ),
      ((sig->created > 0)?
        string_sprintf("t=%lu ", sig->created)
        :
        US""
      ),
      ((sig->expires > 0)?
        string_sprintf("x=%lu ", sig->expires)
        :
        US""
      ),
      ((sig->bodylength > -1)?
        string_sprintf("l=%lu ", sig->bodylength)
        :
        US""
      )
    );

    switch(sig->verify_status) {
      case PDKIM_VERIFY_NONE:
        logmsg = string_append(logmsg, &size, &ptr, 1, "[not verified]");
      break;
      case PDKIM_VERIFY_INVALID:
        logmsg = string_append(logmsg, &size, &ptr, 1, "[invalid - ");
        switch (sig->verify_ext_status) {
          case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE:
            logmsg = string_append(logmsg, &size, &ptr, 1, "public key record (currently?) unavailable]");
          break;
          case PDKIM_VERIFY_INVALID_BUFFER_SIZE:
            logmsg = string_append(logmsg, &size, &ptr, 1, "overlong public key record]");
          break;
          case PDKIM_VERIFY_INVALID_PUBKEY_PARSING:
            logmsg = string_append(logmsg, &size, &ptr, 1, "syntax error in public key record]");
          break;
          default:
            logmsg = string_append(logmsg, &size, &ptr, 1, "unspecified problem]");
        }
      break;
      case PDKIM_VERIFY_FAIL:
        logmsg = string_append(logmsg, &size, &ptr, 1, "[verification failed - ");
        switch (sig->verify_ext_status) {
          case PDKIM_VERIFY_FAIL_BODY:
            logmsg = string_append(logmsg, &size, &ptr, 1, "body hash mismatch (body probably modified in transit)]");
          break;
          case PDKIM_VERIFY_FAIL_MESSAGE:
            logmsg = string_append(logmsg, &size, &ptr, 1, "signature did not verify (headers probably modified in transit)]");
          break;
          default:
            logmsg = string_append(logmsg, &size, &ptr, 1, "unspecified reason]");
        }
      break;
      case PDKIM_VERIFY_PASS:
        logmsg = string_append(logmsg, &size, &ptr, 1, "[verification succeeded]");
      break;
    }

    logmsg[ptr] = '\0';
    log_write(0, LOG_MAIN, (char *)logmsg);

    /* Build a colon-separated list of signing domains in dkim_signing_domains */
    dkim_signing_domains = string_append(dkim_signing_domains,
                                         &dkim_signing_domains_size,
                                         &dkim_signing_domains_ptr,
                                         2,
                                         sig->domain,
                                         ":"
                                        );

    /* Process next signature */
    sig = sig->next;
  }

  /* Chop the last colon from the domain list */
  if ((dkim_signing_domains != NULL) &&
      (Ustrlen(dkim_signing_domains) > 0))
    dkim_signing_domains[Ustrlen(dkim_signing_domains)-1] = '\0';
}


void dkim_exim_acl_setup(uschar *id) {
  pdkim_signature *sig = dkim_signatures;
  dkim_cur_sig = NULL;
  if (dkim_disable_verify ||
      !id || !sig ||
      !dkim_verify_ctx) return;
  /* Find signature to run ACL on */
  while (sig != NULL) {
    uschar *cmp_val = NULL;
    if (Ustrchr(id,'@') != NULL) cmp_val = (uschar *)sig->identity;
                            else cmp_val = (uschar *)sig->domain;
    if (cmp_val && (strcmpic(cmp_val,id) == 0)) {
      dkim_cur_sig = sig;
      /* The "dkim_domain" and "dkim_selector" expansion variables have
         related globals, since they are used in the signing code too.
         Instead of inventing separate names for verification, we set
         them here. This is easy since a domain and selector is guaranteed
         to be in a signature. The other dkim_* expansion items are
         dynamically fetched from dkim_cur_sig at expansion time (see
         function below). */
      dkim_signing_domain   = (uschar *)sig->domain;
      dkim_signing_selector = (uschar *)sig->selector;
      return;
    }
    sig = sig->next;
  }
}


uschar *dkim_exim_expand_query(int what) {

  if (!dkim_verify_ctx ||
      dkim_disable_verify ||
      !dkim_cur_sig) return dkim_exim_expand_defaults(what);

  switch(what) {
    case DKIM_ALGO:
      return dkim_cur_sig->algo?
              (uschar *)(dkim_cur_sig->algo)
              :dkim_exim_expand_defaults(what);
    case DKIM_BODYLENGTH:
      return (dkim_cur_sig->bodylength >= 0)?
              (uschar *)string_sprintf(OFF_T_FMT,(LONGLONG_T)dkim_cur_sig->bodylength)
              :dkim_exim_expand_defaults(what);
    case DKIM_CANON_BODY:
      return dkim_cur_sig->canon_body?
              (uschar *)(dkim_cur_sig->canon_body)
              :dkim_exim_expand_defaults(what);
    case DKIM_CANON_HEADERS:
      return dkim_cur_sig->canon_headers?
              (uschar *)(dkim_cur_sig->canon_headers)
              :dkim_exim_expand_defaults(what);
    case DKIM_COPIEDHEADERS:
      return dkim_cur_sig->copiedheaders?
              (uschar *)(dkim_cur_sig->copiedheaders)
              :dkim_exim_expand_defaults(what);
    case DKIM_CREATED:
      return (dkim_cur_sig->created > 0)?
              (uschar *)string_sprintf("%llu",dkim_cur_sig->created)
              :dkim_exim_expand_defaults(what);
    case DKIM_EXPIRES:
      return (dkim_cur_sig->expires > 0)?
              (uschar *)string_sprintf("%llu",dkim_cur_sig->expires)
              :dkim_exim_expand_defaults(what);
    case DKIM_HEADERNAMES:
      return dkim_cur_sig->headernames?
              (uschar *)(dkim_cur_sig->headernames)
              :dkim_exim_expand_defaults(what);
    case DKIM_IDENTITY:
      return dkim_cur_sig->identity?
              (uschar *)(dkim_cur_sig->identity)
              :dkim_exim_expand_defaults(what);
    case DKIM_KEY_GRANULARITY:
      return dkim_cur_sig->pubkey?
              (dkim_cur_sig->pubkey->granularity?
                (uschar *)(dkim_cur_sig->pubkey->granularity)
                :dkim_exim_expand_defaults(what)
              )
              :dkim_exim_expand_defaults(what);
    case DKIM_KEY_SRVTYPE:
      return dkim_cur_sig->pubkey?
              (dkim_cur_sig->pubkey->srvtype?
                (uschar *)(dkim_cur_sig->pubkey->srvtype)
                :dkim_exim_expand_defaults(what)
              )
              :dkim_exim_expand_defaults(what);
    case DKIM_KEY_NOTES:
      return dkim_cur_sig->pubkey?
              (dkim_cur_sig->pubkey->notes?
                (uschar *)(dkim_cur_sig->pubkey->notes)
                :dkim_exim_expand_defaults(what)
              )
              :dkim_exim_expand_defaults(what);
    case DKIM_KEY_TESTING:
      return dkim_cur_sig->pubkey?
              (dkim_cur_sig->pubkey->testing?
                US"1"
                :dkim_exim_expand_defaults(what)
              )
              :dkim_exim_expand_defaults(what);
    case DKIM_NOSUBDOMAINS:
      return dkim_cur_sig->pubkey?
              (dkim_cur_sig->pubkey->no_subdomaining?
                US"1"
                :dkim_exim_expand_defaults(what)
              )
              :dkim_exim_expand_defaults(what);
    case DKIM_VERIFY_STATUS:
      switch(dkim_cur_sig->verify_status) {
        case PDKIM_VERIFY_INVALID:
          return US"invalid";
        case PDKIM_VERIFY_FAIL:
          return US"fail";
        case PDKIM_VERIFY_PASS:
          return US"pass";
        case PDKIM_VERIFY_NONE:
        default:
          return US"none";
      }
    case DKIM_VERIFY_REASON:
      switch (dkim_cur_sig->verify_ext_status) {
        case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE:
          return US"pubkey_unavailable";
        case PDKIM_VERIFY_INVALID_PUBKEY_PARSING:
          return US"pubkey_syntax";
        case PDKIM_VERIFY_FAIL_BODY:
          return US"bodyhash_mismatch";
        case PDKIM_VERIFY_FAIL_MESSAGE:
          return US"signature_incorrect";
      }
    default:
      return US"";
  }
}


uschar *dkim_exim_expand_defaults(int what) {
  switch(what) {
    case DKIM_ALGO:               return US"";
    case DKIM_BODYLENGTH:         return US"9999999999999";
    case DKIM_CANON_BODY:         return US"";
    case DKIM_CANON_HEADERS:      return US"";
    case DKIM_COPIEDHEADERS:      return US"";
    case DKIM_CREATED:            return US"0";
    case DKIM_EXPIRES:            return US"9999999999999";
    case DKIM_HEADERNAMES:        return US"";
    case DKIM_IDENTITY:           return US"";
    case DKIM_KEY_GRANULARITY:    return US"*";
    case DKIM_KEY_SRVTYPE:        return US"*";
    case DKIM_KEY_NOTES:          return US"";
    case DKIM_KEY_TESTING:        return US"0";
    case DKIM_NOSUBDOMAINS:       return US"0";
    case DKIM_VERIFY_STATUS:      return US"none";
    case DKIM_VERIFY_REASON:      return US"";
    default:                      return US"";
  }
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
