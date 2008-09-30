/* $Cambridge: exim/src/src/dkim-exim.c,v 1.4 2008/09/30 10:03:55 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

/* Code for DKIM support. Other DKIM relevant code is in
   receive.c, transport.c and transports/smtp.c */

#include "exim.h"

#ifdef EXPERIMENTAL_DKIM

/* Globals related to the DKIM reference library. */
DKIMContext          *dkim_context           = NULL;
DKIMSignOptions      *dkim_sign_options      = NULL;
DKIMVerifyOptions    *dkim_verify_options    = NULL;
int                   dkim_verify_result     = DKIM_NEUTRAL;
int                   dkim_internal_status   = DKIM_SUCCESS;

/* Global char buffer for getc/ungetc functions. We need
   to accumulate some chars to be able to match EOD and
   doubled SMTP dots. Those must not be fed to the validation
   engine. */
int dkimbuff[6] = {256,256,256,256,256,256};

/* receive_getc() wrapper that feeds DKIM while Exim reads
   the message. */
int dkim_receive_getc(void) {
  int i;

#ifdef EXPERIMENTAL_DOMAINKEYS
  int c = dk_receive_getc();
#else
  int c = receive_getc();
#endif

  if ((dkim_context != NULL) &&
      (dkim_internal_status == DKIM_SUCCESS)) {
    /* Send oldest byte */
    if (dkimbuff[0] < 256) {
      DKIMVerifyProcess(dkim_context,(char *)&dkimbuff[0],1);
      /* debug_printf("%c",(int)dkimbuff[0]); */
    }
    /* rotate buffer */
    for (i=0;i<5;i++) dkimbuff[i]=dkimbuff[i+1];
    dkimbuff[5]=c;
    /* look for our candidate patterns */
    if ( (dkimbuff[1] == '\r') &&
         (dkimbuff[2] == '\n') &&
         (dkimbuff[3] == '.') &&
         (dkimbuff[4] == '\r') &&
         (dkimbuff[5] == '\n') ) {
      /* End of DATA */
      dkimbuff[1] = 256;
      dkimbuff[2] = 256;
      dkimbuff[3] = 256;
      dkimbuff[4] = 256;
      dkimbuff[5] = 256;
    }
    if ( (dkimbuff[2] == '\r') &&
         (dkimbuff[3] == '\n') &&
         (dkimbuff[4] == '.') &&
         (dkimbuff[5] == '.') ) {
      /* doubled dot, skip this char */
      dkimbuff[5] = 256;
    }
  }

  return c;
}

/* When exim puts a char back in the fd, we
   must rotate our buffer back. */
int dkim_receive_ungetc(int c) {

  if ((dkim_context != NULL) &&
      (dkim_internal_status == DKIM_SUCCESS)) {
    int i;
    /* rotate buffer back */
    for (i=5;i>0;i--) dkimbuff[i]=dkimbuff[i-1];
    dkimbuff[0]=256;
  }

#ifdef EXPERIMENTAL_DOMAINKEYS
  return dk_receive_ungetc(c);
#else
  return receive_ungetc(c);
#endif
}


void dkim_exim_verify_init(void) {
  int old_pool = store_pool;

  /* Bail out unless we got perfect conditions */
  if (!(smtp_input &&
        !smtp_batched_input &&
        dkim_do_verify)) {
    return;
  }

  store_pool = POOL_PERM;

  dkim_context = NULL;
  dkim_verify_options = NULL;

  dkim_context = store_get(sizeof(DKIMContext));
  dkim_verify_options = store_get(sizeof(DKIMVerifyOptions));

  if (!dkim_context ||
      !dkim_verify_options) {
    debug_printf("DKIM: Can't allocate memory for verifying.\n");
    dkim_context = NULL;
  }

  memset(dkim_context,0,sizeof(DKIMContext));
  memset(dkim_verify_options,0,sizeof(DKIMVerifyOptions));

  dkim_verify_options->nHonorBodyLengthTag = 1; /* Honor the l= tag */
  dkim_verify_options->nCheckPolicy = 1;        /* Fetch sender's policy */
  dkim_verify_options->nSubjectRequired = 1;    /* Do not require Subject header inclusion */

  dkim_verify_options->pfnSelectorCallback = NULL;
  dkim_verify_options->pfnPolicyCallback = NULL;

  dkim_status_wrap( DKIMVerifyInit(dkim_context, dkim_verify_options),
                    "error calling DKIMVerifyInit()" );

  if (dkim_internal_status != DKIM_SUCCESS) {
    /* Invalidate context */
    dkim_context = NULL;
  }

  store_pool = old_pool;
}


void dkim_exim_verify_finish(void) {
  int i;
  int old_pool = store_pool;

  if (!dkim_do_verify ||
      (!(smtp_input && !smtp_batched_input)) ||
      (dkim_context == NULL) ||
      (dkim_internal_status != DKIM_SUCCESS)) return;

  store_pool = POOL_PERM;

  /* Flush eventual remaining input chars */
  for (i=0;i<6;i++)
    if (dkimbuff[i] < 256)
      DKIMVerifyProcess(dkim_context,(char *)&dkimbuff[i],1);

  /* Fetch global result. Can be one of:
      DKIM_SUCCESS
      DKIM_PARTIAL_SUCCESS
      DKIM_NEUTRAL
      DKIM_FAIL
  */
  dkim_verify_result = DKIMVerifyResults(dkim_context);

  store_pool = old_pool;
}


/* Lookup result for a given domain (or identity) */
int dkim_exim_verify_result(uschar *domain, uschar **result, uschar **error) {
  int sig_count = 0;
  int i,rc;
  char policy[512];
  DKIMVerifyDetails *dkim_verify_details = NULL;

  if (!dkim_do_verify ||
      (!(smtp_input && !smtp_batched_input)) ||
      (dkim_context == NULL) ||
      (dkim_internal_status != DKIM_SUCCESS)) {
    rc = DKIM_EXIM_UNVERIFIED;
    goto YIELD;
  }

  DKIMVerifyGetDetails(dkim_context,
                       &sig_count,
                       &dkim_verify_details,
                       policy);


  rc = DKIM_EXIM_UNSIGNED;

  debug_printf("DKIM: We have %d signature(s)\n",sig_count);
  for (i=0;i<sig_count;i++) {
    debug_printf( "DKIM: [%d] ", i + 1 );
    if (!dkim_verify_details[i].Domain) {
      debug_printf("parse error (no domain)\n");
      continue;
    }

    if (dkim_verify_details[i].nResult >= 0) {
      debug_printf( "GOOD d=%s i=%s\n",
                    dkim_verify_details[i].Domain,
                    dkim_verify_details[i].IdentityDomain );
    }
    else {
      debug_printf( "FAIL d=%s i=%s c=%d\n",
                    dkim_verify_details[i].Domain,
                    dkim_verify_details[i].IdentityDomain,
                    dkim_verify_details[i].nResult
                    );

    }

    if ( (strcmpic(domain,dkim_verify_details[i].Domain) == 0) ||
         (strcmpic(domain,dkim_verify_details[i].IdentityDomain) == 0) ) {
      if (dkim_verify_details[i].nResult >= 0) {
        rc = DKIM_EXIM_GOOD;
        /* TODO: Add From: domain check */
      }
      else {
        /* Return DEFER for temp. error types */
        if (dkim_verify_details[i].nResult == DKIM_SELECTOR_DNS_TEMP_FAILURE) {
          rc = DKIM_EXIM_DEFER;
        }
        else {
          rc = DKIM_EXIM_FAIL;
        }
      }
    }
  }

  YIELD:
  switch (rc) {
    case DKIM_EXIM_FAIL:
      *result = "bad";
    break;
    case DKIM_EXIM_DEFER:
      *result = "defer";
    break;
    case DKIM_EXIM_UNVERIFIED:
      *result = "unverified";
    break;
    case DKIM_EXIM_UNSIGNED:
      *result = "unsigned";
    break;
    case DKIM_EXIM_GOOD:
      *result = "good";
    break;
  }

  return rc;
}



uschar *dkim_exim_sign_headers = NULL;
int dkim_exim_header_callback(const char* header) {
  int sep = 0;
  uschar *hdr_ptr = dkim_exim_sign_headers;
  uschar *hdr_itr = NULL;
  uschar  hdr_buf[512];
  uschar *hdr_name = string_copy(US header);
  char *colon_pos = strchr(hdr_name,':');

  if (colon_pos == NULL) return 0;
  *colon_pos = '\0';

  debug_printf("DKIM: header '%s' ",hdr_name);
  while ((hdr_itr = string_nextinlist(&hdr_ptr, &sep,
                                      hdr_buf,
                                      sizeof(hdr_buf))) != NULL) {
    if (strcmpic((uschar *)hdr_name,hdr_itr) == 0) {
      debug_printf("included in signature.\n");
      return 1;
    }
  }
  debug_printf("NOT included in signature.\n");
  return 0;
}

uschar *dkim_exim_sign(int dkim_fd,
                       uschar *dkim_private_key,
                       uschar *dkim_domain,
                       uschar *dkim_selector,
                       uschar *dkim_canon,
                       uschar *dkim_sign_headers) {

  uschar *rc = NULL;
  char buf[4096];
  int seen_lf = 0;
  int seen_lfdot = 0;
  int save_errno = 0;
  int sread;
  char *signature;
  int old_pool = store_pool;
  store_pool = POOL_PERM;

  dkim_context = NULL;
  dkim_sign_options = NULL;

  dkim_context = store_get(sizeof(DKIMContext));
  dkim_sign_options = store_get(sizeof(DKIMSignOptions));

  memset(dkim_sign_options,0,sizeof(DKIMSignOptions));
  memset(dkim_context,0,sizeof(DKIMContext));

  dkim_sign_options->nIncludeBodyLengthTag = 0;
  dkim_sign_options->nIncludeCopiedHeaders = 0;
  dkim_sign_options->nHash = DKIM_HASH_SHA256;
  dkim_sign_options->nIncludeTimeStamp = 0;
  dkim_sign_options->nIncludeQueryMethod = 0;
  dkim_sign_options->pfnHeaderCallback = dkim_exim_header_callback;
  dkim_sign_options->nIncludeBodyHash = DKIM_BODYHASH_IETF_1;


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
  Ustrncpy((uschar *)dkim_sign_options->szDomain,dkim_domain,255);


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
  Ustrncpy((uschar *)dkim_sign_options->szSelector,dkim_selector,79);

  /* Expand provided options */
  dkim_canon = expand_string(dkim_canon?dkim_canon:US"relaxed");
  if (dkim_canon == NULL) {
    /* expansion error, do not send message. */
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand "
          "dkim_canon: %s", expand_string_message);
    rc = NULL;
    goto CLEANUP;
  }
  if (Ustrcmp(dkim_canon, "relaxed") == 0)
    dkim_sign_options->nCanon = DKIM_SIGN_RELAXED;
  else if (Ustrcmp(dkim_canon, "simple") == 0)
    dkim_sign_options->nCanon = DKIM_SIGN_SIMPLE;
  else {
    log_write(0, LOG_MAIN, "DKIM: unknown canonicalization method '%s', defaulting to 'relaxed'.\n",dkim_canon);
    dkim_sign_options->nCanon = DKIM_SIGN_RELAXED;
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

  if (dkim_sign_headers == NULL) {
    /* Use RFC defaults */
    dkim_sign_headers = US"from:sender:reply-to:subject:date:"
                          "message-id:to:cc:mime-version:content-type:"
                          "content-transfer-encoding:content-id:"
                          "content-description:resent-date:resent-from:"
                          "resent-sender:resent-to:resent-cc:resent-message-id:"
                          "in-reply-to:references:"
                          "list-id:list-help:list-unsubscribe:"
                          "list-subscribe:list-post:list-owner:list-archive";
  }
  dkim_exim_sign_headers = dkim_sign_headers;

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

  /* Initialize signing context. */
  dkim_status_wrap( DKIMSignInit(dkim_context, dkim_sign_options),
                    "error calling DKIMSignInit()" );

  if (dkim_internal_status != DKIM_SUCCESS) {
    /* Invalidate context */
    dkim_context = NULL;
    goto CLEANUP;
  }

  while((sread = read(dkim_fd,&buf,4096)) > 0) {
    int pos = 0;
    char c;

    while (pos < sread) {
      c = buf[pos++];

      if ((c == '.') && seen_lfdot) {
        /* escaped dot, write "\n.", continue */
        dkim_internal_status = DKIMSignProcess(dkim_context,"\n.",2);
        seen_lf = 0;
        seen_lfdot = 0;
        continue;
      }

      if (seen_lfdot) {
        /* EOM, write "\n" and break */
        dkim_internal_status = DKIMSignProcess(dkim_context,"\n",1);
        break;
      }

      if ((c == '.') && seen_lf) {
        seen_lfdot = 1;
        continue;
      }

      if (seen_lf) {
        /* normal lf, just send it */
        dkim_internal_status = DKIMSignProcess(dkim_context,"\n",1);
        seen_lf = 0;
      }

      if (c == '\n') {
        seen_lf = 1;
        continue;
      }

      /* write the char */
      dkim_internal_status = DKIMSignProcess(dkim_context,&c,1);
    }
  }

  /* Handle failed read above. */
  if (sread == -1) {
    debug_printf("DKIM: Error reading -K file.\n");
    save_errno = errno;
    rc = NULL;
    goto CLEANUP;
  }

  if (!dkim_status_wrap(dkim_internal_status,
                        "error while processing message data")) {
    rc = NULL;
    goto CLEANUP;
  }

  if (!dkim_status_wrap( DKIMSignGetSig2( dkim_context, dkim_private_key, &signature ),
                         "error while signing message" ) ) {
    rc = NULL;
    goto CLEANUP;
  }

  log_write(0, LOG_MAIN, "Message signed with DKIM: %s\n",signature);

  rc = store_get(strlen(signature)+3);
  Ustrcpy(rc,US signature);
  Ustrcat(rc,US"\r\n");

  CLEANUP:
  if (dkim_context != NULL) {
    dkim_context = NULL;
  }
  store_pool = old_pool;
  errno = save_errno;
  return rc;
}

unsigned int dkim_status_wrap(int stat, uschar *text) {
  char *p = DKIMGetErrorString(stat);

  if (stat != DKIM_SUCCESS) {
    debug_printf("DKIM: %s",text?text:US"");
    if (p) debug_printf(" (%s)",p);
    debug_printf("\n");
  }
  dkim_internal_status = stat;
  return (dkim_internal_status==DKIM_SUCCESS)?1:0;
}

#endif
