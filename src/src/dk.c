/* $Cambridge: exim/src/src/dk.c,v 1.2 2005/03/08 16:57:28 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2005 */
/* See the file NOTICE for conditions of use and distribution. */

/* Code for DomainKeys support. Other DK relevant code is in
   receive.c, transport.c and transports/smtp.c */

#include "exim.h"

#ifdef EXPERIMENTAL_DOMAINKEYS

/* Globals related to the DK reference library. */
DK                   *dk_context             = NULL;
DK_LIB               *dk_lib                 = NULL;
DK_FLAGS              dk_flags;
DK_STAT               dk_internal_status;

/* Globals related to Exim DK implementation. */
dk_exim_verify_block *dk_verify_block        = NULL;

/* Global char buffer for getc/ungetc functions. We need
   to accumulate some chars to be able to match EOD and
   doubled SMTP dots. Those must not be fed to the validation
   engine. */
int dkbuff[6] = {256,256,256,256,256,256};

/* receive_getc() wrapper that feeds DK while Exim reads
   the message. */
int dk_receive_getc(void) {
  int i;
  int c = receive_getc();

  if (dk_context != NULL) {
    /* Send oldest byte */
    if ((dkbuff[0] < 256) && (dk_internal_status == DK_STAT_OK)) {
      dk_internal_status = dk_message(dk_context, (char *)&dkbuff[0], 1);
      if (dk_internal_status != DK_STAT_OK)
        DEBUG(D_receive) debug_printf("DK: %s\n", DK_STAT_to_string(dk_internal_status));
    }
    /* rotate buffer */
    for (i=0;i<5;i++) dkbuff[i]=dkbuff[i+1];
    dkbuff[5]=c;
    /* look for our candidate patterns */
    if ( (dkbuff[1] == '\r') &&
         (dkbuff[2] == '\n') &&
         (dkbuff[3] == '.') &&
         (dkbuff[4] == '\r') &&
         (dkbuff[5] == '\n') ) {
      /* End of DATA */
      dkbuff[3] = 256;
      dkbuff[4] = 256;
      dkbuff[5] = 256;
    }
    if ( (dkbuff[2] == '\r') &&
         (dkbuff[3] == '\n') &&
         (dkbuff[4] == '.') &&
         (dkbuff[5] == '.') ) {
      /* doubled dot, skip this char */
      dkbuff[5] = 256;
    }
  }
return c;
}

/* When exim puts a char back in the fd, we
   must rotate our buffer back. */
int dk_receive_ungetc(int c) {
  int i;
  if (dk_context != NULL) {
    /* rotate buffer back */
    for (i=5;i>0;i--) dkbuff[i]=dkbuff[i-1];
    dkbuff[0]=256;
  }
  return receive_ungetc(c);
}


void dk_exim_verify_init(void) {
  int old_pool = store_pool;
  store_pool = POOL_PERM;

  /* Reset DK state in any case. */
  dk_context = NULL;
  dk_lib = NULL;
  dk_verify_block = NULL;

  /* Set up DK context if DK was requested and input is SMTP. */
  if (smtp_input && !smtp_batched_input && dk_do_verify) {
    /* initialize library */
    dk_lib = dk_init(&dk_internal_status);
    if (dk_internal_status != DK_STAT_OK)
      debug_printf("DK: %s\n", DK_STAT_to_string(dk_internal_status));
    else {
      /* initialize verification context */
      dk_context = dk_verify(dk_lib, &dk_internal_status);
      if (dk_internal_status != DK_STAT_OK) {
        debug_printf("DK: %s\n", DK_STAT_to_string(dk_internal_status));
        dk_context = NULL;
      }
      else {
        /* Reserve some space for the verify block. */
        dk_verify_block = store_get(sizeof(dk_exim_verify_block));
        if (dk_verify_block == NULL) {
          debug_printf("DK: Can't allocate %d bytes.\n",sizeof(dk_exim_verify_block));
          dk_context = NULL;
        }
        else {
          memset(dk_verify_block, 0, sizeof(dk_exim_verify_block));
        }
      }
    }
  }
  store_pool = old_pool;
}


void dk_exim_verify_finish(void) {
  char *p,*q;
  int i;
  int old_pool = store_pool;

  /* Bail out if context could not be set up earlier. */
  if (dk_context == NULL)
    return;

  store_pool = POOL_PERM;

  /* Send remaining bytes from input which are still in the buffer. */
  for (i=0;i<6;i++)
    if (dkbuff[i] < 256)
      dk_internal_status = dk_message(dk_context, (char *)&dkbuff[i], 1);

  /* Flag end-of-message. */
  dk_internal_status = dk_end(dk_context, NULL);

  /* Grab address/domain information. */
  p = dk_address(dk_context);
  if (p != NULL) {
    switch(p[0]) {
      case 'N':
        dk_verify_block->address_source = DK_EXIM_ADDRESS_NONE;
      break;
      case 'S':
        dk_verify_block->address_source = DK_EXIM_ADDRESS_FROM_SENDER;
      break;
      case 'F':
        dk_verify_block->address_source = DK_EXIM_ADDRESS_FROM_FROM;
      break;
    }
    p++;
    if (*p != '\0') {
      dk_verify_block->address = string_copy((uschar *)p);
      q = strrchr(p,'@');
      if ((q != NULL) && (*(q+1) != '\0')) {
        dk_verify_block->domain = string_copy((uschar *)(q+1));
        *q = '\0';
        dk_verify_block->local_part = string_copy((uschar *)p);
      }
    }
  }

  dk_flags = dk_policy(dk_context);

  /* Grab domain policy */
  if (dk_flags & DK_FLAG_SET) {
    if (dk_flags & DK_FLAG_TESTING)
      dk_verify_block->testing = TRUE;
    if (dk_flags & DK_FLAG_SIGNSALL)
      dk_verify_block->signsall = TRUE;
  }

  /* Set up main result. */
  switch(dk_internal_status)
    {
    case DK_STAT_NOSIG:
      dk_verify_block->is_signed = FALSE;
      dk_verify_block->result = DK_EXIM_RESULT_NO_SIGNATURE;
    break;
    case DK_STAT_OK:
      dk_verify_block->is_signed = TRUE;
      dk_verify_block->result = DK_EXIM_RESULT_GOOD;
    break;
    case DK_STAT_BADSIG:
      dk_verify_block->is_signed = TRUE;
      dk_verify_block->result = DK_EXIM_RESULT_BAD;
    break;
    case DK_STAT_REVOKED:
      dk_verify_block->is_signed = TRUE;
      dk_verify_block->result = DK_EXIM_RESULT_REVOKED;
    break;
    case DK_STAT_BADKEY:
    case DK_STAT_SYNTAX:
      dk_verify_block->is_signed = TRUE;
      /* Syntax -> Bad format? */
      dk_verify_block->result = DK_EXIM_RESULT_BAD_FORMAT;
    break;
    case DK_STAT_NOKEY:
      dk_verify_block->is_signed = TRUE;
      dk_verify_block->result = DK_EXIM_RESULT_NO_KEY;
    break;
    case DK_STAT_NORESOURCE:
    case DK_STAT_INTERNAL:
    case DK_STAT_ARGS:
    case DK_STAT_CANTVRFY:
      dk_verify_block->result = DK_EXIM_RESULT_ERR;
    break;
    /* This is missing DK_EXIM_RESULT_NON_PARTICIPANT. The lib does not
       report such a status. */
    }

  /* Set up human readable result string. */
  dk_verify_block->result_string = string_copy((uschar *)DK_STAT_to_string(dk_internal_status));

  /* All done, reset dk_context. */
  dk_free(dk_context);
  dk_context = NULL;

  store_pool = old_pool;
}

uschar *dk_exim_sign(int dk_fd,
                     uschar *dk_private_key,
                     uschar *dk_domain,
                     uschar *dk_selector,
                     uschar *dk_canon) {
  uschar *rc = NULL;
  int dk_canon_int = DK_CANON_SIMPLE;
  char c;
  int seen_lf = 0;
  int seen_lfdot = 0;
  uschar sig[1024];
  int save_errno = 0;
  int sread;
  int old_pool = store_pool;
  store_pool = POOL_PERM;

  dk_lib = dk_init(&dk_internal_status);
  if (dk_internal_status != DK_STAT_OK) {
    debug_printf("DK: %s\n", DK_STAT_to_string(dk_internal_status));
    rc = NULL;
    goto CLEANUP;
  }

  /* Figure out what canonicalization to use. Unfortunately
     we must do this BEFORE knowing which domain we sign for. */
  if ((dk_canon != NULL) && (Ustrcmp(dk_canon, "nofws") == 0)) dk_canon_int = DK_CANON_NOFWS;
  else dk_canon = "simple";

  /* Initialize signing context. */
  dk_context = dk_sign(dk_lib, &dk_internal_status, dk_canon_int);
  if (dk_internal_status != DK_STAT_OK) {
    debug_printf("DK: %s\n", DK_STAT_to_string(dk_internal_status));
    dk_context = NULL;
    goto CLEANUP;
  }

  while((sread = read(dk_fd,&c,1)) > 0) {

    if ((c == '.') && seen_lfdot) {
      /* escaped dot, write "\n.", continue */
      dk_message(dk_context, "\n.", 2);
      seen_lf = 0;
      seen_lfdot = 0;
      continue;
    }

    if (seen_lfdot) {
      /* EOM, write "\n" and break */
      dk_message(dk_context, "\n", 1);
      break;
    }

    if ((c == '.') && seen_lf) {
      seen_lfdot = 1;
      continue;
    }

    if (seen_lf) {
      /* normal lf, just send it */
      dk_message(dk_context, "\n", 1);
      seen_lf = 0;
    }

    if (c == '\n') {
      seen_lf = 1;
      continue;
    }

    /* write the char */
    dk_message(dk_context, &c, 1);
  }

  /* Handle failed read above. */
  if (sread == -1) {
    debug_printf("DK: Error reading -K file.\n");
    save_errno = errno;
    rc = NULL;
    goto CLEANUP;
  }

  /* Flag end-of-message. */
  dk_internal_status = dk_end(dk_context, NULL);
  /* TODO: check status */


  /* Get domain to use, unless overridden. */
  if (dk_domain == NULL) {
    dk_domain = dk_address(dk_context);
    switch(dk_domain[0]) {
      case 'N': dk_domain = NULL; break;
      case 'F':
      case 'S':
        dk_domain++;
        dk_domain = strrchr(dk_domain,'@');
        if (dk_domain != NULL) {
          uschar *p;
          dk_domain++;
          p = dk_domain;
          while (*p != 0) { *p = tolower(*p); p++; }
        }
      break;
    }
    if (dk_domain == NULL) {
      debug_printf("DK: Could not determine domain to use for signing from message headers.\n");
      /* In this case, we return "OK" by sending up an empty string as the
         DomainKey-Signature header. If there is no domain to sign for, we
         can send the message anyway since the recipient has no policy to
         apply ... */
      rc = "";
      goto CLEANUP;
    }
  }
  else {
    dk_domain = expand_string(dk_domain);
    if (dk_domain == NULL) {
      /* expansion error, do not send message. */
      debug_printf("DK: Error while expanding dk_domain option.\n");
      rc = NULL;
      goto CLEANUP;
    }
  }

  /* Set up $dk_domain expansion variable. */
  dk_signing_domain = dk_domain;

  /* Get selector to use. */
  dk_selector = expand_string(dk_selector);
  if (dk_selector == NULL) {
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand "
      "dk_selector: %s", expand_string_message);
    rc = NULL;
    goto CLEANUP;
  }

  /* Set up $dk_selector expansion variable. */
  dk_signing_selector = dk_selector;

  /* Get private key to use. */
  dk_private_key = expand_string(dk_private_key);
  if (dk_private_key == NULL) {
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand "
      "dk_private_key: %s", expand_string_message);
    rc = NULL;
    goto CLEANUP;
  }

  if ( (Ustrlen(dk_private_key) == 0) ||
       (Ustrcmp(dk_private_key,"0") == 0) ||
       (Ustrcmp(dk_private_key,"false") == 0) ) {
    /* don't sign, but no error */
    rc = "";
    goto CLEANUP;
  }

  if (dk_private_key[0] == '/') {
    int privkey_fd = 0;
    /* Looks like a filename, load the private key. */
    memset(big_buffer,0,big_buffer_size);
    privkey_fd = open(dk_private_key,O_RDONLY);
    read(privkey_fd,big_buffer,16383);
    close(privkey_fd);
    dk_private_key = big_buffer;
  }

  /* Get the signature. */
  dk_internal_status = dk_getsig(dk_context, dk_private_key, sig, 8192);

  /* Check for unuseable key */
  if (dk_internal_status != DK_STAT_OK) {
    debug_printf("DK: %s\n", DK_STAT_to_string(dk_internal_status));
    rc = NULL;
    goto CLEANUP;
  }

  rc = store_get(1024);
  /* Build DomainKey-Signature header to return. */
  snprintf(rc, 1024, "DomainKey-Signature: a=rsa-sha1; q=dns; c=%s;\r\n"
                     "\ts=%s; d=%s;\r\n"
                     "\tb=%s;\r\n", dk_canon, dk_selector, dk_domain, sig);

  log_write(0, LOG_MAIN, "DK: message signed using a=rsa-sha1; q=dns; c=%s; s=%s; d=%s;", dk_canon, dk_selector, dk_domain);

  CLEANUP:
  if (dk_context != NULL) {
    dk_free(dk_context);
    dk_context = NULL;
  }
  store_pool = old_pool;
  errno = save_errno;
  return rc;
}

#endif
