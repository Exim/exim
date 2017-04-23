/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge, 1995 - 2017 */
/* See the file NOTICE for conditions of use and distribution. */

/* Code for DKIM support. Other DKIM relevant code is in
   receive.c, transport.c and transports/smtp.c */

#include "exim.h"

#ifndef DISABLE_DKIM

#include "pdkim/pdkim.h"

int dkim_verify_oldpool;
pdkim_ctx *dkim_verify_ctx = NULL;
pdkim_signature *dkim_signatures = NULL;
pdkim_signature *dkim_cur_sig = NULL;
static const uschar * dkim_collect_error = NULL;

static int
dkim_exim_query_dns_txt(char *name, char *answer)
{
dns_answer dnsa;
dns_scan dnss;
dns_record *rr;

lookup_dnssec_authenticated = NULL;
if (dns_lookup(&dnsa, US name, T_TXT, NULL) != DNS_SUCCEED)
  return PDKIM_FAIL;	/*XXX better error detail?  logging? */

/* Search for TXT record */

for (rr = dns_next_rr(&dnsa, &dnss, RESET_ANSWERS);
     rr;
     rr = dns_next_rr(&dnsa, &dnss, RESET_NEXT))
  if (rr->type == T_TXT)
    {
    int rr_offset = 0;
    int answer_offset = 0;

    /* Copy record content to the answer buffer */

    while (rr_offset < rr->size)
      {
      uschar len = rr->data[rr_offset++];
      snprintf(answer + answer_offset,
		PDKIM_DNS_TXT_MAX_RECLEN - answer_offset,
		"%.*s", (int)len, (char *) (rr->data + rr_offset));
      rr_offset += len;
      answer_offset += len;
      if (answer_offset >= PDKIM_DNS_TXT_MAX_RECLEN)
	return PDKIM_FAIL;	/*XXX better error detail?  logging? */
      }
    return PDKIM_OK;
    }

return PDKIM_FAIL;	/*XXX better error detail?  logging? */
}


void
dkim_exim_init(void)
{
pdkim_init();
}



void
dkim_exim_verify_init(BOOL dot_stuffing)
{
/* There is a store-reset between header & body reception
so cannot use the main pool. Any allocs done by Exim
memory-handling must use the perm pool. */

dkim_verify_oldpool = store_pool;
store_pool = POOL_PERM;

/* Free previous context if there is one */

if (dkim_verify_ctx)
  pdkim_free_ctx(dkim_verify_ctx);

/* Create new context */

dkim_verify_ctx = pdkim_init_verify(&dkim_exim_query_dns_txt, dot_stuffing);
dkim_collect_input = !!dkim_verify_ctx;
dkim_collect_error = NULL;

/* Start feed up with any cached data */
receive_get_cache();

store_pool = dkim_verify_oldpool;
}


void
dkim_exim_verify_feed(uschar * data, int len)
{
int rc;

store_pool = POOL_PERM;
if (  dkim_collect_input
   && (rc = pdkim_feed(dkim_verify_ctx, CS data, len)) != PDKIM_OK)
  {
  dkim_collect_error = pdkim_errstr(rc);
  log_write(0, LOG_MAIN,
	     "DKIM: validation error: %.100s", dkim_collect_error);
  dkim_collect_input = FALSE;
  }
store_pool = dkim_verify_oldpool;
}


void
dkim_exim_verify_finish(void)
{
pdkim_signature * sig = NULL;
int dkim_signers_size = 0, dkim_signers_ptr = 0, rc;
const uschar * errstr;

store_pool = POOL_PERM;

/* Delete eventual previous signature chain */

dkim_signers = NULL;
dkim_signatures = NULL;

if (dkim_collect_error)
  {
  log_write(0, LOG_MAIN,
      "DKIM: Error during validation, disabling signature verification: %.100s",
      dkim_collect_error);
  dkim_disable_verify = TRUE;
  goto out;
  }

dkim_collect_input = FALSE;

/* Finish DKIM operation and fetch link to signatures chain */

rc = pdkim_feed_finish(dkim_verify_ctx, &dkim_signatures, &errstr);
if (rc != PDKIM_OK)
  {
  log_write(0, LOG_MAIN, "DKIM: validation error: %.100s%s%s", pdkim_errstr(rc),
	    errstr ? ": " : "", errstr ? errstr : US"");
  goto out;
  }

for (sig = dkim_signatures; sig; sig = sig->next)
  {
  int size = 0, ptr = 0;
  uschar * logmsg = NULL, * s;

  /* Log a line for each signature */

  if (!(s = sig->domain)) s = US"<UNSET>";
  logmsg = string_append(logmsg, &size, &ptr, 2, "d=", s);
  if (!(s = sig->selector)) s = US"<UNSET>";
  logmsg = string_append(logmsg, &size, &ptr, 2, " s=", s);
  logmsg = string_append(logmsg, &size, &ptr, 7, 
	" c=", sig->canon_headers == PDKIM_CANON_SIMPLE ? "simple" : "relaxed",
	"/",   sig->canon_body    == PDKIM_CANON_SIMPLE ? "simple" : "relaxed",
	" a=", sig->algo == PDKIM_ALGO_RSA_SHA256
		? "rsa-sha256"
		: sig->algo == PDKIM_ALGO_RSA_SHA1 ? "rsa-sha1" : "err",
	string_sprintf(" b=%d",
			(int)sig->sighash.len > -1 ? sig->sighash.len * 8 : 0));
  if ((s= sig->identity)) string_append(logmsg, &size, &ptr, 2, " i=", s);
  if (sig->created > 0) string_append(logmsg, &size, &ptr, 1,
				      string_sprintf(" t=%lu", sig->created));
  if (sig->expires > 0) string_append(logmsg, &size, &ptr, 1,
				      string_sprintf(" x=%lu", sig->expires));
  if (sig->bodylength > -1) string_append(logmsg, &size, &ptr, 1,
				      string_sprintf(" l=%lu", sig->bodylength));

  switch (sig->verify_status)
    {
    case PDKIM_VERIFY_NONE:
      logmsg = string_append(logmsg, &size, &ptr, 1, " [not verified]");
      break;

    case PDKIM_VERIFY_INVALID:
      logmsg = string_append(logmsg, &size, &ptr, 1, " [invalid - ");
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE:
	  logmsg = string_append(logmsg, &size, &ptr, 1,
		        "public key record (currently?) unavailable]");
	  break;

	case PDKIM_VERIFY_INVALID_BUFFER_SIZE:
	  logmsg = string_append(logmsg, &size, &ptr, 1,
			"overlong public key record]");
	  break;

	case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD:
	case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT:
	  logmsg = string_append(logmsg, &size, &ptr, 1,
		       "syntax error in public key record]");
	  break;

        case PDKIM_VERIFY_INVALID_SIGNATURE_ERROR:
          logmsg = string_append(logmsg, &size, &ptr, 1,
                       "signature tag missing or invalid]");
          break;

        case PDKIM_VERIFY_INVALID_DKIM_VERSION:
          logmsg = string_append(logmsg, &size, &ptr, 1,
                       "unsupported DKIM version]");
          break;

	default:
	  logmsg = string_append(logmsg, &size, &ptr, 1,
			"unspecified problem]");
	}
      break;

    case PDKIM_VERIFY_FAIL:
      logmsg =
	string_append(logmsg, &size, &ptr, 1, " [verification failed - ");
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_FAIL_BODY:
	  logmsg = string_append(logmsg, &size, &ptr, 1,
		       "body hash mismatch (body probably modified in transit)]");
	  break;

	case PDKIM_VERIFY_FAIL_MESSAGE:
	  logmsg = string_append(logmsg, &size, &ptr, 1,
		       "signature did not verify (headers probably modified in transit)]");
	break;

	default:
	  logmsg = string_append(logmsg, &size, &ptr, 1, "unspecified reason]");
	}
      break;

    case PDKIM_VERIFY_PASS:
      logmsg =
	string_append(logmsg, &size, &ptr, 1, " [verification succeeded]");
      break;
    }

  logmsg[ptr] = '\0';
  log_write(0, LOG_MAIN, "DKIM: %s", logmsg);

  /* Build a colon-separated list of signing domains (and identities, if present) in dkim_signers */

  if (sig->domain)
    dkim_signers = string_append_listele(dkim_signers, ':', sig->domain);

  if (sig->identity)
    dkim_signers = string_append_listele(dkim_signers, ':', sig->identity);

  /* Process next signature */
  }

out:
store_pool = dkim_verify_oldpool;
}


void
dkim_exim_acl_setup(uschar * id)
{
pdkim_signature * sig;
uschar * cmp_val;

dkim_cur_sig = NULL;
dkim_cur_signer = id;

if (dkim_disable_verify || !id || !dkim_verify_ctx)
  return;

/* Find signature to run ACL on */

for (sig = dkim_signatures; sig; sig = sig->next)
  if (  (cmp_val = Ustrchr(id, '@') != NULL ? US sig->identity : US sig->domain)
     && strcmpic(cmp_val, id) == 0
     )
    {
    dkim_cur_sig = sig;

    /* The "dkim_domain" and "dkim_selector" expansion variables have
       related globals, since they are used in the signing code too.
       Instead of inventing separate names for verification, we set
       them here. This is easy since a domain and selector is guaranteed
       to be in a signature. The other dkim_* expansion items are
       dynamically fetched from dkim_cur_sig at expansion time (see
       function below). */

    dkim_signing_domain = US sig->domain;
    dkim_signing_selector = US sig->selector;
    dkim_key_length = sig->sighash.len * 8;
    return;
    }
}


static uschar *
dkim_exim_expand_defaults(int what)
{
switch (what)
  {
  case DKIM_ALGO:		return US"";
  case DKIM_BODYLENGTH:		return US"9999999999999";
  case DKIM_CANON_BODY:		return US"";
  case DKIM_CANON_HEADERS:	return US"";
  case DKIM_COPIEDHEADERS:	return US"";
  case DKIM_CREATED:		return US"0";
  case DKIM_EXPIRES:		return US"9999999999999";
  case DKIM_HEADERNAMES:	return US"";
  case DKIM_IDENTITY:		return US"";
  case DKIM_KEY_GRANULARITY:	return US"*";
  case DKIM_KEY_SRVTYPE:	return US"*";
  case DKIM_KEY_NOTES:		return US"";
  case DKIM_KEY_TESTING:	return US"0";
  case DKIM_NOSUBDOMAINS:	return US"0";
  case DKIM_VERIFY_STATUS:	return US"none";
  case DKIM_VERIFY_REASON:	return US"";
  default:			return US"";
  }
}


uschar *
dkim_exim_expand_query(int what)
{
if (!dkim_verify_ctx || dkim_disable_verify || !dkim_cur_sig)
  return dkim_exim_expand_defaults(what);

switch (what)
  {
  case DKIM_ALGO:
    switch (dkim_cur_sig->algo)
      {
      case PDKIM_ALGO_RSA_SHA1:	return US"rsa-sha1";
      case PDKIM_ALGO_RSA_SHA256:
      default:			return US"rsa-sha256";
      }

  case DKIM_BODYLENGTH:
    return dkim_cur_sig->bodylength >= 0
      ? string_sprintf(OFF_T_FMT, (LONGLONG_T) dkim_cur_sig->bodylength)
      : dkim_exim_expand_defaults(what);

  case DKIM_CANON_BODY:
    switch (dkim_cur_sig->canon_body)
      {
      case PDKIM_CANON_RELAXED:	return US"relaxed";
      case PDKIM_CANON_SIMPLE:
      default:			return US"simple";
      }

  case DKIM_CANON_HEADERS:
  switch (dkim_cur_sig->canon_headers)
    {
    case PDKIM_CANON_RELAXED:	return US"relaxed";
    case PDKIM_CANON_SIMPLE:
    default:			return US"simple";
    }

  case DKIM_COPIEDHEADERS:
    return dkim_cur_sig->copiedheaders
      ? US dkim_cur_sig->copiedheaders : dkim_exim_expand_defaults(what);

  case DKIM_CREATED:
    return dkim_cur_sig->created > 0
      ? string_sprintf("%llu", dkim_cur_sig->created)
      : dkim_exim_expand_defaults(what);

  case DKIM_EXPIRES:
    return dkim_cur_sig->expires > 0
      ? string_sprintf("%llu", dkim_cur_sig->expires)
      : dkim_exim_expand_defaults(what);

  case DKIM_HEADERNAMES:
    return dkim_cur_sig->headernames
      ? dkim_cur_sig->headernames : dkim_exim_expand_defaults(what);

  case DKIM_IDENTITY:
    return dkim_cur_sig->identity
      ? US dkim_cur_sig->identity : dkim_exim_expand_defaults(what);

  case DKIM_KEY_GRANULARITY:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->granularity
      ? US dkim_cur_sig->pubkey->granularity
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_KEY_SRVTYPE:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->srvtype
      ? US dkim_cur_sig->pubkey->srvtype
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_KEY_NOTES:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->notes
      ? US dkim_cur_sig->pubkey->notes
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_KEY_TESTING:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->testing
      ? US"1"
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_NOSUBDOMAINS:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->no_subdomaining
      ? US"1"
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_VERIFY_STATUS:
    switch (dkim_cur_sig->verify_status)
      {
      case PDKIM_VERIFY_INVALID:	return US"invalid";
      case PDKIM_VERIFY_FAIL:		return US"fail";
      case PDKIM_VERIFY_PASS:		return US"pass";
      case PDKIM_VERIFY_NONE:
      default:				return US"none";
      }

  case DKIM_VERIFY_REASON:
    switch (dkim_cur_sig->verify_ext_status)
      {
      case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE:
						return US"pubkey_unavailable";
      case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD:return US"pubkey_dns_syntax";
      case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT:	return US"pubkey_der_syntax";
      case PDKIM_VERIFY_FAIL_BODY:		return US"bodyhash_mismatch";
      case PDKIM_VERIFY_FAIL_MESSAGE:		return US"signature_incorrect";
      }

  default:
    return US"";
  }
}


/* Generate signatures for the given file, returning a string.
If a prefix is given, prepend it to the file for the calculations.
*/

uschar *
dkim_exim_sign(int fd, off_t off, uschar * prefix,
  struct ob_dkim * dkim, const uschar ** errstr)
{
const uschar * dkim_domain;
int sep = 0;
uschar *seen_items = NULL;
int seen_items_size = 0;
int seen_items_offset = 0;
uschar *dkim_canon_expanded;
uschar *dkim_sign_headers_expanded;
uschar *dkim_private_key_expanded;
pdkim_ctx *ctx = NULL;
uschar *rc = NULL;
uschar *sigbuf = NULL;
int sigsize = 0;
int sigptr = 0;
pdkim_signature *signature;
int pdkim_canon;
int pdkim_rc;
int sread;
char buf[4096];
int save_errno = 0;
int old_pool = store_pool;

store_pool = POOL_MAIN;

if (!(dkim_domain = expand_cstring(dkim->dkim_domain)))
  {
  /* expansion error, do not send message. */
  log_write(0, LOG_MAIN | LOG_PANIC, "failed to expand "
	     "dkim_domain: %s", expand_string_message);
  goto bad;
  }

/* Set $dkim_domain expansion variable to each unique domain in list. */

while ((dkim_signing_domain = string_nextinlist(&dkim_domain, &sep, NULL, 0)))
  {
  if (dkim_signing_domain[0] == '\0')
    continue;

  /* Only sign once for each domain, no matter how often it
  appears in the expanded list. */

  if (seen_items)
    {
    const uschar *seen_items_list = seen_items;
    if (match_isinlist(dkim_signing_domain,
			&seen_items_list, 0, NULL, NULL, MCL_STRING, TRUE,
			NULL) == OK)
      continue;

    seen_items =
      string_append(seen_items, &seen_items_size, &seen_items_offset, 1, ":");
    }

  seen_items =
    string_append(seen_items, &seen_items_size, &seen_items_offset, 1,
		 dkim_signing_domain);
  seen_items[seen_items_offset] = '\0';

  /* Set up $dkim_selector expansion variable. */

  if (!(dkim_signing_selector = expand_string(dkim->dkim_selector)))
    {
    log_write(0, LOG_MAIN | LOG_PANIC, "failed to expand "
	       "dkim_selector: %s", expand_string_message);
    goto bad;
    }

  /* Get canonicalization to use */

  dkim_canon_expanded = dkim->dkim_canon
    ? expand_string(dkim->dkim_canon) : US"relaxed";
  if (!dkim_canon_expanded)
    {
    /* expansion error, do not send message. */
    log_write(0, LOG_MAIN | LOG_PANIC, "failed to expand "
	       "dkim_canon: %s", expand_string_message);
    goto bad;
    }

  if (Ustrcmp(dkim_canon_expanded, "relaxed") == 0)
    pdkim_canon = PDKIM_CANON_RELAXED;
  else if (Ustrcmp(dkim_canon_expanded, "simple") == 0)
    pdkim_canon = PDKIM_CANON_SIMPLE;
  else
    {
    log_write(0, LOG_MAIN,
	       "DKIM: unknown canonicalization method '%s', defaulting to 'relaxed'.\n",
	       dkim_canon_expanded);
    pdkim_canon = PDKIM_CANON_RELAXED;
    }

  dkim_sign_headers_expanded = NULL;
  if (dkim->dkim_sign_headers)
    if (!(dkim_sign_headers_expanded = expand_string(dkim->dkim_sign_headers)))
      {
      log_write(0, LOG_MAIN | LOG_PANIC, "failed to expand "
		 "dkim_sign_headers: %s", expand_string_message);
      goto bad;
      }
    			/* else pass NULL, which means default header list */

  /* Get private key to use. */

  if (!(dkim_private_key_expanded = expand_string(dkim->dkim_private_key)))
    {
    log_write(0, LOG_MAIN | LOG_PANIC, "failed to expand "
	       "dkim_private_key: %s", expand_string_message);
    goto bad;
    }

  if (  Ustrlen(dkim_private_key_expanded) == 0
     || Ustrcmp(dkim_private_key_expanded, "0") == 0
     || Ustrcmp(dkim_private_key_expanded, "false") == 0
     )
    continue;		/* don't sign, but no error */

  if (dkim_private_key_expanded[0] == '/')
    {
    int privkey_fd, off = 0, len;

    /* Looks like a filename, load the private key. */

    memset(big_buffer, 0, big_buffer_size);

    if ((privkey_fd = open(CS dkim_private_key_expanded, O_RDONLY)) < 0)
      {
      log_write(0, LOG_MAIN | LOG_PANIC, "unable to open "
		 "private key file for reading: %s",
		 dkim_private_key_expanded);
      goto bad;
      }

    do
      {
      if ((len = read(privkey_fd, big_buffer + off, big_buffer_size - 2 - off)) < 0)
	{
	(void) close(privkey_fd);
	log_write(0, LOG_MAIN|LOG_PANIC, "unable to read private key file: %s",
		   dkim_private_key_expanded);
	goto bad;
	}
      off += len;
      }
    while (len > 0);

    (void) close(privkey_fd);
    big_buffer[off] = '\0';
    dkim_private_key_expanded = big_buffer;
    }

  if (!(ctx = pdkim_init_sign(CS dkim_signing_domain,
			CS dkim_signing_selector,
			CS dkim_private_key_expanded,
			PDKIM_ALGO_RSA_SHA256,
			dkim->dot_stuffed,
			&dkim_exim_query_dns_txt,
			errstr
			)))
    goto bad;
  dkim_private_key_expanded[0] = '\0';
  pdkim_set_optional(ctx,
		      CS dkim_sign_headers_expanded,
		      NULL,
		      pdkim_canon,
		      pdkim_canon, -1, 0, 0);

  if (prefix)
    pdkim_feed(ctx, prefix, Ustrlen(prefix));

  lseek(fd, off, SEEK_SET);

  while ((sread = read(fd, &buf, sizeof(buf))) > 0)
    if ((pdkim_rc = pdkim_feed(ctx, buf, sread)) != PDKIM_OK)
      goto pk_bad;

  /* Handle failed read above. */
  if (sread == -1)
    {
    debug_printf("DKIM: Error reading -K file.\n");
    save_errno = errno;
    goto bad;
    }

  if ((pdkim_rc = pdkim_feed_finish(ctx, &signature, errstr)) != PDKIM_OK)
    goto pk_bad;

  sigbuf = string_append(sigbuf, &sigsize, &sigptr, 2,
			  US signature->signature_header, US"\r\n");

  pdkim_free_ctx(ctx);
  ctx = NULL;
  }

if (sigbuf)
  {
  sigbuf[sigptr] = '\0';
  rc = sigbuf;
  }
else
  rc = US"";

CLEANUP:
  if (ctx)
    pdkim_free_ctx(ctx);
  store_pool = old_pool;
  errno = save_errno;
  return rc;

pk_bad:
  log_write(0, LOG_MAIN|LOG_PANIC,
	       	"DKIM: signing failed: %.100s", pdkim_errstr(pdkim_rc));
bad:
  rc = NULL;
  goto CLEANUP;
}

#endif
