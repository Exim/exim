/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2024 */
/* Copyright (c) University of Cambridge, 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Code for DKIM support. Other DKIM relevant code is in
   receive.c, transport.c and transports/smtp.c */

#include "../exim.h"

#ifndef DISABLE_DKIM

# include "pdkim.h"
# include "signing.h"

# ifdef MACRO_PREDEF
#  include "../macro_predef.h"

void
params_dkim(void)
{
builtin_macro_create_var(US"_DKIM_SIGN_HEADERS", US PDKIM_DEFAULT_SIGN_HEADERS);
builtin_macro_create_var(US"_DKIM_OVERSIGN_HEADERS", US PDKIM_OVERSIGN_HEADERS);
}
# else	/*!MACRO_PREDEF*/

/* Options */

uschar *dkim_verify_hashes	= US"sha256:sha512";
uschar *dkim_verify_keytypes	= US"ed25519:rsa";
uschar *dkim_verify_min_keysizes = US"rsa=1024 ed25519=250";
BOOL    dkim_verify_minimal	= FALSE;
uschar *dkim_verify_signers	= US"$dkim_signers";

/* $variables */

uschar *dkim_cur_signer		= NULL;
int     dkim_key_length		= 0;
uschar *dkim_signers		= NULL;
uschar *dkim_signing_domain	= NULL;
uschar *dkim_signing_selector	= NULL;
uschar *dkim_verify_reason	= NULL;
uschar *dkim_verify_status	= NULL;

/* Working variables */

unsigned dkim_collect_input	= 0;
void   *dkim_signatures		= NULL;
gstring *dkim_signing_record	= NULL;
uschar *dkim_vdom_firstpass	= NULL;


extern BOOL    dkim_transport_write_message(transport_ctx *,
                  struct ob_dkim *, const uschar ** errstr);

/****************************************/

pdkim_ctx dkim_sign_ctx;

int dkim_verify_oldpool;
pdkim_ctx * dkim_verify_ctx = NULL;
pdkim_signature *dkim_cur_sig = NULL;
static const uschar * dkim_collect_error = NULL;

#define DKIM_MAX_SIGNATURES 20
static void dkim_exim_verify_pause(BOOL pause);


/****************************************/

/* Look up the DKIM record in DNS for the given hostname.
Will use the first found if there are multiple.
The return string is tainted, having come from off-site.
*/

static uschar *
dkim_exim_query_dns_txt(const uschar * name)
{
dns_answer * dnsa = store_get_dns_answer();
dns_scan dnss;
rmark reset_point = store_mark();
gstring * g = string_get_tainted(256, GET_TAINTED);

lookup_dnssec_authenticated = NULL;
if (dns_lookup(dnsa, name, T_TXT, NULL) != DNS_SUCCEED)
  goto bad;

/* Search for TXT record */

for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS);
     rr;
     rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
  if (rr->type == T_TXT)
    {			/* Copy record content to the answer buffer */
    for (int rr_offset = 0; rr_offset < rr->size; )
      {
      uschar len = rr->data[rr_offset++];

      g = string_catn(g, US(rr->data + rr_offset), len);
      if (g->ptr >= PDKIM_DNS_TXT_MAX_RECLEN)
	goto bad;

      rr_offset += len;
      }

    /* Check if this looks like a DKIM record */
    if (Ustrncmp(g->s, "v=", 2) != 0 || strncasecmp(CS g->s, "v=dkim", 6) == 0)
      {
      store_free_dns_answer(dnsa);
      gstring_release_unused(g);
      return string_from_gstring(g);
      }

    gstring_reset(g);		/* overwrite previous record */
    }

bad:
store_reset(reset_point);
store_free_dns_answer(dnsa);
return NULL;	/*XXX better error detail?  logging? */
}



#ifdef EXPERIMENTAL_ARC
/* Module API:  Lookup a DNS DKIM record and parse the pubkey.

Arguments:
	dnsname		record to lookup in DNS
	pubkey_p	pointer for return of pubkey
	hashes_p	pointer for return of hashes

Return: srvtype, or NULL on error
*/

static const uschar *
dkim_exim_parse_dns_pubkey(const uschar * dnsname, blob ** pubkey_p,
  const uschar ** hashes_p)
{
const uschar * dnstxt = dkim_exim_query_dns_txt(dnsname);
pdkim_pubkey * p;

if (!dnstxt)
  {
  DEBUG(D_acl) debug_printf_indent("pubkey dns lookup fail\n");
  return NULL;
  }
if (!(p = pdkim_parse_pubkey_record(dnstxt)))
  {
  DEBUG(D_acl) debug_printf_indent("pubkey dns record format error\n");
  return NULL;
  }
*pubkey_p = &p->key;
*hashes_p = p->hashes;
return p->srvtype;
}




/* Return:
	OK	verify succesful
	FAIL	verify did not pass
	ERROR	problem setting up the pubkey
*/

static int
dkim_exim_sig_verify(const blob * sighash, const blob * data_hash,
  hashmethod hash, const blob * pubkey, const uschar ** errstr_p)
{
ev_ctx vctx;
const uschar * errstr;
int rc = OK;

if ((errstr = exim_dkim_verify_init(pubkey, KEYFMT_DER, &vctx, NULL)))
  rc = ERROR;
else if ((errstr = exim_dkim_verify(&vctx, hash, data_hash, sighash)))
  rc = FAIL;

*errstr_p = errstr;
return rc;
}
#endif



/****************************************/

static BOOL
dkim_exim_init(void * dummy)
{
if (f.dkim_init_done) return TRUE;
f.dkim_init_done = TRUE;
pdkim_init();
return TRUE;
}



/* Module API: Set up for verification of a message being received.
Always returns OK.
*/

static int
dkim_exim_verify_init(void)
{
BOOL dot_stuffing = chunking_state <= CHUNKING_OFFERED;

if (!smtp_input || smtp_batched_input || f.dkim_disable_verify)
  return OK;

dkim_exim_init(NULL);

/* There is a store-reset between header & body reception for the main pool
(actually, after every header line) so cannot use that as we need the data we
store per-header, during header processing, at the end of body reception
for evaluating the signature.  Any allocs done for dkim verify
memory-handling must use a different pool.  We use a separate one that we
can reset per message. */

dkim_verify_oldpool = store_pool;
store_pool = POOL_MESSAGE;

/* Free previous context if there is one */

if (dkim_verify_ctx)
  pdkim_free_ctx(dkim_verify_ctx);

/* Create new context */

dkim_verify_ctx = pdkim_init_verify(&dkim_exim_query_dns_txt, dot_stuffing);
dkim_exim_verify_pause(FALSE);
dkim_collect_input = dkim_verify_ctx ? DKIM_MAX_SIGNATURES : 0;
dkim_collect_error = NULL;

/* Start feed up with any cached data, but limited to message data */
receive_get_cache(chunking_state == CHUNKING_LAST
		  ? chunking_data_left : GETC_BUFFER_UNLIMITED);

store_pool = dkim_verify_oldpool;
return OK;
}


/* Module API : Submit a chunk of data for verification input.
A NULL data pointer indicates end-of-message.
Only use the data when the feed is activated. */

static void
dkim_exim_verify_feed(const uschar * data, unsigned len)
{
int rc;

store_pool = POOL_MESSAGE;
if (  dkim_collect_input
   && (rc = pdkim_feed(dkim_verify_ctx, data, len)) != PDKIM_OK)
  {
  dkim_collect_error = pdkim_errstr(rc);
  log_write(0, LOG_MAIN,
	     "DKIM: validation error: %.100s", dkim_collect_error);
  dkim_collect_input = 0;
  }
store_pool = dkim_verify_oldpool;
}


/* Module API: pause/resume the verification data feed */

static void
dkim_exim_verify_pause(BOOL pause)
{
static unsigned save = 0;
static BOOL paused = FALSE;

if (!pause)
  {
  if (paused)
    { dkim_collect_input = save; paused = FALSE; }
  }
else
  if (!paused)
    { save = dkim_collect_input; dkim_collect_input = 0; paused = TRUE; }
}

/* Module API: Finish off the body hashes, calculate sigs and do compares */

static void
dkim_exim_verify_finish(void)
{
int rc;
gstring * g = NULL;
const uschar * errstr = NULL;

store_pool = POOL_MESSAGE;

/* Delete eventual previous signature chain */

dkim_signers = NULL;
dkim_signatures = NULL;

if (dkim_collect_error)
  {
  log_write(0, LOG_MAIN,
      "DKIM: Error during validation, disabling signature verification: %.100s",
      dkim_collect_error);
  f.dkim_disable_verify = TRUE;
  goto out;
  }

dkim_collect_input = 0;

/* Finish DKIM operation and fetch link to signatures chain */

rc = pdkim_feed_finish(dkim_verify_ctx, (pdkim_signature **)&dkim_signatures,
			&errstr);
if (rc != PDKIM_OK && errstr && *errstr)
  log_write(0, LOG_MAIN, "DKIM: validation error: %s", errstr);

/* Build a colon-separated list of signing domains (and identities, if present) in dkim_signers */

for (pdkim_signature * sig = dkim_signatures; sig; sig = sig->next)
  {
  if (sig->domain)   g = string_append_listele(g, ':', sig->domain);
  if (sig->identity) g = string_append_listele(g, ':', sig->identity);
  }
gstring_release_unused(g);
dkim_signers = string_from_gstring(g);

out:
store_pool = dkim_verify_oldpool;
}



/* Log the result for the given signature */
static void
dkim_exim_verify_log_sig(pdkim_signature * sig)
{
gstring * logmsg;
uschar * s;

if (!sig) return;

/* Remember the domain for the first pass result */

if (  !dkim_vdom_firstpass
   && dkim_verify_status
      ? Ustrcmp(dkim_verify_status, US"pass") == 0
      : sig->verify_status == PDKIM_VERIFY_PASS
   )
  dkim_vdom_firstpass= string_copy(sig->domain);

/* Rewrite the sig result if the ACL overrode it.  This is only
needed because the DMARC code (sigh) peeks at the dkim sigs.
Mark the sig for this having been done. */

if (  dkim_verify_status
   && (  dkim_verify_status != dkim_exim_expand_query(DKIM_VERIFY_STATUS)
      || dkim_verify_reason != dkim_exim_expand_query(DKIM_VERIFY_REASON)
   )  )
  {			/* overridden by ACL */
  sig->verify_ext_status = -1;
  if (Ustrcmp(dkim_verify_status, US"fail") == 0)
    sig->verify_status = PDKIM_VERIFY_POLICY | PDKIM_VERIFY_FAIL;
  else if (Ustrcmp(dkim_verify_status, US"invalid") == 0)
    sig->verify_status = PDKIM_VERIFY_POLICY | PDKIM_VERIFY_INVALID;
  else if (Ustrcmp(dkim_verify_status, US"none") == 0)
    sig->verify_status = PDKIM_VERIFY_POLICY | PDKIM_VERIFY_NONE;
  else if (Ustrcmp(dkim_verify_status, US"pass") == 0)
    sig->verify_status = PDKIM_VERIFY_POLICY | PDKIM_VERIFY_PASS;
  else
    sig->verify_status = -1;
  }

if (!LOGGING(dkim_verbose)) return;


logmsg = string_catn(NULL, US"DKIM: ", 6);
if (!(s = sig->domain)) s = US"<UNSET>";
logmsg = string_append(logmsg, 2, "d=", s);
if (!(s = sig->selector)) s = US"<UNSET>";
logmsg = string_append(logmsg, 2, " s=", s);
logmsg = string_fmt_append(logmsg, " c=%s/%s a=%s b=" SIZE_T_FMT,
	  sig->canon_headers == PDKIM_CANON_SIMPLE ? "simple" : "relaxed",
	  sig->canon_body    == PDKIM_CANON_SIMPLE ? "simple" : "relaxed",
	  dkim_sig_to_a_tag(sig),
	  (int)sig->sighash.len > -1 ? sig->sighash.len * 8 : (size_t)0);
if ((s= sig->identity)) logmsg = string_append(logmsg, 2, " i=", s);
if (sig->created > 0) logmsg = string_fmt_append(logmsg, " t=%lu",
				    sig->created);
if (sig->expires > 0) logmsg = string_fmt_append(logmsg, " x=%lu",
				    sig->expires);
if (sig->bodylength > -1) logmsg = string_fmt_append(logmsg, " l=%lu",
				    sig->bodylength);

if (sig->verify_status & PDKIM_VERIFY_POLICY)
  logmsg = string_append(logmsg, 5,
	    US" [", dkim_verify_status, US" - ", dkim_verify_reason, US"]");
else
  switch (sig->verify_status)
    {
    case PDKIM_VERIFY_NONE:
      logmsg = string_cat(logmsg, US" [not verified]");
      break;

    case PDKIM_VERIFY_INVALID:
      logmsg = string_cat(logmsg, US" [invalid - ");
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE:
	  logmsg = string_cat(logmsg,
			US"public key record (currently?) unavailable]");
	  break;

	case PDKIM_VERIFY_INVALID_BUFFER_SIZE:
	  logmsg = string_cat(logmsg, US"overlong public key record]");
	  break;

	case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD:
	case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT:
	  logmsg = string_cat(logmsg, US"syntax error in public key record]");
	  break;

	case PDKIM_VERIFY_INVALID_SIGNATURE_ERROR:
	  logmsg = string_cat(logmsg, US"signature tag missing or invalid]");
	  break;

	case PDKIM_VERIFY_INVALID_DKIM_VERSION:
	  logmsg = string_cat(logmsg, US"unsupported DKIM version]");
	  break;

	default:
	  logmsg = string_cat(logmsg, US"unspecified problem]");
	}
      break;

    case PDKIM_VERIFY_FAIL:
      logmsg = string_cat(logmsg, US" [verification failed - ");
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_FAIL_BODY:
	  logmsg = string_cat(logmsg,
	       US"body hash mismatch (body probably modified in transit)]");
	  break;

	case PDKIM_VERIFY_FAIL_MESSAGE:
	  logmsg = string_cat(logmsg,
		US"signature did not verify "
		"(headers probably modified in transit)]");
	  break;

	case PDKIM_VERIFY_INVALID_PUBKEY_KEYSIZE:
	  logmsg = string_cat(logmsg,
		US"signature invalid (key too short)]");
	  break;

	default:
	  logmsg = string_cat(logmsg, US"unspecified reason]");
	}
      break;

    case PDKIM_VERIFY_PASS:
      logmsg = string_cat(logmsg, US" [verification succeeded]");
      break;
    }

log_write(0, LOG_MAIN, "%Y", logmsg);
return;
}


/* Module API:  Log a line for each signature */

void
dkim_exim_verify_log_all(void)
{
for (pdkim_signature * sig = dkim_signatures; sig; sig = sig->next)
  dkim_exim_verify_log_sig(sig);
}


/* Module API: append a log element with domain for the first passing sig */

gstring *
dkim_exim_vdom_firstpass(gstring * g)
{
if (dkim_vdom_firstpass)
  g = string_append(g, 2, US" DKIM=", dkim_vdom_firstpass);
return g;
}


/* For one signature, run the DKIM ACL, log the sig result,
and append ths sig status to the status list.

Args as per dkim_exim_acl_run() below */

static int
dkim_acl_call(uschar * id, gstring ** res_ptr,
  uschar ** user_msgptr, uschar ** log_msgptr)
{
int rc;
DEBUG(D_receive)
  debug_printf("calling acl_smtp_dkim for identity '%s' domain '%s' sel '%s'\n",
	      id, dkim_signing_domain, dkim_signing_selector);

rc = acl_check(ACL_WHERE_DKIM, NULL, acl_smtp_dkim, user_msgptr, log_msgptr);
dkim_exim_verify_log_sig(dkim_cur_sig);
*res_ptr = string_append_listele(*res_ptr, ':', dkim_verify_status);
return rc;
}



/* For the given identity, run the DKIM ACL once for each matching signature.
If none match, run it once.

Arguments
 id		Identity to look for in dkim signatures
 res_ptr	ptr to growable string-list of status results,
		appended to per ACL run
 user_msgptr	where to put a user error (for SMTP response)
 log_msgptr	where to put a logging message (not for SMTP response)

Returns:       OK         access is granted by an ACCEPT verb
               DISCARD    access is granted by a DISCARD verb
               FAIL       access is denied
               FAIL_DROP  access is denied; drop the connection
               DEFER      can't tell at the moment
               ERROR      disaster
*/

static int
dkim_exim_acl_run(uschar * id, gstring ** res_ptr,
  uschar ** user_msgptr, uschar ** log_msgptr)
{
const uschar * cmp_val;
int rc = -1;

dkim_verify_status = US"none";
dkim_verify_reason = US"";
dkim_cur_signer = id;

if (f.dkim_disable_verify || !id || !dkim_verify_ctx)
  return OK;

/* Find signatures to run ACL on */

for (pdkim_signature * sig = dkim_signatures; sig; sig = sig->next)
  if (  (cmp_val = Ustrchr(id, '@') != NULL ? US sig->identity : US sig->domain)
     && strcmpic(cmp_val, id) == 0
     )
    {
    /* The "dkim_domain" and "dkim_selector" expansion variables have
    related globals, since they are used in the signing code too.
    Instead of inventing separate names for verification, we set
    them here. This is easy since a domain and selector is guaranteed
    to be in a signature. The other dkim_* expansion items are
    dynamically fetched from dkim_cur_sig at expansion time (see
    dkim_exim_expand_query() below). */

    dkim_cur_sig = sig;
    dkim_signing_domain = US sig->domain;
    dkim_signing_selector = US sig->selector;
    dkim_key_length = sig->keybits;

    /* These two return static strings, so we can compare the addr
    later to see if the ACL overwrote them.  Check that when logging */

    dkim_verify_status = dkim_exim_expand_query(DKIM_VERIFY_STATUS);
    dkim_verify_reason = dkim_exim_expand_query(DKIM_VERIFY_REASON);

    if (  (rc = dkim_acl_call(id, res_ptr, user_msgptr, log_msgptr)) != OK
       || dkim_verify_minimal && Ustrcmp(dkim_verify_status, "pass") == 0)
      return rc;
    }

if (rc != -1)
  return rc;

/* No matching sig found.  Call ACL once anyway. */

dkim_cur_sig = NULL;
return dkim_acl_call(id, res_ptr, user_msgptr, log_msgptr);
}


/* Module API:
Loop over dkim_verify_signers option doing ACL calls.  If one return any
non-OK value stop and return that, else return OK.
*/

int
    /*XXX need a user_msgptr */
dkim_exim_acl_entry(uschar ** user_msgptr, uschar ** log_msgptr)
{
int rc = OK;

GET_OPTION("dkim_verify_signers");
if (dkim_verify_signers && *dkim_verify_signers)
  {
  const uschar * dkim_verify_signers_expanded =
		      expand_string(dkim_verify_signers);
  gstring * results = NULL, * seen_items = NULL;
  int signer_sep = 0, old_pool = store_pool;

  if (!dkim_verify_signers_expanded)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
      "expansion of dkim_verify_signers option failed: %s",
      expand_string_message);
    return DEFER;
    }

  store_pool = POOL_PERM;   /* Allow created variables to live to data ACL */

  /* Loop over signers we want to verify, calling ACL.  Default to OK
  when no signers are present.  Each call from here expands to an ACL
  call per matching sig in the message. */

  for (uschar * item;
      item = string_nextinlist(&dkim_verify_signers_expanded,
				    &signer_sep, NULL, 0); )
    {
    /* Prevent running ACL for an empty item */
    if (!item || !*item) continue;

    /* Only run ACL once for each domain or identity,
    no matter how often it appears in the expanded list. */
    if (seen_items)
      {
      int seen_sep = ':';
      BOOL seen_this_item = FALSE;

      for (const uschar * seen_items_list = string_from_gstring(seen_items),
	    * seen_item;
	    seen_item = string_nextinlist(&seen_items_list, &seen_sep, NULL, 0);
	  )
	if (Ustrcmp(seen_item, item) == 0)
	  { seen_this_item = TRUE; break; }

      if (seen_this_item)
	{
	DEBUG(D_receive)
	  debug_printf("acl_smtp_dkim: skipping signer %s, "
	    "already seen\n", item);
	continue;
	}

      seen_items = string_catn(seen_items, US":", 1);
      }
    seen_items = string_cat(seen_items, item);

    if ((rc = dkim_exim_acl_run(item, &results, user_msgptr, log_msgptr)) != OK)
      {
      DEBUG(D_receive)
	debug_printf("acl_smtp_dkim: acl_check returned %d on %s, "
	  "skipping remaining items\n", rc, item);
      break;
      }
    if (dkim_verify_minimal && Ustrcmp(dkim_verify_status, "pass") == 0)
      break;
    }			/* signers loop */

  dkim_verify_status = string_from_gstring(results);
  store_pool = old_pool;
  }
else
  dkim_exim_verify_log_all();

return rc;
}

/******************************************************************************/

/* Module API */

static int
dkim_exim_signer_isinlist(const uschar * l)
{
return dkim_cur_signer
  ? match_isinlist(dkim_cur_signer, &l, 0, NULL, NULL, MCL_STRING, TRUE, NULL)
  : FAIL;
}

/* Module API */

static int
dkim_exim_status_listmatch(const uschar * l)
{						/* return good for any match */
const uschar * s = dkim_verify_status ? dkim_verify_status : US"none";
int sep = 0, rc = FAIL;
for (const uschar * ss; ss = string_nextinlist(&s, &sep, NULL, 0); )
  if (   (rc = match_isinlist(ss, &l, 0, NULL, NULL, MCL_STRING, TRUE, NULL))
      == OK) break;
return rc;
}

/* Module API: Overwriteable dkim result variables */

static void
dkim_exim_setvar(const uschar * name, void * val)
{
if (Ustrcmp(name, "dkim_verify_status") == 0)
  dkim_verify_status = val;
else if (Ustrcmp(name, "dkim_verify_reason") == 0)
  dkim_verify_reason = val;
}

/******************************************************************************/

static void
dkim_smtp_reset(void)
{
dkim_cur_signer = dkim_signers =
dkim_signing_domain = dkim_signing_selector = dkim_signatures = NULL;
f.dkim_disable_verify = FALSE;
dkim_collect_input = 0;
dkim_vdom_firstpass = dkim_verify_status = dkim_verify_reason = NULL;
dkim_key_length = 0;
}

/******************************************************************************/

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


/* Module API: return a computed value for a variable expansion */

uschar *
dkim_exim_expand_query(int what)
{
if (!dkim_verify_ctx || f.dkim_disable_verify || !dkim_cur_sig)
  return dkim_exim_expand_defaults(what);

switch (what)
  {
  case DKIM_ALGO:
    return dkim_sig_to_a_tag(dkim_cur_sig);

  case DKIM_BODYLENGTH:
    return dkim_cur_sig->bodylength >= 0
      ? string_sprintf("%ld", dkim_cur_sig->bodylength)
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
      ? string_sprintf("%lu", dkim_cur_sig->created)
      : dkim_exim_expand_defaults(what);

  case DKIM_EXPIRES:
    return dkim_cur_sig->expires > 0
      ? string_sprintf("%lu", dkim_cur_sig->expires)
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
      case PDKIM_VERIFY_INVALID_PUBKEY_KEYSIZE:	return US"pubkey_too_short";
      case PDKIM_VERIFY_FAIL_BODY:		return US"bodyhash_mismatch";
      case PDKIM_VERIFY_FAIL_MESSAGE:		return US"signature_incorrect";
      }

  default:
    return US"";
  }
}


/* Module API */

static void
dkim_exim_sign_init(void)
{
int old_pool = store_pool;

dkim_exim_init(NULL);
store_pool = POOL_MAIN;
pdkim_init_context(&dkim_sign_ctx, FALSE, &dkim_exim_query_dns_txt);
store_pool = old_pool;
}


/* Generate signatures for the given file.
If a prefix is given, prepend it to the file for the calculations.

Return:
  NULL:		error; error string written
  string: 	signature header(s), or a zero-length string (not an error)
*/

gstring *
dkim_exim_sign(int fd, off_t off, uschar * prefix,
  struct ob_dkim * dkim, const uschar ** errstr)
{
const uschar * dkim_domain = NULL;
int sep = 0;
gstring * seen_doms = NULL;
pdkim_signature * sig;
gstring * sigbuf;
int pdkim_rc;
int sread;
uschar buf[4096];
int save_errno = 0;
int old_pool = store_pool;
uschar * errwhen;
const uschar * s;

if (dkim->dot_stuffed)
  dkim_sign_ctx.flags |= PDKIM_DOT_TERM;

store_pool = POOL_MAIN;

GET_OPTION("dkim_domain");
if ((s = dkim->dkim_domain) && !(dkim_domain = expand_string(s)))
  /* expansion error, do not send message. */
  { errwhen = US"dkim_domain"; goto expand_bad; }

/* Set $dkim_domain expansion variable to each unique domain in list. */

if (dkim_domain)
  while ((dkim_signing_domain = string_nextinlist(&dkim_domain, &sep, NULL, 0)))
  {
  const uschar * dkim_sel;
  int sel_sep = 0;

  if (dkim_signing_domain[0] == '\0')
    continue;

  /* Only sign once for each domain, no matter how often it
  appears in the expanded list. */

  dkim_signing_domain = string_copylc(dkim_signing_domain);
  if (match_isinlist(dkim_signing_domain, CUSS &seen_doms,
      0, NULL, NULL, MCL_STRING, TRUE, NULL) == OK)
    continue;

  seen_doms = string_append_listele(seen_doms, ':', dkim_signing_domain);

  /* Set $dkim_selector expansion variable to each selector in list,
  for this domain. */

  GET_OPTION("dkim_selector");
  if (!(dkim_sel = expand_string(dkim->dkim_selector)))
    { errwhen = US"dkim_selector"; goto expand_bad; }

  while ((dkim_signing_selector = string_nextinlist(&dkim_sel, &sel_sep,
	  NULL, 0)))
    {
    uschar * dkim_canon_expanded;
    int pdkim_canon;
    const uschar * dkim_sign_headers_expanded = NULL;
    uschar * dkim_private_key_expanded, * dkim_hash_expanded;
    const uschar * dkim_identity_expanded = NULL;
    const uschar * dkim_timestamps_expanded = NULL;
    unsigned long tval = 0, xval = 0;

    /* Get canonicalization to use */

    GET_OPTION("dkim_canon");
    dkim_canon_expanded = dkim->dkim_canon
      ? expand_string(dkim->dkim_canon) : US"relaxed";
    if (!dkim_canon_expanded)	/* expansion error, do not send message. */
      { errwhen = US"dkim_canon"; goto expand_bad; }

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

    GET_OPTION("dkim_sign_headers");
    if (  dkim->dkim_sign_headers
       && !(dkim_sign_headers_expanded = expand_string(dkim->dkim_sign_headers)))
      { errwhen = US"dkim_sign_header"; goto expand_bad; }
    /* else pass NULL, which means default header list */

    /* Get private key to use. */

    GET_OPTION("dkim_private_key");
    if (!(dkim_private_key_expanded = expand_string(dkim->dkim_private_key)))
      { errwhen = US"dkim_private_key"; goto expand_bad; }

    if (  dkim_private_key_expanded[0] == '\0'
       || Ustrcmp(dkim_private_key_expanded, "0") == 0
       || Ustrcmp(dkim_private_key_expanded, "false") == 0
       )
      continue;		/* don't sign, but no error */

    if (  dkim_private_key_expanded[0] == '/'
       && !(dkim_private_key_expanded =
	     expand_file_big_buffer(dkim_private_key_expanded)))
      goto clear_key_bad;

    GET_OPTION("dkim_hash");
    if (!(dkim_hash_expanded = expand_string(dkim->dkim_hash)))
      { errwhen = US"dkim_hash"; goto clear_key_expand_bad; }

    GET_OPTION("dkim_identity");
    if (dkim->dkim_identity)
      if (!(dkim_identity_expanded = expand_string(dkim->dkim_identity)))
	{ errwhen = US"dkim_identity"; goto clear_key_expand_bad; }
      else if (!*dkim_identity_expanded)
	dkim_identity_expanded = NULL;

    GET_OPTION("dkim_timestamps");
    if (dkim->dkim_timestamps)
      if (!(dkim_timestamps_expanded = expand_string(dkim->dkim_timestamps)))
	{ errwhen = US"dkim_timestamps"; goto clear_key_expand_bad; }
      else
        {
        tval = (unsigned long) time(NULL);
        xval = strtoul(CCS dkim_timestamps_expanded, NULL, 10);
        if (xval > 0)
          xval += tval;
        }

    if (!(sig = pdkim_init_sign(&dkim_sign_ctx, dkim_signing_domain,
			  dkim_signing_selector,
			  dkim_private_key_expanded,
			  dkim_hash_expanded,
			  errstr
			  )))
      goto clear_key_bad;

    if (dkim_private_key_expanded != dkim->dkim_private_key)
      /* Avoid leaking keying material via big_buffer */
      dkim_private_key_expanded[0] = '\0';

    pdkim_set_optional(sig,
			CCS dkim_sign_headers_expanded,
			CCS dkim_identity_expanded,
			pdkim_canon,
			pdkim_canon, -1, tval, xval);

    if (!pdkim_set_sig_bodyhash(&dkim_sign_ctx, sig))
      goto bad;

    dkim_signing_record = string_append_listele(dkim_signing_record, ':', dkim_signing_domain);
    dkim_signing_record = string_append_listele(dkim_signing_record, ':', dkim_signing_selector);

    if (!dkim_sign_ctx.sig)		/* link sig to context chain */
      dkim_sign_ctx.sig = sig;
    else
      {
      pdkim_signature * n = dkim_sign_ctx.sig;
      while (n->next) n = n->next;
      n->next = sig;
      }
    continue;				/* next selector */

    clear_key_bad:
      if (  dkim_private_key_expanded
	 && dkim_private_key_expanded != dkim->dkim_private_key)
	dkim_private_key_expanded[0] = '\0';
      goto bad;

    clear_key_expand_bad:
      if (  dkim_private_key_expanded
	 && dkim_private_key_expanded != dkim->dkim_private_key)
	dkim_private_key_expanded[0] = '\0';
      goto expand_bad;
    }
  }

/* We may need to carry on with the data-feed even if there are no DKIM sigs to
produce, if some other package (eg. ARC) is signing. */

if (!dkim_sign_ctx.sig && !dkim->force_bodyhash)
  {
  DEBUG(D_transport) debug_printf("DKIM: no viable signatures to use\n");
  sigbuf = string_get(1);	/* return a zero-len string */
  }
else
  {
  if (prefix && (pdkim_rc = pdkim_feed(&dkim_sign_ctx, prefix, Ustrlen(prefix))) != PDKIM_OK)
    goto pk_bad;

  if (lseek(fd, off, SEEK_SET) < 0)
    sread = -1;
  else
    while ((sread = read(fd, &buf, sizeof(buf))) > 0)
      if ((pdkim_rc = pdkim_feed(&dkim_sign_ctx, buf, sread)) != PDKIM_OK)
	goto pk_bad;

  /* Handle failed read above. */
  if (sread == -1)
    {
    debug_printf("DKIM: Error reading -K file.\n");
    save_errno = errno;
    goto bad;
    }

  /* Build string of headers, one per signature */

  if ((pdkim_rc = pdkim_feed_finish(&dkim_sign_ctx, &sig, errstr)) != PDKIM_OK)
    goto pk_bad;

  if (!sig)
    {
    DEBUG(D_transport) debug_printf("DKIM: no signatures to use\n");
    sigbuf = string_get(1);	/* return a zero-len string */
    }
  else for (sigbuf = NULL; sig; sig = sig->next)
    sigbuf = string_append(sigbuf, 2, US sig->signature_header, US"\r\n");
  }

CLEANUP:
  (void) string_from_gstring(sigbuf);
  store_pool = old_pool;
  errno = save_errno;
  return sigbuf;

pk_bad:
  log_write(0, LOG_MAIN|LOG_PANIC,
		"DKIM: signing failed: %.100s", pdkim_errstr(pdkim_rc));
bad:
  sigbuf = NULL;
  goto CLEANUP;

expand_bad:
  *errstr = string_sprintf("failed to expand %s: %s",
              errwhen, expand_string_message);
  log_write(0, LOG_MAIN | LOG_PANIC, "%s", *errstr);
  goto bad;
}



#ifdef SUPPORT_DMARC

/* Module API */

static const pdkim_signature *
dkim_sigs_list(void)
{
return dkim_signatures;
}
#endif

#ifdef EXPERIMENTAL_ARC

/* Module API */
static int
dkim_hashname_to_type(const blob * name)
{
return pdkim_hashname_to_hashtype(name->data, name->len);
}

/* Module API */
hashmethod
dkim_hashtype_to_method(int hashtype)
{
return hashtype >= 0 ? pdkim_hashes[hashtype].exim_hashmethod : -1;
}

/* Module API */
hashmethod
dkim_hashname_to_method(const blob * name)
{
return dkim_hashtype_to_method(dkim_hashname_to_type(name));
}

/*  Module API: Set up a body hashing method on the given signature-context
(creates a new one if needed, or uses an already-present one).

Arguments:
	signing		TRUE to use dkim's signing context, else dkim_verify_ctx
        canon		canonicalization spec, text form
        hash		hash spec, text form
        bodylen         byte count for message body

Return: pointer to hashing method struct
*/

static pdkim_bodyhash *
dkim_set_bodyhash(BOOL signing,
  const blob * canon, const blob * hashname, long bodylen)
{
int canon_head = -1, canon_body = -1;

pdkim_cstring_to_canons(canon->data, canon->len, &canon_head, &canon_body);
return pdkim_set_bodyhash(signing ? &dkim_sign_ctx: dkim_verify_ctx,
        dkim_hashname_to_type(hashname),
        canon_body,
        bodylen);
}

/* Module API: Sign a blob of data (which might already be a hash, if
Ed25519 or GCrypt signing).

Arguments:
	data		to be signed
	hm		hash to be applied to the data
	privkey		private key for siging, PEM format
	signature	pointer for result blob

Return: NULL, or error string on failure
*/

static const uschar *
dkim_sign_blob(const blob * data, hashmethod hm, const uschar * privkey,
  blob * signature)
{
es_ctx sctx;
const uschar * errstr;

if ((errstr = exim_dkim_signing_init(privkey, &sctx)))
  { DEBUG(D_transport) debug_printf("signing key setup: %s\n", errstr); }
else errstr = exim_dkim_sign(&sctx, hm, data, signature);

return errstr;
}

#endif	/*EXPERIMENTAL_ARC*/


/* Module API */

gstring *
authres_dkim(gstring * g)
{
int start = 0;		/* compiler quietening */

DEBUG(D_acl) start = gstring_length(g);

for (pdkim_signature * sig = dkim_signatures; sig; sig = sig->next)
  {
  g = string_catn(g, US";\n\tdkim=", 8);

  if (sig->verify_status & PDKIM_VERIFY_POLICY)
    g = string_append(g, 5,
      US"policy (", dkim_verify_status, US" - ", dkim_verify_reason, US")");
  else switch(sig->verify_status)
    {
    case PDKIM_VERIFY_NONE:    g = string_cat(g, US"none"); break;
    case PDKIM_VERIFY_INVALID:
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE:
          g = string_cat(g, US"tmperror (pubkey unavailable)\n\t\t"); break;
        case PDKIM_VERIFY_INVALID_BUFFER_SIZE:
          g = string_cat(g, US"permerror (overlong public key record)\n\t\t"); break;
        case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD:
        case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT:
          g = string_cat(g, US"neutral (public key record import problem)\n\t\t");
          break;
        case PDKIM_VERIFY_INVALID_SIGNATURE_ERROR:
          g = string_cat(g, US"neutral (signature tag missing or invalid)\n\t\t");
          break;
        case PDKIM_VERIFY_INVALID_DKIM_VERSION:
          g = string_cat(g, US"neutral (unsupported DKIM version)\n\t\t");
          break;
        default:
          g = string_cat(g, US"permerror (unspecified problem)\n\t\t"); break;
	}
      break;
    case PDKIM_VERIFY_FAIL:
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_FAIL_BODY:
          g = string_cat(g,
	    US"fail (body hash mismatch; body probably modified in transit)\n\t\t");
	  break;
        case PDKIM_VERIFY_FAIL_MESSAGE:
          g = string_cat(g,
	    US"fail (signature did not verify; headers probably modified in transit)\n\t\t");
	  break;
        case PDKIM_VERIFY_INVALID_PUBKEY_KEYSIZE:	/* should this really be "polcy"? */
          g = string_fmt_append(g, "fail (public key too short: %u bits)\n\t\t", sig->keybits);
          break;
        default:
          g = string_cat(g, US"fail (unspecified reason)\n\t\t");
	  break;
	}
      break;
    case PDKIM_VERIFY_PASS:    g = string_cat(g, US"pass"); break;
    default:                   g = string_cat(g, US"permerror"); break;
    }
  if (sig->domain)   g = string_append(g, 2, US" header.d=", sig->domain);
  if (sig->identity) g = string_append(g, 2, US" header.i=", sig->identity);
  if (sig->selector) g = string_append(g, 2, US" header.s=", sig->selector);
  g = string_append(g, 2, US" header.a=", dkim_sig_to_a_tag(sig));
  }

DEBUG(D_acl)
  if (gstring_length(g) == start)
    debug_printf("DKIM:\tno authres\n");
  else
    debug_printf("DKIM:\tauthres '%.*s'\n", g->ptr - start - 3, g->s + start + 3);
return g;
}

/******************************************************************************/
/* Module API */

static optionlist dkim_options[] = {
  { "acl_smtp_dkim",		opt_stringptr,   {&acl_smtp_dkim} },
  { "dkim_verify_hashes",       opt_stringptr,   {&dkim_verify_hashes} },
  { "dkim_verify_keytypes",     opt_stringptr,   {&dkim_verify_keytypes} },
  { "dkim_verify_min_keysizes", opt_stringptr,   {&dkim_verify_min_keysizes} },
  { "dkim_verify_minimal",      opt_bool,        {&dkim_verify_minimal} },
  { "dkim_verify_signers",      opt_stringptr,   {&dkim_verify_signers} },
};

static void * dkim_functions[] = {
  [DKIM_VERIFY_FEED] =		(void *) dkim_exim_verify_feed,
  [DKIM_VERIFY_PAUSE] =		(void *) dkim_exim_verify_pause,
  [DKIM_VERIFY_FINISH] =	(void *) dkim_exim_verify_finish,
  [DKIM_ACL_ENTRY] =		(void *) dkim_exim_acl_entry,
  [DKIM_VERIFY_LOG_ALL] =	(void *) dkim_exim_verify_log_all,
  [DKIM_VDOM_FIRSTPASS] =	(void *) dkim_exim_vdom_firstpass,

  [DKIM_SIGNER_ISINLIST] =	(void *) dkim_exim_signer_isinlist,
  [DKIM_STATUS_LISTMATCH] =	(void *) dkim_exim_status_listmatch,

  [DKIM_SETVAR] =		(void *) dkim_exim_setvar,
  [DKIM_EXPAND_QUERY] =		(void *) dkim_exim_expand_query,

  [DKIM_TRANSPORT_INIT] =	(void *) dkim_exim_sign_init,
  [DKIM_TRANSPORT_WRITE] =	(void *) dkim_transport_write_message,

#ifdef SUPPORT_DMARC
  [DKIM_SIGS_LIST] =		(void *) dkim_sigs_list,
#endif
#ifdef EXPERIMENTAL_ARC
  [DKIM_HASHNAME_TO_TYPE] =	(void *) dkim_hashname_to_type,
  [DKIM_HASHTYPE_TO_METHOD] =	(void *) dkim_hashtype_to_method,
  [DKIM_HASHNAME_TO_METHOD] =	(void *) dkim_hashname_to_method,
  [DKIM_SET_BODYHASH] =		(void *) dkim_set_bodyhash,
  [DKIM_DNS_PUBKEY] =		(void *) dkim_exim_parse_dns_pubkey,
  [DKIM_SIG_VERIFY] =		(void *) dkim_exim_sig_verify,
  [DKIM_HEADER_RELAX] =		(void *) pdkim_relax_header_n,
  [DKIM_SIGN_DATA] =		(void *) dkim_sign_blob,
#endif
};

static var_entry dkim_variables[] = {
  { "dkim_algo",           vtype_dkim,        (void *)DKIM_ALGO },
  { "dkim_bodylength",     vtype_dkim,        (void *)DKIM_BODYLENGTH },
  { "dkim_canon_body",     vtype_dkim,        (void *)DKIM_CANON_BODY },
  { "dkim_canon_headers",  vtype_dkim,        (void *)DKIM_CANON_HEADERS },
  { "dkim_copiedheaders",  vtype_dkim,        (void *)DKIM_COPIEDHEADERS },
  { "dkim_created",        vtype_dkim,        (void *)DKIM_CREATED },
  { "dkim_cur_signer",     vtype_stringptr,   &dkim_cur_signer },
  { "dkim_domain",         vtype_stringptr,   &dkim_signing_domain },
  { "dkim_expires",        vtype_dkim,        (void *)DKIM_EXPIRES },
  { "dkim_headernames",    vtype_dkim,        (void *)DKIM_HEADERNAMES },
  { "dkim_identity",       vtype_dkim,        (void *)DKIM_IDENTITY },
  { "dkim_key_granularity",vtype_dkim,        (void *)DKIM_KEY_GRANULARITY },
  { "dkim_key_length",     vtype_int,         &dkim_key_length },
  { "dkim_key_nosubdomains",vtype_dkim,       (void *)DKIM_NOSUBDOMAINS },
  { "dkim_key_notes",      vtype_dkim,        (void *)DKIM_KEY_NOTES },
  { "dkim_key_srvtype",    vtype_dkim,        (void *)DKIM_KEY_SRVTYPE },
  { "dkim_key_testing",    vtype_dkim,        (void *)DKIM_KEY_TESTING },
  { "dkim_selector",       vtype_stringptr,   &dkim_signing_selector },
  { "dkim_signers",        vtype_stringptr,   &dkim_signers },
  { "dkim_verify_reason",  vtype_stringptr,   &dkim_verify_reason },
  { "dkim_verify_status",  vtype_stringptr,   &dkim_verify_status },
};

misc_module_info dkim_module_info = {
  .name =		US"dkim",
# ifdef DYNLOOKUP
  .dyn_magic =		MISC_MODULE_MAGIC,
# endif
  .init =		dkim_exim_init,
  .msg_init =		dkim_exim_verify_init,
  .authres =		authres_dkim,
  .smtp_reset =		dkim_smtp_reset,

  .options =		dkim_options,
  .options_count =	nelem(dkim_options),

  .functions =		dkim_functions,
  .functions_count =	nelem(dkim_functions),

  .variables =		dkim_variables,
  .variables_count =	nelem(dkim_variables),
};

# endif	/*!MACRO_PREDEF*/
#endif	/*!DISABLE_DKIM*/
