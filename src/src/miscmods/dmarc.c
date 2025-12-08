/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* DMARC support.
   Copyright (c) The Exim Maintainers 2019 - 2025
   Copyright (c) Todd Lyons <tlyons@exim.org> 2012 - 2014
   License: GPL */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Portions Copyright (c) 2012, 2013, The Trusted Domain Project;
   All rights reserved, licensed for use per LICENSE.opendmarc. */

/* Code for calling dmarc checks via libopendmarc. Called from acl.c. */

#include "../exim.h"

#ifdef SUPPORT_DMARC
# ifndef EXIM_HAVE_SPF
#  error SPF must also be enabled for DMARC
# elif defined DISABLE_DKIM
#  error DKIM must also be enabled for DMARC
# else

#  include "../functions.h"
#  include "dmarc.h"
#  include "pdkim.h"

extern void dmarc_send_forensic_report(const uschar **);
extern uschar * dmarc_dns_lookup(const uschar *);
extern void dmarc_write_history_file(const gstring *);

OPENDMARC_LIB_T     dmarc_ctx;
DMARC_POLICY_T     *dmarc_pctx;
OPENDMARC_STATUS_T  libdm_status;

typedef struct dmarc_exim_p {
  uschar *name;
  int    value;
} dmarc_exim_p;

static dmarc_exim_p dmarc_policy_description[] = {
  /* name		value */
  { US"",           DMARC_RECORD_P_UNSPECIFIED },
  { US"none",       DMARC_RECORD_P_NONE },
  { US"quarantine", DMARC_RECORD_P_QUARANTINE },
  { US"reject",     DMARC_RECORD_P_REJECT },
  { NULL,           0 }
};


/* $variables */
extern BOOL	 dmarc_alignment_dkim;	   /* Subtest result */
extern BOOL	 dmarc_alignment_spf;	   /* Subtest result */
extern const uschar * dmarc_domain_policy; /* Declared policy of used domain */
extern const uschar * dmarc_status;	   /* One word value */
extern const uschar * dmarc_status_text;   /* Human readable value */
extern uschar * dmarc_used_domain;

/* options */
extern uschar * dmarc_forensic_sender;	/* Set sender address for forensic reports */
extern uschar * dmarc_history_file;	/* File to store dmarc results */
extern uschar * dmarc_tld_file;		/* Mozilla TLDs text file */


BOOL
dmarc_local_init(void)
{ return TRUE; }

gstring *
dmarc_version_report(gstring * g)
{
return string_fmt_append(g, "Library version: dmarc: Compile: %d.%d.%d.%d\n",
    (OPENDMARC_LIB_VERSION & 0xff000000) >> 24,
    (OPENDMARC_LIB_VERSION & 0x00ff0000) >> 16,
    (OPENDMARC_LIB_VERSION & 0x0000ff00) >> 8,
    (OPENDMARC_LIB_VERSION & 0x000000ff));
}


void
dmarc_local_msg_init(void)
{
dmarc_pctx         = NULL;

(void) memset(&dmarc_ctx, '\0', sizeof dmarc_ctx);
dmarc_ctx.nscount = 0;
libdm_status = opendmarc_policy_library_init(&dmarc_ctx);
if (libdm_status != DMARC_PARSE_OKAY)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to init library: %s",
		       opendmarc_policy_status_to_str(libdm_status));
  dmarc_abort = TRUE;
  }
else if (opendmarc_tld_read_file(CS dmarc_tld_file, NULL, NULL, NULL))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to load tld list '%s': %s",
		       dmarc_tld_file, strerror(errno));
  dmarc_abort = TRUE;
  }

/* This catches locally originated email and startup errors above. */
if (!dmarc_abort)
  {
  int is_ipv6 = string_is_ip_address(sender_host_address, NULL) == 6;
  if (!(dmarc_pctx = opendmarc_policy_connect_init(sender_host_address, is_ipv6)))
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
      "DMARC failure creating policy context: ip=%s", sender_host_address);
    dmarc_abort = TRUE;
    }
  }
}


static void
dmarc_local_send_forensic_report(u_char ** ruf)
{
/* Earlier ACL does not have *required* control=dmarc_enable_forensic */
if (!f.dmarc_enable_forensic)
  return;

if (   dmarc_policy == DMARC_POLICY_REJECT
    && dmarc_action == DMARC_RESULT_REJECT
   ||  dmarc_policy == DMARC_POLICY_QUARANTINE
    && dmarc_action == DMARC_RESULT_QUARANTINE
   ||  dmarc_policy == DMARC_POLICY_NONE
    && dmarc_action == DMARC_RESULT_REJECT
   ||  dmarc_policy == DMARC_POLICY_NONE
    && dmarc_action == DMARC_RESULT_QUARANTINE
   )
  if (ruf)
    dmarc_send_forensic_report(CUSS ruf);
}



/*API: dmarc_process adds the envelope sender address to the existing
context (if any), retrieves the result, sets up expansion
strings and evaluates the condition outcome.
Called for the first ACL dmarc= condition. */

int
dmarc_process(void)
{
int dmarc_spf_result;			/* stores spf into dmarc conn ctx */
int tmp_ans, c;
uschar * rr;
BOOL has_dmarc_record = TRUE;
u_char ** ruf; /* forensic report addressees, if called for */

dmarc_alignment_spf = dmarc_alignment_dkim = FALSE;

/* ACLs have "control=dmarc_disable_verify" */
if (f.dmarc_disable_verify)
  return OK;

/* Store the header From: sender domain for this part of DMARC.
If there is no from_header string, then it's likely this message
is locally generated and relying on fixups to add it.  Just skip
the entire DMARC system if we can't find a From: header....or if
there was a previous error.  */

if (!dmarc_from_header)
  {
  DEBUG(D_receive) debug_printf_indent("DMARC: no From: header\n");
  dmarc_abort = TRUE;
  }
else if (!dmarc_abort)
  {
  const uschar * end_addr, * s;
  uschar * errormsg;
  int dummy, domain;

  f.parse_allow_group = TRUE;
  end_addr = parse_find_address_end(dmarc_from_header, FALSE);
  s = *end_addr
      ? string_copyn(dmarc_from_header, end_addr - dmarc_from_header)
      : dmarc_from_header;
  if ((dmarc_header_from_sender = parse_extract_address(s, &errormsg,
			      &dummy, &dummy, &domain, FALSE)))
    dmarc_header_from_sender += domain;

  /* The opendmarc library extracts the domain from the email address, but
  only try to store it if it's not empty.  Otherwise, skip out of DMARC. */

  if (!dmarc_header_from_sender || !*dmarc_header_from_sender)
    dmarc_abort = TRUE;
  libdm_status = dmarc_abort
    ? DMARC_PARSE_OKAY
    : opendmarc_policy_store_from_domain(dmarc_pctx, dmarc_header_from_sender);
  if (libdm_status != DMARC_PARSE_OKAY)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
	      "failure to store header From: in DMARC: %s, header was '%s'",
	      opendmarc_policy_status_to_str(libdm_status), dmarc_from_header);
    dmarc_abort = TRUE;
    }
  }

/* Skip DMARC if connection is SMTP Auth. Temporarily, admin should
instead do this in the ACLs.  */

if (!dmarc_abort && !sender_host_authenticated)
  {
  int sr = SPF_RESULT_INVALID, origin;
  uschar * spf_human_readable = NULL, * spf_sender_domain;
  gstring * dkim_history_buffer = NULL;
  typedef const pdkim_signature * (*sigs_fn_t)(void);

  /* Use the envelope sender domain for this part of DMARC */

  spf_sender_domain = expand_string(US"$sender_address_domain");

    {
    typedef int (*fn_t)(uschar **);
    if (dmarc_spf_mod_info)
      sr = ((fn_t *) dmarc_spf_mod_info->functions)[SPF_GET_RESULTS]
							  (&spf_human_readable);
    }

  if (sr == SPF_RESULT_INVALID)
    {
    /* No spf data means null envelope sender so generate a domain name
    from the sender_helo_name  */

    if (!spf_sender_domain || !*spf_sender_domain)
      {
      spf_sender_domain = sender_helo_name;
      log_write(0, LOG_MAIN, "DMARC using synthesized SPF sender domain = %s\n",
			     spf_sender_domain);
      }
    dmarc_spf_result = DMARC_POLICY_SPF_OUTCOME_NONE;
    dmarc_spf_ares_result = ARES_RESULT_UNKNOWN;
    origin = DMARC_POLICY_SPF_ORIGIN_HELO;
    spf_human_readable = US"";
    }
  else
    {
    dmarc_spf_result = sr == SPF_RESULT_NEUTRAL  ? DMARC_POLICY_SPF_OUTCOME_NONE :
		       sr == SPF_RESULT_PASS     ? DMARC_POLICY_SPF_OUTCOME_PASS :
		       sr == SPF_RESULT_FAIL     ? DMARC_POLICY_SPF_OUTCOME_FAIL :
		       sr == SPF_RESULT_SOFTFAIL ? DMARC_POLICY_SPF_OUTCOME_TMPFAIL :
		       DMARC_POLICY_SPF_OUTCOME_NONE;
    dmarc_spf_ares_result = sr == SPF_RESULT_NEUTRAL   ? ARES_RESULT_NEUTRAL :
			    sr == SPF_RESULT_PASS      ? ARES_RESULT_PASS :
			    sr == SPF_RESULT_FAIL      ? ARES_RESULT_FAIL :
			    sr == SPF_RESULT_SOFTFAIL  ? ARES_RESULT_SOFTFAIL :
			    sr == SPF_RESULT_NONE      ? ARES_RESULT_NONE :
			    sr == SPF_RESULT_TEMPERROR ? ARES_RESULT_TEMPERROR :
			    sr == SPF_RESULT_PERMERROR ? ARES_RESULT_PERMERROR :
			    ARES_RESULT_UNKNOWN;
    origin = DMARC_POLICY_SPF_ORIGIN_MAILFROM;
    DEBUG(D_receive) debug_printf_indent("DMARC using SPF sender domain = %s\n",
					spf_sender_domain);
    }
  if (!*spf_sender_domain)
    dmarc_abort = TRUE;
  if (!dmarc_abort)
    {
    libdm_status = opendmarc_policy_store_spf(dmarc_pctx, spf_sender_domain,
				dmarc_spf_result, origin, spf_human_readable);
    if (libdm_status != DMARC_PARSE_OKAY)
      log_write(0, LOG_MAIN|LOG_PANIC, "failure to store spf for DMARC: %s",
			   opendmarc_policy_status_to_str(libdm_status));
    }

  /* Now we cycle through the dkim signature results and put into
  the opendmarc context, further building the DMARC reply. */

  for(const pdkim_signature * sig =
	      (((sigs_fn_t *)dmarc_dkim_mod_info->functions)[DKIM_SIGS_LIST])();
      sig; sig = sig->next)
    {
    int dkim_result, dkim_ares_result, vs, ves;

    vs  = sig->verify_status & ~PDKIM_VERIFY_POLICY;
    ves = sig->verify_ext_status;
    dkim_result = vs == PDKIM_VERIFY_PASS ? DMARC_POLICY_DKIM_OUTCOME_PASS :
		  vs == PDKIM_VERIFY_FAIL ? DMARC_POLICY_DKIM_OUTCOME_FAIL :
		  vs == PDKIM_VERIFY_INVALID ? DMARC_POLICY_DKIM_OUTCOME_TMPFAIL :
		  DMARC_POLICY_DKIM_OUTCOME_NONE;
    libdm_status = opendmarc_policy_store_dkim(dmarc_pctx, US sig->domain,

/* The opendmarc project broke its API in a way we can't detect easily.
The EDITME provides a DMARC_API variable */
#if DMARC_API >= 100400
                                               sig->selector,
#endif
                                               dkim_result, US"");
    DEBUG(D_receive)
      debug_printf_indent("DMARC adding DKIM sender domain = %s\n", sig->domain);
    if (libdm_status != DMARC_PARSE_OKAY)
      log_write(0, LOG_MAIN|LOG_PANIC,
		"failure to store dkim (%s) for DMARC: %s",
		sig->domain, opendmarc_policy_status_to_str(libdm_status));

    dkim_ares_result =
      vs == PDKIM_VERIFY_PASS    ? ARES_RESULT_PASS :
      vs == PDKIM_VERIFY_FAIL    ? ARES_RESULT_FAIL :
      vs == PDKIM_VERIFY_NONE    ? ARES_RESULT_NONE :
      vs == PDKIM_VERIFY_INVALID ?
       ves == PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE ? ARES_RESULT_PERMERROR :
       ves == PDKIM_VERIFY_INVALID_BUFFER_SIZE        ? ARES_RESULT_PERMERROR :
       ves == PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD   ? ARES_RESULT_PERMERROR :
       ves == PDKIM_VERIFY_INVALID_PUBKEY_IMPORT      ? ARES_RESULT_PERMERROR :
       ARES_RESULT_UNKNOWN :
      ARES_RESULT_UNKNOWN;
#if DMARC_API >= 100400
    dkim_history_buffer = string_fmt_append(dkim_history_buffer,
      "dkim %s %s %d\n", sig->domain, sig->selector, dkim_ares_result);
#else
    dkim_history_buffer = string_fmt_append(dkim_history_buffer,
      "dkim %s %d\n", sig->domain, dkim_ares_result);
#endif
    }

  /* Look up DMARC policy record in DNS.  We do this explicitly, rather than
  letting the dmarc library do it with opendmarc_policy_query_dmarc(), so that
  our dns access path is used for debug tracing and for the testsuite
  diversion. */

  libdm_status = (rr = dmarc_dns_lookup(dmarc_header_from_sender))
    ? opendmarc_policy_store_dmarc(dmarc_pctx, rr, dmarc_header_from_sender, NULL)
    : DMARC_DNS_ERROR_NO_RECORD;
  switch (libdm_status)
    {
    case DMARC_DNS_ERROR_NXDOMAIN:
    case DMARC_DNS_ERROR_NO_RECORD:
      DEBUG(D_receive)
	debug_printf_indent("DMARC no record found for %s\n", dmarc_header_from_sender);
      has_dmarc_record = FALSE;
      break;
    case DMARC_PARSE_OKAY:
      DEBUG(D_receive)
	debug_printf_indent("DMARC record found for %s\n", dmarc_header_from_sender);
      break;
    case DMARC_PARSE_ERROR_BAD_VALUE:
      DEBUG(D_receive)
	debug_printf_indent("DMARC record parse error for %s\n", dmarc_header_from_sender);
      has_dmarc_record = FALSE;
      break;
    default:
      /* everything else, skip dmarc */
      DEBUG(D_receive)
	debug_printf_indent("DMARC skipping (%s), unsure what to do with %s",
		      opendmarc_policy_status_to_str(libdm_status),
		      dmarc_from_header);
      has_dmarc_record = FALSE;
      break;
    }

  /* Store the policy string in an expandable variable. */

  libdm_status = opendmarc_policy_fetch_p(dmarc_pctx, &tmp_ans);
  for (c = 0; dmarc_policy_description[c].name; c++)
    if (tmp_ans == dmarc_policy_description[c].value)
      { dmarc_domain_policy = dmarc_policy_description[c].name; break; }

  /* Can't use exim's string manipulation functions so allocate memory
  for libopendmarc using its max hostname length definition. */

  dmarc_used_domain = store_get(DMARC_MAXHOSTNAMELEN, GET_TAINTED);
  libdm_status = opendmarc_policy_fetch_utilized_domain(dmarc_pctx,
    dmarc_used_domain, DMARC_MAXHOSTNAMELEN-1);
  store_release_above(dmarc_used_domain + Ustrlen(dmarc_used_domain)+1);

  if (libdm_status != DMARC_PARSE_OKAY)
    log_write(0, LOG_MAIN|LOG_PANIC,
      "failure to read domainname used for DMARC lookup: %s",
      opendmarc_policy_status_to_str(libdm_status));

  dmarc_policy = libdm_status = opendmarc_get_policy_to_enforce(dmarc_pctx);

  switch(libdm_status)
    {
    case DMARC_POLICY_ABSENT:		/* No DMARC record found */
      dmarc_status = US"norecord";
      dmarc_pass_fail = US"none";
      dmarc_status_text = US"No DMARC record";
      dmarc_action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_FROM_DOMAIN_ABSENT:	/* No From: domain */
      dmarc_status = US"nofrom";
      dmarc_pass_fail = US"temperror";
      dmarc_status_text = US"No From: domain found";
      dmarc_action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_POLICY_NONE:		/* Accept and report */
      dmarc_status = US"none";
      dmarc_pass_fail = US"none";
      dmarc_status_text = US"None, Accept";
      dmarc_action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_POLICY_PASS:		/* Explicit accept */
      dmarc_status = US"accept";
      dmarc_pass_fail = US"pass";
      dmarc_status_text = US"Accept";
      dmarc_action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_POLICY_REJECT:		/* Explicit reject */
      dmarc_status = US"reject";
      dmarc_pass_fail = US"fail";
      dmarc_status_text = US"Reject";
      dmarc_action = DMARC_RESULT_REJECT;
      break;
    case DMARC_POLICY_QUARANTINE:	/* Explicit quarantine */
      dmarc_status = US"quarantine";
      dmarc_pass_fail = US"fail";
      dmarc_status_text = US"Quarantine";
      dmarc_action = DMARC_RESULT_QUARANTINE;
      break;
    default:
      dmarc_status = US"temperror";
      dmarc_pass_fail = US"temperror";
      dmarc_status_text = US"Internal Policy Error";
      dmarc_action = DMARC_RESULT_TEMPFAIL;
      break;
    }

  libdm_status = opendmarc_policy_fetch_alignment(dmarc_pctx,
		    &dmarc_dkim_alignment, &dmarc_spf_alignment);
  if (libdm_status != DMARC_PARSE_OKAY)
    log_write(0, LOG_MAIN|LOG_PANIC, "failure to read DMARC alignment: %s",
			     opendmarc_policy_status_to_str(libdm_status));

  if (has_dmarc_record)
    {
    dmarc_alignment_spf =
      dmarc_spf_alignment == DMARC_POLICY_SPF_ALIGNMENT_PASS;
    dmarc_alignment_dkim =
      dmarc_dkim_alignment == DMARC_POLICY_DKIM_ALIGNMENT_PASS;

    DEBUG(D_receive)
      debug_printf_indent("DMARC results: spf_domain=%s dmarc_domain=%s "
			   "spf_align=%s dkim_align=%s enforcement='%s'",
			   spf_sender_domain, dmarc_used_domain,
			   dmarc_alignment_spf  ? "yes" : "no",
			   dmarc_alignment_dkim ? "yes" : "no",
			   dmarc_status_text);

    dmarc_rua = USS opendmarc_policy_fetch_rua(dmarc_pctx, NULL, 0, 1);
    opendmarc_policy_fetch_pct(dmarc_pctx, &dmarc_pct);
    opendmarc_policy_fetch_adkim(dmarc_pctx, &dmarc_adkim);
    opendmarc_policy_fetch_aspf(dmarc_pctx, &dmarc_aspf);
    opendmarc_policy_fetch_p(dmarc_pctx, &dmarc_dom_policy);
    opendmarc_policy_fetch_sp(dmarc_pctx, &dmarc_subdom_policy);
    dmarc_write_history_file(dkim_history_buffer);

    /* Now get the forensic reporting addresses, if any */
    ruf = opendmarc_policy_fetch_ruf(dmarc_pctx, NULL, 0, 1);
    dmarc_local_send_forensic_report(ruf);
    }
  }

/* shut down libopendmarc */
if (dmarc_pctx)
  (void) opendmarc_policy_connect_shutdown(dmarc_pctx);
if (!f.dmarc_disable_verify)
  (void) opendmarc_policy_library_shutdown(&dmarc_ctx);

return OK;
}

static const uschar *
dmarc_exim_expand_defaults(void)
{
return f.dmarc_disable_verify ?  US"off" : US"none";
}

/*API*/
const uschar *
dmarc_exim_expand_query(void)
{
if (f.dmarc_disable_verify || !dmarc_pctx)
  return dmarc_exim_expand_defaults();

return dmarc_status;
}


# endif /* SUPPORT_SPF */
#endif /* SUPPORT_DMARC */
/* vi: aw ai sw=2
 */
