/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/
/* DMARC support.
   Copyright (c) The Exim Maintainers 2019 - 2023
   Copyright (c) Todd Lyons <tlyons@exim.org> 2012 - 2014
   License: GPL */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Portions Copyright (c) 2012, 2013, The Trusted Domain Project;
   All rights reserved, licensed for use per LICENSE.opendmarc. */

/* Code for calling dmarc checks via libopendmarc. Called from acl.c. */

#include "exim.h"
#ifdef SUPPORT_DMARC
# if !defined SUPPORT_SPF
#  error SPF must also be enabled for DMARC
# elif defined DISABLE_DKIM
#  error DKIM must also be enabled for DMARC
# else

#  include "functions.h"
#  include "dmarc.h"
#  include "pdkim/pdkim.h"

OPENDMARC_LIB_T     dmarc_ctx;
DMARC_POLICY_T     *dmarc_pctx = NULL;
OPENDMARC_STATUS_T  libdm_status, action, dmarc_policy;
OPENDMARC_STATUS_T  da, sa, action;
BOOL dmarc_abort  = FALSE;
uschar *dmarc_pass_fail = US"skipped";
header_line *from_header   = NULL;
extern SPF_response_t   *spf_response;
int dmarc_spf_ares_result  = 0;
uschar *spf_sender_domain  = NULL;
uschar *spf_human_readable = NULL;
u_char *header_from_sender = NULL;
int history_file_status    = DMARC_HIST_OK;

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


gstring *
dmarc_version_report(gstring * g)
{
return string_fmt_append(g, "Library version: dmarc: Compile: %d.%d.%d.%d\n",
    (OPENDMARC_LIB_VERSION & 0xff000000) >> 24, (OPENDMARC_LIB_VERSION & 0x00ff0000) >> 16,
    (OPENDMARC_LIB_VERSION & 0x0000ff00) >> 8, OPENDMARC_LIB_VERSION & 0x000000ff);
}


/* Accept an error_block struct, initialize if empty, parse to the
end, and append the two strings passed to it.  Used for adding
variable amounts of value:pair data to the forensic emails. */

static error_block *
add_to_eblock(error_block *eblock, uschar *t1, uschar *t2)
{
error_block *eb = store_malloc(sizeof(error_block));
if (!eblock)
  eblock = eb;
else
  {
  /* Find the end of the eblock struct and point it at eb */
  error_block *tmp = eblock;
  while(tmp->next)
    tmp = tmp->next;
  tmp->next = eb;
  }
eb->text1 = t1;
eb->text2 = t2;
eb->next  = NULL;
return eblock;
}

/* dmarc_init sets up a context that can be re-used for several
messages on the same SMTP connection (that come from the
same host with the same HELO string) */

int
dmarc_init(void)
{
int *netmask   = NULL;   /* Ignored */
int is_ipv6    = 0;

/* Set some sane defaults.  Also clears previous results when
multiple messages in one connection. */

dmarc_pctx         = NULL;
dmarc_status       = US"none";
dmarc_abort        = FALSE;
dmarc_pass_fail    = US"skipped";
dmarc_used_domain  = US"";
f.dmarc_has_been_checked = FALSE;
header_from_sender = NULL;
spf_sender_domain  = NULL;
spf_human_readable = NULL;

/* ACLs have "control=dmarc_disable_verify" */
if (f.dmarc_disable_verify == TRUE)
  return OK;

(void) memset(&dmarc_ctx, '\0', sizeof dmarc_ctx);
dmarc_ctx.nscount = 0;
libdm_status = opendmarc_policy_library_init(&dmarc_ctx);
if (libdm_status != DMARC_PARSE_OKAY)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to init library: %s",
		       opendmarc_policy_status_to_str(libdm_status));
  dmarc_abort = TRUE;
  }
if (!dmarc_tld_file || !*dmarc_tld_file)
  {
  DEBUG(D_receive) debug_printf_indent("DMARC: no dmarc_tld_file\n");
  dmarc_abort = TRUE;
  }
else if (opendmarc_tld_read_file(CS dmarc_tld_file, NULL, NULL, NULL))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to load tld list '%s': %s",
		       dmarc_tld_file, strerror(errno));
  dmarc_abort = TRUE;
  }
if (!sender_host_address)
  {
  DEBUG(D_receive) debug_printf_indent("DMARC: no sender_host_address\n");
  dmarc_abort = TRUE;
  }
/* This catches locally originated email and startup errors above. */
if (!dmarc_abort)
  {
  is_ipv6 = string_is_ip_address(sender_host_address, netmask) == 6;
  if (!(dmarc_pctx = opendmarc_policy_connect_init(sender_host_address, is_ipv6)))
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
      "DMARC failure creating policy context: ip=%s", sender_host_address);
    dmarc_abort = TRUE;
    }
  }

return OK;
}


/* dmarc_store_data stores the header data so that subsequent dmarc_process can
access the data.
Called after the entire message has been received, with the From: header. */

int
dmarc_store_data(header_line * hdr)
{
/* No debug output because would change every test debug output */
if (!f.dmarc_disable_verify)
  from_header = hdr;
return OK;
}


static void
dmarc_send_forensic_report(u_char ** ruf)
{
uschar *recipient, *save_sender;
BOOL  send_status = FALSE;
error_block *eblock = NULL;
FILE *message_file = NULL;

/* Earlier ACL does not have *required* control=dmarc_enable_forensic */
if (!f.dmarc_enable_forensic)
  return;

if (  dmarc_policy == DMARC_POLICY_REJECT     && action == DMARC_RESULT_REJECT
   || dmarc_policy == DMARC_POLICY_QUARANTINE && action == DMARC_RESULT_QUARANTINE
   || dmarc_policy == DMARC_POLICY_NONE       && action == DMARC_RESULT_REJECT
   || dmarc_policy == DMARC_POLICY_NONE       && action == DMARC_RESULT_QUARANTINE
   )
  if (ruf)
    {
    eblock = add_to_eblock(eblock, US"Sender Domain", dmarc_used_domain);
    eblock = add_to_eblock(eblock, US"Sender IP Address", sender_host_address);
    eblock = add_to_eblock(eblock, US"Received Date", tod_stamp(tod_full));
    eblock = add_to_eblock(eblock, US"SPF Alignment",
		     sa == DMARC_POLICY_SPF_ALIGNMENT_PASS ? US"yes" : US"no");
    eblock = add_to_eblock(eblock, US"DKIM Alignment",
		     da == DMARC_POLICY_DKIM_ALIGNMENT_PASS ? US"yes" : US"no");
    eblock = add_to_eblock(eblock, US"DMARC Results", dmarc_status_text);

    for (int c = 0; ruf[c]; c++)
      {
      recipient = string_copylc(ruf[c]);
      if (Ustrncmp(recipient, "mailto:",7))
	continue;
      /* Move to first character past the colon */
      recipient += 7;
      DEBUG(D_receive)
	debug_printf_indent("DMARC forensic report to %s%s\n", recipient,
	     (host_checking || f.running_in_test_harness) ? " (not really)" : "");
      if (host_checking || f.running_in_test_harness)
	continue;

      if (!moan_send_message(recipient, ERRMESS_DMARC_FORENSIC, eblock,
			    header_list, message_file, NULL))
	log_write(0, LOG_MAIN|LOG_PANIC,
	  "failure to send DMARC forensic report to %s", recipient);
      }
    }
}


/* Look up a DNS dmarc record for the given domain.  Return it or NULL */

static uschar *
dmarc_dns_lookup(uschar * dom)
{
dns_answer * dnsa = store_get_dns_answer();
dns_scan dnss;
int rc = dns_lookup(dnsa, string_sprintf("_dmarc.%s", dom), T_TXT, NULL);

if (rc == DNS_SUCCEED)
  for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS); rr;
       rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
    if (rr->type == T_TXT && rr->size > 3)
      {
      uschar *record = string_copyn_taint(US rr->data, rr->size, GET_TAINTED);
      store_free_dns_answer(dnsa);
      return record;
      }
store_free_dns_answer(dnsa);
return NULL;
}


static int
dmarc_write_history_file(const gstring * dkim_history_buffer)
{
int history_file_fd = 0;
ssize_t written_len;
int tmp_ans;
u_char ** rua; /* aggregate report addressees */
gstring * g;

if (!dmarc_history_file)
  {
  DEBUG(D_receive) debug_printf_indent("DMARC history file not set\n");
  return DMARC_HIST_DISABLED;
  }
if (!host_checking)
  {
  uschar * s = string_copy(dmarc_history_file);		/* need a writeable copy */
  if ((history_file_fd = log_open_as_exim(s)) < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
	      "failure to create DMARC history file: %s: %s",
	      s, strerror(errno));
    return DMARC_HIST_FILE_ERR;
    }
  }

/* Generate the contents of the history file entry */

g = string_fmt_append(NULL,
  "job %s\nreporter %s\nreceived %ld\nipaddr %s\nfrom %s\nmfrom %s\n",
  message_id, primary_hostname, time(NULL), sender_host_address,
  header_from_sender, expand_string(US"$sender_address_domain"));

if (spf_response)
  g = string_fmt_append(g, "spf %d\n", dmarc_spf_ares_result);

if (dkim_history_buffer)
  g = string_fmt_append(g, "%Y", dkim_history_buffer);

g = string_fmt_append(g, "pdomain %s\npolicy %d\n",
  dmarc_used_domain, dmarc_policy);

if ((rua = opendmarc_policy_fetch_rua(dmarc_pctx, NULL, 0, 1)))
  for (tmp_ans = 0; rua[tmp_ans]; tmp_ans++)
    g = string_fmt_append(g, "rua %s\n", rua[tmp_ans]);
else
  g = string_catn(g, US"rua -\n", 6);

opendmarc_policy_fetch_pct(dmarc_pctx, &tmp_ans);
g = string_fmt_append(g, "pct %d\n", tmp_ans);

opendmarc_policy_fetch_adkim(dmarc_pctx, &tmp_ans);
g = string_fmt_append(g, "adkim %d\n", tmp_ans);

opendmarc_policy_fetch_aspf(dmarc_pctx, &tmp_ans);
g = string_fmt_append(g, "aspf %d\n", tmp_ans);

opendmarc_policy_fetch_p(dmarc_pctx, &tmp_ans);
g = string_fmt_append(g, "p %d\n", tmp_ans);

opendmarc_policy_fetch_sp(dmarc_pctx, &tmp_ans);
g = string_fmt_append(g, "sp %d\n", tmp_ans);

g = string_fmt_append(g, "align_dkim %d\nalign_spf %d\naction %d\n",
  da, sa, action);

#if DMARC_API >= 100400
# ifdef EXPERIMENTAL_ARC
g = arc_dmarc_hist_append(g);
# else
g = string_fmt_append(g, "arc %d\narc_policy $d json:[]\n",
		      ARES_RESULT_UNKNOWN, DMARC_ARC_POLICY_RESULT_UNUSED);
# endif
#endif

/* Write the contents to the history file */
DEBUG(D_receive)
  {
  debug_printf_indent("DMARC logging history data for opendmarc reporting%s\n",
	     host_checking ? " (not really)" : "");
  debug_printf_indent("DMARC history data for debugging:\n");
  expand_level++;
    debug_printf_indent("%Y", g);
  expand_level--;
  }

if (!host_checking)
  {
  written_len = write_to_fd_buf(history_file_fd,
				g->s,
				gstring_length(g));
  if (written_len == 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "failure to write to DMARC history file: %s",
			   dmarc_history_file);
    return DMARC_HIST_WRITE_ERR;
    }
  (void)close(history_file_fd);
  }
return DMARC_HIST_OK;
}


/* dmarc_process adds the envelope sender address to the existing
context (if any), retrieves the result, sets up expansion
strings and evaluates the condition outcome.
Called for the first ACL dmarc= condition. */

int
dmarc_process(void)
{
int sr, origin;             /* used in SPF section */
int dmarc_spf_result  = 0;  /* stores spf into dmarc conn ctx */
int tmp_ans, c;
pdkim_signature * sig = dkim_signatures;
uschar * rr;
BOOL has_dmarc_record = TRUE;
u_char ** ruf; /* forensic report addressees, if called for */

/* ACLs have "control=dmarc_disable_verify" */
if (f.dmarc_disable_verify)
  return OK;

/* Store the header From: sender domain for this part of DMARC.
If there is no from_header struct, then it's likely this message
is locally generated and relying on fixups to add it.  Just skip
the entire DMARC system if we can't find a From: header....or if
there was a previous error.  */

if (!from_header)
  {
  DEBUG(D_receive) debug_printf_indent("DMARC: no From: header\n");
  dmarc_abort = TRUE;
  }
else if (!dmarc_abort)
  {
  uschar * errormsg;
  int dummy, domain;
  uschar * p;
  uschar saveend;

  f.parse_allow_group = TRUE;
  p = parse_find_address_end(from_header->text, FALSE);
  saveend = *p; *p = '\0';
  if ((header_from_sender = parse_extract_address(from_header->text, &errormsg,
			      &dummy, &dummy, &domain, FALSE)))
    header_from_sender += domain;
  *p = saveend;

  /* The opendmarc library extracts the domain from the email address, but
  only try to store it if it's not empty.  Otherwise, skip out of DMARC. */

  if (!header_from_sender || (strcmp( CCS header_from_sender, "") == 0))
    dmarc_abort = TRUE;
  libdm_status = dmarc_abort
    ? DMARC_PARSE_OKAY
    : opendmarc_policy_store_from_domain(dmarc_pctx, header_from_sender);
  if (libdm_status != DMARC_PARSE_OKAY)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
	      "failure to store header From: in DMARC: %s, header was '%s'",
	      opendmarc_policy_status_to_str(libdm_status), from_header->text);
    dmarc_abort = TRUE;
    }
  }

/* Skip DMARC if connection is SMTP Auth. Temporarily, admin should
instead do this in the ACLs.  */

if (!dmarc_abort && !sender_host_authenticated)
  {
  uschar * dmarc_domain;
  gstring * dkim_history_buffer = NULL;

  /* Use the envelope sender domain for this part of DMARC */

  spf_sender_domain = expand_string(US"$sender_address_domain");
  if (!spf_response)
    {
    /* No spf data means null envelope sender so generate a domain name
    from the sender_helo_name  */

    if (!spf_sender_domain)
      {
      spf_sender_domain = sender_helo_name;
      log_write(0, LOG_MAIN, "DMARC using synthesized SPF sender domain = %s\n",
			     spf_sender_domain);
      DEBUG(D_receive)
	debug_printf_indent("DMARC using synthesized SPF sender domain = %s\n",
	  spf_sender_domain);
      }
    dmarc_spf_result = DMARC_POLICY_SPF_OUTCOME_NONE;
    dmarc_spf_ares_result = ARES_RESULT_UNKNOWN;
    origin = DMARC_POLICY_SPF_ORIGIN_HELO;
    spf_human_readable = US"";
    }
  else
    {
    sr = spf_response->result;
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
    spf_human_readable = US spf_response->header_comment;
    DEBUG(D_receive)
      debug_printf_indent("DMARC using SPF sender domain = %s\n", spf_sender_domain);
    }
  if (strcmp( CCS spf_sender_domain, "") == 0)
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

  for(pdkim_signature * sig = dkim_signatures; sig; sig = sig->next)
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

  libdm_status = (rr = dmarc_dns_lookup(header_from_sender))
    ? opendmarc_policy_store_dmarc(dmarc_pctx, rr, header_from_sender, NULL)
    : DMARC_DNS_ERROR_NO_RECORD;
  switch (libdm_status)
    {
    case DMARC_DNS_ERROR_NXDOMAIN:
    case DMARC_DNS_ERROR_NO_RECORD:
      DEBUG(D_receive)
	debug_printf_indent("DMARC no record found for %s\n", header_from_sender);
      has_dmarc_record = FALSE;
      break;
    case DMARC_PARSE_OKAY:
      DEBUG(D_receive)
	debug_printf_indent("DMARC record found for %s\n", header_from_sender);
      break;
    case DMARC_PARSE_ERROR_BAD_VALUE:
      DEBUG(D_receive)
	debug_printf_indent("DMARC record parse error for %s\n", header_from_sender);
      has_dmarc_record = FALSE;
      break;
    default:
      /* everything else, skip dmarc */
      DEBUG(D_receive)
	debug_printf_indent("DMARC skipping (%s), unsure what to do with %s",
		      opendmarc_policy_status_to_str(libdm_status),
		      from_header->text);
      has_dmarc_record = FALSE;
      break;
    }

  /* Store the policy string in an expandable variable. */

  libdm_status = opendmarc_policy_fetch_p(dmarc_pctx, &tmp_ans);
  for (c = 0; dmarc_policy_description[c].name; c++)
    if (tmp_ans == dmarc_policy_description[c].value)
      {
      dmarc_domain_policy = string_sprintf("%s",dmarc_policy_description[c].name);
      break;
      }

  /* Can't use exim's string manipulation functions so allocate memory
  for libopendmarc using its max hostname length definition. */

  dmarc_domain = store_get(DMARC_MAXHOSTNAMELEN, GET_TAINTED);
  libdm_status = opendmarc_policy_fetch_utilized_domain(dmarc_pctx,
    dmarc_domain, DMARC_MAXHOSTNAMELEN-1);
  store_release_above(dmarc_domain + Ustrlen(dmarc_domain)+1);
  dmarc_used_domain = dmarc_domain;

  if (libdm_status != DMARC_PARSE_OKAY)
    log_write(0, LOG_MAIN|LOG_PANIC,
      "failure to read domainname used for DMARC lookup: %s",
      opendmarc_policy_status_to_str(libdm_status));

  dmarc_policy = libdm_status = opendmarc_get_policy_to_enforce(dmarc_pctx);
  switch(libdm_status)
    {
    case DMARC_POLICY_ABSENT:     /* No DMARC record found */
      dmarc_status = US"norecord";
      dmarc_pass_fail = US"none";
      dmarc_status_text = US"No DMARC record";
      action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_FROM_DOMAIN_ABSENT:    /* No From: domain */
      dmarc_status = US"nofrom";
      dmarc_pass_fail = US"temperror";
      dmarc_status_text = US"No From: domain found";
      action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_POLICY_NONE:       /* Accept and report */
      dmarc_status = US"none";
      dmarc_pass_fail = US"none";
      dmarc_status_text = US"None, Accept";
      action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_POLICY_PASS:       /* Explicit accept */
      dmarc_status = US"accept";
      dmarc_pass_fail = US"pass";
      dmarc_status_text = US"Accept";
      action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_POLICY_REJECT:       /* Explicit reject */
      dmarc_status = US"reject";
      dmarc_pass_fail = US"fail";
      dmarc_status_text = US"Reject";
      action = DMARC_RESULT_REJECT;
      break;
    case DMARC_POLICY_QUARANTINE:       /* Explicit quarantine */
      dmarc_status = US"quarantine";
      dmarc_pass_fail = US"fail";
      dmarc_status_text = US"Quarantine";
      action = DMARC_RESULT_QUARANTINE;
      break;
    default:
      dmarc_status = US"temperror";
      dmarc_pass_fail = US"temperror";
      dmarc_status_text = US"Internal Policy Error";
      action = DMARC_RESULT_TEMPFAIL;
      break;
    }

  libdm_status = opendmarc_policy_fetch_alignment(dmarc_pctx, &da, &sa);
  if (libdm_status != DMARC_PARSE_OKAY)
    log_write(0, LOG_MAIN|LOG_PANIC, "failure to read DMARC alignment: %s",
			     opendmarc_policy_status_to_str(libdm_status));

  if (has_dmarc_record)
    {
    log_write(0, LOG_MAIN, "DMARC results: spf_domain=%s dmarc_domain=%s "
			   "spf_align=%s dkim_align=%s enforcement='%s'",
			   spf_sender_domain, dmarc_used_domain,
			   sa==DMARC_POLICY_SPF_ALIGNMENT_PASS  ?"yes":"no",
			   da==DMARC_POLICY_DKIM_ALIGNMENT_PASS ?"yes":"no",
			   dmarc_status_text);
    history_file_status = dmarc_write_history_file(dkim_history_buffer);
    /* Now get the forensic reporting addresses, if any */
    ruf = opendmarc_policy_fetch_ruf(dmarc_pctx, NULL, 0, 1);
    dmarc_send_forensic_report(ruf);
    }
  }

/* shut down libopendmarc */
if (dmarc_pctx)
  (void) opendmarc_policy_connect_shutdown(dmarc_pctx);
if (!f.dmarc_disable_verify)
  (void) opendmarc_policy_library_shutdown(&dmarc_ctx);

return OK;
}

uschar *
dmarc_exim_expand_query(int what)
{
if (f.dmarc_disable_verify || !dmarc_pctx)
  return dmarc_exim_expand_defaults(what);

if (what == DMARC_VERIFY_STATUS)
  return dmarc_status;
return US"";
}

uschar *
dmarc_exim_expand_defaults(int what)
{
if (what == DMARC_VERIFY_STATUS)
  return f.dmarc_disable_verify ?  US"off" : US"none";
return US"";
}


gstring *
authres_dmarc(gstring * g)
{
if (f.dmarc_has_been_checked)
  {
  int start = 0;		/* Compiler quietening */
  DEBUG(D_acl) start = gstring_length(g);
  g = string_append(g, 2, US";\n\tdmarc=", dmarc_pass_fail);
  if (header_from_sender)
    g = string_append(g, 2, US" header.from=", header_from_sender);
  DEBUG(D_acl) debug_printf("DMARC:\tauthres '%.*s'\n",
		  gstring_length(g) - start - 3, g->s + start + 3);
  }
else
  DEBUG(D_acl) debug_printf("DMARC:\tno authres\n");
return g;
}

# endif /* SUPPORT_SPF */
#endif /* SUPPORT_DMARC */
/* vi: aw ai sw=2
 */
