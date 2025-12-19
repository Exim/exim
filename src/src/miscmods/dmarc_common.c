/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* DMARC support.
   Copyright (c) The Exim Maintainers 2025
   License: GPL */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"

#ifdef EXIM_HAVE_DMARC

extern BOOL		dmarc_local_init(void);
extern void		dmarc_local_msg_init(void);
extern gstring *	dmarc_version_report(gstring *);
extern int		dmarc_process(void);
extern int		dmarc_result_inlist(const uschar * const *);


/* Other modules needed for services */
const misc_module_info * dmarc_spf_mod_info;
const misc_module_info * dmarc_dkim_mod_info;
const misc_module_info * dmarc_arc_mod_info;

/* Working data */
BOOL		dmarc_abort;
uschar *	dmarc_pass_fail;	/* for authres */
uschar *	dmarc_header_from_sender;

/* results */
int		dmarc_spf_ares_result;
uschar **	dmarc_rua;		/* aggregate report addressees */
int		dmarc_pct;		/* percentage */
int		dmarc_adkim;		/* dkim policy */
int		dmarc_aspf;		/* spf policy */
int		dmarc_policy;		/* policy to enforce */
int		dmarc_dom_policy;	/* (the p tag, as numeric) */
int		dmarc_subdom_policy;	/* (the sp tag, as numeric) */
int		dmarc_spf_alignment;
int		dmarc_dkim_alignment;
int		dmarc_action;


/* $variables */
BOOL	 dmarc_alignment_dkim	 = FALSE; /* Subtest result */
BOOL	 dmarc_alignment_spf	 = FALSE; /* Subtest result */
const uschar * dmarc_domain_policy = NULL; /* Declared policy of used domain */
const uschar * dmarc_status;		/* One word value */
const uschar * dmarc_status_text   = NULL; /* Human readable value */
uschar * dmarc_used_domain;		/* Domain libopendmarc chose for DMARC policy lookup */

/* options */
uschar * dmarc_forensic_sender   = NULL; /* Set sender address for forensic reports */
uschar * dmarc_history_file      = NULL; /* File to store dmarc results */
uschar * dmarc_tld_file          = NULL; /* Mozilla TLDs text file */


/*API:
One-time initialisation for dmarc.  Ensure the spf module is available.
*/

static BOOL
dmarc_init(void * dummy)
{
uschar * errstr;
if (!(dmarc_spf_mod_info = misc_mod_find(US"spf", &errstr)))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "dmarc: %s", errstr);
  return FALSE;
  }

if (!(dmarc_dkim_mod_info = misc_mod_find(US"dkim", &errstr)))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "dmarc: %s", errstr);
  return FALSE;
  }

dmarc_arc_mod_info = misc_mod_findonly(US"arc");
return dmarc_local_init();
}



/*API: dmarc_msg_init could set up a context that can be re-used for several
messages on the same SMTP connection
(that come from the same host with the same HELO string).
However, we seem to only use it for one; we destroy some sort of context
at the tail end of dmarc_process(). */

static int
dmarc_msg_init(void)
{
/* Set some sane defaults.  Also clears previous results when
multiple messages in one connection. */

f.dmarc_has_been_checked = FALSE;
dmarc_header_from_sender = NULL;
dmarc_spf_ares_result  = ARES_RESULT_UNDEFINED;
dmarc_status       = US"none";
dmarc_abort        = FALSE;
dmarc_pass_fail    = US"skipped";
dmarc_used_domain  = US"";

/* ACLs have "control=dmarc_disable_verify" */
if (f.dmarc_disable_verify)
  return OK;

GET_OPTION("dmarc_tld_file");
if (  !dmarc_tld_file
   || !(dmarc_tld_file = expand_string(dmarc_tld_file))
   || !*dmarc_tld_file)
  {
  DEBUG(D_receive) debug_printf_indent("DMARC: no dmarc_tld_file\n");
  dmarc_abort = TRUE;
  }
else if (!sender_host_address)
  {
  DEBUG(D_receive) debug_printf_indent("DMARC: no sender_host_address\n");
  dmarc_abort = TRUE;
  }
else
  dmarc_local_msg_init();

return OK;
}


/*API*/

static void
dmarc_smtp_reset(void)
{
f.dmarc_has_been_checked = f.dmarc_disable_verify =
  f.dmarc_enable_forensic = FALSE;
dmarc_domain_policy = dmarc_status = dmarc_status_text =
  dmarc_used_domain = NULL;
}


/* Accept an error_block struct, initialize if empty, parse to the
end, and append the two strings passed to it.  Used for adding
variable amounts of value:pair data to the forensic emails. */

static error_block *
add_to_eblock(error_block * eblock, const uschar * t1, const uschar * t2)
{
error_block * eb = store_malloc(sizeof(error_block));
if (!eblock)
  eblock = eb;
else
  {
  /* Find the end of the eblock struct and point it at eb */
  error_block * tmp = eblock;
  while(tmp->next)
    tmp = tmp->next;
  tmp->next = eb;
  }
eb->text1 = t1;
eb->text2 = t2;
eb->next  = NULL;
return eblock;
}

void
dmarc_send_forensic_report(const uschar ** ruf)
{
error_block * eblock;

/* Earlier ACL does not have *required* control=dmarc_enable_forensic */
if (!f.dmarc_enable_forensic || !ruf)
  return;

eblock = add_to_eblock(NULL,
	  string_sprintf("Subject: DMARC Forensic Report for %s from IP %s\n\n",
			dmarc_used_domain, sender_host_address), NULL);
eblock = add_to_eblock(eblock,
	  US"A message claiming to be from you has failed the published DMARC\n"
	  "policy for your domain.\n\n", NULL);

eblock = add_to_eblock(eblock, US"Sender Domain", dmarc_header_from_sender);
eblock = add_to_eblock(eblock, US"Sender IP Address", sender_host_address);
eblock = add_to_eblock(eblock, US"Received Date", tod_stamp(tod_full));
eblock = add_to_eblock(eblock, US"SPF Alignment",
			       dmarc_alignment_spf ? US"yes" : US"no");
eblock = add_to_eblock(eblock, US"DKIM Alignment",
			       dmarc_alignment_dkim ? US"yes" : US"no");
eblock = add_to_eblock(eblock, US"DMARC Results", dmarc_status_text);

for (int c = 0; ruf[c]; c++)
  {
  uschar * recipient = string_copylc(ruf[c]);
  if (Ustrncmp(recipient, "mailto:",7))
    continue;
  /* Move to first character past the colon */
  recipient += 7;
  DEBUG(D_receive)
    debug_printf_indent("DMARC forensic report to %s%s\n", recipient,
	 host_checking || f.running_in_test_harness ? " (not really)" : "");
  if (host_checking || f.running_in_test_harness)
    continue;

  if (!moan_send_message(recipient, ERRMESS_DMARC_FORENSIC, eblock,
			header_list, NULL, NULL))
    log_write(0, LOG_MAIN|LOG_PANIC,
      "failure to send DMARC forensic report to %s", recipient);
  }
}


/* Look up a DNS dmarc record for the given domain.  Return it or NULL */

const uschar *
dmarc_dns_lookup(const uschar * dom)
{
dns_answer * dnsa = store_get_dns_answer();
dns_scan dnss = {0};
const uschar * res = NULL;

expand_level++;

/* RFC 7489 6.6.1 :- policy record is at a "_dmarc" sub of the domain */

if (dns_lookup(dnsa, string_sprintf("_dmarc.%s", dom), T_TXT, NULL)
    == DNS_SUCCEED)
  {
/*XXX we lose track of temporary DNS failures */

  for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS); rr;
       rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
    {
    const uschar * rdata = rr->data;
    int len = rdata[0];

    if (len > 511) len = 127;
    rdata++;

/* RFC 7489 6.6.1 :- policy record is a TXT record */
/* RFC 7489 6.6.3 step 2: ignore records not starting "v=DMARC1;"
   (also noted in 6.3 for the v tag) */

    if (  rr->type == T_TXT && len > 9
       && Ustrncmp(rdata, "v=DMARC1;", 9) == 0)
      if (!res)
	res = string_copyn_taint(rdata, len, GET_TAINTED);	/*XXX*/
      else
/* RFC 7489 6.6.3 step 5: multiple records are treated as no record */
	{
	DEBUG(D_receive) debug_printf_indent("DMARC: multiple rr\n");
	res = NULL;
	break;
	}
    }
  }
else
  DEBUG(D_receive) debug_printf_indent("DMARC: no ret\n");

expand_level--;
store_free_dns_answer(dnsa);
DEBUG(D_receive) debug_printf_indent("DMARC: rr %q\n", res);
return res;
}



const uschar *
dmarc_lookup_regdom(const uschar * dom)
{
int expand_setup = -1, partial, affixlen, starflags;
const uschar * affix, * opts, * res;
const lookup_info * li;
void * handle;
static const uschar * cached_key = NULL, * cached_res = NULL;

DEBUG(D_receive) debug_printf_indent("DMARC: lookup regdom for %q\n", dom);

if (cached_key && Ustrcmp(dom, cached_key) == 0)
  {
  res = cached_res;
  DEBUG(D_receive) debug_printf_indent(" DMARC: cached value %q\n", res);
  return res;
  }

expand_level++;
res = NULL;
if (!(li = search_findtype_partial(US"regdom", &partial, &affix, &affixlen,
				  &starflags, &opts)))
  {
  DEBUG(D_receive) debug_printf_indent("DMARC: missing regdom lookup\n");
  goto out;
  }

if (!(handle = search_open(dmarc_tld_file, li, 0, NULL, NULL)))
  goto out;

/*XXX should we handle a defer return?  cf. f.search_find_defer */

res = search_find(handle, dmarc_tld_file, dom, partial, affix,
		  affixlen, starflags, &expand_setup, opts);

out:
  cached_key = dom; cached_res = res;
  expand_level--;
  return res;
}

const uschar *
dmarc_get_dns_policy_record(const uschar ** used_dom_p)
{
const uschar * s;

DEBUG(D_receive) debug_printf_indent("DMARC: lookup policy record for %s\n",
				      dmarc_header_from_sender);

/* RFC 7489 6.6.3 step 1: DNS domain matching the 5322.From */

if ((s= dmarc_dns_lookup(*used_dom_p = dmarc_header_from_sender)))
  return s;

/* RFC 7489 6.6.3 step 3: if no record, use the Organizational Domain */

if (!(s = dmarc_lookup_regdom(dmarc_header_from_sender)))
  return NULL;

/* RFC 7489 6.6.3 step 3: if the Organizational Domain differs */

if (Ustrcmp(s, dmarc_header_from_sender) == 0)
  return NULL;

return dmarc_dns_lookup(*used_dom_p = s);
}


void
dmarc_write_history_file(const gstring * dkim_history_buffer)
{
int history_file_fd = -1;
uschar * s;
gstring * g;

GET_OPTION("dmarc_history_file");
if (!(s = dmarc_history_file) || !(s = expand_string(s)) || !*s)
  {
  DEBUG(D_receive) debug_printf_indent("DMARC history file not set\n");
  return;
  }
if (!host_checking)	/* -bh mode: nothing written except debug */
  if ((history_file_fd = log_open_as_exim(s)) < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
	      "failure to create DMARC history file: %s: %s",
	      s, strerror(errno));
    return;
    }

/* Generate the contents of the history file entry */

g = string_fmt_append(NULL,
  "job %s\n"
  "reporter %s\n"
  "received %ld\n"
  "ipaddr %s\n"
  "from %s\n"
  "mfrom %s\n",
  message_id, primary_hostname, time(NULL), sender_host_address,
  dmarc_header_from_sender, expand_string(US"$sender_address_domain"));

if (dmarc_spf_ares_result != ARES_RESULT_UNDEFINED)
  g = string_fmt_append(g, "spf %d\n", dmarc_spf_ares_result);

if (dkim_history_buffer)
  g = string_fmt_append(g, "%Y", dkim_history_buffer);

g = string_fmt_append(g, "pdomain %s\n"
			  "policy %d\n",
  dmarc_used_domain, dmarc_policy);

if (dmarc_rua)
  for (uschar ** ss = dmarc_rua; *ss; ss++)
    g = string_fmt_append(g, "rua %s\n", *ss);
else
  g = string_catn(g, US"rua -\n", 6);

/* policy tag values */
g = string_fmt_append(g, "pct %d\n"
			  "adkim %d\n"
			  "aspf %d\n"
			  "p %d\n"
			  "sp %d\n",
  dmarc_pct, dmarc_adkim, dmarc_aspf, dmarc_dom_policy, dmarc_subdom_policy);

g = string_fmt_append(g, "align_dkim %d\n"
			  "align_spf %d\n"
			  "action %d\n",
  dmarc_dkim_alignment, dmarc_spf_alignment, dmarc_action);

#ifdef DMARC_SUPPORTS_ARC
  {
# ifdef EXPERIMENTAL_ARC
  const uschar * s;
  gstring * g2 = NULL;
  typedef const uschar * (*fn_t)(gstring **);

  if (!dmarc_arc_mod_info)
    dmarc_arc_mod_info = misc_mod_findonly(US"arc");

  if (  dmarc_arc_mod_info
     && (s = (((fn_t *) dmarc_arc_mod_info->functions)[ARC_ARCSET_INFO]) (&g2)))
    {
    int i = Ustrcmp(s, "pass") == 0 ? ARES_RESULT_PASS
	    : Ustrcmp(s, "fail") == 0 ? ARES_RESULT_FAIL
	    : ARES_RESULT_UNKNOWN;

    g = string_fmt_append(g, "arc %d\n"
			     "arc_policy %d json[%#Y ]\n",
			  i,
			  i == ARES_RESULT_PASS ? DMARC_ARC_POLICY_RESULT_PASS
			  : i == ARES_RESULT_FAIL ? DMARC_ARC_POLICY_RESULT_FAIL
			  : DMARC_ARC_POLICY_RESULT_UNUSED,
			  g2
			  );
    }
  else

# endif
    g = string_fmt_append(g, "arc %d\narc_policy %d json[ ]\n",
		      ARES_RESULT_UNKNOWN, DMARC_ARC_POLICY_RESULT_UNUSED);
  }
#endif

/* Write the contents to the history file */
DEBUG(D_receive)
  {
  debug_printf_indent("DMARC history data for debugging:\n");
  expand_level++;
  debug_printf_indent("%Y", g);
  expand_level--;
  debug_printf_indent("DMARC logging history data for opendmarc reporting%s\n",
	     host_checking ? " (not really)" : "");
  }

if (!host_checking)
  {
  ssize_t written_len = write_to_fd_buf(history_file_fd,
				string_from_gstring(g), gstring_length(g));
  if (written_len == 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
	    "failure to write to DMARC history file: %s", dmarc_history_file);
    (void)close(history_file_fd);
    return;
    }
  (void)close(history_file_fd);
  }
return;
}



/*API*/
static gstring *
authres_dmarc(gstring * g)
{
if (f.dmarc_has_been_checked)
  {
  int start = 0;		/* Compiler quietening */
  DEBUG(D_acl) start = gstring_length(g);
  g = string_append(g, 2, US";\n\tdmarc=", dmarc_pass_fail);
  if (dmarc_header_from_sender)
    g = string_append(g, 2, US" header.from=", dmarc_header_from_sender);
  DEBUG(D_acl) debug_printf_indent("DMARC:\tauthres '%.*s'\n",
		  gstring_length(g) - start - 3, g->s + start + 3);
  }
else
  DEBUG(D_acl) debug_printf_indent("DMARC:\tno authres\n");
return g;
}

/******************************************************************************/
/* Module API */

static optionlist dmarc_options[] = {
  { "dmarc_forensic_sender",    opt_stringptr,      {&dmarc_forensic_sender} },
  { "dmarc_history_file",       opt_stringptr,      {&dmarc_history_file} },
  { "dmarc_tld_file",           opt_stringptr,      {&dmarc_tld_file} },
};

static void * dmarc_functions[] = {
  [DMARC_PROCESS] =	(void *) dmarc_process,
  [DMARC_RESULT_INLIST] = (void *) dmarc_result_inlist,
};

/* dmarc_forensic_sender is provided for visibility of the the option setting
by moan_send_message. We do not document it as a config-visible $variable.
We could provide it via a function but there's little advantage. */

static var_entry dmarc_variables[] = {
  { "dmarc_alignment_dkim",	vtype_bool,		&dmarc_alignment_dkim },
  { "dmarc_alignment_spf",	vtype_bool,		&dmarc_alignment_spf },
  { "dmarc_domain_policy",	vtype_stringptr,	&dmarc_domain_policy },
  { "dmarc_forensic_sender",	vtype_stringptr,	&dmarc_forensic_sender},
  { "dmarc_status",		vtype_stringptr,	&dmarc_status },
  { "dmarc_status_text",	vtype_stringptr,	&dmarc_status_text },
  { "dmarc_used_domain",	vtype_stringptr,	&dmarc_used_domain },
};

misc_module_info dmarc_module_info =
{
  .name =		US"dmarc",
# ifdef DYNLOOKUP
  .dyn_magic =		MISC_MODULE_MAGIC,
# endif
  .init =		dmarc_init,
  .lib_vers_report =	dmarc_version_report,
  .smtp_reset =		dmarc_smtp_reset,
  .msg_init =		dmarc_msg_init,
  .authres =		authres_dmarc,

  .options =		dmarc_options,
  .options_count =	nelem(dmarc_options),

  .functions =		dmarc_functions,
  .functions_count =	nelem(dmarc_functions),

  .variables =		dmarc_variables,
  .variables_count =	nelem(dmarc_variables),
};

#endif	/*EXIM_HAVE_DMARC*/
/* vi: aw ai sw=2
 */
