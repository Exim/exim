/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* DMARC support.
   Copyright (c) The Exim Maintainers 2025
   License: GPL */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"

#ifdef SUPPORT_DMARC
# error Build cannot support both libopendmarc and native DMARC modules
#endif

#ifdef EXPERIMENTAL_DMARC_NATIVE
# ifndef EXIM_HAVE_SPF
#  error SPF must also be enabled for DMARC
# elif defined DISABLE_DKIM
#  error DKIM must also be enabled for DMARC
# elif !defined LOOKUP_PSL
#  error PSL lookups must be enabled for DMARC
# else

#  include "../functions.h"
#  include "pdkim.h"

extern void		dmarc_send_forensic_report(const uschar **);
extern const uschar *	dmarc_get_dns_policy_record(uschar **);
extern void		dmarc_write_history_file(const gstring *);
extern const uschar *	dmarc_lookup_regdom(const uschar *);


static const pcre2_code * dmarc_regex_uri = NULL;
static const pcre2_code * dmarc_regex_pct = NULL;
static const pcre2_code * dmarc_regex_ri = NULL;
static const pcre2_code * dmarc_regex_fo = NULL;

BOOL
dmarc_local_init(void)
{
if (!dmarc_regex_uri)
  dmarc_regex_uri = regex_must_compile(US "^mailto:[^@]+@[^ !]+(?:[ !]|$)",
							MCS_CACHEABLE, FALSE);
if (!dmarc_regex_pct)
  dmarc_regex_pct = regex_must_compile(US "^\\d{1,3}$",  MCS_CACHEABLE, FALSE);
if (!dmarc_regex_ri)
  dmarc_regex_ri =  regex_must_compile(US "^\\d{1,10}$", MCS_CACHEABLE, FALSE);
if (!dmarc_regex_fo)
  dmarc_regex_fo =  regex_must_compile(US "^[01ds]$",    MCS_CACHEABLE, FALSE);
}


#include "../version.h"

gstring *
dmarc_version_report(gstring * g)
{
return string_fmt_append(g, "Library version: dmarc: Exim %s builtin\n",
			    EXIM_VERSION_STR);
}


int
dmarc_local_msg_init()
{
return OK;
}


/* Convert to comma-sep list to NULL-terminated array of pointers */
static uschar **
dmarc_clist_to_array(const uschar * list)
{
int cnt = 0, sep = ',';
const uschar * s = list;
uschar * buf = store_get(2, list), ** rarray;

while (string_nextinlist(&s, &sep, buf, 1)) cnt++;	/* count the elements */
rarray = store_get((cnt+1) * sizeof(*rarray), list);
for (cnt = 0; rarray[cnt] = string_nextinlist(&list, &sep, NULL, 0); ) cnt++;
return rarray;
}


static void
dmarc_maybe_send_forensic(const uschar * ruf)
{
/* Earlier ACL does not have *required* control=dmarc_enable_forensic */
if (!f.dmarc_enable_forensic)
  return;

/* RFC 7489 6.3 - ruf is optional */
if (!ruf)
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
  {
/* RFC 7489 6.3 - ruf is a comma-sep list */
  /* Convert to NULL-terminated array of pointers */
  const uschar ** rarray = CUSS dmarc_clist_to_array(ruf);
  dmarc_send_forensic_report(rarray);
  }
}


/******************************************************************************/
/* Policy record parsing */

/* Value verification routines: return boolean "good" */

static BOOL dmarc_vfy_vmode(const uschar * val)
{ return (*val == 's' || *val == 'r') && val[1] == '\0'; }
static BOOL dmarc_vfy_policy(const uschar * val)
{ return Ustrcmp(val, "none") == 0
	|| Ustrcmp(val, "quarantine") == 0
	|| Ustrcmp(val, "reject") == 0; }
static BOOL dmarc_vfy_fbl(const uschar * val)
{
/* For now, permit a list starting with (a plausible) mailto URI */
return regex_match(dmarc_regex_uri, val, -1, NULL);
}

static BOOL dmarc_tag_vfy_adkim(const uschar * val)
{ return dmarc_vfy_vmode(val); }
static BOOL dmarc_tag_vfy_aspf(const uschar * val)
{ return dmarc_vfy_vmode(val); }
static BOOL dmarc_tag_vfy_fo(const uschar * val)
{ return regex_match(dmarc_regex_fo, val, -1, NULL); }
static BOOL dmarc_tag_vfy_p(const uschar * val)
{ return dmarc_vfy_policy(val); }
static BOOL dmarc_tag_vfy_pct(const uschar * val)
{ return regex_match(dmarc_regex_pct, val, -1, NULL); }
static BOOL dmarc_tag_vfy_rf(const uschar * val)
{ return Ustrcmp(val, "afrf") == 0; }
static BOOL dmarc_tag_vfy_ri(const uschar * val)
{ return regex_match(dmarc_regex_ri, val, -1, NULL); }
static BOOL dmarc_tag_vfy_rua(const uschar * val)
{ return dmarc_vfy_fbl(val); }
static BOOL dmarc_tag_vfy_ruf(const uschar * val)
{ return dmarc_vfy_fbl(val); }
static BOOL dmarc_tag_vfy_sp(const uschar * val)
{ return dmarc_vfy_policy(val); }
static BOOL dmarc_tag_vfy_v(const uschar * val)
{ return Ustrcmp(val, "DMARC1") == 0; }

typedef struct dmarc_policy_record {
  const uschar * adkim;
  const uschar * aspf;
  const uschar * fo;
  const uschar * p;
  const uschar * pct;
  const uschar * rf;
  const uschar * ri;
  const uschar * rua;
  const uschar * ruf;
  const uschar * sp;
  const uschar * v;
} dmarc_policy_record;

typedef struct tag {
  const uschar * name;
  unsigned	 offset;
  BOOL		(*verify)(const uschar *);
} tag;
#define TAG(field) {.name = US mac_expanded_string(field), \
		    .offset = offsetof(dmarc_policy_record, field), \
		    .verify = dmarc_tag_vfy_ ## field }
tag policy_tags[] = {
  TAG(adkim),
  TAG(aspf),
  TAG(fo),
  TAG(p),
  TAG(pct),
  TAG(rf),
  TAG(ri),
  TAG(rua),
  TAG(ruf),
  TAG(sp),
  TAG(v),
};
#undef TAG

/* Handle one potential tag
Return: boolean success; else parsing error

RFC 7489 6.3 :- unknown tags are ignored
*/
static int
parse_tag(const uschar * tagrecord, dmarc_policy_record * prp)
{
const uschar * e = Ustrchr(tagrecord, '='), * s;

/* RFC 6736 3.2 tagspec must have = */
if (!*e)
  return FALSE;

/* RFC 6736 3.2 ignore whitespace between tag name and = */
for (s = e; s > tagrecord && isspace(s[-1]); ) s--;

/* RFC 6736 3.2 tag name at least 1 char */
if (s == tagrecord)
  return FALSE;

/* search for tag name in our table of known ones */
for (tag * ptp = policy_tags; ptp < policy_tags + nelem(policy_tags); ptp++)
 {
  if (  Ustrncmp(ptp->name, tagrecord, s - tagrecord) == 0
     && Ustrlen(ptp->name) == s - tagrecord)

    {			/* match; copy tag value to policy record struct */
    const uschar ** vp = CUSS (US prp + ptp->offset);

// debug_printf_indent("matched %q, off %u\n", tagrecord, ptp->offset);

/* RFC 6736 3.2 ignore whitespace between = and value */
    s = e + 1;
    Uskip_whitespace(&s);

    if (!ptp->verify(s)) DEBUG(D_receive)
      debug_printf_indent("DMARC: bad value for tag %q: %q\n", ptp->name, s);
    *vp = string_copy(s);
    break;
    }
 }
return TRUE;
}

static BOOL
dmarc_local_parse_policy(const uschar * rr, dmarc_policy_record * prp)
{
/* RFC 6376 3.2 :- a taglist is a ;-sep list of tagspec */
int sep = ';';

/* RFC 6736 3.2 :- ignore whitespace preceding tag-name and after value */

for (uschar * tagspec; tagspec = string_nextinlist(&rr, &sep, NULL, 0); )
  if (!parse_tag(tagspec, prp))
    return FALSE;

return TRUE;
}

/******************************************************************************/

static BOOL
identifier_aligned(const uschar * a, const uschar * b, const uschar * mode)
{
BOOL res;

/* RFC 7489 3.3.1 - In strict mode, only an exact match */

if (*mode == 's')
  res = Ustrcmp(a, b) == 0;

/* RFC 7489 3.3.1 - In relaxed mode, the Organizational Domains of both */
else
  {
  /* - if there is an exact match, the ODs will also match -
  so check that first to save on regdom lookups. */

  if (Ustrcmp(a, b) == 0)
    res = TRUE;
  else
    {
    a = dmarc_lookup_regdom(a);
    b = dmarc_lookup_regdom(b);
    res = a && b && Ustrcmp(a, b) == 0;
    }
  }
DEBUG(D_receive)
  if (res) debug_printf_indent("DMARC aligned(%s) %s %s\n", mode, a, b);
return res;
}


/* API: dmarc_process adds the envelope sender address to the existing
context (if any), retrieves the result, sets up expansion
strings and evaluates the condition outcome.
Called for the first ACL dmarc= condition. */

int
dmarc_process(void)
{
const uschar * rr;
BOOL has_dmarc_record = TRUE;

dmarc_alignment_spf = dmarc_alignment_dkim = FALSE;
dmarc_dkim_alignment = DMARC_POLICY_DKIM_ALIGNMENT_FAIL;
dmarc_spf_alignment =  DMARC_POLICY_SPF_ALIGNMENT_FAIL;

/* ACLs have "control=dmarc_disable_verify" */
if (f.dmarc_disable_verify || dmarc_abort)
  return OK;

DEBUG(D_receive) { debug_printf_indent("DMARC: process\n"); expand_level++; }

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
else
  {
/* RFC 7489 6.6.1 :- extract the domain from the 5322.From */
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

  /* Only use the domain if not empty.  Otherwise, skip out of DMARC. */

  if (!dmarc_header_from_sender || !*dmarc_header_from_sender)
    {
    dmarc_status = US"nofrom";
    dmarc_pass_fail = US"temperror";
    dmarc_status_text = US"No From: domain found";
    dmarc_action = DMARC_RESULT_ACCEPT;

    dmarc_abort = TRUE;
    }
  }

/* Skip DMARC if connection is SMTP Auth. Temporarily, admin should
instead do this in the ACLs.  */

if (!dmarc_abort && !sender_host_authenticated)
  {
/* RFC 7489 6.3 :- defaults for policy record tags */
  dmarc_policy_record dmarc_parsed = {
    .adkim =	US"r",
    .aspf =	US"r",
    .fo =	US"0",
    .pct =	US"100",
    .rf =	US"afrf",
    .ri =	US"86400",
    };

  int sr = SPF_RESULT_INVALID, spf_origin;
  uschar * spf_human_readable = NULL, * spf_sender_domain = NULL;
  unsigned dkim_sig_count = 0;
  gstring * dkim_history_buffer = NULL;
  typedef const pdkim_signature * (*sigs_fn_t)(void);

/* RFC 7489 6.6.2 step 2: DMARC policy record from DNS */
  DEBUG(D_receive)
    {
    debug_printf_indent("DMARC: get policy record\n");
    expand_level++;
    }

  /* uses $dmarc_header_from_sender */
  if (!(rr = dmarc_get_dns_policy_record(&dmarc_used_domain)))
	/*XXX want to handle nxdomain,temprror etc. here */
    {
    DEBUG(D_receive) debug_printf_indent("DMARC: no record found for %s\n",
					  dmarc_header_from_sender);
    dmarc_policy = DMARC_POLICY_ABSENT;
    dmarc_status = US"norecord";
    dmarc_pass_fail = US"none";
    dmarc_status_text = US"No DMARC record";
    dmarc_action = DMARC_RESULT_ACCEPT;

    has_dmarc_record = FALSE;
    }

  else if (!dmarc_local_parse_policy(rr, &dmarc_parsed))
    {
    DEBUG(D_receive) debug_printf_indent("DMARC: invalid record found for %s\n",
					  dmarc_header_from_sender);
    dmarc_policy = DMARC_POLICY_ABSENT;
    dmarc_status = US"norecord";
    dmarc_pass_fail = US"none";
    dmarc_status_text = US"No DMARC record";
    dmarc_action = DMARC_RESULT_ACCEPT;

    has_dmarc_record = FALSE;
    goto out;
    }

/* RFC 7489 6.6.3 step 6: p/sp checks */
    if (  !dmarc_parsed.p
       || !dmarc_tag_vfy_p(dmarc_parsed.p)
       || dmarc_parsed.sp && !dmarc_tag_vfy_sp(dmarc_parsed.sp)
       )

/* RFC 7489 6.6.3 step 6: if a valid rua, continue with p=none */
/*XXX "at least one syntactically valid reporting URI" */
      if (dmarc_parsed.rua && dmarc_tag_vfy_rua(dmarc_parsed.rua))
	{
	DEBUG(D_receive)
	  debug_printf_indent("DMARC: invalid p or sp; continue for rua\n");
	dmarc_parsed.p = US"none";
	}
      else
	{
	DEBUG(D_receive)
	  debug_printf_indent("DMARC: invalid p or sp, and no rua. Abort.\n");
	dmarc_abort = TRUE;
	goto out;
	}

/* RFC 7489 6.6.2 step 3: Perform DKIM signature verification checks */
  DEBUG(D_receive)
    {
    expand_level--;
    debug_printf_indent("DMARC: process dkim results\n");
    expand_level++;
    }

  /* Now we cycle through the dkim signature results and put into
  the opendmarc context, further building the DMARC reply. */

  if (has_dmarc_record)
    for(const pdkim_signature * sig =
	      (((sigs_fn_t *)dmarc_dkim_mod_info->functions)[DKIM_SIGS_LIST])();
	sig; sig = sig->next)
    {
    int dkim_result, dkim_ares_result, vs, ves;

    dkim_sig_count++;
    vs  = sig->verify_status & ~PDKIM_VERIFY_POLICY;
    ves = sig->verify_ext_status;
    dkim_result = vs == PDKIM_VERIFY_PASS ? DMARC_POLICY_DKIM_OUTCOME_PASS :
		  vs == PDKIM_VERIFY_FAIL ? DMARC_POLICY_DKIM_OUTCOME_FAIL :
		  vs == PDKIM_VERIFY_INVALID ? DMARC_POLICY_DKIM_OUTCOME_TMPFAIL :
		  DMARC_POLICY_DKIM_OUTCOME_NONE;

    DEBUG(D_receive)
      debug_printf_indent("DMARC: adding DKIM sender domain = %s\n",
			  sig->domain);

    /* Update the history buffer */

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

    dkim_history_buffer = string_fmt_append(dkim_history_buffer,
      "dkim %s %s %d\n", sig->domain, sig->selector, dkim_ares_result);

    /* Evaluate the sig vs. dmarc requirements */

/* RFC 7489 3.1.1 if any DKIM signature ... verifies. */
    if (  !dmarc_alignment_dkim
       && dkim_result == DMARC_POLICY_DKIM_OUTCOME_PASS

/* RFC 7489 3.1.1 dkim alignment: d= tag in dkim sig */
/* RFC 7489 3.1.1 dkim alignment: 5322.From domain */
/* RFC 7489 6.3   adkim: DKIM Identifier Alignment mode */

       && (dmarc_alignment_dkim = identifier_aligned(sig->domain,
				  dmarc_header_from_sender, dmarc_parsed.adkim))
       )
      dmarc_dkim_alignment = DMARC_POLICY_DKIM_ALIGNMENT_PASS;
    }
  DEBUG(D_receive) debug_printf_indent("DMARC: %u dkim sig%s\n",
				dkim_sig_count, dkim_sig_count == 1 ? "" : "s");

  DEBUG(D_receive)
    {
    expand_level--;
    debug_printf_indent("DMARC: process spf results\n");
    expand_level++;
    }

/* RFC 7489 6.6.2 step 4: Perform SPF validation checks */

  if (has_dmarc_record)
    {
    int spf_result;
    typedef int (*fn_t)(uschar **);

    /* Use the envelope sender domain for this part of DMARC */

    spf_sender_domain = expand_string(US"$sender_address_domain");

    if (dmarc_spf_mod_info)
      sr = ((fn_t *) dmarc_spf_mod_info->functions)[SPF_GET_RESULTS]
							  (&spf_human_readable);

    if (sr == SPF_RESULT_INVALID)
      {
      /* No spf data means null envelope sender so generate a domain name
      from the sender_helo_name  */

      DEBUG(D_receive) debug_printf_indent("DMARC: spf result 'invalid'\n");

      if (!spf_sender_domain || !*spf_sender_domain)
	{
	spf_sender_domain = sender_helo_name;
	log_write(0, LOG_MAIN, "DMARC using synthesized SPF sender domain = %s\n",
			       spf_sender_domain);
	}
      spf_result = DMARC_POLICY_SPF_OUTCOME_NONE;
      dmarc_spf_ares_result = ARES_RESULT_UNKNOWN;
      spf_origin = DMARC_POLICY_SPF_ORIGIN_HELO;
      spf_human_readable = US"";
      }
    else
      {
      spf_result = sr == SPF_RESULT_NEUTRAL  ? DMARC_POLICY_SPF_OUTCOME_NONE :
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
      /*XXX hmm, spf_origin never used? */
      spf_origin = DMARC_POLICY_SPF_ORIGIN_MAILFROM;
      DEBUG(D_receive)
	debug_printf_indent("DMARC: using SPF sender domain = %s\n",
					  spf_sender_domain);
      }
    if (!spf_sender_domain || !*spf_sender_domain)
      dmarc_abort = TRUE;
    if (!dmarc_abort)
      {
  /* RFC 7489 3.1.1 spf alignment: the SPF-authenticated domain */
  /* RFC 7489 3.1.1 spf alignment: 5322.From domain */
  /* RFC 7489 6.3   aspf: SPF Identifier Alignment mode */

      if (  spf_result == DMARC_POLICY_SPF_OUTCOME_PASS
	 && (dmarc_alignment_spf = identifier_aligned(spf_sender_domain,
				  dmarc_header_from_sender, dmarc_parsed.aspf))
	 )
	dmarc_spf_alignment = DMARC_POLICY_SPF_ALIGNMENT_PASS;
      }
    }

  DEBUG(D_receive)
    {
    expand_level--;
    debug_printf_indent("DMARC: finished spf\n");
    }

  /* Store the policy string in an expandable variable. */

/* RFC 7489 is unclear how to obtain the policy-string that is to be used.
The decription of tags p & sp in 6.3 uses the term "domain queried". I assume
that is the portion of the DNS lookup key *after* the prepended "_dmarc."
which returned the DMARC RR being used (so it could be the Organizational
Domain, per 6.6.3 bullet 3, rather than the 5322.From domain).

Given that assumption: if dom-used != 5322.From.dom and there is an sp,
use the sp.  Otherwise use the p. */

  dmarc_domain_policy = dmarc_parsed.sp
			&& dmarc_used_domain != dmarc_header_from_sender
		      ? dmarc_parsed.sp : dmarc_parsed.p;

/* RFC 7489 6.6.2 step 5 - if either the spf or dkim shows alignment, pass */
  if (dmarc_alignment_spf || dmarc_alignment_dkim)
    {							/* Explicit accept */
    dmarc_policy = DMARC_POLICY_PASS;
    dmarc_status = US"accept";
    dmarc_pass_fail = US"pass";
    dmarc_status_text = US"Accept";
    dmarc_action = DMARC_RESULT_ACCEPT;
    }

/* RFC 7489 6.6.2 step 6 - dispose of no-alignment per discovered policy */
  else
    {
    dmarc_status = dmarc_domain_policy;
    if (Ustrcmp(dmarc_domain_policy, "none") == 0)
      {							/* Accept and report */
      dmarc_policy = DMARC_POLICY_NONE;
      dmarc_pass_fail = US"none";
      dmarc_status_text = US"None, Accept";
      dmarc_action = DMARC_RESULT_ACCEPT;
      }
    else if (Ustrcmp(dmarc_domain_policy, "quarantine") == 0)
      {							/* Explicit quarantine*/
      dmarc_policy = DMARC_POLICY_QUARANTINE;
      dmarc_pass_fail = US"fail";
      dmarc_status_text = US"Quarantine";
      dmarc_action = DMARC_RESULT_QUARANTINE;
      }
    else if (Ustrcmp(dmarc_domain_policy, "reject") == 0)
      {							/* Explicit reject */
      dmarc_policy = DMARC_POLICY_REJECT;
      dmarc_pass_fail = US"fail";
      dmarc_status_text = US"Reject";
      dmarc_action = DMARC_RESULT_REJECT;
      }
    else	/* should never happen; tag values were validated */
      {		/* could use similar for dns tmpfail */
      dmarc_status = dmarc_pass_fail = US"temperror";
      dmarc_status_text = US"Internal Policy Error";
      dmarc_action = DMARC_RESULT_TEMPFAIL;
      }
    }

  if (has_dmarc_record && !dmarc_abort)
    {
    /* Log results. */

    if (LOGGING(dmarc_verbose))
      log_write(0, LOG_MAIN, "DMARC results: spf_domain=%s dmarc_domain=%s "
			   "spf_align=%s dkim_align=%s enforcement='%s'",
			   spf_sender_domain, dmarc_used_domain,
			   dmarc_alignment_spf  ? "yes" : "no",
			   dmarc_alignment_dkim ? "yes" : "no",
			   dmarc_status_text);


    /* History file, for later aggregate reporting. */

    dmarc_pct = atoi(CCS dmarc_parsed.pct);

    dmarc_adkim = dmarc_parsed.adkim
		? *dmarc_parsed.adkim : DMARC_RECORD_A_UNSPECIFIED;
    dmarc_aspf = dmarc_parsed.aspf 
		? *dmarc_parsed.aspf : DMARC_RECORD_A_UNSPECIFIED;
    dmarc_dom_policy = dmarc_parsed.p
		? *dmarc_parsed.p : DMARC_RECORD_P_UNSPECIFIED;
    dmarc_subdom_policy = dmarc_parsed.sp
		? *dmarc_parsed.sp : DMARC_RECORD_P_UNSPECIFIED;

/* RFC 7489 6.3 - rua is a comma-sep list */
    dmarc_rua = dmarc_clist_to_array(dmarc_parsed.rua);

    dmarc_write_history_file(dkim_history_buffer);

    /* Forensic reporting */

    dmarc_maybe_send_forensic(dmarc_parsed.ruf);
    }
  }

out:
  DEBUG(D_receive)
    {
    expand_level--;
    debug_printf_indent("DMARC: finished process, status %q\n", dmarc_status);
    }
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
if (f.dmarc_disable_verify )            // || !dmarc_pctx)
  return dmarc_exim_expand_defaults();

return dmarc_status;
}


# endif /* have SPF & DKIM */
#endif /* EXPERIMENTAL_DMARC_NATIVE */
/* vi: aw ai sw=2
 */
