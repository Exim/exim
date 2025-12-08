/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* SPF support.
   Copyright (c) The Exim Maintainers 2015 - 2025
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004 - 2014
   License: GPL
   SPDX-License-Identifier: GPL-2.0-or-later
*/

/* Code for calling spf checks via libspf-alt. Called from acl.c. */

#include "../exim.h"
#ifdef SUPPORT_SPF

/* must be kept in numeric order */
static spf_result_id spf_result_id_list[] = {
  /* name		value */
  { US"invalid",	0},
  { US"neutral",	1 },
  { US"pass",		2 },
  { US"fail",		3 },
  { US"softfail",	4 },
  { US"none",		5 },
  { US"temperror",	6 }, /* RFC 4408 defined */
  { US"permerror",	7 }  /* RFC 4408 defined */
};

SPF_server_t    *spf_server = NULL;
SPF_request_t   *spf_request = NULL;
SPF_response_t  *spf_response = NULL;
SPF_response_t  *spf_response_2mx = NULL;

SPF_dns_rr_t  * spf_nxdomain = NULL;

uschar * spf_guess              = US"v=spf1 a/24 mx/24 ptr ?all";
uschar * spf_header_comment     = NULL;
uschar * spf_received           = NULL;
uschar * spf_result             = NULL;
uschar * spf_smtp_comment       = NULL;
uschar * spf_smtp_comment_template
                    /* Used to be: "Please%_see%_http://www.open-spf.org/Why?id=%{S}&ip=%{C}&receiver=%{R}" */
				= US"Please%_see%_http://www.open-spf.org/Why";
BOOL    spf_result_guessed	= FALSE;
const uschar * spf_used_domain	= NULL;




static gstring *
spf_lib_version_report(gstring * g)
{
int maj, min, patch;

SPF_get_lib_version(&maj, &min, &patch);
g = string_fmt_append(g, "Library version: spf2: Compile: %d.%d.%d\n",
	SPF_LIB_VERSION_MAJOR, SPF_LIB_VERSION_MINOR, SPF_LIB_VERSION_PATCH);
g = string_fmt_append(g,    "                       Runtime: %d.%d.%d\n",
	 maj, min, patch);
return g;
}



static SPF_dns_rr_t *
SPF_dns_exim_lookup(SPF_dns_server_t *spf_dns_server,
  const char *domain, ns_type rr_type, int should_cache)
{
dns_answer * dnsa = store_get_dns_answer();
dns_scan dnss = {0};
SPF_dns_rr_t * spfrr;
unsigned found = 0;

SPF_dns_rr_t srr = {
  .domain = CS domain,			/* query information */
  .domain_buf_len = 0,
  .rr_type = rr_type,

  .rr_buf_len = 0,			/* answer information */
  .rr_buf_num = 0, /* no free of s */
  .utc_ttl = 0,

  .hook = NULL,				/* misc information */
  .source = spf_dns_server
};

DEBUG(D_receive)
  { debug_printf_indent("SPF_dns_exim_lookup '%s'\n", domain); expand_level++; }

/* Shortcircuit SPF RR lookups by returning NO_DATA.  They were obsoleted by
RFC 6686/7208 years ago. see bug #1294 */

if (rr_type == T_SPF)
  {
  HDEBUG(D_host_lookup)
    debug_printf_indent("faking NO_DATA for SPF RR(99) lookup\n");
  srr.herrno = NO_DATA;
  goto out;
  }

switch (dns_lookup(dnsa, US domain, rr_type, NULL))
  {
  case DNS_AGAIN:	srr.herrno = TRY_AGAIN;		break;
  case DNS_NOMATCH:	srr.herrno = HOST_NOT_FOUND;	break;
  case DNS_NODATA:	srr.herrno = NO_DATA;		break;
  case DNS_FAIL:
  default:		srr.herrno = NO_RECOVERY;	break;
  case DNS_SUCCEED:
    srr.herrno = NETDB_SUCCESS;
    for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS); rr;
	 rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
      /* Need to alloc space for all records, so no early-out */
      if (rr->type == rr_type) found++;
    break;
  }

if (found == 0)
  goto out;

srr.rr = store_malloc(sizeof(SPF_dns_rr_data_t) * found);

found = 0;
for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS); rr;
   rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
  if (rr->type == rr_type)
    {
    const uschar * s = rr->data;

    srr.ttl = rr->ttl;
    switch(rr_type)
      {
      case T_MX:
	if (rr->size < 2) continue;
	s += 2;	/* skip the MX precedence field */
      case T_PTR:
	{
	/* We lose taint-tracking here, really just assuming the data
	given to the spf library will never leak back out.  Not sure if
	the lib assumes it can free this (it does for srr.rr) - meaning we
	cannot use pool store. The use of malloc also for T_TXT implies so. */

	uschar * buf = store_malloc(256);	/*TTT alloc*/
	/*TTT*/
	if (dn_expand(dnsa->answer, dnsa->answer + dnsa->answerlen, s,
	    (DN_EXPAND_ARG4_TYPE)buf, 256) < 0)
	  continue;
	s = buf;
	break;
	}

      case T_TXT:
	{
	gstring * g = NULL;
	uschar chunk_len;

	if (rr->size < 1+6) continue;		/* min for version str */
	if (strncmpic(rr->data+1, US SPF_VER_STR, 6) != 0)
	  {
	  HDEBUG(D_host_lookup) debug_printf_indent("not an spf record: %.*s\n",
						    (int) s[0], s+1);
	  continue;
	  }

	/* require 1 byte for the chunk_len */
	for (int offset = 0; offset < rr->size - 1; offset += chunk_len)
	  {
	  if (  !(chunk_len = s[offset++])
	     || rr->size < offset + chunk_len	/* ignore bogus size chunks */
	     ) break;
	  g = string_catn(g, s+offset , chunk_len);	/*TTT*/
	  }
	if (!g)
	  continue;
	s = string_copy_malloc(string_from_gstring(g));	/*TTT*/
	gstring_reset(g);
	gstring_release_unused(g);
	DEBUG(D_receive) debug_printf_indent("SPF_dns_exim_lookup '%s'\n", s);
	break;
	}

      case T_A:
      case T_AAAA:
      default:
	{
	uschar * buf = store_malloc(dnsa->answerlen + 1);	/*TTT alloc*/
	s = memcpy(buf, s, dnsa->answerlen + 1);
	break;
	}
      }
    srr.rr[found++] = (void *) s;
    }

/* Did we filter out all TXT RRs? Return NO_DATA instead of SUCCESS with
empty ANSWER section. */

if (!(srr.num_rr = found))
  srr.herrno = NO_DATA;

out:
  /* spfrr->rr must have been malloc()d for this */
  SPF_dns_rr_dup(&spfrr, &srr);

  DEBUG(D_receive) expand_level--;
  store_free_dns_answer(dnsa);
  return spfrr;
}



static SPF_dns_server_t *
SPF_dns_exim_new(int debug)
{
SPF_dns_server_t * spf_dns_server = store_malloc(sizeof(SPF_dns_server_t));

/* DEBUG(D_receive) debug_printf_indent("SPF_dns_exim_new\n"); */

memset(spf_dns_server, 0, sizeof(SPF_dns_server_t));
spf_dns_server->destroy      = NULL;
spf_dns_server->lookup       = SPF_dns_exim_lookup;
spf_dns_server->get_spf      = NULL;
spf_dns_server->get_exp      = NULL;
spf_dns_server->add_cache    = NULL;
spf_dns_server->layer_below  = NULL;
spf_dns_server->name         = "exim";
spf_dns_server->debug        = debug;

/* XXX This might have to return NO_DATA sometimes. */

spf_nxdomain = SPF_dns_rr_new_init(spf_dns_server,
  "", ns_t_any, 24 * 60 * 60, HOST_NOT_FOUND);
if (!spf_nxdomain)
  {
  store_free(spf_dns_server);
  return NULL;
  }

return spf_dns_server;
}




/* Construct the SPF library stack.
   Return: Boolean success.
*/

static BOOL
spf_init(void * dummy_ctx)
{
SPF_dns_server_t * dc;
int debug = 0;
const uschar *s;

DEBUG(D_receive) debug = 1;

/* We insert our own DNS access layer rather than letting the spf library
do it, so that our dns access path is used for debug tracing and for the
testsuite. */

if (!(dc = SPF_dns_exim_new(debug)))
  {
  DEBUG(D_receive) debug_printf_indent("SPF_dns_exim_new() failed\n");
  return FALSE;
  }
if (!(dc = SPF_dns_cache_new(dc, NULL, debug, 8)))
  {
  DEBUG(D_receive) debug_printf_indent("SPF_dns_cache_new() failed\n");
  return FALSE;
  }
if (!(spf_server = SPF_server_new_dns(dc, debug)))
  {
  DEBUG(D_receive) debug_printf_indent("SPF_server_new() failed.\n");
  return FALSE;
  }

/* Override the outdated explanation URL.
See https://www.mail-archive.com/mailop@mailop.org/msg08019.html
Used to work as "Please%_see%_http://www.open-spf.org/Why?id=%{S}&ip=%{C}&receiver=%{R}",
but is broken now (May 18th, 2020) */

GET_OPTION("spf_smtp_comment_template");
if (!(s = expand_string(spf_smtp_comment_template)))
  log_write_die(0, LOG_MAIN, "expansion of spf_smtp_comment_template failed");

SPF_server_set_explanation(spf_server, CCS s, &spf_response);
if (SPF_response_errcode(spf_response) != SPF_E_SUCCESS)
  log_write_die(0, LOG_MAIN, "%s", SPF_strerror(SPF_response_errcode(spf_response)));

return TRUE;
}


/* Set up a context that can be re-used for several
   messages on the same SMTP connection (that come from the
   same host with the same HELO string).

Return: OK/FAIL
*/

static int
spf_conn_init(const uschar * spf_helo_domain, const uschar * spf_remote_addr,
  const uschar ** errstr)
{
DEBUG(D_receive) debug_printf_indent("spf_conn_init: %s %s\n",
				      spf_helo_domain, spf_remote_addr);

if (!spf_server && !spf_init(NULL))
  {
  *errstr = US"spf: library init call";
  return FAIL;
  }

if (SPF_server_set_rec_dom(spf_server, CS primary_hostname))
  {
  DEBUG(D_receive) debug_printf_indent("SPF_server_set_rec_dom(%q) failed.\n",
					primary_hostname);
  spf_server = NULL;
  *errstr = US"spf: setting host name";
  return FAIL;
  }

spf_request = SPF_request_new(spf_server);

if (  SPF_request_set_ipv4_str(spf_request, CCS spf_remote_addr)
   && SPF_request_set_ipv6_str(spf_request, CCS spf_remote_addr)
   )
  {
  DEBUG(D_receive)
    debug_printf_indent("SPF_request_set_ipv4_str() and "
      "SPF_request_set_ipv6_str() failed [%s]\n", spf_remote_addr);
  spf_server = NULL;
  spf_request = NULL;
  *errstr = US"spf: setting remote addr";
  return FAIL;
  }

if (SPF_request_set_helo_dom(spf_request, CCS spf_helo_domain))
  {
  DEBUG(D_receive) debug_printf_indent("SPF_set_helo_dom(%q) failed.\n",
				      spf_helo_domain);
  spf_server = NULL;
  spf_request = NULL;
  *errstr = US"spf: setting helo string";
  return FAIL;
  }

return OK;
}

static void
spf_smtp_reset(void)
{
spf_header_comment = spf_received = spf_result = spf_smtp_comment = NULL;
spf_result_guessed = FALSE;
}


static void
spf_response_debug(SPF_response_t * spf_response)
{
if (SPF_response_messages(spf_response) == 0)
  debug_printf_indent(" (no errors)\n");
else for (int i = 0; i < SPF_response_messages(spf_response); i++)
  {
  SPF_error_t * err = SPF_response_message(spf_response, i);
  debug_printf_indent("%s_msg = (%d) %s\n",
		      SPF_error_errorp(err) ? "warn" : "err",
		      SPF_error_code(err),
		      SPF_error_message(err));
  }
}


/* spf_process adds the envelope sender address to the existing
   context (if any), retrieves the result, sets up expansion
   strings and evaluates the condition outcome.

Return: OK/FAIL  */

static int
spf_process(const uschar ** listptr, const uschar * spf_envelope_sender,
  int action)
{
int rc = SPF_RESULT_PERMERROR, ret;

DEBUG(D_receive) { debug_printf_indent("SPF: process\n"); expand_level++; }

if (!(spf_server && spf_request))
  /* no global context, assume temp error and skip to evaluation */
  rc = SPF_RESULT_PERMERROR;

else if (SPF_request_set_env_from(spf_request, CS spf_envelope_sender))
  /* Invalid sender address. This should be a real rare occurrence */
  rc = SPF_RESULT_PERMERROR;

else
  {
  /* get SPF result */
  if (action == SPF_PROCESS_FALLBACK)
    {
    SPF_request_query_fallback(spf_request, &spf_response, CS spf_guess);
    spf_result_guessed = TRUE;
    }
  else
    SPF_request_query_mailfrom(spf_request, &spf_response);

  /* set up expansion items */
  spf_header_comment     = US SPF_response_get_header_comment(spf_response);
  spf_received           = US SPF_response_get_received_spf(spf_response);
  spf_result             = US SPF_strresult(SPF_response_result(spf_response));
  spf_smtp_comment       = US SPF_response_get_smtp_comment(spf_response);
  spf_used_domain	 = sender_address && *sender_address
			  ? expand_string(US"$sender_address_domain")
			  : sender_helo_name;

  rc = SPF_response_result(spf_response);

  DEBUG(D_acl) spf_response_debug(spf_response);
  }

/* We got a result. Now see if we should return OK or FAIL for it */
DEBUG(D_acl)
  debug_printf_indent("SPF: result is %s (%d)\n", SPF_strresult(rc), rc);

if (action == SPF_PROCESS_GUESS && (!strcmp (SPF_strresult(rc), "none")))
  ret = spf_process(listptr, spf_envelope_sender, SPF_PROCESS_FALLBACK);

else
  {
  const uschar * list = *listptr;
  ret = match_isinlist(spf_result_id_list[rc].name, &list,
                    0, NULL, NULL, MCL_STRING, TRUE, NULL);
  }

DEBUG(D_receive) expand_level--;
return ret;
}



static gstring *
authres_spf(gstring * g)
{
uschar * s;
if (spf_result)
  {
  int start = 0;		/* Compiler quietening */
  DEBUG(D_acl) start = gstring_length(g);

  g = string_append(g, 2, US";\n\tspf=", spf_result);
  if (spf_result_guessed)
    g = string_cat(g, US" (best guess record for domain)");

  s = expand_string(US"$sender_address_domain");
  if (s && *s)
    g = string_append(g, 2, US" smtp.mailfrom=", s);
  else
    {
    s = sender_helo_name;
    g = s && *s
      ? string_append(g, 2, US" smtp.helo=", s)
      : string_cat(g, US" smtp.mailfrom=<>");
    }
  DEBUG(D_acl) debug_printf_indent("SPF:\tauthres '%.*s'\n",
		  gstring_length(g) - start - 3, g->s + start + 3);
  }
else
  DEBUG(D_acl) debug_printf_indent("SPF:\tno authres\n");
return g;
}


static int
spf_get_results(uschar ** human_readable_p)
{
uschar * s = NULL;
int res = SPF_RESULT_INVALID;

if (spf_response)
  {
  res = spf_response->result;
  s = US spf_response->header_comment;
  }
*human_readable_p = s ? string_copy(s) : US"";
DEBUG(D_acl) debug_printf_indent(" SPF: %d '%s'\n", res, s);
return res;
}

/******************************************************************************/
/* Lookup support */

static void *
spf_lookup_open(const uschar * filename, uschar ** errmsg)
{
SPF_dns_server_t * dc;
SPF_server_t * spf_server = NULL;
int debug = 0;

DEBUG(D_lookup) debug = 1;

if ((dc = SPF_dns_exim_new(debug)))
  if ((dc = SPF_dns_cache_new(dc, NULL, debug, 8)))
    spf_server = SPF_server_new_dns(dc, debug);

if (!spf_server)
  {
  *errmsg = US"SPF_dns_exim_nnew() failed";
  return NULL;
  }
return (void *) spf_server;
}

static void
spf_lookup_close(void * handle)
{
SPF_server_t * spf_server = handle;
if (spf_server) SPF_server_free(spf_server);
}

static int
spf_lookup_find(void * handle, const uschar * filename,
  const uschar * keystring, int key_len, uschar ** result, uschar ** errmsg,
  uint * do_cache, const uschar * opts)
{
SPF_server_t *spf_server = handle;
SPF_request_t *spf_request;
SPF_response_t *spf_response = NULL;

if (!(spf_request = SPF_request_new(spf_server)))
  {
  *errmsg = US"SPF_request_new() failed";
  return FAIL;
  }

#if HAVE_IPV6
switch (string_is_ip_address(filename, NULL))
#else
switch (4)
#endif
  {
  case 4:
    if (!SPF_request_set_ipv4_str(spf_request, CS filename))
      break;
    *errmsg = string_sprintf("invalid IPv4 address '%s'", filename);
    return FAIL;
#if HAVE_IPV6

  case 6:
    if (!SPF_request_set_ipv6_str(spf_request, CS filename))
      break;
    *errmsg = string_sprintf("invalid IPv6 address '%s'", filename);
    return FAIL;

  default:
    *errmsg = string_sprintf("invalid IP address '%s'", filename);
    return FAIL;
#endif
  }

if (SPF_request_set_env_from(spf_request, CS keystring))
    {
  *errmsg = string_sprintf("invalid envelope from address '%s'", keystring);
  return FAIL;
}

SPF_request_query_mailfrom(spf_request, &spf_response);
*result = string_copy(US SPF_strresult(SPF_response_result(spf_response)));

DEBUG(D_lookup) spf_response_debug(spf_response);

SPF_response_free(spf_response);
SPF_request_free(spf_request);
return OK;
}


/******************************************************************************/
/* Module API */

static optionlist spf_options[] = {
  { "spf_guess",                opt_stringptr,   {&spf_guess} },
  { "spf_smtp_comment_template",opt_stringptr,   {&spf_smtp_comment_template} },
};

static void * spf_functions[] = {
  [SPF_PROCESS] =	(void *) spf_process,
  [SPF_GET_RESULTS] =	(void *) spf_get_results,	/* for dmarc */
  
  [SPF_OPEN] =		(void *) spf_lookup_open,
  [SPF_CLOSE] =		(void *) spf_lookup_close,
  [SPF_FIND] =		(void *) spf_lookup_find,
};

static var_entry spf_variables[] = {
  { "spf_guess",		vtype_stringptr,	&spf_guess },
  { "spf_header_comment",	vtype_stringptr,	&spf_header_comment },
  { "spf_received",		vtype_stringptr,	&spf_received },
  { "spf_result",		vtype_stringptr,	&spf_result },
  { "spf_result_guessed",	vtype_bool,		&spf_result_guessed },
  { "spf_smtp_comment",		vtype_stringptr,	&spf_smtp_comment },
  { "spf_used_domain",		vtype_stringptr,	&spf_used_domain },
};

misc_module_info spf_module_info =
{
  .name =		US"spf",
# ifdef DYNLOOKUP
  .dyn_magic =		MISC_MODULE_MAGIC,
# endif
  .init =		spf_init,
  .lib_vers_report =	spf_lib_version_report,
  .conn_init =		spf_conn_init,
  .smtp_reset =		spf_smtp_reset,
  .authres =		authres_spf,

  .options =		spf_options,
  .options_count =	nelem(spf_options),

  .functions =		spf_functions,
  .functions_count =	nelem(spf_functions),

  .variables =		spf_variables,
  .variables_count =	nelem(spf_variables),
};

#endif	/* almost all the file */
