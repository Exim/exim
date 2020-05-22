/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* SPF support.
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004 - 2014
   License: GPL
   Copyright (c) The Exim Maintainers 2015 - 2020
*/

/* Code for calling spf checks via libspf-alt. Called from acl.c. */

#include "exim.h"
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


void
spf_lib_version_report(FILE * fp)
{
int maj, min, patch;
SPF_get_lib_version(&maj, &min, &patch);
fprintf(fp, "Library version: spf2: Compile: %d.%d.%d\n",
	SPF_LIB_VERSION_MAJOR, SPF_LIB_VERSION_MINOR, SPF_LIB_VERSION_PATCH);
fprintf(fp, "                       Runtime: %d.%d.%d\n",
	 maj, min, patch);
}



static SPF_dns_rr_t *
SPF_dns_exim_lookup(SPF_dns_server_t *spf_dns_server,
  const char *domain, ns_type rr_type, int should_cache)
{
dns_answer * dnsa = store_get_dns_answer();
dns_scan dnss;
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
int dns_rc;

DEBUG(D_receive) debug_printf("SPF_dns_exim_lookup '%s'\n", domain);

/* Shortcircuit SPF RR lookups by returning NO_DATA.  They were obsoleted by
RFC 6686/7208 years ago. see bug #1294 */

if (rr_type == T_SPF)
  {
  HDEBUG(D_host_lookup) debug_printf("faking NO_DATA for SPF RR(99) lookup\n");
  srr.herrno = NO_DATA;
  SPF_dns_rr_dup(&spfrr, &srr);
  return spfrr;
  }

switch (dns_rc = dns_lookup(dnsa, US domain, rr_type, NULL))
  {
  case DNS_SUCCEED:	srr.herrno = NETDB_SUCCESS;	break;
  case DNS_AGAIN:	srr.herrno = TRY_AGAIN;		break;
  case DNS_NOMATCH:	srr.herrno = HOST_NOT_FOUND;	break;
  case DNS_NODATA:	srr.herrno = NO_DATA;		break;
  case DNS_FAIL:
  default:		srr.herrno = NO_RECOVERY;	break;
  }

for (dns_record * rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS); rr;
     rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
  if (rr->type == rr_type) found++;

if (found == 0)
  {
  SPF_dns_rr_dup(&spfrr, &srr);
  return spfrr;
  }

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
	s += 2;	/* skip the MX precedence field */
      case T_PTR:
	{
	uschar * buf = store_malloc(256);
	(void)dn_expand(dnsa->answer, dnsa->answer + dnsa->answerlen, s,
	  (DN_EXPAND_ARG4_TYPE)buf, 256);
	s = buf;
	break;
	}

      case T_TXT:
	{
	gstring * g = NULL;
	uschar chunk_len;

	if (strncmpic(rr->data+1, US SPF_VER_STR, 6) != 0)
	  {
	  HDEBUG(D_host_lookup) debug_printf("not an spf record: %.*s\n",
	    (int) s[0], s+1);
	  continue;
	  }

	for (int off = 0; off < rr->size; off += chunk_len)
	  {
	  if (!(chunk_len = s[off++])) break;
	  g = string_catn(g, s+off, chunk_len);
	  }
	if (!g)
	  continue;
	gstring_release_unused(g);
	s = string_copy_malloc(string_from_gstring(g));
	DEBUG(D_receive) debug_printf("SPF_dns_exim_lookup '%s'\n", s);
	break;
	}

      case T_A:
      case T_AAAA:
      default:
	{
	uschar * buf = store_malloc(dnsa->answerlen + 1);
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

/* spfrr->rr must have been malloc()d for this */
SPF_dns_rr_dup(&spfrr, &srr);
return spfrr;
}



SPF_dns_server_t *
SPF_dns_exim_new(int debug)
{
SPF_dns_server_t * spf_dns_server = store_malloc(sizeof(SPF_dns_server_t));

DEBUG(D_receive) debug_printf("SPF_dns_exim_new\n");

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
  free(spf_dns_server);
  return NULL;
  }

return spf_dns_server;
}




/* Construct the SPF library stack.
   Return: Boolean success.
*/

BOOL
spf_init(void)
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
  DEBUG(D_receive) debug_printf("spf: SPF_dns_exim_new() failed\n");
  return FALSE;
  }
if (!(dc = SPF_dns_cache_new(dc, NULL, debug, 8)))
  {
  DEBUG(D_receive) debug_printf("spf: SPF_dns_cache_new() failed\n");
  return FALSE;
  }
if (!(spf_server = SPF_server_new_dns(dc, debug)))
  {
  DEBUG(D_receive) debug_printf("spf: SPF_server_new() failed.\n");
  return FALSE;
  }
  /* Override the outdated explanation URL.
  See https://www.mail-archive.com/mailop@mailop.org/msg08019.html
  Used to work as "Please%_see%_http://www.open-spf.org/Why?id=%{S}&ip=%{C}&receiver=%{R}",
  but is broken now (May 18th, 2020) */
if (!(s = expand_string(spf_smtp_comment_template)))
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "expansion of spf_smtp_comment_template failed");

SPF_server_set_explanation(spf_server, s, &spf_response);
if (SPF_response_errcode(spf_response) != SPF_E_SUCCESS)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "%s", SPF_strerror(SPF_response_errcode(spf_response)));

return TRUE;
}


/* Set up a context that can be re-used for several
   messages on the same SMTP connection (that come from the
   same host with the same HELO string).

Return: Boolean success
*/

BOOL
spf_conn_init(uschar * spf_helo_domain, uschar * spf_remote_addr)
{
DEBUG(D_receive)
  debug_printf("spf_conn_init: %s %s\n", spf_helo_domain, spf_remote_addr);

if (!spf_server && !spf_init()) return FALSE;

if (SPF_server_set_rec_dom(spf_server, CS primary_hostname))
  {
  DEBUG(D_receive) debug_printf("spf: SPF_server_set_rec_dom(\"%s\") failed.\n",
    primary_hostname);
  spf_server = NULL;
  return FALSE;
  }

spf_request = SPF_request_new(spf_server);

if (  SPF_request_set_ipv4_str(spf_request, CS spf_remote_addr)
   && SPF_request_set_ipv6_str(spf_request, CS spf_remote_addr)
   )
  {
  DEBUG(D_receive)
    debug_printf("spf: SPF_request_set_ipv4_str() and "
      "SPF_request_set_ipv6_str() failed [%s]\n", spf_remote_addr);
  spf_server = NULL;
  spf_request = NULL;
  return FALSE;
  }

if (SPF_request_set_helo_dom(spf_request, CS spf_helo_domain))
  {
  DEBUG(D_receive) debug_printf("spf: SPF_set_helo_dom(\"%s\") failed.\n",
    spf_helo_domain);
  spf_server = NULL;
  spf_request = NULL;
  return FALSE;
  }

return TRUE;
}


void
spf_response_debug(SPF_response_t * spf_response)
{
if (SPF_response_messages(spf_response) == 0)
  debug_printf(" (no errors)\n");
else for (int i = 0; i < SPF_response_messages(spf_response); i++)
  {
  SPF_error_t * err = SPF_response_message(spf_response, i);
  debug_printf( "%s_msg = (%d) %s\n",
		  (SPF_error_errorp(err) ? "warn" : "err"),
		  SPF_error_code(err),
		  SPF_error_message(err));
  }
}


/* spf_process adds the envelope sender address to the existing
   context (if any), retrieves the result, sets up expansion
   strings and evaluates the condition outcome.

Return: OK/FAIL  */

int
spf_process(const uschar **listptr, uschar *spf_envelope_sender, int action)
{
int sep = 0;
const uschar *list = *listptr;
uschar *spf_result_id;
int rc = SPF_RESULT_PERMERROR;

DEBUG(D_receive) debug_printf("spf_process\n");

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

  rc = SPF_response_result(spf_response);

  DEBUG(D_acl) spf_response_debug(spf_response);
  }

/* We got a result. Now see if we should return OK or FAIL for it */
DEBUG(D_acl) debug_printf("SPF result is %s (%d)\n", SPF_strresult(rc), rc);

if (action == SPF_PROCESS_GUESS && (!strcmp (SPF_strresult(rc), "none")))
  return spf_process(listptr, spf_envelope_sender, SPF_PROCESS_FALLBACK);

while ((spf_result_id = string_nextinlist(&list, &sep, NULL, 0)))
  {
  BOOL negate, result;

  if ((negate = spf_result_id[0] == '!'))
    spf_result_id++;

  result = Ustrcmp(spf_result_id, spf_result_id_list[rc].name) == 0;
  if (negate != result) return OK;
  }

/* no match */
return FAIL;
}



gstring *
authres_spf(gstring * g)
{
uschar * s;
if (!spf_result) return g;

g = string_append(g, 2, US";\n\tspf=", spf_result);
if (spf_result_guessed)
  g = string_cat(g, US" (best guess record for domain)");

s = expand_string(US"$sender_address_domain");
return s && *s
  ? string_append(g, 2, US" smtp.mailfrom=", s)
  : string_cat(g, US" smtp.mailfrom=<>");
}


#endif
