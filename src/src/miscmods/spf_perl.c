/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* SPF support.
   Copyright (c) The Exim Maintainers 2025
   Copyright (c) Jeremy Harris 2025
   License: GPL
   SPDX-License-Identifier: GPL-2.0-or-later
*/

/* Code for calling spf checks via Mail::SPF.
Called from acl.c and lookups/spf.c */

#include "../exim.h"
#ifdef EXPERIMENTAL_SPF_PERL

# ifndef EXIM_PERL
#  error EXPERIMENTAL_SPF_PERL module requires perl support in Exim
# endif
# ifdef SUPPORT_SPF
#  error incompat: standard (libspf2) and Experimental (perl) implementations
# endif

/* should be kept in numeric order */
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

const uschar * conn_helo = NULL;
const uschar * conn_addr = NULL;

uschar * spf_guess              = US"v=spf1 a/24 mx/24 ptr ?all";
uschar * spf_header_comment     = NULL;
uschar * spf_received           = NULL;
uschar * spf_result             = NULL;
uschar * spf_smtp_comment       = NULL;
uschar * spf_smtp_comment_template
                    /* Used to be: "Please%_see%_http://www.open-spf.org/Why?id=%{S}&ip=%{C}&receiver=%{R}" */
				= US"Please%_see%_http://www.open-spf.org/Why";
BOOL    spf_result_guessed     = FALSE;


static const misc_module_info * spf_perl_mi = NULL;


/* This is the block of code we add to the perl interpreter for doing
SPF operations. The function returns an Exim list, newline-sep, with
the first element being the result word and the remainder being the
suggested 2822 header. */

static const uschar spf_pl[] =
  "use Mail::SPF;"
  "sub my_spf_req {"
    "my ($mfrom, $conn_addr, $conn_helo) = @_;"
    "my $request = Mail::SPF::Request->new("
      "scope       => 'mfrom',"
      "identity    => $mfrom,"
      "ip_address  => $conn_addr,"
      "helo_identity => $conn_helo"
      ");"
    "my $server = Mail::SPF::Server->new();"
    "my $result = $server->process($request);"
    "return $result->code . '\n' . $result->received_spf_header;"
    "}"
  ;

/******************************************************************************/

/* Start the perl interpreter, if not already running, and add our perl
spf lookup routine to it.  Safely does nothing if called again.
*/

static const misc_module_info *
setup_spf_perl_mi(void)
{
typedef uschar * (*fn_t)(const uschar *);

if (!spf_perl_mi)
  {
  if (!(spf_perl_mi = perl_startup(opt_perl_startup ? opt_perl_startup : US"")))
    /* errstr = string_sprintf("spf: %s", expand_string_message); */
    return NULL;

  /*XXX could return an error string here:
  if ((errstr = (((fn_t *) spf_perl_mi->functions)[PERL_ADDBLOCK]) (spf_pl)))
  */

  if ((((fn_t *) spf_perl_mi->functions)[PERL_ADDBLOCK]) (spf_pl))
    return spf_perl_mi = NULL;
  }
return spf_perl_mi;
}

/* Call our perl routine */

gstring *
call_my_spf_req(const uschar ** argv)
{
uschar * errstr;
gstring * g;
typedef gstring * (*fn_t)(gstring *, uschar **, uschar *, const uschar **);

DEBUG(D_acl) debug_printf_indent("calling Mail::SPF\n");
expand_level++;
if (!(g = (((fn_t *) spf_perl_mi->functions)[PERL_CAT])
			  (NULL, &errstr, US"my_spf_req", argv)))
  DEBUG(D_acl) debug_printf_indent("SPF err %q\n", errstr);
expand_level--;
return g;
}

/******************************************************************************/


/*API*/
static gstring *
spf_lib_version_report(gstring * g)
{
/*XXX Does Mail::SPF have a version? MetaCPAN says yes, but does not
document a method that returns it. */
return string_cat(g, US"Library_version: SPF: perl Mail::SPF\n");
}



/*API*/
/* Set up a context that can be re-used for several
   messages on the same SMTP connection (that come from the
   same host with the same HELO string).

We delay doing perl startup until spf processing time, as ACL might
never need us on any given connection.

Return: OK/FAIL
*/

static int
spf_conn_init(const uschar * spf_helo_domain, const uschar * spf_remote_addr,
  const uschar ** errstr)
{
DEBUG(D_receive) debug_printf_indent("spf_conn_init: helo:%s addr:%s\n",
			      spf_helo_domain, spf_remote_addr);

/* Copy the args to globals */

conn_helo = spf_helo_domain;
conn_addr = spf_remote_addr;

return OK;
}



/*API*/
static void
spf_smtp_reset(void)
{
spf_header_comment = spf_received = spf_result = spf_smtp_comment = NULL;
spf_result_guessed = FALSE;
}



/*API*/
/* spf_process adds the envelope sender address to the existing
   context (if any), retrieves the result, sets up expansion
   strings and evaluates the condition outcome.

Arguments:
  listptr		a list of result-words, colon-sep by default
  spf_envelope_sender	the 2821.mfrom address
  action		SPF_PROCESS_NORMAL or SPF_PROCESS_GUESS

Return: OK/FAIL  */

static int
spf_process(const uschar ** listptr, const uschar * spf_envelope_sender,
  int action)
{
int res = FAIL, sep;
const uschar * arglist = *listptr;

expand_level++;
DEBUG(D_acl)
  debug_printf_indent("%s: mfrom:<%s>\n", __FUNCTION__, spf_envelope_sender);

if (!setup_spf_perl_mi())
  return FAIL;

if (!(conn_helo && conn_addr))
  spf_result = US"permerror";

else
  {
  const uschar * argv[4] = {spf_envelope_sender, conn_addr, conn_helo, NULL};
  gstring * g;
  uschar * res_list, * s;

  if (!(g = call_my_spf_req(argv)))
    goto out;

  res_list = US string_from_gstring(g);
  sep = '\n';

  spf_result = string_nextinlist(CUSS &res_list, &sep, NULL, 0);
  DEBUG(D_acl) debug_printf_indent("SPF result is %s\n", spf_received);

  spf_received = res_list;		/* remainder of the returned string */

  while (*res_list++ != ':') ;
  spf_header_comment = res_list;	/* ditto with header name skipped */
  if ((s = Ustrchr(res_list, '(')))
    {
    uschar * t = Ustrchr(s, ')');	/* grab a (comment) if there is one */
    if (t) spf_header_comment = string_copyn(s+1, t-s-1);
    }
  }

sep = 0;
for (uschar * ele; ele = string_nextinlist(&arglist, &sep, NULL, 0); )
  {
  BOOL negate, result;

  if ((negate = *ele == '!'))
    ele++;

  result = Ustrcmp(ele, spf_result) == 0;
  if (negate != result) { res = OK; break; }
  }
/* if the loop ran out of list, no match */

out:
  expand_level--;
  return res;
}



/*API*/
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


/*API, for dmarc */
static int
spf_get_results(uschar ** human_readable_p)
{
uschar * s = NULL;
int res = SPF_RESULT_INVALID;

/* Translate result word to number */

if (spf_result)
  {
  for (spf_result_id * sip = spf_result_id_list;
       sip < spf_result_id_list + nelem(spf_result_id_list);
       sip++)
    if (Ustrcmp(spf_result, sip->name) == 0) { res = sip->value; break; }

  s = spf_header_comment;
  }

*human_readable_p = s ? string_copy(s) : US"";
DEBUG(D_acl) debug_printf_indent(" SPF: %d '%s'\n", res, s);
return res;
}


/******************************************************************************/
/* Lookup support */

/*API*/
static void *
spf_lookup_open(const uschar * filename, uschar ** errmsg)
{
return (void *)1;
}

/*API*/
static void
spf_lookup_close(void * handle)
{
}

/*API: keystring is the email addr (mfrom), "filename" is an IP - presumably
the sender_host_addr equivalent */

static int
spf_lookup_find(void * handle, const uschar * filename,
  const uschar * keystring, int key_len, uschar ** result, uschar ** errmsg,
  uint * do_cache, const uschar * opts)
{
int res = FAIL;

expand_level++;
DEBUG(D_acl) debug_printf_indent("%s: mfrom:<%s> ip %q\n", __FUNCTION__,
				  keystring, filename);

if (setup_spf_perl_mi())
  if (!filename)
    *result = US"permerror";
  else
    {
    const uschar * argv[4] = {keystring, filename, conn_helo, NULL};
    gstring * g;

    if ((g = call_my_spf_req(argv)))
      {
      uschar * res_list = US string_from_gstring(g);
      int sep = '\n';
      *result = string_nextinlist(CUSS &res_list, &sep, NULL, 0);
      DEBUG(D_acl) debug_printf_indent("SPF result is %s\n", *result);
      res = OK;
      }
    }

return res;
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
};

misc_module_info spf_module_info =
{
  .name =		US"spf",
# ifdef DYNLOOKUP
  .dyn_magic =		MISC_MODULE_MAGIC,
# endif
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
