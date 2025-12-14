/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2023 - 2025 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"

#ifdef EXPERIMENTAL_XCLIENT

/* This is a proxy protocol.

From https://www.postfix.org/XCLIENT_README.html I infer two generations of
protocol.  The more recent one obviates the utility of the HELO attribute, since
it mandates the proxy always sending a HELO/EHLO smtp command following (a
successful) XCLIENT command, and that will carry a NELO name (which we assume,
though it isn't specified, will be the actual one presented to the proxy by the
possibly-new client).  The same applies to the PROTO attribute. */

# define XCLIENT_V2

enum xclient_cmd_e {
  XCLIENT_CMD_UNKNOWN,
  XCLIENT_CMD_ADDR,
  XCLIENT_CMD_NAME,
  XCLIENT_CMD_PORT,
  XCLIENT_CMD_LOGIN,
  XCLIENT_CMD_DESTADDR,
  XCLIENT_CMD_DESTPORT,
# ifdef XCLIENT_V1
  XCLIENT_CMD_HELO,
  XCLIENT_CMD_PROTO,
# endif
};

struct xclient_cmd {
  const uschar *	str;
  unsigned		len;
} xclient_cmds[] = {
  [XCLIENT_CMD_UNKNOWN] = { NULL },
  [XCLIENT_CMD_ADDR] =	{ US"ADDR",  4 },
  [XCLIENT_CMD_NAME] =	{ US"NAME",  4 },
  [XCLIENT_CMD_PORT] =	{ US"PORT",  4 },
  [XCLIENT_CMD_LOGIN] =	{ US"LOGIN", 5 },
  [XCLIENT_CMD_DESTADDR] =	{ US"DESTADDR", 8 },
  [XCLIENT_CMD_DESTPORT] =	{ US"DESTPORT", 8 },
# ifdef XCLIENT_V1
  [XCLIENT_CMD_HELO] =	{ US"HELO",  4 },
  [XCLIENT_CMD_PROTO] =	{ US"PROTO", 5 },
# endif
};

/*************************************************
*          XCLIENT proxy implementation          *
*************************************************/

/* Arguments:
  code        points to the coded string
  end         points to the end of coded string
  ptr         where to put the pointer to the result, which is in
              dynamic store
Returns:      the number of bytes in the result, excluding the final zero;
              -1 if the input is malformed
*/

static int
xclient_xtextdecode(const uschar * code, const uschar * end, uschar ** ptr)
{
return xtextdecode(string_copyn(code, end-code), ptr);
}

/*************************************************
*   Check XCLIENT line and set sender_address    *
*************************************************/


/* Check the format of a XCLIENT line.
Arguments:
  s       	the data portion of the line (already past any white space)
  resp		result: smtp respose code
  flagp		input: helo seen  output: fail is fatal

Return: NULL on success, or error message
*/

# define XCLIENT_UNAVAIL     US"[UNAVAILABLE]"
# define XCLIENT_TEMPUNAVAIL US"[TEMPUNAVAIL]"

static uschar *
xclient_smtp_command(const uschar * s, int * resp, BOOL * flagp)
{
const uschar * word = s;
uschar * errmsg = NULL;
enum {
  XCLIENT_READ_COMMAND = 0,
  XCLIENT_READ_VALUE,
  XCLIENT_SKIP_SPACES
} state = XCLIENT_SKIP_SPACES;
enum xclient_cmd_e cmd;
static BOOL xc_proxy_session = FALSE;

if (  !*flagp
   && verify_check_host(&hosts_require_helo) == OK)
  {
  *resp = 503;
  *flagp= FALSE;
  return US"no HELO/EHLO given";
  }

/* If already in a proxy session, do not re-check permission. */

if (!xc_proxy_session && verify_check_host(&hosts_xclient) == FAIL)
  {
  *resp = 501;
  *flagp= TRUE;
  return US"XCLIENT command used when not advertised";
  }

if (sender_address)
  {
  *resp = 503;
  *flagp= FALSE;
  return US"mail transaction in progress";
  }

if (!*word)
  {
  errmsg = US"XCLIENT must have at least one operand";
  goto fatal_501;
  }

for (state = XCLIENT_SKIP_SPACES; *s; )
  switch (state)
    {
    case XCLIENT_READ_COMMAND:
      {
      int len;

      word = s;
      while (*s && *s != '=') s++;
      len = s - word;
      if (!*s)
	{
	errmsg = string_sprintf("XCLIENT: missing value for parameter '%.*s'",
			  len, word);
	goto fatal_501;
	}

      DEBUG(D_transport) debug_printf(" XCLIENT: cmd %.*s\n", len, word);
      cmd = XCLIENT_CMD_UNKNOWN;
      for (struct xclient_cmd * x = xclient_cmds + 1;
	   x < xclient_cmds + nelem(xclient_cmds); x++)
	if (len == x->len && strncmpic(word, x->str, len) == 0)
	  {
	  cmd = x - xclient_cmds;
	  break;
	  }
      if (cmd == XCLIENT_CMD_UNKNOWN)
	{
	errmsg = string_sprintf("XCLIENT: unrecognised parameter '%.*s'",
			  len, word);
	goto fatal_501;
	}
      state = XCLIENT_READ_VALUE;
      }
      break;

    case XCLIENT_READ_VALUE:
      {
      int old_pool = store_pool;
      int len;
      uschar * val;

      word = ++s;			/* skip the = */
      Uskip_nonwhite(&s);
      len = s - word;

      DEBUG(D_transport) debug_printf(" XCLIENT: \tvalue %.*s\n", len, word);
      if (len == 0)
	{ errmsg = US"XCLIENT: zero-length value for param"; goto fatal_501; }

      if (  len == 13
	 && (  strncmpic(word, XCLIENT_UNAVAIL, 13) == 0
	    || strncmpic(word, XCLIENT_TEMPUNAVAIL, 13) == 0
	 )  )
	val = NULL;

      else if ((len = xclient_xtextdecode(word, s, &val)) == -1)
	{
	errmsg = string_sprintf("failed xtext decode for XCLIENT: '%.*s'", len, word);
	goto fatal_501;
	}

      store_pool = POOL_PERM;
      switch (cmd)
	{
	case XCLIENT_CMD_ADDR:
	  proxy_local_address = sender_host_address;
	  sender_host_address = val ? string_copyn(val, len) : NULL;
	  break;
	case XCLIENT_CMD_NAME:
	  sender_host_name = val ? string_copyn(val, len) : NULL;
	  break;
	case XCLIENT_CMD_PORT:
	  proxy_local_port = sender_host_port;
	  sender_host_port = val ? Uatoi(val) : 0;
	  break;
	case XCLIENT_CMD_DESTADDR:
	  proxy_external_address = val ? string_copyn(val, len) : NULL;
	  break;
	case XCLIENT_CMD_DESTPORT:
	  proxy_external_port = val ? Uatoi(val) : 0;
	  break;

	case XCLIENT_CMD_LOGIN:
	  if (val)
	    {
	    authenticated_id = string_copyn(val, len);
	    sender_host_authenticated = US"xclient";
	    authentication_failed = FALSE;
	    }
	  else
	    {
	    authenticated_id = NULL;
	    sender_host_authenticated = NULL;
	    }
	  break;

# ifdef XCLIENT_V1
	case XCLIENT_CMD_HELO:
	  sender_helo_name = val ? string_copyn(val, len) : NULL;
	  break;
	case XCLIENT_CMD_PROTO:
	  if (!val)
	    { store_pool = old_pool; errmsg = US"missing proto for XCLIENT"; goto fatal_501; }
	  else if (len == 4 && strncmpic(val, US"SMTP", 4) == 0)
	    *esmtpflag = FALSE;	/* function arg */
	  else if (len == 5 && strncmpic(val, US"ESMTP", 5) == 0)
	    *esmtpflag = TRUE;
	  else
	    { store_pool = old_pool; errmsg = US"bad proto for XCLIENT"; goto fatal_501; }
	  break;
# endif
	default: break;	/* stupid compiler silencing */
	}
      store_pool = old_pool;
      state = XCLIENT_SKIP_SPACES;
      break;
      }

    case XCLIENT_SKIP_SPACES:
      Uskip_whitespace(&s);
      state = XCLIENT_READ_COMMAND;
      break;

    default:
      errmsg = US"unhandled XCLIENT parameter type";
      goto fatal_501;
    }

if (!proxy_local_address)
  { errmsg = US"missing ADDR for XCLIENT"; goto fatal_501; }
if (!proxy_local_port)
  { errmsg = US"missing PORT for XCLIENT"; goto fatal_501; }
if (state != XCLIENT_SKIP_SPACES)
  { errmsg = US"bad state parsing XCLIENT parameters"; goto fatal_501; }

host_build_sender_fullhost();
proxy_session = TRUE;		/* global */
xc_proxy_session = TRUE;	/* local */
*resp = 220;
return NULL;

fatal_501:
  *flagp= TRUE;
  *resp = 501;
  return errmsg;
}

# undef XCLIENT_UNAVAIL
# undef XCLIENT_TEMPUNAVAIL


/*API*/
static gstring *
xclient_smtp_advertise_str(gstring * g)
{
g = string_catn(g, US"-XCLIENT ", 8);
for (int i = 1; i < nelem(xclient_cmds); i++)
  {
  g = string_catn(g, US" ", 1);
  g = string_cat(g, xclient_cmds[i].str);
  }
return string_catn(g, US"\r\n", 2);
}


/*API
Return: true if the cmd was good and the protocol started
*/

static int
xclient_protocol_start(const uschar * smtp_cmd_data, int * donep,
  BOOL helo_seen)
{
BOOL fatal = helo_seen;
uschar * errmsg;
int resp;

if (!(errmsg = xclient_smtp_command(smtp_cmd_data, &resp, &fatal)))
  {
  /*XXX unclear in spec. if this needs to be an ESMTP banner,
  nor whether we get the original client's HELO after (or a proxy fake).
  We require that we do; the following HELO/EHLO handling will set
  sender_helo_name as normal. */

  smtp_printf("%d XCLIENT success\r\n", SP_NO_MORE, resp);
  return TRUE;
  }
else if (fatal)
  *donep = synprot_error(L_smtp_syntax_error, resp, NULL, errmsg);
else
  {
  smtp_printf("%d %s\r\n", SP_NO_MORE, resp, errmsg);
  log_write(0, LOG_MAIN|LOG_REJECT, "rejected XCLIENT from %s: %s",
    host_and_ident(FALSE), errmsg);
  }
  
return FALSE;
}

/******************************************************************************/
/* Module API */

static void * xclient_functions[] = {
  [XCLIENT_PROTO_ADVERTISE] =	(void *) xclient_smtp_advertise_str,
  [XCLIENT_PROTO_START] =	(void *) xclient_protocol_start,
};

misc_module_info xclient_module_info =
{
  .name =		US"xclient",
# ifdef DYNLOOKUP
  .dyn_magic =		MISC_MODULE_MAGIC,
# endif
  .functions =		xclient_functions,
  .functions_count =	nelem(xclient_functions),
};
#endif	/*EXPERIMENTAL_XCLIENT*/

/* vi: aw ai sw=2
*/
/* End of xclient.c */

