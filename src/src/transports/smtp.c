/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "smtp.h"

#if defined(SUPPORT_DANE) && defined(DISABLE_TLS)
# error TLS is required for DANE
#endif


/* Options specific to the smtp transport. This transport also supports LMTP
over TCP/IP. The options must be in alphabetic order (note that "_" comes
before the lower case letters). Some live in the transport_instance block so as
to be publicly visible; these are flagged with opt_public. */

#define LOFF(field) OPT_OFF(smtp_transport_options_block, field)

optionlist smtp_transport_options[] = {
  { "*expand_multi_domain",             opt_stringptr | opt_hidden | opt_public,
      OPT_OFF(transport_instance, expand_multi_domain) },
  { "*expand_retry_include_ip_address", opt_stringptr | opt_hidden,
      LOFF(expand_retry_include_ip_address) },

  { "address_retry_include_sender", opt_bool,
      LOFF(address_retry_include_sender) },
  { "allow_localhost",      opt_bool,	   LOFF(allow_localhost) },
#ifdef EXPERIMENTAL_ARC
  { "arc_sign", opt_stringptr,		   LOFF(arc_sign) },
#endif
  { "authenticated_sender", opt_stringptr, LOFF(authenticated_sender) },
  { "authenticated_sender_force", opt_bool, LOFF(authenticated_sender_force) },
  { "command_timeout",      opt_time,	   LOFF(command_timeout) },
  { "connect_timeout",      opt_time,	   LOFF(connect_timeout) },
  { "connection_max_messages", opt_int | opt_public,
      OPT_OFF(transport_instance, connection_max_messages) },
# ifdef SUPPORT_DANE
  { "dane_require_tls_ciphers", opt_stringptr, LOFF(dane_require_tls_ciphers) },
# endif
  { "data_timeout",         opt_time,	   LOFF(data_timeout) },
  { "delay_after_cutoff",   opt_bool,	   LOFF(delay_after_cutoff) },
#ifndef DISABLE_DKIM
  { "dkim_canon", opt_stringptr,	   LOFF(dkim.dkim_canon) },
  { "dkim_domain", opt_stringptr,	   LOFF(dkim.dkim_domain) },
  { "dkim_hash", opt_stringptr,		   LOFF(dkim.dkim_hash) },
  { "dkim_identity", opt_stringptr,	   LOFF(dkim.dkim_identity) },
  { "dkim_private_key", opt_stringptr,	   LOFF(dkim.dkim_private_key) },
  { "dkim_selector", opt_stringptr,	   LOFF(dkim.dkim_selector) },
  { "dkim_sign_headers", opt_stringptr,	   LOFF(dkim.dkim_sign_headers) },
  { "dkim_strict", opt_stringptr,	   LOFF(dkim.dkim_strict) },
  { "dkim_timestamps", opt_stringptr,	   LOFF(dkim.dkim_timestamps) },
#endif
  { "dns_qualify_single",   opt_bool,	   LOFF(dns_qualify_single) },
  { "dns_search_parents",   opt_bool,	   LOFF(dns_search_parents) },
  { "dnssec_request_domains", opt_stringptr, LOFF(dnssec.request) },
  { "dnssec_require_domains", opt_stringptr, LOFF(dnssec.require) },
  { "dscp",                 opt_stringptr, LOFF(dscp) },
  { "fallback_hosts",       opt_stringptr, LOFF(fallback_hosts) },
  { "final_timeout",        opt_time,	   LOFF(final_timeout) },
  { "gethostbyname",        opt_bool,	   LOFF(gethostbyname) },
  { "helo_data",            opt_stringptr, LOFF(helo_data) },
  { "hosts",                opt_stringptr, LOFF(hosts) },
  { "hosts_avoid_esmtp",    opt_stringptr, LOFF(hosts_avoid_esmtp) },
  { "hosts_avoid_pipelining", opt_stringptr, LOFF(hosts_avoid_pipelining) },
#ifndef DISABLE_TLS
  { "hosts_avoid_tls",      opt_stringptr, LOFF(hosts_avoid_tls) },
#endif
  { "hosts_max_try",        opt_int,	   LOFF(hosts_max_try) },
  { "hosts_max_try_hardlimit", opt_int,	   LOFF(hosts_max_try_hardlimit) },
#ifndef DISABLE_TLS
  { "hosts_nopass_tls",     opt_stringptr, LOFF(hosts_nopass_tls) },
  { "hosts_noproxy_tls",    opt_stringptr, LOFF(hosts_noproxy_tls) },
#endif
  { "hosts_override",       opt_bool,	   LOFF(hosts_override) },
#ifndef DISABLE_PIPE_CONNECT
  { "hosts_pipe_connect",   opt_stringptr, LOFF(hosts_pipe_connect) },
#endif
  { "hosts_randomize",      opt_bool,	   LOFF(hosts_randomize) },
#if !defined(DISABLE_TLS) && !defined(DISABLE_OCSP)
  { "hosts_request_ocsp",   opt_stringptr, LOFF(hosts_request_ocsp) },
#endif
  { "hosts_require_auth",   opt_stringptr, LOFF(hosts_require_auth) },
#ifndef DISABLE_TLS
# ifdef SUPPORT_DANE
  { "hosts_require_dane",   opt_stringptr, LOFF(hosts_require_dane) },
# endif
# ifndef DISABLE_OCSP
  { "hosts_require_ocsp",   opt_stringptr, LOFF(hosts_require_ocsp) },
# endif
  { "hosts_require_tls",    opt_stringptr, LOFF(hosts_require_tls) },
#endif
  { "hosts_try_auth",       opt_stringptr, LOFF(hosts_try_auth) },
  { "hosts_try_chunking",   opt_stringptr, LOFF(hosts_try_chunking) },
#ifdef SUPPORT_DANE
  { "hosts_try_dane",       opt_stringptr, LOFF(hosts_try_dane) },
#endif
  { "hosts_try_fastopen",   opt_stringptr, LOFF(hosts_try_fastopen) },
#ifndef DISABLE_PRDR
  { "hosts_try_prdr",       opt_stringptr, LOFF(hosts_try_prdr) },
#endif
#ifndef DISABLE_TLS
  { "hosts_verify_avoid_tls", opt_stringptr, LOFF(hosts_verify_avoid_tls) },
#endif
  { "interface",            opt_stringptr, LOFF(interface) },
  { "keepalive",            opt_bool,	   LOFF(keepalive) },
  { "lmtp_ignore_quota",    opt_bool,	   LOFF(lmtp_ignore_quota) },
  { "max_rcpt",             opt_int | opt_public,
      OPT_OFF(transport_instance, max_addresses) },
  { "message_linelength_limit", opt_int,   LOFF(message_linelength_limit) },
  { "multi_domain",         opt_expand_bool | opt_public,
      OPT_OFF(transport_instance, multi_domain) },
  { "port",                 opt_stringptr, LOFF(port) },
  { "protocol",             opt_stringptr, LOFF(protocol) },
  { "retry_include_ip_address", opt_expand_bool, LOFF(retry_include_ip_address) },
  { "serialize_hosts",      opt_stringptr, LOFF(serialize_hosts) },
  { "size_addition",        opt_int,	   LOFF(size_addition) },
#ifdef SUPPORT_SOCKS
  { "socks_proxy",          opt_stringptr, LOFF(socks_proxy) },
#endif
#ifndef DISABLE_TLS
  { "tls_certificate",      opt_stringptr, LOFF(tls_certificate) },
  { "tls_crl",              opt_stringptr, LOFF(tls_crl) },
  { "tls_dh_min_bits",      opt_int,	   LOFF(tls_dh_min_bits) },
  { "tls_privatekey",       opt_stringptr, LOFF(tls_privatekey) },
  { "tls_require_ciphers",  opt_stringptr, LOFF(tls_require_ciphers) },
# ifndef DISABLE_TLS_RESUME
  { "tls_resumption_hosts", opt_stringptr, LOFF(tls_resumption_hosts) },
# endif
  { "tls_sni",              opt_stringptr, LOFF(tls_sni) },
  { "tls_tempfail_tryclear", opt_bool, LOFF(tls_tempfail_tryclear) },
  { "tls_try_verify_hosts", opt_stringptr, LOFF(tls_try_verify_hosts) },
  { "tls_verify_cert_hostnames", opt_stringptr, LOFF(tls_verify_cert_hostnames)},
  { "tls_verify_certificates", opt_stringptr, LOFF(tls_verify_certificates) },
  { "tls_verify_hosts",     opt_stringptr, LOFF(tls_verify_hosts) },
#endif
#ifdef SUPPORT_I18N
  { "utf8_downconvert",	    opt_stringptr, LOFF(utf8_downconvert) },
#endif
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int smtp_transport_options_count = nelem(smtp_transport_options);


#ifdef MACRO_PREDEF

/* Dummy values */
smtp_transport_options_block smtp_transport_option_defaults = {0};
void smtp_transport_init(transport_instance *tblock) {}
BOOL smtp_transport_entry(transport_instance *tblock, address_item *addr) {return FALSE;}
void smtp_transport_closedown(transport_instance *tblock) {}

#else   /*!MACRO_PREDEF*/


/* Default private options block for the smtp transport. */

smtp_transport_options_block smtp_transport_option_defaults = {
  /* All non-mentioned elements 0/NULL/FALSE */
  .helo_data =			US"$primary_hostname",
  .protocol =			US"smtp",
  .hosts_try_chunking =		US"*",
#ifdef SUPPORT_DANE
  .hosts_try_dane =		US"*",
#endif
  .hosts_try_fastopen =		US"*",
#ifndef DISABLE_PRDR
  .hosts_try_prdr =		US"*",
#endif
#ifndef DISABLE_OCSP
  .hosts_request_ocsp =		US"*",               /* hosts_request_ocsp (except under DANE; tls_client_start()) */
#endif
  .command_timeout =		5*60,
  .connect_timeout =		5*60,
  .data_timeout =		5*60,
  .final_timeout =		10*60,
  .size_addition =		1024,
  .hosts_max_try =		5,
  .hosts_max_try_hardlimit =	50,
  .message_linelength_limit =	998,
  .address_retry_include_sender = TRUE,
  .dns_qualify_single =		TRUE,
  .dnssec = { .request= US"*", .require=NULL },
  .delay_after_cutoff =		TRUE,
  .keepalive =			TRUE,
  .retry_include_ip_address =	TRUE,
#ifndef DISABLE_TLS
# if defined(SUPPORT_SYSDEFAULT_CABUNDLE) || !defined(USE_GNUTLS)
  .tls_verify_certificates =	US"system",
# endif
  .tls_dh_min_bits =		EXIM_CLIENT_DH_DEFAULT_MIN_BITS,
  .tls_tempfail_tryclear =	TRUE,
  .tls_try_verify_hosts =	US"*",
  .tls_verify_cert_hostnames =	US"*",
#endif
#ifdef SUPPORT_I18N
  .utf8_downconvert =		US"-1",
#endif
#ifndef DISABLE_DKIM
 .dkim =
   { .dkim_hash =		US"sha256", },
#endif
};

/* some DSN flags for use later */

static int     rf_list[] = {rf_notify_never, rf_notify_success,
                            rf_notify_failure, rf_notify_delay };

static uschar *rf_names[] = { US"NEVER", US"SUCCESS", US"FAILURE", US"DELAY" };



/* Local statics */

static uschar *smtp_command;		/* Points to last cmd for error messages */
static uschar *mail_command;		/* Points to MAIL cmd for error messages */
static uschar *data_command = US"";	/* Points to DATA cmd for error messages */
static BOOL    update_waiting;		/* TRUE to update the "wait" database */

/*XXX move to smtp_context */
static BOOL    pipelining_active;	/* current transaction is in pipe mode */


static unsigned ehlo_response(uschar * buf, unsigned checks);


/******************************************************************************/

void
smtp_deliver_init(void)
{
if (!regex_PIPELINING) regex_PIPELINING =
  regex_must_compile(US"\\n250[\\s\\-]PIPELINING(\\s|\\n|$)", FALSE, TRUE);

if (!regex_SIZE) regex_SIZE =
  regex_must_compile(US"\\n250[\\s\\-]SIZE(\\s|\\n|$)", FALSE, TRUE);

if (!regex_AUTH) regex_AUTH =
  regex_must_compile(AUTHS_REGEX, FALSE, TRUE);

#ifndef DISABLE_TLS
if (!regex_STARTTLS) regex_STARTTLS =
  regex_must_compile(US"\\n250[\\s\\-]STARTTLS(\\s|\\n|$)", FALSE, TRUE);
#endif

if (!regex_CHUNKING) regex_CHUNKING =
  regex_must_compile(US"\\n250[\\s\\-]CHUNKING(\\s|\\n|$)", FALSE, TRUE);

#ifndef DISABLE_PRDR
if (!regex_PRDR) regex_PRDR =
  regex_must_compile(US"\\n250[\\s\\-]PRDR(\\s|\\n|$)", FALSE, TRUE);
#endif

#ifdef SUPPORT_I18N
if (!regex_UTF8) regex_UTF8 =
  regex_must_compile(US"\\n250[\\s\\-]SMTPUTF8(\\s|\\n|$)", FALSE, TRUE);
#endif

if (!regex_DSN) regex_DSN  =
  regex_must_compile(US"\\n250[\\s\\-]DSN(\\s|\\n|$)", FALSE, TRUE);

if (!regex_IGNOREQUOTA) regex_IGNOREQUOTA =
  regex_must_compile(US"\\n250[\\s\\-]IGNOREQUOTA(\\s|\\n|$)", FALSE, TRUE);

#ifndef DISABLE_PIPE_CONNECT
if (!regex_EARLY_PIPE) regex_EARLY_PIPE =
  regex_must_compile(US"\\n250[\\s\\-]" EARLY_PIPE_FEATURE_NAME "(\\s|\\n|$)", FALSE, TRUE);
#endif

#ifdef EXPERIMENTAL_ESMTP_LIMITS
if (!regex_LIMITS) regex_LIMITS =
  regex_must_compile(US"\\n250[\\s\\-]LIMITS\\s", FALSE, TRUE);
#endif
}


/*************************************************
*             Setup entry point                  *
*************************************************/

/* This function is called when the transport is about to be used,
but before running it in a sub-process. It is used for two things:

  (1) To set the fallback host list in addresses, when delivering.
  (2) To pass back the interface, port, protocol, and other options, for use
      during callout verification.

Arguments:
  tblock    pointer to the transport instance block
  addrlist  list of addresses about to be transported
  tf        if not NULL, pointer to block in which to return options
  uid       the uid that will be set (not used)
  gid       the gid that will be set (not used)
  errmsg    place for error message (not used)

Returns:  OK always (FAIL, DEFER not used)
*/

static int
smtp_transport_setup(transport_instance *tblock, address_item *addrlist,
  transport_feedback *tf, uid_t uid, gid_t gid, uschar **errmsg)
{
smtp_transport_options_block *ob = SOB tblock->options_block;

/* Pass back options if required. This interface is getting very messy. */

if (tf)
  {
  tf->interface = ob->interface;
  tf->port = ob->port;
  tf->protocol = ob->protocol;
  tf->hosts = ob->hosts;
  tf->hosts_override = ob->hosts_override;
  tf->hosts_randomize = ob->hosts_randomize;
  tf->gethostbyname = ob->gethostbyname;
  tf->qualify_single = ob->dns_qualify_single;
  tf->search_parents = ob->dns_search_parents;
  tf->helo_data = ob->helo_data;
  }

/* Set the fallback host list for all the addresses that don't have fallback
host lists, provided that the local host wasn't present in the original host
list. */

if (!testflag(addrlist, af_local_host_removed))
  for (; addrlist; addrlist = addrlist->next)
    if (!addrlist->fallback_hosts) addrlist->fallback_hosts = ob->fallback_hostlist;

return OK;
}



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up.

Argument:   pointer to the transport instance block
Returns:    nothing
*/

void
smtp_transport_init(transport_instance *tblock)
{
smtp_transport_options_block *ob = SOB tblock->options_block;

/* Retry_use_local_part defaults FALSE if unset */

if (tblock->retry_use_local_part == TRUE_UNSET)
  tblock->retry_use_local_part = FALSE;

/* Set the default port according to the protocol */

if (!ob->port)
  ob->port = strcmpic(ob->protocol, US"lmtp") == 0
  ? US"lmtp"
  : strcmpic(ob->protocol, US"smtps") == 0
  ? US"smtps" : US"smtp";

/* Set up the setup entry point, to be called before subprocesses for this
transport. */

tblock->setup = smtp_transport_setup;

/* Complain if any of the timeouts are zero. */

if (ob->command_timeout <= 0 || ob->data_timeout <= 0 ||
    ob->final_timeout <= 0)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "command, data, or final timeout value is zero for %s transport",
      tblock->name);

/* If hosts_override is set and there are local hosts, set the global
flag that stops verify from showing router hosts. */

if (ob->hosts_override && ob->hosts) tblock->overrides_hosts = TRUE;

/* If there are any fallback hosts listed, build a chain of host items
for them, but do not do any lookups at this time. */

host_build_hostlist(&(ob->fallback_hostlist), ob->fallback_hosts, FALSE);
}





/*************************************************
*   Set delivery info into all active addresses  *
*************************************************/

/* Only addresses whose status is >= PENDING are relevant. A lesser
status means that an address is not currently being processed.

Arguments:
  addrlist       points to a chain of addresses
  errno_value    to put in each address's errno field
  msg            to put in each address's message field
  rc             to put in each address's transport_return field
  pass_message   if TRUE, set the "pass message" flag in the address
  host           if set, mark addrs as having used this host
  smtp_greeting  from peer
  helo_response  from peer
  start		 points to timestamp of delivery start

If errno_value has the special value ERRNO_CONNECTTIMEOUT, ETIMEDOUT is put in
the errno field, and RTEF_CTOUT is ORed into the more_errno field, to indicate
this particular type of timeout.

Returns:       nothing
*/

static void
set_errno(address_item *addrlist, int errno_value, uschar *msg, int rc,
  BOOL pass_message, host_item * host,
#ifdef EXPERIMENTAL_DSN_INFO
  const uschar * smtp_greeting, const uschar * helo_response,
#endif
  struct timeval * start
  )
{
int orvalue = 0;
struct timeval deliver_time;

if (errno_value == ERRNO_CONNECTTIMEOUT)
  {
  errno_value = ETIMEDOUT;
  orvalue = RTEF_CTOUT;
  }
timesince(&deliver_time, start);

for (address_item * addr = addrlist; addr; addr = addr->next)
  if (addr->transport_return >= PENDING)
    {
    addr->basic_errno = errno_value;
    addr->more_errno |= orvalue;
    addr->delivery_time = deliver_time;
    if (msg)
      {
      addr->message = msg;
      if (pass_message) setflag(addr, af_pass_message);
      }
    addr->transport_return = rc;
    if (host)
      {
      addr->host_used = host;
#ifdef EXPERIMENTAL_DSN_INFO
      if (smtp_greeting)
	{uschar * s = Ustrchr(smtp_greeting, '\n'); if (s) *s = '\0';}
      addr->smtp_greeting = smtp_greeting;

      if (helo_response)
	{uschar * s = Ustrchr(helo_response, '\n'); if (s) *s = '\0';}
      addr->helo_response = helo_response;
#endif
      }
    }
}

static void
set_errno_nohost(address_item * addrlist, int errno_value, uschar * msg, int rc,
  BOOL pass_message, struct timeval * start)
{
set_errno(addrlist, errno_value, msg, rc, pass_message, NULL,
#ifdef EXPERIMENTAL_DSN_INFO
	  NULL, NULL,
#endif
	  start);
}


/*************************************************
*          Check an SMTP response                *
*************************************************/

/* This function is given an errno code and the SMTP response buffer
to analyse, together with the host identification for generating messages. It
sets an appropriate message and puts the first digit of the response code into
the yield variable. If no response was actually read, a suitable digit is
chosen.

Arguments:
  host           the current host, to get its name for messages
  errno_value    pointer to the errno value
  more_errno     from the top address for use with ERRNO_FILTER_FAIL
  buffer         the SMTP response buffer
  yield          where to put a one-digit SMTP response code
  message        where to put an error message
  pass_message   set TRUE if message is an SMTP response

Returns:         TRUE if an SMTP "QUIT" command should be sent, else FALSE
*/

static BOOL
check_response(host_item *host, int *errno_value, int more_errno,
  uschar *buffer, int *yield, uschar **message, BOOL *pass_message)
{
uschar * pl = pipelining_active ? US"pipelined " : US"";
const uschar * s;

*yield = '4';    /* Default setting is to give a temporary error */

switch(*errno_value)
  {
  case ETIMEDOUT:		/* Handle response timeout */
    *message = US string_sprintf("SMTP timeout after %s%s",
	pl, smtp_command);
    if (transport_count > 0)
      *message = US string_sprintf("%s (%d bytes written)", *message,
	transport_count);
    return FALSE;

  case ERRNO_SMTPFORMAT:	/* Handle malformed SMTP response */
    s = string_printing(buffer);
    while (isspace(*s)) s++;
    *message = *s == 0
      ? string_sprintf("Malformed SMTP reply (an empty line) "
	  "in response to %s%s", pl, smtp_command)
      : string_sprintf("Malformed SMTP reply in response to %s%s: %s",
	  pl, smtp_command, s);
    return FALSE;

  case ERRNO_TLSFAILURE:	/* Handle bad first read; can happen with
				GnuTLS and TLS1.3 */
    *message = US"bad first read from TLS conn";
    return TRUE;

  case ERRNO_FILTER_FAIL:	/* Handle a failed filter process error;
			  can't send QUIT as we mustn't end the DATA. */
    *message = string_sprintf("transport filter process failed (%d)%s",
      more_errno,
      more_errno == EX_EXECFAILED ? ": unable to execute command" : "");
    return FALSE;

  case ERRNO_CHHEADER_FAIL:	/* Handle a failed add_headers expansion;
			    can't send QUIT as we mustn't end the DATA. */
    *message =
      string_sprintf("failed to expand headers_add or headers_remove: %s",
	expand_string_message);
    return FALSE;

  case ERRNO_WRITEINCOMPLETE:	/* failure to write a complete data block */
    *message = US"failed to write a data block";
    return FALSE;

#ifdef SUPPORT_I18N
  case ERRNO_UTF8_FWD: /* no advertised SMTPUTF8, for international message */
    *message = US"utf8 support required but not offered for forwarding";
    DEBUG(D_deliver|D_transport) debug_printf("%s\n", *message);
    return TRUE;
#endif
  }

/* Handle error responses from the remote mailer. */

if (buffer[0] != 0)
  {
  *message = string_sprintf("SMTP error from remote mail server after %s%s: "
    "%s", pl, smtp_command, s = string_printing(buffer));
  *pass_message = TRUE;
  *yield = buffer[0];
  return TRUE;
  }

/* No data was read. If there is no errno, this must be the EOF (i.e.
connection closed) case, which causes deferral. An explicit connection reset
error has the same effect. Otherwise, put the host's identity in the message,
leaving the errno value to be interpreted as well. In all cases, we have to
assume the connection is now dead. */

if (*errno_value == 0 || *errno_value == ECONNRESET)
  {
  *errno_value = ERRNO_SMTPCLOSED;
  *message = US string_sprintf("Remote host closed connection "
    "in response to %s%s", pl, smtp_command);
  }
else
  *message = US string_sprintf("%s [%s]", host->name, host->address);

return FALSE;
}



/*************************************************
*          Write error message to logs           *
*************************************************/

/* This writes to the main log and to the message log.

Arguments:
  host     the current host
  detail  the current message (addr_item->message)
  basic_errno the errno (addr_item->basic_errno)

Returns:   nothing
*/

static void
write_logs(const host_item *host, const uschar *suffix, int basic_errno)
{
gstring * message = LOGGING(outgoing_port)
  ? string_fmt_append(NULL, "H=%s [%s]:%d", host->name, host->address,
		    host->port == PORT_NONE ? 25 : host->port)
  : string_fmt_append(NULL, "H=%s [%s]", host->name, host->address);

if (suffix)
  {
  message = string_fmt_append(message, ": %s", suffix);
  if (basic_errno > 0)
    message = string_fmt_append(message, ": %s", strerror(basic_errno));
  }
else
  message = string_fmt_append(message, " %s", exim_errstr(basic_errno));

log_write(0, LOG_MAIN, "%s", string_from_gstring(message));
deliver_msglog("%s %s\n", tod_stamp(tod_log), message->s);
}

static void
msglog_line(host_item * host, uschar * message)
{
deliver_msglog("%s H=%s [%s] %s\n", tod_stamp(tod_log),
  host->name, host->address, message);
}



#ifndef DISABLE_EVENT
/*************************************************
*   Post-defer action                            *
*************************************************/

/* This expands an arbitrary per-transport string.
   It might, for example, be used to write to the database log.

Arguments:
  addr                  the address item containing error information
  host                  the current host
  evstr			the event

Returns:   nothing
*/

static void
deferred_event_raise(address_item * addr, host_item * host, uschar * evstr)
{
uschar * action = addr->transport->event_action;
const uschar * save_domain;
uschar * save_local;

if (!action)
  return;

save_domain = deliver_domain;
save_local = deliver_localpart;

/*XXX would ip & port already be set up? */
deliver_host_address = string_copy(host->address);
deliver_host_port =    host->port == PORT_NONE ? 25 : host->port;
event_defer_errno =    addr->basic_errno;

router_name =    addr->router->name;
transport_name = addr->transport->name;
deliver_domain = addr->domain;
deliver_localpart = addr->local_part;

(void) event_raise(action, evstr,
    addr->message
      ? addr->basic_errno > 0
	? string_sprintf("%s: %s", addr->message, strerror(addr->basic_errno))
	: string_copy(addr->message)
      : addr->basic_errno > 0
	? string_copy(US strerror(addr->basic_errno))
	: NULL);

deliver_localpart = save_local;
deliver_domain =    save_domain;
router_name = transport_name = NULL;
}
#endif

/*************************************************
*           Reap SMTP specific responses         *
*************************************************/
static int
smtp_discard_responses(smtp_context * sx, smtp_transport_options_block * ob,
  int count)
{
uschar flushbuffer[4096];

while (count-- > 0)
  {
  if (!smtp_read_response(sx, flushbuffer, sizeof(flushbuffer),
	     '2', ob->command_timeout)
      && (errno != 0 || flushbuffer[0] == 0))
    break;
  }
return count;
}


/* Return boolean success */

static BOOL
smtp_reap_banner(smtp_context * sx)
{
BOOL good_response;
#if defined(__linux__) && defined(TCP_QUICKACK)
  {	/* Hack to get QUICKACK disabled; has to be right after 3whs, and has to on->off */
  int sock = sx->cctx.sock;
  struct pollfd p = {.fd = sock, .events = POLLOUT};
  int rc = poll(&p, 1, 1000);
  (void) setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, US &on, sizeof(on));
  (void) setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, US &off, sizeof(off));
  }
#endif
good_response = smtp_read_response(sx, sx->buffer, sizeof(sx->buffer),
  '2', (SOB sx->conn_args.ob)->command_timeout);
#ifdef EXPERIMENTAL_DSN_INFO
sx->smtp_greeting = string_copy(sx->buffer);
#endif
return good_response;
}

static BOOL
smtp_reap_ehlo(smtp_context * sx)
{
if (!smtp_read_response(sx, sx->buffer, sizeof(sx->buffer), '2',
       (SOB sx->conn_args.ob)->command_timeout))
  {
  if (errno != 0 || sx->buffer[0] == 0 || sx->lmtp)
    {
#ifdef EXPERIMENTAL_DSN_INFO
    sx->helo_response = string_copy(sx->buffer);
#endif
    return FALSE;
    }
  sx->esmtp = FALSE;
  }
#ifdef EXPERIMENTAL_DSN_INFO
sx->helo_response = string_copy(sx->buffer);
#endif
#ifndef DISABLE_EVENT
(void) event_raise(sx->conn_args.tblock->event_action,
  US"smtp:ehlo", sx->buffer);
#endif
return TRUE;
}


/******************************************************************************/

#ifdef EXPERIMENTAL_ESMTP_LIMITS
/* If TLS, or TLS not offered, called with the EHLO response in the buffer.
Check it for a LIMITS keyword and parse values into the smtp context structure.

We don't bother with peers that we won't talk TLS to, even though they can,
just ignore their LIMITS advice (if any) and treat them as if they do not.
This saves us dealing with a duplicate set of values. */

static void
ehlo_response_limits_read(smtp_context * sx)
{
int ovec[3];	/* results vector for a main-match only */

/* matches up to just after the first space after the keyword */

if (pcre_exec(regex_LIMITS, NULL, CS sx->buffer, Ustrlen(sx->buffer),
	      0, PCRE_EOPT, ovec, nelem(ovec)) >= 0)
  for (const uschar * s = sx->buffer + ovec[1]; *s; )
    {
    while (isspace(*s)) s++;
    if (*s == '\n') break;

    if (strncmpic(s, US"MAILMAX=", 8) == 0)
      {
      sx->peer_limit_mail = atoi(CS (s += 8));
      while (isdigit(*s)) s++;
      }
    else if (strncmpic(s, US"RCPTMAX=", 8) == 0)
      {
      sx->peer_limit_rcpt = atoi(CS (s += 8));
      while (isdigit(*s)) s++;
      }
    else if (strncmpic(s, US"RCPTDOMAINMAX=", 14) == 0)
      {
      sx->peer_limit_rcptdom = atoi(CS (s += 14));
      while (isdigit(*s)) s++;
      }
    else
      while (*s && !isspace(*s)) s++;
    }
}

/* Apply given values to the current connection */
static void
ehlo_limits_apply(smtp_context * sx,
  unsigned limit_mail, unsigned limit_rcpt, unsigned limit_rcptdom)
{
if (limit_mail && limit_mail < sx->max_mail) sx->max_mail = limit_mail;
if (limit_rcpt && limit_rcpt < sx->max_rcpt) sx->max_rcpt = limit_rcpt;
if (limit_rcptdom)
  {
  DEBUG(D_transport) debug_printf("will treat as !multi_domain\n");
  sx->single_rcpt_domain = TRUE;
  }
}

/* Apply values from EHLO-resp to the current connection */
static void
ehlo_response_limits_apply(smtp_context * sx)
{
ehlo_limits_apply(sx, sx->peer_limit_mail, sx->peer_limit_rcpt,
  sx->peer_limit_rcptdom);
}

/* Apply values read from cache to the current connection */
static void
ehlo_cache_limits_apply(smtp_context * sx)
{
ehlo_limits_apply(sx, sx->ehlo_resp.limit_mail, sx->ehlo_resp.limit_rcpt,
  sx->ehlo_resp.limit_rcptdom);
}
#endif

/******************************************************************************/

#ifndef DISABLE_PIPE_CONNECT
static uschar *
ehlo_cache_key(const smtp_context * sx)
{
host_item * host = sx->conn_args.host;
return Ustrchr(host->address, ':')
  ? string_sprintf("[%s]:%d.EHLO", host->address,
    host->port == PORT_NONE ? sx->port : host->port)
  : string_sprintf("%s:%d.EHLO", host->address,
    host->port == PORT_NONE ? sx->port : host->port);
}

/* Cache EHLO-response info for use by early-pipe.
Called
- During a normal flow on EHLO response (either cleartext or under TLS),
  when we are willing to do PIPE_CONNECT and it is offered
- During an early-pipe flow on receiving the actual EHLO response and noting
  disparity versus the cached info used, when PIPE_CONNECT is still being offered

We assume that suitable values have been set in the sx.ehlo_resp structure for
features and auths; we handle the copy of limits. */

static void
write_ehlo_cache_entry(smtp_context * sx)
{
open_db dbblock, * dbm_file;

#ifdef EXPERIMENTAL_ESMTP_LIMITS
sx->ehlo_resp.limit_mail = sx->peer_limit_mail;
sx->ehlo_resp.limit_rcpt = sx->peer_limit_rcpt;
sx->ehlo_resp.limit_rcptdom = sx->peer_limit_rcptdom;
#endif

if ((dbm_file = dbfn_open(US"misc", O_RDWR, &dbblock, TRUE, TRUE)))
  {
  uschar * ehlo_resp_key = ehlo_cache_key(sx);
  dbdata_ehlo_resp er = { .data = sx->ehlo_resp };

  HDEBUG(D_transport)
#ifdef EXPERIMENTAL_ESMTP_LIMITS
    if (sx->ehlo_resp.limit_mail || sx->ehlo_resp.limit_rcpt || sx->ehlo_resp.limit_rcptdom)
      debug_printf("writing clr %04x/%04x cry %04x/%04x lim %05d/%05d/%05d\n",
	sx->ehlo_resp.cleartext_features, sx->ehlo_resp.cleartext_auths,
	sx->ehlo_resp.crypted_features, sx->ehlo_resp.crypted_auths,
	sx->ehlo_resp.limit_mail, sx->ehlo_resp.limit_rcpt,
	sx->ehlo_resp.limit_rcptdom);
    else
#endif
      debug_printf("writing clr %04x/%04x cry %04x/%04x\n",
	sx->ehlo_resp.cleartext_features, sx->ehlo_resp.cleartext_auths,
	sx->ehlo_resp.crypted_features, sx->ehlo_resp.crypted_auths);

  dbfn_write(dbm_file, ehlo_resp_key, &er, (int)sizeof(er));
  dbfn_close(dbm_file);
  }
}

static void
invalidate_ehlo_cache_entry(smtp_context * sx)
{
open_db dbblock, * dbm_file;

if (  sx->early_pipe_active
   && (dbm_file = dbfn_open(US"misc", O_RDWR, &dbblock, TRUE, TRUE)))
  {
  uschar * ehlo_resp_key = ehlo_cache_key(sx);
  dbfn_delete(dbm_file, ehlo_resp_key);
  dbfn_close(dbm_file);
  }
}

static BOOL
read_ehlo_cache_entry(smtp_context * sx)
{
open_db dbblock;
open_db * dbm_file;

if (!(dbm_file = dbfn_open(US"misc", O_RDONLY, &dbblock, FALSE, TRUE)))
  { DEBUG(D_transport) debug_printf("ehlo-cache: no misc DB\n"); }
else
  {
  uschar * ehlo_resp_key = ehlo_cache_key(sx);
  dbdata_ehlo_resp * er;

  if (!(er = dbfn_read_enforce_length(dbm_file, ehlo_resp_key, sizeof(dbdata_ehlo_resp))))
    { DEBUG(D_transport) debug_printf("no ehlo-resp record\n"); }
  else if (time(NULL) - er->time_stamp > retry_data_expire)
    {
    DEBUG(D_transport) debug_printf("ehlo-resp record too old\n");
    dbfn_close(dbm_file);
    if ((dbm_file = dbfn_open(US"misc", O_RDWR, &dbblock, TRUE, TRUE)))
      dbfn_delete(dbm_file, ehlo_resp_key);
    }
  else
    {
    DEBUG(D_transport)
#ifdef EXPERIMENTAL_ESMTP_LIMITS
      if (er->data.limit_mail || er->data.limit_rcpt || er->data.limit_rcptdom)
	debug_printf("EHLO response bits from cache:"
	  " cleartext 0x%04x/0x%04x crypted 0x%04x/0x%04x lim %05d/%05d/%05d\n",
	  er->data.cleartext_features, er->data.cleartext_auths,
	  er->data.crypted_features, er->data.crypted_auths,
	  er->data.limit_mail, er->data.limit_rcpt, er->data.limit_rcptdom);
      else
#endif
	debug_printf("EHLO response bits from cache:"
	  " cleartext 0x%04x/0x%04x crypted 0x%04x/0x%04x\n",
	  er->data.cleartext_features, er->data.cleartext_auths,
	  er->data.crypted_features, er->data.crypted_auths);

    sx->ehlo_resp = er->data;
#ifdef EXPERIMENTAL_ESMTP_LIMITS
    ehlo_cache_limits_apply(sx);
#endif
    dbfn_close(dbm_file);
    return TRUE;
    }
  dbfn_close(dbm_file);
  }
return FALSE;
}



/* Return an auths bitmap for the set of AUTH methods offered by the server
which match our authenticators. */

static unsigned short
study_ehlo_auths(smtp_context * sx)
{
uschar * names;
auth_instance * au;
uschar authnum;
unsigned short authbits = 0;

if (!sx->esmtp) return 0;
if (!regex_AUTH) regex_AUTH = regex_must_compile(AUTHS_REGEX, FALSE, TRUE);
if (!regex_match_and_setup(regex_AUTH, sx->buffer, 0, -1)) return 0;
expand_nmax = -1;						/* reset */
names = string_copyn(expand_nstring[1], expand_nlength[1]);

for (au = auths, authnum = 0; au; au = au->next, authnum++) if (au->client)
  {
  const uschar * list = names;
  uschar * s;
  for (int sep = ' '; s = string_nextinlist(&list, &sep, NULL, 0); )
    if (strcmpic(au->public_name, s) == 0)
      { authbits |= BIT(authnum); break; }
  }

DEBUG(D_transport)
  debug_printf("server offers %s AUTH, methods '%s', bitmap 0x%04x\n",
    tls_out.active.sock >= 0 ? "crypted" : "plaintext", names, authbits);

if (tls_out.active.sock >= 0)
  sx->ehlo_resp.crypted_auths = authbits;
else
  sx->ehlo_resp.cleartext_auths = authbits;
return authbits;
}




/* Wait for and check responses for early-pipelining.

Called from the lower-level smtp_read_response() function
used for general code that assume synchronisation, if context
flags indicate outstanding early-pipelining commands.  Also
called fom sync_responses() which handles pipelined commands.

Arguments:
 sx	smtp connection context
 countp	number of outstanding responses, adjusted on return

Return:
 OK	all well
 DEFER	error on first read of TLS'd conn
 FAIL	SMTP error in response
*/
int
smtp_reap_early_pipe(smtp_context * sx, int * countp)
{
BOOL pending_BANNER = sx->pending_BANNER;
BOOL pending_EHLO = sx->pending_EHLO;
int rc = FAIL;

sx->pending_BANNER = FALSE;	/* clear early to avoid recursion */
sx->pending_EHLO = FALSE;

if (pending_BANNER)
  {
  DEBUG(D_transport) debug_printf("%s expect banner\n", __FUNCTION__);
  (*countp)--;
  if (!smtp_reap_banner(sx))
    {
    DEBUG(D_transport) debug_printf("bad banner\n");
    if (tls_out.active.sock >= 0) rc = DEFER;
    goto fail;
    }
  }

if (pending_EHLO)
  {
  unsigned peer_offered;
  unsigned short authbits = 0, * ap;

  DEBUG(D_transport) debug_printf("%s expect ehlo\n", __FUNCTION__);
  (*countp)--;
  if (!smtp_reap_ehlo(sx))
    {
    DEBUG(D_transport) debug_printf("bad response for EHLO\n");
    if (tls_out.active.sock >= 0) rc = DEFER;
    goto fail;
    }

  /* Compare the actual EHLO response extensions and AUTH methods to the cached
  value we assumed; on difference, dump or rewrite the cache and arrange for a
  retry. */

  ap = tls_out.active.sock < 0
      ? &sx->ehlo_resp.cleartext_auths : &sx->ehlo_resp.crypted_auths;

  peer_offered = ehlo_response(sx->buffer,
	  (tls_out.active.sock < 0 ?  OPTION_TLS : 0)
	| OPTION_CHUNKING | OPTION_PRDR | OPTION_DSN | OPTION_PIPE | OPTION_SIZE
	| OPTION_UTF8 | OPTION_EARLY_PIPE
	);
#ifdef EXPERIMENTAL_ESMTP_LIMITS
  if (tls_out.active.sock >= 0 || !(peer_offered & OPTION_TLS))
    ehlo_response_limits_read(sx);
#endif
  if (  peer_offered != sx->peer_offered
     || (authbits = study_ehlo_auths(sx)) != *ap)
    {
    HDEBUG(D_transport)
      debug_printf("EHLO %s extensions changed, 0x%04x/0x%04x -> 0x%04x/0x%04x\n",
		    tls_out.active.sock < 0 ? "cleartext" : "crypted",
		    sx->peer_offered, *ap, peer_offered, authbits);
    if (peer_offered & OPTION_EARLY_PIPE)
      {
      *(tls_out.active.sock < 0
	? &sx->ehlo_resp.cleartext_features : &sx->ehlo_resp.crypted_features) =
	  peer_offered;
      *ap = authbits;
      write_ehlo_cache_entry(sx);
      }
    else
      invalidate_ehlo_cache_entry(sx);

    return OK;		/* just carry on */
    }
#ifdef EXPERIMENTAL_ESMTP_LIMITS
    /* If we are handling LIMITS, compare the actual EHLO LIMITS values with the
    cached values and invalidate cache if different.  OK to carry on with
    connect since values are advisory. */
    {
    if (  (tls_out.active.sock >= 0 || !(peer_offered & OPTION_TLS))
       && (  sx->peer_limit_mail != sx->ehlo_resp.limit_mail
          || sx->peer_limit_rcpt != sx->ehlo_resp.limit_rcpt
          || sx->peer_limit_rcptdom != sx->ehlo_resp.limit_rcptdom
       )  )
      {
      HDEBUG(D_transport)
	{
	debug_printf("EHLO LIMITS changed:");
	if (sx->peer_limit_mail != sx->ehlo_resp.limit_mail)
	  debug_printf(" MAILMAX %u -> %u\n", sx->ehlo_resp.limit_mail, sx->peer_limit_mail);
	else if (sx->peer_limit_rcpt != sx->ehlo_resp.limit_rcpt)
	  debug_printf(" RCPTMAX %u -> %u\n", sx->ehlo_resp.limit_rcpt, sx->peer_limit_rcpt);
	else
	  debug_printf(" RCPTDOMAINMAX %u -> %u\n", sx->ehlo_resp.limit_rcptdom, sx->peer_limit_rcptdom);
	}
      invalidate_ehlo_cache_entry(sx);
      }
    }
#endif
  }
return OK;

fail:
  invalidate_ehlo_cache_entry(sx);
  (void) smtp_discard_responses(sx, sx->conn_args.ob, *countp);
  return rc;
}
#endif	/*!DISABLE_PIPE_CONNECT*/


/*************************************************
*           Synchronize SMTP responses           *
*************************************************/

/* This function is called from smtp_deliver() to receive SMTP responses from
the server, and match them up with the commands to which they relate. When
PIPELINING is not in use, this function is called after every command, and is
therefore somewhat over-engineered, but it is simpler to use a single scheme
that works both with and without PIPELINING instead of having two separate sets
of code.

The set of commands that are buffered up with pipelining may start with MAIL
and may end with DATA; in between are RCPT commands that correspond to the
addresses whose status is PENDING_DEFER. All other commands (STARTTLS, AUTH,
etc.) are never buffered.

Errors after MAIL or DATA abort the whole process leaving the response in the
buffer. After MAIL, pending responses are flushed, and the original command is
re-instated in big_buffer for error messages. For RCPT commands, the remote is
permitted to reject some recipient addresses while accepting others. However
certain errors clearly abort the whole process. Set the value in
transport_return to PENDING_OK if the address is accepted. If there is a
subsequent general error, it will get reset accordingly. If not, it will get
converted to OK at the end.

Arguments:
  sx		    smtp connection context
  count             the number of responses to read
  pending_DATA      0 if last command sent was not DATA
                   +1 if previously had a good recipient
                   -1 if not previously had a good recipient

Returns:      3 if at least one address had 2xx and one had 5xx
              2 if at least one address had 5xx but none had 2xx
              1 if at least one host had a 2xx response, but none had 5xx
              0 no address had 2xx or 5xx but no errors (all 4xx, or just DATA)
             -1 timeout while reading RCPT response
             -2 I/O or other non-response error for RCPT
             -3 DATA or MAIL failed - errno and buffer set
	     -4 banner or EHLO failed (early-pipelining)
	     -5 banner or EHLO failed (early-pipelining, TLS)
*/

static int
sync_responses(smtp_context * sx, int count, int pending_DATA)
{
address_item * addr = sx->sync_addr;
smtp_transport_options_block * ob = sx->conn_args.ob;
int yield = 0;

#ifndef DISABLE_PIPE_CONNECT
int rc;
if ((rc = smtp_reap_early_pipe(sx, &count)) != OK)
  return rc == FAIL ? -4 : -5;
#endif

/* Handle the response for a MAIL command. On error, reinstate the original
command in big_buffer for error message use, and flush any further pending
responses before returning, except after I/O errors and timeouts. */

if (sx->pending_MAIL)
  {
  DEBUG(D_transport) debug_printf("%s expect mail\n", __FUNCTION__);
  count--;
  sx->pending_MAIL = sx->RCPT_452 = FALSE;
  if (!smtp_read_response(sx, sx->buffer, sizeof(sx->buffer),
			  '2', ob->command_timeout))
    {
    DEBUG(D_transport) debug_printf("bad response for MAIL\n");
    Ustrcpy(big_buffer, mail_command);  /* Fits, because it came from there! */
    if (errno == ERRNO_TLSFAILURE)
      return -5;
    if (errno == 0 && sx->buffer[0] != 0)
      {
      int save_errno = 0;
      if (sx->buffer[0] == '4')
        {
        save_errno = ERRNO_MAIL4XX;
        addr->more_errno |= ((sx->buffer[1] - '0')*10 + sx->buffer[2] - '0') << 8;
        }
      count = smtp_discard_responses(sx, ob, count);
      errno = save_errno;
      }

    if (pending_DATA) count--;  /* Number of RCPT responses to come */
    while (count-- > 0)		/* Mark any pending addrs with the host used */
      {
      while (addr->transport_return != PENDING_DEFER) addr = addr->next;
      addr->host_used = sx->conn_args.host;
      addr = addr->next;
      }
    return -3;
    }
  }

if (pending_DATA) count--;  /* Number of RCPT responses to come */

/* Read and handle the required number of RCPT responses, matching each one up
with an address by scanning for the next address whose status is PENDING_DEFER.
*/

while (count-- > 0)
  {
  while (addr->transport_return != PENDING_DEFER)
    if (!(addr = addr->next))
      return -2;

  /* The address was accepted */
  addr->host_used = sx->conn_args.host;

  DEBUG(D_transport) debug_printf("%s expect rcpt for %s\n", __FUNCTION__, addr->address);
  if (smtp_read_response(sx, sx->buffer, sizeof(sx->buffer),
			  '2', ob->command_timeout))
    {
    yield |= 1;
    addr->transport_return = PENDING_OK;

    /* If af_dr_retry_exists is set, there was a routing delay on this address;
    ensure that any address-specific retry record is expunged. We do this both
    for the basic key and for the version that also includes the sender. */

    if (testflag(addr, af_dr_retry_exists))
      {
      uschar *altkey = string_sprintf("%s:<%s>", addr->address_retry_key,
        sender_address);
      retry_add_item(addr, altkey, rf_delete);
      retry_add_item(addr, addr->address_retry_key, rf_delete);
      }
    }

  /* Error on first TLS read */

  else if (errno == ERRNO_TLSFAILURE)
    return -5;

  /* Timeout while reading the response */

  else if (errno == ETIMEDOUT)
    {
    uschar *message = string_sprintf("SMTP timeout after RCPT TO:<%s>",
		transport_rcpt_address(addr, sx->conn_args.tblock->rcpt_include_affixes));
    set_errno_nohost(sx->first_addr, ETIMEDOUT, message, DEFER, FALSE, &sx->delivery_start);
    retry_add_item(addr, addr->address_retry_key, 0);
    update_waiting = FALSE;
    return -1;
    }

  /* Handle other errors in obtaining an SMTP response by returning -1. This
  will cause all the addresses to be deferred. Restore the SMTP command in
  big_buffer for which we are checking the response, so the error message
  makes sense. */

  else if (errno != 0 || sx->buffer[0] == 0)
    {
    gstring gs = { .size = big_buffer_size, .ptr = 0, .s = big_buffer }, * g = &gs;

    /* Use taint-unchecked routines for writing into big_buffer, trusting
    that we'll never expand it. */

    g = string_fmt_append_f(g, SVFMT_TAINT_NOCHK, "RCPT TO:<%s>",
      transport_rcpt_address(addr, sx->conn_args.tblock->rcpt_include_affixes));
    string_from_gstring(g);
    return -2;
    }

  /* Handle SMTP permanent and temporary response codes. */

  else
    {
    addr->message =
      string_sprintf("SMTP error from remote mail server after RCPT TO:<%s>: "
	"%s", transport_rcpt_address(addr, sx->conn_args.tblock->rcpt_include_affixes),
	string_printing(sx->buffer));
    setflag(addr, af_pass_message);
    if (!sx->verify)
      msglog_line(sx->conn_args.host, addr->message);

    /* The response was 5xx */

    if (sx->buffer[0] == '5')
      {
      addr->transport_return = FAIL;
      yield |= 2;
      }

    /* The response was 4xx */

    else
      {
      addr->transport_return = DEFER;
      addr->basic_errno = ERRNO_RCPT4XX;
      addr->more_errno |= ((sx->buffer[1] - '0')*10 + sx->buffer[2] - '0') << 8;

      if (!sx->verify)
	{
#ifndef DISABLE_EVENT
	event_defer_errno = addr->more_errno;
	msg_event_raise(US"msg:rcpt:host:defer", addr);
#endif
	/* If a 452 and we've had at least one 2xx or 5xx, set next_addr to the
	start point for another MAIL command. */

	if (addr->more_errno >> 8 == 52  &&  yield & 3)
	  {
	  if (!sx->RCPT_452)		/* initialised at MAIL-ack above */
	    {
	    DEBUG(D_transport)
	      debug_printf("%s: seen first 452 too-many-rcpts\n", __FUNCTION__);
	    sx->RCPT_452 = TRUE;
	    sx->next_addr = addr;
	    }
	  addr->transport_return = PENDING_DEFER;
	  addr->basic_errno = 0;
	  }
	else
	  {
	  /* Log temporary errors if there are more hosts to be tried.
	  If not, log this last one in the == line. */

	  if (sx->conn_args.host->next)
	    if (LOGGING(outgoing_port))
	      log_write(0, LOG_MAIN, "H=%s [%s]:%d %s", sx->conn_args.host->name,
		sx->conn_args.host->address,
		sx->port == PORT_NONE ? 25 : sx->port, addr->message);
	    else
	      log_write(0, LOG_MAIN, "H=%s [%s]: %s", sx->conn_args.host->name,
		sx->conn_args.host->address, addr->message);

#ifndef DISABLE_EVENT
	  else
	    msg_event_raise(US"msg:rcpt:defer", addr);
#endif

	  /* Do not put this message on the list of those waiting for specific
	  hosts, as otherwise it is likely to be tried too often. */

	  update_waiting = FALSE;

	  /* Add a retry item for the address so that it doesn't get tried again
	  too soon. If address_retry_include_sender is true, add the sender address
	  to the retry key. */

	  retry_add_item(addr,
	    ob->address_retry_include_sender
	      ? string_sprintf("%s:<%s>", addr->address_retry_key, sender_address)
	      : addr->address_retry_key,
	    0);
	  }
	}
      }
    }
  if (count && !(addr = addr->next))
    return -2;
  }       /* Loop for next RCPT response */

/* Update where to start at for the next block of responses, unless we
have already handled all the addresses. */

if (addr) sx->sync_addr = addr->next;

/* Handle a response to DATA. If we have not had any good recipients, either
previously or in this block, the response is ignored. */

if (pending_DATA != 0)
  {
  DEBUG(D_transport) debug_printf("%s expect data\n", __FUNCTION__);
  if (!smtp_read_response(sx, sx->buffer, sizeof(sx->buffer),
			'3', ob->command_timeout))
    {
    int code;
    uschar *msg;
    BOOL pass_message;

    if (errno == ERRNO_TLSFAILURE)	/* Error on first TLS read */
      return -5;

    if (pending_DATA > 0 || (yield & 1) != 0)
      {
      if (errno == 0 && sx->buffer[0] == '4')
	{
	errno = ERRNO_DATA4XX;
	sx->first_addr->more_errno |= ((sx->buffer[1] - '0')*10 + sx->buffer[2] - '0') << 8;
	}
      return -3;
      }
    (void)check_response(sx->conn_args.host, &errno, 0, sx->buffer, &code, &msg, &pass_message);
    DEBUG(D_transport) debug_printf("%s\nerror for DATA ignored: pipelining "
      "is in use and there were no good recipients\n", msg);
    }
  }

/* All responses read and handled; MAIL (if present) received 2xx and DATA (if
present) received 3xx. If any RCPTs were handled and yielded anything other
than 4xx, yield will be set non-zero. */

return yield;
}





/* Try an authenticator's client entry */

static int
try_authenticator(smtp_context * sx, auth_instance * au)
{
smtp_transport_options_block * ob = sx->conn_args.ob;	/* transport options */
host_item * host = sx->conn_args.host;			/* host to deliver to */
int rc;

sx->outblock.authenticating = TRUE;
rc = (au->info->clientcode)(au, sx, ob->command_timeout,
			    sx->buffer, sizeof(sx->buffer));
sx->outblock.authenticating = FALSE;
DEBUG(D_transport) debug_printf("%s authenticator yielded %d\n", au->name, rc);

/* A temporary authentication failure must hold up delivery to
this host. After a permanent authentication failure, we carry on
to try other authentication methods. If all fail hard, try to
deliver the message unauthenticated unless require_auth was set. */

switch(rc)
  {
  case OK:
    f.smtp_authenticated = TRUE;   /* stops the outer loop */
    client_authenticator = au->name;
    if (au->set_client_id)
      client_authenticated_id = expand_string(au->set_client_id);
    break;

  /* Failure after writing a command */

  case FAIL_SEND:
    return FAIL_SEND;

  /* Failure after reading a response */

  case FAIL:
    if (errno != 0 || sx->buffer[0] != '5') return FAIL;
    log_write(0, LOG_MAIN, "%s authenticator failed H=%s [%s] %s",
      au->name, host->name, host->address, sx->buffer);
    break;

  /* Failure by some other means. In effect, the authenticator
  decided it wasn't prepared to handle this case. Typically this
  is the result of "fail" in an expansion string. Do we need to
  log anything here? Feb 2006: a message is now put in the buffer
  if logging is required. */

  case CANCELLED:
    if (*sx->buffer != 0)
      log_write(0, LOG_MAIN, "%s authenticator cancelled "
	"authentication H=%s [%s] %s", au->name, host->name,
	host->address, sx->buffer);
    break;

  /* Internal problem, message in buffer. */

  case ERROR:
    set_errno_nohost(sx->addrlist, ERRNO_AUTHPROB, string_copy(sx->buffer),
	      DEFER, FALSE, &sx->delivery_start);
    return ERROR;
  }
return OK;
}




/* Do the client side of smtp-level authentication.

Arguments:
  sx		smtp connection context

sx->buffer should have the EHLO response from server (gets overwritten)

Returns:
  OK			Success, or failed (but not required): global "smtp_authenticated" set
  DEFER			Failed authentication (and was required)
  ERROR			Internal problem

  FAIL_SEND		Failed communications - transmit
  FAIL			- response
*/

static int
smtp_auth(smtp_context * sx)
{
host_item * host = sx->conn_args.host;			/* host to deliver to */
smtp_transport_options_block * ob = sx->conn_args.ob;	/* transport options */
int require_auth = verify_check_given_host(CUSS &ob->hosts_require_auth, host);
#ifndef DISABLE_PIPE_CONNECT
unsigned short authbits = tls_out.active.sock >= 0
      ? sx->ehlo_resp.crypted_auths : sx->ehlo_resp.cleartext_auths;
#endif
uschar * fail_reason = US"server did not advertise AUTH support";

f.smtp_authenticated = FALSE;
client_authenticator = client_authenticated_id = client_authenticated_sender = NULL;

if (!regex_AUTH)
  regex_AUTH = regex_must_compile(AUTHS_REGEX, FALSE, TRUE);

/* Is the server offering AUTH? */

if (  sx->esmtp
   &&
#ifndef DISABLE_PIPE_CONNECT
      sx->early_pipe_active ? authbits
      :
#endif
	regex_match_and_setup(regex_AUTH, sx->buffer, 0, -1)
   )
  {
  uschar * names = NULL;
  expand_nmax = -1;                          /* reset */

#ifndef DISABLE_PIPE_CONNECT
  if (!sx->early_pipe_active)
#endif
    names = string_copyn(expand_nstring[1], expand_nlength[1]);

  /* Must not do this check until after we have saved the result of the
  regex match above as the check could be another RE. */

  if (  require_auth == OK
     || verify_check_given_host(CUSS &ob->hosts_try_auth, host) == OK)
    {
    DEBUG(D_transport) debug_printf("scanning authentication mechanisms\n");
    fail_reason = US"no common mechanisms were found";

#ifndef DISABLE_PIPE_CONNECT
    if (sx->early_pipe_active)
      {
      /* Scan our authenticators (which support use by a client and were offered
      by the server (checked at cache-write time)), not suppressed by
      client_condition.  If one is found, attempt to authenticate by calling its
      client function.  We are limited to supporting up to 16 authenticator
      public-names by the number of bits in a short. */

      auth_instance * au;
      uschar bitnum;
      int rc;

      for (bitnum = 0, au = auths;
	   !f.smtp_authenticated && au && bitnum < 16;
	   bitnum++, au = au->next) if (authbits & BIT(bitnum))
	{
	if (  au->client_condition
	   && !expand_check_condition(au->client_condition, au->name,
                   US"client authenticator"))
	  {
	  DEBUG(D_transport) debug_printf("skipping %s authenticator: %s\n",
	    au->name, "client_condition is false");
	  continue;
	  }

	/* Found data for a listed mechanism. Call its client entry. Set
	a flag in the outblock so that data is overwritten after sending so
	that reflections don't show it. */

	fail_reason = US"authentication attempt(s) failed";

	if ((rc = try_authenticator(sx, au)) != OK)
	  return rc;
	}
      }
    else
#endif

    /* Scan the configured authenticators looking for one which is configured
    for use as a client, which is not suppressed by client_condition, and
    whose name matches an authentication mechanism supported by the server.
    If one is found, attempt to authenticate by calling its client function.
    */

    for (auth_instance * au = auths; !f.smtp_authenticated && au; au = au->next)
      {
      uschar *p = names;

      if (  !au->client
         || (   au->client_condition
	    &&  !expand_check_condition(au->client_condition, au->name,
		   US"client authenticator")))
	{
	DEBUG(D_transport) debug_printf("skipping %s authenticator: %s\n",
	  au->name,
	  (au->client)? "client_condition is false" :
			"not configured as a client");
	continue;
	}

      /* Loop to scan supported server mechanisms */

      while (*p)
	{
	int len = Ustrlen(au->public_name);
	int rc;

	while (isspace(*p)) p++;

	if (strncmpic(au->public_name, p, len) != 0 ||
	    (p[len] != 0 && !isspace(p[len])))
	  {
	  while (*p != 0 && !isspace(*p)) p++;
	  continue;
	  }

	/* Found data for a listed mechanism. Call its client entry. Set
	a flag in the outblock so that data is overwritten after sending so
	that reflections don't show it. */

	fail_reason = US"authentication attempt(s) failed";

	if ((rc = try_authenticator(sx, au)) != OK)
	  return rc;

	break;  /* If not authenticated, try next authenticator */
	}       /* Loop for scanning supported server mechanisms */
      }         /* Loop for further authenticators */
    }
  }

/* If we haven't authenticated, but are required to, give up. */

if (require_auth == OK && !f.smtp_authenticated)
  {
#ifndef DISABLE_PIPE_CONNECT
  invalidate_ehlo_cache_entry(sx);
#endif
  set_errno_nohost(sx->addrlist, ERRNO_AUTHFAIL,
    string_sprintf("authentication required but %s", fail_reason), DEFER,
    FALSE, &sx->delivery_start);
  return DEFER;
  }

return OK;
}


/* Construct AUTH appendix string for MAIL TO */
/*
Arguments
  sx		context for smtp connection
  p		point in sx->buffer to build string
  addrlist      chain of potential addresses to deliver

Globals		f.smtp_authenticated
		client_authenticated_sender
Return	True on error, otherwise buffer has (possibly empty) terminated string
*/

static BOOL
smtp_mail_auth_str(smtp_context * sx, uschar * p, address_item * addrlist)
{
smtp_transport_options_block * ob = sx->conn_args.ob;
uschar * local_authenticated_sender = authenticated_sender;

#ifdef notdef
  debug_printf("smtp_mail_auth_str: as<%s> os<%s> SA<%s>\n",
    authenticated_sender, ob->authenticated_sender, f.smtp_authenticated?"Y":"N");
#endif

if (ob->authenticated_sender)
  {
  uschar * new = expand_string(ob->authenticated_sender);
  if (!new)
    {
    if (!f.expand_string_forcedfail)
      {
      uschar *message = string_sprintf("failed to expand "
        "authenticated_sender: %s", expand_string_message);
      set_errno_nohost(addrlist, ERRNO_EXPANDFAIL, message, DEFER, FALSE, &sx->delivery_start);
      return TRUE;
      }
    }
  else if (*new)
    local_authenticated_sender = new;
  }

/* Add the authenticated sender address if present */

if (  (f.smtp_authenticated || ob->authenticated_sender_force)
   && local_authenticated_sender)
  {
  string_format_nt(p, sizeof(sx->buffer) - (p-sx->buffer), " AUTH=%s",
    auth_xtextencode(local_authenticated_sender,
      Ustrlen(local_authenticated_sender)));
  client_authenticated_sender = string_copy(local_authenticated_sender);
  }
else
  *p = 0;

return FALSE;
}



typedef struct smtp_compare_s
{
    uschar *			current_sender_address;
    struct transport_instance *	tblock;
} smtp_compare_t;


/* Create a unique string that identifies this message, it is based on
sender_address, helo_data and tls_certificate if enabled.
*/

static uschar *
smtp_local_identity(uschar * sender, struct transport_instance * tblock)
{
address_item * addr1;
uschar * if1 = US"";
uschar * helo1 = US"";
#ifndef DISABLE_TLS
uschar * tlsc1 = US"";
#endif
uschar * save_sender_address = sender_address;
uschar * local_identity = NULL;
smtp_transport_options_block * ob = SOB tblock->options_block;

sender_address = sender;

addr1 = deliver_make_addr (sender, TRUE);
deliver_set_expansions(addr1);

if (ob->interface)
  if1 = expand_string(ob->interface);

if (ob->helo_data)
  helo1 = expand_string(ob->helo_data);

#ifndef DISABLE_TLS
if (ob->tls_certificate)
  tlsc1 = expand_string(ob->tls_certificate);
local_identity = string_sprintf ("%s^%s^%s", if1, helo1, tlsc1);
#else
local_identity = string_sprintf ("%s^%s", if1, helo1);
#endif

deliver_set_expansions(NULL);
sender_address = save_sender_address;

return local_identity;
}



/* This routine is a callback that is called from transport_check_waiting.
This function will evaluate the incoming message versus the previous
message.  If the incoming message is using a different local identity then
we will veto this new message.  */

static BOOL
smtp_are_same_identities(uschar * message_id, smtp_compare_t * s_compare)
{
uschar * message_local_identity,
       * current_local_identity,
       * new_sender_address;

current_local_identity =
  smtp_local_identity(s_compare->current_sender_address, s_compare->tblock);

if (!(new_sender_address = spool_sender_from_msgid(message_id)))
  return FALSE;


message_local_identity =
  smtp_local_identity(new_sender_address, s_compare->tblock);

return Ustrcmp(current_local_identity, message_local_identity) == 0;
}



static unsigned
ehlo_response(uschar * buf, unsigned checks)
{
size_t bsize = Ustrlen(buf);

/* debug_printf("%s: check for 0x%04x\n", __FUNCTION__, checks); */

#ifndef DISABLE_TLS
if (  checks & OPTION_TLS
   && pcre_exec(regex_STARTTLS, NULL, CS buf, bsize, 0, PCRE_EOPT, NULL, 0) < 0)
#endif
  checks &= ~OPTION_TLS;

if (  checks & OPTION_IGNQ
   && pcre_exec(regex_IGNOREQUOTA, NULL, CS buf, bsize, 0,
		PCRE_EOPT, NULL, 0) < 0)
  checks &= ~OPTION_IGNQ;

if (  checks & OPTION_CHUNKING
   && pcre_exec(regex_CHUNKING, NULL, CS buf, bsize, 0, PCRE_EOPT, NULL, 0) < 0)
  checks &= ~OPTION_CHUNKING;

#ifndef DISABLE_PRDR
if (  checks & OPTION_PRDR
   && pcre_exec(regex_PRDR, NULL, CS buf, bsize, 0, PCRE_EOPT, NULL, 0) < 0)
#endif
  checks &= ~OPTION_PRDR;

#ifdef SUPPORT_I18N
if (  checks & OPTION_UTF8
   && pcre_exec(regex_UTF8, NULL, CS buf, bsize, 0, PCRE_EOPT, NULL, 0) < 0)
#endif
  checks &= ~OPTION_UTF8;

if (  checks & OPTION_DSN
   && pcre_exec(regex_DSN, NULL, CS buf, bsize, 0, PCRE_EOPT, NULL, 0) < 0)
  checks &= ~OPTION_DSN;

if (  checks & OPTION_PIPE
   && pcre_exec(regex_PIPELINING, NULL, CS buf, bsize, 0,
		PCRE_EOPT, NULL, 0) < 0)
  checks &= ~OPTION_PIPE;

if (  checks & OPTION_SIZE
   && pcre_exec(regex_SIZE, NULL, CS buf, bsize, 0, PCRE_EOPT, NULL, 0) < 0)
  checks &= ~OPTION_SIZE;

#ifndef DISABLE_PIPE_CONNECT
if (  checks & OPTION_EARLY_PIPE
   && pcre_exec(regex_EARLY_PIPE, NULL, CS buf, bsize, 0,
		PCRE_EOPT, NULL, 0) < 0)
#endif
  checks &= ~OPTION_EARLY_PIPE;

/* debug_printf("%s: found     0x%04x\n", __FUNCTION__, checks); */
return checks;
}



/* Callback for emitting a BDAT data chunk header.

If given a nonzero size, first flush any buffered SMTP commands
then emit the command.

Reap previous SMTP command responses if requested, and always reap
the response from a previous BDAT command.

Args:
 tctx		transport context
 chunk_size	value for SMTP BDAT command
 flags
   tc_chunk_last	add LAST option to SMTP BDAT command
   tc_reap_prev		reap response to previous SMTP commands

Returns:
  OK or ERROR
  DEFER			TLS error on first read (EHLO-resp); errno set
*/

static int
smtp_chunk_cmd_callback(transport_ctx * tctx, unsigned chunk_size,
  unsigned flags)
{
smtp_transport_options_block * ob = SOB tctx->tblock->options_block;
smtp_context * sx = tctx->smtp_context;
int cmd_count = 0;
int prev_cmd_count;

/* Write SMTP chunk header command.  If not reaping responses, note that
there may be more writes (like, the chunk data) done soon. */

if (chunk_size > 0)
  {
#ifndef DISABLE_PIPE_CONNECT
  BOOL new_conn = !!(sx->outblock.conn_args);
#endif
  if((cmd_count = smtp_write_command(sx,
	      flags & tc_reap_prev ? SCMD_FLUSH : SCMD_MORE,
	      "BDAT %u%s\r\n", chunk_size, flags & tc_chunk_last ? " LAST" : "")
     ) < 0) return ERROR;
  if (flags & tc_chunk_last)
    data_command = string_copy(big_buffer);  /* Save for later error message */
#ifndef DISABLE_PIPE_CONNECT
  /* That command write could have been the one that made the connection.
  Copy the fd from the client conn ctx (smtp transport specific) to the
  generic transport ctx. */

  if (new_conn)
    tctx->u.fd = sx->outblock.cctx->sock;
#endif
  }

prev_cmd_count = cmd_count += sx->cmd_count;

/* Reap responses for any previous, but not one we just emitted */

if (chunk_size > 0)
  prev_cmd_count--;
if (sx->pending_BDAT)
  prev_cmd_count--;

if (flags & tc_reap_prev  &&  prev_cmd_count > 0)
  {
  DEBUG(D_transport) debug_printf("look for %d responses"
    " for previous pipelined cmds\n", prev_cmd_count);

  switch(sync_responses(sx, prev_cmd_count, 0))
    {
    case 1:				/* 2xx (only) => OK */
    case 3: sx->good_RCPT = TRUE;	/* 2xx & 5xx => OK & progress made */
    case 2: sx->completed_addr = TRUE;	/* 5xx (only) => progress made */
    case 0: break;			/* No 2xx or 5xx, but no probs */

    case -5: errno = ERRNO_TLSFAILURE;
	     return DEFER;
#ifndef DISABLE_PIPE_CONNECT
    case -4:				/* non-2xx for pipelined banner or EHLO */
#endif
    case -1:				/* Timeout on RCPT */
    default: return ERROR;		/* I/O error, or any MAIL/DATA error */
    }
  cmd_count = 1;
  if (!sx->pending_BDAT)
    pipelining_active = FALSE;
  }

/* Reap response for an outstanding BDAT */

if (sx->pending_BDAT)
  {
  DEBUG(D_transport) debug_printf("look for one response for BDAT\n");

  if (!smtp_read_response(sx, sx->buffer, sizeof(sx->buffer), '2',
       ob->command_timeout))
    {
    if (errno == 0 && sx->buffer[0] == '4')
      {
      errno = ERRNO_DATA4XX;	/*XXX does this actually get used? */
      sx->addrlist->more_errno |=
	((sx->buffer[1] - '0')*10 + sx->buffer[2] - '0') << 8;
      }
    return ERROR;
    }
  cmd_count--;
  sx->pending_BDAT = FALSE;
  pipelining_active = FALSE;
  }
else if (chunk_size > 0)
  sx->pending_BDAT = TRUE;


sx->cmd_count = cmd_count;
return OK;
}



/*************************************************
*       Make connection for given message        *
*************************************************/

/*
Arguments:
  sx		  connection context
  suppress_tls    if TRUE, don't attempt a TLS connection - this is set for
                    a second attempt after TLS initialization fails

Returns:          OK    - the connection was made and the delivery attempted;
                          fd is set in the conn context, tls_out set up.
                  DEFER - the connection could not be made, or something failed
                          while setting up the SMTP session, or there was a
                          non-message-specific error, such as a timeout.
                  ERROR - helo_data or add_headers or authenticated_sender is
			  specified for this transport, and the string failed
			  to expand
*/
int
smtp_setup_conn(smtp_context * sx, BOOL suppress_tls)
{
smtp_transport_options_block * ob = sx->conn_args.tblock->options_block;
BOOL pass_message = FALSE;
uschar * message = NULL;
int yield = OK;
#ifndef DISABLE_TLS
uschar * tls_errstr;
#endif

sx->conn_args.ob = ob;

sx->lmtp = strcmpic(ob->protocol, US"lmtp") == 0;
sx->smtps = strcmpic(ob->protocol, US"smtps") == 0;
/* sx->ok = FALSE; */
sx->send_rset = TRUE;
sx->send_quit = TRUE;
sx->setting_up = TRUE;
sx->esmtp = TRUE;
/* sx->esmtp_sent = FALSE; */
#ifdef SUPPORT_I18N
/* sx->utf8_needed = FALSE; */
#endif
sx->dsn_all_lasthop = TRUE;
#ifdef SUPPORT_DANE
/* sx->conn_args.dane = FALSE; */
sx->dane_required =
  verify_check_given_host(CUSS &ob->hosts_require_dane, sx->conn_args.host) == OK;
#endif
#ifndef DISABLE_PIPE_CONNECT
/* sx->early_pipe_active = sx->early_pipe_ok = FALSE; */
/* sx->ehlo_resp.cleartext_features = sx->ehlo_resp.crypted_features = 0; */
/* sx->pending_BANNER = sx->pending_EHLO = sx->pending_MAIL = FALSE; */
#endif

if ((sx->max_mail = sx->conn_args.tblock->connection_max_messages) == 0) sx->max_mail = 999999;
if ((sx->max_rcpt = sx->conn_args.tblock->max_addresses) == 0)           sx->max_rcpt = 999999;
/* sx->peer_offered = 0; */
/* sx->avoid_option = 0; */
sx->igquotstr = US"";
if (!sx->helo_data) sx->helo_data = ob->helo_data;
#ifdef EXPERIMENTAL_DSN_INFO
/* sx->smtp_greeting = NULL; */
/* sx->helo_response = NULL; */
#endif

smtp_command = US"initial connection";
/* sx->buffer[0] = '\0'; */

/* Set up the buffer for reading SMTP response packets. */

sx->inblock.buffer = sx->inbuffer;
sx->inblock.buffersize = sizeof(sx->inbuffer);
sx->inblock.ptr = sx->inbuffer;
sx->inblock.ptrend = sx->inbuffer;

/* Set up the buffer for holding SMTP commands while pipelining */

sx->outblock.buffer = sx->outbuffer;
sx->outblock.buffersize = sizeof(sx->outbuffer);
sx->outblock.ptr = sx->outbuffer;
/* sx->outblock.cmd_count = 0; */
/* sx->outblock.authenticating = FALSE; */
/* sx->outblock.conn_args = NULL; */

/* Reset the parameters of a TLS session. */

tls_out.bits = 0;
tls_out.cipher = NULL;	/* the one we may use for this transport */
tls_out.ourcert = NULL;
tls_out.peercert = NULL;
tls_out.peerdn = NULL;
#ifdef USE_OPENSSL
tls_out.sni = NULL;
#endif
tls_out.ocsp = OCSP_NOT_REQ;
#ifndef DISABLE_TLS_RESUME
tls_out.resumption = 0;
#endif
tls_out.ver = NULL;

/* Flip the legacy TLS-related variables over to the outbound set in case
they're used in the context of the transport.  Don't bother resetting
afterward (when being used by a transport) as we're in a subprocess.
For verify, unflipped once the callout is dealt with */

tls_modify_variables(&tls_out);

#ifdef DISABLE_TLS
if (sx->smtps)
  {
  set_errno_nohost(sx->addrlist, ERRNO_TLSFAILURE, US"TLS support not available",
	    DEFER, FALSE, &sx->delivery_start);
  return ERROR;
  }
#else

/* If we have a proxied TLS connection, check usability for this message */

if (continue_hostname && continue_proxy_cipher)
  {
  int rc;
  const uschar * sni = US"";

# ifdef SUPPORT_DANE
  /* Check if the message will be DANE-verified; if so force its SNI */

  tls_out.dane_verified = FALSE;
  smtp_port_for_connect(sx->conn_args.host, sx->port);
  if (  sx->conn_args.host->dnssec == DS_YES
     && (  sx->dane_required
	|| verify_check_given_host(CUSS &ob->hosts_try_dane, sx->conn_args.host) == OK
     )  )
    switch (rc = tlsa_lookup(sx->conn_args.host, &sx->conn_args.tlsa_dnsa, sx->dane_required))
      {
      case OK:		sx->conn_args.dane = TRUE;
			ob->tls_tempfail_tryclear = FALSE;	/* force TLS */
                        ob->tls_sni = sx->conn_args.host->name; /* force SNI */
			break;
      case FAIL_FORCED:	break;
      default:		set_errno_nohost(sx->addrlist, ERRNO_DNSDEFER,
			      string_sprintf("DANE error: tlsa lookup %s",
				rc_to_string(rc)),
			      rc, FALSE, &sx->delivery_start);
#  ifndef DISABLE_EVENT
			    (void) event_raise(sx->conn_args.tblock->event_action,
			      US"dane:fail", sx->dane_required
				?  US"dane-required" : US"dnssec-invalid");
#  endif
			    return rc;
      }
# endif

  /* If the SNI or the DANE status required for the new message differs from the
  existing conn drop the connection to force a new one. */

  if (ob->tls_sni && !(sni = expand_cstring(ob->tls_sni)))
    log_write(0, LOG_MAIN|LOG_PANIC,
      "<%s>: failed to expand transport's tls_sni value: %s",
      sx->addrlist->address, expand_string_message);

# ifdef SUPPORT_DANE
  if (  (continue_proxy_sni ? (Ustrcmp(continue_proxy_sni, sni) == 0) : !*sni)
     && continue_proxy_dane == sx->conn_args.dane)
    {
    tls_out.sni = US sni;
    if ((tls_out.dane_verified = continue_proxy_dane))
      sx->conn_args.host->dnssec = DS_YES;
    }
# else
  if ((continue_proxy_sni ? (Ustrcmp(continue_proxy_sni, sni) == 0) : !*sni))
    tls_out.sni = US sni;
# endif
  else
    {
    DEBUG(D_transport)
      debug_printf("Closing proxied-TLS connection due to SNI mismatch\n");

    HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  SMTP>> QUIT\n");
    write(0, "QUIT\r\n", 6);
    close(0);
    continue_hostname = continue_proxy_cipher = NULL;
    f.continue_more = FALSE;
    continue_sequence = 1;	/* Unfortunately, this process cannot affect success log
    				which is done by delivery proc.  Would have to pass this
				back through reporting pipe. */
    }
  }
#endif	/*!DISABLE_TLS*/

/* Make a connection to the host if this isn't a continued delivery, and handle
the initial interaction and HELO/EHLO/LHLO. Connect timeout errors are handled
specially so they can be identified for retries. */

if (!continue_hostname)
  {
  if (sx->verify)
    HDEBUG(D_verify) debug_printf("interface=%s port=%d\n", sx->conn_args.interface, sx->port);

  /* Arrange to report to calling process this is a new connection */

  clearflag(sx->first_addr, af_cont_conn);
  setflag(sx->first_addr, af_new_conn);

  /* Get the actual port the connection will use, into sx->conn_args.host */

  smtp_port_for_connect(sx->conn_args.host, sx->port);

#ifdef SUPPORT_DANE
    /* Do TLSA lookup for DANE */
    {
    tls_out.dane_verified = FALSE;
    tls_out.tlsa_usage = 0;

    if (sx->conn_args.host->dnssec == DS_YES)
      {
      int rc;
      if(  sx->dane_required
	|| verify_check_given_host(CUSS &ob->hosts_try_dane, sx->conn_args.host) == OK
	)
	switch (rc = tlsa_lookup(sx->conn_args.host, &sx->conn_args.tlsa_dnsa, sx->dane_required))
	  {
	  case OK:		sx->conn_args.dane = TRUE;
				ob->tls_tempfail_tryclear = FALSE;	/* force TLS */
				ob->tls_sni = sx->conn_args.host->name; /* force SNI */
				break;
	  case FAIL_FORCED:	break;
	  default:		set_errno_nohost(sx->addrlist, ERRNO_DNSDEFER,
				  string_sprintf("DANE error: tlsa lookup %s",
				    rc_to_string(rc)),
				  rc, FALSE, &sx->delivery_start);
# ifndef DISABLE_EVENT
				(void) event_raise(sx->conn_args.tblock->event_action,
				  US"dane:fail", sx->dane_required
				    ?  US"dane-required" : US"dnssec-invalid");
# endif
				return rc;
	  }
      }
    else if (sx->dane_required)
      {
      set_errno_nohost(sx->addrlist, ERRNO_DNSDEFER,
	string_sprintf("DANE error: %s lookup not DNSSEC", sx->conn_args.host->name),
	FAIL, FALSE, &sx->delivery_start);
# ifndef DISABLE_EVENT
      (void) event_raise(sx->conn_args.tblock->event_action,
	US"dane:fail", US"dane-required");
# endif
      return FAIL;
      }
    }
#endif	/*DANE*/

  /* Make the TCP connection */

  sx->cctx.tls_ctx = NULL;
  sx->inblock.cctx = sx->outblock.cctx = &sx->cctx;
#ifdef EXPERIMENTAL_ESMTP_LIMITS
  sx->peer_limit_mail = sx->peer_limit_rcpt = sx->peer_limit_rcptdom =
#endif
  sx->avoid_option = sx->peer_offered = smtp_peer_options = 0;

#ifndef DISABLE_PIPE_CONNECT
  if (  verify_check_given_host(CUSS &ob->hosts_pipe_connect,
					    sx->conn_args.host) == OK)

    /* We don't find out the local ip address until the connect, so if
    the helo string might use it avoid doing early-pipelining. */

    if (  !sx->helo_data
       || !Ustrstr(sx->helo_data, "$sending_ip_address")
       || Ustrstr(sx->helo_data, "def:sending_ip_address")
       )
      {
      sx->early_pipe_ok = TRUE;
      if (  read_ehlo_cache_entry(sx)
	 && sx->ehlo_resp.cleartext_features & OPTION_EARLY_PIPE)
	{
	DEBUG(D_transport)
	  debug_printf("Using cached cleartext PIPE_CONNECT\n");
	sx->early_pipe_active = TRUE;
	sx->peer_offered = sx->ehlo_resp.cleartext_features;
	}
      }
    else DEBUG(D_transport)
      debug_printf("helo needs $sending_ip_address\n");

PIPE_CONNECT_RETRY:
  if (sx->early_pipe_active)
    sx->outblock.conn_args = &sx->conn_args;
  else
#endif
    {
    blob lazy_conn = {.data = NULL};
    /* For TLS-connect, a TFO lazy-connect is useful since the Client Hello
    can go on the TCP SYN. */

    if ((sx->cctx.sock = smtp_connect(&sx->conn_args,
			    sx->smtps ? &lazy_conn : NULL)) < 0)
      {
      set_errno_nohost(sx->addrlist,
	errno == ETIMEDOUT ? ERRNO_CONNECTTIMEOUT : errno,
	sx->verify ? US strerror(errno) : NULL,
	DEFER, FALSE, &sx->delivery_start);
      sx->send_quit = FALSE;
      return DEFER;
      }
#ifdef TCP_QUICKACK
    (void) setsockopt(sx->cctx.sock, IPPROTO_TCP, TCP_QUICKACK, US &off,
			sizeof(off));
#endif
    }
  /* Expand the greeting message while waiting for the initial response. (Makes
  sense if helo_data contains ${lookup dnsdb ...} stuff). The expansion is
  delayed till here so that $sending_interface and $sending_port are set. */
/*XXX early-pipe: they still will not be. Is there any way to find out what they
will be?  Somehow I doubt it. */

  if (sx->helo_data)
    if (!(sx->helo_data = expand_string(sx->helo_data)))
      if (sx->verify)
	log_write(0, LOG_MAIN|LOG_PANIC,
	  "<%s>: failed to expand transport's helo_data value for callout: %s",
	  sx->addrlist->address, expand_string_message);

#ifdef SUPPORT_I18N
  if (sx->helo_data)
    {
    expand_string_message = NULL;
    if ((sx->helo_data = string_domain_utf8_to_alabel(sx->helo_data,
					      &expand_string_message)),
	expand_string_message)
      if (sx->verify)
	log_write(0, LOG_MAIN|LOG_PANIC,
	  "<%s>: failed to expand transport's helo_data value for callout: %s",
	  sx->addrlist->address, expand_string_message);
      else
	sx->helo_data = NULL;
    }
#endif

  /* The first thing is to wait for an initial OK response. The dreaded "goto"
  is nevertheless a reasonably clean way of programming this kind of logic,
  where you want to escape on any error. */

  if (!sx->smtps)
    {
#ifndef DISABLE_PIPE_CONNECT
    if (sx->early_pipe_active)
      {
      sx->pending_BANNER = TRUE;	/* sync_responses() must eventually handle */
      sx->outblock.cmd_count = 1;
      }
    else
#endif
      {
      if (!smtp_reap_banner(sx))
	goto RESPONSE_FAILED;
      }

#ifndef DISABLE_EVENT
      {
      uschar * s;
      lookup_dnssec_authenticated = sx->conn_args.host->dnssec==DS_YES ? US"yes"
	: sx->conn_args.host->dnssec==DS_NO ? US"no" : NULL;
      s = event_raise(sx->conn_args.tblock->event_action, US"smtp:connect", sx->buffer);
      if (s)
	{
	set_errno_nohost(sx->addrlist, ERRNO_EXPANDFAIL,
	  string_sprintf("deferred by smtp:connect event expansion: %s", s),
	  DEFER, FALSE, &sx->delivery_start);
	yield = DEFER;
	goto SEND_QUIT;
	}
      }
#endif

    /* Now check if the helo_data expansion went well, and sign off cleanly if
    it didn't. */

    if (!sx->helo_data)
      {
      message = string_sprintf("failed to expand helo_data: %s",
        expand_string_message);
      set_errno_nohost(sx->addrlist, ERRNO_EXPANDFAIL, message, DEFER, FALSE, &sx->delivery_start);
      yield = DEFER;
      goto SEND_QUIT;
      }
    }

/** Debugging without sending a message
sx->addrlist->transport_return = DEFER;
goto SEND_QUIT;
**/

  /* Errors that occur after this point follow an SMTP command, which is
  left in big_buffer by smtp_write_command() for use in error messages. */

  smtp_command = big_buffer;

  /* Tell the remote who we are...

  February 1998: A convention has evolved that ESMTP-speaking MTAs include the
  string "ESMTP" in their greeting lines, so make Exim send EHLO if the
  greeting is of this form. The assumption was that the far end supports it
  properly... but experience shows that there are some that give 5xx responses,
  even though the banner includes "ESMTP" (there's a bloody-minded one that
  says "ESMTP not spoken here"). Cope with that case.

  September 2000: Time has passed, and it seems reasonable now to always send
  EHLO at the start. It is also convenient to make the change while installing
  the TLS stuff.

  July 2003: Joachim Wieland met a broken server that advertises "PIPELINING"
  but times out after sending MAIL FROM, RCPT TO and DATA all together. There
  would be no way to send out the mails, so there is now a host list
  "hosts_avoid_esmtp" that disables ESMTP for special hosts and solves the
  PIPELINING problem as well. Maybe it can also be useful to cure other
  problems with broken servers.

  Exim originally sent "Helo" at this point and ran for nearly a year that way.
  Then somebody tried it with a Microsoft mailer... It seems that all other
  mailers use upper case for some reason (the RFC is quite clear about case
  independence) so, for peace of mind, I gave in. */

  sx->esmtp = verify_check_given_host(CUSS &ob->hosts_avoid_esmtp, sx->conn_args.host) != OK;

  /* Alas; be careful, since this goto is not an error-out, so conceivably
  we might set data between here and the target which we assume to exist
  and be usable.  I can see this coming back to bite us. */
#ifndef DISABLE_TLS
  if (sx->smtps)
    {
    smtp_peer_options |= OPTION_TLS;
    suppress_tls = FALSE;
    ob->tls_tempfail_tryclear = FALSE;
    smtp_command = US"SSL-on-connect";
    goto TLS_NEGOTIATE;
    }
#endif

  if (sx->esmtp)
    {
    if (smtp_write_command(sx,
#ifndef DISABLE_PIPE_CONNECT
	  sx->early_pipe_active ? SCMD_BUFFER :
#endif
	    SCMD_FLUSH,
	  "%s %s\r\n", sx->lmtp ? "LHLO" : "EHLO", sx->helo_data) < 0)
      goto SEND_FAILED;
    sx->esmtp_sent = TRUE;

#ifndef DISABLE_PIPE_CONNECT
    if (sx->early_pipe_active)
      {
      sx->pending_EHLO = TRUE;

      /* If we have too many authenticators to handle and might need to AUTH
      for this transport, pipeline no further as we will need the
      list of auth methods offered.  Reap the banner and EHLO. */

      if (  (ob->hosts_require_auth || ob->hosts_try_auth)
	 && f.smtp_in_early_pipe_no_auth)
	{
	DEBUG(D_transport) debug_printf("may need to auth, so pipeline no further\n");
	if (smtp_write_command(sx, SCMD_FLUSH, NULL) < 0)
	  goto SEND_FAILED;
	if (sync_responses(sx, 2, 0) != 0)
	  {
	  HDEBUG(D_transport)
	    debug_printf("failed reaping pipelined cmd responses\n");
	  goto RESPONSE_FAILED;
	  }
	sx->early_pipe_active = FALSE;
	}
      }
    else
#endif
      if (!smtp_reap_ehlo(sx))
	goto RESPONSE_FAILED;
    }
  else
    DEBUG(D_transport)
      debug_printf("not sending EHLO (host matches hosts_avoid_esmtp)\n");

#ifndef DISABLE_PIPE_CONNECT
  if (!sx->early_pipe_active)
#endif
    if (!sx->esmtp)
      {
      BOOL good_response;
      int n = sizeof(sx->buffer);
      uschar * rsp = sx->buffer;

      if (sx->esmtp_sent && (n = Ustrlen(sx->buffer) + 1) < sizeof(sx->buffer)/2)
	{ rsp = sx->buffer + n; n = sizeof(sx->buffer) - n; }

      if (smtp_write_command(sx, SCMD_FLUSH, "HELO %s\r\n", sx->helo_data) < 0)
	goto SEND_FAILED;
      good_response = smtp_read_response(sx, rsp, n, '2', ob->command_timeout);
#ifdef EXPERIMENTAL_DSN_INFO
      sx->helo_response = string_copy(rsp);
#endif
      if (!good_response)
	{
	/* Handle special logging for a closed connection after HELO
	when had previously sent EHLO */

	if (rsp != sx->buffer && rsp[0] == 0 && (errno == 0 || errno == ECONNRESET))
	  {
	  errno = ERRNO_SMTPCLOSED;
	  goto EHLOHELO_FAILED;
	  }
	memmove(sx->buffer, rsp, Ustrlen(rsp));
	goto RESPONSE_FAILED;
	}
      }

  if (sx->esmtp || sx->lmtp)
    {
#ifndef DISABLE_PIPE_CONNECT
    if (!sx->early_pipe_active)
#endif
      {
      sx->peer_offered = ehlo_response(sx->buffer,
	OPTION_TLS	/* others checked later */
#ifndef DISABLE_PIPE_CONNECT
	| (sx->early_pipe_ok
	  ?   OPTION_IGNQ
	    | OPTION_CHUNKING | OPTION_PRDR | OPTION_DSN | OPTION_PIPE | OPTION_SIZE
#ifdef SUPPORT_I18N
	    | OPTION_UTF8
#endif
	    | OPTION_EARLY_PIPE
	  : 0
	  )
#endif
	);
#ifdef EXPERIMENTAL_ESMTP_LIMITS
      if (tls_out.active.sock >= 0 || !(sx->peer_offered & OPTION_TLS))
	{
	ehlo_response_limits_read(sx);
	ehlo_response_limits_apply(sx);
	}
#endif
#ifndef DISABLE_PIPE_CONNECT
      if (sx->early_pipe_ok)
	{
	sx->ehlo_resp.cleartext_features = sx->peer_offered;

	if (  (sx->peer_offered & (OPTION_PIPE | OPTION_EARLY_PIPE))
	   == (OPTION_PIPE | OPTION_EARLY_PIPE))
	  {
	  DEBUG(D_transport) debug_printf("PIPE_CONNECT usable in future for this IP\n");
	  sx->ehlo_resp.cleartext_auths = study_ehlo_auths(sx);
	  write_ehlo_cache_entry(sx);
	  }
	}
#endif
      }

  /* Set tls_offered if the response to EHLO specifies support for STARTTLS. */

#ifndef DISABLE_TLS
    smtp_peer_options |= sx->peer_offered & OPTION_TLS;
#endif
    }
  }

/* For continuing deliveries down the same channel, having re-exec'd  the socket
is the standard input; for a socket held open from verify it is recorded
in the cutthrough context block.  Either way we don't need to redo EHLO here
(but may need to do so for TLS - see below).
Set up the pointer to where subsequent commands will be left, for
error messages. Note that smtp_peer_options will have been
set from the command line if they were set in the process that passed the
connection on. */

/*XXX continue case needs to propagate DSN_INFO, prob. in deliver.c
as the continue goes via transport_pass_socket() and doublefork and exec.
It does not wait.  Unclear how we keep separate host's responses
separate - we could match up by host ip+port as a bodge. */

else
  {
  if (cutthrough.cctx.sock >= 0 && cutthrough.callout_hold_only)
    {
    sx->cctx = cutthrough.cctx;
    sx->conn_args.host->port = sx->port = cutthrough.host.port;
    }
  else
    {
    sx->cctx.sock = 0;				/* stdin */
    sx->cctx.tls_ctx = NULL;
    smtp_port_for_connect(sx->conn_args.host, sx->port);	/* Record the port that was used */
    }
  sx->inblock.cctx = sx->outblock.cctx = &sx->cctx;
  smtp_command = big_buffer;
  sx->peer_offered = smtp_peer_options;
#ifdef EXPERIMENTAL_ESMTP_LIMITS
  /* Limits passed by cmdline over exec. */
  ehlo_limits_apply(sx,
		    sx->peer_limit_mail = continue_limit_mail,
		    sx->peer_limit_rcpt = continue_limit_rcpt,
		    sx->peer_limit_rcptdom = continue_limit_rcptdom);
#endif
  sx->helo_data = NULL;		/* ensure we re-expand ob->helo_data */

  /* For a continued connection with TLS being proxied for us, or a
  held-open verify connection with TLS, nothing more to do. */

  if (  continue_proxy_cipher
     || (cutthrough.cctx.sock >= 0 && cutthrough.callout_hold_only
         && cutthrough.is_tls)
     )
    {
    sx->pipelining_used = pipelining_active = !!(smtp_peer_options & OPTION_PIPE);
    HDEBUG(D_transport) debug_printf("continued connection, %s TLS\n",
      continue_proxy_cipher ? "proxied" : "verify conn with");
    return OK;
    }
  HDEBUG(D_transport) debug_printf("continued connection, no TLS\n");
  }

/* If TLS is available on this connection, whether continued or not, attempt to
start up a TLS session, unless the host is in hosts_avoid_tls. If successful,
send another EHLO - the server may give a different answer in secure mode. We
use a separate buffer for reading the response to STARTTLS so that if it is
negative, the original EHLO data is available for subsequent analysis, should
the client not be required to use TLS. If the response is bad, copy the buffer
for error analysis. */

#ifndef DISABLE_TLS
if (  smtp_peer_options & OPTION_TLS
   && !suppress_tls
   && verify_check_given_host(CUSS &ob->hosts_avoid_tls, sx->conn_args.host) != OK
   && (  !sx->verify
      || verify_check_given_host(CUSS &ob->hosts_verify_avoid_tls, sx->conn_args.host) != OK
   )  )
  {
  uschar buffer2[4096];

  if (smtp_write_command(sx, SCMD_FLUSH, "STARTTLS\r\n") < 0)
    goto SEND_FAILED;

#ifndef DISABLE_PIPE_CONNECT
  /* If doing early-pipelining reap the banner and EHLO-response but leave
  the response for the STARTTLS we just sent alone.  On fail, assume wrong
  cached capability and retry with the pipelining disabled. */

  if (sx->early_pipe_active && sync_responses(sx, 2, 0) != 0)
    {
    HDEBUG(D_transport)
      debug_printf("failed reaping pipelined cmd responses\n");
    close(sx->cctx.sock);
    sx->cctx.sock = -1;
    sx->early_pipe_active = FALSE;
    goto PIPE_CONNECT_RETRY;
    }
#endif

  /* If there is an I/O error, transmission of this message is deferred. If
  there is a temporary rejection of STARRTLS and tls_tempfail_tryclear is
  false, we also defer. However, if there is a temporary rejection of STARTTLS
  and tls_tempfail_tryclear is true, or if there is an outright rejection of
  STARTTLS, we carry on. This means we will try to send the message in clear,
  unless the host is in hosts_require_tls (tested below). */

  if (!smtp_read_response(sx, buffer2, sizeof(buffer2), '2', ob->command_timeout))
    {
    if (  errno != 0
       || buffer2[0] == 0
       || (buffer2[0] == '4' && !ob->tls_tempfail_tryclear)
       )
      {
      Ustrncpy(sx->buffer, buffer2, sizeof(sx->buffer));
      sx->buffer[sizeof(sx->buffer)-1] = '\0';
      goto RESPONSE_FAILED;
      }
    }

  /* STARTTLS accepted: try to negotiate a TLS session. */

  else
  TLS_NEGOTIATE:
    {
    if (!tls_client_start(&sx->cctx, &sx->conn_args, sx->addrlist, &tls_out, &tls_errstr))
      {
      /* TLS negotiation failed; give an error. From outside, this function may
      be called again to try in clear on a new connection, if the options permit
      it for this host. */
  TLS_CONN_FAILED:
      DEBUG(D_tls) debug_printf("TLS session fail: %s\n", tls_errstr);

# ifdef SUPPORT_DANE
      if (sx->conn_args.dane)
        {
	log_write(0, LOG_MAIN,
	  "DANE attempt failed; TLS connection to %s [%s]: %s",
	  sx->conn_args.host->name, sx->conn_args.host->address, tls_errstr);
#  ifndef DISABLE_EVENT
	(void) event_raise(sx->conn_args.tblock->event_action,
	  US"dane:fail", US"validation-failure");	/* could do with better detail */
#  endif
	}
# endif

      errno = ERRNO_TLSFAILURE;
      message = string_sprintf("TLS session: %s", tls_errstr);
      sx->send_quit = FALSE;
      goto TLS_FAILED;
      }
    sx->send_tlsclose = TRUE;

    /* TLS session is set up.  Check the inblock fill level.  If there is
    content then as we have not yet done a tls read it must have arrived before
    the TLS handshake, in-clear.  That violates the sync requirement of the
    STARTTLS RFC, so fail. */

    if (sx->inblock.ptr != sx->inblock.ptrend)
      {
      DEBUG(D_tls)
	{
	int i = sx->inblock.ptrend - sx->inblock.ptr;
	debug_printf("unused data in input buffer after ack for STARTTLS:\n"
	  "'%.*s'%s\n",
	  i > 100 ? 100 : i, sx->inblock.ptr, i > 100 ? "..." : "");
	}
      tls_errstr = US"synch error before connect";
      goto TLS_CONN_FAILED;
      }

    smtp_peer_options_wrap = smtp_peer_options;
    for (address_item * addr = sx->addrlist; addr; addr = addr->next)
      if (addr->transport_return == PENDING_DEFER)
        {
        addr->cipher = tls_out.cipher;
        addr->ourcert = tls_out.ourcert;
        addr->peercert = tls_out.peercert;
        addr->peerdn = tls_out.peerdn;
	addr->ocsp = tls_out.ocsp;
        addr->tlsver = tls_out.ver;
        }
    }
  }

/* if smtps, we'll have smtp_command set to something else; always safe to
reset it here. */
smtp_command = big_buffer;

/* If we started TLS, redo the EHLO/LHLO exchange over the secure channel. If
helo_data is null, we are dealing with a connection that was passed from
another process, and so we won't have expanded helo_data above. We have to
expand it here. $sending_ip_address and $sending_port are set up right at the
start of the Exim process (in exim.c). */

if (tls_out.active.sock >= 0)
  {
  uschar * greeting_cmd;

  if (!sx->helo_data && !(sx->helo_data = expand_string(ob->helo_data)))
    {
    uschar *message = string_sprintf("failed to expand helo_data: %s",
      expand_string_message);
    set_errno_nohost(sx->addrlist, ERRNO_EXPANDFAIL, message, DEFER, FALSE, &sx->delivery_start);
    yield = DEFER;
    goto SEND_QUIT;
    }

#ifndef DISABLE_PIPE_CONNECT
  /* For SMTPS there is no cleartext early-pipe; use the crypted permission bit.
  We're unlikely to get the group sent and delivered before the server sends its
  banner, but it's still worth sending as a group.
  For STARTTLS allow for cleartext early-pipe but no crypted early-pipe, but not
  the reverse.  */

  if (sx->smtps ? sx->early_pipe_ok : sx->early_pipe_active)
    {
    sx->peer_offered = sx->ehlo_resp.crypted_features;
    if ((sx->early_pipe_active =
	 !!(sx->ehlo_resp.crypted_features & OPTION_EARLY_PIPE)))
      DEBUG(D_transport) debug_printf("Using cached crypted PIPE_CONNECT\n");
    }
#endif
#ifdef EXPERIMMENTAL_ESMTP_LIMITS
  /* As we are about to send another EHLO, forget any LIMITS received so far. */
  sx->peer_limit_mail = sx->peer_limit_rcpt = sx->peer_limit_rcptdom = 0;
  if ((sx->max_mail = sx->conn_args.tblock->connection_max_message) == 0) sx->max_mail = 999999;
  if ((sx->max_rcpt = sx->conn_args.tblock->max_addresses) == 0)          sx->max_rcpt = 999999;
  sx->single_rcpt_domain = FALSE;
#endif

  /* For SMTPS we need to wait for the initial OK response. */
  if (sx->smtps)
#ifndef DISABLE_PIPE_CONNECT
    if (sx->early_pipe_active)
      {
      sx->pending_BANNER = TRUE;
      sx->outblock.cmd_count = 1;
      }
    else
#endif
      if (!smtp_reap_banner(sx))
	goto RESPONSE_FAILED;

  if (sx->lmtp)
    greeting_cmd = US"LHLO";
  else if (sx->esmtp)
    greeting_cmd = US"EHLO";
  else
    {
    greeting_cmd = US"HELO";
    DEBUG(D_transport)
      debug_printf("not sending EHLO (host matches hosts_avoid_esmtp)\n");
    }

  if (smtp_write_command(sx,
#ifndef DISABLE_PIPE_CONNECT
	sx->early_pipe_active ? SCMD_BUFFER :
#endif
	  SCMD_FLUSH,
	"%s %s\r\n", greeting_cmd, sx->helo_data) < 0)
    goto SEND_FAILED;

#ifndef DISABLE_PIPE_CONNECT
  if (sx->early_pipe_active)
    sx->pending_EHLO = TRUE;
  else
#endif
    {
    if (!smtp_reap_ehlo(sx))
#ifdef USE_GNUTLS
      {
      /* The GnuTLS layer in Exim only spots a server-rejection of a client
      cert late, under TLS1.3 - which means here; the first time we try to
      receive crypted data.  Treat it as if it was a connect-time failure.
      See also the early-pipe equivalent... which will be hard; every call
      to sync_responses will need to check the result.
      It would be nicer to have GnuTLS check the cert during the handshake.
      Can it do that, with all the flexibility we need? */

      tls_errstr = US"error on first read";
      goto TLS_CONN_FAILED;
      }
#else
      goto RESPONSE_FAILED;
#endif
    smtp_peer_options = 0;
    }
  }

/* If the host is required to use a secure channel, ensure that we
have one. */

else if (  sx->smtps
# ifdef SUPPORT_DANE
	|| sx->conn_args.dane
# endif
	|| verify_check_given_host(CUSS &ob->hosts_require_tls, sx->conn_args.host) == OK
	)
  {
  errno = ERRNO_TLSREQUIRED;
  message = string_sprintf("a TLS session is required, but %s",
    smtp_peer_options & OPTION_TLS
    ? "an attempt to start TLS failed" : "the server did not offer TLS support");
# if defined(SUPPORT_DANE) && !defined(DISABLE_EVENT)
  if (sx->conn_args.dane)
    (void) event_raise(sx->conn_args.tblock->event_action, US"dane:fail",
      smtp_peer_options & OPTION_TLS
      ? US"validation-failure"		/* could do with better detail */
      : US"starttls-not-supported");
# endif
  goto TLS_FAILED;
  }
#endif	/*DISABLE_TLS*/

/* If TLS is active, we have just started it up and re-done the EHLO command,
so its response needs to be analyzed. If TLS is not active and this is a
continued session down a previously-used socket, we haven't just done EHLO, so
we skip this. */

if (   !continue_hostname
#ifndef DISABLE_TLS
    || tls_out.active.sock >= 0
#endif
    )
  {
  if (sx->esmtp || sx->lmtp)
    {
#ifndef DISABLE_PIPE_CONNECT
  if (!sx->early_pipe_active)
#endif
    {
    sx->peer_offered = ehlo_response(sx->buffer,
	0 /* no TLS */
#ifndef DISABLE_PIPE_CONNECT
	| (sx->lmtp && ob->lmtp_ignore_quota ? OPTION_IGNQ : 0)
	| OPTION_DSN | OPTION_PIPE | OPTION_SIZE
	| OPTION_CHUNKING | OPTION_PRDR | OPTION_UTF8
	| (tls_out.active.sock >= 0 ? OPTION_EARLY_PIPE : 0) /* not for lmtp */

#else

	| (sx->lmtp && ob->lmtp_ignore_quota ? OPTION_IGNQ : 0)
	| OPTION_CHUNKING
	| OPTION_PRDR
# ifdef SUPPORT_I18N
	| (sx->addrlist->prop.utf8_msg ? OPTION_UTF8 : 0)
	  /*XXX if we hand peercaps on to continued-conn processes,
		must not depend on this addr */
# endif
	| OPTION_DSN
	| OPTION_PIPE
	| (ob->size_addition >= 0 ? OPTION_SIZE : 0)
#endif
      );
#ifndef DISABLE_PIPE_CONNECT
    if (tls_out.active.sock >= 0)
      sx->ehlo_resp.crypted_features = sx->peer_offered;
#endif

#ifdef EXPERIMENTAL_ESMTP_LIMITS
    if (tls_out.active.sock >= 0 || !(sx->peer_offered & OPTION_TLS))
      {
      ehlo_response_limits_read(sx);
      ehlo_response_limits_apply(sx);
      }
#endif
    }

    /* Set for IGNOREQUOTA if the response to LHLO specifies support and the
    lmtp_ignore_quota option was set. */

    sx->igquotstr = sx->peer_offered & OPTION_IGNQ ? US" IGNOREQUOTA" : US"";

    /* If the response to EHLO specified support for the SIZE parameter, note
    this, provided size_addition is non-negative. */

    smtp_peer_options |= sx->peer_offered & OPTION_SIZE;

    /* Note whether the server supports PIPELINING. If hosts_avoid_esmtp matched
    the current host, esmtp will be false, so PIPELINING can never be used. If
    the current host matches hosts_avoid_pipelining, don't do it. */

    if (  sx->peer_offered & OPTION_PIPE
       && verify_check_given_host(CUSS &ob->hosts_avoid_pipelining, sx->conn_args.host) != OK)
      smtp_peer_options |= OPTION_PIPE;

    DEBUG(D_transport) debug_printf("%susing PIPELINING\n",
      smtp_peer_options & OPTION_PIPE ? "" : "not ");

    if (  sx->peer_offered & OPTION_CHUNKING
       && verify_check_given_host(CUSS &ob->hosts_try_chunking, sx->conn_args.host) != OK)
      sx->peer_offered &= ~OPTION_CHUNKING;

    if (sx->peer_offered & OPTION_CHUNKING)
      DEBUG(D_transport) debug_printf("CHUNKING usable\n");

#ifndef DISABLE_PRDR
    if (  sx->peer_offered & OPTION_PRDR
       && verify_check_given_host(CUSS &ob->hosts_try_prdr, sx->conn_args.host) != OK)
      sx->peer_offered &= ~OPTION_PRDR;

    if (sx->peer_offered & OPTION_PRDR)
      DEBUG(D_transport) debug_printf("PRDR usable\n");
#endif

    /* Note if the server supports DSN */
    smtp_peer_options |= sx->peer_offered & OPTION_DSN;
    DEBUG(D_transport) debug_printf("%susing DSN\n",
			sx->peer_offered & OPTION_DSN ? "" : "not ");

#ifndef DISABLE_PIPE_CONNECT
    if (  sx->early_pipe_ok
       && !sx->early_pipe_active
       && tls_out.active.sock >= 0
       && smtp_peer_options & OPTION_PIPE
       && ( sx->ehlo_resp.cleartext_features | sx->ehlo_resp.crypted_features)
	  & OPTION_EARLY_PIPE)
      {
      DEBUG(D_transport) debug_printf("PIPE_CONNECT usable in future for this IP\n");
      sx->ehlo_resp.crypted_auths = study_ehlo_auths(sx);
      write_ehlo_cache_entry(sx);
      }
#endif

    /* Note if the response to EHLO specifies support for the AUTH extension.
    If it has, check that this host is one we want to authenticate to, and do
    the business. The host name and address must be available when the
    authenticator's client driver is running. */

    switch (yield = smtp_auth(sx))
      {
      default:		goto SEND_QUIT;
      case OK:		break;
      case FAIL_SEND:	goto SEND_FAILED;
      case FAIL:	goto RESPONSE_FAILED;
      }
    }
  }
sx->pipelining_used = pipelining_active = !!(smtp_peer_options & OPTION_PIPE);

/* The setting up of the SMTP call is now complete. Any subsequent errors are
message-specific. */

sx->setting_up = FALSE;

#ifdef SUPPORT_I18N
if (sx->addrlist->prop.utf8_msg)
  {
  uschar * s;

  /* If the transport sets a downconversion mode it overrides any set by ACL
  for the message. */

  if ((s = ob->utf8_downconvert))
    {
    if (!(s = expand_string(s)))
      {
      message = string_sprintf("failed to expand utf8_downconvert: %s",
        expand_string_message);
      set_errno_nohost(sx->addrlist, ERRNO_EXPANDFAIL, message, DEFER, FALSE, &sx->delivery_start);
      yield = DEFER;
      goto SEND_QUIT;
      }
    switch (*s)
      {
      case '1':	sx->addrlist->prop.utf8_downcvt = TRUE;
		sx->addrlist->prop.utf8_downcvt_maybe = FALSE;
		break;
      case '0':	sx->addrlist->prop.utf8_downcvt = FALSE;
		sx->addrlist->prop.utf8_downcvt_maybe = FALSE;
		break;
      case '-':	if (s[1] == '1')
		  {
		  sx->addrlist->prop.utf8_downcvt = FALSE;
		  sx->addrlist->prop.utf8_downcvt_maybe = TRUE;
		  }
		break;
      }
    }

  sx->utf8_needed = !sx->addrlist->prop.utf8_downcvt
		    && !sx->addrlist->prop.utf8_downcvt_maybe;
  DEBUG(D_transport) if (!sx->utf8_needed)
    debug_printf("utf8: %s downconvert\n",
      sx->addrlist->prop.utf8_downcvt ? "mandatory" : "optional");
  }

/* If this is an international message we need the host to speak SMTPUTF8 */
if (sx->utf8_needed && !(sx->peer_offered & OPTION_UTF8))
  {
  errno = ERRNO_UTF8_FWD;
  goto RESPONSE_FAILED;
  }
#endif	/*SUPPORT_I18N*/

return OK;


  {
  int code;

  RESPONSE_FAILED:
    if (errno == ECONNREFUSED)	/* first-read error on a TFO conn */
      {
      /* There is a testing facility for simulating a connection timeout, as I
      can't think of any other way of doing this. It converts a connection
      refused into a timeout if the timeout is set to 999999.  This is done for
      a 3whs connection in ip_connect(), but a TFO connection does not error
      there - instead it gets ECONNREFUSED on the first data read.  Tracking
      that a TFO really was done is too hard, or we would set a
      sx->pending_conn_done bit and test that in smtp_reap_banner() and
      smtp_reap_ehlo().  That would let us also add the conn-timeout to the
      cmd-timeout. */

      if (f.running_in_test_harness && ob->connect_timeout == 999999)
	errno = ETIMEDOUT;
      set_errno_nohost(sx->addrlist,
	errno == ETIMEDOUT ? ERRNO_CONNECTTIMEOUT : errno,
	sx->verify ? US strerror(errno) : NULL,
	DEFER, FALSE, &sx->delivery_start);
      sx->send_quit = FALSE;
      return DEFER;
      }

    /* really an error on an SMTP read */
    message = NULL;
    sx->send_quit = check_response(sx->conn_args.host, &errno, sx->addrlist->more_errno,
      sx->buffer, &code, &message, &pass_message);
    yield = DEFER;
    goto FAILED;

  SEND_FAILED:
    code = '4';
    message = US string_sprintf("send() to %s [%s] failed: %s",
      sx->conn_args.host->name, sx->conn_args.host->address, strerror(errno));
    sx->send_quit = FALSE;
    yield = DEFER;
    goto FAILED;

  EHLOHELO_FAILED:
    code = '4';
    message = string_sprintf("Remote host closed connection in response to %s"
      " (EHLO response was: %s)", smtp_command, sx->buffer);
    sx->send_quit = FALSE;
    yield = DEFER;
    goto FAILED;

  /* This label is jumped to directly when a TLS negotiation has failed,
  or was not done for a host for which it is required. Values will be set
  in message and errno, and setting_up will always be true. Treat as
  a temporary error. */

#ifndef DISABLE_TLS
  TLS_FAILED:
    code = '4', yield = DEFER;
    goto FAILED;
#endif

  /* The failure happened while setting up the call; see if the failure was
  a 5xx response (this will either be on connection, or following HELO - a 5xx
  after EHLO causes it to try HELO). If so, and there are no more hosts to try,
  fail all addresses, as this host is never going to accept them. For other
  errors during setting up (timeouts or whatever), defer all addresses, and
  yield DEFER, so that the host is not tried again for a while.

  XXX This peeking for another host feels like a layering violation. We want
  to note the host as unusable, but down here we shouldn't know if this was
  the last host to try for the addr(list).  Perhaps the upper layer should be
  the one to do set_errno() ?  The problem is that currently the addr is where
  errno etc. are stashed, but until we run out of hosts to try the errors are
  host-specific.  Maybe we should enhance the host_item definition? */

FAILED:
  sx->ok = FALSE;                /* For when reached by GOTO */
  set_errno(sx->addrlist, errno, message,
	    sx->conn_args.host->next
	    ? DEFER
	    : code == '5'
#ifdef SUPPORT_I18N
			|| errno == ERRNO_UTF8_FWD
#endif
	    ? FAIL : DEFER,
	    pass_message,
	    errno == ECONNREFUSED ? NULL : sx->conn_args.host,
#ifdef EXPERIMENTAL_DSN_INFO
	    sx->smtp_greeting, sx->helo_response,
#endif
	    &sx->delivery_start);
  }


SEND_QUIT:

if (sx->send_quit)
  (void)smtp_write_command(sx, SCMD_FLUSH, "QUIT\r\n");

#ifndef DISABLE_TLS
if (sx->cctx.tls_ctx)
  {
  if (sx->send_tlsclose)
    {
    tls_close(sx->cctx.tls_ctx, TLS_SHUTDOWN_NOWAIT);
    sx->send_tlsclose = FALSE;
    }
  sx->cctx.tls_ctx = NULL;
  }
#endif

/* Close the socket, and return the appropriate value, first setting
works because the NULL setting is passed back to the calling process, and
remote_max_parallel is forced to 1 when delivering over an existing connection,
*/

HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  SMTP(close)>>\n");
if (sx->send_quit)
  {
  shutdown(sx->cctx.sock, SHUT_WR);
  if (fcntl(sx->cctx.sock, F_SETFL, O_NONBLOCK) == 0)
    for (int i = 16; read(sx->cctx.sock, sx->inbuffer, sizeof(sx->inbuffer)) > 0 && i > 0;)
      i--;				/* drain socket */
  sx->send_quit = FALSE;
  }
(void)close(sx->cctx.sock);
sx->cctx.sock = -1;

#ifndef DISABLE_EVENT
(void) event_raise(sx->conn_args.tblock->event_action, US"tcp:close", NULL);
#endif

continue_transport = NULL;
continue_hostname = NULL;
return yield;
}




/* Create the string of options that will be appended to the MAIL FROM:
in the connection context buffer */

static int
build_mailcmd_options(smtp_context * sx, address_item * addrlist)
{
uschar * p = sx->buffer;
address_item * addr;
int address_count;

*p = 0;

/* If we know the receiving MTA supports the SIZE qualification, and we know it,
send it, adding something to the message size to allow for imprecision
and things that get added en route. Exim keeps the number of lines
in a message, so we can give an accurate value for the original message, but we
need some additional to handle added headers. (Double "." characters don't get
included in the count.) */

if (  message_size > 0
   && sx->peer_offered & OPTION_SIZE && !(sx->avoid_option & OPTION_SIZE))
  {
/*XXX problem here under spool_files_wireformat?
Or just forget about lines?  Or inflate by a fixed proportion? */

  sprintf(CS p, " SIZE=%d", message_size+message_linecount+(SOB sx->conn_args.ob)->size_addition);
  while (*p) p++;
  }

#ifndef DISABLE_PRDR
/* If it supports Per-Recipient Data Responses, and we have more than one recipient,
request that */

sx->prdr_active = FALSE;
if (sx->peer_offered & OPTION_PRDR)
  for (address_item * addr = addrlist; addr; addr = addr->next)
    if (addr->transport_return == PENDING_DEFER)
      {
      for (addr = addr->next; addr; addr = addr->next)
        if (addr->transport_return == PENDING_DEFER)
	  {			/* at least two recipients to send */
	  sx->prdr_active = TRUE;
	  sprintf(CS p, " PRDR"); p += 5;
	  break;
	  }
      break;
      }
#endif

#ifdef SUPPORT_I18N
/* If it supports internationalised messages, and this meesage need that,
request it */

if (  sx->peer_offered & OPTION_UTF8
   && addrlist->prop.utf8_msg
   && !addrlist->prop.utf8_downcvt
   )
  Ustrcpy(p, US" SMTPUTF8"), p += 9;
#endif

/* check if all addresses have DSN-lasthop flag; do not send RET and ENVID if so */
for (sx->dsn_all_lasthop = TRUE, addr = addrlist, address_count = 0;
     addr && address_count < sx->max_rcpt;	/*XXX maybe also || sx->single_rcpt_domain ? */
     addr = addr->next) if (addr->transport_return == PENDING_DEFER)
  {
  address_count++;
  if (!(addr->dsn_flags & rf_dsnlasthop))
    {
    sx->dsn_all_lasthop = FALSE;
    break;
    }
  }

/* Add any DSN flags to the mail command */

if (sx->peer_offered & OPTION_DSN && !sx->dsn_all_lasthop)
  {
  if (dsn_ret == dsn_ret_hdrs)
    { Ustrcpy(p, US" RET=HDRS"); p += 9; }
  else if (dsn_ret == dsn_ret_full)
    { Ustrcpy(p, US" RET=FULL"); p += 9; }

  if (dsn_envid)
    {
    string_format(p, sizeof(sx->buffer) - (p-sx->buffer), " ENVID=%s", dsn_envid);
    while (*p) p++;
    }
  }

/* If an authenticated_sender override has been specified for this transport
instance, expand it. If the expansion is forced to fail, and there was already
an authenticated_sender for this message, the original value will be used.
Other expansion failures are serious. An empty result is ignored, but there is
otherwise no check - this feature is expected to be used with LMTP and other
cases where non-standard addresses (e.g. without domains) might be required. */

return smtp_mail_auth_str(sx, p, addrlist) ? ERROR : OK;
}


static void
build_rcptcmd_options(smtp_context * sx, const address_item * addr)
{
uschar * p = sx->buffer;
*p = 0;

/* Add any DSN flags to the rcpt command */

if (sx->peer_offered & OPTION_DSN && !(addr->dsn_flags & rf_dsnlasthop))
  {
  if (addr->dsn_flags & rf_dsnflags)
    {
    BOOL first = TRUE;

    Ustrcpy(p, US" NOTIFY=");
    while (*p) p++;
    for (int i = 0; i < nelem(rf_list); i++) if (addr->dsn_flags & rf_list[i])
      {
      if (!first) *p++ = ',';
      first = FALSE;
      Ustrcpy(p, rf_names[i]);
      while (*p) p++;
      }
    }

  if (addr->dsn_orcpt)
    {
    string_format(p, sizeof(sx->buffer) - (p-sx->buffer), " ORCPT=%s",
      addr->dsn_orcpt);
    while (*p) p++;
    }
  }
}



/*
Return:
 0	good, rcpt results in addr->transport_return (PENDING_OK, DEFER, FAIL)
 -1	MAIL response error
 -2	any non-MAIL read i/o error
 -3	non-MAIL response timeout
 -4	internal error; channel still usable
 -5	transmit failed
 */

int
smtp_write_mail_and_rcpt_cmds(smtp_context * sx, int * yield)
{
address_item * addr;
#ifdef EXPERIMENTAL_ESMTP_LIMITS
address_item * restart_addr = NULL;
#endif
int address_count, pipe_limit;
int rc;

if (build_mailcmd_options(sx, sx->first_addr) != OK)
  {
  *yield = ERROR;
  return -4;
  }

/* From here until we send the DATA command, we can make use of PIPELINING
if the server host supports it. The code has to be able to check the responses
at any point, for when the buffer fills up, so we write it totally generally.
When PIPELINING is off, each command written reports that it has flushed the
buffer. */

sx->pending_MAIL = TRUE;     /* The block starts with MAIL */

  {
  uschar * s = sx->from_addr;
#ifdef SUPPORT_I18N
  uschar * errstr = NULL;

  /* If we must downconvert, do the from-address here.  Remember we had to
  for the to-addresses (done below), and also (ugly) for re-doing when building
  the delivery log line. */

  if (  sx->addrlist->prop.utf8_msg
     && (sx->addrlist->prop.utf8_downcvt || !(sx->peer_offered & OPTION_UTF8))
     )
    {
    if (s = string_address_utf8_to_alabel(s, &errstr), errstr)
      {
      set_errno_nohost(sx->addrlist, ERRNO_EXPANDFAIL, errstr, DEFER, FALSE, &sx->delivery_start);
      *yield = ERROR;
      return -4;
      }
    setflag(sx->addrlist, af_utf8_downcvt);
    }
#endif

  rc = smtp_write_command(sx, pipelining_active ? SCMD_BUFFER : SCMD_FLUSH,
	  "MAIL FROM:<%s>%s\r\n", s, sx->buffer);
  }

mail_command = string_copy(big_buffer);  /* Save for later error message */

switch(rc)
  {
  case -1:                /* Transmission error */
    return -5;

  case +1:                /* Cmd was sent */
    if (!smtp_read_response(sx, sx->buffer, sizeof(sx->buffer), '2',
       (SOB sx->conn_args.ob)->command_timeout))
      {
      if (errno == 0 && sx->buffer[0] == '4')
	{
	errno = ERRNO_MAIL4XX;
	sx->addrlist->more_errno |= ((sx->buffer[1] - '0')*10 + sx->buffer[2] - '0') << 8;
	}
      return -1;
      }
    sx->pending_MAIL = FALSE;
    break;

  /* otherwise zero: command queued for pipeline */
  }

/* Pass over all the relevant recipient addresses for this host, which are the
ones that have status PENDING_DEFER. If we are using PIPELINING, we can send
several before we have to read the responses for those seen so far. This
checking is done by a subroutine because it also needs to be done at the end.
Send only up to max_rcpt addresses at a time, leaving next_addr pointing to
the next one if not all are sent.

In the MUA wrapper situation, we want to flush the PIPELINING buffer for the
last address because we want to abort if any recipients have any kind of
problem, temporary or permanent. We know that all recipient addresses will have
the PENDING_DEFER status, because only one attempt is ever made, and we know
that max_rcpt will be large, so all addresses will be done at once.

For verify we flush the pipeline after any (the only) rcpt address. */

for (addr = sx->first_addr, address_count = 0, pipe_limit = 100;
     addr &&  address_count < sx->max_rcpt;
     addr = addr->next) if (addr->transport_return == PENDING_DEFER)
  {
  int cmds_sent;
  BOOL no_flush;
  uschar * rcpt_addr;

#ifdef EXPERIMENTAL_ESMTP_LIMITS
  if (  sx->single_rcpt_domain					/* restriction on domains */
     && address_count > 0					/* not first being sent */
     && Ustrcmp(addr->domain, sx->first_addr->domain) != 0	/* dom diff from first */
     )
    {
    DEBUG(D_transport) debug_printf("skipping different domain %s\n", addr->domain);

    /* Ensure the smtp-response reaper does not think the address had a RCPT
    command sent for it.  Reset to PENDING_DEFER in smtp_deliver(), where we
    goto SEND_MESSAGE.  */

    addr->transport_return = SKIP;
    if (!restart_addr) restart_addr = addr;	/* note restart point */
    continue;					/* skip this one */
    }
#endif

  addr->dsn_aware = sx->peer_offered & OPTION_DSN
    ? dsn_support_yes : dsn_support_no;

  address_count++;
  if (pipe_limit-- <= 0)
    { no_flush = FALSE; pipe_limit = 100; }
  else
    no_flush = pipelining_active && !sx->verify
	  && (!mua_wrapper || addr->next && address_count < sx->max_rcpt);

  build_rcptcmd_options(sx, addr);

  /* Now send the RCPT command, and process outstanding responses when
  necessary. After a timeout on RCPT, we just end the function, leaving the
  yield as OK, because this error can often mean that there is a problem with
  just one address, so we don't want to delay the host. */

  rcpt_addr = transport_rcpt_address(addr, sx->conn_args.tblock->rcpt_include_affixes);

#ifdef SUPPORT_I18N
  if (  testflag(sx->addrlist, af_utf8_downcvt)
     && !(rcpt_addr = string_address_utf8_to_alabel(rcpt_addr, NULL))
     )
    {
    /*XXX could we use a per-address errstr here? Not fail the whole send? */
    errno = ERRNO_EXPANDFAIL;
    return -5;		/*XXX too harsh? */
    }
#endif

  cmds_sent = smtp_write_command(sx, no_flush ? SCMD_BUFFER : SCMD_FLUSH,
    "RCPT TO:<%s>%s%s\r\n", rcpt_addr, sx->igquotstr, sx->buffer);

  if (cmds_sent < 0) return -5;
  if (cmds_sent > 0)
    {
    switch(sync_responses(sx, cmds_sent, 0))
      {
      case 3: sx->ok = TRUE;			/* 2xx & 5xx => OK & progress made */
      case 2: sx->completed_addr = TRUE;	/* 5xx (only) => progress made */
	      break;

      case 1: sx->ok = TRUE;			/* 2xx (only) => OK, but if LMTP, */
	      if (!sx->lmtp)			/*  can't tell about progress yet */
		sx->completed_addr = TRUE;
      case 0:					/* No 2xx or 5xx, but no probs */
	      /* If any RCPT got a 452 response then next_addr has been updated
	      for restarting with a new MAIL on the same connection.  Send no more
	      RCPTs for this MAIL. */

	      if (sx->RCPT_452)
		{
		DEBUG(D_transport) debug_printf("seen 452 too-many-rcpts\n");
		sx->RCPT_452 = FALSE;
		/* sx->next_addr has been reset for fast_retry */
		return 0;
		}
	      break;

      case -1: return -3;			/* Timeout on RCPT */
      case -2: return -2;			/* non-MAIL read i/o error */
      default: return -1;			/* any MAIL error */

#ifndef DISABLE_PIPE_CONNECT
      case -4: return -1;			/* non-2xx for pipelined banner or EHLO */
      case -5: return -1;			/* TLS first-read error */
#endif
      }
    }
  }      /* Loop for next address */

#ifdef EXPERIMENTAL_ESMTP_LIMITS
sx->next_addr = restart_addr ? restart_addr : addr;
#else
sx->next_addr = addr;
#endif
return 0;
}


#ifndef DISABLE_TLS
/*****************************************************
* Proxy TLS connection for another transport process *
******************************************************/
/*
Close the unused end of the pipe, fork once more, then use the given buffer
as a staging area, and select on both the given fd and the TLS'd client-fd for
data to read (per the coding in ip_recv() and fd_ready() this is legitimate).
Do blocking full-size writes, and reads under a timeout.  Once both input
channels are closed, exit the process.

Arguments:
  ct_ctx	tls context
  buf		space to use for buffering
  bufsiz	size of buffer
  pfd		pipe filedescriptor array; [0] is comms to proxied process
  timeout	per-read timeout, seconds

Does not return.
*/

void
smtp_proxy_tls(void * ct_ctx, uschar * buf, size_t bsize, int * pfd,
  int timeout)
{
fd_set rfds, efds;
int max_fd = MAX(pfd[0], tls_out.active.sock) + 1;
int rc, i;
BOOL send_tls_shutdown = TRUE;

close(pfd[1]);
if ((rc = exim_fork(US"tls-proxy")))
  _exit(rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS);

set_process_info("proxying TLS connection for continued transport");
FD_ZERO(&rfds);
FD_SET(tls_out.active.sock, &rfds);
FD_SET(pfd[0], &rfds);

for (int fd_bits = 3; fd_bits; )
  {
  time_t time_left = timeout;
  time_t time_start = time(NULL);

  /* wait for data */
  efds = rfds;
  do
    {
    struct timeval tv = { time_left, 0 };

    rc = select(max_fd,
      (SELECT_ARG2_TYPE *)&rfds, NULL, (SELECT_ARG2_TYPE *)&efds, &tv);

    if (rc < 0 && errno == EINTR)
      if ((time_left -= time(NULL) - time_start) > 0) continue;

    if (rc <= 0)
      {
      DEBUG(D_transport) if (rc == 0) debug_printf("%s: timed out\n", __FUNCTION__);
      goto done;
      }

    /* For errors where not readable, bomb out */

    if (FD_ISSET(tls_out.active.sock, &efds) || FD_ISSET(pfd[0], &efds))
      {
      DEBUG(D_transport) debug_printf("select: exceptional cond on %s fd\n",
	FD_ISSET(pfd[0], &efds) ? "proxy" : "tls");
      if (!(FD_ISSET(tls_out.active.sock, &rfds) || FD_ISSET(pfd[0], &rfds)))
	goto done;
      DEBUG(D_transport) debug_printf("- but also readable; no exit yet\n");
      }
    }
  while (rc < 0 || !(FD_ISSET(tls_out.active.sock, &rfds) || FD_ISSET(pfd[0], &rfds)));

  /* handle inbound data */
  if (FD_ISSET(tls_out.active.sock, &rfds))
    if ((rc = tls_read(ct_ctx, buf, bsize)) <= 0)	/* Expect -1 for EOF; */
    {				    /* that reaps the TLS Close Notify record */
      fd_bits &= ~1;
      FD_CLR(tls_out.active.sock, &rfds);
      shutdown(pfd[0], SHUT_WR);
      timeout = 5;
      }
    else
      for (int nbytes = 0; rc - nbytes > 0; nbytes += i)
	if ((i = write(pfd[0], buf + nbytes, rc - nbytes)) < 0) goto done;

  /* Handle outbound data.  We cannot combine payload and the TLS-close
  due to the limitations of the (pipe) channel feeding us.  Maybe use a unix-domain
  socket? */
  if (FD_ISSET(pfd[0], &rfds))
    if ((rc = read(pfd[0], buf, bsize)) <= 0)
      {
      fd_bits &= ~2;
      FD_CLR(pfd[0], &rfds);

# ifdef EXIM_TCP_CORK  /* Use _CORK to get TLS Close Notify in FIN segment */
      (void) setsockopt(tls_out.active.sock, IPPROTO_TCP, EXIM_TCP_CORK, US &on, sizeof(on));
# endif
      tls_shutdown_wr(ct_ctx);
      send_tls_shutdown = FALSE;
      shutdown(tls_out.active.sock, SHUT_WR);
      }
    else
      for (int nbytes = 0; rc - nbytes > 0; nbytes += i)
	if ((i = tls_write(ct_ctx, buf + nbytes, rc - nbytes, FALSE)) < 0)
	  goto done;

  if (fd_bits & 1) FD_SET(tls_out.active.sock, &rfds);
  if (fd_bits & 2) FD_SET(pfd[0], &rfds);
  }

done:
  if (send_tls_shutdown) tls_close(ct_ctx, TLS_SHUTDOWN_NOWAIT);
  ct_ctx = NULL;
  testharness_pause_ms(100);	/* let logging complete */
  exim_exit(EXIT_SUCCESS);
}
#endif


/*************************************************
*       Deliver address list to given host       *
*************************************************/

/* If continue_hostname is not null, we get here only when continuing to
deliver down an existing channel. The channel was passed as the standard
input. TLS is never active on a passed channel; the previous process either
closes it down before passing the connection on, or inserts a TLS-proxy
process and passes on a cleartext conection.

Otherwise, we have to make a connection to the remote host, and do the
initial protocol exchange.

When running as an MUA wrapper, if the sender or any recipient is rejected,
temporarily or permanently, we force failure for all recipients.

Arguments:
  addrlist        chain of potential addresses to deliver; only those whose
                  transport_return field is set to PENDING_DEFER are currently
                  being processed; others should be skipped - they have either
                  been delivered to an earlier host or IP address, or been
                  failed by one of them.
  host            host to deliver to
  host_af         AF_INET or AF_INET6
  defport         default TCP/IP port to use if host does not specify, in host
		  byte order
  interface       interface to bind to, or NULL
  tblock          transport instance block
  message_defer   set TRUE if yield is OK, but all addresses were deferred
                    because of a non-recipient, non-host failure, that is, a
                    4xx response to MAIL FROM, DATA, or ".". This is a defer
                    that is specific to the message.
  suppress_tls    if TRUE, don't attempt a TLS connection - this is set for
                    a second attempt after TLS initialization fails

Returns:          OK    - the connection was made and the delivery attempted;
                          the result for each address is in its data block.
                  DEFER - the connection could not be made, or something failed
                          while setting up the SMTP session, or there was a
                          non-message-specific error, such as a timeout.
                  ERROR - a filter command is specified for this transport,
                          and there was a problem setting it up; OR helo_data
                          or add_headers or authenticated_sender is specified
                          for this transport, and the string failed to expand

		For all non-OK returns the first addr of the list carries the
		time taken for the attempt.
*/

static int
smtp_deliver(address_item *addrlist, host_item *host, int host_af, int defport,
  uschar *interface, transport_instance *tblock,
  BOOL *message_defer, BOOL suppress_tls)
{
smtp_transport_options_block * ob = SOB tblock->options_block;
int yield = OK;
int save_errno;
int rc;

uschar *message = NULL;
uschar new_message_id[MESSAGE_ID_LENGTH + 1];
smtp_context * sx = store_get(sizeof(*sx), TRUE);	/* tainted, for the data buffers */
BOOL pass_message = FALSE;
#ifdef EXPERIMENTAL_ESMTP_LIMITS
BOOL mail_limit = FALSE;
#endif
#ifdef SUPPORT_DANE
BOOL dane_held;
#endif
BOOL tcw_done = FALSE, tcw = FALSE;

*message_defer = FALSE;

memset(sx, 0, sizeof(*sx));
sx->addrlist = addrlist;
sx->conn_args.host = host;
sx->conn_args.host_af = host_af,
sx->port = defport;
sx->conn_args.interface = interface;
sx->helo_data = NULL;
sx->conn_args.tblock = tblock;
/* sx->verify = FALSE; */
gettimeofday(&sx->delivery_start, NULL);
sx->sync_addr = sx->first_addr = addrlist;

REPEAT_CONN:
#ifdef SUPPORT_DANE
dane_held = FALSE;
#endif

/* Get the channel set up ready for a message, MAIL FROM being the next
SMTP command to send. */

if ((rc = smtp_setup_conn(sx, suppress_tls)) != OK)
  {
  timesince(&addrlist->delivery_time, &sx->delivery_start);
  yield = rc;
  goto TIDYUP;
  }

#ifdef SUPPORT_DANE
/* If the connection used DANE, ignore for now any addresses with incompatible
domains.  The SNI has to be the domain.  Arrange a whole new TCP conn later,
just in case only TLS isn't enough. */

if (sx->conn_args.dane)
  {
  const uschar * dane_domain = sx->first_addr->domain;

  for (address_item * a = sx->first_addr->next; a; a = a->next)
    if (  a->transport_return == PENDING_DEFER
       && Ustrcmp(dane_domain, a->domain) != 0)
      {
      DEBUG(D_transport) debug_printf("DANE: holding %s for later\n", a->domain);
      dane_held = TRUE;
      a->transport_return = DANE;
      }
  }
#endif

/* If there is a filter command specified for this transport, we can now
set it up. This cannot be done until the identity of the host is known. */

if (tblock->filter_command)
  {
  transport_filter_timeout = tblock->filter_timeout;

  /* On failure, copy the error to all addresses, abandon the SMTP call, and
  yield ERROR. */

  if (!transport_set_up_command(&transport_filter_argv,
	tblock->filter_command, TRUE, DEFER, addrlist,
	string_sprintf("%.50s transport", tblock->name), NULL))
    {
    set_errno_nohost(addrlist->next, addrlist->basic_errno, addrlist->message, DEFER,
      FALSE, &sx->delivery_start);
    yield = ERROR;
    goto SEND_QUIT;
    }

  if (  transport_filter_argv
     && *transport_filter_argv
     && **transport_filter_argv
     && sx->peer_offered & OPTION_CHUNKING
#ifndef DISABLE_DKIM
    /* When dkim signing, chunking is handled even with a transport-filter */
     && !(ob->dkim.dkim_private_key && ob->dkim.dkim_domain && ob->dkim.dkim_selector)
     && !ob->dkim.force_bodyhash
#endif
     )
    {
    sx->peer_offered &= ~OPTION_CHUNKING;
    DEBUG(D_transport) debug_printf("CHUNKING not usable due to transport filter\n");
    }
  }

/* For messages that have more than the maximum number of envelope recipients,
we want to send several transactions down the same SMTP connection. (See
comments in deliver.c as to how this reconciles, heuristically, with
remote_max_parallel.) This optimization was added to Exim after the following
code was already working. The simplest way to put it in without disturbing the
code was to use a goto to jump back to this point when there is another
transaction to handle. */

SEND_MESSAGE:
sx->from_addr = return_path;
sx->sync_addr = sx->first_addr;
sx->ok = FALSE;
sx->send_rset = TRUE;
sx->completed_addr = FALSE;


/* If we are a continued-connection-after-verify the MAIL and RCPT
commands were already sent; do not re-send but do mark the addrs as
having been accepted up to RCPT stage.  A traditional cont-conn
always has a sequence number greater than one. */

if (continue_hostname && continue_sequence == 1)
  {
  /* sx->pending_MAIL = FALSE; */
  sx->ok = TRUE;
  /* sx->next_addr = NULL; */

  for (address_item * addr = addrlist; addr; addr = addr->next)
    addr->transport_return = PENDING_OK;
  }
else
  {
  /* Initiate a message transfer. */

  switch(smtp_write_mail_and_rcpt_cmds(sx, &yield))
    {
    case 0:		break;
    case -1: case -2:	goto RESPONSE_FAILED;
    case -3:		goto END_OFF;
    case -4:		goto SEND_QUIT;
    default:		goto SEND_FAILED;
    }

  /* If we are an MUA wrapper, abort if any RCPTs were rejected, either
  permanently or temporarily. We should have flushed and synced after the last
  RCPT. */

  if (mua_wrapper)
    {
    address_item * a;
    unsigned cnt;

    for (a = sx->first_addr, cnt = 0; a && cnt < sx->max_rcpt; a = a->next, cnt++)
      if (a->transport_return != PENDING_OK)
	{
	/*XXX could we find a better errno than 0 here? */
	set_errno_nohost(addrlist, 0, a->message, FAIL,
	  testflag(a, af_pass_message), &sx->delivery_start);
	sx->ok = FALSE;
	break;
	}
    }
  }

/* If ok is TRUE, we know we have got at least one good recipient, and must now
send DATA, but if it is FALSE (in the normal, non-wrapper case), we may still
have a good recipient buffered up if we are pipelining. We don't want to waste
time sending DATA needlessly, so we only send it if either ok is TRUE or if we
are pipelining. The responses are all handled by sync_responses().
If using CHUNKING, do not send a BDAT until we know how big a chunk we want
to send is. */

if (  !(sx->peer_offered & OPTION_CHUNKING)
   && (sx->ok || (pipelining_active && !mua_wrapper)))
  {
  int count = smtp_write_command(sx, SCMD_FLUSH, "DATA\r\n");

  if (count < 0) goto SEND_FAILED;
  switch(sync_responses(sx, count, sx->ok ? +1 : -1))
    {
    case 3: sx->ok = TRUE;            /* 2xx & 5xx => OK & progress made */
    case 2: sx->completed_addr = TRUE;    /* 5xx (only) => progress made */
    break;

    case 1: sx->ok = TRUE;            /* 2xx (only) => OK, but if LMTP, */
    if (!sx->lmtp) sx->completed_addr = TRUE; /* can't tell about progress yet */
    case 0: break;			/* No 2xx or 5xx, but no probs */

    case -1: goto END_OFF;		/* Timeout on RCPT */

#ifndef DISABLE_PIPE_CONNECT
    case -5:				/* TLS first-read error */
    case -4:  HDEBUG(D_transport)
		debug_printf("failed reaping pipelined cmd responses\n");
#endif
    default: goto RESPONSE_FAILED;       /* I/O error, or any MAIL/DATA error */
    }
  pipelining_active = FALSE;
  data_command = string_copy(big_buffer);  /* Save for later error message */
  }

/* If there were no good recipients (but otherwise there have been no
problems), just set ok TRUE, since we have handled address-specific errors
already. Otherwise, it's OK to send the message. Use the check/escape mechanism
for handling the SMTP dot-handling protocol, flagging to apply to headers as
well as body. Set the appropriate timeout value to be used for each chunk.
(Haven't been able to make it work using select() for writing yet.) */

if (  !sx->ok
   && (!(sx->peer_offered & OPTION_CHUNKING) || !pipelining_active))
  {
  /* Save the first address of the next batch. */
  sx->first_addr = sx->next_addr;

  sx->ok = TRUE;
  }
else
  {
  transport_ctx tctx = {
    .u = {.fd = sx->cctx.sock},	/*XXX will this need TLS info? */
    .tblock =	tblock,
    .addr =	addrlist,
    .check_string = US".",
    .escape_string = US"..",	/* Escaping strings */
    .options =
      topt_use_crlf | topt_escape_headers
    | (tblock->body_only	? topt_no_headers : 0)
    | (tblock->headers_only	? topt_no_body : 0)
    | (tblock->return_path_add	? topt_add_return_path : 0)
    | (tblock->delivery_date_add ? topt_add_delivery_date : 0)
    | (tblock->envelope_to_add	? topt_add_envelope_to : 0)
  };

  /* If using CHUNKING we need a callback from the generic transport
  support to us, for the sending of BDAT smtp commands and the reaping
  of responses.  The callback needs a whole bunch of state so set up
  a transport-context structure to be passed around. */

  if (sx->peer_offered & OPTION_CHUNKING)
    {
    tctx.check_string = tctx.escape_string = NULL;
    tctx.options |= topt_use_bdat;
    tctx.chunk_cb = smtp_chunk_cmd_callback;
    sx->pending_BDAT = FALSE;
    sx->good_RCPT = sx->ok;
    sx->cmd_count = 0;
    tctx.smtp_context = sx;
    }
  else
    tctx.options |= topt_end_dot;

  /* Save the first address of the next batch. */
  sx->first_addr = sx->next_addr;

  /* Responses from CHUNKING commands go in buffer.  Otherwise,
  there has not been a response. */

  sx->buffer[0] = 0;

  sigalrm_seen = FALSE;
  transport_write_timeout = ob->data_timeout;
  smtp_command = US"sending data block";   /* For error messages */
  DEBUG(D_transport|D_v)
    if (sx->peer_offered & OPTION_CHUNKING)
      debug_printf("         will write message using CHUNKING\n");
    else
      debug_printf("  SMTP>> writing message and terminating \".\"\n");
  transport_count = 0;

#ifndef DISABLE_DKIM
  {
# ifdef MEASURE_TIMING
  struct timeval t0;
  gettimeofday(&t0, NULL);
# endif
  dkim_exim_sign_init();
# ifdef EXPERIMENTAL_ARC
    {
    uschar * s = ob->arc_sign;
    if (s)
      {
      if (!(ob->dkim.arc_signspec = s = expand_string(s)))
	{
	if (!f.expand_string_forcedfail)
	  {
	  message = US"failed to expand arc_sign";
	  sx->ok = FALSE;
	  goto SEND_FAILED;
	  }
	}
      else if (*s)
	{
	/* Ask dkim code to hash the body for ARC */
	(void) arc_ams_setup_sign_bodyhash();
	ob->dkim.force_bodyhash = TRUE;
	}
      }
    }
# endif
# ifdef MEASURE_TIMING
  report_time_since(&t0, US"dkim_exim_sign_init (delta)");
# endif
  }
#endif

  /* See if we can pipeline QUIT.  Reasons not to are
  - pipelining not active
  - not ok to send quit
  - errors in amtp transation responses
  - more addrs to send for this message or this host
  - this message was being retried
  - more messages for this host
  If we can, we want the message-write to not flush (the tail end of) its data out.  */

  if (  sx->pipelining_used
     && (sx->ok && sx->completed_addr || sx->peer_offered & OPTION_CHUNKING)
     && sx->send_quit
     && !(sx->first_addr || f.continue_more)
     && f.deliver_firsttime
     )
    {
    smtp_compare_t t_compare =
      {.tblock = tblock, .current_sender_address = sender_address};

    tcw_done = TRUE;
    tcw =
#ifndef DISABLE_TLS
	   (  tls_out.active.sock < 0  &&  !continue_proxy_cipher
           || verify_check_given_host(CUSS &ob->hosts_nopass_tls, host) != OK
	   )
        &&
#endif
           transport_check_waiting(tblock->name, host->name,
             tblock->connection_max_messages, new_message_id,
	     (oicf)smtp_are_same_identities, (void*)&t_compare);
    if (!tcw)
      {
      HDEBUG(D_transport) debug_printf("will pipeline QUIT\n");
      tctx.options |= topt_no_flush;
      }
    }

#ifndef DISABLE_DKIM
  sx->ok = dkim_transport_write_message(&tctx, &ob->dkim, CUSS &message);
#else
  sx->ok = transport_write_message(&tctx, 0);
#endif

  /* transport_write_message() uses write() because it is called from other
  places to write to non-sockets. This means that under some OS (e.g. Solaris)
  it can exit with "Broken pipe" as its error. This really means that the
  socket got closed at the far end. */

  transport_write_timeout = 0;   /* for subsequent transports */

  /* Failure can either be some kind of I/O disaster (including timeout),
  or the failure of a transport filter or the expansion of added headers.
  Or, when CHUNKING, it can be a protocol-detected failure. */

  if (!sx->ok)
    if (message) goto SEND_FAILED;
    else         goto RESPONSE_FAILED;

  /* We used to send the terminating "." explicitly here, but because of
  buffering effects at both ends of TCP/IP connections, you don't gain
  anything by keeping it separate, so it might as well go in the final
  data buffer for efficiency. This is now done by setting the topt_end_dot
  flag above. */

  smtp_command = US"end of data";

  /* If we can pipeline a QUIT with the data them send it now.  If a new message
  for this host appeared in the queue while data was being sent, we will not see
  it and it will have to wait for a queue run.  If there was one but another
  thread took it, we might attempt to send it - but locking of spoolfiles will
  detect that. Use _MORE to get QUIT in FIN segment. */

  if (tcw_done && !tcw)
    {
    /*XXX jgh 2021/03/10 google et. al screwup.  G, at least, sends TCP FIN in response to TLS
    close-notify.  Under TLS 1.3, violating RFC.
    However, TLS 1.2 does not have half-close semantics. */

    if (     sx->cctx.tls_ctx
#if 0 && !defined(DISABLE_TLS)
          && Ustrcmp(tls_out.ver, "TLS1.3") != 0
#endif
       || !f.deliver_firsttime
       )
      {				/* Send QUIT now and not later */
      (void)smtp_write_command(sx, SCMD_FLUSH, "QUIT\r\n");
      sx->send_quit = FALSE;
      }
    else
      {				/* add QUIT to the output buffer */
      (void)smtp_write_command(sx, SCMD_MORE, "QUIT\r\n");
      sx->send_quit = FALSE;	/* avoid sending it later */

#ifndef DISABLE_TLS
      if (sx->cctx.tls_ctx)	/* need to send TLS Cloe Notify */
	{
# ifdef EXIM_TCP_CORK		/* Use _CORK to get Close Notify in FIN segment */
	(void) setsockopt(sx->cctx.sock, IPPROTO_TCP, EXIM_TCP_CORK, US &on, sizeof(on));
# endif
	tls_shutdown_wr(sx->cctx.tls_ctx);
	sx->send_tlsclose = FALSE;	/* avoid later repeat */
	}
#endif
      HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  SMTP(shutdown)>>\n");
      shutdown(sx->cctx.sock, SHUT_WR);	/* flush output buffer, with TCP FIN */
      }
    }

  if (sx->peer_offered & OPTION_CHUNKING && sx->cmd_count > 1)
    {
    /* Reap any outstanding MAIL & RCPT commands, but not a DATA-go-ahead */
    switch(sync_responses(sx, sx->cmd_count-1, 0))
      {
      case 3: sx->ok = TRUE;            /* 2xx & 5xx => OK & progress made */
      case 2: sx->completed_addr = TRUE;    /* 5xx (only) => progress made */
	      break;

      case 1: sx->ok = TRUE;		/* 2xx (only) => OK, but if LMTP, */
      if (!sx->lmtp) sx->completed_addr = TRUE; /* can't tell about progress yet */
      case 0: break;			/* No 2xx or 5xx, but no probs */

      case -1: goto END_OFF;		/* Timeout on RCPT */

#ifndef DISABLE_PIPE_CONNECT
      case -5:				/* TLS first-read error */
      case -4:  HDEBUG(D_transport)
		  debug_printf("failed reaping pipelined cmd responses\n");
#endif
      default: goto RESPONSE_FAILED;	/* I/O error, or any MAIL/DATA error */
      }
    }

#ifndef DISABLE_PRDR
  /* For PRDR we optionally get a partial-responses warning followed by the
  individual responses, before going on with the overall response.  If we don't
  get the warning then deal with per non-PRDR. */

  if(sx->prdr_active)
    {
    sx->ok = smtp_read_response(sx, sx->buffer, sizeof(sx->buffer), '3', ob->final_timeout);
    if (!sx->ok && errno == 0) switch(sx->buffer[0])
      {
      case '2': sx->prdr_active = FALSE;
		sx->ok = TRUE;
		break;
      case '4': errno = ERRNO_DATA4XX;
		addrlist->more_errno |=
		  ((sx->buffer[1] - '0')*10 + sx->buffer[2] - '0') << 8;
		break;
      }
    }
  else
#endif

  /* For non-PRDR SMTP, we now read a single response that applies to the
  whole message.  If it is OK, then all the addresses have been delivered. */

  if (!sx->lmtp)
    {
    sx->ok = smtp_read_response(sx, sx->buffer, sizeof(sx->buffer), '2',
      ob->final_timeout);
    if (!sx->ok && errno == 0 && sx->buffer[0] == '4')
      {
      errno = ERRNO_DATA4XX;
      addrlist->more_errno |= ((sx->buffer[1] - '0')*10 + sx->buffer[2] - '0') << 8;
      }
    }

  /* For LMTP, we get back a response for every RCPT command that we sent;
  some may be accepted and some rejected. For those that get a response, their
  status is fixed; any that are accepted have been handed over, even if later
  responses crash - at least, that's how I read RFC 2033.

  If all went well, mark the recipient addresses as completed, record which
  host/IPaddress they were delivered to, and cut out RSET when sending another
  message down the same channel. Write the completed addresses to the journal
  now so that they are recorded in case there is a crash of hardware or
  software before the spool gets updated. Also record the final SMTP
  confirmation if needed (for SMTP only). */

  if (sx->ok)
    {
    int flag = '=';
    struct timeval delivery_time;
    int len;
    uschar * conf = NULL;

    timesince(&delivery_time, &sx->delivery_start);
    sx->send_rset = FALSE;
    pipelining_active = FALSE;

    /* Set up confirmation if needed - applies only to SMTP */

    if (
#ifdef DISABLE_EVENT
          LOGGING(smtp_confirmation) &&
#endif
          !sx->lmtp
       )
      {
      const uschar * s = string_printing(sx->buffer);
      /* deconst cast ok here as string_printing was checked to have alloc'n'copied */
      conf = s == sx->buffer ? US string_copy(s) : US s;
      }

    /* Process all transported addresses - for LMTP or PRDR, read a status for
    each one. We used to drop out at first_addr, until someone returned a 452
    followed by a 250... and we screwed up the accepted addresses. */

    for (address_item * addr = addrlist; addr; addr = addr->next)
      {
      if (addr->transport_return != PENDING_OK) continue;

      /* LMTP - if the response fails badly (e.g. timeout), use it for all the
      remaining addresses. Otherwise, it's a return code for just the one
      address. For temporary errors, add a retry item for the address so that
      it doesn't get tried again too soon. */

#ifndef DISABLE_PRDR
      if (sx->lmtp || sx->prdr_active)
#else
      if (sx->lmtp)
#endif
        {
        if (!smtp_read_response(sx, sx->buffer, sizeof(sx->buffer), '2',
            ob->final_timeout))
          {
          if (errno != 0 || sx->buffer[0] == 0) goto RESPONSE_FAILED;
          addr->message = string_sprintf(
#ifndef DISABLE_PRDR
	    "%s error after %s: %s", sx->prdr_active ? "PRDR":"LMTP",
#else
	    "LMTP error after %s: %s",
#endif
	    data_command, string_printing(sx->buffer));
          setflag(addr, af_pass_message);   /* Allow message to go to user */
          if (sx->buffer[0] == '5')
            addr->transport_return = FAIL;
          else
            {
            errno = ERRNO_DATA4XX;
            addr->more_errno |= ((sx->buffer[1] - '0')*10 + sx->buffer[2] - '0') << 8;
            addr->transport_return = DEFER;
#ifndef DISABLE_PRDR
            if (!sx->prdr_active)
#endif
              retry_add_item(addr, addr->address_retry_key, 0);
            }
          continue;
          }
        sx->completed_addr = TRUE;   /* NOW we can set this flag */
        if (LOGGING(smtp_confirmation))
          {
          const uschar *s = string_printing(sx->buffer);
	  /* deconst cast ok here as string_printing was checked to have alloc'n'copied */
          conf = (s == sx->buffer) ? US string_copy(s) : US s;
          }
        }

      /* SMTP, or success return from LMTP for this address. Pass back the
      actual host that was used. */

      addr->transport_return = OK;
      addr->host_used = host;
      addr->delivery_time = delivery_time;
      addr->special_action = flag;
      addr->message = conf;

      if (tcp_out_fastopen)
	{
	setflag(addr, af_tcp_fastopen_conn);
	if (tcp_out_fastopen >= TFO_USED_NODATA) setflag(addr, af_tcp_fastopen);
	if (tcp_out_fastopen >= TFO_USED_DATA) setflag(addr, af_tcp_fastopen_data);
	}
      if (sx->pipelining_used) setflag(addr, af_pipelining);
#ifndef DISABLE_PIPE_CONNECT
      if (sx->early_pipe_active) setflag(addr, af_early_pipe);
#endif
#ifndef DISABLE_PRDR
      if (sx->prdr_active) setflag(addr, af_prdr_used);
#endif
      if (sx->peer_offered & OPTION_CHUNKING) setflag(addr, af_chunking_used);
      flag = '-';

#ifndef DISABLE_PRDR
      if (!sx->prdr_active)
#endif
        {
        /* Update the journal. For homonymic addresses, use the base address plus
        the transport name. See lots of comments in deliver.c about the reasons
        for the complications when homonyms are involved. Just carry on after
        write error, as it may prove possible to update the spool file later. */

        if (testflag(addr, af_homonym))
          sprintf(CS sx->buffer, "%.500s/%s\n", addr->unique + 3, tblock->name);
        else
          sprintf(CS sx->buffer, "%.500s\n", addr->unique);

        DEBUG(D_deliver) debug_printf("S:journalling %s", sx->buffer);
        len = Ustrlen(CS sx->buffer);
        if (write(journal_fd, sx->buffer, len) != len)
          log_write(0, LOG_MAIN|LOG_PANIC, "failed to write journal for "
            "%s: %s", sx->buffer, strerror(errno));
        }
      }

#ifndef DISABLE_PRDR
    if (sx->prdr_active)
      {
      const uschar * overall_message;

      /* PRDR - get the final, overall response.  For any non-success
      upgrade all the address statuses. */

      sx->ok = smtp_read_response(sx, sx->buffer, sizeof(sx->buffer), '2',
	ob->final_timeout);
      if (!sx->ok)
	{
	if(errno == 0 && sx->buffer[0] == '4')
	  {
	  errno = ERRNO_DATA4XX;
	  addrlist->more_errno |= ((sx->buffer[1] - '0')*10 + sx->buffer[2] - '0') << 8;
	  }
	for (address_item * addr = addrlist; addr != sx->first_addr; addr = addr->next)
	  if (sx->buffer[0] == '5' || addr->transport_return == OK)
	    addr->transport_return = PENDING_OK; /* allow set_errno action */
	goto RESPONSE_FAILED;
	}

      /* Append the overall response to the individual PRDR response for logging
      and update the journal, or setup retry. */

      overall_message = string_printing(sx->buffer);
      for (address_item * addr = addrlist; addr != sx->first_addr; addr = addr->next)
	if (addr->transport_return == OK)
	  addr->message = string_sprintf("%s\\n%s", addr->message, overall_message);

      for (address_item * addr = addrlist; addr != sx->first_addr; addr = addr->next)
	if (addr->transport_return == OK)
	  {
	  if (testflag(addr, af_homonym))
	    sprintf(CS sx->buffer, "%.500s/%s\n", addr->unique + 3, tblock->name);
	  else
	    sprintf(CS sx->buffer, "%.500s\n", addr->unique);

	  DEBUG(D_deliver) debug_printf("journalling(PRDR) %s\n", sx->buffer);
	  len = Ustrlen(CS sx->buffer);
	  if (write(journal_fd, sx->buffer, len) != len)
	    log_write(0, LOG_MAIN|LOG_PANIC, "failed to write journal for "
	      "%s: %s", sx->buffer, strerror(errno));
	  }
	else if (addr->transport_return == DEFER)
	  retry_add_item(addr, addr->address_retry_key, -2);
      }
#endif

    /* Ensure the journal file is pushed out to disk. */

    if (EXIMfsync(journal_fd) < 0)
      log_write(0, LOG_MAIN|LOG_PANIC, "failed to fsync journal: %s",
        strerror(errno));
    }
  }


/* Handle general (not specific to one address) failures here. The value of ok
is used to skip over this code on the falling through case. A timeout causes a
deferral. Other errors may defer or fail according to the response code, and
may set up a special errno value, e.g. after connection chopped, which is
assumed if errno == 0 and there is no text in the buffer. If control reaches
here during the setting up phase (i.e. before MAIL FROM) then always defer, as
the problem is not related to this specific message. */

if (!sx->ok)
  {
  int code, set_rc;
  uschar * set_message;

  RESPONSE_FAILED:
    {
    save_errno = errno;
    message = NULL;
    /* Clear send_quit flag if needed.  Do not set. */
    sx->send_quit &= check_response(host, &save_errno, addrlist->more_errno,
      sx->buffer, &code, &message, &pass_message);
    goto FAILED;
    }

  SEND_FAILED:
    {
    save_errno = errno;
    code = '4';
    message = string_sprintf("send() to %s [%s] failed: %s",
      host->name, host->address, message ? message : US strerror(save_errno));
    sx->send_quit = FALSE;
    goto FAILED;
    }

  FAILED:
    {
    BOOL message_error;

    sx->ok = FALSE;                /* For when reached by GOTO */
    set_message = message;

  /* We want to handle timeouts after MAIL or "." and loss of connection after
  "." specially. They can indicate a problem with the sender address or with
  the contents of the message rather than a real error on the connection. These
  cases are treated in the same way as a 4xx response. This next bit of code
  does the classification. */

    switch(save_errno)
      {
      case 0:
      case ERRNO_MAIL4XX:
      case ERRNO_DATA4XX:
	message_error = TRUE;
	break;

      case ETIMEDOUT:
	message_error = Ustrncmp(smtp_command,"MAIL",4) == 0 ||
			Ustrncmp(smtp_command,"end ",4) == 0;
	break;

      case ERRNO_SMTPCLOSED:
	message_error = Ustrncmp(smtp_command,"end ",4) == 0;
	break;

      default:
	message_error = FALSE;
	break;
      }

    /* Handle the cases that are treated as message errors. These are:

      (a) negative response or timeout after MAIL
      (b) negative response after DATA
      (c) negative response or timeout or dropped connection after "."
      (d) utf8 support required and not offered

    It won't be a negative response or timeout after RCPT, as that is dealt
    with separately above. The action in all cases is to set an appropriate
    error code for all the addresses, but to leave yield set to OK because the
    host itself has not failed. Of course, it might in practice have failed
    when we've had a timeout, but if so, we'll discover that at the next
    delivery attempt. For a temporary error, set the message_defer flag, and
    write to the logs for information if this is not the last host. The error
    for the last host will be logged as part of the address's log line. */

    if (message_error)
      {
      if (mua_wrapper) code = '5';  /* Force hard failure in wrapper mode */

      /* If there's an errno, the message contains just the identity of
      the host. */

      if (code == '5')
	set_rc = FAIL;
      else		/* Anything other than 5 is treated as temporary */
        {
	set_rc = DEFER;
        if (save_errno > 0)
          message = US string_sprintf("%s: %s", message, strerror(save_errno));

        write_logs(host, message, sx->first_addr ? sx->first_addr->basic_errno : 0);

        *message_defer = TRUE;
        }
#ifdef TIOCOUTQ
      DEBUG(D_transport) if (sx->cctx.sock >= 0)
	{
	int n;
	if (ioctl(sx->cctx.sock, TIOCOUTQ, &n) == 0)
	  debug_printf("%d bytes remain in socket output buffer\n", n);
	}
#endif
      }
    /* Otherwise, we have an I/O error or a timeout other than after MAIL or
    ".", or some other transportation error. We defer all addresses and yield
    DEFER, except for the case of failed add_headers expansion, or a transport
    filter failure, when the yield should be ERROR, to stop it trying other
    hosts. */

    else
      {
#ifndef DISABLE_PIPE_CONNECT
      /* If we were early-pipelinng and the actual EHLO response did not match
      the cached value we assumed, we could have detected it and passed a
      custom errno through to here.  It would be nice to RSET and retry right
      away, but to reliably do that we eould need an extra synch point before
      we committed to data and that would discard half the gained roundrips.
      Or we could summarily drop the TCP connection. but that is also ugly.
      Instead, we ignore the possibility (having freshened the cache) and rely
      on the server telling us with a nonmessage error if we have tried to
      do something it no longer supports. */
#endif
      set_rc = DEFER;
      yield = (save_errno == ERRNO_CHHEADER_FAIL ||
               save_errno == ERRNO_FILTER_FAIL) ? ERROR : DEFER;
      }
    }

  set_errno(addrlist, save_errno, set_message, set_rc, pass_message, host,
#ifdef EXPERIMENTAL_DSN_INFO
	    sx->smtp_greeting, sx->helo_response,
#endif
	    &sx->delivery_start);
  }

/* If all has gone well, send_quit will be set TRUE, implying we can end the
SMTP session tidily. However, if there were too many addresses to send in one
message (indicated by first_addr being non-NULL) we want to carry on with the
rest of them. Also, it is desirable to send more than one message down the SMTP
connection if there are several waiting, provided we haven't already sent so
many as to hit the configured limit. The function transport_check_waiting looks
for a waiting message and returns its id. Then transport_pass_socket tries to
set up a continued delivery by passing the socket on to another process. The
variable send_rset is FALSE if a message has just been successfully transferred.

If we are already sending down a continued channel, there may be further
addresses not yet delivered that are aimed at the same host, but which have not
been passed in this run of the transport. In this case, continue_more will be
true, and all we should do is send RSET if necessary, and return, leaving the
channel open.

However, if no address was disposed of, i.e. all addresses got 4xx errors, we
do not want to continue with other messages down the same channel, because that
can lead to looping between two or more messages, all with the same,
temporarily failing address(es). [The retry information isn't updated yet, so
new processes keep on trying.] We probably also don't want to try more of this
message's addresses either.

If we have started a TLS session, we have to end it before passing the
connection to a new process. However, not all servers can handle this (Exim
can), so we do not pass such a connection on if the host matches
hosts_nopass_tls. */

DEBUG(D_transport)
  debug_printf("ok=%d send_quit=%d send_rset=%d continue_more=%d "
    "yield=%d first_address is %sNULL\n", sx->ok, sx->send_quit,
    sx->send_rset, f.continue_more, yield, sx->first_addr ? "not " : "");

if (sx->completed_addr && sx->ok && sx->send_quit)
#ifdef EXPERIMENTAL_ESMTP_LIMITS
  if (mail_limit = continue_sequence >= sx->max_mail)
    {
    DEBUG(D_transport)
      debug_printf("reached limit %u for MAILs per conn\n", sx->max_mail);
    }
  else
#endif
    {
    smtp_compare_t t_compare =
      {.tblock = tblock, .current_sender_address = sender_address};

    if (  sx->first_addr			/* more addrs for this message */
       || f.continue_more			/* more addrs for continued-host */
       || tcw_done && tcw			/* more messages for host */
       || (
#ifndef DISABLE_TLS
	     (  tls_out.active.sock < 0  &&  !continue_proxy_cipher
	     || verify_check_given_host(CUSS &ob->hosts_nopass_tls, host) != OK
	     )
	  &&
#endif
	     transport_check_waiting(tblock->name, host->name,
	       sx->max_mail, new_message_id,
	       (oicf)smtp_are_same_identities, (void*)&t_compare)
       )  )
      {
      uschar *msg;
      BOOL pass_message;

      if (sx->send_rset)
	if (! (sx->ok = smtp_write_command(sx, SCMD_FLUSH, "RSET\r\n") >= 0))
	  {
	  msg = US string_sprintf("send() to %s [%s] failed: %s", host->name,
	    host->address, strerror(errno));
	  sx->send_quit = FALSE;
	  }
	else if (! (sx->ok = smtp_read_response(sx, sx->buffer, sizeof(sx->buffer),
		    '2', ob->command_timeout)))
	  {
	  int code;
	  sx->send_quit = check_response(host, &errno, 0, sx->buffer, &code, &msg,
	    &pass_message);
	  if (!sx->send_quit)
	    {
	    DEBUG(D_transport) debug_printf("H=%s [%s] %s\n",
	      host->name, host->address, msg);
	    }
	  }

      /* Either RSET was not needed, or it succeeded */

      if (sx->ok)
	{
#ifndef DISABLE_TLS
	int pfd[2];
#endif
	int socket_fd = sx->cctx.sock;

	if (sx->first_addr)		/* More addresses still to be sent */
	  {				/*   for this message              */
#ifdef EXPERIMENTAL_ESMTP_LIMITS
	  /* Any that we marked as skipped, reset to do now */
	  for (address_item * a = sx->first_addr; a; a = a->next)
	    if (a->transport_return == SKIP)
	      a->transport_return = PENDING_DEFER;
#endif
	  continue_sequence++;				/* for consistency */
	  clearflag(sx->first_addr, af_new_conn);
	  setflag(sx->first_addr, af_cont_conn);	/* Causes * in logging */
	  pipelining_active = sx->pipelining_used;	/* was cleared at DATA */
	  goto SEND_MESSAGE;
	  }

	/* Unless caller said it already has more messages listed for this host,
	pass the connection on to a new Exim process (below, the call to
	transport_pass_socket).  If the caller has more ready, just return with
	the connection still open. */

#ifndef DISABLE_TLS
	if (tls_out.active.sock >= 0)
	  if (  f.continue_more
	     || verify_check_given_host(CUSS &ob->hosts_noproxy_tls, host) == OK)
	    {
	    /* Before passing the socket on, or returning to caller with it still
	    open, we must shut down TLS.  Not all MTAs allow for the continuation
	    of the SMTP session when TLS is shut down. We test for this by sending
	    a new EHLO. If we don't get a good response, we don't attempt to pass
	    the socket on. */

	  tls_close(sx->cctx.tls_ctx, TLS_SHUTDOWN_WAIT);
	  sx->send_tlsclose = FALSE;
	  sx->cctx.tls_ctx = NULL;
	  tls_out.active.sock = -1;
	  smtp_peer_options = smtp_peer_options_wrap;
	  sx->ok = !sx->smtps
	    && smtp_write_command(sx, SCMD_FLUSH, "EHLO %s\r\n", sx->helo_data)
		>= 0
	    && smtp_read_response(sx, sx->buffer, sizeof(sx->buffer),
				      '2', ob->command_timeout);

	    if (sx->ok && f.continue_more)
	      goto TIDYUP;		/* More addresses for another run */
	    }
	  else
	    {
	    /* Set up a pipe for proxying TLS for the new transport process */

	    smtp_peer_options |= OPTION_TLS;
	    if ((sx->ok = socketpair(AF_UNIX, SOCK_STREAM, 0, pfd) == 0))
	      socket_fd = pfd[1];
	    else
	      set_errno(sx->first_addr, errno, US"internal allocation problem",
		      DEFER, FALSE, host,
# ifdef EXPERIMENTAL_DSN_INFO
		      sx->smtp_greeting, sx->helo_response,
# endif
		      &sx->delivery_start);
	    }
	else
#endif
	  if (f.continue_more)
	    goto TIDYUP;			/* More addresses for another run */

	/* If the socket is successfully passed, we mustn't send QUIT (or
	indeed anything!) from here. */

  /*XXX DSN_INFO: assume likely to do new HELO; but for greet we'll want to
  propagate it from the initial
  */
	if (sx->ok && transport_pass_socket(tblock->name, host->name,
	      host->address, new_message_id, socket_fd
#ifdef EXPERIMENTAL_ESMTP_LIMITS
	      , sx->peer_limit_mail, sx->peer_limit_rcpt, sx->peer_limit_rcptdom
#endif
	      ))
	  {
	  sx->send_quit = FALSE;

	  /* We have passed the client socket to a fresh transport process.
	  If TLS is still active, we need to proxy it for the transport we
	  just passed the baton to.  Fork a child to to do it, and return to
	  get logging done asap.  Which way to place the work makes assumptions
	  about post-fork prioritisation which may not hold on all platforms. */
#ifndef DISABLE_TLS
	  if (tls_out.active.sock >= 0)
	    {
	    int pid = exim_fork(US"tls-proxy-interproc");
	    if (pid == 0)		/* child; fork again to disconnect totally */
	      {
	      /* does not return */
	      smtp_proxy_tls(sx->cctx.tls_ctx, sx->buffer, sizeof(sx->buffer), pfd,
			      ob->command_timeout);
	      }

	    if (pid > 0)		/* parent */
	      {
	      close(pfd[0]);
	      /* tidy the inter-proc to disconn the proxy proc */
	      waitpid(pid, NULL, 0);
	      tls_close(sx->cctx.tls_ctx, TLS_NO_SHUTDOWN);
	      sx->cctx.tls_ctx = NULL;
	      (void)close(sx->cctx.sock);
	      sx->cctx.sock = -1;
	      continue_transport = NULL;
	      continue_hostname = NULL;
	      goto TIDYUP;
	      }
	    log_write(0, LOG_PANIC_DIE, "fork failed");
	    }
#endif
	  }
	}

      /* If RSET failed and there are addresses left, they get deferred. */
      else
	set_errno(sx->first_addr, errno, msg, DEFER, FALSE, host,
#ifdef EXPERIMENTAL_DSN_INFO
		    sx->smtp_greeting, sx->helo_response,
#endif
		    &sx->delivery_start);
      }
    }

/* End off tidily with QUIT unless the connection has died or the socket has
been passed to another process. */

SEND_QUIT:
if (sx->send_quit)
  {			/* Use _MORE to get QUIT in FIN segment */
  (void)smtp_write_command(sx, SCMD_MORE, "QUIT\r\n");
#ifndef DISABLE_TLS
  if (sx->cctx.tls_ctx)
    {
# ifdef EXIM_TCP_CORK	/* Use _CORK to get TLS Close Notify in FIN segment */
    (void) setsockopt(sx->cctx.sock, IPPROTO_TCP, EXIM_TCP_CORK, US &on, sizeof(on));
# endif
    tls_shutdown_wr(sx->cctx.tls_ctx);
    sx->send_tlsclose = FALSE;
    }
#endif
  }

END_OFF:

/* Close the socket, and return the appropriate value, first setting
works because the NULL setting is passed back to the calling process, and
remote_max_parallel is forced to 1 when delivering over an existing connection,

If all went well and continue_more is set, we shouldn't actually get here if
there are further addresses, as the return above will be taken. However,
writing RSET might have failed, or there may be other addresses whose hosts are
specified in the transports, and therefore not visible at top level, in which
case continue_more won't get set. */

if (sx->send_quit)
  {
  /* This flushes data queued in the socket, being the QUIT and any TLS Close,
  sending them along with the client FIN flag.  Us (we hope) sending FIN first
  means we (client) take the TIME_WAIT state, so the server (which likely has a
  higher connection rate) does not have to. */

  HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  SMTP(shutdown)>>\n");
  shutdown(sx->cctx.sock, SHUT_WR);
  }

if (sx->send_quit || tcw_done && !tcw)
  {
  /* Wait for (we hope) ack of our QUIT, and a server FIN.  Discard any data
  received, then discard the socket.  Any packet received after then, or receive
  data still in the socket, will get a RST - hence the pause/drain. */

  /* Reap the response to QUIT, timing out after one second */
  (void) smtp_read_response(sx, sx->buffer, sizeof(sx->buffer), '2', 1);
#ifndef DISABLE_TLS
  if (sx->cctx.tls_ctx)
    {
    int n;

    /* Reap the TLS Close Notify from the server, timing out after one second */
    sigalrm_seen = FALSE;
    ALARM(1);
    do
      n = tls_read(sx->cctx.tls_ctx, sx->inbuffer, sizeof(sx->inbuffer));
    while (!sigalrm_seen && n > 0);
    ALARM_CLR(0);

# ifdef EXIM_TCP_CORK
    (void) setsockopt(sx->cctx.sock, IPPROTO_TCP, EXIM_TCP_CORK, US &on, sizeof(on));
# endif
    tls_close(sx->cctx.tls_ctx, TLS_SHUTDOWN_WAIT);
    sx->cctx.tls_ctx = NULL;
    }
#endif
  millisleep(20);
  if (fcntl(sx->cctx.sock, F_SETFL, O_NONBLOCK) == 0)
    for (int i = 16, n;						/* drain socket */
	 (n = read(sx->cctx.sock, sx->inbuffer, sizeof(sx->inbuffer))) > 0 && i > 0;
	 i--) HDEBUG(D_transport|D_acl|D_v)
      {
      int m = MIN(n, 64);
      debug_printf_indent("  SMTP(drain %d bytes)<< %.*s\n", n, m, sx->inbuffer);
      for (m = 0; m < n; m++)
	debug_printf("0x%02x\n", sx->inbuffer[m]);
      }
  }
HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  SMTP(close)>>\n");
(void)close(sx->cctx.sock);
sx->cctx.sock = -1;
continue_transport = NULL;
continue_hostname = NULL;

#ifndef DISABLE_EVENT
(void) event_raise(tblock->event_action, US"tcp:close", NULL);
#endif

#ifdef SUPPORT_DANE
if (dane_held)
  {
  sx->first_addr = NULL;
  for (address_item * a = sx->addrlist->next; a; a = a->next)
    if (a->transport_return == DANE)
      {
      a->transport_return = PENDING_DEFER;
      if (!sx->first_addr)
	{
	/* Remember the new start-point in the addrlist, for smtp_setup_conn()
	to get the domain string for SNI */

	sx->first_addr = a;
	clearflag(a, af_cont_conn);
	setflag(a, af_new_conn);		/* clear * from logging */
	DEBUG(D_transport) debug_printf("DANE: go-around for %s\n", a->domain);
	}
      }
  continue_sequence = 1;			/* for consistency */
  goto REPEAT_CONN;
  }
#endif

#ifdef EXPERIMENTAL_ESMTP_LIMITS
if (mail_limit && sx->first_addr)
  {
  /* Reset the sequence count since we closed the connection.  This is flagged
  on the pipe back to the delivery process so that a non-continued-conn delivery
  is logged. */

  continue_sequence = 1;			/* for consistency */
  clearflag(sx->first_addr, af_cont_conn);
  setflag(sx->first_addr, af_new_conn);		/* clear  * from logging */
  goto REPEAT_CONN;
  }
#endif

return yield;

TIDYUP:
#ifdef SUPPORT_DANE
if (dane_held) for (address_item * a = sx->addrlist->next; a; a = a->next)
  if (a->transport_return == DANE)
    a->transport_return = PENDING_DEFER;
#endif
return yield;
}




/*************************************************
*              Closedown entry point             *
*************************************************/

/* This function is called when exim is passed an open smtp channel
from another incarnation, but the message which it has been asked
to deliver no longer exists. The channel is on stdin.

We might do fancy things like looking for another message to send down
the channel, but if the one we sought has gone, it has probably been
delivered by some other process that itself will seek further messages,
so just close down our connection.

Argument:   pointer to the transport instance block
Returns:    nothing
*/

void
smtp_transport_closedown(transport_instance *tblock)
{
smtp_transport_options_block * ob = SOB tblock->options_block;
client_conn_ctx cctx;
smtp_context sx;
uschar buffer[256];
uschar inbuffer[4096];
uschar outbuffer[16];

/*XXX really we need an active-smtp-client ctx, rather than assuming stdout */
cctx.sock = fileno(stdin);
cctx.tls_ctx = cctx.sock == tls_out.active.sock ? tls_out.active.tls_ctx : NULL;

sx.inblock.cctx = &cctx;
sx.inblock.buffer = inbuffer;
sx.inblock.buffersize = sizeof(inbuffer);
sx.inblock.ptr = inbuffer;
sx.inblock.ptrend = inbuffer;

sx.outblock.cctx = &cctx;
sx.outblock.buffersize = sizeof(outbuffer);
sx.outblock.buffer = outbuffer;
sx.outblock.ptr = outbuffer;
sx.outblock.cmd_count = 0;
sx.outblock.authenticating = FALSE;

(void)smtp_write_command(&sx, SCMD_FLUSH, "QUIT\r\n");
(void)smtp_read_response(&sx, buffer, sizeof(buffer), '2', ob->command_timeout);
(void)close(cctx.sock);
}



/*************************************************
*            Prepare addresses for delivery      *
*************************************************/

/* This function is called to flush out error settings from previous delivery
attempts to other hosts. It also records whether we got here via an MX record
or not in the more_errno field of the address. We are interested only in
addresses that are still marked DEFER - others may have got delivered to a
previously considered IP address. Set their status to PENDING_DEFER to indicate
which ones are relevant this time.

Arguments:
  addrlist     the list of addresses
  host         the host we are delivering to

Returns:       the first address for this delivery
*/

static address_item *
prepare_addresses(address_item *addrlist, host_item *host)
{
address_item *first_addr = NULL;
for (address_item * addr = addrlist; addr; addr = addr->next)
  if (addr->transport_return == DEFER)
    {
    if (!first_addr) first_addr = addr;
    addr->transport_return = PENDING_DEFER;
    addr->basic_errno = 0;
    addr->more_errno = (host->mx >= 0)? 'M' : 'A';
    addr->message = NULL;
#ifndef DISABLE_TLS
    addr->cipher = NULL;
    addr->ourcert = NULL;
    addr->peercert = NULL;
    addr->peerdn = NULL;
    addr->ocsp = OCSP_NOT_REQ;
    addr->tlsver = NULL;
#endif
#ifdef EXPERIMENTAL_DSN_INFO
    addr->smtp_greeting = NULL;
    addr->helo_response = NULL;
#endif
    }
return first_addr;
}



/*************************************************
*              Main entry point                  *
*************************************************/

/* See local README for interface details. As this is a remote transport, it is
given a chain of addresses to be delivered in one connection, if possible. It
always returns TRUE, indicating that each address has its own independent
status set, except if there is a setting up problem, in which case it returns
FALSE. */

BOOL
smtp_transport_entry(
  transport_instance *tblock,      /* data for this instantiation */
  address_item *addrlist)          /* addresses we are working on */
{
int defport;
int hosts_defer = 0;
int hosts_fail  = 0;
int hosts_looked_up = 0;
int hosts_retry = 0;
int hosts_serial = 0;
int hosts_total = 0;
int total_hosts_tried = 0;
BOOL expired = TRUE;
uschar *expanded_hosts = NULL;
uschar *pistring;
uschar *tid = string_sprintf("%s transport", tblock->name);
smtp_transport_options_block *ob = SOB tblock->options_block;
host_item *hostlist = addrlist->host_list;
host_item *host = NULL;

DEBUG(D_transport)
  {
  debug_printf("%s transport entered\n", tblock->name);
  for (address_item * addr = addrlist; addr; addr = addr->next)
    debug_printf("  %s\n", addr->address);
  if (hostlist)
    {
    debug_printf("hostlist:\n");
    for (host_item * host = hostlist; host; host = host->next)
      debug_printf("  '%s' IP %s port %d\n", host->name, host->address, host->port);
    }
  if (continue_hostname)
    debug_printf("already connected to %s [%s] (on fd %d)\n",
      continue_hostname, continue_host_address,
      cutthrough.cctx.sock >= 0 ? cutthrough.cctx.sock : 0);
  }

/* Check the restrictions on line length */

if (max_received_linelength > ob->message_linelength_limit)
  {
  struct timeval now;
  gettimeofday(&now, NULL);

  for (address_item * addr = addrlist; addr; addr = addr->next)
    if (addr->transport_return == DEFER)
      addr->transport_return = PENDING_DEFER;

  set_errno_nohost(addrlist, ERRNO_SMTPFORMAT,
    US"message has lines too long for transport", FAIL, TRUE, &now);
  goto END_TRANSPORT;
  }

/* Set the flag requesting that these hosts be added to the waiting
database if the delivery fails temporarily or if we are running with
queue_smtp or a 2-stage queue run. This gets unset for certain
kinds of error, typically those that are specific to the message. */

update_waiting =  TRUE;

/* If a host list is not defined for the addresses - they must all have the
same one in order to be passed to a single transport - or if the transport has
a host list with hosts_override set, use the host list supplied with the
transport. It is an error for this not to exist. */

if (!hostlist || (ob->hosts_override && ob->hosts))
  {
  if (!ob->hosts)
    {
    addrlist->message = string_sprintf("%s transport called with no hosts set",
      tblock->name);
    addrlist->transport_return = PANIC;
    return FALSE;   /* Only top address has status */
    }

  DEBUG(D_transport) debug_printf("using the transport's hosts: %s\n",
    ob->hosts);

  /* If the transport's host list contains no '$' characters, and we are not
  randomizing, it is fixed and therefore a chain of hosts can be built once
  and for all, and remembered for subsequent use by other calls to this
  transport. If, on the other hand, the host list does contain '$', or we are
  randomizing its order, we have to rebuild it each time. In the fixed case,
  as the hosts string will never be used again, it doesn't matter that we
  replace all the : characters with zeros. */

  if (!ob->hostlist)
    {
    uschar *s = ob->hosts;

    if (Ustrchr(s, '$'))
      {
      if (!(expanded_hosts = expand_string(s)))
        {
        addrlist->message = string_sprintf("failed to expand list of hosts "
          "\"%s\" in %s transport: %s", s, tblock->name, expand_string_message);
        addrlist->transport_return = f.search_find_defer ? DEFER : PANIC;
        return FALSE;     /* Only top address has status */
        }
      DEBUG(D_transport) debug_printf("expanded list of hosts \"%s\" to "
        "\"%s\"\n", s, expanded_hosts);
      s = expanded_hosts;
      }
    else
      if (ob->hosts_randomize) s = expanded_hosts = string_copy(s);

    if (is_tainted(s))
      {
      log_write(0, LOG_MAIN|LOG_PANIC,
	"attempt to use tainted host list '%s' from '%s' in transport %s",
	s, ob->hosts, tblock->name);
      /* Avoid leaking info to an attacker */
      addrlist->message = US"internal configuration error";
      addrlist->transport_return = PANIC;
      return FALSE;
      }

    host_build_hostlist(&hostlist, s, ob->hosts_randomize);

    /* Check that the expansion yielded something useful. */
    if (!hostlist)
      {
      addrlist->message =
        string_sprintf("%s transport has empty hosts setting", tblock->name);
      addrlist->transport_return = PANIC;
      return FALSE;   /* Only top address has status */
      }

    /* If there was no expansion of hosts, save the host list for
    next time. */

    if (!expanded_hosts) ob->hostlist = hostlist;
    }

  /* This is not the first time this transport has been run in this delivery;
  the host list was built previously. */

  else
    hostlist = ob->hostlist;
  }

/* The host list was supplied with the address. If hosts_randomize is set, we
must sort it into a random order if it did not come from MX records and has not
already been randomized (but don't bother if continuing down an existing
connection). */

else if (ob->hosts_randomize && hostlist->mx == MX_NONE && !continue_hostname)
  {
  host_item *newlist = NULL;
  while (hostlist)
    {
    host_item *h = hostlist;
    hostlist = hostlist->next;

    h->sort_key = random_number(100);

    if (!newlist)
      {
      h->next = NULL;
      newlist = h;
      }
    else if (h->sort_key < newlist->sort_key)
      {
      h->next = newlist;
      newlist = h;
      }
    else
      {
      host_item *hh = newlist;
      while (hh->next)
        {
        if (h->sort_key < hh->next->sort_key) break;
        hh = hh->next;
        }
      h->next = hh->next;
      hh->next = h;
      }
    }

  hostlist = addrlist->host_list = newlist;
  }

/* Sort out the default port.  */

if (!smtp_get_port(ob->port, addrlist, &defport, tid)) return FALSE;

/* For each host-plus-IP-address on the list:

.  If this is a continued delivery and the host isn't the one with the
   current connection, skip.

.  If the status is unusable (i.e. previously failed or retry checked), skip.

.  If no IP address set, get the address, either by turning the name into
   an address, calling gethostbyname if gethostbyname is on, or by calling
   the DNS. The DNS may yield multiple addresses, in which case insert the
   extra ones into the list.

.  Get the retry data if not previously obtained for this address and set the
   field which remembers the state of this address. Skip if the retry time is
   not reached. If not, remember whether retry data was found. The retry string
   contains both the name and the IP address.

.  Scan the list of addresses and mark those whose status is DEFER as
   PENDING_DEFER. These are the only ones that will be processed in this cycle
   of the hosts loop.

.  Make a delivery attempt - addresses marked PENDING_DEFER will be tried.
   Some addresses may be successfully delivered, others may fail, and yet
   others may get temporary errors and so get marked DEFER.

.  The return from the delivery attempt is OK if a connection was made and a
   valid SMTP dialogue was completed. Otherwise it is DEFER.

.  If OK, add a "remove" retry item for this host/IPaddress, if any.

.  If fail to connect, or other defer state, add a retry item.

.  If there are any addresses whose status is still DEFER, carry on to the
   next host/IPaddress, unless we have tried the number of hosts given
   by hosts_max_try or hosts_max_try_hardlimit; otherwise return. Note that
   there is some fancy logic for hosts_max_try that means its limit can be
   overstepped in some circumstances.

If we get to the end of the list, all hosts have deferred at least one address,
or not reached their retry times. If delay_after_cutoff is unset, it requests a
delivery attempt to those hosts whose last try was before the arrival time of
the current message. To cope with this, we have to go round the loop a second
time. After that, set the status and error data for any addresses that haven't
had it set already. */

for (int cutoff_retry = 0;
     expired && cutoff_retry < (ob->delay_after_cutoff ? 1 : 2);
     cutoff_retry++)
  {
  host_item *nexthost = NULL;
  int unexpired_hosts_tried = 0;
  BOOL continue_host_tried = FALSE;

retry_non_continued:
  for (host = hostlist;
          host
       && unexpired_hosts_tried < ob->hosts_max_try
       && total_hosts_tried < ob->hosts_max_try_hardlimit;
       host = nexthost)
    {
    int rc;
    int host_af;
    BOOL host_is_expired = FALSE;
    BOOL message_defer = FALSE;
    BOOL some_deferred = FALSE;
    address_item *first_addr = NULL;
    uschar *interface = NULL;
    uschar *retry_host_key = NULL;
    uschar *retry_message_key = NULL;
    uschar *serialize_key = NULL;

    /* Default next host is next host. :-) But this can vary if the
    hosts_max_try limit is hit (see below). It may also be reset if a host
    address is looked up here (in case the host was multihomed). */

    nexthost = host->next;

    /* If the address hasn't yet been obtained from the host name, look it up
    now, unless the host is already marked as unusable. If it is marked as
    unusable, it means that the router was unable to find its IP address (in
    the DNS or wherever) OR we are in the 2nd time round the cutoff loop, and
    the lookup failed last time. We don't get this far if *all* MX records
    point to non-existent hosts; that is treated as a hard error.

    We can just skip this host entirely. When the hosts came from the router,
    the address will timeout based on the other host(s); when the address is
    looked up below, there is an explicit retry record added.

    Note that we mustn't skip unusable hosts if the address is not unset; they
    may be needed as expired hosts on the 2nd time round the cutoff loop. */

    if (!host->address)
      {
      int new_port, flags;

      if (host->status >= hstatus_unusable)
        {
        DEBUG(D_transport) debug_printf("%s has no address and is unusable - skipping\n",
          host->name);
        continue;
        }

      DEBUG(D_transport) debug_printf("getting address for %s\n", host->name);

      /* The host name is permitted to have an attached port. Find it, and
      strip it from the name. Just remember it for now. */

      new_port = host_item_get_port(host);

      /* Count hosts looked up */

      hosts_looked_up++;

      /* Find by name if so configured, or if it's an IP address. We don't
      just copy the IP address, because we need the test-for-local to happen. */

      flags = HOST_FIND_BY_A | HOST_FIND_BY_AAAA;
      if (ob->dns_qualify_single) flags |= HOST_FIND_QUALIFY_SINGLE;
      if (ob->dns_search_parents) flags |= HOST_FIND_SEARCH_PARENTS;

      if (ob->gethostbyname || string_is_ip_address(host->name, NULL) != 0)
        rc = host_find_byname(host, NULL, flags, NULL, TRUE);
      else
        rc = host_find_bydns(host, NULL, flags, NULL, NULL, NULL,
	  &ob->dnssec,		/* domains for request/require */
          NULL, NULL);

      /* Update the host (and any additional blocks, resulting from
      multihoming) with a host-specific port, if any. */

      for (host_item * hh = host; hh != nexthost; hh = hh->next) hh->port = new_port;

      /* Failure to find the host at this time (usually DNS temporary failure)
      is really a kind of routing failure rather than a transport failure.
      Therefore we add a retry item of the routing kind, not to stop us trying
      to look this name up here again, but to ensure the address gets timed
      out if the failures go on long enough. A complete failure at this point
      commonly points to a configuration error, but the best action is still
      to carry on for the next host. */

      if (rc == HOST_FIND_AGAIN || rc == HOST_FIND_SECURITY || rc == HOST_FIND_FAILED)
        {
        retry_add_item(addrlist, string_sprintf("R:%s", host->name), 0);
        expired = FALSE;
        if (rc == HOST_FIND_AGAIN) hosts_defer++; else hosts_fail++;
        DEBUG(D_transport) debug_printf("rc = %s for %s\n", (rc == HOST_FIND_AGAIN)?
          "HOST_FIND_AGAIN" : "HOST_FIND_FAILED", host->name);
        host->status = hstatus_unusable;

        for (address_item * addr = addrlist; addr; addr = addr->next)
          {
          if (addr->transport_return != DEFER) continue;
          addr->basic_errno = ERRNO_UNKNOWNHOST;
          addr->message = string_sprintf(
	    rc == HOST_FIND_SECURITY
	      ? "lookup of IP address for %s was insecure"
	      : "failed to lookup IP address for %s",
	    host->name);
          }
        continue;
        }

      /* If the host is actually the local host, we may have a problem, or
      there may be some cunning configuration going on. In the problem case,
      log things and give up. The default transport status is already DEFER. */

      if (rc == HOST_FOUND_LOCAL && !ob->allow_localhost)
        {
        for (address_item * addr = addrlist; addr; addr = addr->next)
          {
          addr->basic_errno = ERRNO_HOST_IS_LOCAL;
          addr->message = string_sprintf("%s transport found host %s to be "
            "local", tblock->name, host->name);
          }
        goto END_TRANSPORT;
        }
      }   /* End of block for IP address lookup */

    /* If this is a continued delivery, we are interested only in the host
    which matches the name of the existing open channel. The check is put
    here after the local host lookup, in case the name gets expanded as a
    result of the lookup. Set expired FALSE, to save the outer loop executing
    twice. */

    if (continue_hostname)
      if (  Ustrcmp(continue_hostname, host->name) != 0
         || Ustrcmp(continue_host_address, host->address) != 0
	 )
	{
	expired = FALSE;
	continue;      /* With next host */
	}
      else
	continue_host_tried = TRUE;

    /* Reset the default next host in case a multihomed host whose addresses
    are not looked up till just above added to the host list. */

    nexthost = host->next;

    /* If queue_smtp is set (-odqs or the first part of a 2-stage run), or the
    domain is in queue_smtp_domains, we don't actually want to attempt any
    deliveries. When doing a queue run, queue_smtp_domains is always unset. If
    there is a lookup defer in queue_smtp_domains, proceed as if the domain
    were not in it. We don't want to hold up all SMTP deliveries! Except when
    doing a two-stage queue run, don't do this if forcing. */

    if (  (!f.deliver_force || f.queue_2stage)
       && (  f.queue_smtp
	  || match_isinlist(addrlist->domain,
	      CUSS &queue_smtp_domains, 0,
	      &domainlist_anchor, NULL, MCL_DOMAIN, TRUE, NULL) == OK)
       )
      {
      DEBUG(D_transport) debug_printf("first-pass routing only\n");
      expired = FALSE;
      for (address_item * addr = addrlist; addr; addr = addr->next)
        if (addr->transport_return == DEFER)
	  addr->message = US"first-pass only routing due to -odqs, "
			    "queue_smtp_domains or control=queue";
      continue;      /* With next host */
      }

    /* Count hosts being considered - purely for an intelligent comment
    if none are usable. */

    hosts_total++;

    /* Set $host and $host address now in case they are needed for the
    interface expansion or the serialize_hosts check; they remain set if an
    actual delivery happens. */

    deliver_host = host->name;
    deliver_host_address = host->address;
    lookup_dnssec_authenticated = host->dnssec == DS_YES ? US"yes"
				: host->dnssec == DS_NO ? US"no"
				: US"";

    /* Set up a string for adding to the retry key if the port number is not
    the standard SMTP port. A host may have its own port setting that overrides
    the default. */

    pistring = string_sprintf(":%d", host->port == PORT_NONE
      ? defport : host->port);
    if (Ustrcmp(pistring, ":25") == 0) pistring = US"";

    /* Select IPv4 or IPv6, and choose an outgoing interface. If the interface
    string is set, even if constant (as different transports can have different
    constant settings), we must add it to the key that is used for retries,
    because connections to the same host from a different interface should be
    treated separately. */

    host_af = Ustrchr(host->address, ':') ? AF_INET6 : AF_INET;
      {
      uschar * s = ob->interface;
      if (s && *s)
	{
	if (!smtp_get_interface(s, host_af, addrlist, &interface, tid))
	  return FALSE;
	pistring = string_sprintf("%s/%s", pistring, interface);
	}
      }

    /* The first time round the outer loop, check the status of the host by
    inspecting the retry data. The second time round, we are interested only
    in expired hosts that haven't been tried since this message arrived. */

    if (cutoff_retry == 0)
      {
      BOOL incl_ip;
      /* Ensure the status of the address is set by checking retry data if
      necessary. There may be host-specific retry data (applicable to all
      messages) and also data for retries of a specific message at this host.
      If either of these retry records are actually read, the keys used are
      returned to save recomputing them later. */

      if (exp_bool(addrlist, US"transport", tblock->name, D_transport,
		US"retry_include_ip_address", ob->retry_include_ip_address,
		ob->expand_retry_include_ip_address, &incl_ip) != OK)
	continue;	/* with next host */

      host_is_expired = retry_check_address(addrlist->domain, host, pistring,
        incl_ip, &retry_host_key, &retry_message_key);

      DEBUG(D_transport) debug_printf("%s [%s]%s retry-status = %s\n", host->name,
        host->address ? host->address : US"", pistring,
        host->status == hstatus_usable ? "usable"
        : host->status == hstatus_unusable ? "unusable"
        : host->status == hstatus_unusable_expired ? "unusable (expired)" : "?");

      /* Skip this address if not usable at this time, noting if it wasn't
      actually expired, both locally and in the address. */

      switch (host->status)
        {
        case hstatus_unusable:
	  expired = FALSE;
	  setflag(addrlist, af_retry_skipped);
	  /* Fall through */

        case hstatus_unusable_expired:
	  switch (host->why)
	    {
	    case hwhy_retry: hosts_retry++; break;
	    case hwhy_failed:  hosts_fail++; break;
	    case hwhy_insecure:
	    case hwhy_deferred: hosts_defer++; break;
	    }

	  /* If there was a retry message key, implying that previously there
	  was a message-specific defer, we don't want to update the list of
	  messages waiting for these hosts. */

	  if (retry_message_key) update_waiting = FALSE;
	  continue;   /* With the next host or IP address */
        }
      }

    /* Second time round the loop: if the address is set but expired, and
    the message is newer than the last try, let it through. */

    else
      {
      if (  !host->address
         || host->status != hstatus_unusable_expired
	 || host->last_try > received_time.tv_sec)
        continue;
      DEBUG(D_transport) debug_printf("trying expired host %s [%s]%s\n",
          host->name, host->address, pistring);
      host_is_expired = TRUE;
      }

    /* Setting "expired=FALSE" doesn't actually mean not all hosts are expired;
    it remains TRUE only if all hosts are expired and none are actually tried.
    */

    expired = FALSE;

    /* If this host is listed as one to which access must be serialized,
    see if another Exim process has a connection to it, and if so, skip
    this host. If not, update the database to record our connection to it
    and remember this for later deletion. Do not do any of this if we are
    sending the message down a pre-existing connection. */

    if (  !continue_hostname
       && verify_check_given_host(CUSS &ob->serialize_hosts, host) == OK)
      {
      serialize_key = string_sprintf("host-serialize-%s", host->name);
      if (!enq_start(serialize_key, 1))
        {
        DEBUG(D_transport)
          debug_printf("skipping host %s because another Exim process "
            "is connected to it\n", host->name);
        hosts_serial++;
        continue;
        }
      }

    /* OK, we have an IP address that is not waiting for its retry time to
    arrive (it might be expired) OR (second time round the loop) we have an
    expired host that hasn't been tried since the message arrived. Have a go
    at delivering the message to it. First prepare the addresses by flushing
    out the result of previous attempts, and finding the first address that
    is still to be delivered. */

    first_addr = prepare_addresses(addrlist, host);

    DEBUG(D_transport) debug_printf("delivering %s to %s [%s] (%s%s)\n",
      message_id, host->name, host->address, addrlist->address,
      addrlist->next ? ", ..." : "");

    set_process_info("delivering %s to %s [%s]%s (%s%s)",
      message_id, host->name, host->address, pistring, addrlist->address,
      addrlist->next ? ", ..." : "");

    /* This is not for real; don't do the delivery. If there are
    any remaining hosts, list them. */

    if (f.dont_deliver)
      {
      struct timeval now;
      gettimeofday(&now, NULL);
      set_errno_nohost(addrlist, 0, NULL, OK, FALSE, &now);
      for (address_item * addr = addrlist; addr; addr = addr->next)
        {
        addr->host_used = host;
        addr->special_action = '*';
        addr->message = US"delivery bypassed by -N option";
        }
      DEBUG(D_transport)
        {
        debug_printf("*** delivery by %s transport bypassed by -N option\n"
                     "*** host and remaining hosts:\n", tblock->name);
        for (host_item * host2 = host; host2; host2 = host2->next)
          debug_printf("    %s [%s]\n", host2->name,
            host2->address ? host2->address : US"unset");
        }
      rc = OK;
      }

    /* This is for real. If the host is expired, we don't count it for
    hosts_max_retry. This ensures that all hosts must expire before an address
    is timed out, unless hosts_max_try_hardlimit (which protects against
    lunatic DNS configurations) is reached.

    If the host is not expired and we are about to hit the hosts_max_retry
    limit, check to see if there is a subsequent hosts with a different MX
    value. If so, make that the next host, and don't count this one. This is a
    heuristic to make sure that different MXs do get tried. With a normal kind
    of retry rule, they would get tried anyway when the earlier hosts were
    delayed, but if the domain has a "retry every time" type of rule - as is
    often used for the the very large ISPs, that won't happen. */

    else
      {
      host_item * thost;
      /* Make a copy of the host if it is local to this invocation
       of the transport. */

      if (expanded_hosts)
	{
	thost = store_get(sizeof(host_item), FALSE);
	*thost = *host;
	thost->name = string_copy(host->name);
	thost->address = string_copy(host->address);
	}
      else
        thost = host;

      if (!host_is_expired && ++unexpired_hosts_tried >= ob->hosts_max_try)
        {
        DEBUG(D_transport)
          debug_printf("hosts_max_try limit reached with this host\n");
        for (host_item * h = host; h; h = h->next) if (h->mx != host->mx)
	  {
	  nexthost = h;
	  unexpired_hosts_tried--;
	  DEBUG(D_transport) debug_printf("however, a higher MX host exists "
	    "and will be tried\n");
	  break;
	  }
        }

      /* Attempt the delivery. */

      total_hosts_tried++;
      rc = smtp_deliver(addrlist, thost, host_af, defport, interface, tblock,
        &message_defer, FALSE);

      /* Yield is one of:
         OK     => connection made, each address contains its result;
                     message_defer is set for message-specific defers (when all
                     recipients are marked defer)
         DEFER  => there was a non-message-specific delivery problem;
         ERROR  => there was a problem setting up the arguments for a filter,
                   or there was a problem with expanding added headers
      */

      /* If the result is not OK, there was a non-message-specific problem.
      If the result is DEFER, we need to write to the logs saying what happened
      for this particular host, except in the case of authentication and TLS
      failures, where the log has already been written. If all hosts defer a
      general message is written at the end. */

      if (rc == DEFER && first_addr->basic_errno != ERRNO_AUTHFAIL
		      && first_addr->basic_errno != ERRNO_TLSFAILURE)
        write_logs(host, first_addr->message, first_addr->basic_errno);

#ifndef DISABLE_EVENT
      if (rc == DEFER)
	deferred_event_raise(first_addr, host, US"msg:host:defer");
#endif

      /* If STARTTLS was accepted, but there was a failure in setting up the
      TLS session (usually a certificate screwup), and the host is not in
      hosts_require_tls, and tls_tempfail_tryclear is true, try again, with
      TLS forcibly turned off. We have to start from scratch with a new SMTP
      connection. That's why the retry is done from here, not from within
      smtp_deliver(). [Rejections of STARTTLS itself don't screw up the
      session, so the in-clear transmission after those errors, if permitted,
      happens inside smtp_deliver().] */

#ifndef DISABLE_TLS
      if (  rc == DEFER
	 && first_addr->basic_errno == ERRNO_TLSFAILURE
	 && ob->tls_tempfail_tryclear
	 && verify_check_given_host(CUSS &ob->hosts_require_tls, host) != OK
	 )
        {
        log_write(0, LOG_MAIN,
	  "%s: delivering unencrypted to H=%s [%s] (not in hosts_require_tls)",
	  first_addr->message, host->name, host->address);
        first_addr = prepare_addresses(addrlist, host);
        rc = smtp_deliver(addrlist, thost, host_af, defport, interface, tblock,
          &message_defer, TRUE);
        if (rc == DEFER && first_addr->basic_errno != ERRNO_AUTHFAIL)
          write_logs(host, first_addr->message, first_addr->basic_errno);
# ifndef DISABLE_EVENT
	if (rc == DEFER)
	  deferred_event_raise(first_addr, host, US"msg:host:defer");
# endif
        }
#endif	/*DISABLE_TLS*/

#ifndef DISABLE_EVENT
      /* If the last host gave a defer raise a per-message event */

      if (  !(  nexthost
	     && unexpired_hosts_tried < ob->hosts_max_try
	     && total_hosts_tried < ob->hosts_max_try_hardlimit
	     )
         && (message_defer || rc == DEFER)
	 )
	deferred_event_raise(first_addr, host, US"msg:defer");
#endif
      }

    /* Delivery attempt finished */

    set_process_info("delivering %s: just tried %s [%s]%s for %s%s: result %s",
      message_id, host->name, host->address, pistring, addrlist->address,
      addrlist->next ? " (& others)" : "", rc_to_string(rc));

    /* Release serialization if set up */

    if (serialize_key) enq_end(serialize_key);

    /* If the result is DEFER, or if a host retry record is known to exist, we
    need to add an item to the retry chain for updating the retry database
    at the end of delivery. We only need to add the item to the top address,
    of course. Also, if DEFER, we mark the IP address unusable so as to skip it
    for any other delivery attempts using the same address. (It is copied into
    the unusable tree at the outer level, so even if different address blocks
    contain the same address, it still won't get tried again.) */

    if (rc == DEFER || retry_host_key)
      {
      int delete_flag = rc != DEFER ? rf_delete : 0;
      if (!retry_host_key)
        {
	BOOL incl_ip;
	if (exp_bool(addrlist, US"transport", tblock->name, D_transport,
		  US"retry_include_ip_address", ob->retry_include_ip_address,
		  ob->expand_retry_include_ip_address, &incl_ip) != OK)
	  incl_ip = TRUE;	/* error; use most-specific retry record */

        retry_host_key = incl_ip
	  ? string_sprintf("T:%S:%s%s", host->name, host->address, pistring)
	  : string_sprintf("T:%S%s", host->name, pistring);
        }

      /* If a delivery of another message over an existing SMTP connection
      yields DEFER, we do NOT set up retry data for the host. This covers the
      case when there are delays in routing the addresses in the second message
      that are so long that the server times out. This is alleviated by not
      routing addresses that previously had routing defers when handling an
      existing connection, but even so, this case may occur (e.g. if a
      previously happily routed address starts giving routing defers). If the
      host is genuinely down, another non-continued message delivery will
      notice it soon enough. */

      if (delete_flag != 0 || !continue_hostname)
        retry_add_item(first_addr, retry_host_key, rf_host | delete_flag);

      /* We may have tried an expired host, if its retry time has come; ensure
      the status reflects the expiry for the benefit of any other addresses. */

      if (rc == DEFER)
        {
        host->status = host_is_expired
	  ? hstatus_unusable_expired : hstatus_unusable;
        host->why = hwhy_deferred;
        }
      }

    /* If message_defer is set (host was OK, but every recipient got deferred
    because of some message-specific problem), or if that had happened
    previously so that a message retry key exists, add an appropriate item
    to the retry chain. Note that if there was a message defer but now there is
    a host defer, the message defer record gets deleted. That seems perfectly
    reasonable. Also, stop the message from being remembered as waiting
    for specific hosts. */

    if (message_defer || retry_message_key)
      {
      int delete_flag = message_defer ? 0 : rf_delete;
      if (!retry_message_key)
        {
	BOOL incl_ip;
	if (exp_bool(addrlist, US"transport", tblock->name, D_transport,
		  US"retry_include_ip_address", ob->retry_include_ip_address,
		  ob->expand_retry_include_ip_address, &incl_ip) != OK)
	  incl_ip = TRUE;	/* error; use most-specific retry record */

        retry_message_key = incl_ip
	  ? string_sprintf("T:%S:%s%s:%s", host->name, host->address, pistring,
	      message_id)
	  : string_sprintf("T:%S%s:%s", host->name, pistring, message_id);
        }
      retry_add_item(addrlist, retry_message_key,
        rf_message | rf_host | delete_flag);
      update_waiting = FALSE;
      }

    /* Any return other than DEFER (that is, OK or ERROR) means that the
    addresses have got their final statuses filled in for this host. In the OK
    case, see if any of them are deferred. */

    if (rc == OK)
      for (address_item * addr = addrlist; addr; addr = addr->next)
        if (addr->transport_return == DEFER)
          {
          some_deferred = TRUE;
          break;
          }

    /* If no addresses deferred or the result was ERROR, return. We do this for
    ERROR because a failing filter set-up or add_headers expansion is likely to
    fail for any host we try. */

    if (rc == ERROR || (rc == OK && !some_deferred))
      {
      DEBUG(D_transport) debug_printf("Leaving %s transport\n", tblock->name);
      return TRUE;    /* Each address has its status */
      }

    /* If the result was DEFER or some individual addresses deferred, let
    the loop run to try other hosts with the deferred addresses, except for the
    case when we were trying to deliver down an existing channel and failed.
    Don't try any other hosts in this case. */

    if (continue_hostname) break;

    /* If the whole delivery, or some individual addresses, were deferred and
    there are more hosts that could be tried, do not count this host towards
    the hosts_max_try limit if the age of the message is greater than the
    maximum retry time for this host. This means we may try try all hosts,
    ignoring the limit, when messages have been around for some time. This is
    important because if we don't try all hosts, the address will never time
    out. NOTE: this does not apply to hosts_max_try_hardlimit. */

    if ((rc == DEFER || some_deferred) && nexthost)
      {
      BOOL timedout;
      retry_config *retry = retry_find_config(host->name, NULL, 0, 0);

      if (retry && retry->rules)
        {
        retry_rule *last_rule;
        for (last_rule = retry->rules;
             last_rule->next;
             last_rule = last_rule->next);
        timedout = time(NULL) - received_time.tv_sec > last_rule->timeout;
        }
      else timedout = TRUE;    /* No rule => timed out */

      if (timedout)
        {
        unexpired_hosts_tried--;
        DEBUG(D_transport) debug_printf("temporary delivery error(s) override "
          "hosts_max_try (message older than host's retry time)\n");
        }
      }

    DEBUG(D_transport)
      {
      if (unexpired_hosts_tried >= ob->hosts_max_try)
	debug_printf("reached transport hosts_max_try limit %d\n",
	  ob->hosts_max_try);
      if (total_hosts_tried >= ob->hosts_max_try_hardlimit)
	debug_printf("reached transport hosts_max_try_hardlimit limit %d\n",
	  ob->hosts_max_try_hardlimit);
      }

    testharness_pause_ms(500); /* let server debug out */
    }   /* End of loop for trying multiple hosts. */

  /* If we failed to find a matching host in the list, for an already-open
  connection, just close it and start over with the list.  This can happen
  for routing that changes from run to run, or big multi-IP sites with
  round-robin DNS. */

  if (continue_hostname && !continue_host_tried)
    {
    int fd = cutthrough.cctx.sock >= 0 ? cutthrough.cctx.sock : 0;

    DEBUG(D_transport) debug_printf("no hosts match already-open connection\n");
#ifndef DISABLE_TLS
    /* A TLS conn could be open for a cutthrough, but not for a plain continued-
    transport */
/*XXX doublecheck that! */

    if (cutthrough.cctx.sock >= 0 && cutthrough.is_tls)
      {
      (void) tls_write(cutthrough.cctx.tls_ctx, US"QUIT\r\n", 6, FALSE);
      tls_close(cutthrough.cctx.tls_ctx, TLS_SHUTDOWN_NOWAIT);
      cutthrough.cctx.tls_ctx = NULL;
      cutthrough.is_tls = FALSE;
      }
    else
#else
      (void) write(fd, US"QUIT\r\n", 6);
#endif
    (void) close(fd);
    cutthrough.cctx.sock = -1;
    continue_hostname = NULL;
    goto retry_non_continued;
    }

  /* This is the end of the loop that repeats iff expired is TRUE and
  ob->delay_after_cutoff is FALSE. The second time round we will
  try those hosts that haven't been tried since the message arrived. */

  DEBUG(D_transport)
    {
    debug_printf("all IP addresses skipped or deferred at least one address\n");
    if (expired && !ob->delay_after_cutoff && cutoff_retry == 0)
      debug_printf("retrying IP addresses not tried since message arrived\n");
    }
  }


/* Get here if all IP addresses are skipped or defer at least one address. In
MUA wrapper mode, this will happen only for connection or other non-message-
specific failures. Force the delivery status for all addresses to FAIL. */

if (mua_wrapper)
  {
  for (address_item * addr = addrlist; addr; addr = addr->next)
    addr->transport_return = FAIL;
  goto END_TRANSPORT;
  }

/* In the normal, non-wrapper case, add a standard message to each deferred
address if there hasn't been an error, that is, if it hasn't actually been
tried this time. The variable "expired" will be FALSE if any deliveries were
actually tried, or if there was at least one host that was not expired. That
is, it is TRUE only if no deliveries were tried and all hosts were expired. If
a delivery has been tried, an error code will be set, and the failing of the
message is handled by the retry code later.

If queue_smtp is set, or this transport was called to send a subsequent message
down an existing TCP/IP connection, and something caused the host not to be
found, we end up here, but can detect these cases and handle them specially. */

for (address_item * addr = addrlist; addr; addr = addr->next)
  {
  /* If host is not NULL, it means that we stopped processing the host list
  because of hosts_max_try or hosts_max_try_hardlimit. In the former case, this
  means we need to behave as if some hosts were skipped because their retry
  time had not come. Specifically, this prevents the address from timing out.
  However, if we have hit hosts_max_try_hardlimit, we want to behave as if all
  hosts were tried. */

  if (host)
    if (total_hosts_tried >= ob->hosts_max_try_hardlimit)
      {
      DEBUG(D_transport)
        debug_printf("hosts_max_try_hardlimit reached: behave as if all "
          "hosts were tried\n");
      }
    else
      {
      DEBUG(D_transport)
        debug_printf("hosts_max_try limit caused some hosts to be skipped\n");
      setflag(addr, af_retry_skipped);
      }

  if (f.queue_smtp)    /* no deliveries attempted */
    {
    addr->transport_return = DEFER;
    addr->basic_errno = 0;
    addr->message = US"SMTP delivery explicitly queued";
    }

  else if (  addr->transport_return == DEFER
	  && (addr->basic_errno == ERRNO_UNKNOWNERROR || addr->basic_errno == 0)
	  && !addr->message
	  )
    {
    addr->basic_errno = ERRNO_HRETRY;
    if (continue_hostname)
      addr->message = US"no host found for existing SMTP connection";
    else if (expired)
      {
      setflag(addr, af_pass_message);   /* This is not a security risk */
      addr->message = string_sprintf(
	"all hosts%s have been failing for a long time %s",
	addr->domain ? string_sprintf(" for '%s'", addr->domain) : US"",
        ob->delay_after_cutoff
	? US"(and retry time not reached)"
	: US"and were last tried after this message arrived");

      /* If we are already using fallback hosts, or there are no fallback hosts
      defined, convert the result to FAIL to cause a bounce. */

      if (addr->host_list == addr->fallback_hosts || !addr->fallback_hosts)
        addr->transport_return = FAIL;
      }
    else
      {
      const char * s;
      if (hosts_retry == hosts_total)
        s = "retry time not reached for any host%s";
      else if (hosts_fail == hosts_total)
        s = "all host address lookups%s failed permanently";
      else if (hosts_defer == hosts_total)
        s = "all host address lookups%s failed temporarily";
      else if (hosts_serial == hosts_total)
        s = "connection limit reached for all hosts%s";
      else if (hosts_fail+hosts_defer == hosts_total)
        s = "all host address lookups%s failed";
      else
        s = "some host address lookups failed and retry time "
        "not reached for other hosts or connection limit reached%s";

      addr->message = string_sprintf(s,
	addr->domain ? string_sprintf(" for '%s'", addr->domain) : US"");
      }
    }
  }

/* Update the database which keeps information about which messages are waiting
for which hosts to become available. For some message-specific errors, the
update_waiting flag is turned off because we don't want follow-on deliveries in
those cases.  If this transport instance is explicitly limited to one message
per connection then follow-on deliveries are not possible and there's no need
to create/update the per-transport wait-<transport_name> database. */

if (update_waiting && tblock->connection_max_messages != 1)
  transport_update_waiting(hostlist, tblock->name);

END_TRANSPORT:

DEBUG(D_transport) debug_printf("Leaving %s transport\n", tblock->name);

return TRUE;   /* Each address has its status */
}

#endif	/*!MACRO_PREDEF*/
/* vi: aw ai sw=2
*/
/* End of transport/smtp.c */
