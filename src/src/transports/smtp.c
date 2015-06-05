/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "smtp.h"

#define PENDING          256
#define PENDING_DEFER   (PENDING + DEFER)
#define PENDING_OK      (PENDING + OK)


/* Options specific to the smtp transport. This transport also supports LMTP
over TCP/IP. The options must be in alphabetic order (note that "_" comes
before the lower case letters). Some live in the transport_instance block so as
to be publicly visible; these are flagged with opt_public. */

optionlist smtp_transport_options[] = {
  { "*expand_multi_domain",             opt_stringptr | opt_hidden | opt_public,
      (void *)offsetof(transport_instance, expand_multi_domain) },
  { "*expand_retry_include_ip_address", opt_stringptr | opt_hidden,
       (void *)(offsetof(smtp_transport_options_block, expand_retry_include_ip_address)) },

  { "address_retry_include_sender", opt_bool,
      (void *)offsetof(smtp_transport_options_block, address_retry_include_sender) },
  { "allow_localhost",      opt_bool,
      (void *)offsetof(smtp_transport_options_block, allow_localhost) },
  { "authenticated_sender", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, authenticated_sender) },
  { "authenticated_sender_force", opt_bool,
      (void *)offsetof(smtp_transport_options_block, authenticated_sender_force) },
  { "command_timeout",      opt_time,
      (void *)offsetof(smtp_transport_options_block, command_timeout) },
  { "connect_timeout",      opt_time,
      (void *)offsetof(smtp_transport_options_block, connect_timeout) },
  { "connection_max_messages", opt_int | opt_public,
      (void *)offsetof(transport_instance, connection_max_messages) },
  { "data_timeout",         opt_time,
      (void *)offsetof(smtp_transport_options_block, data_timeout) },
  { "delay_after_cutoff", opt_bool,
      (void *)offsetof(smtp_transport_options_block, delay_after_cutoff) },
#ifndef DISABLE_DKIM
  { "dkim_canon", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, dkim_canon) },
  { "dkim_domain", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, dkim_domain) },
  { "dkim_private_key", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, dkim_private_key) },
  { "dkim_selector", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, dkim_selector) },
  { "dkim_sign_headers", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, dkim_sign_headers) },
  { "dkim_strict", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, dkim_strict) },
#endif
  { "dns_qualify_single",   opt_bool,
      (void *)offsetof(smtp_transport_options_block, dns_qualify_single) },
  { "dns_search_parents",   opt_bool,
      (void *)offsetof(smtp_transport_options_block, dns_search_parents) },
  { "dnssec_request_domains", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, dnssec.request) },
  { "dnssec_require_domains", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, dnssec.require) },
  { "dscp",                 opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, dscp) },
  { "fallback_hosts",       opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, fallback_hosts) },
  { "final_timeout",        opt_time,
      (void *)offsetof(smtp_transport_options_block, final_timeout) },
  { "gethostbyname",        opt_bool,
      (void *)offsetof(smtp_transport_options_block, gethostbyname) },
#ifdef SUPPORT_TLS
  /* These are no longer honoured, as of Exim 4.80; for now, we silently
  ignore; 4.83 will warn, and a later-still release will remove
  these options, so that using them becomes an error. */
  { "gnutls_require_kx",    opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, gnutls_require_kx) },
  { "gnutls_require_mac",   opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, gnutls_require_mac) },
  { "gnutls_require_protocols", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, gnutls_require_proto) },
#endif
  { "helo_data",            opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, helo_data) },
  { "hosts",                opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts) },
  { "hosts_avoid_esmtp",    opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_avoid_esmtp) },
  { "hosts_avoid_pipelining", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_avoid_pipelining) },
#ifdef SUPPORT_TLS
  { "hosts_avoid_tls",      opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_avoid_tls) },
#endif
  { "hosts_max_try",        opt_int,
      (void *)offsetof(smtp_transport_options_block, hosts_max_try) },
  { "hosts_max_try_hardlimit", opt_int,
      (void *)offsetof(smtp_transport_options_block, hosts_max_try_hardlimit) },
#ifdef SUPPORT_TLS
  { "hosts_nopass_tls",     opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_nopass_tls) },
#endif
  { "hosts_override",       opt_bool,
      (void *)offsetof(smtp_transport_options_block, hosts_override) },
  { "hosts_randomize",      opt_bool,
      (void *)offsetof(smtp_transport_options_block, hosts_randomize) },
#if defined(SUPPORT_TLS) && !defined(DISABLE_OCSP)
  { "hosts_request_ocsp",   opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_request_ocsp) },
#endif
  { "hosts_require_auth",   opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_require_auth) },
#ifdef SUPPORT_TLS
# ifdef EXPERIMENTAL_DANE
  { "hosts_require_dane",   opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_require_dane) },
# endif
# ifndef DISABLE_OCSP
  { "hosts_require_ocsp",   opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_require_ocsp) },
# endif
  { "hosts_require_tls",    opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_require_tls) },
#endif
  { "hosts_try_auth",       opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_try_auth) },
#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_DANE)
  { "hosts_try_dane",       opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_try_dane) },
#endif
#ifndef DISABLE_PRDR
  { "hosts_try_prdr",       opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_try_prdr) },
#endif
#ifdef SUPPORT_TLS
  { "hosts_verify_avoid_tls", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, hosts_verify_avoid_tls) },
#endif
  { "interface",            opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, interface) },
  { "keepalive",            opt_bool,
      (void *)offsetof(smtp_transport_options_block, keepalive) },
  { "lmtp_ignore_quota",    opt_bool,
      (void *)offsetof(smtp_transport_options_block, lmtp_ignore_quota) },
  { "max_rcpt",             opt_int | opt_public,
      (void *)offsetof(transport_instance, max_addresses) },
  { "multi_domain",         opt_expand_bool | opt_public,
      (void *)offsetof(transport_instance, multi_domain) },
  { "port",                 opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, port) },
  { "protocol",             opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, protocol) },
  { "retry_include_ip_address", opt_expand_bool,
      (void *)offsetof(smtp_transport_options_block, retry_include_ip_address) },
  { "serialize_hosts",      opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, serialize_hosts) },
  { "size_addition",        opt_int,
      (void *)offsetof(smtp_transport_options_block, size_addition) }
#ifdef EXPERIMENTAL_SOCKS
 ,{ "socks_proxy",          opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, socks_proxy) }
#endif
#ifdef SUPPORT_TLS
 ,{ "tls_certificate",      opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, tls_certificate) },
  { "tls_crl",              opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, tls_crl) },
  { "tls_dh_min_bits",      opt_int,
      (void *)offsetof(smtp_transport_options_block, tls_dh_min_bits) },
  { "tls_privatekey",       opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, tls_privatekey) },
  { "tls_require_ciphers",  opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, tls_require_ciphers) },
  { "tls_sni",              opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, tls_sni) },
  { "tls_tempfail_tryclear", opt_bool,
      (void *)offsetof(smtp_transport_options_block, tls_tempfail_tryclear) },
  { "tls_try_verify_hosts", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, tls_try_verify_hosts) },
  { "tls_verify_cert_hostnames", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block,tls_verify_cert_hostnames)},
  { "tls_verify_certificates", opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, tls_verify_certificates) },
  { "tls_verify_hosts",     opt_stringptr,
      (void *)offsetof(smtp_transport_options_block, tls_verify_hosts) }
#endif
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int smtp_transport_options_count =
  sizeof(smtp_transport_options)/sizeof(optionlist);

/* Default private options block for the smtp transport. */

smtp_transport_options_block smtp_transport_option_defaults = {
  NULL,                /* hosts */
  NULL,                /* fallback_hosts */
  NULL,                /* hostlist */
  NULL,                /* fallback_hostlist */
  NULL,                /* authenticated_sender */
  US"$primary_hostname", /* helo_data */
  NULL,                /* interface */
  NULL,                /* port */
  US"smtp",            /* protocol */
  NULL,                /* DSCP */
  NULL,                /* serialize_hosts */
  NULL,                /* hosts_try_auth */
  NULL,                /* hosts_require_auth */
#ifdef EXPERIMENTAL_DANE
  NULL,                /* hosts_try_dane */
  NULL,                /* hosts_require_dane */
#endif
#ifndef DISABLE_PRDR
  US"*",                /* hosts_try_prdr */
#endif
#ifndef DISABLE_OCSP
  US"*",               /* hosts_request_ocsp (except under DANE; tls_client_start()) */
  NULL,                /* hosts_require_ocsp */
#endif
  NULL,                /* hosts_require_tls */
  NULL,                /* hosts_avoid_tls */
  NULL,                /* hosts_verify_avoid_tls */
  NULL,                /* hosts_avoid_pipelining */
  NULL,                /* hosts_avoid_esmtp */
  NULL,                /* hosts_nopass_tls */
  5*60,                /* command_timeout */
  5*60,                /* connect_timeout; shorter system default overrides */
  5*60,                /* data timeout */
  10*60,               /* final timeout */
  1024,                /* size_addition */
  5,                   /* hosts_max_try */
  50,                  /* hosts_max_try_hardlimit */
  TRUE,                /* address_retry_include_sender */
  FALSE,               /* allow_localhost */
  FALSE,               /* authenticated_sender_force */
  FALSE,               /* gethostbyname */
  TRUE,                /* dns_qualify_single */
  FALSE,               /* dns_search_parents */
  { NULL, NULL },      /* dnssec_domains {request,require} */
  TRUE,                /* delay_after_cutoff */
  FALSE,               /* hosts_override */
  FALSE,               /* hosts_randomize */
  TRUE,                /* keepalive */
  FALSE,               /* lmtp_ignore_quota */
  NULL,		       /* expand_retry_include_ip_address */
  TRUE                 /* retry_include_ip_address */
#ifdef EXPERIMENTAL_SOCKS
 ,NULL                 /* socks_proxy */
#endif
#ifdef SUPPORT_TLS
 ,NULL,                /* tls_certificate */
  NULL,                /* tls_crl */
  NULL,                /* tls_privatekey */
  NULL,                /* tls_require_ciphers */
  NULL,                /* gnutls_require_kx */
  NULL,                /* gnutls_require_mac */
  NULL,                /* gnutls_require_proto */
  NULL,                /* tls_sni */
  US"system",          /* tls_verify_certificates */
  EXIM_CLIENT_DH_DEFAULT_MIN_BITS,
                       /* tls_dh_min_bits */
  TRUE,                /* tls_tempfail_tryclear */
  NULL,                /* tls_verify_hosts */
  US"*",               /* tls_try_verify_hosts */
  US"*"                /* tls_verify_cert_hostnames */
#endif
#ifndef DISABLE_DKIM
 ,NULL,                /* dkim_canon */
  NULL,                /* dkim_domain */
  NULL,                /* dkim_private_key */
  NULL,                /* dkim_selector */
  NULL,                /* dkim_sign_headers */
  NULL                 /* dkim_strict */
#endif
};

/* some DSN flags for use later */

static int     rf_list[] = {rf_notify_never, rf_notify_success,
                            rf_notify_failure, rf_notify_delay };

static uschar *rf_names[] = { US"NEVER", US"SUCCESS", US"FAILURE", US"DELAY" };



/* Local statics */

static uschar *smtp_command;   /* Points to last cmd for error messages */
static uschar *mail_command;   /* Points to MAIL cmd for error messages */
static BOOL    update_waiting; /* TRUE to update the "wait" database */


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
smtp_transport_options_block *ob =
  (smtp_transport_options_block *)(tblock->options_block);

errmsg = errmsg;    /* Keep picky compilers happy */
uid = uid;
gid = gid;

/* Pass back options if required. This interface is getting very messy. */

if (tf != NULL)
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
  {
  for (; addrlist != NULL; addrlist = addrlist->next)
    if (addrlist->fallback_hosts == NULL)
      addrlist->fallback_hosts = ob->fallback_hostlist;
  }

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
smtp_transport_options_block *ob =
  (smtp_transport_options_block *)(tblock->options_block);

/* Retry_use_local_part defaults FALSE if unset */

if (tblock->retry_use_local_part == TRUE_UNSET)
  tblock->retry_use_local_part = FALSE;

/* Set the default port according to the protocol */

if (ob->port == NULL)
  ob->port = (strcmpic(ob->protocol, US"lmtp") == 0)? US"lmtp" :
    (strcmpic(ob->protocol, US"smtps") == 0)? US"smtps" : US"smtp";

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

if (ob->hosts_override && ob->hosts != NULL) tblock->overrides_hosts = TRUE;

/* If there are any fallback hosts listed, build a chain of host items
for them, but do not do any lookups at this time. */

host_build_hostlist(&(ob->fallback_hostlist), ob->fallback_hosts, FALSE);

#ifdef SUPPORT_TLS
if (  ob->gnutls_require_kx
   || ob->gnutls_require_mac
   || ob->gnutls_require_proto)
  log_write(0, LOG_MAIN, "WARNING: smtp transport options"
    " gnutls_require_kx, gnutls_require_mac and gnutls_require_protocols"
    " are obsolete\n");
#endif
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

If errno_value has the special value ERRNO_CONNECTTIMEOUT, ETIMEDOUT is put in
the errno field, and RTEF_CTOUT is ORed into the more_errno field, to indicate
this particular type of timeout.

Returns:       nothing
*/

static void
set_errno(address_item *addrlist, int errno_value, uschar *msg, int rc,
  BOOL pass_message, host_item * host)
{
address_item *addr;
int orvalue = 0;
if (errno_value == ERRNO_CONNECTTIMEOUT)
  {
  errno_value = ETIMEDOUT;
  orvalue = RTEF_CTOUT;
  }
for (addr = addrlist; addr != NULL; addr = addr->next)
  if (addr->transport_return >= PENDING)
    {
    addr->basic_errno = errno_value;
    addr->more_errno |= orvalue;
    if (msg != NULL)
      {
      addr->message = msg;
      if (pass_message) setflag(addr, af_pass_message);
      }
    addr->transport_return = rc;
    if (host)
      addr->host_used = host;
    }
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
  message        where to put an errror message
  pass_message   set TRUE if message is an SMTP response

Returns:         TRUE if an SMTP "QUIT" command should be sent, else FALSE
*/

static BOOL
check_response(host_item *host, int *errno_value, int more_errno,
  uschar *buffer, int *yield, uschar **message, BOOL *pass_message)
{
uschar *pl = US"";

if (smtp_use_pipelining &&
    (Ustrcmp(smtp_command, "MAIL") == 0 ||
     Ustrcmp(smtp_command, "RCPT") == 0 ||
     Ustrcmp(smtp_command, "DATA") == 0))
  pl = US"pipelined ";

*yield = '4';    /* Default setting is to give a temporary error */

/* Handle response timeout */

if (*errno_value == ETIMEDOUT)
  {
  *message = US string_sprintf("SMTP timeout after %s%s",
      pl, smtp_command);
  if (transport_count > 0)
    *message = US string_sprintf("%s (%d bytes written)", *message,
      transport_count);
  return FALSE;
  }

/* Handle malformed SMTP response */

if (*errno_value == ERRNO_SMTPFORMAT)
  {
  const uschar *malfresp = string_printing(buffer);
  while (isspace(*malfresp)) malfresp++;
  *message = *malfresp == 0
    ? string_sprintf("Malformed SMTP reply (an empty line) "
	"in response to %s%s", pl, smtp_command)
    : string_sprintf("Malformed SMTP reply in response to %s%s: %s",
	pl, smtp_command, malfresp);
  return FALSE;
  }

/* Handle a failed filter process error; can't send QUIT as we mustn't
end the DATA. */

if (*errno_value == ERRNO_FILTER_FAIL)
  {
  *message = US string_sprintf("transport filter process failed (%d)%s",
    more_errno,
    (more_errno == EX_EXECFAILED)? ": unable to execute command" : "");
  return FALSE;
  }

/* Handle a failed add_headers expansion; can't send QUIT as we mustn't
end the DATA. */

if (*errno_value == ERRNO_CHHEADER_FAIL)
  {
  *message =
    US string_sprintf("failed to expand headers_add or headers_remove: %s",
      expand_string_message);
  return FALSE;
  }

/* Handle failure to write a complete data block */

if (*errno_value == ERRNO_WRITEINCOMPLETE)
  {
  *message = US string_sprintf("failed to write a data block");
  return FALSE;
  }

#ifdef EXPERIMENTAL_INTERNATIONAL
/* Handle lack of advertised SMTPUTF8, for international message */
if (*errno_value == ERRNO_UTF8_FWD)
  {
  *message = US string_sprintf("utf8 support required but not offered for forwarding");
  DEBUG(D_deliver|D_transport) debug_printf("%s\n", *message);
  return TRUE;
  }
#endif

/* Handle error responses from the remote mailer. */

if (buffer[0] != 0)
  {
  const uschar *s = string_printing(buffer);
  *message = US string_sprintf("SMTP error from remote mail server after %s%s: "
    "%s", pl, smtp_command, s);
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
    "in response to %s%s",  pl, smtp_command);
  }
else *message = US string_sprintf("%s [%s]", host->name, host->address);

return FALSE;
}



/*************************************************
*          Write error message to logs           *
*************************************************/

/* This writes to the main log and to the message log.

Arguments:
  addr     the address item containing error information
  host     the current host

Returns:   nothing
*/

static void
write_logs(address_item *addr, host_item *host)
{
uschar * message = string_sprintf("H=%s [%s]", host->name, host->address);

if (addr->message)
  {
  message = string_sprintf("%s: %s", message, addr->message);
  if (addr->basic_errno > 0)
    message = string_sprintf("%s: %s", message, strerror(addr->basic_errno));
  log_write(0, LOG_MAIN, "%s", message);
  deliver_msglog("%s %s\n", tod_stamp(tod_log), message);
  }
else
  {
  if (log_extra_selector & LX_outgoing_port)
    message = string_sprintf("%s:%d", message,
		host->port == PORT_NONE ? 25 : host->port);
  log_write(0, LOG_MAIN, "%s %s", message, strerror(addr->basic_errno));
  deliver_msglog("%s %s %s\n", tod_stamp(tod_log), message,
		strerror(addr->basic_errno));
  }
}

static void
msglog_line(host_item * host, uschar * message)
{
  deliver_msglog("%s H=%s [%s] %s\n", tod_stamp(tod_log),
    host->name, host->address, message);
}



#ifdef EXPERIMENTAL_EVENT
/*************************************************
*   Post-defer action                            *
*************************************************/

/* This expands an arbitrary per-transport string.
   It might, for example, be used to write to the database log.

Arguments:
  addr                  the address item containing error information
  host                  the current host

Returns:   nothing
*/

static void
deferred_event_raise(address_item *addr, host_item *host)
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

(void) event_raise(action, US"msg:host:defer",
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
  addrlist          the complete address list
  include_affixes   TRUE if affixes include in RCPT
  sync_addr         ptr to the ptr of the one to start scanning at (updated)
  host              the host we are connected to
  count             the number of responses to read
  address_retry_
    include_sender  true if 4xx retry is to include the sender it its key
  pending_MAIL      true if the first response is for MAIL
  pending_DATA      0 if last command sent was not DATA
                   +1 if previously had a good recipient
                   -1 if not previously had a good recipient
  inblock           incoming SMTP block
  timeout           timeout value
  buffer            buffer for reading response
  buffsize          size of buffer

Returns:      3 if at least one address had 2xx and one had 5xx
              2 if at least one address had 5xx but none had 2xx
              1 if at least one host had a 2xx response, but none had 5xx
              0 no address had 2xx or 5xx but no errors (all 4xx, or just DATA)
             -1 timeout while reading RCPT response
             -2 I/O or other non-response error for RCPT
             -3 DATA or MAIL failed - errno and buffer set
*/

static int
sync_responses(address_item *addrlist, BOOL include_affixes,
  address_item **sync_addr, host_item *host, int count,
  BOOL address_retry_include_sender, BOOL pending_MAIL,
  int pending_DATA, smtp_inblock *inblock, int timeout, uschar *buffer,
  int buffsize)
{
address_item *addr = *sync_addr;
int yield = 0;

/* Handle the response for a MAIL command. On error, reinstate the original
command in big_buffer for error message use, and flush any further pending
responses before returning, except after I/O errors and timeouts. */

if (pending_MAIL)
  {
  count--;
  if (!smtp_read_response(inblock, buffer, buffsize, '2', timeout))
    {
    Ustrcpy(big_buffer, mail_command);  /* Fits, because it came from there! */
    if (errno == 0 && buffer[0] != 0)
      {
      uschar flushbuffer[4096];
      int save_errno = 0;
      if (buffer[0] == '4')
        {
        save_errno = ERRNO_MAIL4XX;
        addr->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
        }
      while (count-- > 0)
        {
        if (!smtp_read_response(inblock, flushbuffer, sizeof(flushbuffer),
                   '2', timeout)
            && (errno != 0 || flushbuffer[0] == 0))
          break;
        }
      errno = save_errno;
      }

    if (pending_DATA) count--;  /* Number of RCPT responses to come */
    while (count-- > 0)		/* Mark any pending addrs with the host used */
      {
      while (addr->transport_return != PENDING_DEFER) addr = addr->next;
      addr->host_used = host;
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
  while (addr->transport_return != PENDING_DEFER) addr = addr->next;

  /* The address was accepted */
  addr->host_used = host;

  if (smtp_read_response(inblock, buffer, buffsize, '2', timeout))
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

  /* Timeout while reading the response */

  else if (errno == ETIMEDOUT)
    {
    uschar *message = string_sprintf("SMTP timeout after RCPT TO:<%s>",
			  transport_rcpt_address(addr, include_affixes));
    set_errno(addrlist, ETIMEDOUT, message, DEFER, FALSE, NULL);
    retry_add_item(addr, addr->address_retry_key, 0);
    update_waiting = FALSE;
    return -1;
    }

  /* Handle other errors in obtaining an SMTP response by returning -1. This
  will cause all the addresses to be deferred. Restore the SMTP command in
  big_buffer for which we are checking the response, so the error message
  makes sense. */

  else if (errno != 0 || buffer[0] == 0)
    {
    string_format(big_buffer, big_buffer_size, "RCPT TO:<%s>",
      transport_rcpt_address(addr, include_affixes));
    return -2;
    }

  /* Handle SMTP permanent and temporary response codes. */

  else
    {
    addr->message =
      string_sprintf("SMTP error from remote mail server after RCPT TO:<%s>: "
	"%s", transport_rcpt_address(addr, include_affixes),
	string_printing(buffer));
    setflag(addr, af_pass_message);
    msglog_line(host, addr->message);

    /* The response was 5xx */

    if (buffer[0] == '5')
      {
      addr->transport_return = FAIL;
      yield |= 2;
      }

    /* The response was 4xx */

    else
      {
      addr->transport_return = DEFER;
      addr->basic_errno = ERRNO_RCPT4XX;
      addr->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;

      /* Log temporary errors if there are more hosts to be tried.
      If not, log this last one in the == line. */

      if (host->next)
	log_write(0, LOG_MAIN, "H=%s [%s]: %s", host->name, host->address, addr->message);

      /* Do not put this message on the list of those waiting for specific
      hosts, as otherwise it is likely to be tried too often. */

      update_waiting = FALSE;

      /* Add a retry item for the address so that it doesn't get tried again
      too soon. If address_retry_include_sender is true, add the sender address
      to the retry key. */

      if (address_retry_include_sender)
        {
        uschar *altkey = string_sprintf("%s:<%s>", addr->address_retry_key,
          sender_address);
        retry_add_item(addr, altkey, 0);
        }
      else retry_add_item(addr, addr->address_retry_key, 0);
      }
    }
  }       /* Loop for next RCPT response */

/* Update where to start at for the next block of responses, unless we
have already handled all the addresses. */

if (addr != NULL) *sync_addr = addr->next;

/* Handle a response to DATA. If we have not had any good recipients, either
previously or in this block, the response is ignored. */

if (pending_DATA != 0 &&
    !smtp_read_response(inblock, buffer, buffsize, '3', timeout))
  {
  int code;
  uschar *msg;
  BOOL pass_message;
  if (pending_DATA > 0 || (yield & 1) != 0)
    {
    if (errno == 0 && buffer[0] == '4')
      {
      errno = ERRNO_DATA4XX;
      addrlist->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
      }
    return -3;
    }
  (void)check_response(host, &errno, 0, buffer, &code, &msg, &pass_message);
  DEBUG(D_transport) debug_printf("%s\nerror for DATA ignored: pipelining "
    "is in use and there were no good recipients\n", msg);
  }

/* All responses read and handled; MAIL (if present) received 2xx and DATA (if
present) received 3xx. If any RCPTs were handled and yielded anything other
than 4xx, yield will be set non-zero. */

return yield;
}



/* Do the client side of smtp-level authentication */
/*
Arguments:
  buffer	EHLO response from server (gets overwritten)
  addrlist      chain of potential addresses to deliver
  host          host to deliver to
  ob		transport options
  ibp, obp	comms channel control blocks

Returns:
  OK			Success, or failed (but not required): global "smtp_authenticated" set
  DEFER			Failed authentication (and was required)
  ERROR			Internal problem

  FAIL_SEND		Failed communications - transmit
  FAIL			- response
*/

int
smtp_auth(uschar *buffer, unsigned bufsize, address_item *addrlist, host_item *host,
    smtp_transport_options_block *ob, BOOL is_esmtp,
    smtp_inblock *ibp, smtp_outblock *obp)
{
int require_auth;
uschar *fail_reason = US"server did not advertise AUTH support";

smtp_authenticated = FALSE;
client_authenticator = client_authenticated_id = client_authenticated_sender = NULL;
require_auth = verify_check_given_host(&ob->hosts_require_auth, host);

if (is_esmtp && !regex_AUTH) regex_AUTH =
    regex_must_compile(US"\\n250[\\s\\-]AUTH\\s+([\\-\\w\\s]+)(?:\\n|$)",
	  FALSE, TRUE);

if (is_esmtp && regex_match_and_setup(regex_AUTH, buffer, 0, -1))
  {
  uschar *names = string_copyn(expand_nstring[1], expand_nlength[1]);
  expand_nmax = -1;                          /* reset */

  /* Must not do this check until after we have saved the result of the
  regex match above. */

  if (require_auth == OK ||
      verify_check_given_host(&ob->hosts_try_auth, host) == OK)
    {
    auth_instance *au;
    fail_reason = US"no common mechanisms were found";

    DEBUG(D_transport) debug_printf("scanning authentication mechanisms\n");

    /* Scan the configured authenticators looking for one which is configured
    for use as a client, which is not suppressed by client_condition, and
    whose name matches an authentication mechanism supported by the server.
    If one is found, attempt to authenticate by calling its client function.
    */

    for (au = auths; !smtp_authenticated && au != NULL; au = au->next)
      {
      uschar *p = names;
      if (!au->client ||
	  (au->client_condition != NULL &&
	   !expand_check_condition(au->client_condition, au->name,
	     US"client authenticator")))
	{
	DEBUG(D_transport) debug_printf("skipping %s authenticator: %s\n",
	  au->name,
	  (au->client)? "client_condition is false" :
			"not configured as a client");
	continue;
	}

      /* Loop to scan supported server mechanisms */

      while (*p != 0)
	{
	int rc;
	int len = Ustrlen(au->public_name);
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
	obp->authenticating = TRUE;
	rc = (au->info->clientcode)(au, ibp, obp,
	  ob->command_timeout, buffer, bufsize);
	obp->authenticating = FALSE;
	DEBUG(D_transport) debug_printf("%s authenticator yielded %d\n",
	  au->name, rc);

	/* A temporary authentication failure must hold up delivery to
	this host. After a permanent authentication failure, we carry on
	to try other authentication methods. If all fail hard, try to
	deliver the message unauthenticated unless require_auth was set. */

	switch(rc)
	  {
	  case OK:
	  smtp_authenticated = TRUE;   /* stops the outer loop */
	  client_authenticator = au->name;
	  if (au->set_client_id != NULL)
	    client_authenticated_id = expand_string(au->set_client_id);
	  break;

	  /* Failure after writing a command */

	  case FAIL_SEND:
	  return FAIL_SEND;

	  /* Failure after reading a response */

	  case FAIL:
	  if (errno != 0 || buffer[0] != '5') return FAIL;
	  log_write(0, LOG_MAIN, "%s authenticator failed H=%s [%s] %s",
	    au->name, host->name, host->address, buffer);
	  break;

	  /* Failure by some other means. In effect, the authenticator
	  decided it wasn't prepared to handle this case. Typically this
	  is the result of "fail" in an expansion string. Do we need to
	  log anything here? Feb 2006: a message is now put in the buffer
	  if logging is required. */

	  case CANCELLED:
	  if (*buffer != 0)
	    log_write(0, LOG_MAIN, "%s authenticator cancelled "
	      "authentication H=%s [%s] %s", au->name, host->name,
	      host->address, buffer);
	  break;

	  /* Internal problem, message in buffer. */

	  case ERROR:
	  set_errno(addrlist, ERRNO_AUTHPROB, string_copy(buffer),
		    DEFER, FALSE, NULL);
	  return ERROR;
	  }

	break;  /* If not authenticated, try next authenticator */
	}       /* Loop for scanning supported server mechanisms */
      }         /* Loop for further authenticators */
    }
  }

/* If we haven't authenticated, but are required to, give up. */

if (require_auth == OK && !smtp_authenticated)
  {
  set_errno(addrlist, ERRNO_AUTHFAIL,
    string_sprintf("authentication required but %s", fail_reason), DEFER,
    FALSE, NULL);
  return DEFER;
  }

return OK;
}


/* Construct AUTH appendix string for MAIL TO */
/*
Arguments
  buffer	to build string
  addrlist      chain of potential addresses to deliver
  ob		transport options

Globals		smtp_authenticated
		client_authenticated_sender
Return	True on error, otherwise buffer has (possibly empty) terminated string
*/

BOOL
smtp_mail_auth_str(uschar *buffer, unsigned bufsize, address_item *addrlist,
		    smtp_transport_options_block *ob)
{
uschar *local_authenticated_sender = authenticated_sender;

#ifdef notdef
  debug_printf("smtp_mail_auth_str: as<%s> os<%s> SA<%s>\n", authenticated_sender, ob->authenticated_sender, smtp_authenticated?"Y":"N");
#endif

if (ob->authenticated_sender != NULL)
  {
  uschar *new = expand_string(ob->authenticated_sender);
  if (new == NULL)
    {
    if (!expand_string_forcedfail)
      {
      uschar *message = string_sprintf("failed to expand "
        "authenticated_sender: %s", expand_string_message);
      set_errno(addrlist, ERRNO_EXPANDFAIL, message, DEFER, FALSE, NULL);
      return TRUE;
      }
    }
  else if (new[0] != 0) local_authenticated_sender = new;
  }

/* Add the authenticated sender address if present */

if ((smtp_authenticated || ob->authenticated_sender_force) &&
    local_authenticated_sender != NULL)
  {
  string_format(buffer, bufsize, " AUTH=%s",
    auth_xtextencode(local_authenticated_sender,
    Ustrlen(local_authenticated_sender)));
  client_authenticated_sender = string_copy(local_authenticated_sender);
  }
else
  *buffer= 0;

return FALSE;
}



#ifdef EXPERIMENTAL_DANE
int
tlsa_lookup(const host_item * host, dns_answer * dnsa,
  BOOL dane_required, BOOL * dane)
{
/* move this out to host.c given the similarity to dns_lookup() ? */
uschar buffer[300];
const uschar * fullname = buffer;

/* TLSA lookup string */
(void)sprintf(CS buffer, "_%d._tcp.%.256s", host->port, host->name);

switch (dns_lookup(dnsa, buffer, T_TLSA, &fullname))
  {
  case DNS_AGAIN:
    return DEFER; /* just defer this TLS'd conn */

  default:
  case DNS_FAIL:
    if (dane_required)
      return FAIL;
    break;

  case DNS_SUCCEED:
    if (!dns_is_secure(dnsa))
      {
      log_write(0, LOG_MAIN, "DANE error: TLSA lookup not DNSSEC");
      return DEFER;
      }
    *dane = TRUE;
    break;
  }
return OK;
}
#endif



typedef struct smtp_compare_s
{
    uschar                          *current_sender_address;
    struct transport_instance       *tblock;
} smtp_compare_t;

/*
Create a unique string that identifies this message, it is based on
sender_address, helo_data and tls_certificate if enabled.  */

static uschar *
smtp_local_identity(uschar * sender, struct transport_instance * tblock)
{
address_item * addr1;
uschar * if1 = US"";
uschar * helo1 = US"";
#ifdef SUPPORT_TLS
uschar * tlsc1 = US"";
#endif
uschar * save_sender_address = sender_address;
uschar * local_identity = NULL;
smtp_transport_options_block * ob =
  (smtp_transport_options_block *)tblock->options_block;

sender_address = sender;

addr1 = deliver_make_addr (sender, TRUE);
deliver_set_expansions(addr1);

if (ob->interface)
  if1 = expand_string(ob->interface);

if (ob->helo_data)
  helo1 = expand_string(ob->helo_data);

#ifdef SUPPORT_TLS
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
uschar * save_sender_address = sender_address;
uschar * current_local_identity =
  smtp_local_identity(s_compare->current_sender_address, s_compare->tblock);
uschar * new_sender_address = deliver_get_sender_address(message_id);
uschar * message_local_identity =
  smtp_local_identity(new_sender_address, s_compare->tblock);

sender_address = save_sender_address;

return Ustrcmp(current_local_identity, message_local_identity) == 0;
}



/*************************************************
*       Deliver address list to given host       *
*************************************************/

/* If continue_hostname is not null, we get here only when continuing to
deliver down an existing channel. The channel was passed as the standard
input. TLS is never active on a passed channel; the previous process always
closes it down before passing the connection on.

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
  port            default TCP/IP port to use, in host byte order
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
*/

static int
smtp_deliver(address_item *addrlist, host_item *host, int host_af, int port,
  uschar *interface, transport_instance *tblock,
  BOOL *message_defer, BOOL suppress_tls)
{
address_item *addr;
address_item *sync_addr;
address_item *first_addr = addrlist;
int yield = OK;
int address_count;
int save_errno;
int rc;
time_t start_delivery_time = time(NULL);
smtp_transport_options_block *ob =
  (smtp_transport_options_block *)(tblock->options_block);
BOOL lmtp = strcmpic(ob->protocol, US"lmtp") == 0;
BOOL smtps = strcmpic(ob->protocol, US"smtps") == 0;
BOOL ok = FALSE;
BOOL send_rset = TRUE;
BOOL send_quit = TRUE;
BOOL setting_up = TRUE;
BOOL completed_address = FALSE;
BOOL esmtp = TRUE;
BOOL pending_MAIL;
BOOL pass_message = FALSE;
#ifndef DISABLE_PRDR
BOOL prdr_offered = FALSE;
BOOL prdr_active;
#endif
#ifdef EXPERIMENTAL_INTERNATIONAL
BOOL utf8_needed = FALSE;
BOOL utf8_offered = FALSE;
#endif
BOOL dsn_all_lasthop = TRUE;
#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_DANE)
BOOL dane = FALSE;
BOOL dane_required = verify_check_given_host(&ob->hosts_require_dane, host) == OK;
dns_answer tlsa_dnsa;
#endif
smtp_inblock inblock;
smtp_outblock outblock;
int max_rcpt = tblock->max_addresses;
uschar *igquotstr = US"";

uschar *helo_data = NULL;

uschar *message = NULL;
uschar new_message_id[MESSAGE_ID_LENGTH + 1];
uschar *p;
uschar buffer[4096];
uschar inbuffer[4096];
uschar outbuffer[4096];

suppress_tls = suppress_tls;  /* stop compiler warning when no TLS support */

*message_defer = FALSE;
smtp_command = US"initial connection";
if (max_rcpt == 0) max_rcpt = 999999;

/* Set up the buffer for reading SMTP response packets. */

inblock.buffer = inbuffer;
inblock.buffersize = sizeof(inbuffer);
inblock.ptr = inbuffer;
inblock.ptrend = inbuffer;

/* Set up the buffer for holding SMTP commands while pipelining */

outblock.buffer = outbuffer;
outblock.buffersize = sizeof(outbuffer);
outblock.ptr = outbuffer;
outblock.cmd_count = 0;
outblock.authenticating = FALSE;

/* Reset the parameters of a TLS session. */

tls_out.bits = 0;
tls_out.cipher = NULL;	/* the one we may use for this transport */
tls_out.ourcert = NULL;
tls_out.peercert = NULL;
tls_out.peerdn = NULL;
#if defined(SUPPORT_TLS) && !defined(USE_GNUTLS)
tls_out.sni = NULL;
#endif
tls_out.ocsp = OCSP_NOT_REQ;

/* Flip the legacy TLS-related variables over to the outbound set in case
they're used in the context of the transport.  Don't bother resetting
afterward as we're in a subprocess. */

tls_modify_variables(&tls_out);

#ifndef SUPPORT_TLS
if (smtps)
  {
  set_errno(addrlist, ERRNO_TLSFAILURE, US"TLS support not available",
	    DEFER, FALSE, NULL);
  return ERROR;
  }
#endif

/* Make a connection to the host if this isn't a continued delivery, and handle
the initial interaction and HELO/EHLO/LHLO. Connect timeout errors are handled
specially so they can be identified for retries. */

if (continue_hostname == NULL)
  {
  /* This puts port into host->port */
  inblock.sock = outblock.sock =
    smtp_connect(host, host_af, port, interface, ob->connect_timeout, tblock);

  if (inblock.sock < 0)
    {
    set_errno(addrlist, (errno == ETIMEDOUT)? ERRNO_CONNECTTIMEOUT : errno,
      NULL, DEFER, FALSE, NULL);
    return DEFER;
    }

#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_DANE)
    {
    tls_out.dane_verified = FALSE;
    tls_out.tlsa_usage = 0;

    if (host->dnssec == DS_YES)
      {
      if(  (  dane_required
	   || verify_check_given_host(&ob->hosts_try_dane, host) == OK
	   )
	&& (rc = tlsa_lookup(host, &tlsa_dnsa, dane_required, &dane)) != OK
	&& dane_required	/* do not error on only dane-requested */
	)
	{
	set_errno(addrlist, ERRNO_DNSDEFER,
	  string_sprintf("DANE error: tlsa lookup %s",
	    rc == DEFER ? "DEFER" : "FAIL"),
	  rc, FALSE, NULL);
	return rc;
	}
      }
    else if (dane_required)
      {
      set_errno(addrlist, ERRNO_DNSDEFER,
	string_sprintf("DANE error: %s lookup not DNSSEC", host->name),
	FAIL, FALSE, NULL);
      return  FAIL;
      }

    if (dane)
      ob->tls_tempfail_tryclear = FALSE;
    }
#endif	/*DANE*/

  /* Expand the greeting message while waiting for the initial response. (Makes
  sense if helo_data contains ${lookup dnsdb ...} stuff). The expansion is
  delayed till here so that $sending_interface and $sending_port are set. */

  helo_data = expand_string(ob->helo_data);
#ifdef EXPERIMENTAL_INTERNATIONAL
  if (helo_data)
    {
    uschar * errstr = NULL;
    if ((helo_data = string_domain_utf8_to_alabel(helo_data, &errstr)), errstr)
      {
      errstr = string_sprintf("failed to expand helo_data: %s", errstr);
      set_errno(addrlist, ERRNO_EXPANDFAIL, errstr, DEFER, FALSE, NULL);
      yield = DEFER;
      goto SEND_QUIT;
      }
    }
#endif

  /* The first thing is to wait for an initial OK response. The dreaded "goto"
  is nevertheless a reasonably clean way of programming this kind of logic,
  where you want to escape on any error. */

  if (!smtps)
    {
    if (!smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
      ob->command_timeout)) goto RESPONSE_FAILED;

#ifdef EXPERIMENTAL_EVENT
      {
      uschar * s;
      lookup_dnssec_authenticated = host->dnssec==DS_YES ? US"yes"
	: host->dnssec==DS_NO ? US"no" : NULL;
      s = event_raise(tblock->event_action, US"smtp:connect", buffer);
      if (s)
	{
	set_errno(addrlist, ERRNO_EXPANDFAIL,
	  string_sprintf("deferred by smtp:connect event expansion: %s", s),
	  DEFER, FALSE, NULL);
	yield = DEFER;
	goto SEND_QUIT;
	}
      }
#endif

    /* Now check if the helo_data expansion went well, and sign off cleanly if
    it didn't. */

    if (helo_data == NULL)
      {
      uschar *message = string_sprintf("failed to expand helo_data: %s",
        expand_string_message);
      set_errno(addrlist, ERRNO_EXPANDFAIL, message, DEFER, FALSE, NULL);
      yield = DEFER;
      goto SEND_QUIT;
      }
    }

/** Debugging without sending a message
addrlist->transport_return = DEFER;
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

  esmtp = verify_check_given_host(&ob->hosts_avoid_esmtp, host) != OK;

  /* Alas; be careful, since this goto is not an error-out, so conceivably
  we might set data between here and the target which we assume to exist
  and be usable.  I can see this coming back to bite us. */
#ifdef SUPPORT_TLS
  if (smtps)
    {
    tls_offered = TRUE;
    suppress_tls = FALSE;
    ob->tls_tempfail_tryclear = FALSE;
    smtp_command = US"SSL-on-connect";
    goto TLS_NEGOTIATE;
    }
#endif

  if (esmtp)
    {
    if (smtp_write_command(&outblock, FALSE, "%s %s\r\n",
         lmtp? "LHLO" : "EHLO", helo_data) < 0)
      goto SEND_FAILED;
    if (!smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
           ob->command_timeout))
      {
      if (errno != 0 || buffer[0] == 0 || lmtp) goto RESPONSE_FAILED;
      esmtp = FALSE;
      }
    }
  else
    {
    DEBUG(D_transport)
      debug_printf("not sending EHLO (host matches hosts_avoid_esmtp)\n");
    }

  if (!esmtp)
    {
    if (smtp_write_command(&outblock, FALSE, "HELO %s\r\n", helo_data) < 0)
      goto SEND_FAILED;
    if (!smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
      ob->command_timeout)) goto RESPONSE_FAILED;
    }

  /* Set IGNOREQUOTA if the response to LHLO specifies support and the
  lmtp_ignore_quota option was set. */

  igquotstr = (lmtp && ob->lmtp_ignore_quota &&
    pcre_exec(regex_IGNOREQUOTA, NULL, CS buffer, Ustrlen(CS buffer), 0,
      PCRE_EOPT, NULL, 0) >= 0)? US" IGNOREQUOTA" : US"";

  /* Set tls_offered if the response to EHLO specifies support for STARTTLS. */

#ifdef SUPPORT_TLS
  tls_offered = esmtp &&
    pcre_exec(regex_STARTTLS, NULL, CS buffer, Ustrlen(buffer), 0,
      PCRE_EOPT, NULL, 0) >= 0;
#endif

#ifndef DISABLE_PRDR
  prdr_offered = esmtp
    && pcre_exec(regex_PRDR, NULL, CS buffer, Ustrlen(buffer), 0,
		  PCRE_EOPT, NULL, 0) >= 0
    && verify_check_given_host(&ob->hosts_try_prdr, host) == OK;

  if (prdr_offered)
    {DEBUG(D_transport) debug_printf("PRDR usable\n");}
#endif

#ifdef EXPERIMENTAL_INTERNATIONAL
  if (addrlist->prop.utf8_msg)
    {
    utf8_needed =  !addrlist->prop.utf8_downcvt
		&& !addrlist->prop.utf8_downcvt_maybe;
    DEBUG(D_transport) if (!utf8_needed) debug_printf("utf8: %s downconvert\n",
      addrlist->prop.utf8_downcvt ? "mandatory" : "optional");

    utf8_offered = esmtp
      && pcre_exec(regex_UTF8, NULL, CS buffer, Ustrlen(buffer), 0,
		    PCRE_EOPT, NULL, 0) >= 0;
    }
#endif
  }

/* For continuing deliveries down the same channel, the socket is the standard
input, and we don't need to redo EHLO here (but may need to do so for TLS - see
below). Set up the pointer to where subsequent commands will be left, for
error messages. Note that smtp_use_size and smtp_use_pipelining will have been
set from the command line if they were set in the process that passed the
connection on. */

else
  {
  inblock.sock = outblock.sock = fileno(stdin);
  smtp_command = big_buffer;
  host->port = port;    /* Record the port that was used */
  }

/* If TLS is available on this connection, whether continued or not, attempt to
start up a TLS session, unless the host is in hosts_avoid_tls. If successful,
send another EHLO - the server may give a different answer in secure mode. We
use a separate buffer for reading the response to STARTTLS so that if it is
negative, the original EHLO data is available for subsequent analysis, should
the client not be required to use TLS. If the response is bad, copy the buffer
for error analysis. */

#ifdef SUPPORT_TLS
if (  tls_offered
   && !suppress_tls
   && verify_check_given_host(&ob->hosts_avoid_tls, host) != OK)
  {
  uschar buffer2[4096];
  if (smtp_write_command(&outblock, FALSE, "STARTTLS\r\n") < 0)
    goto SEND_FAILED;

  /* If there is an I/O error, transmission of this message is deferred. If
  there is a temporary rejection of STARRTLS and tls_tempfail_tryclear is
  false, we also defer. However, if there is a temporary rejection of STARTTLS
  and tls_tempfail_tryclear is true, or if there is an outright rejection of
  STARTTLS, we carry on. This means we will try to send the message in clear,
  unless the host is in hosts_require_tls (tested below). */

  if (!smtp_read_response(&inblock, buffer2, sizeof(buffer2), '2',
      ob->command_timeout))
    {
    if (errno != 0 || buffer2[0] == 0 ||
         (buffer2[0] == '4' && !ob->tls_tempfail_tryclear))
      {
      Ustrncpy(buffer, buffer2, sizeof(buffer));
      goto RESPONSE_FAILED;
      }
    }

  /* STARTTLS accepted: try to negotiate a TLS session. */

  else
  TLS_NEGOTIATE:
    {
    int rc = tls_client_start(inblock.sock, host, addrlist, tblock
# ifdef EXPERIMENTAL_DANE
			     , dane ? &tlsa_dnsa : NULL
# endif
			     );

    /* TLS negotiation failed; give an error. From outside, this function may
    be called again to try in clear on a new connection, if the options permit
    it for this host. */

    if (rc != OK)
      {
# ifdef EXPERIMENTAL_DANE
      if (rc == DEFER && dane && !dane_required)
	{
	log_write(0, LOG_MAIN, "DANE attempt failed;"
	  " trying CA-root TLS to %s [%s] (not in hosts_require_dane)",
	  host->name, host->address);
	dane = FALSE;
	goto TLS_NEGOTIATE;
	}
# endif

      save_errno = ERRNO_TLSFAILURE;
      message = US"failure while setting up TLS session";
      send_quit = FALSE;
      goto TLS_FAILED;
      }

    /* TLS session is set up */

    for (addr = addrlist; addr != NULL; addr = addr->next)
      if (addr->transport_return == PENDING_DEFER)
        {
        addr->cipher = tls_out.cipher;
        addr->ourcert = tls_out.ourcert;
        addr->peercert = tls_out.peercert;
        addr->peerdn = tls_out.peerdn;
	addr->ocsp = tls_out.ocsp;
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

if (tls_out.active >= 0)
  {
  char *greeting_cmd;
  if (helo_data == NULL)
    {
    helo_data = expand_string(ob->helo_data);
    if (helo_data == NULL)
      {
      uschar *message = string_sprintf("failed to expand helo_data: %s",
        expand_string_message);
      set_errno(addrlist, ERRNO_EXPANDFAIL, message, DEFER, FALSE, NULL);
      yield = DEFER;
      goto SEND_QUIT;
      }
    }

  /* For SMTPS we need to wait for the initial OK response. */
  if (smtps)
    {
    if (!smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
      ob->command_timeout)) goto RESPONSE_FAILED;
    }

  if (esmtp)
    greeting_cmd = "EHLO";
  else
    {
    greeting_cmd = "HELO";
    DEBUG(D_transport)
      debug_printf("not sending EHLO (host matches hosts_avoid_esmtp)\n");
    }

  if (smtp_write_command(&outblock, FALSE, "%s %s\r\n",
        lmtp? "LHLO" : greeting_cmd, helo_data) < 0)
    goto SEND_FAILED;
  if (!smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
       ob->command_timeout))
    goto RESPONSE_FAILED;
  }

/* If the host is required to use a secure channel, ensure that we
have one. */

else if (
# ifdef EXPERIMENTAL_DANE
	dane ||
# endif
        verify_check_given_host(&ob->hosts_require_tls, host) == OK
	)
  {
  save_errno = ERRNO_TLSREQUIRED;
  message = string_sprintf("a TLS session is required, but %s",
    tls_offered? "an attempt to start TLS failed" :
                 "the server did not offer TLS support");
  goto TLS_FAILED;
  }
#endif	/*SUPPORT_TLS*/

/* If TLS is active, we have just started it up and re-done the EHLO command,
so its response needs to be analyzed. If TLS is not active and this is a
continued session down a previously-used socket, we haven't just done EHLO, so
we skip this. */

if (continue_hostname == NULL
#ifdef SUPPORT_TLS
    || tls_out.active >= 0
#endif
    )
  {
  /* Set for IGNOREQUOTA if the response to LHLO specifies support and the
  lmtp_ignore_quota option was set. */

  igquotstr = (lmtp && ob->lmtp_ignore_quota &&
    pcre_exec(regex_IGNOREQUOTA, NULL, CS buffer, Ustrlen(CS buffer), 0,
      PCRE_EOPT, NULL, 0) >= 0)? US" IGNOREQUOTA" : US"";

  /* If the response to EHLO specified support for the SIZE parameter, note
  this, provided size_addition is non-negative. */

  smtp_use_size = esmtp && ob->size_addition >= 0 &&
    pcre_exec(regex_SIZE, NULL, CS buffer, Ustrlen(CS buffer), 0,
      PCRE_EOPT, NULL, 0) >= 0;

  /* Note whether the server supports PIPELINING. If hosts_avoid_esmtp matched
  the current host, esmtp will be false, so PIPELINING can never be used. If
  the current host matches hosts_avoid_pipelining, don't do it. */

  smtp_use_pipelining = esmtp
    && verify_check_given_host(&ob->hosts_avoid_pipelining, host) != OK
    && pcre_exec(regex_PIPELINING, NULL, CS buffer, Ustrlen(CS buffer), 0,
		  PCRE_EOPT, NULL, 0) >= 0;

  DEBUG(D_transport) debug_printf("%susing PIPELINING\n",
    smtp_use_pipelining? "" : "not ");

#ifndef DISABLE_PRDR
  prdr_offered = esmtp
    && pcre_exec(regex_PRDR, NULL, CS buffer, Ustrlen(CS buffer), 0,
		  PCRE_EOPT, NULL, 0) >= 0
    && verify_check_given_host(&ob->hosts_try_prdr, host) == OK;

  if (prdr_offered)
    {DEBUG(D_transport) debug_printf("PRDR usable\n");}
#endif

#ifdef EXPERIMENTAL_INTERNATIONAL
  if (addrlist->prop.utf8_msg)
    utf8_offered = esmtp
      && pcre_exec(regex_UTF8, NULL, CS buffer, Ustrlen(buffer), 0,
		    PCRE_EOPT, NULL, 0) >= 0;
#endif

  /* Note if the server supports DSN */
  smtp_use_dsn = esmtp
    && pcre_exec(regex_DSN, NULL, CS buffer, Ustrlen(CS buffer), 0,
		  PCRE_EOPT, NULL, 0) >= 0;
  DEBUG(D_transport) debug_printf("use_dsn=%d\n", smtp_use_dsn);

  /* Note if the response to EHLO specifies support for the AUTH extension.
  If it has, check that this host is one we want to authenticate to, and do
  the business. The host name and address must be available when the
  authenticator's client driver is running. */

  switch (yield = smtp_auth(buffer, sizeof(buffer), addrlist, host,
			    ob, esmtp, &inblock, &outblock))
    {
    default:		goto SEND_QUIT;
    case OK:		break;
    case FAIL_SEND:	goto SEND_FAILED;
    case FAIL:		goto RESPONSE_FAILED;
    }
  }

/* The setting up of the SMTP call is now complete. Any subsequent errors are
message-specific. */

setting_up = FALSE;

#ifdef EXPERIMENTAL_INTERNATIONAL
/* If this is an international message we need the host to speak SMTPUTF8 */
if (utf8_needed && !utf8_offered)
  {
  errno = ERRNO_UTF8_FWD;
  goto RESPONSE_FAILED;
  }
#endif

/* If there is a filter command specified for this transport, we can now
set it up. This cannot be done until the identify of the host is known. */

if (tblock->filter_command != NULL)
  {
  BOOL rc;
  uschar buffer[64];
  sprintf(CS buffer, "%.50s transport", tblock->name);
  rc = transport_set_up_command(&transport_filter_argv, tblock->filter_command,
    TRUE, DEFER, addrlist, buffer, NULL);
  transport_filter_timeout = tblock->filter_timeout;

  /* On failure, copy the error to all addresses, abandon the SMTP call, and
  yield ERROR. */

  if (!rc)
    {
    set_errno(addrlist->next, addrlist->basic_errno, addrlist->message, DEFER,
      FALSE, NULL);
    yield = ERROR;
    goto SEND_QUIT;
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
sync_addr = first_addr;
address_count = 0;
ok = FALSE;
send_rset = TRUE;
completed_address = FALSE;


/* Initiate a message transfer. If we know the receiving MTA supports the SIZE
qualification, send it, adding something to the message size to allow for
imprecision and things that get added en route. Exim keeps the number of lines
in a message, so we can give an accurate value for the original message, but we
need some additional to handle added headers. (Double "." characters don't get
included in the count.) */

p = buffer;
*p = 0;

if (smtp_use_size)
  {
  sprintf(CS p, " SIZE=%d", message_size+message_linecount+ob->size_addition);
  while (*p) p++;
  }

#ifndef DISABLE_PRDR
prdr_active = FALSE;
if (prdr_offered)
  {
  for (addr = first_addr; addr; addr = addr->next)
    if (addr->transport_return == PENDING_DEFER)
      {
      for (addr = addr->next; addr; addr = addr->next)
        if (addr->transport_return == PENDING_DEFER)
	  {			/* at least two recipients to send */
	  prdr_active = TRUE;
	  sprintf(CS p, " PRDR"); p += 5;
	  break;
	  }
      break;
      }
  }
#endif

#ifdef EXPERIMENTAL_INTERNATIONAL
if (addrlist->prop.utf8_msg && !addrlist->prop.utf8_downcvt && utf8_offered)
  sprintf(CS p, " SMTPUTF8"), p += 9;
#endif

/* check if all addresses have lasthop flag */
/* do not send RET and ENVID if true */
for (dsn_all_lasthop = TRUE, addr = first_addr;
     address_count < max_rcpt && addr != NULL;
     addr = addr->next)
  if ((addr->dsn_flags & rf_dsnlasthop) != 1)
    {
    dsn_all_lasthop = FALSE;
    break;
    }

/* Add any DSN flags to the mail command */

if (smtp_use_dsn && !dsn_all_lasthop)
  {
  if (dsn_ret == dsn_ret_hdrs)
    {
    Ustrcpy(p, " RET=HDRS");
    while (*p) p++;
    }
  else if (dsn_ret == dsn_ret_full)
    {
    Ustrcpy(p, " RET=FULL");
    while (*p) p++;
    }
  if (dsn_envid != NULL)
    {
    string_format(p, sizeof(buffer) - (p-buffer), " ENVID=%s", dsn_envid);
    while (*p) p++;
    }
  }

/* If an authenticated_sender override has been specified for this transport
instance, expand it. If the expansion is forced to fail, and there was already
an authenticated_sender for this message, the original value will be used.
Other expansion failures are serious. An empty result is ignored, but there is
otherwise no check - this feature is expected to be used with LMTP and other
cases where non-standard addresses (e.g. without domains) might be required. */

if (smtp_mail_auth_str(p, sizeof(buffer) - (p-buffer), addrlist, ob))
  {
  yield = ERROR;
  goto SEND_QUIT;
  }

/* From here until we send the DATA command, we can make use of PIPELINING
if the server host supports it. The code has to be able to check the responses
at any point, for when the buffer fills up, so we write it totally generally.
When PIPELINING is off, each command written reports that it has flushed the
buffer. */

pending_MAIL = TRUE;     /* The block starts with MAIL */

  {
  uschar * s = return_path;
#ifdef EXPERIMENTAL_INTERNATIONAL
  uschar * errstr = NULL;

  /* If we must downconvert, do the from-address here.  Remember we had to
  for the to-addresses (done below), and also (ugly) for re-doing when building
  the delivery log line. */

  if (addrlist->prop.utf8_msg && (addrlist->prop.utf8_downcvt || !utf8_offered))
    {
    if (s = string_address_utf8_to_alabel(return_path, &errstr), errstr)
      {
      set_errno(addrlist, ERRNO_EXPANDFAIL, errstr, DEFER, FALSE, NULL);
      yield = ERROR;
      goto SEND_QUIT;
      }
    setflag(addrlist, af_utf8_downcvt);
    }
#endif

  rc = smtp_write_command(&outblock, smtp_use_pipelining,
	  "MAIL FROM:<%s>%s\r\n", s, buffer);
  }

mail_command = string_copy(big_buffer);  /* Save for later error message */

switch(rc)
  {
  case -1:                /* Transmission error */
    goto SEND_FAILED;

  case +1:                /* Block was sent */
    if (!smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
       ob->command_timeout))
      {
      if (errno == 0 && buffer[0] == '4')
	{
	errno = ERRNO_MAIL4XX;
	addrlist->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
	}
      goto RESPONSE_FAILED;
      }
    pending_MAIL = FALSE;
    break;
  }

/* Pass over all the relevant recipient addresses for this host, which are the
ones that have status PENDING_DEFER. If we are using PIPELINING, we can send
several before we have to read the responses for those seen so far. This
checking is done by a subroutine because it also needs to be done at the end.
Send only up to max_rcpt addresses at a time, leaving first_addr pointing to
the next one if not all are sent.

In the MUA wrapper situation, we want to flush the PIPELINING buffer for the
last address because we want to abort if any recipients have any kind of
problem, temporary or permanent. We know that all recipient addresses will have
the PENDING_DEFER status, because only one attempt is ever made, and we know
that max_rcpt will be large, so all addresses will be done at once. */

for (addr = first_addr;
     address_count < max_rcpt && addr != NULL;
     addr = addr->next)
  {
  int count;
  BOOL no_flush;
  uschar * rcpt_addr;

  addr->dsn_aware = smtp_use_dsn ? dsn_support_yes : dsn_support_no;

  if (addr->transport_return != PENDING_DEFER) continue;

  address_count++;
  no_flush = smtp_use_pipelining && (!mua_wrapper || addr->next != NULL);

  /* Add any DSN flags to the rcpt command and add to the sent string */

  p = buffer;
  *p = 0;

  if (smtp_use_dsn && (addr->dsn_flags & rf_dsnlasthop) != 1)
    {
    if ((addr->dsn_flags & rf_dsnflags) != 0)
      {
      int i;
      BOOL first = TRUE;
      Ustrcpy(p, " NOTIFY=");
      while (*p) p++;
      for (i = 0; i < 4; i++)
        if ((addr->dsn_flags & rf_list[i]) != 0)
          {
          if (!first) *p++ = ',';
          first = FALSE;
          Ustrcpy(p, rf_names[i]);
          while (*p) p++;
          }
      }

    if (addr->dsn_orcpt != NULL)
      {
      string_format(p, sizeof(buffer) - (p-buffer), " ORCPT=%s",
        addr->dsn_orcpt);
      while (*p) p++;
      }
    }

  /* Now send the RCPT command, and process outstanding responses when
  necessary. After a timeout on RCPT, we just end the function, leaving the
  yield as OK, because this error can often mean that there is a problem with
  just one address, so we don't want to delay the host. */

  rcpt_addr = transport_rcpt_address(addr, tblock->rcpt_include_affixes);

#ifdef EXPERIMENTAL_INTERNATIONAL
  {
  uschar * dummy_errstr;
  if (  testflag(addrlist, af_utf8_downcvt)
     && (rcpt_addr = string_address_utf8_to_alabel(rcpt_addr, &dummy_errstr),
	 dummy_errstr
     )  )
    {
    errno = ERRNO_EXPANDFAIL;
    goto SEND_FAILED;
    }
  }
#endif

  count = smtp_write_command(&outblock, no_flush, "RCPT TO:<%s>%s%s\r\n",
    rcpt_addr, igquotstr, buffer);

  if (count < 0) goto SEND_FAILED;
  if (count > 0)
    {
    switch(sync_responses(first_addr, tblock->rcpt_include_affixes,
             &sync_addr, host, count, ob->address_retry_include_sender,
             pending_MAIL, 0, &inblock, ob->command_timeout, buffer,
             sizeof(buffer)))
      {
      case 3: ok = TRUE;                   /* 2xx & 5xx => OK & progress made */
      case 2: completed_address = TRUE;    /* 5xx (only) => progress made */
      break;

      case 1: ok = TRUE;                   /* 2xx (only) => OK, but if LMTP, */
      if (!lmtp) completed_address = TRUE; /* can't tell about progress yet */
      case 0:                              /* No 2xx or 5xx, but no probs */
      break;

      case -1: goto END_OFF;               /* Timeout on RCPT */
      default: goto RESPONSE_FAILED;       /* I/O error, or any MAIL error */
      }
    pending_MAIL = FALSE;                  /* Dealt with MAIL */
    }
  }      /* Loop for next address */

/* If we are an MUA wrapper, abort if any RCPTs were rejected, either
permanently or temporarily. We should have flushed and synced after the last
RCPT. */

if (mua_wrapper)
  {
  address_item *badaddr;
  for (badaddr = first_addr; badaddr; badaddr = badaddr->next)
    if (badaddr->transport_return != PENDING_OK)
      {
      /*XXX could we find a better errno than 0 here? */
      set_errno(addrlist, 0, badaddr->message, FAIL,
	testflag(badaddr, af_pass_message), NULL);
      ok = FALSE;
      break;
      }
  }

/* If ok is TRUE, we know we have got at least one good recipient, and must now
send DATA, but if it is FALSE (in the normal, non-wrapper case), we may still
have a good recipient buffered up if we are pipelining. We don't want to waste
time sending DATA needlessly, so we only send it if either ok is TRUE or if we
are pipelining. The responses are all handled by sync_responses(). */

if (ok || (smtp_use_pipelining && !mua_wrapper))
  {
  int count = smtp_write_command(&outblock, FALSE, "DATA\r\n");
  if (count < 0) goto SEND_FAILED;
  switch(sync_responses(first_addr, tblock->rcpt_include_affixes, &sync_addr,
           host, count, ob->address_retry_include_sender, pending_MAIL,
           ok? +1 : -1, &inblock, ob->command_timeout, buffer, sizeof(buffer)))
    {
    case 3: ok = TRUE;                   /* 2xx & 5xx => OK & progress made */
    case 2: completed_address = TRUE;    /* 5xx (only) => progress made */
    break;

    case 1: ok = TRUE;                   /* 2xx (only) => OK, but if LMTP, */
    if (!lmtp) completed_address = TRUE; /* can't tell about progress yet */
    case 0: break;                       /* No 2xx or 5xx, but no probs */

    case -1: goto END_OFF;               /* Timeout on RCPT */
    default: goto RESPONSE_FAILED;       /* I/O error, or any MAIL/DATA error */
    }
  }

/* Save the first address of the next batch. */

first_addr = addr;

/* If there were no good recipients (but otherwise there have been no
problems), just set ok TRUE, since we have handled address-specific errors
already. Otherwise, it's OK to send the message. Use the check/escape mechanism
for handling the SMTP dot-handling protocol, flagging to apply to headers as
well as body. Set the appropriate timeout value to be used for each chunk.
(Haven't been able to make it work using select() for writing yet.) */

if (!ok) ok = TRUE; else
  {
  sigalrm_seen = FALSE;
  transport_write_timeout = ob->data_timeout;
  smtp_command = US"sending data block";   /* For error messages */
  DEBUG(D_transport|D_v)
    debug_printf("  SMTP>> writing message and terminating \".\"\n");
  transport_count = 0;

#ifndef DISABLE_DKIM
  ok = dkim_transport_write_message(addrlist, inblock.sock,
    topt_use_crlf | topt_end_dot | topt_escape_headers |
      (tblock->body_only? topt_no_headers : 0) |
      (tblock->headers_only? topt_no_body : 0) |
      (tblock->return_path_add? topt_add_return_path : 0) |
      (tblock->delivery_date_add? topt_add_delivery_date : 0) |
      (tblock->envelope_to_add? topt_add_envelope_to : 0),
    0,            /* No size limit */
    tblock->add_headers, tblock->remove_headers,
    US".", US"..",    /* Escaping strings */
    tblock->rewrite_rules, tblock->rewrite_existflags,
    ob->dkim_private_key, ob->dkim_domain, ob->dkim_selector,
    ob->dkim_canon, ob->dkim_strict, ob->dkim_sign_headers
    );
#else
  ok = transport_write_message(addrlist, inblock.sock,
    topt_use_crlf | topt_end_dot | topt_escape_headers |
      (tblock->body_only? topt_no_headers : 0) |
      (tblock->headers_only? topt_no_body : 0) |
      (tblock->return_path_add? topt_add_return_path : 0) |
      (tblock->delivery_date_add? topt_add_delivery_date : 0) |
      (tblock->envelope_to_add? topt_add_envelope_to : 0),
    0,            /* No size limit */
    tblock->add_headers, tblock->remove_headers,
    US".", US"..",    /* Escaping strings */
    tblock->rewrite_rules, tblock->rewrite_existflags);
#endif

  /* transport_write_message() uses write() because it is called from other
  places to write to non-sockets. This means that under some OS (e.g. Solaris)
  it can exit with "Broken pipe" as its error. This really means that the
  socket got closed at the far end. */

  transport_write_timeout = 0;   /* for subsequent transports */

  /* Failure can either be some kind of I/O disaster (including timeout),
  or the failure of a transport filter or the expansion of added headers. */

  if (!ok)
    {
    buffer[0] = 0;              /* There hasn't been a response */
    goto RESPONSE_FAILED;
    }

  /* We used to send the terminating "." explicitly here, but because of
  buffering effects at both ends of TCP/IP connections, you don't gain
  anything by keeping it separate, so it might as well go in the final
  data buffer for efficiency. This is now done by setting the topt_end_dot
  flag above. */

  smtp_command = US"end of data";

#ifndef DISABLE_PRDR
  /* For PRDR we optionally get a partial-responses warning
   * followed by the individual responses, before going on with
   * the overall response.  If we don't get the warning then deal
   * with per non-PRDR. */
  if(prdr_active)
    {
    ok = smtp_read_response(&inblock, buffer, sizeof(buffer), '3',
      ob->final_timeout);
    if (!ok && errno == 0)
      switch(buffer[0])
        {
	case '2': prdr_active = FALSE;
	          ok = TRUE;
		  break;
	case '4': errno = ERRNO_DATA4XX;
                  addrlist->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
		  break;
        }
    }
  else
#endif

  /* For non-PRDR SMTP, we now read a single response that applies to the
  whole message.  If it is OK, then all the addresses have been delivered. */

  if (!lmtp)
    {
    ok = smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
      ob->final_timeout);
    if (!ok && errno == 0 && buffer[0] == '4')
      {
      errno = ERRNO_DATA4XX;
      addrlist->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
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

  if (ok)
    {
    int flag = '=';
    int delivery_time = (int)(time(NULL) - start_delivery_time);
    int len;
    uschar *conf = NULL;
    send_rset = FALSE;

    /* Set up confirmation if needed - applies only to SMTP */

    if (
#ifndef EXPERIMENTAL_EVENT
          (log_extra_selector & LX_smtp_confirmation) != 0 &&
#endif
          !lmtp
       )
      {
      const uschar *s = string_printing(buffer);
      /* deconst cast ok here as string_printing was checked to have alloc'n'copied */
      conf = (s == buffer)? (uschar *)string_copy(s) : US s;
      }

    /* Process all transported addresses - for LMTP or PRDR, read a status for
    each one. */

    for (addr = addrlist; addr != first_addr; addr = addr->next)
      {
      if (addr->transport_return != PENDING_OK) continue;

      /* LMTP - if the response fails badly (e.g. timeout), use it for all the
      remaining addresses. Otherwise, it's a return code for just the one
      address. For temporary errors, add a retry item for the address so that
      it doesn't get tried again too soon. */

#ifndef DISABLE_PRDR
      if (lmtp || prdr_active)
#else
      if (lmtp)
#endif
        {
        if (!smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
            ob->final_timeout))
          {
          if (errno != 0 || buffer[0] == 0) goto RESPONSE_FAILED;
          addr->message = string_sprintf(
#ifndef DISABLE_PRDR
	    "%s error after %s: %s", prdr_active ? "PRDR":"LMTP",
#else
	    "LMTP error after %s: %s",
#endif
            big_buffer, string_printing(buffer));
          setflag(addr, af_pass_message);   /* Allow message to go to user */
          if (buffer[0] == '5')
            addr->transport_return = FAIL;
          else
            {
            errno = ERRNO_DATA4XX;
            addr->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
            addr->transport_return = DEFER;
#ifndef DISABLE_PRDR
            if (!prdr_active)
#endif
              retry_add_item(addr, addr->address_retry_key, 0);
            }
          continue;
          }
        completed_address = TRUE;   /* NOW we can set this flag */
        if ((log_extra_selector & LX_smtp_confirmation) != 0)
          {
          const uschar *s = string_printing(buffer);
	  /* deconst cast ok here as string_printing was checked to have alloc'n'copied */
          conf = (s == buffer)? (uschar *)string_copy(s) : US s;
          }
        }

      /* SMTP, or success return from LMTP for this address. Pass back the
      actual host that was used. */

      addr->transport_return = OK;
      addr->more_errno = delivery_time;
      addr->host_used = host;
      addr->special_action = flag;
      addr->message = conf;
#ifndef DISABLE_PRDR
      if (prdr_active) addr->flags |= af_prdr_used;
#endif
      flag = '-';

#ifndef DISABLE_PRDR
      if (!prdr_active)
#endif
        {
        /* Update the journal. For homonymic addresses, use the base address plus
        the transport name. See lots of comments in deliver.c about the reasons
        for the complications when homonyms are involved. Just carry on after
        write error, as it may prove possible to update the spool file later. */

        if (testflag(addr, af_homonym))
          sprintf(CS buffer, "%.500s/%s\n", addr->unique + 3, tblock->name);
        else
          sprintf(CS buffer, "%.500s\n", addr->unique);

        DEBUG(D_deliver) debug_printf("journalling %s", buffer);
        len = Ustrlen(CS buffer);
        if (write(journal_fd, buffer, len) != len)
          log_write(0, LOG_MAIN|LOG_PANIC, "failed to write journal for "
            "%s: %s", buffer, strerror(errno));
        }
      }

#ifndef DISABLE_PRDR
      if (prdr_active)
        {
	/* PRDR - get the final, overall response.  For any non-success
	upgrade all the address statuses. */
        ok = smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
          ob->final_timeout);
        if (!ok)
	  {
	  if(errno == 0 && buffer[0] == '4')
            {
            errno = ERRNO_DATA4XX;
            addrlist->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
            }
	  for (addr = addrlist; addr != first_addr; addr = addr->next)
            if (buffer[0] == '5' || addr->transport_return == OK)
              addr->transport_return = PENDING_OK; /* allow set_errno action */
	  goto RESPONSE_FAILED;
	  }

	/* Update the journal, or setup retry. */
        for (addr = addrlist; addr != first_addr; addr = addr->next)
	  if (addr->transport_return == OK)
	  {
          if (testflag(addr, af_homonym))
            sprintf(CS buffer, "%.500s/%s\n", addr->unique + 3, tblock->name);
          else
            sprintf(CS buffer, "%.500s\n", addr->unique);

          DEBUG(D_deliver) debug_printf("journalling(PRDR) %s", buffer);
          len = Ustrlen(CS buffer);
          if (write(journal_fd, buffer, len) != len)
            log_write(0, LOG_MAIN|LOG_PANIC, "failed to write journal for "
              "%s: %s", buffer, strerror(errno));
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

if (!ok)
  {
  int code;

  RESPONSE_FAILED:
  save_errno = errno;
  message = NULL;
  send_quit = check_response(host, &save_errno, addrlist->more_errno,
    buffer, &code, &message, &pass_message);
  goto FAILED;

  SEND_FAILED:
  save_errno = errno;
  code = '4';
  message = US string_sprintf("send() to %s [%s] failed: %s",
    host->name, host->address, strerror(save_errno));
  send_quit = FALSE;
  goto FAILED;

  /* This label is jumped to directly when a TLS negotiation has failed,
  or was not done for a host for which it is required. Values will be set
  in message and save_errno, and setting_up will always be true. Treat as
  a temporary error. */

#ifdef SUPPORT_TLS
  TLS_FAILED:
  code = '4';
#endif

  /* If the failure happened while setting up the call, see if the failure was
  a 5xx response (this will either be on connection, or following HELO - a 5xx
  after EHLO causes it to try HELO). If so, fail all addresses, as this host is
  never going to accept them. For other errors during setting up (timeouts or
  whatever), defer all addresses, and yield DEFER, so that the host is not
  tried again for a while. */

  FAILED:
  ok = FALSE;                /* For when reached by GOTO */

  if (setting_up)
    {
    if (code == '5')
      set_errno(addrlist, save_errno, message, FAIL, pass_message, host);
    else
      {
      set_errno(addrlist, save_errno, message, DEFER, pass_message, host);
      yield = DEFER;
      }
    }

  /* We want to handle timeouts after MAIL or "." and loss of connection after
  "." specially. They can indicate a problem with the sender address or with
  the contents of the message rather than a real error on the connection. These
  cases are treated in the same way as a 4xx response. This next bit of code
  does the classification. */

  else
    {
    BOOL message_error;

    switch(save_errno)
      {
#ifdef EXPERIMENTAL_INTERNATIONAL
      case ERRNO_UTF8_FWD:
        code = '5';
      /*FALLTHROUGH*/
#endif
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
      set_errno(addrlist, save_errno, message, (code == '5')? FAIL : DEFER,
        pass_message, host);

      /* If there's an errno, the message contains just the identity of
      the host. */

      if (code != '5')     /* Anything other than 5 is treated as temporary */
        {
        if (save_errno > 0)
          message = US string_sprintf("%s: %s", message, strerror(save_errno));
        if (host->next != NULL) log_write(0, LOG_MAIN, "%s", message);
	msglog_line(host, message);
        *message_defer = TRUE;
        }
      }

    /* Otherwise, we have an I/O error or a timeout other than after MAIL or
    ".", or some other transportation error. We defer all addresses and yield
    DEFER, except for the case of failed add_headers expansion, or a transport
    filter failure, when the yield should be ERROR, to stop it trying other
    hosts. */

    else
      {
      yield = (save_errno == ERRNO_CHHEADER_FAIL ||
               save_errno == ERRNO_FILTER_FAIL)? ERROR : DEFER;
      set_errno(addrlist, save_errno, message, DEFER, pass_message, host);
      }
    }
  }


/* If all has gone well, send_quit will be set TRUE, implying we can end the
SMTP session tidily. However, if there were too many addresses to send in one
message (indicated by first_addr being non-NULL) we want to carry on with the
rest of them. Also, it is desirable to send more than one message down the SMTP
connection if there are several waiting, provided we haven't already sent so
many as to hit the configured limit. The function transport_check_waiting looks
for a waiting message and returns its id. Then transport_pass_socket tries to
set up a continued delivery by passing the socket on to another process. The
variable send_rset is FALSE if a message has just been successfully transfered.

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
    "yield=%d first_address is %sNULL\n", ok, send_quit, send_rset,
    continue_more, yield, (first_addr == NULL)? "":"not ");

if (completed_address && ok && send_quit)
  {
  BOOL more;
  smtp_compare_t t_compare;

  t_compare.tblock = tblock;
  t_compare.current_sender_address = sender_address;

  if (  first_addr != NULL
     || continue_more
     || (  (  tls_out.active < 0
           || verify_check_given_host(&ob->hosts_nopass_tls, host) != OK
	   )
        &&
           transport_check_waiting(tblock->name, host->name,
             tblock->connection_max_messages, new_message_id, &more,
	     (oicf)smtp_are_same_identities, (void*)&t_compare)
     )  )
    {
    uschar *msg;
    BOOL pass_message;

    if (send_rset)
      {
      if (! (ok = smtp_write_command(&outblock, FALSE, "RSET\r\n") >= 0))
        {
        msg = US string_sprintf("send() to %s [%s] failed: %s", host->name,
          host->address, strerror(save_errno));
        send_quit = FALSE;
        }
      else if (! (ok = smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
                  ob->command_timeout)))
        {
        int code;
        send_quit = check_response(host, &errno, 0, buffer, &code, &msg,
          &pass_message);
        if (!send_quit)
          {
          DEBUG(D_transport) debug_printf("H=%s [%s] %s\n",
	    host->name, host->address, msg);
          }
        }
      }

    /* Either RSET was not needed, or it succeeded */

    if (ok)
      {
      if (first_addr != NULL)            /* More addresses still to be sent */
        {                                /*   in this run of the transport */
        continue_sequence++;             /* Causes * in logging */
        goto SEND_MESSAGE;
        }
      if (continue_more) return yield;   /* More addresses for another run */

      /* Pass the socket to a new Exim process. Before doing so, we must shut
      down TLS. Not all MTAs allow for the continuation of the SMTP session
      when TLS is shut down. We test for this by sending a new EHLO. If we
      don't get a good response, we don't attempt to pass the socket on. */

#ifdef SUPPORT_TLS
      if (tls_out.active >= 0)
        {
        tls_close(FALSE, TRUE);
        if (smtps)
          ok = FALSE;
        else
          ok = smtp_write_command(&outblock,FALSE,"EHLO %s\r\n",helo_data) >= 0 &&
               smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
                 ob->command_timeout);
        }
#endif

      /* If the socket is successfully passed, we musn't send QUIT (or
      indeed anything!) from here. */

      if (ok && transport_pass_socket(tblock->name, host->name, host->address,
            new_message_id, inblock.sock))
        {
        send_quit = FALSE;
        }
      }

    /* If RSET failed and there are addresses left, they get deferred. */

    else set_errno(first_addr, errno, msg, DEFER, FALSE, host);
    }
  }

/* End off tidily with QUIT unless the connection has died or the socket has
been passed to another process. There has been discussion on the net about what
to do after sending QUIT. The wording of the RFC suggests that it is necessary
to wait for a response, but on the other hand, there isn't anything one can do
with an error response, other than log it. Exim used to do that. However,
further discussion suggested that it is positively advantageous not to wait for
the response, but to close the session immediately. This is supposed to move
the TCP/IP TIME_WAIT state from the server to the client, thereby removing some
load from the server. (Hosts that are both servers and clients may not see much
difference, of course.) Further discussion indicated that this was safe to do
on Unix systems which have decent implementations of TCP/IP that leave the
connection around for a while (TIME_WAIT) after the application has gone away.
This enables the response sent by the server to be properly ACKed rather than
timed out, as can happen on broken TCP/IP implementations on other OS.

This change is being made on 31-Jul-98. After over a year of trouble-free
operation, the old commented-out code was removed on 17-Sep-99. */

SEND_QUIT:
if (send_quit) (void)smtp_write_command(&outblock, FALSE, "QUIT\r\n");

END_OFF:

#ifdef SUPPORT_TLS
tls_close(FALSE, TRUE);
#endif

/* Close the socket, and return the appropriate value, first setting
works because the NULL setting is passed back to the calling process, and
remote_max_parallel is forced to 1 when delivering over an existing connection,

If all went well and continue_more is set, we shouldn't actually get here if
there are further addresses, as the return above will be taken. However,
writing RSET might have failed, or there may be other addresses whose hosts are
specified in the transports, and therefore not visible at top level, in which
case continue_more won't get set. */

(void)close(inblock.sock);

#ifdef EXPERIMENTAL_EVENT
(void) event_raise(tblock->event_action, US"tcp:close", NULL);
#endif

continue_transport = NULL;
continue_hostname = NULL;
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
smtp_transport_options_block *ob =
  (smtp_transport_options_block *)(tblock->options_block);
smtp_inblock inblock;
smtp_outblock outblock;
uschar buffer[256];
uschar inbuffer[4096];
uschar outbuffer[16];

inblock.sock = fileno(stdin);
inblock.buffer = inbuffer;
inblock.buffersize = sizeof(inbuffer);
inblock.ptr = inbuffer;
inblock.ptrend = inbuffer;

outblock.sock = inblock.sock;
outblock.buffersize = sizeof(outbuffer);
outblock.buffer = outbuffer;
outblock.ptr = outbuffer;
outblock.cmd_count = 0;
outblock.authenticating = FALSE;

(void)smtp_write_command(&outblock, FALSE, "QUIT\r\n");
(void)smtp_read_response(&inblock, buffer, sizeof(buffer), '2',
  ob->command_timeout);
(void)close(inblock.sock);
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
address_item *addr;
for (addr = addrlist; addr != NULL; addr = addr->next)
  if (addr->transport_return == DEFER)
    {
    if (first_addr == NULL) first_addr = addr;
    addr->transport_return = PENDING_DEFER;
    addr->basic_errno = 0;
    addr->more_errno = (host->mx >= 0)? 'M' : 'A';
    addr->message = NULL;
#ifdef SUPPORT_TLS
    addr->cipher = NULL;
    addr->ourcert = NULL;
    addr->peercert = NULL;
    addr->peerdn = NULL;
    addr->ocsp = OCSP_NOT_REQ;
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
int cutoff_retry;
int port;
int hosts_defer = 0;
int hosts_fail  = 0;
int hosts_looked_up = 0;
int hosts_retry = 0;
int hosts_serial = 0;
int hosts_total = 0;
int total_hosts_tried = 0;
address_item *addr;
BOOL expired = TRUE;
BOOL continuing = continue_hostname != NULL;
uschar *expanded_hosts = NULL;
uschar *pistring;
uschar *tid = string_sprintf("%s transport", tblock->name);
smtp_transport_options_block *ob =
  (smtp_transport_options_block *)(tblock->options_block);
host_item *hostlist = addrlist->host_list;
host_item *host = NULL;

DEBUG(D_transport)
  {
  debug_printf("%s transport entered\n", tblock->name);
  for (addr = addrlist; addr != NULL; addr = addr->next)
    debug_printf("  %s\n", addr->address);
  if (continuing) debug_printf("already connected to %s [%s]\n",
      continue_hostname, continue_host_address);
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

if (hostlist == NULL || (ob->hosts_override && ob->hosts != NULL))
  {
  if (ob->hosts == NULL)
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

  if (ob->hostlist == NULL)
    {
    uschar *s = ob->hosts;

    if (Ustrchr(s, '$') != NULL)
      {
      if (!(expanded_hosts = expand_string(s)))
        {
        addrlist->message = string_sprintf("failed to expand list of hosts "
          "\"%s\" in %s transport: %s", s, tblock->name, expand_string_message);
        addrlist->transport_return = search_find_defer? DEFER : PANIC;
        return FALSE;     /* Only top address has status */
        }
      DEBUG(D_transport) debug_printf("expanded list of hosts \"%s\" to "
        "\"%s\"\n", s, expanded_hosts);
      s = expanded_hosts;
      }
    else
      if (ob->hosts_randomize) s = expanded_hosts = string_copy(s);

    host_build_hostlist(&hostlist, s, ob->hosts_randomize);

    /* Check that the expansion yielded something useful. */
    if (hostlist == NULL)
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

else if (ob->hosts_randomize && hostlist->mx == MX_NONE && !continuing)
  {
  host_item *newlist = NULL;
  while (hostlist != NULL)
    {
    host_item *h = hostlist;
    hostlist = hostlist->next;

    h->sort_key = random_number(100);

    if (newlist == NULL)
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
      while (hh->next != NULL)
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

if (!smtp_get_port(ob->port, addrlist, &port, tid)) return FALSE;

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

for (cutoff_retry = 0; expired &&
     cutoff_retry < ((ob->delay_after_cutoff)? 1 : 2);
     cutoff_retry++)
  {
  host_item *nexthost = NULL;
  int unexpired_hosts_tried = 0;

  for (host = hostlist;
       host != NULL &&
         unexpired_hosts_tried < ob->hosts_max_try &&
         total_hosts_tried < ob->hosts_max_try_hardlimit;
       host = nexthost)
    {
    int rc;
    int host_af;
    uschar *rs;
    BOOL serialized = FALSE;
    BOOL host_is_expired = FALSE;
    BOOL message_defer = FALSE;
    BOOL ifchanges = FALSE;
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

    if (host->address == NULL)
      {
      int new_port, flags;
      host_item *hh;

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

      flags = HOST_FIND_BY_A;
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

      for (hh = host; hh != nexthost; hh = hh->next) hh->port = new_port;

      /* Failure to find the host at this time (usually DNS temporary failure)
      is really a kind of routing failure rather than a transport failure.
      Therefore we add a retry item of the routing kind, not to stop us trying
      to look this name up here again, but to ensure the address gets timed
      out if the failures go on long enough. A complete failure at this point
      commonly points to a configuration error, but the best action is still
      to carry on for the next host. */

      if (rc == HOST_FIND_AGAIN || rc == HOST_FIND_FAILED)
        {
        retry_add_item(addrlist, string_sprintf("R:%s", host->name), 0);
        expired = FALSE;
        if (rc == HOST_FIND_AGAIN) hosts_defer++; else hosts_fail++;
        DEBUG(D_transport) debug_printf("rc = %s for %s\n", (rc == HOST_FIND_AGAIN)?
          "HOST_FIND_AGAIN" : "HOST_FIND_FAILED", host->name);
        host->status = hstatus_unusable;

        for (addr = addrlist; addr != NULL; addr = addr->next)
          {
          if (addr->transport_return != DEFER) continue;
          addr->basic_errno = ERRNO_UNKNOWNHOST;
          addr->message =
            string_sprintf("failed to lookup IP address for %s", host->name);
          }
        continue;
        }

      /* If the host is actually the local host, we may have a problem, or
      there may be some cunning configuration going on. In the problem case,
      log things and give up. The default transport status is already DEFER. */

      if (rc == HOST_FOUND_LOCAL && !ob->allow_localhost)
        {
        for (addr = addrlist; addr != NULL; addr = addr->next)
          {
          addr->basic_errno = 0;
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

    if (continuing && (Ustrcmp(continue_hostname, host->name) != 0 ||
                       Ustrcmp(continue_host_address, host->address) != 0))
      {
      expired = FALSE;
      continue;      /* With next host */
      }

    /* Reset the default next host in case a multihomed host whose addresses
    are not looked up till just above added to the host list. */

    nexthost = host->next;

    /* If queue_smtp is set (-odqs or the first part of a 2-stage run), or the
    domain is in queue_smtp_domains, we don't actually want to attempt any
    deliveries. When doing a queue run, queue_smtp_domains is always unset. If
    there is a lookup defer in queue_smtp_domains, proceed as if the domain
    were not in it. We don't want to hold up all SMTP deliveries! Except when
    doing a two-stage queue run, don't do this if forcing. */

    if ((!deliver_force || queue_2stage) && (queue_smtp ||
        match_isinlist(addrlist->domain,
	  (const uschar **)&queue_smtp_domains, 0,
          &domainlist_anchor, NULL, MCL_DOMAIN, TRUE, NULL) == OK))
      {
      expired = FALSE;
      for (addr = addrlist; addr != NULL; addr = addr->next)
        {
        if (addr->transport_return != DEFER) continue;
        addr->message = US"domain matches queue_smtp_domains, or -odqs set";
        }
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

    pistring = string_sprintf(":%d", (host->port == PORT_NONE)?
      port : host->port);
    if (Ustrcmp(pistring, ":25") == 0) pistring = US"";

    /* Select IPv4 or IPv6, and choose an outgoing interface. If the interface
    string changes upon expansion, we must add it to the key that is used for
    retries, because connections to the same host from a different interface
    should be treated separately. */

    host_af = (Ustrchr(host->address, ':') == NULL)? AF_INET : AF_INET6;
    if (!smtp_get_interface(ob->interface, host_af, addrlist, &ifchanges,
         &interface, tid))
      return FALSE;
    if (ifchanges) pistring = string_sprintf("%s/%s", pistring, interface);

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

      DEBUG(D_transport) debug_printf("%s [%s]%s status = %s\n", host->name,
        (host->address == NULL)? US"" : host->address, pistring,
        (host->status == hstatus_usable)? "usable" :
        (host->status == hstatus_unusable)? "unusable" :
        (host->status == hstatus_unusable_expired)? "unusable (expired)" : "?");

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
          case hwhy_deferred: hosts_defer++; break;
          }

        /* If there was a retry message key, implying that previously there
        was a message-specific defer, we don't want to update the list of
        messages waiting for these hosts. */

        if (retry_message_key != NULL) update_waiting = FALSE;
        continue;   /* With the next host or IP address */
        }
      }

    /* Second time round the loop: if the address is set but expired, and
    the message is newer than the last try, let it through. */

    else
      {
      if (host->address == NULL ||
          host->status != hstatus_unusable_expired ||
          host->last_try > received_time)
        continue;
      DEBUG(D_transport)
        debug_printf("trying expired host %s [%s]%s\n",
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

    if (!continuing &&
        verify_check_given_host(&ob->serialize_hosts, host) == OK)
      {
      serialize_key = string_sprintf("host-serialize-%s", host->name);
      if (!enq_start(serialize_key))
        {
        DEBUG(D_transport)
          debug_printf("skipping host %s because another Exim process "
            "is connected to it\n", host->name);
        hosts_serial++;
        continue;
        }
      serialized = TRUE;
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
      (addrlist->next == NULL)? "" : ", ...");

    set_process_info("delivering %s to %s [%s] (%s%s)",
      message_id, host->name, host->address, addrlist->address,
      (addrlist->next == NULL)? "" : ", ...");

    /* This is not for real; don't do the delivery. If there are
    any remaining hosts, list them. */

    if (dont_deliver)
      {
      host_item *host2;
      set_errno(addrlist, 0, NULL, OK, FALSE, NULL);
      for (addr = addrlist; addr != NULL; addr = addr->next)
        {
        addr->host_used = host;
        addr->special_action = '*';
        addr->message = US"delivery bypassed by -N option";
        }
      DEBUG(D_transport)
        {
        debug_printf("*** delivery by %s transport bypassed by -N option\n"
                     "*** host and remaining hosts:\n", tblock->name);
        for (host2 = host; host2 != NULL; host2 = host2->next)
          debug_printf("    %s [%s]\n", host2->name,
            (host2->address == NULL)? US"unset" : host2->address);
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
	thost = store_get(sizeof(host_item));
	*thost = *host;
	thost->name = string_copy(host->name);
	thost->address = string_copy(host->address);
	}
      else
        thost = host;

      if (!host_is_expired && ++unexpired_hosts_tried >= ob->hosts_max_try)
        {
        host_item *h;
        DEBUG(D_transport)
          debug_printf("hosts_max_try limit reached with this host\n");
        for (h = host; h != NULL; h = h->next)
          if (h->mx != host->mx) break;
        if (h != NULL)
          {
          nexthost = h;
          unexpired_hosts_tried--;
          DEBUG(D_transport) debug_printf("however, a higher MX host exists "
            "and will be tried\n");
          }
        }

      /* Attempt the delivery. */

      total_hosts_tried++;
      rc = smtp_deliver(addrlist, thost, host_af, port, interface, tblock,
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

      if (rc == DEFER && first_addr->basic_errno != ERRNO_AUTHFAIL &&
                         first_addr->basic_errno != ERRNO_TLSFAILURE)
        write_logs(first_addr, host);

#ifdef EXPERIMENTAL_EVENT
      if (rc == DEFER)
        deferred_event_raise(first_addr, host);
#endif

      /* If STARTTLS was accepted, but there was a failure in setting up the
      TLS session (usually a certificate screwup), and the host is not in
      hosts_require_tls, and tls_tempfail_tryclear is true, try again, with
      TLS forcibly turned off. We have to start from scratch with a new SMTP
      connection. That's why the retry is done from here, not from within
      smtp_deliver(). [Rejections of STARTTLS itself don't screw up the
      session, so the in-clear transmission after those errors, if permitted,
      happens inside smtp_deliver().] */

#ifdef SUPPORT_TLS
      if (  rc == DEFER
	 && first_addr->basic_errno == ERRNO_TLSFAILURE
	 && ob->tls_tempfail_tryclear
	 && verify_check_given_host(&ob->hosts_require_tls, host) != OK
	 )
        {
        log_write(0, LOG_MAIN, "TLS session failure: delivering unencrypted "
          "to %s [%s] (not in hosts_require_tls)", host->name, host->address);
        first_addr = prepare_addresses(addrlist, host);
        rc = smtp_deliver(addrlist, thost, host_af, port, interface, tblock,
          &message_defer, TRUE);
        if (rc == DEFER && first_addr->basic_errno != ERRNO_AUTHFAIL)
          write_logs(first_addr, host);
# ifdef EXPERIMENTAL_EVENT
        if (rc == DEFER)
          deferred_event_raise(first_addr, host);
# endif
        }
#endif	/*SUPPORT_TLS*/
      }

    /* Delivery attempt finished */

    rs = (rc == OK)? US"OK" : (rc == DEFER)? US"DEFER" : (rc == ERROR)?
      US"ERROR" : US"?";

    set_process_info("delivering %s: just tried %s [%s] for %s%s: result %s",
      message_id, host->name, host->address, addrlist->address,
      (addrlist->next == NULL)? "" : " (& others)", rs);

    /* Release serialization if set up */

    if (serialized) enq_end(serialize_key);

    /* If the result is DEFER, or if a host retry record is known to exist, we
    need to add an item to the retry chain for updating the retry database
    at the end of delivery. We only need to add the item to the top address,
    of course. Also, if DEFER, we mark the IP address unusable so as to skip it
    for any other delivery attempts using the same address. (It is copied into
    the unusable tree at the outer level, so even if different address blocks
    contain the same address, it still won't get tried again.) */

    if (rc == DEFER || retry_host_key != NULL)
      {
      int delete_flag = (rc != DEFER)? rf_delete : 0;
      if (retry_host_key == NULL)
        {
	BOOL incl_ip;
	if (exp_bool(addrlist, US"transport", tblock->name, D_transport,
		  US"retry_include_ip_address", ob->retry_include_ip_address,
		  ob->expand_retry_include_ip_address, &incl_ip) != OK)
	  incl_ip = TRUE;	/* error; use most-specific retry record */

        retry_host_key = incl_ip ?
          string_sprintf("T:%S:%s%s", host->name, host->address, pistring) :
          string_sprintf("T:%S%s", host->name, pistring);
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

      if (delete_flag != 0 || !continuing)
        retry_add_item(first_addr, retry_host_key, rf_host | delete_flag);

      /* We may have tried an expired host, if its retry time has come; ensure
      the status reflects the expiry for the benefit of any other addresses. */

      if (rc == DEFER)
        {
        host->status = (host_is_expired)?
          hstatus_unusable_expired : hstatus_unusable;
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

    if (message_defer || retry_message_key != NULL)
      {
      int delete_flag = message_defer? 0 : rf_delete;
      if (retry_message_key == NULL)
        {
	BOOL incl_ip;
	if (exp_bool(addrlist, US"transport", tblock->name, D_transport,
		  US"retry_include_ip_address", ob->retry_include_ip_address,
		  ob->expand_retry_include_ip_address, &incl_ip) != OK)
	  incl_ip = TRUE;	/* error; use most-specific retry record */

        retry_message_key = incl_ip ?
          string_sprintf("T:%S:%s%s:%s", host->name, host->address, pistring,
            message_id) :
          string_sprintf("T:%S%s:%s", host->name, pistring, message_id);
        }
      retry_add_item(addrlist, retry_message_key,
        rf_message | rf_host | delete_flag);
      update_waiting = FALSE;
      }

    /* Any return other than DEFER (that is, OK or ERROR) means that the
    addresses have got their final statuses filled in for this host. In the OK
    case, see if any of them are deferred. */

    if (rc == OK)
      for (addr = addrlist; addr; addr = addr->next)
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

    if (continuing) break;

    /* If the whole delivery, or some individual addresses, were deferred and
    there are more hosts that could be tried, do not count this host towards
    the hosts_max_try limit if the age of the message is greater than the
    maximum retry time for this host. This means we may try try all hosts,
    ignoring the limit, when messages have been around for some time. This is
    important because if we don't try all hosts, the address will never time
    out. NOTE: this does not apply to hosts_max_try_hardlimit. */

    if ((rc == DEFER || some_deferred) && nexthost != NULL)
      {
      BOOL timedout;
      retry_config *retry = retry_find_config(host->name, NULL, 0, 0);

      if (retry != NULL && retry->rules != NULL)
        {
        retry_rule *last_rule;
        for (last_rule = retry->rules;
             last_rule->next != NULL;
             last_rule = last_rule->next);
        timedout = time(NULL) - received_time > last_rule->timeout;
        }
      else timedout = TRUE;    /* No rule => timed out */

      if (timedout)
        {
        unexpired_hosts_tried--;
        DEBUG(D_transport) debug_printf("temporary delivery error(s) override "
          "hosts_max_try (message older than host's retry time)\n");
        }
      }
    }   /* End of loop for trying multiple hosts. */

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
  for (addr = addrlist; addr != NULL; addr = addr->next)
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

for (addr = addrlist; addr != NULL; addr = addr->next)
  {
  /* If host is not NULL, it means that we stopped processing the host list
  because of hosts_max_try or hosts_max_try_hardlimit. In the former case, this
  means we need to behave as if some hosts were skipped because their retry
  time had not come. Specifically, this prevents the address from timing out.
  However, if we have hit hosts_max_try_hardlimit, we want to behave as if all
  hosts were tried. */

  if (host != NULL)
    {
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
    }

  if (queue_smtp)    /* no deliveries attempted */
    {
    addr->transport_return = DEFER;
    addr->basic_errno = 0;
    addr->message = US"SMTP delivery explicitly queued";
    }

  else if (addr->transport_return == DEFER &&
       (addr->basic_errno == ERRNO_UNKNOWNERROR || addr->basic_errno == 0) &&
       addr->message == NULL)
    {
    addr->basic_errno = ERRNO_HRETRY;
    if (continue_hostname != NULL)
      {
      addr->message = US"no host found for existing SMTP connection";
      }
    else if (expired)
      {
      setflag(addr, af_pass_message);   /* This is not a security risk */
      addr->message = (ob->delay_after_cutoff)?
        US"retry time not reached for any host after a long failure period" :
        US"all hosts have been failing for a long time and were last tried "
          "after this message arrived";

      /* If we are already using fallback hosts, or there are no fallback hosts
      defined, convert the result to FAIL to cause a bounce. */

      if (addr->host_list == addr->fallback_hosts ||
          addr->fallback_hosts == NULL)
        addr->transport_return = FAIL;
      }
    else
      {
      if (hosts_retry == hosts_total)
        addr->message = US"retry time not reached for any host";
      else if (hosts_fail == hosts_total)
        addr->message = US"all host address lookups failed permanently";
      else if (hosts_defer == hosts_total)
        addr->message = US"all host address lookups failed temporarily";
      else if (hosts_serial == hosts_total)
        addr->message = US"connection limit reached for all hosts";
      else if (hosts_fail+hosts_defer == hosts_total)
        addr->message = US"all host address lookups failed";
      else addr->message = US"some host address lookups failed and retry time "
        "not reached for other hosts or connection limit reached";
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

/* vi: aw ai sw=2
*/
/* End of transport/smtp.c */
