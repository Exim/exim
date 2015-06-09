/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions concerned with verifying things. The original code for callout
caching was contributed by Kevin Fleming (but I hacked it around a bit). */


#include "exim.h"
#include "transports/smtp.h"

#define CUTTHROUGH_CMD_TIMEOUT  30	/* timeout for cutthrough-routing calls */
#define CUTTHROUGH_DATA_TIMEOUT 60	/* timeout for cutthrough-routing calls */
static smtp_outblock ctblock;
uschar ctbuffer[8192];


/* Structure for caching DNSBL lookups */

typedef struct dnsbl_cache_block {
  dns_address *rhs;
  uschar *text;
  int rc;
  BOOL text_set;
} dnsbl_cache_block;


/* Anchor for DNSBL cache */

static tree_node *dnsbl_cache = NULL;


/* Bits for match_type in one_check_dnsbl() */

#define MT_NOT 1
#define MT_ALL 2

static uschar cutthrough_response(char, uschar **);


/*************************************************
*          Retrieve a callout cache record       *
*************************************************/

/* If a record exists, check whether it has expired.

Arguments:
  dbm_file          an open hints file
  key               the record key
  type              "address" or "domain"
  positive_expire   expire time for positive records
  negative_expire   expire time for negative records

Returns:            the cache record if a non-expired one exists, else NULL
*/

static dbdata_callout_cache *
get_callout_cache_record(open_db *dbm_file, const uschar *key, uschar *type,
  int positive_expire, int negative_expire)
{
BOOL negative;
int length, expire;
time_t now;
dbdata_callout_cache *cache_record;

cache_record = dbfn_read_with_length(dbm_file, key, &length);

if (cache_record == NULL)
  {
  HDEBUG(D_verify) debug_printf("callout cache: no %s record found for %s\n", type, key);
  return NULL;
  }

/* We treat a record as "negative" if its result field is not positive, or if
it is a domain record and the postmaster field is negative. */

negative = cache_record->result != ccache_accept ||
  (type[0] == 'd' && cache_record->postmaster_result == ccache_reject);
expire = negative? negative_expire : positive_expire;
now = time(NULL);

if (now - cache_record->time_stamp > expire)
  {
  HDEBUG(D_verify) debug_printf("callout cache: %s record expired for %s\n", type, key);
  return NULL;
  }

/* If this is a non-reject domain record, check for the obsolete format version
that doesn't have the postmaster and random timestamps, by looking at the
length. If so, copy it to a new-style block, replicating the record's
timestamp. Then check the additional timestamps. (There's no point wasting
effort if connections are rejected.) */

if (type[0] == 'd' && cache_record->result != ccache_reject)
  {
  if (length == sizeof(dbdata_callout_cache_obs))
    {
    dbdata_callout_cache *new = store_get(sizeof(dbdata_callout_cache));
    memcpy(new, cache_record, length);
    new->postmaster_stamp = new->random_stamp = new->time_stamp;
    cache_record = new;
    }

  if (now - cache_record->postmaster_stamp > expire)
    cache_record->postmaster_result = ccache_unknown;

  if (now - cache_record->random_stamp > expire)
    cache_record->random_result = ccache_unknown;
  }

HDEBUG(D_verify) debug_printf("callout cache: found %s record for %s\n", type, key);
return cache_record;
}



/*************************************************
*      Do callout verification for an address    *
*************************************************/

/* This function is called from verify_address() when the address has routed to
a host list, and a callout has been requested. Callouts are expensive; that is
why a cache is used to improve the efficiency.

Arguments:
  addr              the address that's been routed
  host_list         the list of hosts to try
  tf                the transport feedback block

  ifstring          "interface" option from transport, or NULL
  portstring        "port" option from transport, or NULL
  protocolstring    "protocol" option from transport, or NULL
  callout           the per-command callout timeout
  callout_overall   the overall callout timeout (if < 0 use 4*callout)
  callout_connect   the callout connection timeout (if < 0 use callout)
  options           the verification options - these bits are used:
                      vopt_is_recipient => this is a recipient address
                      vopt_callout_no_cache => don't use callout cache
                      vopt_callout_fullpm => if postmaster check, do full one
                      vopt_callout_random => do the "random" thing
                      vopt_callout_recipsender => use real sender for recipient
                      vopt_callout_recippmaster => use postmaster for recipient
  se_mailfrom         MAIL FROM address for sender verify; NULL => ""
  pm_mailfrom         if non-NULL, do the postmaster check with this sender

Returns:            OK/FAIL/DEFER
*/

static int
do_callout(address_item *addr, host_item *host_list, transport_feedback *tf,
  int callout, int callout_overall, int callout_connect, int options,
  uschar *se_mailfrom, uschar *pm_mailfrom)
{
BOOL is_recipient = (options & vopt_is_recipient) != 0;
BOOL callout_no_cache = (options & vopt_callout_no_cache) != 0;
BOOL callout_random = (options & vopt_callout_random) != 0;

int yield = OK;
int old_domain_cache_result = ccache_accept;
BOOL done = FALSE;
uschar *address_key;
uschar *from_address;
uschar *random_local_part = NULL;
const uschar *save_deliver_domain = deliver_domain;
uschar **failure_ptr = is_recipient?
  &recipient_verify_failure : &sender_verify_failure;
open_db dbblock;
open_db *dbm_file = NULL;
dbdata_callout_cache new_domain_record;
dbdata_callout_cache_address new_address_record;
host_item *host;
time_t callout_start_time;
#ifdef EXPERIMENTAL_INTERNATIONAL
BOOL utf8_offered = FALSE;
#endif

new_domain_record.result = ccache_unknown;
new_domain_record.postmaster_result = ccache_unknown;
new_domain_record.random_result = ccache_unknown;

memset(&new_address_record, 0, sizeof(new_address_record));

/* For a recipient callout, the key used for the address cache record must
include the sender address if we are using the real sender in the callout,
because that may influence the result of the callout. */

address_key = addr->address;
from_address = US"";

if (is_recipient)
  {
  if (options & vopt_callout_recipsender)
    {
    address_key = string_sprintf("%s/<%s>", addr->address, sender_address);
    from_address = sender_address;
    }
  else if (options & vopt_callout_recippmaster)
    {
    address_key = string_sprintf("%s/<postmaster@%s>", addr->address,
      qualify_domain_sender);
    from_address = string_sprintf("postmaster@%s", qualify_domain_sender);
    }
  }

/* For a sender callout, we must adjust the key if the mailfrom address is not
empty. */

else
  {
  from_address = (se_mailfrom == NULL)? US"" : se_mailfrom;
  if (from_address[0] != 0)
    address_key = string_sprintf("%s/<%s>", addr->address, from_address);
  }

/* Open the callout cache database, it it exists, for reading only at this
stage, unless caching has been disabled. */

if (callout_no_cache)
  {
  HDEBUG(D_verify) debug_printf("callout cache: disabled by no_cache\n");
  }
else if ((dbm_file = dbfn_open(US"callout", O_RDWR, &dbblock, FALSE)) == NULL)
  {
  HDEBUG(D_verify) debug_printf("callout cache: not available\n");
  }

/* If a cache database is available see if we can avoid the need to do an
actual callout by making use of previously-obtained data. */

if (dbm_file != NULL)
  {
  dbdata_callout_cache_address *cache_address_record;
  dbdata_callout_cache *cache_record = get_callout_cache_record(dbm_file,
    addr->domain, US"domain",
    callout_cache_domain_positive_expire,
    callout_cache_domain_negative_expire);

  /* If an unexpired cache record was found for this domain, see if the callout
  process can be short-circuited. */

  if (cache_record != NULL)
    {
    /* In most cases, if an early command (up to and including MAIL FROM:<>)
    was rejected, there is no point carrying on. The callout fails. However, if
    we are doing a recipient verification with use_sender or use_postmaster
    set, a previous failure of MAIL FROM:<> doesn't count, because this time we
    will be using a non-empty sender. We have to remember this situation so as
    not to disturb the cached domain value if this whole verification succeeds
    (we don't want it turning into "accept"). */

    old_domain_cache_result = cache_record->result;

    if (cache_record->result == ccache_reject ||
         (*from_address == 0 && cache_record->result == ccache_reject_mfnull))
      {
      setflag(addr, af_verify_nsfail);
      HDEBUG(D_verify)
        debug_printf("callout cache: domain gave initial rejection, or "
          "does not accept HELO or MAIL FROM:<>\n");
      setflag(addr, af_verify_nsfail);
      addr->user_message = US"(result of an earlier callout reused).";
      yield = FAIL;
      *failure_ptr = US"mail";
      goto END_CALLOUT;
      }

    /* If a previous check on a "random" local part was accepted, we assume
    that the server does not do any checking on local parts. There is therefore
    no point in doing the callout, because it will always be successful. If a
    random check previously failed, arrange not to do it again, but preserve
    the data in the new record. If a random check is required but hasn't been
    done, skip the remaining cache processing. */

    if (callout_random) switch(cache_record->random_result)
      {
      case ccache_accept:
      HDEBUG(D_verify)
        debug_printf("callout cache: domain accepts random addresses\n");
      goto END_CALLOUT;     /* Default yield is OK */

      case ccache_reject:
      HDEBUG(D_verify)
        debug_printf("callout cache: domain rejects random addresses\n");
      callout_random = FALSE;
      new_domain_record.random_result = ccache_reject;
      new_domain_record.random_stamp = cache_record->random_stamp;
      break;

      default:
      HDEBUG(D_verify)
        debug_printf("callout cache: need to check random address handling "
          "(not cached or cache expired)\n");
      goto END_CACHE;
      }

    /* If a postmaster check is requested, but there was a previous failure,
    there is again no point in carrying on. If a postmaster check is required,
    but has not been done before, we are going to have to do a callout, so skip
    remaining cache processing. */

    if (pm_mailfrom != NULL)
      {
      if (cache_record->postmaster_result == ccache_reject)
        {
        setflag(addr, af_verify_pmfail);
        HDEBUG(D_verify)
          debug_printf("callout cache: domain does not accept "
            "RCPT TO:<postmaster@domain>\n");
        yield = FAIL;
        *failure_ptr = US"postmaster";
        setflag(addr, af_verify_pmfail);
        addr->user_message = US"(result of earlier verification reused).";
        goto END_CALLOUT;
        }
      if (cache_record->postmaster_result == ccache_unknown)
        {
        HDEBUG(D_verify)
          debug_printf("callout cache: need to check RCPT "
            "TO:<postmaster@domain> (not cached or cache expired)\n");
        goto END_CACHE;
        }

      /* If cache says OK, set pm_mailfrom NULL to prevent a redundant
      postmaster check if the address itself has to be checked. Also ensure
      that the value in the cache record is preserved (with its old timestamp).
      */

      HDEBUG(D_verify) debug_printf("callout cache: domain accepts RCPT "
        "TO:<postmaster@domain>\n");
      pm_mailfrom = NULL;
      new_domain_record.postmaster_result = ccache_accept;
      new_domain_record.postmaster_stamp = cache_record->postmaster_stamp;
      }
    }

  /* We can't give a result based on information about the domain. See if there
  is an unexpired cache record for this specific address (combined with the
  sender address if we are doing a recipient callout with a non-empty sender).
  */

  cache_address_record = (dbdata_callout_cache_address *)
    get_callout_cache_record(dbm_file,
      address_key, US"address",
      callout_cache_positive_expire,
      callout_cache_negative_expire);

  if (cache_address_record != NULL)
    {
    if (cache_address_record->result == ccache_accept)
      {
      HDEBUG(D_verify)
        debug_printf("callout cache: address record is positive\n");
      }
    else
      {
      HDEBUG(D_verify)
        debug_printf("callout cache: address record is negative\n");
      addr->user_message = US"Previous (cached) callout verification failure";
      *failure_ptr = US"recipient";
      yield = FAIL;
      }
    goto END_CALLOUT;
    }

  /* Close the cache database while we actually do the callout for real. */

  END_CACHE:
  dbfn_close(dbm_file);
  dbm_file = NULL;
  }

if (!addr->transport)
  {
  HDEBUG(D_verify) debug_printf("cannot callout via null transport\n");
  }
else if (Ustrcmp(addr->transport->driver_name, "smtp") != 0)
  log_write(0, LOG_MAIN|LOG_PANIC|LOG_CONFIG_FOR, "callout transport '%s': %s is non-smtp",
    addr->transport->name, addr->transport->driver_name);
else
  {
  smtp_transport_options_block *ob =
    (smtp_transport_options_block *)addr->transport->options_block;

  /* The information wasn't available in the cache, so we have to do a real
  callout and save the result in the cache for next time, unless no_cache is set,
  or unless we have a previously cached negative random result. If we are to test
  with a random local part, ensure that such a local part is available. If not,
  log the fact, but carry on without randomming. */

  if (callout_random && callout_random_local_part != NULL)
    if (!(random_local_part = expand_string(callout_random_local_part)))
      log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand "
        "callout_random_local_part: %s", expand_string_message);

  /* Default the connect and overall callout timeouts if not set, and record the
  time we are starting so that we can enforce it. */

  if (callout_overall < 0) callout_overall = 4 * callout;
  if (callout_connect < 0) callout_connect = callout;
  callout_start_time = time(NULL);

  /* Before doing a real callout, if this is an SMTP connection, flush the SMTP
  output because a callout might take some time. When PIPELINING is active and
  there are many recipients, the total time for doing lots of callouts can add up
  and cause the client to time out. So in this case we forgo the PIPELINING
  optimization. */

  if (smtp_out != NULL && !disable_callout_flush) mac_smtp_fflush();

/* cutthrough-multi: if a nonfirst rcpt has the same routing as the first,
and we are holding a cutthrough conn open, we can just append the rcpt to
that conn for verification purposes (and later delivery also).  Simplest
coding means skipping this whole loop and doing the append separately.

We will need to remember it has been appended so that rcpt-acl tail code
can do it there for the non-rcpt-verify case.  For this we keep an addresscount.
*/

  /* Can we re-use an open cutthrough connection? */
  if (  cutthrough.fd >= 0
     && (options & (vopt_callout_recipsender | vopt_callout_recippmaster))
	== vopt_callout_recipsender
     && !random_local_part
     && !pm_mailfrom
     )
    {
    if (addr->transport == cutthrough.addr.transport)
      for (host = host_list; host; host = host->next)
	if (Ustrcmp(host->address, cutthrough.host.address) == 0)
	  {
	  int host_af;
	  uschar *interface = NULL;  /* Outgoing interface to use; NULL => any */
	  int port = 25;

	  deliver_host = host->name;
	  deliver_host_address = host->address;
	  deliver_host_port = host->port;
	  deliver_domain = addr->domain;
	  transport_name = addr->transport->name;

	  host_af = (Ustrchr(host->address, ':') == NULL)? AF_INET:AF_INET6;

	  if (!smtp_get_interface(tf->interface, host_af, addr, NULL, &interface,
		  US"callout") ||
	      !smtp_get_port(tf->port, addr, &port, US"callout"))
	    log_write(0, LOG_MAIN|LOG_PANIC, "<%s>: %s", addr->address,
	      addr->message);

	  if (  (  interface == cutthrough.interface
	        || (  interface
	           && cutthrough.interface
		   && Ustrcmp(interface, cutthrough.interface) == 0
		)  )
	     && port == cutthrough.host.port
	     )
	    {
	    uschar * resp;

	    /* Match!  Send the RCPT TO, append the addr, set done */
	    done =
	      smtp_write_command(&ctblock, FALSE, "RCPT TO:<%.1000s>\r\n",
		transport_rcpt_address(addr,
		  (addr->transport == NULL)? FALSE :
		   addr->transport->rcpt_include_affixes)) >= 0 &&
	      cutthrough_response('2', &resp) == '2';

	    /* This would go horribly wrong if a callout fail was ignored by ACL.
	    We punt by abandoning cutthrough on a reject, like the
	    first-rcpt does. */

	    if (done)
	      {
	      address_item * na = store_get(sizeof(address_item));
	      *na = cutthrough.addr;
	      cutthrough.addr = *addr;
	      cutthrough.addr.host_used = &cutthrough.host;
	      cutthrough.addr.next = na;

	      cutthrough.nrcpt++;
	      }
	    else
	      {
	      cancel_cutthrough_connection("recipient rejected");
	      if (errno == ETIMEDOUT)
		{
		HDEBUG(D_verify) debug_printf("SMTP timeout\n");
		}
	      else if (errno == 0)
		{
		if (*resp == 0)
		  Ustrcpy(resp, US"connection dropped");

		addr->message =
		  string_sprintf("response to \"%s\" from %s [%s] was: %s",
		    big_buffer, host->name, host->address,
		    string_printing(resp));

		addr->user_message =
		  string_sprintf("Callout verification failed:\n%s", resp);

		/* Hard rejection ends the process */

		if (resp[0] == '5')   /* Address rejected */
		  {
		  yield = FAIL;
		  done = TRUE;
		  }
		}
	      }
	    }
	  break;
	  }
    if (!done)
      cancel_cutthrough_connection("incompatible connection");
    }

  /* Now make connections to the hosts and do real callouts. The list of hosts
  is passed in as an argument. */

  for (host = host_list; host != NULL && !done; host = host->next)
    {
    smtp_inblock inblock;
    smtp_outblock outblock;
    int host_af;
    int port = 25;
    BOOL send_quit = TRUE;
    uschar *active_hostname = smtp_active_hostname;
    BOOL lmtp;
    BOOL smtps;
    BOOL esmtp;
    BOOL suppress_tls = FALSE;
    uschar *interface = NULL;  /* Outgoing interface to use; NULL => any */
#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_DANE)
    BOOL dane = FALSE;
    BOOL dane_required;
    dns_answer tlsa_dnsa;
#endif
    uschar inbuffer[4096];
    uschar outbuffer[1024];
    uschar responsebuffer[4096];

    clearflag(addr, af_verify_pmfail);  /* postmaster callout flag */
    clearflag(addr, af_verify_nsfail);  /* null sender callout flag */

    /* Skip this host if we don't have an IP address for it. */

    if (host->address == NULL)
      {
      DEBUG(D_verify) debug_printf("no IP address for host name %s: skipping\n",
        host->name);
      continue;
      }

    /* Check the overall callout timeout */

    if (time(NULL) - callout_start_time >= callout_overall)
      {
      HDEBUG(D_verify) debug_printf("overall timeout for callout exceeded\n");
      break;
      }

    /* Set IPv4 or IPv6 */

    host_af = (Ustrchr(host->address, ':') == NULL)? AF_INET:AF_INET6;

    /* Expand and interpret the interface and port strings. The latter will not
    be used if there is a host-specific port (e.g. from a manualroute router).
    This has to be delayed till now, because they may expand differently for
    different hosts. If there's a failure, log it, but carry on with the
    defaults. */

    deliver_host = host->name;
    deliver_host_address = host->address;
    deliver_host_port = host->port;
    deliver_domain = addr->domain;
    transport_name = addr->transport->name;

    if (  !smtp_get_interface(tf->interface, host_af, addr, NULL, &interface,
            US"callout")
       || !smtp_get_port(tf->port, addr, &port, US"callout")
       )
      log_write(0, LOG_MAIN|LOG_PANIC, "<%s>: %s", addr->address,
        addr->message);

    /* Set HELO string according to the protocol */
    lmtp= Ustrcmp(tf->protocol, "lmtp") == 0;
    smtps= Ustrcmp(tf->protocol, "smtps") == 0;


    HDEBUG(D_verify) debug_printf("interface=%s port=%d\n", interface, port);

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

    /* Connect to the host; on failure, just loop for the next one, but we
    set the error for the last one. Use the callout_connect timeout. */

    tls_retry_connection:

    /* Reset the parameters of a TLS session */
    tls_out.cipher = tls_out.peerdn = tls_out.peercert = NULL;

    inblock.sock = outblock.sock =
      smtp_connect(host, host_af, port, interface, callout_connect,
		  addr->transport);
    if (inblock.sock < 0)
      {
      addr->message = string_sprintf("could not connect to %s [%s]: %s",
          host->name, host->address, strerror(errno));
      transport_name = NULL;
      deliver_host = deliver_host_address = NULL;
      deliver_domain = save_deliver_domain;
      continue;
      }

#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_DANE)
      {
      int rc;

      tls_out.dane_verified = FALSE;
      tls_out.tlsa_usage = 0;

      dane_required =
	verify_check_given_host(&ob->hosts_require_dane, host) == OK;

      if (host->dnssec == DS_YES)
	{
	if(  (  dane_required
	     || verify_check_given_host(&ob->hosts_try_dane, host) == OK
	     )
	  && (rc = tlsa_lookup(host, &tlsa_dnsa, dane_required, &dane)) != OK
	  )
	  return rc;
	}
      else if (dane_required)
	{
	log_write(0, LOG_MAIN, "DANE error: %s lookup not DNSSEC", host->name);
	return FAIL;
	}

      if (dane)
	ob->tls_tempfail_tryclear = FALSE;
      }
#endif  /*DANE*/

    /* Expand the helo_data string to find the host name to use. */

    if (tf->helo_data != NULL)
      {
      uschar *s = expand_string(tf->helo_data);
      if (s == NULL)
        log_write(0, LOG_MAIN|LOG_PANIC, "<%s>: failed to expand transport's "
          "helo_data value for callout: %s", addr->address,
          expand_string_message);
      else active_hostname = s;
      }

    /* Wait for initial response, and send HELO. The smtp_write_command()
    function leaves its command in big_buffer. This is used in error responses.
    Initialize it in case the connection is rejected. */

    Ustrcpy(big_buffer, "initial connection");

    /* Unless ssl-on-connect, wait for the initial greeting */
    smtps_redo_greeting:

#ifdef SUPPORT_TLS
    if (!smtps || (smtps && tls_out.active >= 0))
#endif
      {
      if (!(done= smtp_read_response(&inblock, responsebuffer, sizeof(responsebuffer), '2', callout)))
        goto RESPONSE_FAILED;

#ifdef EXPERIMENTAL_EVENT
      lookup_dnssec_authenticated = host->dnssec==DS_YES ? US"yes"
	: host->dnssec==DS_NO ? US"no" : NULL;
      if (event_raise(addr->transport->event_action,
			    US"smtp:connect", responsebuffer))
	{
	lookup_dnssec_authenticated = NULL;
	/* Logging?  Debug? */
	goto RESPONSE_FAILED;
	}
      lookup_dnssec_authenticated = NULL;
#endif
      }

    /* Not worth checking greeting line for ESMTP support */
    if (!(esmtp = verify_check_given_host(&ob->hosts_avoid_esmtp, host) != OK))
      DEBUG(D_transport)
        debug_printf("not sending EHLO (host matches hosts_avoid_esmtp)\n");

    tls_redo_helo:

#ifdef SUPPORT_TLS
    if (smtps  &&  tls_out.active < 0)	/* ssl-on-connect, first pass */
      {
      tls_offered = TRUE;
      ob->tls_tempfail_tryclear = FALSE;
      }
    else				/* all other cases */
#endif

      { esmtp_retry:

      if (!(done= smtp_write_command(&outblock, FALSE, "%s %s\r\n",
        !esmtp? "HELO" : lmtp? "LHLO" : "EHLO", active_hostname) >= 0))
        goto SEND_FAILED;
      if (!smtp_read_response(&inblock, responsebuffer, sizeof(responsebuffer), '2', callout))
        {
	if (errno != 0 || responsebuffer[0] == 0 || lmtp || !esmtp || tls_out.active >= 0)
	  {
	  done= FALSE;
	  goto RESPONSE_FAILED;
	  }
#ifdef SUPPORT_TLS
        tls_offered = FALSE;
#endif
        esmtp = FALSE;
        goto esmtp_retry;			/* fallback to HELO */
        }

      /* Set tls_offered if the response to EHLO specifies support for STARTTLS. */
#ifdef SUPPORT_TLS
      if (esmtp && !suppress_tls &&  tls_out.active < 0)
	{
	if (regex_STARTTLS == NULL) regex_STARTTLS =
	  regex_must_compile(US"\\n250[\\s\\-]STARTTLS(\\s|\\n|$)", FALSE, TRUE);

	tls_offered = pcre_exec(regex_STARTTLS, NULL, CS responsebuffer,
		      Ustrlen(responsebuffer), 0, PCRE_EOPT, NULL, 0) >= 0;
	}
      else
        tls_offered = FALSE;
#endif
      }

    /* If TLS is available on this connection attempt to
    start up a TLS session, unless the host is in hosts_avoid_tls. If successful,
    send another EHLO - the server may give a different answer in secure mode. We
    use a separate buffer for reading the response to STARTTLS so that if it is
    negative, the original EHLO data is available for subsequent analysis, should
    the client not be required to use TLS. If the response is bad, copy the buffer
    for error analysis. */

#ifdef SUPPORT_TLS
    if (  tls_offered
       && verify_check_given_host(&ob->hosts_avoid_tls, host) != OK
       && verify_check_given_host(&ob->hosts_verify_avoid_tls, host) != OK
       )
      {
      uschar buffer2[4096];
      if (  !smtps
         && !(done= smtp_write_command(&outblock, FALSE, "STARTTLS\r\n") >= 0))
        goto SEND_FAILED;

      /* If there is an I/O error, transmission of this message is deferred. If
      there is a temporary rejection of STARRTLS and tls_tempfail_tryclear is
      false, we also defer. However, if there is a temporary rejection of STARTTLS
      and tls_tempfail_tryclear is true, or if there is an outright rejection of
      STARTTLS, we carry on. This means we will try to send the message in clear,
      unless the host is in hosts_require_tls (tested below). */

      if (!smtps && !smtp_read_response(&inblock, buffer2, sizeof(buffer2), '2',
  			ob->command_timeout))
        {
        if (errno != 0 || buffer2[0] == 0 ||
        	(buffer2[0] == '4' && !ob->tls_tempfail_tryclear))
	  {
	  Ustrncpy(responsebuffer, buffer2, sizeof(responsebuffer));
	  done= FALSE;
	  goto RESPONSE_FAILED;
	  }
        }

       /* STARTTLS accepted or ssl-on-connect: try to negotiate a TLS session. */
      else
        {
	int oldtimeout = ob->command_timeout;
	int rc;

	tls_negotiate:
	ob->command_timeout = callout;
        rc = tls_client_start(inblock.sock, host, addr, addr->transport
# ifdef EXPERIMENTAL_DANE
			    , dane ? &tlsa_dnsa : NULL
# endif
			    );
	ob->command_timeout = oldtimeout;

        /* TLS negotiation failed; give an error.  Try in clear on a new
	connection, if the options permit it for this host. */
        if (rc != OK)
          {
	  if (rc == DEFER)
	    {
	    (void)close(inblock.sock);
# ifdef EXPERIMENTAL_EVENT
	    (void) event_raise(addr->transport->event_action,
				    US"tcp:close", NULL);
# endif
# ifdef EXPERIMENTAL_DANE
	    if (dane)
	      {
	      if (!dane_required)
		{
		log_write(0, LOG_MAIN, "DANE attempt failed;"
		  " trying CA-root TLS to %s [%s] (not in hosts_require_dane)",
		  host->name, host->address);
		dane = FALSE;
		goto tls_negotiate;
		}
	      }
	    else
# endif
	      if (  ob->tls_tempfail_tryclear
		 && !smtps
		 && verify_check_given_host(&ob->hosts_require_tls, host) != OK
		 )
	      {
	      log_write(0, LOG_MAIN, "TLS session failure:"
		" delivering unencrypted to %s [%s] (not in hosts_require_tls)",
		host->name, host->address);
	      suppress_tls = TRUE;
	      goto tls_retry_connection;
	      }
	    }

	  /*save_errno = ERRNO_TLSFAILURE;*/
	  /*message = US"failure while setting up TLS session";*/
	  send_quit = FALSE;
	  done= FALSE;
	  goto TLS_FAILED;
	  }

        /* TLS session is set up.  Copy info for logging. */
        addr->cipher = tls_out.cipher;
        addr->peerdn = tls_out.peerdn;

        /* For SMTPS we need to wait for the initial OK response, then do HELO. */
        if (smtps)
	  goto smtps_redo_greeting;

        /* For STARTTLS we need to redo EHLO */
        goto tls_redo_helo;
        }
      }

    /* If the host is required to use a secure channel, ensure that we have one. */
    if (tls_out.active < 0)
      if (
# ifdef EXPERIMENTAL_DANE
	 dane ||
# endif
         verify_check_given_host(&ob->hosts_require_tls, host) == OK
	 )
        {
        /*save_errno = ERRNO_TLSREQUIRED;*/
        log_write(0, LOG_MAIN,
	  "H=%s [%s]: a TLS session is required for this host, but %s",
          host->name, host->address,
	  tls_offered ? "an attempt to start TLS failed"
		      : "the server did not offer TLS support");
        done= FALSE;
        goto TLS_FAILED;
        }

#endif /*SUPPORT_TLS*/

    done = TRUE; /* so far so good; have response to HELO */

    /*XXX the EHLO response would be analyzed here for IGNOREQUOTA, SIZE, PIPELINING */

    /* For now, transport_filter by cutthrough-delivery is not supported */
    /* Need proper integration with the proper transport mechanism. */
    if (cutthrough.delivery)
      {
      if (addr->transport->filter_command)
        {
        cutthrough.delivery = FALSE;
        HDEBUG(D_acl|D_v) debug_printf("Cutthrough cancelled by presence of transport filter\n");
        }
#ifndef DISABLE_DKIM
      if (ob->dkim_domain)
        {
        cutthrough.delivery = FALSE;
        HDEBUG(D_acl|D_v) debug_printf("Cutthrough cancelled by presence of DKIM signing\n");
        }
#endif
      }

    SEND_FAILED:
    RESPONSE_FAILED:
    TLS_FAILED:
    ;
    /* Clear down of the TLS, SMTP and TCP layers on error is handled below.  */

    /* Failure to accept HELO is cached; this blocks the whole domain for all
    senders. I/O errors and defer responses are not cached. */

    if (!done)
      {
      *failure_ptr = US"mail";     /* At or before MAIL */
      if (errno == 0 && responsebuffer[0] == '5')
        {
        setflag(addr, af_verify_nsfail);
        new_domain_record.result = ccache_reject;
        }
      }

#ifdef EXPERIMENTAL_INTERNATIONAL
    else if (  addr->prop.utf8_msg
	    && !addr->prop.utf8_downcvt
	    && !(  esmtp
		&& (  regex_UTF8
		   || ( (regex_UTF8 = regex_must_compile(
			  US"\\n250[\\s\\-]SMTPUTF8(\\s|\\n|$)", FALSE, TRUE)),
		      TRUE
		   )  )
		&& (  (utf8_offered = pcre_exec(regex_UTF8, NULL,
			    CS responsebuffer, Ustrlen(responsebuffer),
			    0, PCRE_EOPT, NULL, 0) >= 0)
		   || addr->prop.utf8_downcvt_maybe
	    )   )  )
      {
      HDEBUG(D_acl|D_v) debug_printf("utf8 required but not offered\n");
      errno = ERRNO_UTF8_FWD;
      setflag(addr, af_verify_nsfail);
      done = FALSE;
      }
    else if (  addr->prop.utf8_msg
	    && (addr->prop.utf8_downcvt || !utf8_offered)
	    && (setflag(addr, af_utf8_downcvt),
	        from_address = string_address_utf8_to_alabel(from_address,
				      &addr->message),
		addr->message
	    )  )
      {
      errno = ERRNO_EXPANDFAIL;
      setflag(addr, af_verify_nsfail);
      done = FALSE;
      }
#endif

    /* If we haven't authenticated, but are required to, give up. */
    /* Try to AUTH */

    else done = smtp_auth(responsebuffer, sizeof(responsebuffer),
	addr, host, ob, esmtp, &inblock, &outblock) == OK  &&

      		/* Copy AUTH info for logging */
      ( (addr->authenticator = client_authenticator),
        (addr->auth_id = client_authenticated_id),

    /* Build a mail-AUTH string (re-using responsebuffer for convenience */
        !smtp_mail_auth_str(responsebuffer, sizeof(responsebuffer), addr, ob)
      )  &&

      ( (addr->auth_sndr = client_authenticated_sender),

    /* Send the MAIL command */
        (smtp_write_command(&outblock, FALSE,
#ifdef EXPERIMENTAL_INTERNATIONAL
	  addr->prop.utf8_msg && !addr->prop.utf8_downcvt
	  ? "MAIL FROM:<%s>%s SMTPUTF8\r\n"
	  :
#endif
	    "MAIL FROM:<%s>%s\r\n",
          from_address, responsebuffer) >= 0)
      )  &&

      smtp_read_response(&inblock, responsebuffer, sizeof(responsebuffer),
        '2', callout);

    deliver_host = deliver_host_address = NULL;
    deliver_domain = save_deliver_domain;

    /* If the host does not accept MAIL FROM:<>, arrange to cache this
    information, but again, don't record anything for an I/O error or a defer. Do
    not cache rejections of MAIL when a non-empty sender has been used, because
    that blocks the whole domain for all senders. */

    if (!done)
      {
      *failure_ptr = US"mail";     /* At or before MAIL */
      if (errno == 0 && responsebuffer[0] == '5')
        {
        setflag(addr, af_verify_nsfail);
        if (from_address[0] == 0)
          new_domain_record.result = ccache_reject_mfnull;
        }
      }

    /* Otherwise, proceed to check a "random" address (if required), then the
    given address, and the postmaster address (if required). Between each check,
    issue RSET, because some servers accept only one recipient after MAIL
    FROM:<>.

    Before doing this, set the result in the domain cache record to "accept",
    unless its previous value was ccache_reject_mfnull. In that case, the domain
    rejects MAIL FROM:<> and we want to continue to remember that. When that is
    the case, we have got here only in the case of a recipient verification with
    a non-null sender. */

    else
      {
      const uschar * rcpt_domain = addr->domain;

#ifdef EXPERIMENTAL_INTERNATIONAL
      uschar * errstr = NULL;
      if (  testflag(addr, af_utf8_downcvt)
	 && (rcpt_domain = string_domain_utf8_to_alabel(rcpt_domain,
				    &errstr), errstr)
	 )
	{
	addr->message = errstr;
	errno = ERRNO_EXPANDFAIL;
	setflag(addr, af_verify_nsfail);
	done = FALSE;
	rcpt_domain = US"";  /*XXX errorhandling! */
	}
#endif

      new_domain_record.result =
        (old_domain_cache_result == ccache_reject_mfnull)?
          ccache_reject_mfnull: ccache_accept;

      /* Do the random local part check first */

      if (random_local_part != NULL)
        {
        uschar randombuffer[1024];
        BOOL random_ok =
          smtp_write_command(&outblock, FALSE,
            "RCPT TO:<%.1000s@%.1000s>\r\n", random_local_part,
            rcpt_domain) >= 0 &&
          smtp_read_response(&inblock, randombuffer,
            sizeof(randombuffer), '2', callout);

        /* Remember when we last did a random test */

        new_domain_record.random_stamp = time(NULL);

        /* If accepted, we aren't going to do any further tests below. */

        if (random_ok)
          new_domain_record.random_result = ccache_accept;

        /* Otherwise, cache a real negative response, and get back to the right
        state to send RCPT. Unless there's some problem such as a dropped
        connection, we expect to succeed, because the commands succeeded above.
	However, some servers drop the connection after responding to  an
	invalid recipient, so on (any) error we drop and remake the connection.
	*/

        else if (errno == 0)
          {
	  /* This would be ok for 1st rcpt a cutthrough, but no way to
	  handle a subsequent.  So refuse to support any */
	  cancel_cutthrough_connection("random-recipient");

          if (randombuffer[0] == '5')
            new_domain_record.random_result = ccache_reject;

          done =
            smtp_write_command(&outblock, FALSE, "RSET\r\n") >= 0 &&
            smtp_read_response(&inblock, responsebuffer, sizeof(responsebuffer),
              '2', callout) &&

            smtp_write_command(&outblock, FALSE,
#ifdef EXPERIMENTAL_INTERNATIONAL
	      addr->prop.utf8_msg && !addr->prop.utf8_downcvt
	      ? "MAIL FROM:<%s> SMTPUTF8\r\n"
	      :
#endif
	        "MAIL FROM:<%s>\r\n",
              from_address) >= 0 &&
            smtp_read_response(&inblock, responsebuffer, sizeof(responsebuffer),
              '2', callout);

	  if (!done)
	    {
	    HDEBUG(D_acl|D_v)
	      debug_printf("problem after random/rset/mfrom; reopen conn\n");
	    random_local_part = NULL;
#ifdef SUPPORT_TLS
	    tls_close(FALSE, TRUE);
#endif
	    (void)close(inblock.sock);
#ifdef EXPERIMENTAL_EVENT
	    (void) event_raise(addr->transport->event_action,
			      US"tcp:close", NULL);
#endif
	    goto tls_retry_connection;
	    }
          }
        else done = FALSE;    /* Some timeout/connection problem */
        }                     /* Random check */

      /* If the host is accepting all local parts, as determined by the "random"
      check, we don't need to waste time doing any further checking. */

      if (new_domain_record.random_result != ccache_accept && done)
        {
        /* Get the rcpt_include_affixes flag from the transport if there is one,
        but assume FALSE if there is not. */

	uschar * rcpt = transport_rcpt_address(addr,
              addr->transport ? addr->transport->rcpt_include_affixes : FALSE);

#ifdef EXPERIMENTAL_INTERNATIONAL
	/*XXX should the conversion be moved into transport_rcpt_address() ? */
	uschar * dummy_errstr = NULL;
	if (  testflag(addr, af_utf8_downcvt)
	   && (rcpt = string_address_utf8_to_alabel(rcpt, &dummy_errstr),
	       dummy_errstr
	   )  )
	{
	errno = ERRNO_EXPANDFAIL;
	*failure_ptr = US"recipient";
	done = FALSE;
	}
	else
#endif

        done =
          smtp_write_command(&outblock, FALSE, "RCPT TO:<%.1000s>\r\n",
            rcpt) >= 0 &&
          smtp_read_response(&inblock, responsebuffer, sizeof(responsebuffer),
            '2', callout);

        if (done)
          new_address_record.result = ccache_accept;
        else if (errno == 0 && responsebuffer[0] == '5')
          {
          *failure_ptr = US"recipient";
          new_address_record.result = ccache_reject;
          }

        /* Do postmaster check if requested; if a full check is required, we
        check for RCPT TO:<postmaster> (no domain) in accordance with RFC 821. */

        if (done && pm_mailfrom != NULL)
          {
          /* Could possibly shift before main verify, just above, and be ok
	  for cutthrough.  But no way to handle a subsequent rcpt, so just
	  refuse any */
	cancel_cutthrough_connection("postmaster verify");
  	HDEBUG(D_acl|D_v) debug_printf("Cutthrough cancelled by presence of postmaster verify\n");

          done =
            smtp_write_command(&outblock, FALSE, "RSET\r\n") >= 0 &&
            smtp_read_response(&inblock, responsebuffer,
              sizeof(responsebuffer), '2', callout) &&

            smtp_write_command(&outblock, FALSE,
              "MAIL FROM:<%s>\r\n", pm_mailfrom) >= 0 &&
            smtp_read_response(&inblock, responsebuffer,
              sizeof(responsebuffer), '2', callout) &&

            /* First try using the current domain */

            ((
            smtp_write_command(&outblock, FALSE,
              "RCPT TO:<postmaster@%.1000s>\r\n", rcpt_domain) >= 0 &&
            smtp_read_response(&inblock, responsebuffer,
              sizeof(responsebuffer), '2', callout)
            )

            ||

            /* If that doesn't work, and a full check is requested,
            try without the domain. */

            (
            (options & vopt_callout_fullpm) != 0 &&
            smtp_write_command(&outblock, FALSE,
              "RCPT TO:<postmaster>\r\n") >= 0 &&
            smtp_read_response(&inblock, responsebuffer,
              sizeof(responsebuffer), '2', callout)
            ));

          /* Sort out the cache record */

          new_domain_record.postmaster_stamp = time(NULL);

          if (done)
            new_domain_record.postmaster_result = ccache_accept;
          else if (errno == 0 && responsebuffer[0] == '5')
            {
            *failure_ptr = US"postmaster";
            setflag(addr, af_verify_pmfail);
            new_domain_record.postmaster_result = ccache_reject;
            }
          }
        }           /* Random not accepted */
      }             /* MAIL FROM: accepted */

    /* For any failure of the main check, other than a negative response, we just
    close the connection and carry on. We can identify a negative response by the
    fact that errno is zero. For I/O errors it will be non-zero

    Set up different error texts for logging and for sending back to the caller
    as an SMTP response. Log in all cases, using a one-line format. For sender
    callouts, give a full response to the caller, but for recipient callouts,
    don't give the IP address because this may be an internal host whose identity
    is not to be widely broadcast. */

    if (!done)
      {
      if (errno == ETIMEDOUT)
        {
        HDEBUG(D_verify) debug_printf("SMTP timeout\n");
        send_quit = FALSE;
        }
#ifdef EXPERIMENTAL_INTERNATIONAL
      else if (errno == ERRNO_UTF8_FWD)
	{
	extern int acl_where;	/* src/acl.c */
	errno = 0;
	addr->message = string_sprintf(
	    "response to \"%s\" from %s [%s] did not include SMTPUTF8",
            big_buffer, host->name, host->address);
        addr->user_message = acl_where == ACL_WHERE_RCPT
	  ? US"533 mailbox name not allowed"
	  : US"550 mailbox unavailable";
	yield = FAIL;
	done = TRUE;
	}
#endif
      else if (errno == 0)
        {
        if (*responsebuffer == 0) Ustrcpy(responsebuffer, US"connection dropped");

        addr->message =
          string_sprintf("response to \"%s\" from %s [%s] was: %s",
            big_buffer, host->name, host->address,
            string_printing(responsebuffer));

        addr->user_message = is_recipient?
          string_sprintf("Callout verification failed:\n%s", responsebuffer)
          :
          string_sprintf("Called:   %s\nSent:     %s\nResponse: %s",
            host->address, big_buffer, responsebuffer);

        /* Hard rejection ends the process */

        if (responsebuffer[0] == '5')   /* Address rejected */
          {
          yield = FAIL;
          done = TRUE;
          }
        }
      }

    /* End the SMTP conversation and close the connection. */

    /* Cutthrough - on a successfull connect and recipient-verify with
    use-sender and we are 1st rcpt and have no cutthrough conn so far
    here is where we want to leave the conn open */
    if (  cutthrough.delivery
       && rcpt_count == 1
       && done
       && yield == OK
       && (options & (vopt_callout_recipsender|vopt_callout_recippmaster)) == vopt_callout_recipsender
       && !random_local_part
       && !pm_mailfrom
       && cutthrough.fd < 0
       && !lmtp
       )
      {
      cutthrough.fd = outblock.sock;	/* We assume no buffer in use in the outblock */
      cutthrough.nrcpt = 1;
      cutthrough.interface = interface;
      cutthrough.host = *host;
      cutthrough.addr = *addr;		/* Save the address_item for later logging */
      cutthrough.addr.next =	  NULL;
      cutthrough.addr.host_used = &cutthrough.host;
      if (addr->parent)
        *(cutthrough.addr.parent = store_get(sizeof(address_item))) =
	  *addr->parent;
      ctblock.buffer = ctbuffer;
      ctblock.buffersize = sizeof(ctbuffer);
      ctblock.ptr = ctbuffer;
      /* ctblock.cmd_count = 0; ctblock.authenticating = FALSE; */
      ctblock.sock = cutthrough.fd;
      }
    else
      {
      /* Ensure no cutthrough on multiple address verifies */
      if (options & vopt_callout_recipsender)
        cancel_cutthrough_connection("multiple verify calls");
      if (send_quit) (void)smtp_write_command(&outblock, FALSE, "QUIT\r\n");

#ifdef SUPPORT_TLS
      tls_close(FALSE, TRUE);
#endif
      (void)close(inblock.sock);
#ifdef EXPERIMENTAL_EVENT
      (void) event_raise(addr->transport->event_action,
			      US"tcp:close", NULL);
#endif
      }

    }    /* Loop through all hosts, while !done */
  }

/* If we get here with done == TRUE, a successful callout happened, and yield
will be set OK or FAIL according to the response to the RCPT command.
Otherwise, we looped through the hosts but couldn't complete the business.
However, there may be domain-specific information to cache in both cases.

The value of the result field in the new_domain record is ccache_unknown if
there was an error before or with MAIL FROM:, and errno was not zero,
implying some kind of I/O error. We don't want to write the cache in that case.
Otherwise the value is ccache_accept, ccache_reject, or ccache_reject_mfnull. */

if (!callout_no_cache && new_domain_record.result != ccache_unknown)
  {
  if ((dbm_file = dbfn_open(US"callout", O_RDWR|O_CREAT, &dbblock, FALSE))
       == NULL)
    {
    HDEBUG(D_verify) debug_printf("callout cache: not available\n");
    }
  else
    {
    (void)dbfn_write(dbm_file, addr->domain, &new_domain_record,
      (int)sizeof(dbdata_callout_cache));
    HDEBUG(D_verify) debug_printf("wrote callout cache domain record:\n"
      "  result=%d postmaster=%d random=%d\n",
      new_domain_record.result,
      new_domain_record.postmaster_result,
      new_domain_record.random_result);
    }
  }

/* If a definite result was obtained for the callout, cache it unless caching
is disabled. */

if (done)
  {
  if (!callout_no_cache && new_address_record.result != ccache_unknown)
    {
    if (dbm_file == NULL)
      dbm_file = dbfn_open(US"callout", O_RDWR|O_CREAT, &dbblock, FALSE);
    if (dbm_file == NULL)
      {
      HDEBUG(D_verify) debug_printf("no callout cache available\n");
      }
    else
      {
      (void)dbfn_write(dbm_file, address_key, &new_address_record,
        (int)sizeof(dbdata_callout_cache_address));
      HDEBUG(D_verify) debug_printf("wrote %s callout cache address record\n",
        (new_address_record.result == ccache_accept)? "positive" : "negative");
      }
    }
  }    /* done */

/* Failure to connect to any host, or any response other than 2xx or 5xx is a
temporary error. If there was only one host, and a response was received, leave
it alone if supplying details. Otherwise, give a generic response. */

else   /* !done */
  {
  uschar *dullmsg = string_sprintf("Could not complete %s verify callout",
    is_recipient? "recipient" : "sender");
  yield = DEFER;

  if (host_list->next != NULL || addr->message == NULL) addr->message = dullmsg;

  addr->user_message = (!smtp_return_error_details)? dullmsg :
    string_sprintf("%s for <%s>.\n"
      "The mail server(s) for the domain may be temporarily unreachable, or\n"
      "they may be permanently unreachable from this server. In the latter case,\n%s",
      dullmsg, addr->address,
      is_recipient?
        "the address will never be accepted."
        :
        "you need to change the address or create an MX record for its domain\n"
        "if it is supposed to be generally accessible from the Internet.\n"
        "Talk to your mail administrator for details.");

  /* Force a specific error code */

  addr->basic_errno = ERRNO_CALLOUTDEFER;
  }

/* Come here from within the cache-reading code on fast-track exit. */

END_CALLOUT:
if (dbm_file != NULL) dbfn_close(dbm_file);
return yield;
}



/* Called after recipient-acl to get a cutthrough connection open when
   one was requested and a recipient-verify wasn't subsequently done.
*/
void
open_cutthrough_connection( address_item * addr )
{
address_item addr2;

/* Use a recipient-verify-callout to set up the cutthrough connection. */
/* We must use a copy of the address for verification, because it might
get rewritten. */

addr2 = *addr;
HDEBUG(D_acl) debug_printf("----------- %s cutthrough setup ------------\n",
  rcpt_count > 1 ? "more" : "start");
(void) verify_address(&addr2, NULL,
	vopt_is_recipient | vopt_callout_recipsender | vopt_callout_no_cache,
	CUTTHROUGH_CMD_TIMEOUT, -1, -1,
	NULL, NULL, NULL);
HDEBUG(D_acl) debug_printf("----------- end cutthrough setup ------------\n");
return;
}



/* Send given number of bytes from the buffer */
static BOOL
cutthrough_send(int n)
{
if(cutthrough.fd < 0)
  return TRUE;

if(
#ifdef SUPPORT_TLS
   (tls_out.active == cutthrough.fd) ? tls_write(FALSE, ctblock.buffer, n) :
#endif
   send(cutthrough.fd, ctblock.buffer, n, 0) > 0
  )
{
  transport_count += n;
  ctblock.ptr= ctblock.buffer;
  return TRUE;
}

HDEBUG(D_transport|D_acl) debug_printf("cutthrough_send failed: %s\n", strerror(errno));
return FALSE;
}



static BOOL
_cutthrough_puts(uschar * cp, int n)
{
while(n--)
 {
 if(ctblock.ptr >= ctblock.buffer+ctblock.buffersize)
   if(!cutthrough_send(ctblock.buffersize))
     return FALSE;

 *ctblock.ptr++ = *cp++;
 }
return TRUE;
}

/* Buffered output of counted data block.   Return boolean success */
BOOL
cutthrough_puts(uschar * cp, int n)
{
if (cutthrough.fd < 0)       return TRUE;
if (_cutthrough_puts(cp, n)) return TRUE;
cancel_cutthrough_connection("transmit failed");
return FALSE;
}


static BOOL
_cutthrough_flush_send(void)
{
int n= ctblock.ptr-ctblock.buffer;

if(n>0)
  if(!cutthrough_send(n))
    return FALSE;
return TRUE;
}


/* Send out any bufferred output.  Return boolean success. */
BOOL
cutthrough_flush_send(void)
{
if (_cutthrough_flush_send()) return TRUE;
cancel_cutthrough_connection("transmit failed");
return FALSE;
}


BOOL
cutthrough_put_nl(void)
{
return cutthrough_puts(US"\r\n", 2);
}


/* Get and check response from cutthrough target */
static uschar
cutthrough_response(char expect, uschar ** copy)
{
smtp_inblock inblock;
uschar inbuffer[4096];
uschar responsebuffer[4096];

inblock.buffer = inbuffer;
inblock.buffersize = sizeof(inbuffer);
inblock.ptr = inbuffer;
inblock.ptrend = inbuffer;
inblock.sock = cutthrough.fd;
/* this relies on (inblock.sock == tls_out.active) */
if(!smtp_read_response(&inblock, responsebuffer, sizeof(responsebuffer), expect, CUTTHROUGH_DATA_TIMEOUT))
  cancel_cutthrough_connection("target timeout on read");

if(copy != NULL)
  {
  uschar * cp;
  *copy = cp = string_copy(responsebuffer);
  /* Trim the trailing end of line */
  cp += Ustrlen(responsebuffer);
  if(cp > *copy  &&  cp[-1] == '\n') *--cp = '\0';
  if(cp > *copy  &&  cp[-1] == '\r') *--cp = '\0';
  }

return responsebuffer[0];
}


/* Negotiate dataphase with the cutthrough target, returning success boolean */
BOOL
cutthrough_predata(void)
{
if(cutthrough.fd < 0)
  return FALSE;

HDEBUG(D_transport|D_acl|D_v) debug_printf("  SMTP>> DATA\n");
cutthrough_puts(US"DATA\r\n", 6);
cutthrough_flush_send();

/* Assume nothing buffered.  If it was it gets ignored. */
return cutthrough_response('3', NULL) == '3';
}


/* fd and use_crlf args only to match write_chunk() */
static BOOL
cutthrough_write_chunk(int fd, uschar * s, int len, BOOL use_crlf)
{
uschar * s2;
while(s && (s2 = Ustrchr(s, '\n')))
 {
 if(!cutthrough_puts(s, s2-s) || !cutthrough_put_nl())
  return FALSE;
 s = s2+1;
 }
return TRUE;
}


/* Buffered send of headers.  Return success boolean. */
/* Expands newlines to wire format (CR,NL).           */
/* Also sends header-terminating blank line.          */
BOOL
cutthrough_headers_send(void)
{
if(cutthrough.fd < 0)
  return FALSE;

/* We share a routine with the mainline transport to handle header add/remove/rewrites,
   but having a separate buffered-output function (for now)
*/
HDEBUG(D_acl) debug_printf("----------- start cutthrough headers send -----------\n");

if (!transport_headers_send(&cutthrough.addr, cutthrough.fd,
	cutthrough.addr.transport->add_headers,
	cutthrough.addr.transport->remove_headers,
	&cutthrough_write_chunk, TRUE,
	cutthrough.addr.transport->rewrite_rules,
	cutthrough.addr.transport->rewrite_existflags))
  return FALSE;

HDEBUG(D_acl) debug_printf("----------- done cutthrough headers send ------------\n");
return TRUE;
}


static void
close_cutthrough_connection(const char * why)
{
if(cutthrough.fd >= 0)
  {
  /* We could be sending this after a bunch of data, but that is ok as
     the only way to cancel the transfer in dataphase is to drop the tcp
     conn before the final dot.
  */
  ctblock.ptr = ctbuffer;
  HDEBUG(D_transport|D_acl|D_v) debug_printf("  SMTP>> QUIT\n");
  _cutthrough_puts(US"QUIT\r\n", 6);	/* avoid recursion */
  _cutthrough_flush_send();
  /* No wait for response */

  #ifdef SUPPORT_TLS
  tls_close(FALSE, TRUE);
  #endif
  (void)close(cutthrough.fd);
  cutthrough.fd = -1;
  HDEBUG(D_acl) debug_printf("----------- cutthrough shutdown (%s) ------------\n", why);
  }
ctblock.ptr = ctbuffer;
}

void
cancel_cutthrough_connection(const char * why)
{
close_cutthrough_connection(why);
cutthrough.delivery = FALSE;
}




/* Have senders final-dot.  Send one to cutthrough target, and grab the response.
   Log an OK response as a transmission.
   Close the connection.
   Return smtp response-class digit.
*/
uschar *
cutthrough_finaldot(void)
{
uschar res;
address_item * addr;
HDEBUG(D_transport|D_acl|D_v) debug_printf("  SMTP>> .\n");

/* Assume data finshed with new-line */
if(  !cutthrough_puts(US".", 1)
  || !cutthrough_put_nl()
  || !cutthrough_flush_send()
  )
  return cutthrough.addr.message;

res = cutthrough_response('2', &cutthrough.addr.message);
for (addr = &cutthrough.addr; addr; addr = addr->next)
  {
  addr->message = cutthrough.addr.message;
  switch(res)
    {
    case '2':
      delivery_log(LOG_MAIN, addr, (int)'>', NULL);
      close_cutthrough_connection("delivered");
      break;

    case '4':
      delivery_log(LOG_MAIN, addr, 0,
	US"tmp-reject from cutthrough after DATA:");
      break;

    case '5':
      delivery_log(LOG_MAIN|LOG_REJECT, addr, 0,
	US"rejected after DATA:");
      break;

    default:
      break;
    }
  }
return cutthrough.addr.message;
}



/*************************************************
*           Copy error to toplevel address       *
*************************************************/

/* This function is used when a verify fails or defers, to ensure that the
failure or defer information is in the original toplevel address. This applies
when an address is redirected to a single new address, and the failure or
deferral happens to the child address.

Arguments:
  vaddr       the verify address item
  addr        the final address item
  yield       FAIL or DEFER

Returns:      the value of YIELD
*/

static int
copy_error(address_item *vaddr, address_item *addr, int yield)
{
if (addr != vaddr)
  {
  vaddr->message = addr->message;
  vaddr->user_message = addr->user_message;
  vaddr->basic_errno = addr->basic_errno;
  vaddr->more_errno = addr->more_errno;
  vaddr->prop.address_data = addr->prop.address_data;
  copyflag(vaddr, addr, af_pass_message);
  }
return yield;
}




/**************************************************
* printf that automatically handles TLS if needed *
***************************************************/

/* This function is used by verify_address() as a substitute for all fprintf()
calls; a direct fprintf() will not produce output in a TLS SMTP session, such
as a response to an EXPN command.  smtp_in.c makes smtp_printf available but
that assumes that we always use the smtp_out FILE* when not using TLS or the
ssl buffer when we are.  Instead we take a FILE* parameter and check to see if
that is smtp_out; if so, smtp_printf() with TLS support, otherwise regular
fprintf().

Arguments:
  f           the candidate FILE* to write to
  format      format string
  ...         optional arguments

Returns:
              nothing
*/

static void PRINTF_FUNCTION(2,3)
respond_printf(FILE *f, const char *format, ...)
{
va_list ap;

va_start(ap, format);
if (smtp_out && (f == smtp_out))
  smtp_vprintf(format, ap);
else
  vfprintf(f, format, ap);
va_end(ap);
}



/*************************************************
*            Verify an email address             *
*************************************************/

/* This function is used both for verification (-bv and at other times) and
address testing (-bt), which is indicated by address_test_mode being set.

Arguments:
  vaddr            contains the address to verify; the next field in this block
                     must be NULL
  f                if not NULL, write the result to this file
  options          various option bits:
                     vopt_fake_sender => this sender verify is not for the real
                       sender (it was verify=sender=xxxx or an address from a
                       header line) - rewriting must not change sender_address
                     vopt_is_recipient => this is a recipient address, otherwise
                       it's a sender address - this affects qualification and
                       rewriting and messages from callouts
                     vopt_qualify => qualify an unqualified address; else error
                     vopt_expn => called from SMTP EXPN command
                     vopt_success_on_redirect => when a new address is generated
                       the verification instantly succeeds

                     These ones are used by do_callout() -- the options variable
                       is passed to it.

                     vopt_callout_fullpm => if postmaster check, do full one
                     vopt_callout_no_cache => don't use callout cache
                     vopt_callout_random => do the "random" thing
                     vopt_callout_recipsender => use real sender for recipient
                     vopt_callout_recippmaster => use postmaster for recipient

  callout          if > 0, specifies that callout is required, and gives timeout
                     for individual commands
  callout_overall  if > 0, gives overall timeout for the callout function;
                   if < 0, a default is used (see do_callout())
  callout_connect  the connection timeout for callouts
  se_mailfrom      when callout is requested to verify a sender, use this
                     in MAIL FROM; NULL => ""
  pm_mailfrom      when callout is requested, if non-NULL, do the postmaster
                     thing and use this as the sender address (may be "")

  routed           if not NULL, set TRUE if routing succeeded, so we can
                     distinguish between routing failed and callout failed

Returns:           OK      address verified
                   FAIL    address failed to verify
                   DEFER   can't tell at present
*/

int
verify_address(address_item *vaddr, FILE *f, int options, int callout,
  int callout_overall, int callout_connect, uschar *se_mailfrom,
  uschar *pm_mailfrom, BOOL *routed)
{
BOOL allok = TRUE;
BOOL full_info = (f == NULL)? FALSE : (debug_selector != 0);
BOOL is_recipient = (options & vopt_is_recipient) != 0;
BOOL expn         = (options & vopt_expn) != 0;
BOOL success_on_redirect = (options & vopt_success_on_redirect) != 0;
int i;
int yield = OK;
int verify_type = expn? v_expn :
     address_test_mode? v_none :
          is_recipient? v_recipient : v_sender;
address_item *addr_list;
address_item *addr_new = NULL;
address_item *addr_remote = NULL;
address_item *addr_local = NULL;
address_item *addr_succeed = NULL;
uschar **failure_ptr = is_recipient?
  &recipient_verify_failure : &sender_verify_failure;
uschar *ko_prefix, *cr;
uschar *address = vaddr->address;
uschar *save_sender;
uschar null_sender[] = { 0 };             /* Ensure writeable memory */

/* Clear, just in case */

*failure_ptr = NULL;

/* Set up a prefix and suffix for error message which allow us to use the same
output statements both in EXPN mode (where an SMTP response is needed) and when
debugging with an output file. */

if (expn)
  {
  ko_prefix = US"553 ";
  cr = US"\r";
  }
else ko_prefix = cr = US"";

/* Add qualify domain if permitted; otherwise an unqualified address fails. */

if (parse_find_at(address) == NULL)
  {
  if ((options & vopt_qualify) == 0)
    {
    if (f != NULL)
      respond_printf(f, "%sA domain is required for \"%s\"%s\n",
        ko_prefix, address, cr);
    *failure_ptr = US"qualify";
    return FAIL;
    }
  address = rewrite_address_qualify(address, is_recipient);
  }

DEBUG(D_verify)
  {
  debug_printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  debug_printf("%s %s\n", address_test_mode? "Testing" : "Verifying", address);
  }

/* Rewrite and report on it. Clear the domain and local part caches - these
may have been set by domains and local part tests during an ACL. */

if (global_rewrite_rules != NULL)
  {
  uschar *old = address;
  address = rewrite_address(address, is_recipient, FALSE,
    global_rewrite_rules, rewrite_existflags);
  if (address != old)
    {
    for (i = 0; i < (MAX_NAMED_LIST * 2)/32; i++) vaddr->localpart_cache[i] = 0;
    for (i = 0; i < (MAX_NAMED_LIST * 2)/32; i++) vaddr->domain_cache[i] = 0;
    if (f != NULL && !expn) fprintf(f, "Address rewritten as: %s\n", address);
    }
  }

/* If this is the real sender address, we must update sender_address at
this point, because it may be referred to in the routers. */

if ((options & (vopt_fake_sender|vopt_is_recipient)) == 0)
  sender_address = address;

/* If the address was rewritten to <> no verification can be done, and we have
to return OK. This rewriting is permitted only for sender addresses; for other
addresses, such rewriting fails. */

if (address[0] == 0) return OK;

/* Flip the legacy TLS-related variables over to the outbound set in case
they're used in the context of a transport used by verification. Reset them
at exit from this routine. */

tls_modify_variables(&tls_out);

/* Save a copy of the sender address for re-instating if we change it to <>
while verifying a sender address (a nice bit of self-reference there). */

save_sender = sender_address;

/* Update the address structure with the possibly qualified and rewritten
address. Set it up as the starting address on the chain of new addresses. */

vaddr->address = address;
addr_new = vaddr;

/* We need a loop, because an address can generate new addresses. We must also
cope with generated pipes and files at the top level. (See also the code and
comment in deliver.c.) However, it is usually the case that the router for
user's .forward files has its verify flag turned off.

If an address generates more than one child, the loop is used only when
full_info is set, and this can only be set locally. Remote enquiries just get
information about the top level address, not anything that it generated. */

while (addr_new != NULL)
  {
  int rc;
  address_item *addr = addr_new;

  addr_new = addr->next;
  addr->next = NULL;

  DEBUG(D_verify)
    {
    debug_printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    debug_printf("Considering %s\n", addr->address);
    }

  /* Handle generated pipe, file or reply addresses. We don't get these
  when handling EXPN, as it does only one level of expansion. */

  if (testflag(addr, af_pfr))
    {
    allok = FALSE;
    if (f != NULL)
      {
      BOOL allow;

      if (addr->address[0] == '>')
        {
        allow = testflag(addr, af_allow_reply);
        fprintf(f, "%s -> mail %s", addr->parent->address, addr->address + 1);
        }
      else
        {
        allow = (addr->address[0] == '|')?
          testflag(addr, af_allow_pipe) : testflag(addr, af_allow_file);
        fprintf(f, "%s -> %s", addr->parent->address, addr->address);
        }

      if (addr->basic_errno == ERRNO_BADTRANSPORT)
        fprintf(f, "\n*** Error in setting up pipe, file, or autoreply:\n"
          "%s\n", addr->message);
      else if (allow)
        fprintf(f, "\n  transport = %s\n", addr->transport->name);
      else
        fprintf(f, " *** forbidden ***\n");
      }
    continue;
    }

  /* Just in case some router parameter refers to it. */

  return_path = (addr->prop.errors_address != NULL)?
    addr->prop.errors_address : sender_address;

  /* Split the address into domain and local part, handling the %-hack if
  necessary, and then route it. While routing a sender address, set
  $sender_address to <> because that is what it will be if we were trying to
  send a bounce to the sender. */

  if (routed != NULL) *routed = FALSE;
  if ((rc = deliver_split_address(addr)) == OK)
    {
    if (!is_recipient) sender_address = null_sender;
    rc = route_address(addr, &addr_local, &addr_remote, &addr_new,
      &addr_succeed, verify_type);
    sender_address = save_sender;     /* Put back the real sender */
    }

  /* If routing an address succeeded, set the flag that remembers, for use when
  an ACL cached a sender verify (in case a callout fails). Then if routing set
  up a list of hosts or the transport has a host list, and the callout option
  is set, and we aren't in a host checking run, do the callout verification,
  and set another flag that notes that a callout happened. */

  if (rc == OK)
    {
    if (routed != NULL) *routed = TRUE;
    if (callout > 0)
      {
      host_item *host_list = addr->host_list;

      /* Make up some data for use in the case where there is no remote
      transport. */

      transport_feedback tf = {
        NULL,                       /* interface (=> any) */
        US"smtp",                   /* port */
        US"smtp",                   /* protocol */
        NULL,                       /* hosts */
        US"$smtp_active_hostname",  /* helo_data */
        FALSE,                      /* hosts_override */
        FALSE,                      /* hosts_randomize */
        FALSE,                      /* gethostbyname */
        TRUE,                       /* qualify_single */
        FALSE                       /* search_parents */
        };

      /* If verification yielded a remote transport, we want to use that
      transport's options, so as to mimic what would happen if we were really
      sending a message to this address. */

      if (addr->transport != NULL && !addr->transport->info->local)
        {
        (void)(addr->transport->setup)(addr->transport, addr, &tf, 0, 0, NULL);

        /* If the transport has hosts and the router does not, or if the
        transport is configured to override the router's hosts, we must build a
        host list of the transport's hosts, and find the IP addresses */

        if (tf.hosts != NULL && (host_list == NULL || tf.hosts_override))
          {
          uschar *s;
          const uschar *save_deliver_domain = deliver_domain;
          uschar *save_deliver_localpart = deliver_localpart;

          host_list = NULL;    /* Ignore the router's hosts */

          deliver_domain = addr->domain;
          deliver_localpart = addr->local_part;
          s = expand_string(tf.hosts);
          deliver_domain = save_deliver_domain;
          deliver_localpart = save_deliver_localpart;

          if (s == NULL)
            {
            log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand list of hosts "
              "\"%s\" in %s transport for callout: %s", tf.hosts,
              addr->transport->name, expand_string_message);
            }
          else
            {
            int flags;
            host_item *host, *nexthost;
            host_build_hostlist(&host_list, s, tf.hosts_randomize);

            /* Just ignore failures to find a host address. If we don't manage
            to find any addresses, the callout will defer. Note that more than
            one address may be found for a single host, which will result in
            additional host items being inserted into the chain. Hence we must
            save the next host first. */

            flags = HOST_FIND_BY_A;
            if (tf.qualify_single) flags |= HOST_FIND_QUALIFY_SINGLE;
            if (tf.search_parents) flags |= HOST_FIND_SEARCH_PARENTS;

            for (host = host_list; host != NULL; host = nexthost)
              {
              nexthost = host->next;
              if (tf.gethostbyname ||
                  string_is_ip_address(host->name, NULL) != 0)
                (void)host_find_byname(host, NULL, flags, NULL, TRUE);
              else
		{
		dnssec_domains * dnssec_domains = NULL;
		if (Ustrcmp(addr->transport->driver_name, "smtp") == 0)
		  {
		  smtp_transport_options_block * ob =
		      (smtp_transport_options_block *)
			addr->transport->options_block;
		  dnssec_domains = &ob->dnssec;
		  }

                (void)host_find_bydns(host, NULL, flags, NULL, NULL, NULL,
		  dnssec_domains, NULL, NULL);
		}
              }
            }
          }
        }

      /* Can only do a callout if we have at least one host! If the callout
      fails, it will have set ${sender,recipient}_verify_failure. */

      if (host_list != NULL)
        {
        HDEBUG(D_verify) debug_printf("Attempting full verification using callout\n");
        if (host_checking && !host_checking_callout)
          {
          HDEBUG(D_verify)
            debug_printf("... callout omitted by default when host testing\n"
              "(Use -bhc if you want the callouts to happen.)\n");
          }
        else
          {
#ifdef SUPPORT_TLS
	  deliver_set_expansions(addr);
#endif
	  verify_mode = is_recipient ? US"R" : US"S";
          rc = do_callout(addr, host_list, &tf, callout, callout_overall,
            callout_connect, options, se_mailfrom, pm_mailfrom);
	  verify_mode = NULL;
          }
        }
      else
        {
        HDEBUG(D_verify) debug_printf("Cannot do callout: neither router nor "
          "transport provided a host list\n");
        }
      }
    }

  /* Otherwise, any failure is a routing failure */

  else *failure_ptr = US"route";

  /* A router may return REROUTED if it has set up a child address as a result
  of a change of domain name (typically from widening). In this case we always
  want to continue to verify the new child. */

  if (rc == REROUTED) continue;

  /* Handle hard failures */

  if (rc == FAIL)
    {
    allok = FALSE;
    if (f != NULL)
      {
      address_item *p = addr->parent;

      respond_printf(f, "%s%s %s", ko_prefix,
        full_info? addr->address : address,
        address_test_mode? "is undeliverable" : "failed to verify");
      if (!expn && admin_user)
        {
        if (addr->basic_errno > 0)
          respond_printf(f, ": %s", strerror(addr->basic_errno));
        if (addr->message != NULL)
          respond_printf(f, ": %s", addr->message);
        }

      /* Show parents iff doing full info */

      if (full_info) while (p != NULL)
        {
        respond_printf(f, "%s\n    <-- %s", cr, p->address);
        p = p->parent;
        }
      respond_printf(f, "%s\n", cr);
      }
    cancel_cutthrough_connection("routing hard fail");

    if (!full_info)
    {
      yield = copy_error(vaddr, addr, FAIL);
      goto out;
    }
    else yield = FAIL;
    }

  /* Soft failure */

  else if (rc == DEFER)
    {
    allok = FALSE;
    if (f != NULL)
      {
      address_item *p = addr->parent;
      respond_printf(f, "%s%s cannot be resolved at this time", ko_prefix,
        full_info? addr->address : address);
      if (!expn && admin_user)
        {
        if (addr->basic_errno > 0)
          respond_printf(f, ": %s", strerror(addr->basic_errno));
        if (addr->message != NULL)
          respond_printf(f, ": %s", addr->message);
        else if (addr->basic_errno <= 0)
          respond_printf(f, ": unknown error");
        }

      /* Show parents iff doing full info */

      if (full_info) while (p != NULL)
        {
        respond_printf(f, "%s\n    <-- %s", cr, p->address);
        p = p->parent;
        }
      respond_printf(f, "%s\n", cr);
      }
    cancel_cutthrough_connection("routing soft fail");

    if (!full_info)
      {
      yield = copy_error(vaddr, addr, DEFER);
      goto out;
      }
    else if (yield == OK) yield = DEFER;
    }

  /* If we are handling EXPN, we do not want to continue to route beyond
  the top level (whose address is in "address"). */

  else if (expn)
    {
    uschar *ok_prefix = US"250-";
    if (addr_new == NULL)
      {
      if (addr_local == NULL && addr_remote == NULL)
        respond_printf(f, "250 mail to <%s> is discarded\r\n", address);
      else
        respond_printf(f, "250 <%s>\r\n", address);
      }
    else while (addr_new != NULL)
      {
      address_item *addr2 = addr_new;
      addr_new = addr2->next;
      if (addr_new == NULL) ok_prefix = US"250 ";
      respond_printf(f, "%s<%s>\r\n", ok_prefix, addr2->address);
      }
    yield = OK;
    goto out;
    }

  /* Successful routing other than EXPN. */

  else
    {
    /* Handle successful routing when short info wanted. Otherwise continue for
    other (generated) addresses. Short info is the operational case. Full info
    can be requested only when debug_selector != 0 and a file is supplied.

    There is a conflict between the use of aliasing as an alternate email
    address, and as a sort of mailing list. If an alias turns the incoming
    address into just one address (e.g. J.Caesar->jc44) you may well want to
    carry on verifying the generated address to ensure it is valid when
    checking incoming mail. If aliasing generates multiple addresses, you
    probably don't want to do this. Exim therefore treats the generation of
    just a single new address as a special case, and continues on to verify the
    generated address. */

    if (!full_info &&                    /* Stop if short info wanted AND */
         (((addr_new == NULL ||          /* No new address OR */
           addr_new->next != NULL ||     /* More than one new address OR */
           testflag(addr_new, af_pfr)))  /* New address is pfr */
         ||                              /* OR */
         (addr_new != NULL &&            /* At least one new address AND */
          success_on_redirect)))         /* success_on_redirect is set */
      {
      if (f != NULL) fprintf(f, "%s %s\n", address,
        address_test_mode? "is deliverable" : "verified");

      /* If we have carried on to verify a child address, we want the value
      of $address_data to be that of the child */

      vaddr->prop.address_data = addr->prop.address_data;
      yield = OK;
      goto out;
      }
    }
  }     /* Loop for generated addresses */

/* Display the full results of the successful routing, including any generated
addresses. Control gets here only when full_info is set, which requires f not
to be NULL, and this occurs only when a top-level verify is called with the
debugging switch on.

If there are no local and no remote addresses, and there were no pipes, files,
or autoreplies, and there were no errors or deferments, the message is to be
discarded, usually because of the use of :blackhole: in an alias file. */

if (allok && addr_local == NULL && addr_remote == NULL)
  {
  fprintf(f, "mail to %s is discarded\n", address);
  goto out;
  }

for (addr_list = addr_local, i = 0; i < 2; addr_list = addr_remote, i++)
  {
  while (addr_list != NULL)
    {
    address_item *addr = addr_list;
    address_item *p = addr->parent;
    addr_list = addr->next;

    fprintf(f, "%s", CS addr->address);
#ifdef EXPERIMENTAL_SRS
    if(addr->prop.srs_sender)
      fprintf(f, "    [srs = %s]", addr->prop.srs_sender);
#endif

    /* If the address is a duplicate, show something about it. */

    if (!testflag(addr, af_pfr))
      {
      tree_node *tnode;
      if ((tnode = tree_search(tree_duplicates, addr->unique)) != NULL)
        fprintf(f, "   [duplicate, would not be delivered]");
      else tree_add_duplicate(addr->unique, addr);
      }

    /* Now show its parents */

    while (p != NULL)
      {
      fprintf(f, "\n    <-- %s", p->address);
      p = p->parent;
      }
    fprintf(f, "\n  ");

    /* Show router, and transport */

    fprintf(f, "router = %s, ", addr->router->name);
    fprintf(f, "transport = %s\n", (addr->transport == NULL)? US"unset" :
      addr->transport->name);

    /* Show any hosts that are set up by a router unless the transport
    is going to override them; fiddle a bit to get a nice format. */

    if (addr->host_list != NULL && addr->transport != NULL &&
        !addr->transport->overrides_hosts)
      {
      host_item *h;
      int maxlen = 0;
      int maxaddlen = 0;
      for (h = addr->host_list; h != NULL; h = h->next)
        {
        int len = Ustrlen(h->name);
        if (len > maxlen) maxlen = len;
        len = (h->address != NULL)? Ustrlen(h->address) : 7;
        if (len > maxaddlen) maxaddlen = len;
        }
      for (h = addr->host_list; h != NULL; h = h->next)
        {
        int len = Ustrlen(h->name);
        fprintf(f, "  host %s ", h->name);
        while (len++ < maxlen) fprintf(f, " ");
        if (h->address != NULL)
          {
          fprintf(f, "[%s] ", h->address);
          len = Ustrlen(h->address);
          }
        else if (!addr->transport->info->local)  /* Omit [unknown] for local */
          {
          fprintf(f, "[unknown] ");
          len = 7;
          }
        else len = -3;
        while (len++ < maxaddlen) fprintf(f," ");
        if (h->mx >= 0) fprintf(f, "MX=%d", h->mx);
        if (h->port != PORT_NONE) fprintf(f, " port=%d", h->port);
        if (running_in_test_harness)
#ifndef DISABLE_DNSSEC
          fprintf(f, " ad=%s", h->dnssec==DS_YES ? "yes" : "no");
#else
          fprintf(f, " ad=no");
#endif
        if (h->status == hstatus_unusable) fprintf(f, " ** unusable **");
        fprintf(f, "\n");
        }
      }
    }
  }

/* Yield will be DEFER or FAIL if any one address has, only for full_info (which is
the -bv or -bt case). */

out:
tls_modify_variables(&tls_in);

return yield;
}




/*************************************************
*      Check headers for syntax errors           *
*************************************************/

/* This function checks those header lines that contain addresses, and verifies
that all the addresses therein are syntactially correct.

Arguments:
  msgptr     where to put an error message

Returns:     OK
             FAIL
*/

int
verify_check_headers(uschar **msgptr)
{
header_line *h;
uschar *colon, *s;
int yield = OK;

for (h = header_list; h != NULL && yield == OK; h = h->next)
  {
  if (h->type != htype_from &&
      h->type != htype_reply_to &&
      h->type != htype_sender &&
      h->type != htype_to &&
      h->type != htype_cc &&
      h->type != htype_bcc)
    continue;

  colon = Ustrchr(h->text, ':');
  s = colon + 1;
  while (isspace(*s)) s++;

  /* Loop for multiple addresses in the header, enabling group syntax. Note
  that we have to reset this after the header has been scanned. */

  parse_allow_group = TRUE;

  while (*s != 0)
    {
    uschar *ss = parse_find_address_end(s, FALSE);
    uschar *recipient, *errmess;
    int terminator = *ss;
    int start, end, domain;

    /* Temporarily terminate the string at this point, and extract the
    operative address within, allowing group syntax. */

    *ss = 0;
    recipient = parse_extract_address(s,&errmess,&start,&end,&domain,FALSE);
    *ss = terminator;

    /* Permit an unqualified address only if the message is local, or if the
    sending host is configured to be permitted to send them. */

    if (recipient != NULL && domain == 0)
      {
      if (h->type == htype_from || h->type == htype_sender)
        {
        if (!allow_unqualified_sender) recipient = NULL;
        }
      else
        {
        if (!allow_unqualified_recipient) recipient = NULL;
        }
      if (recipient == NULL) errmess = US"unqualified address not permitted";
      }

    /* It's an error if no address could be extracted, except for the special
    case of an empty address. */

    if (recipient == NULL && Ustrcmp(errmess, "empty address") != 0)
      {
      uschar *verb = US"is";
      uschar *t = ss;
      uschar *tt = colon;
      int len;

      /* Arrange not to include any white space at the end in the
      error message or the header name. */

      while (t > s && isspace(t[-1])) t--;
      while (tt > h->text && isspace(tt[-1])) tt--;

      /* Add the address that failed to the error message, since in a
      header with very many addresses it is sometimes hard to spot
      which one is at fault. However, limit the amount of address to
      quote - cases have been seen where, for example, a missing double
      quote in a humungous To: header creates an "address" that is longer
      than string_sprintf can handle. */

      len = t - s;
      if (len > 1024)
        {
        len = 1024;
        verb = US"begins";
        }

      /* deconst cast ok as we're passing a non-const to string_printing() */
      *msgptr = US string_printing(
        string_sprintf("%s: failing address in \"%.*s:\" header %s: %.*s",
          errmess, tt - h->text, h->text, verb, len, s));

      yield = FAIL;
      break;          /* Out of address loop */
      }

    /* Advance to the next address */

    s = ss + (terminator? 1:0);
    while (isspace(*s)) s++;
    }   /* Next address */

  parse_allow_group = FALSE;
  parse_found_group = FALSE;
  }     /* Next header unless yield has been set FALSE */

return yield;
}


/*************************************************
*      Check header names for 8-bit characters   *
*************************************************/

/* This function checks for invalid charcters in header names. See
RFC 5322, 2.2. and RFC 6532, 3.

Arguments:
  msgptr     where to put an error message

Returns:     OK
             FAIL
*/

int
verify_check_header_names_ascii(uschar **msgptr)
{
header_line *h;
uschar *colon, *s;

for (h = header_list; h != NULL; h = h->next)
  {
   colon = Ustrchr(h->text, ':');
   for(s = h->text; s < colon; s++)
     {
        if ((*s < 33) || (*s > 126))
        {
                *msgptr = string_sprintf("Invalid character in header \"%.*s\" found",
                                         colon - h->text, h->text);
                return FAIL;
        }
     }
  }
return OK;
}

/*************************************************
*          Check for blind recipients            *
*************************************************/

/* This function checks that every (envelope) recipient is mentioned in either
the To: or Cc: header lines, thus detecting blind carbon copies.

There are two ways of scanning that could be used: either scan the header lines
and tick off the recipients, or scan the recipients and check the header lines.
The original proposed patch did the former, but I have chosen to do the latter,
because (a) it requires no memory and (b) will use fewer resources when there
are many addresses in To: and/or Cc: and only one or two envelope recipients.

Arguments:   none
Returns:     OK    if there are no blind recipients
             FAIL  if there is at least one blind recipient
*/

int
verify_check_notblind(void)
{
int i;
for (i = 0; i < recipients_count; i++)
  {
  header_line *h;
  BOOL found = FALSE;
  uschar *address = recipients_list[i].address;

  for (h = header_list; !found && h != NULL; h = h->next)
    {
    uschar *colon, *s;

    if (h->type != htype_to && h->type != htype_cc) continue;

    colon = Ustrchr(h->text, ':');
    s = colon + 1;
    while (isspace(*s)) s++;

    /* Loop for multiple addresses in the header, enabling group syntax. Note
    that we have to reset this after the header has been scanned. */

    parse_allow_group = TRUE;

    while (*s != 0)
      {
      uschar *ss = parse_find_address_end(s, FALSE);
      uschar *recipient,*errmess;
      int terminator = *ss;
      int start, end, domain;

      /* Temporarily terminate the string at this point, and extract the
      operative address within, allowing group syntax. */

      *ss = 0;
      recipient = parse_extract_address(s,&errmess,&start,&end,&domain,FALSE);
      *ss = terminator;

      /* If we found a valid recipient that has a domain, compare it with the
      envelope recipient. Local parts are compared case-sensitively, domains
      case-insensitively. By comparing from the start with length "domain", we
      include the "@" at the end, which ensures that we are comparing the whole
      local part of each address. */

      if (recipient != NULL && domain != 0)
        {
        found = Ustrncmp(recipient, address, domain) == 0 &&
                strcmpic(recipient + domain, address + domain) == 0;
        if (found) break;
        }

      /* Advance to the next address */

      s = ss + (terminator? 1:0);
      while (isspace(*s)) s++;
      }   /* Next address */

    parse_allow_group = FALSE;
    parse_found_group = FALSE;
    }     /* Next header (if found is false) */

  if (!found) return FAIL;
  }       /* Next recipient */

return OK;
}



/*************************************************
*          Find if verified sender               *
*************************************************/

/* Usually, just a single address is verified as the sender of the message.
However, Exim can be made to verify other addresses as well (often related in
some way), and this is useful in some environments. There may therefore be a
chain of such addresses that have previously been tested. This function finds
whether a given address is on the chain.

Arguments:   the address to be verified
Returns:     pointer to an address item, or NULL
*/

address_item *
verify_checked_sender(uschar *sender)
{
address_item *addr;
for (addr = sender_verified_list; addr != NULL; addr = addr->next)
  if (Ustrcmp(sender, addr->address) == 0) break;
return addr;
}





/*************************************************
*             Get valid header address           *
*************************************************/

/* Scan the originator headers of the message, looking for an address that
verifies successfully. RFC 822 says:

    o   The "Sender" field mailbox should be sent  notices  of
        any  problems in transport or delivery of the original
        messages.  If there is no  "Sender"  field,  then  the
        "From" field mailbox should be used.

    o   If the "Reply-To" field exists, then the reply  should
        go to the addresses indicated in that field and not to
        the address(es) indicated in the "From" field.

So we check a Sender field if there is one, else a Reply_to field, else a From
field. As some strange messages may have more than one of these fields,
especially if they are resent- fields, check all of them if there is more than
one.

Arguments:
  user_msgptr      points to where to put a user error message
  log_msgptr       points to where to put a log error message
  callout          timeout for callout check (passed to verify_address())
  callout_overall  overall callout timeout (ditto)
  callout_connect  connect callout timeout (ditto)
  se_mailfrom      mailfrom for verify; NULL => ""
  pm_mailfrom      sender for pm callout check (passed to verify_address())
  options          callout options (passed to verify_address())
  verrno           where to put the address basic_errno

If log_msgptr is set to something without setting user_msgptr, the caller
normally uses log_msgptr for both things.

Returns:           result of the verification attempt: OK, FAIL, or DEFER;
                   FAIL is given if no appropriate headers are found
*/

int
verify_check_header_address(uschar **user_msgptr, uschar **log_msgptr,
  int callout, int callout_overall, int callout_connect, uschar *se_mailfrom,
  uschar *pm_mailfrom, int options, int *verrno)
{
static int header_types[] = { htype_sender, htype_reply_to, htype_from };
BOOL done = FALSE;
int yield = FAIL;
int i;

for (i = 0; i < 3 && !done; i++)
  {
  header_line *h;
  for (h = header_list; h != NULL && !done; h = h->next)
    {
    int terminator, new_ok;
    uschar *s, *ss, *endname;

    if (h->type != header_types[i]) continue;
    s = endname = Ustrchr(h->text, ':') + 1;

    /* Scan the addresses in the header, enabling group syntax. Note that we
    have to reset this after the header has been scanned. */

    parse_allow_group = TRUE;

    while (*s != 0)
      {
      address_item *vaddr;

      while (isspace(*s) || *s == ',') s++;
      if (*s == 0) break;        /* End of header */

      ss = parse_find_address_end(s, FALSE);

      /* The terminator is a comma or end of header, but there may be white
      space preceding it (including newline for the last address). Move back
      past any white space so we can check against any cached envelope sender
      address verifications. */

      while (isspace(ss[-1])) ss--;
      terminator = *ss;
      *ss = 0;

      HDEBUG(D_verify) debug_printf("verifying %.*s header address %s\n",
        (int)(endname - h->text), h->text, s);

      /* See if we have already verified this address as an envelope sender,
      and if so, use the previous answer. */

      vaddr = verify_checked_sender(s);

      if (vaddr != NULL &&                   /* Previously checked */
           (callout <= 0 ||                  /* No callout needed; OR */
            vaddr->special_action > 256))    /* Callout was done */
        {
        new_ok = vaddr->special_action & 255;
        HDEBUG(D_verify) debug_printf("previously checked as envelope sender\n");
        *ss = terminator;  /* Restore shortened string */
        }

      /* Otherwise we run the verification now. We must restore the shortened
      string before running the verification, so the headers are correct, in
      case there is any rewriting. */

      else
        {
        int start, end, domain;
        uschar *address = parse_extract_address(s, log_msgptr, &start, &end,
          &domain, FALSE);

        *ss = terminator;

        /* If we found an empty address, just carry on with the next one, but
        kill the message. */

        if (address == NULL && Ustrcmp(*log_msgptr, "empty address") == 0)
          {
          *log_msgptr = NULL;
          s = ss;
          continue;
          }

        /* If verification failed because of a syntax error, fail this
        function, and ensure that the failing address gets added to the error
        message. */

        if (address == NULL)
          {
          new_ok = FAIL;
          while (ss > s && isspace(ss[-1])) ss--;
          *log_msgptr = string_sprintf("syntax error in '%.*s' header when "
            "scanning for sender: %s in \"%.*s\"",
            endname - h->text, h->text, *log_msgptr, ss - s, s);
          yield = FAIL;
          done = TRUE;
          break;
          }

        /* Else go ahead with the sender verification. But it isn't *the*
        sender of the message, so set vopt_fake_sender to stop sender_address
        being replaced after rewriting or qualification. */

        else
          {
          vaddr = deliver_make_addr(address, FALSE);
          new_ok = verify_address(vaddr, NULL, options | vopt_fake_sender,
            callout, callout_overall, callout_connect, se_mailfrom,
            pm_mailfrom, NULL);
          }
        }

      /* We now have the result, either newly found, or cached. If we are
      giving out error details, set a specific user error. This means that the
      last of these will be returned to the user if all three fail. We do not
      set a log message - the generic one below will be used. */

      if (new_ok != OK)
        {
        *verrno = vaddr->basic_errno;
        if (smtp_return_error_details)
          {
          *user_msgptr = string_sprintf("Rejected after DATA: "
            "could not verify \"%.*s\" header address\n%s: %s",
            endname - h->text, h->text, vaddr->address, vaddr->message);
          }
        }

      /* Success or defer */

      if (new_ok == OK)
        {
        yield = OK;
        done = TRUE;
        break;
        }

      if (new_ok == DEFER) yield = DEFER;

      /* Move on to any more addresses in the header */

      s = ss;
      }     /* Next address */

    parse_allow_group = FALSE;
    parse_found_group = FALSE;
    }       /* Next header, unless done */
  }         /* Next header type unless done */

if (yield == FAIL && *log_msgptr == NULL)
  *log_msgptr = US"there is no valid sender in any header line";

if (yield == DEFER && *log_msgptr == NULL)
  *log_msgptr = US"all attempts to verify a sender in a header line deferred";

return yield;
}




/*************************************************
*            Get RFC 1413 identification         *
*************************************************/

/* Attempt to get an id from the sending machine via the RFC 1413 protocol. If
the timeout is set to zero, then the query is not done. There may also be lists
of hosts and nets which are exempt. To guard against malefactors sending
non-printing characters which could, for example, disrupt a message's headers,
make sure the string consists of printing characters only.

Argument:
  port    the port to connect to; usually this is IDENT_PORT (113), but when
          running in the test harness with -bh a different value is used.

Returns:  nothing

Side effect: any received ident value is put in sender_ident (NULL otherwise)
*/

void
verify_get_ident(int port)
{
int sock, host_af, qlen;
int received_sender_port, received_interface_port, n;
uschar *p;
uschar buffer[2048];

/* Default is no ident. Check whether we want to do an ident check for this
host. */

sender_ident = NULL;
if (rfc1413_query_timeout <= 0 || verify_check_host(&rfc1413_hosts) != OK)
  return;

DEBUG(D_ident) debug_printf("doing ident callback\n");

/* Set up a connection to the ident port of the remote host. Bind the local end
to the incoming interface address. If the sender host address is an IPv6
address, the incoming interface address will also be IPv6. */

host_af = (Ustrchr(sender_host_address, ':') == NULL)? AF_INET : AF_INET6;
sock = ip_socket(SOCK_STREAM, host_af);
if (sock < 0) return;

if (ip_bind(sock, host_af, interface_address, 0) < 0)
  {
  DEBUG(D_ident) debug_printf("bind socket for ident failed: %s\n",
    strerror(errno));
  goto END_OFF;
  }

if (ip_connect(sock, host_af, sender_host_address, port, rfc1413_query_timeout)
     < 0)
  {
  if (errno == ETIMEDOUT && (log_extra_selector & LX_ident_timeout) != 0)
    {
    log_write(0, LOG_MAIN, "ident connection to %s timed out",
      sender_host_address);
    }
  else
    {
    DEBUG(D_ident) debug_printf("ident connection to %s failed: %s\n",
      sender_host_address, strerror(errno));
    }
  goto END_OFF;
  }

/* Construct and send the query. */

sprintf(CS buffer, "%d , %d\r\n", sender_host_port, interface_port);
qlen = Ustrlen(buffer);
if (send(sock, buffer, qlen, 0) < 0)
  {
  DEBUG(D_ident) debug_printf("ident send failed: %s\n", strerror(errno));
  goto END_OFF;
  }

/* Read a response line. We put it into the rest of the buffer, using several
recv() calls if necessary. */

p = buffer + qlen;

for (;;)
  {
  uschar *pp;
  int count;
  int size = sizeof(buffer) - (p - buffer);

  if (size <= 0) goto END_OFF;   /* Buffer filled without seeing \n. */
  count = ip_recv(sock, p, size, rfc1413_query_timeout);
  if (count <= 0) goto END_OFF;  /* Read error or EOF */

  /* Scan what we just read, to see if we have reached the terminating \r\n. Be
  generous, and accept a plain \n terminator as well. The only illegal
  character is 0. */

  for (pp = p; pp < p + count; pp++)
    {
    if (*pp == 0) goto END_OFF;   /* Zero octet not allowed */
    if (*pp == '\n')
      {
      if (pp[-1] == '\r') pp--;
      *pp = 0;
      goto GOT_DATA;             /* Break out of both loops */
      }
    }

  /* Reached the end of the data without finding \n. Let the loop continue to
  read some more, if there is room. */

  p = pp;
  }

GOT_DATA:

/* We have received a line of data. Check it carefully. It must start with the
same two port numbers that we sent, followed by data as defined by the RFC. For
example,

  12345 , 25 : USERID : UNIX :root

However, the amount of white space may be different to what we sent. In the
"osname" field there may be several sub-fields, comma separated. The data we
actually want to save follows the third colon. Some systems put leading spaces
in it - we discard those. */

if (sscanf(CS buffer + qlen, "%d , %d%n", &received_sender_port,
      &received_interface_port, &n) != 2 ||
    received_sender_port != sender_host_port ||
    received_interface_port != interface_port)
  goto END_OFF;

p = buffer + qlen + n;
while(isspace(*p)) p++;
if (*p++ != ':') goto END_OFF;
while(isspace(*p)) p++;
if (Ustrncmp(p, "USERID", 6) != 0) goto END_OFF;
p += 6;
while(isspace(*p)) p++;
if (*p++ != ':') goto END_OFF;
while (*p != 0 && *p != ':') p++;
if (*p++ == 0) goto END_OFF;
while(isspace(*p)) p++;
if (*p == 0) goto END_OFF;

/* The rest of the line is the data we want. We turn it into printing
characters when we save it, so that it cannot mess up the format of any logging
or Received: lines into which it gets inserted. We keep a maximum of 127
characters. The deconst cast is ok as we fed a nonconst to string_printing() */

sender_ident = US string_printing(string_copyn(p, 127));
DEBUG(D_ident) debug_printf("sender_ident = %s\n", sender_ident);

END_OFF:
(void)close(sock);
return;
}




/*************************************************
*      Match host to a single host-list item     *
*************************************************/

/* This function compares a host (name or address) against a single item
from a host list. The host name gets looked up if it is needed and is not
already known. The function is called from verify_check_this_host() via
match_check_list(), which is why most of its arguments are in a single block.

Arguments:
  arg            the argument block (see below)
  ss             the host-list item
  valueptr       where to pass back looked up data, or NULL
  error          for error message when returning ERROR

The block contains:
  host_name      (a) the host name, or
                 (b) NULL, implying use sender_host_name and
                       sender_host_aliases, looking them up if required, or
                 (c) the empty string, meaning that only IP address matches
                       are permitted
  host_address   the host address
  host_ipv4      the IPv4 address taken from an IPv6 one

Returns:         OK      matched
                 FAIL    did not match
                 DEFER   lookup deferred
                 ERROR   (a) failed to find the host name or IP address, or
                         (b) unknown lookup type specified, or
                         (c) host name encountered when only IP addresses are
                               being matched
*/

int
check_host(void *arg, const uschar *ss, const uschar **valueptr, uschar **error)
{
check_host_block *cb = (check_host_block *)arg;
int mlen = -1;
int maskoffset;
BOOL iplookup = FALSE;
BOOL isquery = FALSE;
BOOL isiponly = cb->host_name != NULL && cb->host_name[0] == 0;
const uschar *t;
uschar *semicolon;
uschar **aliases;

/* Optimize for the special case when the pattern is "*". */

if (*ss == '*' && ss[1] == 0) return OK;

/* If the pattern is empty, it matches only in the case when there is no host -
this can occur in ACL checking for SMTP input using the -bs option. In this
situation, the host address is the empty string. */

if (cb->host_address[0] == 0) return (*ss == 0)? OK : FAIL;
if (*ss == 0) return FAIL;

/* If the pattern is precisely "@" then match against the primary host name,
provided that host name matching is permitted; if it's "@[]" match against the
local host's IP addresses. */

if (*ss == '@')
  {
  if (ss[1] == 0)
    {
    if (isiponly) return ERROR;
    ss = primary_hostname;
    }
  else if (Ustrcmp(ss, "@[]") == 0)
    {
    ip_address_item *ip;
    for (ip = host_find_interfaces(); ip != NULL; ip = ip->next)
      if (Ustrcmp(ip->address, cb->host_address) == 0) return OK;
    return FAIL;
    }
  }

/* If the pattern is an IP address, optionally followed by a bitmask count, do
a (possibly masked) comparision with the current IP address. */

if (string_is_ip_address(ss, &maskoffset) != 0)
  return (host_is_in_net(cb->host_address, ss, maskoffset)? OK : FAIL);

/* The pattern is not an IP address. A common error that people make is to omit
one component of an IPv4 address, either by accident, or believing that, for
example, 1.2.3/24 is the same as 1.2.3.0/24, or 1.2.3 is the same as 1.2.3.0,
which it isn't. (Those applications that do accept 1.2.3 as an IP address
interpret it as 1.2.0.3 because the final component becomes 16-bit - this is an
ancient specification.) To aid in debugging these cases, we give a specific
error if the pattern contains only digits and dots or contains a slash preceded
only by digits and dots (a slash at the start indicates a file name and of
course slashes may be present in lookups, but not preceded only by digits and
dots). */

for (t = ss; isdigit(*t) || *t == '.'; t++);
if (*t == 0 || (*t == '/' && t != ss))
  {
  *error = US"malformed IPv4 address or address mask";
  return ERROR;
  }

/* See if there is a semicolon in the pattern */

semicolon = Ustrchr(ss, ';');

/* If we are doing an IP address only match, then all lookups must be IP
address lookups, even if there is no "net-". */

if (isiponly)
  {
  iplookup = semicolon != NULL;
  }

/* Otherwise, if the item is of the form net[n]-lookup;<file|query> then it is
a lookup on a masked IP network, in textual form. We obey this code even if we
have already set iplookup, so as to skip over the "net-" prefix and to set the
mask length. The net- stuff really only applies to single-key lookups where the
key is implicit. For query-style lookups the key is specified in the query.
From release 4.30, the use of net- for query style is no longer needed, but we
retain it for backward compatibility. */

if (Ustrncmp(ss, "net", 3) == 0 && semicolon != NULL)
  {
  mlen = 0;
  for (t = ss + 3; isdigit(*t); t++) mlen = mlen * 10 + *t - '0';
  if (mlen == 0 && t == ss+3) mlen = -1;  /* No mask supplied */
  iplookup = (*t++ == '-');
  }
else t = ss;

/* Do the IP address lookup if that is indeed what we have */

if (iplookup)
  {
  int insize;
  int search_type;
  int incoming[4];
  void *handle;
  uschar *filename, *key, *result;
  uschar buffer[64];

  /* Find the search type */

  search_type = search_findtype(t, semicolon - t);

  if (search_type < 0) log_write(0, LOG_MAIN|LOG_PANIC_DIE, "%s",
    search_error_message);

  /* Adjust parameters for the type of lookup. For a query-style lookup, there
  is no file name, and the "key" is just the query. For query-style with a file
  name, we have to fish the file off the start of the query. For a single-key
  lookup, the key is the current IP address, masked appropriately, and
  reconverted to text form, with the mask appended. For IPv6 addresses, specify
  dot separators instead of colons, except when the lookup type is "iplsearch".
  */

  if (mac_islookup(search_type, lookup_absfilequery))
    {
    filename = semicolon + 1;
    key = filename;
    while (*key != 0 && !isspace(*key)) key++;
    filename = string_copyn(filename, key - filename);
    while (isspace(*key)) key++;
    }
  else if (mac_islookup(search_type, lookup_querystyle))
    {
    filename = NULL;
    key = semicolon + 1;
    }
  else   /* Single-key style */
    {
    int sep = (Ustrcmp(lookup_list[search_type]->name, "iplsearch") == 0)?
      ':' : '.';
    insize = host_aton(cb->host_address, incoming);
    host_mask(insize, incoming, mlen);
    (void)host_nmtoa(insize, incoming, mlen, buffer, sep);
    key = buffer;
    filename = semicolon + 1;
    }

  /* Now do the actual lookup; note that there is no search_close() because
  of the caching arrangements. */

  handle = search_open(filename, search_type, 0, NULL, NULL);
  if (handle == NULL) log_write(0, LOG_MAIN|LOG_PANIC_DIE, "%s",
    search_error_message);
  result = search_find(handle, filename, key, -1, NULL, 0, 0, NULL);
  if (valueptr != NULL) *valueptr = result;
  return (result != NULL)? OK : search_find_defer? DEFER: FAIL;
  }

/* The pattern is not an IP address or network reference of any kind. That is,
it is a host name pattern. If this is an IP only match, there's an error in the
host list. */

if (isiponly)
  {
  *error = US"cannot match host name in match_ip list";
  return ERROR;
  }

/* Check the characters of the pattern to see if they comprise only letters,
digits, full stops, and hyphens (the constituents of domain names). Allow
underscores, as they are all too commonly found. Sigh. Also, if
allow_utf8_domains is set, allow top-bit characters. */

for (t = ss; *t != 0; t++)
  if (!isalnum(*t) && *t != '.' && *t != '-' && *t != '_' &&
      (!allow_utf8_domains || *t < 128)) break;

/* If the pattern is a complete domain name, with no fancy characters, look up
its IP address and match against that. Note that a multi-homed host will add
items to the chain. */

if (*t == 0)
  {
  int rc;
  host_item h;
  h.next = NULL;
  h.name = ss;
  h.address = NULL;
  h.mx = MX_NONE;

  /* Using byname rather than bydns here means we cannot determine dnssec
  status.  On the other hand it is unclear how that could be either
  propagated up or enforced. */

  rc = host_find_byname(&h, NULL, HOST_FIND_QUALIFY_SINGLE, NULL, FALSE);
  if (rc == HOST_FOUND || rc == HOST_FOUND_LOCAL)
    {
    host_item *hh;
    for (hh = &h; hh != NULL; hh = hh->next)
      {
      if (host_is_in_net(hh->address, cb->host_address, 0)) return OK;
      }
    return FAIL;
    }
  if (rc == HOST_FIND_AGAIN) return DEFER;
  *error = string_sprintf("failed to find IP address for %s", ss);
  return ERROR;
  }

/* Almost all subsequent comparisons require the host name, and can be done
using the general string matching function. When this function is called for
outgoing hosts, the name is always given explicitly. If it is NULL, it means we
must use sender_host_name and its aliases, looking them up if necessary. */

if (cb->host_name != NULL)   /* Explicit host name given */
  return match_check_string(cb->host_name, ss, -1, TRUE, TRUE, TRUE,
    valueptr);

/* Host name not given; in principle we need the sender host name and its
aliases. However, for query-style lookups, we do not need the name if the
query does not contain $sender_host_name. From release 4.23, a reference to
$sender_host_name causes it to be looked up, so we don't need to do the lookup
on spec. */

if ((semicolon = Ustrchr(ss, ';')) != NULL)
  {
  const uschar *affix;
  int partial, affixlen, starflags, id;

  *semicolon = 0;
  id = search_findtype_partial(ss, &partial, &affix, &affixlen, &starflags);
  *semicolon=';';

  if (id < 0)                           /* Unknown lookup type */
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "%s in host list item \"%s\"",
      search_error_message, ss);
    return DEFER;
    }
  isquery = mac_islookup(id, lookup_querystyle|lookup_absfilequery);
  }

if (isquery)
  {
  switch(match_check_string(US"", ss, -1, TRUE, TRUE, TRUE, valueptr))
    {
    case OK:    return OK;
    case DEFER: return DEFER;
    default:    return FAIL;
    }
  }

/* Not a query-style lookup; must ensure the host name is present, and then we
do a check on the name and all its aliases. */

if (sender_host_name == NULL)
  {
  HDEBUG(D_host_lookup)
    debug_printf("sender host name required, to match against %s\n", ss);
  if (host_lookup_failed || host_name_lookup() != OK)
    {
    *error = string_sprintf("failed to find host name for %s",
      sender_host_address);;
    return ERROR;
    }
  host_build_sender_fullhost();
  }

/* Match on the sender host name, using the general matching function */

switch(match_check_string(sender_host_name, ss, -1, TRUE, TRUE, TRUE,
       valueptr))
  {
  case OK:    return OK;
  case DEFER: return DEFER;
  }

/* If there are aliases, try matching on them. */

aliases = sender_host_aliases;
while (*aliases != NULL)
  {
  switch(match_check_string(*aliases++, ss, -1, TRUE, TRUE, TRUE, valueptr))
    {
    case OK:    return OK;
    case DEFER: return DEFER;
    }
  }
return FAIL;
}




/*************************************************
*    Check a specific host matches a host list   *
*************************************************/

/* This function is passed a host list containing items in a number of
different formats and the identity of a host. Its job is to determine whether
the given host is in the set of hosts defined by the list. The host name is
passed as a pointer so that it can be looked up if needed and not already
known. This is commonly the case when called from verify_check_host() to check
an incoming connection. When called from elsewhere the host name should usually
be set.

This function is now just a front end to match_check_list(), which runs common
code for scanning a list. We pass it the check_host() function to perform a
single test.

Arguments:
  listptr              pointer to the host list
  cache_bits           pointer to cache for named lists, or NULL
  host_name            the host name or NULL, implying use sender_host_name and
                         sender_host_aliases, looking them up if required
  host_address         the IP address
  valueptr             if not NULL, data from a lookup is passed back here

Returns:    OK    if the host is in the defined set
            FAIL  if the host is not in the defined set,
            DEFER if a data lookup deferred (not a host lookup)

If the host name was needed in order to make a comparison, and could not be
determined from the IP address, the result is FAIL unless the item
"+allow_unknown" was met earlier in the list, in which case OK is returned. */

int
verify_check_this_host(const uschar **listptr, unsigned int *cache_bits,
  const uschar *host_name, const uschar *host_address, const uschar **valueptr)
{
int rc;
unsigned int *local_cache_bits = cache_bits;
const uschar *save_host_address = deliver_host_address;
check_host_block cb;
cb.host_name = host_name;
cb.host_address = host_address;

if (valueptr != NULL) *valueptr = NULL;

/* If the host address starts off ::ffff: it is an IPv6 address in
IPv4-compatible mode. Find the IPv4 part for checking against IPv4
addresses. */

cb.host_ipv4 = (Ustrncmp(host_address, "::ffff:", 7) == 0)?
  host_address + 7 : host_address;

/* During the running of the check, put the IP address into $host_address. In
the case of calls from the smtp transport, it will already be there. However,
in other calls (e.g. when testing ignore_target_hosts), it won't. Just to be on
the safe side, any existing setting is preserved, though as I write this
(November 2004) I can't see any cases where it is actually needed. */

deliver_host_address = host_address;
rc = match_check_list(
       listptr,                                /* the list */
       0,                                      /* separator character */
       &hostlist_anchor,                       /* anchor pointer */
       &local_cache_bits,                      /* cache pointer */
       check_host,                             /* function for testing */
       &cb,                                    /* argument for function */
       MCL_HOST,                               /* type of check */
       (host_address == sender_host_address)?
         US"host" : host_address,              /* text for debugging */
       valueptr);                              /* where to pass back data */
deliver_host_address = save_host_address;
return rc;
}




/*************************************************
*      Check the given host item matches a list  *
*************************************************/
int
verify_check_given_host(uschar **listptr, host_item *host)
{
return verify_check_this_host(CUSS listptr, NULL, host->name, host->address, NULL);
}

/*************************************************
*      Check the remote host matches a list      *
*************************************************/

/* This is a front end to verify_check_this_host(), created because checking
the remote host is a common occurrence. With luck, a good compiler will spot
the tail recursion and optimize it. If there's no host address, this is
command-line SMTP input - check against an empty string for the address.

Arguments:
  listptr              pointer to the host list

Returns:               the yield of verify_check_this_host(),
                       i.e. OK, FAIL, or DEFER
*/

int
verify_check_host(uschar **listptr)
{
return verify_check_this_host(CUSS listptr, sender_host_cache, NULL,
  (sender_host_address == NULL)? US"" : sender_host_address, NULL);
}





/*************************************************
*              Invert an IP address              *
*************************************************/

/* Originally just used for DNS xBL lists, now also used for the
reverse_ip expansion operator.

Arguments:
  buffer         where to put the answer
  address        the address to invert
*/

void
invert_address(uschar *buffer, uschar *address)
{
int bin[4];
uschar *bptr = buffer;

/* If this is an IPv4 address mapped into IPv6 format, adjust the pointer
to the IPv4 part only. */

if (Ustrncmp(address, "::ffff:", 7) == 0) address += 7;

/* Handle IPv4 address: when HAVE_IPV6 is false, the result of host_aton() is
always 1. */

if (host_aton(address, bin) == 1)
  {
  int i;
  int x = bin[0];
  for (i = 0; i < 4; i++)
    {
    sprintf(CS bptr, "%d.", x & 255);
    while (*bptr) bptr++;
    x >>= 8;
    }
  }

/* Handle IPv6 address. Actually, as far as I know, there are no IPv6 addresses
in any DNS black lists, and the format in which they will be looked up is
unknown. This is just a guess. */

#if HAVE_IPV6
else
  {
  int i, j;
  for (j = 3; j >= 0; j--)
    {
    int x = bin[j];
    for (i = 0; i < 8; i++)
      {
      sprintf(CS bptr, "%x.", x & 15);
      while (*bptr) bptr++;
      x >>= 4;
      }
    }
  }
#endif

/* Remove trailing period -- this is needed so that both arbitrary
dnsbl keydomains and inverted addresses may be combined with the
same format string, "%s.%s" */

*(--bptr) = 0;
}



/*************************************************
*          Perform a single dnsbl lookup         *
*************************************************/

/* This function is called from verify_check_dnsbl() below. It is also called
recursively from within itself when domain and domain_txt are different
pointers, in order to get the TXT record from the alternate domain.

Arguments:
  domain         the outer dnsbl domain
  domain_txt     alternate domain to lookup TXT record on success; when the
                   same domain is to be used, domain_txt == domain (that is,
                   the pointers must be identical, not just the text)
  keydomain      the current keydomain (for debug message)
  prepend        subdomain to lookup (like keydomain, but
                   reversed if IP address)
  iplist         the list of matching IP addresses, or NULL for "any"
  bitmask        true if bitmask matching is wanted
  match_type     condition for 'succeed' result
                   0 => Any RR in iplist     (=)
                   1 => No RR in iplist      (!=)
                   2 => All RRs in iplist    (==)
                   3 => Some RRs not in iplist (!==)
                   the two bits are defined as MT_NOT and MT_ALL
  defer_return   what to return for a defer

Returns:         OK if lookup succeeded
                 FAIL if not
*/

static int
one_check_dnsbl(uschar *domain, uschar *domain_txt, uschar *keydomain,
  uschar *prepend, uschar *iplist, BOOL bitmask, int match_type,
  int defer_return)
{
dns_answer dnsa;
dns_scan dnss;
tree_node *t;
dnsbl_cache_block *cb;
int old_pool = store_pool;
uschar query[256];         /* DNS domain max length */

/* Construct the specific query domainname */

if (!string_format(query, sizeof(query), "%s.%s", prepend, domain))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "dnslist query is too long "
    "(ignored): %s...", query);
  return FAIL;
  }

/* Look for this query in the cache. */

t = tree_search(dnsbl_cache, query);

/* If not cached from a previous lookup, we must do a DNS lookup, and
cache the result in permanent memory. */

if (t == NULL)
  {
  store_pool = POOL_PERM;

  /* Set up a tree entry to cache the lookup */

  t = store_get(sizeof(tree_node) + Ustrlen(query));
  Ustrcpy(t->name, query);
  t->data.ptr = cb = store_get(sizeof(dnsbl_cache_block));
  (void)tree_insertnode(&dnsbl_cache, t);

  /* Do the DNS loopup . */

  HDEBUG(D_dnsbl) debug_printf("new DNS lookup for %s\n", query);
  cb->rc = dns_basic_lookup(&dnsa, query, T_A);
  cb->text_set = FALSE;
  cb->text = NULL;
  cb->rhs = NULL;

  /* If the lookup succeeded, cache the RHS address. The code allows for
  more than one address - this was for complete generality and the possible
  use of A6 records. However, A6 records have been reduced to experimental
  status (August 2001) and may die out. So they may never get used at all,
  let alone in dnsbl records. However, leave the code here, just in case.

  Quite apart from one A6 RR generating multiple addresses, there are DNS
  lists that return more than one A record, so we must handle multiple
  addresses generated in that way as well. */

  if (cb->rc == DNS_SUCCEED)
    {
    dns_record *rr;
    dns_address **addrp = &(cb->rhs);
    for (rr = dns_next_rr(&dnsa, &dnss, RESET_ANSWERS);
         rr;
         rr = dns_next_rr(&dnsa, &dnss, RESET_NEXT))
      {
      if (rr->type == T_A)
        {
        dns_address *da = dns_address_from_rr(&dnsa, rr);
        if (da)
          {
          *addrp = da;
          while (da->next != NULL) da = da->next;
          addrp = &(da->next);
          }
        }
      }

    /* If we didn't find any A records, change the return code. This can
    happen when there is a CNAME record but there are no A records for what
    it points to. */

    if (cb->rhs == NULL) cb->rc = DNS_NODATA;
    }

  store_pool = old_pool;
  }

/* Previous lookup was cached */

else
  {
  HDEBUG(D_dnsbl) debug_printf("using result of previous DNS lookup\n");
  cb = t->data.ptr;
  }

/* We now have the result of the DNS lookup, either newly done, or cached
from a previous call. If the lookup succeeded, check against the address
list if there is one. This may be a positive equality list (introduced by
"="), a negative equality list (introduced by "!="), a positive bitmask
list (introduced by "&"), or a negative bitmask list (introduced by "!&").*/

if (cb->rc == DNS_SUCCEED)
  {
  dns_address *da = NULL;
  uschar *addlist = cb->rhs->address;

  /* For A and AAAA records, there may be multiple addresses from multiple
  records. For A6 records (currently not expected to be used) there may be
  multiple addresses from a single record. */

  for (da = cb->rhs->next; da != NULL; da = da->next)
    addlist = string_sprintf("%s, %s", addlist, da->address);

  HDEBUG(D_dnsbl) debug_printf("DNS lookup for %s succeeded (yielding %s)\n",
    query, addlist);

  /* Address list check; this can be either for equality, or via a bitmask.
  In the latter case, all the bits must match. */

  if (iplist != NULL)
    {
    for (da = cb->rhs; da != NULL; da = da->next)
      {
      int ipsep = ',';
      uschar ip[46];
      const uschar *ptr = iplist;
      uschar *res;

      /* Handle exact matching */

      if (!bitmask)
        {
        while ((res = string_nextinlist(&ptr, &ipsep, ip, sizeof(ip))) != NULL)
          {
          if (Ustrcmp(CS da->address, ip) == 0) break;
          }
        }

      /* Handle bitmask matching */

      else
        {
        int address[4];
        int mask = 0;

        /* At present, all known DNS blocking lists use A records, with
        IPv4 addresses on the RHS encoding the information they return. I
        wonder if this will linger on as the last vestige of IPv4 when IPv6
        is ubiquitous? Anyway, for now we use paranoia code to completely
        ignore IPv6 addresses. The default mask is 0, which always matches.
        We change this only for IPv4 addresses in the list. */

        if (host_aton(da->address, address) == 1) mask = address[0];

        /* Scan the returned addresses, skipping any that are IPv6 */

        while ((res = string_nextinlist(&ptr, &ipsep, ip, sizeof(ip))) != NULL)
          {
          if (host_aton(ip, address) != 1) continue;
          if ((address[0] & mask) == address[0]) break;
          }
        }

      /* If either

         (a) An IP address in an any ('=') list matched, or
         (b) No IP address in an all ('==') list matched

      then we're done searching. */

      if (((match_type & MT_ALL) != 0) == (res == NULL)) break;
      }

    /* If da == NULL, either

       (a) No IP address in an any ('=') list matched, or
       (b) An IP address in an all ('==') list didn't match

    so behave as if the DNSBL lookup had not succeeded, i.e. the host is not on
    the list. */

    if ((match_type == MT_NOT || match_type == MT_ALL) != (da == NULL))
      {
      HDEBUG(D_dnsbl)
        {
        uschar *res = NULL;
        switch(match_type)
          {
          case 0:
          res = US"was no match";
          break;
          case MT_NOT:
          res = US"was an exclude match";
          break;
          case MT_ALL:
          res = US"was an IP address that did not match";
          break;
          case MT_NOT|MT_ALL:
          res = US"were no IP addresses that did not match";
          break;
          }
        debug_printf("=> but we are not accepting this block class because\n");
        debug_printf("=> there %s for %s%c%s\n",
          res,
          ((match_type & MT_ALL) == 0)? "" : "=",
          bitmask? '&' : '=', iplist);
        }
      return FAIL;
      }
    }

  /* Either there was no IP list, or the record matched, implying that the
  domain is on the list. We now want to find a corresponding TXT record. If an
  alternate domain is specified for the TXT record, call this function
  recursively to look that up; this has the side effect of re-checking that
  there is indeed an A record at the alternate domain. */

  if (domain_txt != domain)
    return one_check_dnsbl(domain_txt, domain_txt, keydomain, prepend, NULL,
      FALSE, match_type, defer_return);

  /* If there is no alternate domain, look up a TXT record in the main domain
  if it has not previously been cached. */

  if (!cb->text_set)
    {
    cb->text_set = TRUE;
    if (dns_basic_lookup(&dnsa, query, T_TXT) == DNS_SUCCEED)
      {
      dns_record *rr;
      for (rr = dns_next_rr(&dnsa, &dnss, RESET_ANSWERS);
           rr != NULL;
           rr = dns_next_rr(&dnsa, &dnss, RESET_NEXT))
        if (rr->type == T_TXT) break;
      if (rr != NULL)
        {
        int len = (rr->data)[0];
        if (len > 511) len = 127;
        store_pool = POOL_PERM;
        cb->text = string_sprintf("%.*s", len, (const uschar *)(rr->data+1));
        store_pool = old_pool;
        }
      }
    }

  dnslist_value = addlist;
  dnslist_text = cb->text;
  return OK;
  }

/* There was a problem with the DNS lookup */

if (cb->rc != DNS_NOMATCH && cb->rc != DNS_NODATA)
  {
  log_write(L_dnslist_defer, LOG_MAIN,
    "DNS list lookup defer (probably timeout) for %s: %s", query,
    (defer_return == OK)?   US"assumed in list" :
    (defer_return == FAIL)? US"assumed not in list" :
                            US"returned DEFER");
  return defer_return;
  }

/* No entry was found in the DNS; continue for next domain */

HDEBUG(D_dnsbl)
  {
  debug_printf("DNS lookup for %s failed\n", query);
  debug_printf("=> that means %s is not listed at %s\n",
     keydomain, domain);
  }

return FAIL;
}




/*************************************************
*        Check host against DNS black lists      *
*************************************************/

/* This function runs checks against a list of DNS black lists, until one
matches. Each item on the list can be of the form

  domain=ip-address/key

The domain is the right-most domain that is used for the query, for example,
blackholes.mail-abuse.org. If the IP address is present, there is a match only
if the DNS lookup returns a matching IP address. Several addresses may be
given, comma-separated, for example: x.y.z=127.0.0.1,127.0.0.2.

If no key is given, what is looked up in the domain is the inverted IP address
of the current client host. If a key is given, it is used to construct the
domain for the lookup. For example:

  dsn.rfc-ignorant.org/$sender_address_domain

After finding a match in the DNS, the domain is placed in $dnslist_domain, and
then we check for a TXT record for an error message, and if found, save its
value in $dnslist_text. We also cache everything in a tree, to optimize
multiple lookups.

The TXT record is normally looked up in the same domain as the A record, but
when many lists are combined in a single DNS domain, this will not be a very
specific message. It is possible to specify a different domain for looking up
TXT records; this is given before the main domain, comma-separated. For
example:

  dnslists = http.dnsbl.sorbs.net,dnsbl.sorbs.net=127.0.0.2 : \
             socks.dnsbl.sorbs.net,dnsbl.sorbs.net=127.0.0.3

The caching ensures that only one lookup in dnsbl.sorbs.net is done.

Note: an address for testing RBL is 192.203.178.39
Note: an address for testing DUL is 192.203.178.4
Note: a domain for testing RFCI is example.tld.dsn.rfc-ignorant.org

Arguments:
  listptr      the domain/address/data list

Returns:    OK      successful lookup (i.e. the address is on the list), or
                      lookup deferred after +include_unknown
            FAIL    name not found, or no data found for the given type, or
                      lookup deferred after +exclude_unknown (default)
            DEFER   lookup failure, if +defer_unknown was set
*/

int
verify_check_dnsbl(const uschar **listptr)
{
int sep = 0;
int defer_return = FAIL;
const uschar *list = *listptr;
uschar *domain;
uschar *s;
uschar buffer[1024];
uschar revadd[128];        /* Long enough for IPv6 address */

/* Indicate that the inverted IP address is not yet set up */

revadd[0] = 0;

/* In case this is the first time the DNS resolver is being used. */

dns_init(FALSE, FALSE, FALSE);	/*XXX dnssec? */

/* Loop through all the domains supplied, until something matches */

while ((domain = string_nextinlist(&list, &sep, buffer, sizeof(buffer))) != NULL)
  {
  int rc;
  BOOL bitmask = FALSE;
  int match_type = 0;
  uschar *domain_txt;
  uschar *comma;
  uschar *iplist;
  uschar *key;

  HDEBUG(D_dnsbl) debug_printf("DNS list check: %s\n", domain);

  /* Deal with special values that change the behaviour on defer */

  if (domain[0] == '+')
    {
    if      (strcmpic(domain, US"+include_unknown") == 0) defer_return = OK;
    else if (strcmpic(domain, US"+exclude_unknown") == 0) defer_return = FAIL;
    else if (strcmpic(domain, US"+defer_unknown") == 0)   defer_return = DEFER;
    else
      log_write(0, LOG_MAIN|LOG_PANIC, "unknown item in dnslist (ignored): %s",
        domain);
    continue;
    }

  /* See if there's explicit data to be looked up */

  key = Ustrchr(domain, '/');
  if (key != NULL) *key++ = 0;

  /* See if there's a list of addresses supplied after the domain name. This is
  introduced by an = or a & character; if preceded by = we require all matches
  and if preceded by ! we invert the result. */

  iplist = Ustrchr(domain, '=');
  if (iplist == NULL)
    {
    bitmask = TRUE;
    iplist = Ustrchr(domain, '&');
    }

  if (iplist != NULL)                          /* Found either = or & */
    {
    if (iplist > domain && iplist[-1] == '!')  /* Handle preceding ! */
      {
      match_type |= MT_NOT;
      iplist[-1] = 0;
      }

    *iplist++ = 0;                             /* Terminate domain, move on */

    /* If we found = (bitmask == FALSE), check for == or =& */

    if (!bitmask && (*iplist == '=' || *iplist == '&'))
      {
      bitmask = *iplist++ == '&';
      match_type |= MT_ALL;
      }
    }

  /* If there is a comma in the domain, it indicates that a second domain for
  looking up TXT records is provided, before the main domain. Otherwise we must
  set domain_txt == domain. */

  domain_txt = domain;
  comma = Ustrchr(domain, ',');
  if (comma != NULL)
    {
    *comma++ = 0;
    domain = comma;
    }

  /* Check that what we have left is a sensible domain name. There is no reason
  why these domains should in fact use the same syntax as hosts and email
  domains, but in practice they seem to. However, there is little point in
  actually causing an error here, because that would no doubt hold up incoming
  mail. Instead, I'll just log it. */

  for (s = domain; *s != 0; s++)
    {
    if (!isalnum(*s) && *s != '-' && *s != '.' && *s != '_')
      {
      log_write(0, LOG_MAIN, "dnslists domain \"%s\" contains "
        "strange characters - is this right?", domain);
      break;
      }
    }

  /* Check the alternate domain if present */

  if (domain_txt != domain) for (s = domain_txt; *s != 0; s++)
    {
    if (!isalnum(*s) && *s != '-' && *s != '.' && *s != '_')
      {
      log_write(0, LOG_MAIN, "dnslists domain \"%s\" contains "
        "strange characters - is this right?", domain_txt);
      break;
      }
    }

  /* If there is no key string, construct the query by adding the domain name
  onto the inverted host address, and perform a single DNS lookup. */

  if (key == NULL)
    {
    if (sender_host_address == NULL) return FAIL;    /* can never match */
    if (revadd[0] == 0) invert_address(revadd, sender_host_address);
    rc = one_check_dnsbl(domain, domain_txt, sender_host_address, revadd,
      iplist, bitmask, match_type, defer_return);
    if (rc == OK)
      {
      dnslist_domain = string_copy(domain_txt);
      dnslist_matched = string_copy(sender_host_address);
      HDEBUG(D_dnsbl) debug_printf("=> that means %s is listed at %s\n",
        sender_host_address, dnslist_domain);
      }
    if (rc != FAIL) return rc;     /* OK or DEFER */
    }

  /* If there is a key string, it can be a list of domains or IP addresses to
  be concatenated with the main domain. */

  else
    {
    int keysep = 0;
    BOOL defer = FALSE;
    uschar *keydomain;
    uschar keybuffer[256];
    uschar keyrevadd[128];

    while ((keydomain = string_nextinlist(CUSS &key, &keysep, keybuffer,
            sizeof(keybuffer))) != NULL)
      {
      uschar *prepend = keydomain;

      if (string_is_ip_address(keydomain, NULL) != 0)
        {
        invert_address(keyrevadd, keydomain);
        prepend = keyrevadd;
        }

      rc = one_check_dnsbl(domain, domain_txt, keydomain, prepend, iplist,
        bitmask, match_type, defer_return);

      if (rc == OK)
        {
        dnslist_domain = string_copy(domain_txt);
        dnslist_matched = string_copy(keydomain);
        HDEBUG(D_dnsbl) debug_printf("=> that means %s is listed at %s\n",
          keydomain, dnslist_domain);
        return OK;
        }

      /* If the lookup deferred, remember this fact. We keep trying the rest
      of the list to see if we get a useful result, and if we don't, we return
      DEFER at the end. */

      if (rc == DEFER) defer = TRUE;
      }    /* continue with next keystring domain/address */

    if (defer) return DEFER;
    }
  }        /* continue with next dnsdb outer domain */

return FAIL;
}

/* vi: aw ai sw=2
*/
/* End of verify.c */
