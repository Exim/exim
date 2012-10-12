/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/
/* Experimental DMARC support.
   Copyright (c) Todd Lyons <tlyons@exim.org> 2012
   License: GPL */

/* Code for calling dmarc checks via libopendmarc. Called from acl.c. */

#include "exim.h"
#ifdef EXPERIMENTAL_DMARC

#include "dmarc.h"

OPENDMARC_LIB_T    dmarc_ctx;
DMARC_POLICY_T    *dmarc_pctx = NULL;
OPENDMARC_STATUS_T libdm_status;
BOOL dmarc_skip  = FALSE;
extern pdkim_signature  *dkim_signatures;
#ifdef EXPERIMENTAL_SPF
extern SPF_response_t   *spf_response;
uschar *spf_sender_domain = NULL;
uschar *human_readable = NULL;
#endif

/* dmarc_init sets up a context that can be re-used for several
   messages on the same SMTP connection (that come from the
   same host with the same HELO string) */

// int dmarc_init(uschar *spf_helo_domain, uschar *spf_remote_addr) {
int dmarc_init() {
  int *netmask   = NULL;   /* Ignored */
  int is_ipv6    = 0;
  char *tld_file = (dmarc_tld_file == NULL) ?
                   "/etc/exim/opendmarc.tlds" :
                   (char *)dmarc_tld_file;

  (void) memset(&dmarc_ctx, '\0', sizeof dmarc_ctx);
  dmarc_ctx.nscount = 0;
  libdm_status = opendmarc_policy_library_init(&dmarc_ctx);
  if (libdm_status != DMARC_PARSE_OKAY)
  {
    log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to init library: %s",
                         opendmarc_policy_status_to_str(libdm_status));
    dmarc_skip = TRUE;
  }
  if (opendmarc_tld_read_file(tld_file, NULL, NULL, NULL))
  {
    log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to load tld list %s: %d",
                         tld_file, errno);
    dmarc_skip = TRUE;
  }
  if (sender_host_address == NULL)
    dmarc_skip = TRUE;
  /* This catches locally originated email and startup errors above. */
  if ( dmarc_skip == FALSE )
  {
    is_ipv6 = string_is_ip_address(sender_host_address, netmask);
    is_ipv6 = (is_ipv6 == 6) ? TRUE :
              (is_ipv6 == 4) ? FALSE : FALSE;
    dmarc_pctx = opendmarc_policy_connect_init(sender_host_address, is_ipv6);
    if (dmarc_pctx == NULL )
    {
      log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure creating policy context: ip=%s",
                                       sender_host_address);
      dmarc_skip = TRUE;
    }
  }

  return 1;
}


/* dmarc_process adds the envelope sender address to the existing
   context (if any), retrieves the result, sets up expansion
   strings and evaluates the condition outcome. */

// int dmarc_process(uschar **listptr, uschar *spf_envelope_sender, int action) {
int dmarc_process(header_line *from_header) {
    int spf_result, sr, origin; /* used in SPF section */
    int da, sa;
    pdkim_signature *sig  = NULL;
    uschar *enforcement   = NULL;
    uschar *tmp_status    = NULL;
    BOOL has_dmarc_record = TRUE;

  /* Store the header From: sender domain for this part of DMARC.
   * If there is no from_header struct, then it's likely this message
   * is locally generated and relying on fixups to add it.  Just skip
   * the entire DMARC system if we can't find a From: header....or if
   * there was a previous error.
   */
  if (from_header == 0 || dmarc_skip == TRUE)
    dmarc_skip = TRUE;
  else
  {
    u_char *header_from_sender = NULL;
    /* I strongly encourage anybody who can make this better to contact me directly!
     * <cannonball> Is this an insane way to extract the email address from the From: header?
     * <jgh_hm> it's sure a horrid layer-crossing....
     * <cannonball> I'm not denying that :-/
     * <jgh_hm> there may well be no better though
     */
    header_from_sender = expand_string( string_sprintf("${extract{1}{:}{${addresses:%s}}}",
                                                       from_header->text) );
    /* The opendmarc library extracts the domain from the email address. */
    libdm_status = opendmarc_policy_store_from_domain(dmarc_pctx, header_from_sender);
    if (libdm_status != DMARC_PARSE_OKAY)
    {
      log_write(0, LOG_MAIN|LOG_PANIC, "failure to store header From: in DMARC: %s",
                           opendmarc_policy_status_to_str(libdm_status));
    }
  }

  /* Skip DMARC if connection is SMTP Auth. Temporarily, admin should
   * instead do this in the ACLs.  */
  if (dmarc_skip == FALSE && sender_host_authenticated == NULL)
  {
#ifdef EXPERIMENTAL_SPF
    /* Use the envelope sender domain for this part of DMARC */
    spf_sender_domain = expand_string(US"$sender_address_domain");
    if ( spf_response == NULL )
    {
      /* No spf data means null envelope sender so generate a domain name
       * from the sender_host_name || sender_helo_name  */
      if (spf_sender_domain == NULL)
      {
        spf_sender_domain = (sender_host_name == NULL) ? sender_helo_name : sender_host_name;
        uschar *subdomain = spf_sender_domain;
        int count = 0;
        while (subdomain && *subdomain != '.')
        {
          subdomain++;
          count++;
        }
        /* If parsed characters in temp var "subdomain" and is pointing to
         * a period now, get rid of the period and use that.  Otherwise
         * will use whatever was first set in spf_sender_domain.  Goal is to
         * generate a sane answer, not necessarily the right/best answer b/c
         * at this point with a null sender, it's a bounce message, making
         * the spf domain be subjective.  */
        if (count > 0 && *subdomain == '.')
        {
          subdomain++;
          spf_sender_domain = subdomain;
        }
        log_write(0, LOG_MAIN, "DMARC using synthesized SPF sender domain = %s\n",
                               spf_sender_domain);
        DEBUG(D_receive)
          debug_printf("DMARC using synthesized SPF sender domain = %s\n", spf_sender_domain);
      }
      spf_result = DMARC_POLICY_SPF_OUTCOME_NONE;
      origin = DMARC_POLICY_SPF_ORIGIN_HELO;
      human_readable = US"";
    }
    else
    {
      sr = spf_response->result;
      spf_result = (sr == SPF_RESULT_NEUTRAL)  ? DMARC_POLICY_SPF_OUTCOME_NONE :
                   (sr == SPF_RESULT_PASS)     ? DMARC_POLICY_SPF_OUTCOME_PASS :
                   (sr == SPF_RESULT_FAIL)     ? DMARC_POLICY_SPF_OUTCOME_FAIL :
                   (sr == SPF_RESULT_SOFTFAIL) ? DMARC_POLICY_SPF_OUTCOME_TMPFAIL :
                   DMARC_POLICY_SPF_OUTCOME_NONE;
      origin = DMARC_POLICY_SPF_ORIGIN_MAILFROM;
      human_readable = (uschar *)spf_response->header_comment;
      DEBUG(D_receive)
        debug_printf("DMARC using SPF sender domain = %s\n", spf_sender_domain);
    }
    libdm_status = opendmarc_policy_store_spf(dmarc_pctx, spf_sender_domain,
                                              spf_result, origin, human_readable);
    if (libdm_status != DMARC_PARSE_OKAY)
    {
      log_write(0, LOG_MAIN|LOG_PANIC, "failure to store spf for DMARC: %s",
                           opendmarc_policy_status_to_str(libdm_status));
    }
#endif /* EXPERIMENTAL_SPF */
    /* Now we cycle through the dkim signature results and put into
     * the opendmarc context, further building the DMARC reply.  */
    sig = dkim_signatures;
    while (sig != NULL)
    {
      int dkim_result, vs;
      vs = sig->verify_status;
      dkim_result = ( vs == PDKIM_VERIFY_PASS ) ? DMARC_POLICY_DKIM_OUTCOME_PASS :
		    ( vs == PDKIM_VERIFY_FAIL ) ? DMARC_POLICY_DKIM_OUTCOME_FAIL :
		    ( vs == PDKIM_VERIFY_INVALID ) ? DMARC_POLICY_DKIM_OUTCOME_TMPFAIL :
	            DMARC_POLICY_DKIM_OUTCOME_NONE;
      libdm_status = opendmarc_policy_store_dkim(dmarc_pctx, (uschar *)sig->domain,
		                                 dkim_result, US"");
      DEBUG(D_receive)
        debug_printf("DMARC adding DKIM sender domain = %s\n", sig->domain);
      if (libdm_status != DMARC_PARSE_OKAY)
      {
        log_write(0, LOG_MAIN|LOG_PANIC, "failure to store dkim (%s) for DMARC: %s",
			     sig->domain, opendmarc_policy_status_to_str(libdm_status));
      }
      sig = sig->next;
    }
    libdm_status = opendmarc_policy_query_dmarc(dmarc_pctx, US"");
    switch (libdm_status)
    {
      case DMARC_DNS_ERROR_NXDOMAIN:
      case DMARC_DNS_ERROR_NO_RECORD:
        has_dmarc_record = FALSE;
        break;
      case DMARC_PARSE_OKAY:
        DEBUG(D_receive)
          debug_printf("DMARC record found for %s\n", from_header->text);
        break;
      default:
        /* everything else, skip dmarc */
        has_dmarc_record = FALSE;
        break;
    }
    /* Can't use exim's string manipulation functions so allocate memory
     * for libopendmarc using its max hostname length definition. */
    uschar *dmarc_domain = (uschar *)calloc(DMARC_MAXHOSTNAMELEN, sizeof(uschar));
    libdm_status = opendmarc_policy_fetch_utilized_domain(dmarc_pctx, dmarc_domain,
		                                          DMARC_MAXHOSTNAMELEN-1);
    dmarc_used_domain = string_copy(dmarc_domain);
    free(dmarc_domain);
    if (libdm_status != DMARC_PARSE_OKAY)
    {
      log_write(0, LOG_MAIN|LOG_PANIC, "failure to read domainname used for DMARC lookup: %s",
                                       opendmarc_policy_status_to_str(libdm_status));
    }
    libdm_status = opendmarc_get_policy_to_enforce(dmarc_pctx);
    tmp_status =  (libdm_status == DMARC_POLICY_NONE)        ? US"none" :
                  (libdm_status == DMARC_POLICY_PASS)        ? US"accept" :
                  (libdm_status == DMARC_POLICY_REJECT)      ? US"reject" :
                  (libdm_status == DMARC_POLICY_QUARANTINE)  ? US"quarantine" :
                  (libdm_status == DMARC_POLICY_ABSENT)      ? US"norecord" :
                  (libdm_status == DMARC_FROM_DOMAIN_ABSENT) ? US"nofrom" :
                  US"error";
    dmarc_status = string_copy(tmp_status);
    enforcement = (libdm_status == DMARC_POLICY_NONE)        ? US"None, Accept" :
                  (libdm_status == DMARC_POLICY_PASS)        ? US"Accept" :
                  (libdm_status == DMARC_POLICY_REJECT)      ? US"Reject" :
                  (libdm_status == DMARC_POLICY_QUARANTINE)  ? US"Quarantine" :
                  (libdm_status == DMARC_POLICY_ABSENT)      ? US"No DMARC record" :
                  (libdm_status == DMARC_FROM_DOMAIN_ABSENT) ? US"No From: domain found" :
                  US"Internal Policy Error";
    dmarc_status_text = string_copy(enforcement);
    libdm_status = opendmarc_policy_fetch_alignment(dmarc_pctx, &da, &sa);
    if (libdm_status != DMARC_PARSE_OKAY)
    {
      log_write(0, LOG_MAIN|LOG_PANIC, "failure to read DMARC alignment: %s",
                                       opendmarc_policy_status_to_str(libdm_status));
    }
    if (has_dmarc_record == TRUE)
      log_write(0, LOG_MAIN, "DMARC results: spf_domain=%s dmarc_domain=%s "
                             "spf_align=%s dkim_align=%s enforcement='%s'",
                             spf_sender_domain, dmarc_used_domain,
                             (sa==DMARC_POLICY_SPF_ALIGNMENT_PASS) ?"yes":"no",
                             (da==DMARC_POLICY_DKIM_ALIGNMENT_PASS)?"yes":"no",
                             enforcement);
  }

  /* set some global variables here */

  /* shut down libopendmarc */
  if ( dmarc_pctx != NULL )
    (void) opendmarc_policy_connect_shutdown(dmarc_pctx);
  (void) opendmarc_policy_library_shutdown(&dmarc_ctx);

  /* no match */
  return FAIL;
}

#endif
