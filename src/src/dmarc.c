/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/
/* Experimental DMARC support.
   Copyright (c) Todd Lyons <tlyons@exim.org> 2012
   License: GPL */

/* Code for calling dmarc checks via libopendmarc. Called from acl.c. */

#include "exim.h"
#ifdef EXPERIMENTAL_DMARC

#include "functions.h"
#include "dmarc.h"
#include "pdkim/pdkim.h"

OPENDMARC_LIB_T     dmarc_ctx;
DMARC_POLICY_T     *dmarc_pctx = NULL;
OPENDMARC_STATUS_T  libdm_status;
BOOL dmarc_abort  = FALSE;
uschar *dmarc_pass_fail = US"skipped";
extern pdkim_signature  *dkim_signatures;
header_line *from_header   = NULL;
#ifdef EXPERIMENTAL_SPF
extern SPF_response_t   *spf_response;
uschar *spf_sender_domain  = NULL;
uschar *spf_human_readable = NULL;
#endif
u_char *header_from_sender = NULL;
int history_file_status    = DMARC_HIST_OK;
uschar *history_buffer     = NULL;
uschar *dkim_history_buffer= NULL;

/* dmarc_init sets up a context that can be re-used for several
   messages on the same SMTP connection (that come from the
   same host with the same HELO string) */

int dmarc_init() {
  int *netmask   = NULL;   /* Ignored */
  int is_ipv6    = 0;
  char *tld_file = (dmarc_tld_file == NULL) ?
                   "/etc/exim/opendmarc.tlds" :
                   (char *)dmarc_tld_file;

  /* Set some sane defaults.  Also clears previous results when
   * multiple messages in one connection. */
  dmarc_pctx = NULL;
  dmarc_status = US"none";
  dmarc_abort  = FALSE;
  dmarc_pass_fail = US"skipped";
  dmarc_used_domain = US"";
  header_from_sender = NULL;
#ifdef EXPERIMENTAL_SPF
  spf_sender_domain  = NULL;
  spf_human_readable = NULL;
#endif

  /* ACLs have "control=dmarc_disable_verify" */
  if (dmarc_disable_verify == TRUE)
    return OK;

  (void) memset(&dmarc_ctx, '\0', sizeof dmarc_ctx);
  dmarc_ctx.nscount = 0;
  libdm_status = opendmarc_policy_library_init(&dmarc_ctx);
  if (libdm_status != DMARC_PARSE_OKAY)
  {
    log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to init library: %s",
                         opendmarc_policy_status_to_str(libdm_status));
    dmarc_abort = TRUE;
  }
  if (opendmarc_tld_read_file(tld_file, NULL, NULL, NULL))
  {
    log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to load tld list %s: %d",
                         tld_file, errno);
    dmarc_abort = TRUE;
  }
  if (sender_host_address == NULL)
    dmarc_abort = TRUE;
  /* This catches locally originated email and startup errors above. */
  if ( dmarc_abort == FALSE )
  {
    is_ipv6 = string_is_ip_address(sender_host_address, netmask);
    is_ipv6 = (is_ipv6 == 6) ? TRUE :
              (is_ipv6 == 4) ? FALSE : FALSE;
    dmarc_pctx = opendmarc_policy_connect_init(sender_host_address, is_ipv6);
    if (dmarc_pctx == NULL )
    {
      log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure creating policy context: ip=%s",
                                       sender_host_address);
      dmarc_abort = TRUE;
    }
  }

  return OK;
}


/* dmarc_store_data stores the header data so that subsequent
 * dmarc_process can access the data */

int dmarc_store_data(header_line *hdr) {
  DEBUG(D_receive)
    debug_printf("DMARC storing header data\n");
  if (dmarc_disable_verify != TRUE)
    from_header = hdr;
  return OK;
}


/* dmarc_process adds the envelope sender address to the existing
   context (if any), retrieves the result, sets up expansion
   strings and evaluates the condition outcome. */

int dmarc_process() {
    int spf_result, sr, origin; /* used in SPF section */
    int da, sa, tmp_ans;
    u_char **ruv;
    pdkim_signature *sig  = NULL;
    uschar *enforcement   = NULL;
    uschar *tmp_status    = NULL;
    BOOL has_dmarc_record = TRUE;

  /* ACLs have "control=dmarc_disable_verify" */
  if (dmarc_disable_verify == TRUE)
  {
    dmarc_ar_header = dmarc_auth_results_header(from_header, NULL);
    return OK;
  }

  /* Store the header From: sender domain for this part of DMARC.
   * If there is no from_header struct, then it's likely this message
   * is locally generated and relying on fixups to add it.  Just skip
   * the entire DMARC system if we can't find a From: header....or if
   * there was a previous error.
   */
  if (from_header == NULL || dmarc_abort == TRUE)
    dmarc_abort = TRUE;
  else
  {
    /* I strongly encourage anybody who can make this better to contact me directly!
     * <cannonball> Is this an insane way to extract the email address from the From: header?
     * <jgh_hm> it's sure a horrid layer-crossing....
     * <cannonball> I'm not denying that :-/
     * <jgh_hm> there may well be no better though
     */
    header_from_sender = expand_string(
                           string_sprintf("${domain:${extract{1}{:}{${addresses:%s}}}}",
                             from_header->text) );
    /* The opendmarc library extracts the domain from the email address, but
     * only try to store it if it's not empty.  Otherwise, skip out of DMARC. */
    if (strcmp( CCS header_from_sender, "") == 0)
      dmarc_abort = TRUE;
    libdm_status = (dmarc_abort == TRUE) ?
	           DMARC_PARSE_OKAY :
		   opendmarc_policy_store_from_domain(dmarc_pctx, header_from_sender);
    if (libdm_status != DMARC_PARSE_OKAY)
    {
      log_write(0, LOG_MAIN|LOG_PANIC, "failure to store header From: in DMARC: %s, header was '%s'",
                           opendmarc_policy_status_to_str(libdm_status), from_header->text);
      dmarc_abort = TRUE;
    }
  }

  /* Skip DMARC if connection is SMTP Auth. Temporarily, admin should
   * instead do this in the ACLs.  */
  if (dmarc_abort == FALSE && sender_host_authenticated == NULL)
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
      spf_human_readable = US"";
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
      spf_human_readable = (uschar *)spf_response->header_comment;
      DEBUG(D_receive)
        debug_printf("DMARC using SPF sender domain = %s\n", spf_sender_domain);
    }
    if (strcmp( CCS spf_sender_domain, "") == 0)
      dmarc_abort = TRUE;
    if (dmarc_abort == FALSE)
    {
      libdm_status = opendmarc_policy_store_spf(dmarc_pctx, spf_sender_domain,
                                                spf_result, origin, spf_human_readable);
      if (libdm_status != DMARC_PARSE_OKAY)
        log_write(0, LOG_MAIN|LOG_PANIC, "failure to store spf for DMARC: %s",
                             opendmarc_policy_status_to_str(libdm_status));
    }
#endif /* EXPERIMENTAL_SPF */

    /* Now we cycle through the dkim signature results and put into
     * the opendmarc context, further building the DMARC reply.  */
    sig = dkim_signatures;
    dkim_history_buffer = US"";
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
        log_write(0, LOG_MAIN|LOG_PANIC, "failure to store dkim (%s) for DMARC: %s",
        		     sig->domain, opendmarc_policy_status_to_str(libdm_status));

      dkim_history_buffer = string_sprintf("%sdkim %s %d\n", dkim_history_buffer,
                                                             sig->domain, dkim_result);
      sig = sig->next;
    }
    libdm_status = opendmarc_policy_query_dmarc(dmarc_pctx, US"");
    switch (libdm_status)
    {
      case DMARC_DNS_ERROR_NXDOMAIN:
      case DMARC_DNS_ERROR_NO_RECORD:
        DEBUG(D_receive)
          debug_printf("DMARC no record found for '%s'\n", from_header->text);
        has_dmarc_record = FALSE;
        break;
      case DMARC_PARSE_OKAY:
        DEBUG(D_receive)
          debug_printf("DMARC record found for '%s'\n", from_header->text);
        break;
      default:
        /* everything else, skip dmarc */
        DEBUG(D_receive)
          debug_printf("DMARC skipping, unsure what to do with '%s'\n", from_header->text);
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
    dmarc_pass_fail = (libdm_status == DMARC_POLICY_NONE)    ? US"none" :
                      (libdm_status == DMARC_POLICY_PASS)    ? US"pass" :
		      (libdm_status == DMARC_POLICY_REJECT)  ? US"fail" :
		      (libdm_status == DMARC_POLICY_QUARANTINE)  ? US"fail" :
		      (libdm_status == DMARC_POLICY_ABSENT)  ? US"temperror" :
		      (libdm_status == DMARC_FROM_DOMAIN_ABSENT) ? US"temperror" :
		      US"permerror";
    enforcement = (libdm_status == DMARC_POLICY_NONE)        ? US"None, Accept" :
                  (libdm_status == DMARC_POLICY_PASS)        ? US"Accept" :
                  (libdm_status == DMARC_POLICY_REJECT)      ? US"Reject" :
                  (libdm_status == DMARC_POLICY_QUARANTINE)  ? US"Quarantine" :
                  (libdm_status == DMARC_POLICY_ABSENT)      ? US"No DMARC record" :
                  (libdm_status == DMARC_FROM_DOMAIN_ABSENT) ? US"No From: domain found" :
                  US"Internal Policy Error";
    dmarc_status_text = string_copy(enforcement);

    history_buffer = string_sprintf("job %s\n", message_id);
    history_buffer = string_sprintf("%sreporter %s\n", history_buffer, primary_hostname);
    history_buffer = string_sprintf("%sreceived %ld\n", history_buffer, time(NULL));
    history_buffer = string_sprintf("%sipaddr %s\n", history_buffer, sender_host_address);
    history_buffer = string_sprintf("%sfrom %s\n", history_buffer, header_from_sender);
    history_buffer = string_sprintf("%smfrom %s\n", history_buffer,
                       expand_string(US"$sender_address_domain"));

#ifdef EXPERIMENTAL_SPF
    if (spf_response != NULL)
      history_buffer = string_sprintf("%sspf %d\n", history_buffer, sr);
#else
      history_buffer = string_sprintf("%sspf -1\n", history_buffer);
#endif /* EXPERIMENTAL_SPF */

    history_buffer = string_sprintf("%s%s", history_buffer, dkim_history_buffer);
    history_buffer = string_sprintf("%spdomain %s\n", history_buffer, dmarc_used_domain);
    history_buffer = string_sprintf("%spolicy %d\n", history_buffer, libdm_status);

    ruv = opendmarc_policy_fetch_rua(dmarc_pctx, NULL, 0, 1);
    if (ruv != NULL)
    {
      for (tmp_ans = 0; ruv[tmp_ans] != NULL; tmp_ans++)
      {
        history_buffer = string_sprintf("%srua %s\n", history_buffer, ruv[tmp_ans]);
      }
    }
    else
      history_buffer = string_sprintf("%srua -\n", history_buffer);

    opendmarc_policy_fetch_pct(dmarc_pctx, &tmp_ans);
    history_buffer = string_sprintf("%spct %d\n", history_buffer, tmp_ans);

    opendmarc_policy_fetch_adkim(dmarc_pctx, &tmp_ans);
    history_buffer = string_sprintf("%sadkim %d\n", history_buffer, tmp_ans);

    opendmarc_policy_fetch_aspf(dmarc_pctx, &tmp_ans);
    history_buffer = string_sprintf("%saspf %d\n", history_buffer, tmp_ans);

    opendmarc_policy_fetch_p(dmarc_pctx, &tmp_ans);
    history_buffer = string_sprintf("%sp %d\n", history_buffer, tmp_ans);

    opendmarc_policy_fetch_sp(dmarc_pctx, &tmp_ans);
    history_buffer = string_sprintf("%ssp %d\n", history_buffer, tmp_ans);

    libdm_status = opendmarc_policy_fetch_alignment(dmarc_pctx, &da, &sa);
    if (libdm_status != DMARC_PARSE_OKAY)
    {
      log_write(0, LOG_MAIN|LOG_PANIC, "failure to read DMARC alignment: %s",
                                       opendmarc_policy_status_to_str(libdm_status));
    }

    if (has_dmarc_record == TRUE)
    {
      log_write(0, LOG_MAIN, "DMARC results: spf_domain=%s dmarc_domain=%s "
                             "spf_align=%s dkim_align=%s enforcement='%s'",
                             spf_sender_domain, dmarc_used_domain,
                             (sa==DMARC_POLICY_SPF_ALIGNMENT_PASS) ?"yes":"no",
                             (da==DMARC_POLICY_DKIM_ALIGNMENT_PASS)?"yes":"no",
                             enforcement);
      history_buffer = string_sprintf("%salign_dkim %d\n", history_buffer, sa);
      history_buffer = string_sprintf("%salign_spf %d\n", history_buffer, da);

      history_file_status = dmarc_write_history_file();
    }
  }

  /* set some global variables here */
  dmarc_ar_header = dmarc_auth_results_header(from_header, NULL);

  /* shut down libopendmarc */
  if ( dmarc_pctx != NULL )
    (void) opendmarc_policy_connect_shutdown(dmarc_pctx);
  if ( dmarc_disable_verify == FALSE )
    (void) opendmarc_policy_library_shutdown(&dmarc_ctx);

  return OK;
}

int dmarc_write_history_file()
{
  static int history_file_fd;
  ssize_t written_len;

  if (dmarc_history_file == NULL)
    return DMARC_HIST_DISABLED;
  if (history_buffer == NULL)
    return DMARC_HIST_EMPTY;
  history_file_fd = log_create(dmarc_history_file);
  if (history_file_fd < 0)
    return DMARC_HIST_FILE_ERR;
  written_len = write_to_fd_buf(history_file_fd,
                                history_buffer,
                                Ustrlen(history_buffer));
  if (written_len == 0)
    return DMARC_HIST_WRITE_ERR;
  (void)close(history_file_fd);
  return DMARC_HIST_OK;
}

uschar *dmarc_exim_expand_query(int what)
{
  if (dmarc_disable_verify || !dmarc_pctx)
    return dmarc_exim_expand_defaults(what);

  switch(what) {
    case DMARC_VERIFY_STATUS:
      return(dmarc_status);
    default:
      return US"";
  }
}

uschar *dmarc_exim_expand_defaults(int what)
{
  switch(what) {
    case DMARC_VERIFY_STATUS:
      return (dmarc_disable_verify) ?
              US"off" :
              US"none";
    default:
      return US"";
  }
}

uschar *dmarc_auth_results_header(header_line *from_header, uschar *hostname)
{
  uschar *hdr_tmp    = US"";

  /* Allow a server hostname to be passed to this function, but is
   * currently unused */
  if (hostname == NULL)
    hostname = primary_hostname;
  hdr_tmp = string_sprintf("%s %s;", DMARC_AR_HEADER, hostname);

#if 0
  /* I don't think this belongs here, but left it here commented out
   * because it was a lot of work to get working right. */
#ifdef EXPERIMENTAL_SPF
  if (spf_response != NULL) {
    uschar *dmarc_ar_spf = US"";
    int sr               = 0;
    sr = spf_response->result;
    dmarc_ar_spf = (sr == SPF_RESULT_NEUTRAL)  ? US"neutral" :
                   (sr == SPF_RESULT_PASS)     ? US"pass" :
                   (sr == SPF_RESULT_FAIL)     ? US"fail" :
                   (sr == SPF_RESULT_SOFTFAIL) ? US"softfail" :
                   US"none";
    hdr_tmp = string_sprintf("%s spf=%s (%s) smtp.mail=%s;",
                             hdr_tmp, dmarc_ar_spf_result,
                             spf_response->header_comment,
                             expand_string(US"$sender_address") );
  }
#endif
#endif
  hdr_tmp = string_sprintf("%s dmarc=%s",
                           hdr_tmp, dmarc_pass_fail);
  if (header_from_sender)
    hdr_tmp = string_sprintf("%s header.from=%s",
                             hdr_tmp, header_from_sender);
  return hdr_tmp;
}

#endif

// vim:sw=2 expandtab
