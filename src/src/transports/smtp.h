/* $Cambridge: exim/src/src/transports/smtp.h,v 1.2 2005/01/04 10:00:45 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2005 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options and other private data. */

typedef struct {
  uschar *hosts;
  uschar *fallback_hosts;
  host_item *hostlist;
  host_item *fallback_hostlist;
  uschar *authenticated_sender;
  uschar *helo_data;
  uschar *interface;
  uschar *port;
  uschar *protocol;
  uschar *serialize_hosts;
  uschar *hosts_try_auth;
  uschar *hosts_require_auth;
  uschar *hosts_require_tls;
  uschar *hosts_avoid_tls;
  uschar *hosts_avoid_esmtp;
  uschar *hosts_nopass_tls;
  int     command_timeout;
  int     connect_timeout;
  int     data_timeout;
  int     final_timeout;
  int     size_addition;
  int     hosts_max_try;
  BOOL    allow_localhost;
  BOOL    gethostbyname;
  BOOL    dns_qualify_single;
  BOOL    dns_search_parents;
  BOOL    delay_after_cutoff;
  BOOL    hosts_override;
  BOOL    hosts_randomize;
  BOOL    keepalive;
  BOOL    retry_include_ip_address;
  #ifdef SUPPORT_TLS
  uschar *tls_certificate;
  uschar *tls_crl;
  uschar *tls_privatekey;
  uschar *tls_require_ciphers;
  uschar *tls_verify_certificates;
  BOOL    tls_tempfail_tryclear;
  #endif
} smtp_transport_options_block;

/* Data for reading the private options. */

extern optionlist smtp_transport_options[];
extern int smtp_transport_options_count;

/* Block containing default values. */

extern smtp_transport_options_block smtp_transport_option_defaults;

/* The main, init, and closedown entry points for the transport */

extern BOOL smtp_transport_entry(transport_instance *, address_item *);
extern void smtp_transport_init(transport_instance *);
extern void smtp_transport_closedown(transport_instance *);

/* End of transports/smtp.h */
