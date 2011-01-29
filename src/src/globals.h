/* $Cambridge: exim/src/src/globals.h,v 1.69 2010/06/12 15:21:26 jetmore Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* Almost all the global variables are defined together in this one header, so
that they are easy to find. However, those that are visible during the
compilation of the local_scan() function are defined separately in the
local_scan.h header file. */

/* First put any specials that are required for some operating systems. */

#ifdef NEED_H_ERRNO
extern int h_errno;
#endif

/* Now things that are present only when configured. */

#ifdef EXIM_PERL
extern uschar *opt_perl_startup;       /* Startup code for Perl interpreter */
extern BOOL    opt_perl_at_start;      /* Start Perl interpreter at start */
extern BOOL    opt_perl_started;       /* Set once interpreter started */
#endif

#ifdef EXPAND_DLFUNC
extern tree_node *dlobj_anchor;        /* Tree of dynamically-loaded objects */
#endif

#ifdef LOOKUP_IBASE
extern uschar *ibase_servers;
#endif

#ifdef LOOKUP_LDAP
extern uschar *eldap_ca_cert_dir;      /* Directory with CA certificates */
extern uschar *eldap_ca_cert_file;     /* CA certificate file */
extern uschar *eldap_cert_file;        /* Certificate file */
extern uschar *eldap_cert_key;         /* Certificate key file */
extern uschar *eldap_cipher_suite;     /* Allowed cipher suite */
extern uschar *eldap_default_servers;  /* List of default servers */
extern uschar *eldap_require_cert;     /* Peer certificate checking strategy */
extern BOOL    eldap_start_tls;        /* Use STARTTLS */
extern int     eldap_version;          /* LDAP version */
#endif

#ifdef LOOKUP_MYSQL
extern uschar *mysql_servers;          /* List of servers and connect info */
#endif

#ifdef LOOKUP_ORACLE
extern uschar *oracle_servers;         /* List of servers and connect info */
#endif

#ifdef LOOKUP_PGSQL
extern uschar *pgsql_servers;          /* List of servers and connect info */
#endif

#ifdef LOOKUP_SQLITE
extern int     sqlite_lock_timeout;    /* Internal lock waiting timeout */
#endif

#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
extern BOOL    move_frozen_messages;   /* Get them out of the normal directory */
#endif

/* These variables are outside the #ifdef because it keeps the code less
cluttered in several places (e.g. during logging) if we can always refer to
them. Also, the tls_ variables are now always visible. */

extern int     tls_active;             /* fd/socket when in a TLS session */
extern BOOL    tls_certificate_verified; /* Client certificate verified */
extern uschar *tls_cipher;             /* Cipher used */
extern BOOL    tls_on_connect;         /* For older MTAs that don't STARTTLS */
extern uschar *tls_on_connect_ports;   /* Ports always tls-on-connect */
extern uschar *tls_peerdn;             /* DN from peer */

#ifdef SUPPORT_TLS
extern BOOL    gnutls_compat_mode;     /* Less security, more compatibility */
extern uschar *gnutls_require_mac;     /* So some can be avoided */
extern uschar *gnutls_require_kx;      /* So some can be avoided */
extern uschar *gnutls_require_proto;   /* So some can be avoided */
extern uschar *openssl_options;        /* OpenSSL compatibility options */
extern const pcre *regex_STARTTLS;     /* For recognizing STARTTLS settings */
extern uschar *tls_advertise_hosts;    /* host for which TLS is advertised */
extern uschar *tls_certificate;        /* Certificate file */
extern uschar *tls_crl;                /* CRL File */
extern uschar *tls_dhparam;            /* DH param file */
extern BOOL    tls_offered;            /* Server offered TLS */
extern uschar *tls_privatekey;         /* Private key file */
extern BOOL    tls_remember_esmtp;     /* For YAEB */
extern uschar *tls_require_ciphers;    /* So some can be avoided */
extern uschar *tls_try_verify_hosts;   /* Optional client verification */
extern uschar *tls_verify_certificates;/* Path for certificates to check */
extern uschar *tls_verify_hosts;       /* Mandatory client verification */
#endif


/* Input-reading functions for messages, so we can use special ones for
incoming TCP/IP. */

extern int (*receive_getc)(void);
extern int (*receive_ungetc)(int);
extern int (*receive_feof)(void);
extern int (*receive_ferror)(void);
extern BOOL (*receive_smtp_buffered)(void);


/* For clearing, saving, restoring address expansion variables. We have to have
the size of this vector set explicitly, because it is referenced from more than
one module. */

extern uschar **address_expansions[ADDRESS_EXPANSIONS_COUNT];

/* General global variables */

extern BOOL    accept_8bitmime;        /* Allow *BITMIME incoming */
extern header_line *acl_added_headers; /* Headers added by an ACL */
extern tree_node *acl_anchor;          /* Tree of named ACLs */
extern uschar *acl_not_smtp;           /* ACL run for non-SMTP messages */
#ifdef WITH_CONTENT_SCAN
extern uschar *acl_not_smtp_mime;      /* For MIME parts of ditto */
#endif
extern uschar *acl_not_smtp_start;     /* ACL run at the beginning of a non-SMTP session */
extern uschar *acl_smtp_auth;          /* ACL run for AUTH */
extern uschar *acl_smtp_connect;       /* ACL run on SMTP connection */
extern uschar *acl_smtp_data;          /* ACL run after DATA received */
#ifndef DISABLE_DKIM
extern uschar *acl_smtp_dkim;          /* ACL run for DKIM signatures / domains */
#endif
extern uschar *acl_smtp_etrn;          /* ACL run for ETRN */
extern uschar *acl_smtp_expn;          /* ACL run for EXPN */
extern uschar *acl_smtp_helo;          /* ACL run for HELO/EHLO */
extern uschar *acl_smtp_mail;          /* ACL run for MAIL */
extern uschar *acl_smtp_mailauth;      /* ACL run for MAIL AUTH */
#ifdef WITH_CONTENT_SCAN
extern uschar *acl_smtp_mime;          /* ACL run after DATA, before acl_smtp_data, for each MIME part */
#endif
extern uschar *acl_smtp_notquit;       /* ACL run for disconnects */
extern uschar *acl_smtp_predata;       /* ACL run for DATA command */
extern uschar *acl_smtp_quit;          /* ACL run for QUIT */
extern uschar *acl_smtp_rcpt;          /* ACL run for RCPT */
extern uschar *acl_smtp_starttls;      /* ACL run for STARTTLS */
extern uschar *acl_smtp_vrfy;          /* ACL run for VRFY */
extern BOOL    acl_temp_details;       /* TRUE to give details for 4xx error */
extern tree_node *acl_var_c;           /* ACL connection variables */
extern tree_node *acl_var_m;           /* ACL messsage variables */
extern uschar *acl_verify_message;     /* User message for verify failure */
extern string_item *acl_warn_logged;   /* Logged lines */
extern uschar *acl_wherecodes[];       /* Response codes for ACL fails */
extern uschar *acl_wherenames[];       /* Names for messages */
extern BOOL    active_local_from_check;/* For adding Sender: (switchable) */
extern BOOL    active_local_sender_retain; /* For keeping Sender: (switchable) */
extern address_item *addr_duplicate;   /* Duplicate address list */
extern address_item address_defaults;  /* Default data for address item */
extern uschar *address_file;           /* Name of file when delivering to one */
extern uschar *address_pipe;           /* Pipe command when delivering to one */
extern BOOL    address_test_mode;      /* True for -bt */
extern tree_node *addresslist_anchor;  /* Tree of defined address lists */
extern int     addresslist_count;      /* Number defined */
extern gid_t  *admin_groups;           /* List of admin groups */
extern BOOL    admin_user;             /* True if caller can do admin */
extern BOOL    allow_auth_unadvertised;/* As it says */
extern BOOL    allow_domain_literals;  /* As it says */
extern BOOL    allow_mx_to_ip;         /* Allow MX records to -> ip address */
extern BOOL    allow_unqualified_recipient; /* As it says */
extern BOOL    allow_unqualified_sender; /* Ditto */
extern BOOL    allow_utf8_domains;     /* For experimenting */
extern uschar *authenticated_id;       /* ID that was authenticated */
extern uschar *authenticated_sender;   /* From AUTH on MAIL */
extern BOOL    authentication_failed;  /* TRUE if AUTH was tried and failed */
extern uschar *auth_advertise_hosts;   /* Only advertise to these */
extern auth_info auths_available[];    /* Vector of available auth mechanisms */
extern auth_instance *auths;           /* Chain of instantiated auths */
extern auth_instance auth_defaults;    /* Default values */
extern uschar *auth_defer_msg;         /* Error message for log */
extern uschar *auth_defer_user_msg;    /* Error message for user */
extern uschar *auth_vars[];            /* $authn variables */
extern int     auto_thaw;              /* Auto-thaw interval */
#ifdef WITH_CONTENT_SCAN
extern uschar *av_scanner;             /* AntiVirus scanner to use for the malware condition */
#endif

extern BOOL    background_daemon;      /* Set FALSE to keep in foreground */
extern uschar *base62_chars;           /* Table of base-62 characters */
extern uschar *bi_command;             /* Command for -bi option */
extern uschar *big_buffer;             /* Used for various temp things */
extern int     big_buffer_size;        /* Current size (can expand) */
#ifdef EXPERIMENTAL_BRIGHTMAIL
extern uschar *bmi_alt_location;       /* expansion variable that contains the alternate location for the rcpt (available during routing) */
extern uschar *bmi_base64_tracker_verdict; /* expansion variable with base-64 encoded OLD verdict string (available during routing) */
extern uschar *bmi_base64_verdict;     /* expansion variable with base-64 encoded verdict string (available during routing) */
extern uschar *bmi_config_file;        /* Brightmail config file */
extern int     bmi_deliver;            /* Flag that determines if the message should be delivered to the rcpt (available during routing) */
extern int     bmi_run;                /* Flag that determines if message should be run through Brightmail server */
extern uschar *bmi_verdicts;           /* BASE64-encoded verdicts with recipient lists */
#endif
extern uschar *bounce_message_file;    /* Template file */
extern uschar *bounce_message_text;    /* One-liner */
extern uschar *bounce_recipient;       /* When writing an errmsg */
extern BOOL    bounce_return_body;     /* Include body in returned message */
extern BOOL    bounce_return_message;  /* Include message in bounce */
extern int     bounce_return_size_limit; /* Max amount to return */
extern uschar *bounce_sender_authentication; /* AUTH address for bounces */
extern int     bsmtp_transaction_linecount; /* Start of last transaction */

extern int     callout_cache_domain_positive_expire; /* Time for positive domain callout cache records to expire */
extern int     callout_cache_domain_negative_expire; /* Time for negative domain callout cache records to expire */
extern int     callout_cache_positive_expire; /* Time for positive callout cache records to expire */
extern int     callout_cache_negative_expire; /* Time for negative callout cache records to expire */
extern uschar *callout_random_local_part; /* Local part to be used to check if server called will accept any local part */
extern uschar *check_dns_names_pattern;/* Regex for syntax check */
extern int     check_log_inodes;       /* Minimum for message acceptance */
extern int     check_log_space;        /* Minimum for message acceptance */
extern BOOL    check_rfc2047_length;   /* Check RFC 2047 encoded string length */
extern int     check_spool_inodes;     /* Minimum for message acceptance */
extern int     check_spool_space;      /* Minimum for message acceptance */
extern int     clmacro_count;          /* Number of command line macros */
extern uschar *clmacros[];             /* Copy of them, for re-exec */
extern int     connection_max_messages;/* Max down one SMTP connection */
extern BOOL    config_changed;         /* True if -C used */
extern FILE   *config_file;            /* Configuration file */
extern uschar *config_filename;        /* Configuration file name */
#ifdef CONFIGURE_GROUP
extern gid_t   config_gid;             /* Additional group owner */
#endif
extern int     config_lineno;          /* Line number */
extern uschar *config_main_filelist;   /* List of possible config files */
extern uschar *config_main_filename;   /* File name actually used */
#ifdef CONFIGURE_OWNER
extern uid_t   config_uid;             /* Additional owner */
#endif
extern uschar *continue_hostname;      /* Host for continued delivery */
extern uschar *continue_host_address;  /* IP address for ditto */
extern BOOL    continue_more;          /* Flag more addresses waiting */
extern int     continue_sequence;      /* Sequence num for continued delivery */
extern uschar *continue_transport;     /* Transport for continued delivery */

extern uschar *csa_status;             /* Client SMTP Authorization result */

extern BOOL    daemon_listen;          /* True if listening required */
extern uschar *daemon_smtp_port;       /* Can be a list of ports */
extern int     daemon_startup_retries; /* Number of times to retry */
extern int     daemon_startup_sleep;   /* Sleep between retries */

#ifdef EXPERIMENTAL_DCC
extern BOOL    dcc_direct_add_header;  /* directly add header */
extern uschar *dcc_header;             /* dcc header */
extern uschar *dcc_result;             /* dcc result */
extern uschar *dccifd_address;         /* address of the dccifd daemon */
extern uschar *dccifd_options;         /* options for the dccifd daemon */
#endif

extern BOOL    debug_daemon;           /* Debug the daemon process only */
extern int     debug_fd;               /* The fd for debug_file */
extern FILE   *debug_file;             /* Where to write debugging info */
extern bit_table debug_options[];      /* Table of debug options */
extern int     debug_options_count;    /* Size of table */
extern int     delay_warning[];        /* Times between warnings */
extern uschar *delay_warning_condition; /* Condition string for warnings */
extern BOOL    delivery_date_remove;   /* Remove delivery-date headers */

extern uschar *deliver_address_data;   /* Arbitrary data for an address */
extern int     deliver_datafile;       /* FD for data part of message */
extern uschar *deliver_domain;         /* The local domain for delivery */
extern uschar *deliver_domain_data;    /* From domain lookup */
extern uschar *deliver_domain_orig;    /* The original local domain for delivery */
extern uschar *deliver_domain_parent;  /* The parent domain for delivery */
extern BOOL    deliver_drop_privilege; /* TRUE for unprivileged delivery */
extern BOOL    deliver_firsttime;      /* True for first delivery attempt */
extern BOOL    deliver_force;          /* TRUE if delivery was forced */
extern BOOL    deliver_freeze;         /* TRUE if delivery is frozen */
extern int     deliver_frozen_at;      /* Time of freezing */
extern uschar *deliver_home;           /* Home directory for pipes */
extern uschar *deliver_host;           /* (First) host for routed local deliveries */
                                       /* Remote host for filter */
extern uschar *deliver_host_address;   /* Address for remote delivery filter */
extern uschar *deliver_in_buffer;      /* Buffer for copying file */
extern ino_t   deliver_inode;          /* Inode for appendfile */
extern uschar *deliver_localpart;      /* The local part for delivery */
extern uschar *deliver_localpart_data; /* From local part lookup */
extern uschar *deliver_localpart_orig; /* The original local part for delivery */
extern uschar *deliver_localpart_parent; /* The parent local part for delivery */
extern uschar *deliver_localpart_prefix; /* The stripped prefix, if any */
extern uschar *deliver_localpart_suffix; /* The stripped suffix, if any */
extern BOOL    deliver_force_thaw;     /* TRUE to force thaw in queue run */
extern BOOL    deliver_manual_thaw;    /* TRUE if manually thawed */
extern uschar *deliver_out_buffer;     /* Buffer for copying file */
extern int     deliver_queue_load_max; /* Different value for queue running */
extern address_item *deliver_recipients; /* Current set of addresses */
extern uschar *deliver_selectstring;   /* For selecting by recipient */
extern BOOL    deliver_selectstring_regex; /* String is regex */
extern uschar *deliver_selectstring_sender; /* For selecting by sender */
extern BOOL    deliver_selectstring_sender_regex; /* String is regex */
#ifdef WITH_OLD_DEMIME
extern int     demime_errorlevel;      /* Severity of MIME error */
extern int     demime_ok;              /* Nonzero if message has been demimed */
extern uschar *demime_reason;          /* Reason for broken MIME container */
#endif
extern BOOL    disable_callout_flush;  /* Don't flush before callouts */
extern BOOL    disable_delay_flush;    /* Don't flush before "delay" in ACL */
#ifdef ENABLE_DISABLE_FSYNC
extern BOOL    disable_fsync;          /* Not for normal use */
#endif
extern BOOL    disable_ipv6;           /* Don't do any IPv6 things */
extern BOOL    disable_logging;        /* Disables log writing when TRUE */

#ifndef DISABLE_DKIM
extern uschar *dkim_cur_signer;        /* Expansion variable, holds the current "signer" domain or identity during a acl_smtp_dkim run */
extern uschar *dkim_signers;           /* Expansion variable, holds colon-separated list of domains and identities that have signed a message */
extern uschar *dkim_signing_domain;    /* Expansion variable, domain used for signing a message. */
extern uschar *dkim_signing_selector;  /* Expansion variable, selector used for signing a message. */
extern uschar *dkim_verify_signers;    /* Colon-separated list of domains for each of which we call the DKIM ACL */
extern BOOL    dkim_collect_input;     /* Runtime flag that tracks wether SMTP input is fed to DKIM validation */
extern BOOL    dkim_disable_verify;    /* Set via ACL control statement. When set, DKIM verification is disabled for the current message */
#endif

extern uschar *dns_again_means_nonexist; /* Domains that are badly set up */
extern int     dns_csa_search_limit;   /* How deep to search for CSA SRV records */
extern BOOL    dns_csa_use_reverse;    /* Check CSA in reverse DNS? (non-standard) */
extern uschar *dns_ipv4_lookup;        /* For these domains, don't look for AAAA (or A6) */
extern int     dns_retrans;            /* Retransmission time setting */
extern int     dns_retry;              /* Number of retries */
extern uschar *dnslist_domain;         /* DNS (black) list domain */
extern uschar *dnslist_matched;        /* DNS (black) list matched key */
extern uschar *dnslist_text;           /* DNS (black) list text message */
extern uschar *dnslist_value;          /* DNS (black) list IP address */
extern tree_node *domainlist_anchor;   /* Tree of defined domain lists */
extern int     domainlist_count;       /* Number defined */
extern BOOL    dont_deliver;           /* TRUE for -N option */
extern BOOL    dot_ends;               /* TRUE if "." ends non-SMTP input */

/* This option is now a no-opt, retained for compatibility */
extern BOOL    drop_cr;                /* For broken local MUAs */

extern uschar *dsn_from;               /* From: string for DSNs */

extern BOOL    enable_dollar_recipients; /* Make $recipients available */
extern int     envelope_to_remove;     /* Remove envelope_to_headers */
extern int     errno_quota;            /* Quota errno in this OS */
extern int     error_handling;         /* Error handling style */
extern uschar *errors_copy;            /* For taking copies of errors */
extern uschar *errors_reply_to;        /* Reply-to for error messages */
extern int     errors_sender_rc;       /* Return after message to sender*/
extern gid_t   exim_gid;               /* To be used with exim_uid */
extern BOOL    exim_gid_set;           /* TRUE if exim_gid set */
extern uschar *exim_path;              /* Path to exec exim */
extern uid_t   exim_uid;               /* Non-root uid for exim */
extern BOOL    exim_uid_set;           /* TRUE if exim_uid set */
extern int     expand_forbid;          /* RDO flags for forbidding things */
extern int     expand_nlength[];       /* Lengths of numbered strings */
extern int     expand_nmax;            /* Max numerical value */
extern uschar *expand_nstring[];       /* Numbered strings */
extern BOOL    expand_string_forcedfail; /* TRUE if failure was "expected" */
extern BOOL    extract_addresses_remove_arguments; /* Controls -t behaviour */
extern uschar *extra_local_interfaces; /* Local, non-listen interfaces */

extern int     fake_response;          /* Fake FAIL or DEFER response to data */
extern uschar *fake_response_text;     /* User defined message for the above. Default is in globals.c. */
extern int     filter_n[FILTER_VARIABLE_COUNT]; /* filter variables */
extern BOOL    filter_running;         /* TRUE while running a filter */
extern int     filter_sn[FILTER_VARIABLE_COUNT]; /* variables set by system filter */
extern int     filter_test;            /* Filter test type */
extern uschar *filter_test_sfile;      /* System filter test file */
extern uschar *filter_test_ufile;      /* User filter test file */
extern uschar *filter_thisaddress;     /* For address looping */
extern int     finduser_retries;       /* Retry count for getpwnam() */
extern uid_t   fixed_never_users[];    /* Can't be overridden */
#ifdef WITH_OLD_DEMIME
extern uschar *found_extension;        /* demime acl condition: file extension found */
#endif
extern uschar *freeze_tell;            /* Message on (some) freezings */
extern uschar *freeze_tell_config;     /* The configured setting */
extern uschar *fudged_queue_times;     /* For use in test harness */

extern uschar *gecos_name;             /* To be expanded when pattern matches */
extern uschar *gecos_pattern;          /* Pattern to match */
extern rewrite_rule *global_rewrite_rules;  /* Chain of rewriting rules */

extern int     header_insert_maxlen;   /* Max for inserting headers */
extern int     header_maxsize;         /* Max total length for header */
extern int     header_line_maxsize;    /* Max for an individual line */
extern header_name header_names[];     /* Table of header names */
extern int     header_names_size;      /* Number of entries */
extern BOOL    header_rewritten;       /* TRUE if header changed by router */
extern uschar *helo_accept_junk_hosts; /* Allowed to use junk arg */
extern uschar *helo_allow_chars;       /* Rogue chars to allow in HELO/EHLO */
extern uschar *helo_lookup_domains;    /* If these given, lookup host name */
extern uschar *helo_try_verify_hosts;  /* Soft check HELO argument for these */
extern BOOL    helo_verified;          /* True if HELO verified */
extern BOOL    helo_verify_failed;     /* True if attempt failed */
extern uschar *helo_verify_hosts;      /* Hard check HELO argument for these */
extern uschar *hex_digits;             /* Used in several places */
extern uschar *hold_domains;           /* Hold up deliveries to these */
extern BOOL    host_find_failed_syntax;/* DNS syntax check failure */
extern BOOL    host_checking_callout;  /* TRUE if real callout wanted */
extern uschar *host_data;              /* Obtained from lookup in ACL */
extern uschar *host_lookup;            /* For which IP addresses are always looked up */
extern BOOL    host_lookup_deferred;   /* TRUE if lookup deferred */
extern BOOL    host_lookup_failed;     /* TRUE if lookup failed */
extern uschar *host_lookup_order;      /* Order of host lookup types */
extern uschar *host_lookup_msg;        /* Text for why it failed */
extern int     host_number;            /* For sharing spools */
extern uschar *host_number_string;     /* For expanding */
extern uschar *host_reject_connection; /* Reject these hosts */
extern tree_node *hostlist_anchor;     /* Tree of defined host lists */
extern int     hostlist_count;         /* Number defined */
extern uschar *hosts_connection_nolog; /* Limits the logging option */
extern uschar *hosts_treat_as_local;   /* For routing */

extern int     ignore_bounce_errors_after; /* Keep them for this time. */
extern BOOL    ignore_fromline_local;  /* Local SMTP ignore fromline */
extern uschar *ignore_fromline_hosts;  /* Hosts permitted to send "From " */
extern BOOL    is_inetd;               /* True for inetd calls */
extern uschar *iterate_item;           /* Item from iterate list */

extern int     journal_fd;             /* Fd for journal file */

extern int     keep_malformed;         /* Time to keep malformed messages */

extern uschar *eldap_dn;               /* Where LDAP DNs are left */
extern int     load_average;           /* Most recently read load average */
extern BOOL    local_error_message;    /* True if handling one of these */
extern BOOL    local_from_check;       /* For adding Sender: (global value) */
extern uschar *local_from_prefix;      /* Permitted prefixes */
extern uschar *local_from_suffix;      /* Permitted suffixes */
extern uschar *local_interfaces;       /* For forcing specific interfaces */
extern uschar *local_scan_data;        /* Text returned by local_scan() */
extern optionlist local_scan_options[];/* Option list for local_scan() */
extern int     local_scan_options_count; /* Size of the list */
extern int     local_scan_timeout;     /* Timeout for local_scan() */
extern BOOL    local_sender_retain;    /* Retain Sender: (with no From: check) */
extern gid_t   local_user_gid;         /* As it says; may be set in routers */
extern uid_t   local_user_uid;         /* As it says; may be set in routers */
extern tree_node *localpartlist_anchor;/* Tree of defined localpart lists */
extern int     localpartlist_count;    /* Number defined */
extern uschar *log_buffer;             /* For constructing log entries */
extern unsigned int log_extra_selector;/* Bit map of logging options other than used by log_write() */
extern uschar *log_file_path;          /* If unset, use default */
extern bit_table log_options[];        /* Table of options */
extern int     log_options_count;      /* Size of table */
extern int     log_reject_target;      /* Target log for ACL rejections */
extern uschar *log_selector_string;    /* As supplied in the config */
extern FILE   *log_stderr;             /* Copy of stderr for log use, or NULL */
extern BOOL    log_testing_mode;       /* TRUE in various testing modes */
extern BOOL    log_timezone;           /* TRUE to include the timezone in log lines */
extern unsigned int log_write_selector;/* Bit map of logging options for log_write() */
extern uschar *login_sender_address;   /* The actual sender address */
extern lookup_info **lookup_list;      /* Array of pointers to available lookups */
extern int     lookup_list_count;      /* Number of entries in the list */
extern int     lookup_open_max;        /* Max lookup files to cache */
extern uschar *lookup_value;           /* Value looked up from file */

extern macro_item *macros;             /* Configuration macros */
extern uschar *mailstore_basename;     /* For mailstore deliveries */
#ifdef WITH_CONTENT_SCAN
extern uschar *malware_name;           /* Name of virus or malware ("W32/Klez-H") */
#endif
extern int     max_received_linelength;/* What it says */
extern int     max_username_length;    /* For systems with broken getpwnam() */
extern int     message_age;            /* In seconds */
extern uschar *message_body;           /* Start of message body for filter */
extern uschar *message_body_end;       /* End of message body for filter */
extern BOOL    message_body_newlines;  /* FALSE => remove newlines */
extern int     message_body_size;      /* Sic */
extern int     message_body_visible;   /* Amount visible in message_body */
extern int     message_ended;          /* State of message reading and how ended */
extern uschar *message_headers;        /* When built */
extern uschar  message_id_option[];    /* -E<message-id> for use as option */
extern uschar *message_id_external;    /* External form of following */
extern uschar *message_id_domain;      /* Expanded to form domain-part of message_id */
extern uschar *message_id_text;        /* Expanded to form message_id */
extern struct timeval message_id_tv;   /* Time used to create last message_id */
extern int     message_linecount;      /* As it says */
extern BOOL    message_logs;           /* TRUE to write message logs */
extern int     message_size;           /* Size of message */
extern uschar *message_size_limit;     /* As it says */
extern uschar  message_subdir[];       /* Subdirectory for messages */
extern uschar *message_reference;      /* Reference for error messages */

/* MIME ACL expandables */
#ifdef WITH_CONTENT_SCAN
extern int     mime_anomaly_level;
extern uschar *mime_anomaly_text;
extern uschar *mime_boundary;
extern uschar *mime_charset;
extern uschar *mime_content_description;
extern uschar *mime_content_disposition;
extern uschar *mime_content_id;
extern unsigned int mime_content_size;
extern uschar *mime_content_transfer_encoding;
extern uschar *mime_content_type;
extern uschar *mime_decoded_filename;
extern uschar *mime_filename;
extern int     mime_is_multipart;
extern int     mime_is_coverletter;
extern int     mime_is_rfc822;
extern int     mime_part_count;
#endif

extern BOOL    mua_wrapper;            /* TRUE when Exim is wrapping an MUA */

extern uid_t  *never_users;            /* List of uids never to be used */
#ifdef WITH_CONTENT_SCAN
extern BOOL    no_mbox_unspool;        /* don't unlink files in /scan directory */
#endif
extern BOOL    no_multiline_responses; /* For broken clients */

extern optionlist optionlist_auths[];      /* These option lists are made */
extern int     optionlist_auths_size;      /* global so that readconf can */
extern optionlist optionlist_routers[];    /* see them for printing out   */
extern int     optionlist_routers_size;    /* the options.                */
extern optionlist optionlist_transports[];
extern int     optionlist_transports_size;

extern uid_t   original_euid;          /* Original effective uid */
extern gid_t   originator_gid;         /* Gid of whoever wrote spool file */
extern uschar *originator_login;       /* Login of same */
extern uschar *originator_name;        /* Full name of same */
extern uid_t   originator_uid;         /* Uid of ditto */
extern uschar *override_local_interfaces; /* Value of -oX argument */
extern uschar *override_pid_file_path; /* Value of -oP argument */

extern BOOL    parse_allow_group;      /* Allow group syntax */
extern BOOL    parse_found_group;      /* In the middle of a group */
extern uschar *percent_hack_domains;   /* Local domains for which '% operates */
extern uschar *pid_file_path;          /* For writing daemon pids */
extern uschar *pipelining_advertise_hosts; /* As it says */
extern BOOL    pipelining_enable;      /* As it says */
extern BOOL    preserve_message_logs;  /* Save msglog files */
extern uschar *primary_hostname;       /* Primary name of this computer */
extern BOOL    print_topbitchars;      /* Topbit chars are printing chars */
extern uschar  process_info[];         /* For SIGUSR1 output */
extern uschar *process_log_path;       /* Alternate path */
extern BOOL    prod_requires_admin;    /* TRUE if prodding requires admin */
extern uschar *prvscheck_address;      /* Set during prvscheck expansion item */
extern uschar *prvscheck_keynum;       /* Set during prvscheck expansion item */
extern uschar *prvscheck_result;       /* Set during prvscheck expansion item */

extern uschar *qualify_domain_recipient; /* Domain to qualify recipients with */
extern uschar *qualify_domain_sender;  /* Domain to qualify senders with */
extern BOOL    queue_2stage;           /* Run queue in 2-stage manner */
extern uschar *queue_domains;          /* Queue these domains */
extern BOOL    queue_list_requires_admin; /* TRUE if -bp requires admin */
extern BOOL    queue_run_first_delivery; /* If TRUE, first deliveries only */
extern BOOL    queue_run_force;        /* TRUE to force during queue run */
extern BOOL    queue_run_local;        /* Local deliveries only in queue run */
extern BOOL    queue_running;          /* TRUE for queue running process and */
                                       /*   immediate children */
extern pid_t   queue_run_pid;          /* PID of the queue running process or 0 */
extern int     queue_run_pipe;         /* Pipe for synchronizing */
extern int     queue_interval;         /* Queue running interval */
extern BOOL    queue_only;             /* TRUE to disable immediate delivery */
extern int     queue_only_load;        /* Max load before auto-queue */
extern BOOL    queue_only_load_latch;  /* Latch queue_only_load TRUE */
extern uschar *queue_only_file;        /* Queue if file exists/not-exists */
extern BOOL    queue_only_override;    /* Allow override from command line */
extern BOOL    queue_only_policy;      /* ACL or local_scan wants queue_only */
extern BOOL    queue_run_in_order;     /* As opposed to random */
extern int     queue_run_max;          /* Max queue runners */
extern BOOL    queue_smtp;             /* Disable all immediate STMP (-odqs)*/
extern uschar *queue_smtp_domains;     /* Ditto, for these domains */

extern unsigned int random_seed;       /* Seed for random numbers */
extern tree_node *ratelimiters_cmd;    /* Results of command ratelimit checks */
extern tree_node *ratelimiters_conn;   /* Results of connection ratelimit checks */
extern tree_node *ratelimiters_mail;   /* Results of per-mail ratelimit checks */
extern uschar *raw_active_hostname;    /* Pre-expansion */
extern uschar *raw_sender;             /* Before rewriting */
extern uschar **raw_recipients;        /* Before rewriting */
extern int     raw_recipients_count;
extern int     rcpt_count;             /* Count of RCPT commands in a message */
extern int     rcpt_fail_count;        /* Those that got 5xx */
extern int     rcpt_defer_count;       /* Those that got 4xx */
extern gid_t   real_gid;               /* Real gid */
extern uid_t   real_uid;               /* Real user running program */
extern BOOL    really_exim;            /* FALSE in utilities */
extern BOOL    receive_call_bombout;   /* Flag for crashing log */
extern int     receive_linecount;      /* Mainly for BSMTP errors */
extern int     receive_messagecount;   /* Mainly for BSMTP errors */
extern int     receive_timeout;        /* For non-SMTP acceptance */
extern int     received_count;         /* Count of Received: headers */
extern uschar *received_for;           /* For "for" field */
extern uschar *received_header_text;   /* Definition of Received: header */
extern int     received_headers_max;   /* Max count of Received: headers */
extern int     received_time;          /* Time the message was received */
extern uschar *recipient_data;         /* lookup data for recipients */
extern uschar *recipient_unqualified_hosts; /* Permitted unqualified recipients */
extern uschar *recipient_verify_failure; /* What went wrong */
extern BOOL    recipients_discarded;   /* By an ACL */
extern int     recipients_list_max;    /* Maximum number fitting in list */
extern int     recipients_max;         /* Max permitted */
extern int     recipients_max_reject;  /* If TRUE, reject whole message */
extern const pcre *regex_AUTH;         /* For recognizing AUTH settings */
extern const pcre  *regex_check_dns_names; /* For DNS name checking */
extern const pcre  *regex_From;        /* For recognizing "From_" lines */
extern const pcre  *regex_IGNOREQUOTA; /* For recognizing IGNOREQUOTA (LMTP) */
extern const pcre  *regex_PIPELINING;  /* For recognizing PIPELINING */
extern const pcre  *regex_SIZE;        /* For recognizing SIZE settings */
extern const pcre  *regex_smtp_code;   /* For recognizing SMTP codes */
extern const pcre  *regex_ismsgid;     /* Compiled r.e. for message it */
#ifdef WHITELIST_D_MACROS
extern const pcre  *regex_whitelisted_macro; /* For -D macro values */
#endif
#ifdef WITH_CONTENT_SCAN
extern uschar *regex_match_string;     /* regex that matched a line (regex ACL condition) */
#endif
extern int     remote_delivery_count;  /* Number of remote addresses */
extern int     remote_max_parallel;    /* Maximum parallel delivery */
extern uschar *remote_sort_domains;    /* Remote domain sorting order */
extern retry_config *retries;          /* Chain of retry config information */
extern int     retry_data_expire;      /* When to expire retry data */
extern int     retry_interval_max;     /* Absolute maximum */
extern int     retry_maximum_timeout;  /* The maximum timeout */
extern uschar *return_path;            /* Return path for a message */
extern BOOL    return_path_remove;     /* Remove return-path headers */
extern int     rewrite_existflags;     /* Indicate which headers have rewrites */
extern uschar *rfc1413_hosts;          /* RFC hosts */
extern int     rfc1413_query_timeout;  /* Timeout on RFC 1413 calls */
/* extern BOOL    rfc821_domains;  */       /* If set, syntax is 821, not 822 => being abolished */
extern uid_t   root_gid;               /* The gid for root */
extern uid_t   root_uid;               /* The uid for root */
extern router_info routers_available[];/* Vector of available routers */
extern router_instance *routers;       /* Chain of instantiated routers */
extern router_instance router_defaults;/* Default values */
extern BOOL    running_in_test_harness; /*TRUE when running_status is patched */
extern ip_address_item *running_interfaces; /* Host's running interfaces */
extern uschar *running_status;         /* Flag string for testing */
extern int     runrc;                  /* rc from ${run} */

extern uschar *search_error_message;   /* Details of lookup problem */
extern BOOL    search_find_defer;      /* Set TRUE if lookup deferred */
extern uschar *self_hostname;          /* Self host after routing->directors */
extern unsigned int sender_address_cache[(MAX_NAMED_LIST * 2)/32]; /* Cache bits for sender */
extern uschar *sender_address_data;    /* address_data from sender verify */
extern BOOL    sender_address_forced;  /* Set by -f */
extern uschar *sender_address_unrewritten; /* Set if rewritten by verify */
extern uschar *sender_data;            /* lookup result for senders */
extern unsigned int sender_domain_cache[(MAX_NAMED_LIST * 2)/32]; /* Cache bits for sender domain */
extern uschar *sender_fullhost;        /* Sender host name + address */
extern uschar *sender_helo_name;       /* Host name from HELO/EHLO */
extern uschar **sender_host_aliases;   /* Points to list of alias names */
extern unsigned int sender_host_cache[(MAX_NAMED_LIST * 2)/32]; /* Cache bits for incoming host */
extern BOOL    sender_host_notsocket;  /* Set for -bs and -bS */
extern BOOL    sender_host_unknown;    /* TRUE for -bs and -bS except inetd */
extern uschar *sender_ident;           /* Sender identity via RFC 1413 */
extern BOOL    sender_local;           /* TRUE for local senders */
extern BOOL    sender_name_forced;     /* Set by -F */
extern uschar *sender_rate;            /* Sender rate computed by ACL */
extern uschar *sender_rate_limit;      /* Configured rate limit */
extern uschar *sender_rate_period;     /* Configured smoothing period */
extern uschar *sender_rcvhost;         /* Host data for Received: */
extern BOOL    sender_set_untrusted;   /* Sender set by untrusted caller */
extern uschar *sender_unqualified_hosts; /* Permitted unqualified senders */
extern uschar *sender_verify_failure;  /* What went wrong */
extern address_item *sender_verified_list; /* Saved chain of sender verifies */
extern address_item *sender_verified_failed; /* The one that caused denial */
extern uschar *sending_ip_address;     /* Address of outgoing (SMTP) interface */
extern int     sending_port;           /* Port of outgoing interface */
extern volatile BOOL sigalrm_seen;     /* Flag for sigalrm_handler */
extern uschar **sighup_argv;           /* Args for re-execing after SIGHUP */
extern int     smtp_accept_count;      /* Count of connections */
extern BOOL    smtp_accept_keepalive;  /* Set keepalive on incoming */
extern int     smtp_accept_max;        /* Max SMTP connections */
extern int     smtp_accept_max_nonmail;/* Max non-mail commands in one con */
extern uschar *smtp_accept_max_nonmail_hosts; /* Limit non-mail cmds from these hosts */
extern int     smtp_accept_max_per_connection; /* Max msgs per connection */
extern uschar *smtp_accept_max_per_host; /* Max SMTP cons from one IP addr */
extern int     smtp_accept_queue;      /* Queue after so many connections */
extern int     smtp_accept_queue_per_connection; /* Queue after so many msgs */
extern int     smtp_accept_reserve;    /* Reserve these SMTP connections */
extern uschar *smtp_active_hostname;   /* Hostname for this message */
extern BOOL    smtp_authenticated;     /* Sending client has authenticated */
extern uschar *smtp_banner;            /* Banner string (to be expanded) */
extern BOOL    smtp_check_spool_space; /* TRUE to check SMTP SIZE value */
extern int     smtp_ch_index;          /* Index in smtp_connection_had */
extern uschar *smtp_cmd_argument;      /* For all SMTP commands */
extern uschar *smtp_cmd_buffer;        /* SMTP command buffer */
extern time_t  smtp_connection_start;  /* Start time of SMTP connection */
extern uschar  smtp_connection_had[];  /* Recent SMTP commands */
extern int     smtp_connect_backlog;   /* Max backlog permitted */
extern double  smtp_delay_mail;        /* Current MAIL delay */
extern double  smtp_delay_rcpt;        /* Current RCPT delay */
extern BOOL    smtp_enforce_sync;      /* Enforce sync rules */
extern uschar *smtp_etrn_command;      /* Command to run */
extern BOOL    smtp_etrn_serialize;    /* Only one at once */
extern FILE   *smtp_in;                /* Incoming SMTP input file */
extern int     smtp_load_reserve;      /* Only from reserved if load > this */
extern int     smtp_mailcmd_count;     /* Count of MAIL commands */
extern int     smtp_max_synprot_errors;/* Max syntax/protocol errors */
extern int     smtp_max_unknown_commands; /* As it says */
extern uschar *smtp_notquit_reason;    /* Global for disconnect reason */
extern FILE   *smtp_out;               /* Incoming SMTP output file */
extern uschar *smtp_ratelimit_hosts;   /* Rate limit these hosts */
extern uschar *smtp_ratelimit_mail;    /* Parameters for MAIL limiting */
extern uschar *smtp_ratelimit_rcpt;    /* Parameters for RCPT limiting */
extern uschar *smtp_read_error;        /* Message for SMTP input error */
extern int     smtp_receive_timeout;   /* Applies to each received line */
extern uschar *smtp_reserve_hosts;     /* Hosts for reserved slots */
extern BOOL    smtp_return_error_details; /* TRUE to return full info */
extern int     smtp_rlm_base;          /* Base interval for MAIL rate limit */
extern double  smtp_rlm_factor;        /* Factor for MAIL rate limit */
extern int     smtp_rlm_limit;         /* Max delay */
extern int     smtp_rlm_threshold;     /* Threshold for RCPT rate limit */
extern int     smtp_rlr_base;          /* Base interval for RCPT rate limit */
extern double  smtp_rlr_factor;        /* Factor for RCPT rate limit */
extern int     smtp_rlr_limit;         /* Max delay */
extern int     smtp_rlr_threshold;     /* Threshold for RCPT rate limit */
extern BOOL    smtp_use_pipelining;    /* Global for passed connections */
extern BOOL    smtp_use_size;          /* Global for passed connections */

#ifdef WITH_CONTENT_SCAN
extern uschar *spamd_address;          /* address for the spamassassin daemon */
extern uschar *spam_bar;               /* the spam "bar" (textual representation of spam_score) */
extern uschar *spam_report;            /* the spamd report (multiline) */
extern uschar *spam_score;             /* the spam score (float) */
extern uschar *spam_score_int;         /* spam_score * 10 (int) */
#endif
#ifdef EXPERIMENTAL_SPF
extern uschar *spf_guess;              /* spf best-guess record */
extern uschar *spf_header_comment;     /* spf header comment */
extern uschar *spf_received;           /* Received-SPF: header */
extern uschar *spf_result;             /* spf result in string form */
extern uschar *spf_smtp_comment;       /* spf comment to include in SMTP reply */
#endif
extern BOOL    split_spool_directory;  /* TRUE to use multiple subdirs */
extern uschar *spool_directory;        /* Name of spool directory */
#ifdef EXPERIMENTAL_SRS
extern uschar *srs_config;             /* SRS config secret:max age:hash length:use timestamp:use hash */
extern uschar *srs_db_address;         /* SRS db address */
extern uschar *srs_db_key;             /* SRS db key */
extern int     srs_hashlength;         /* SRS hash length */
extern int     srs_hashmin;            /* SRS minimum hash length */
extern int     srs_maxage;             /* SRS max age */
extern uschar *srs_orig_sender;        /* SRS original sender */
extern uschar *srs_orig_recipient;     /* SRS original recipient */
extern uschar *srs_recipient;          /* SRS recipient */
extern uschar *srs_secrets;            /* SRS secrets list */
extern uschar *srs_status;             /* SRS staus */
extern BOOL    srs_usehash;            /* SRS use hash flag */
extern BOOL    srs_usetimestamp;       /* SRS use timestamp flag */
#endif
extern BOOL    strict_acl_vars;        /* ACL variables have to be set before being used */
extern int     string_datestamp_offset;/* After insertion by string_format */
extern BOOL    strip_excess_angle_brackets; /* Surrounding route-addrs */
extern BOOL    strip_trailing_dot;     /* Remove dots at ends of domains */
extern uschar *submission_domain;      /* Domain for submission mode */
extern BOOL    submission_mode;        /* Can be forced from ACL */
extern uschar *submission_name;        /* User name set from ACL */
extern BOOL    suppress_local_fixups;  /* Can be forced from ACL */
extern BOOL    synchronous_delivery;   /* TRUE if -odi is set */
extern BOOL    syslog_duplication;     /* FALSE => no duplicate logging */
extern int     syslog_facility;        /* As defined by Syslog.h */
extern uschar *syslog_processname;     /* 'ident' param to openlog() */
extern BOOL    syslog_timestamp;       /* TRUE if time on syslogs */
extern uschar *system_filter;          /* Name of system filter file */

extern uschar *system_filter_directory_transport;  /* Transports for the */
extern uschar *system_filter_file_transport;       /* system filter */
extern uschar *system_filter_pipe_transport;
extern uschar *system_filter_reply_transport;

extern gid_t   system_filter_gid;      /* Gid for running system filter */
extern BOOL    system_filter_gid_set;  /* TRUE if gid set */
extern uid_t   system_filter_uid;      /* Uid for running system filter */
extern BOOL    system_filter_uid_set;  /* TRUE if uid set */
extern BOOL    system_filtering;       /* TRUE when running system filter */

extern BOOL    tcp_nodelay;            /* Controls TCP_NODELAY on daemon */
#ifdef USE_TCP_WRAPPERS
extern uschar *tcp_wrappers_daemon_name; /* tcpwrappers daemon lookup name */
#endif
extern int     test_harness_load_avg;  /* For use when testing */
extern int     thismessage_size_limit; /* Limit for this message */
extern int     timeout_frozen_after;   /* Max time to keep frozen messages */
extern BOOL    timestamps_utc;         /* Use UTC for all times */
extern int     transport_count;        /* Count of bytes transported */
extern uschar **transport_filter_argv; /* For on-the-fly filtering */
extern int     transport_filter_timeout; /* Timeout for same */
extern BOOL    transport_filter_timed_out; /* True if it did */

extern transport_info transports_available[]; /* Vector of available transports */
extern transport_instance *transports; /* Chain of instantiated transports */
extern transport_instance transport_defaults; /* Default values */

extern int     transport_write_timeout;/* Set to time out individual writes */

extern tree_node *tree_dns_fails;      /* Tree of DNS lookup failures */
extern tree_node *tree_duplicates;     /* Tree of duplicate addresses */
extern tree_node *tree_nonrecipients;  /* Tree of nonrecipient addresses */
extern tree_node *tree_unusable;       /* Tree of unusable addresses */

extern BOOL    trusted_caller;         /* Caller is trusted */
extern BOOL    trusted_config;         /* Configuration file is trusted */
extern gid_t  *trusted_groups;         /* List of trusted groups */
extern uid_t  *trusted_users;          /* List of trusted users */
extern uschar *timezone_string;        /* Required timezone setting */

extern uschar *unknown_login;          /* To use when login id unknown */
extern uschar *unknown_username;       /* Ditto */
extern uschar *untrusted_set_sender;   /* Let untrusted users set these senders */
extern uschar *uucp_from_pattern;      /* For recognizing "From " lines */
extern uschar *uucp_from_sender;       /* For building the sender */

extern uschar *warn_message_file;      /* Template for warning messages */
extern uschar *warnmsg_delay;          /* String form of delay time */
extern uschar *warnmsg_recipients;     /* Recipients of warning message */
extern BOOL    write_rejectlog;        /* Control of reject logging */

extern uschar *version_copyright;      /* Copyright notice */
extern uschar *version_date;           /* Date of compilation */
extern uschar *version_cnumber;        /* Compile number */
extern uschar *version_string;         /* Version string */

extern int     warning_count;          /* Delay warnings sent for this msg */

/* End of globals.h */
