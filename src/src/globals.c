/* $Cambridge: exim/src/src/globals.c,v 1.4 2004/10/19 13:40:39 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2004 */
/* See the file NOTICE for conditions of use and distribution. */

/* All the global variables are defined together in this one module, so
that they are easy to find. */

#include "exim.h"


/* The OSF1 linker puts out a worrying warning if any sections contain no
executable code. It says

Warning: Linking some objects which contain exception information sections
        and some which do not. This may cause fatal runtime exception handling
        problems.

As this may cause people to worry needlessly, include a dummy function here
to stop the message from appearing. Make it reference itself to stop picky
compilers complaining that it is unused, and put in a dummy argument to stop
even pickier compilers complaining about infinite loops. */

static void dummy(int x) { dummy(x-1); }


/* Generic options for auths, all of which live inside auth_instance
data blocks and hence have the opt_public flag set. */

optionlist optionlist_auths[] = {
  { "driver",        opt_stringptr | opt_public,
                 (void *)(offsetof(auth_instance, driver_name)) },
  { "public_name",   opt_stringptr | opt_public,
                 (void *)(offsetof(auth_instance, public_name)) },
  { "server_advertise_condition", opt_stringptr | opt_public,
                 (void *)(offsetof(auth_instance, advertise_condition))},
  { "server_debug_print", opt_stringptr | opt_public,
                 (void *)(offsetof(auth_instance, server_debug_string)) },
  { "server_mail_auth_condition", opt_stringptr | opt_public,
                 (void *)(offsetof(auth_instance, mail_auth_condition)) },
  { "server_set_id", opt_stringptr | opt_public,
                 (void *)(offsetof(auth_instance, set_id)) }
};

int     optionlist_auths_size = sizeof(optionlist_auths)/sizeof(optionlist);

/* An empty host aliases list. */

uschar *no_aliases             = NULL;


/* For comments on these variables, see globals.h. I'm too idle to
duplicate them here... */

#ifdef EXIM_PERL
uschar *opt_perl_startup       = NULL;
BOOL    opt_perl_at_start      = FALSE;
BOOL    opt_perl_started       = FALSE;
#endif

#ifdef LOOKUP_IBASE
uschar *ibase_servers          = NULL;
#endif

#ifdef LOOKUP_LDAP
uschar *eldap_default_servers  = NULL;
int     eldap_version          = -1;
#endif

#ifdef LOOKUP_MYSQL
uschar *mysql_servers          = NULL;
#endif

#ifdef LOOKUP_ORACLE
uschar *oracle_servers         = NULL;
#endif

#ifdef LOOKUP_PGSQL
uschar *pgsql_servers          = NULL;
#endif

#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
BOOL    move_frozen_messages   = FALSE;
#endif

/* These variables are outside the #ifdef because it keeps the code less
cluttered in several places (e.g. during logging) if we can always refer to
them. Also, the tls_ variables are now always visible. */

BOOL    tls_active             = -1;
BOOL    tls_certificate_verified = FALSE;
uschar *tls_cipher             = NULL;
BOOL    tls_on_connect         = FALSE;
uschar *tls_on_connect_ports   = NULL;
uschar *tls_peerdn             = NULL;

#ifdef SUPPORT_TLS
const pcre *regex_STARTTLS     = NULL;
uschar *tls_advertise_hosts    = NULL;    /* This is deliberate */
uschar *tls_certificate        = NULL;
uschar *tls_crl                = NULL;
uschar *tls_dhparam            = NULL;
BOOL    tls_offered            = FALSE;
uschar *tls_privatekey         = NULL;
BOOL    tls_remember_esmtp     = FALSE;
uschar *tls_require_ciphers    = NULL;
uschar *tls_try_verify_hosts   = NULL;
uschar *tls_verify_certificates= NULL;
uschar *tls_verify_hosts       = NULL;
#endif


/* Input-reading functions for messages, so we can use special ones for
incoming TCP/IP. The defaults use stdin. We never need these for any
stand-alone tests. */

#ifndef STAND_ALONE
int (*receive_getc)(void)      = stdin_getc;
int (*receive_ungetc)(int)     = stdin_ungetc;
int (*receive_feof)(void)      = stdin_feof;
int (*receive_ferror)(void)    = stdin_ferror;
#endif


/* List of per-address expansion variables for clearing and saving/restoring
when verifying one address while routing/verifying another. We have to have
the size explicit, because it is referenced from more than one module. */

uschar **address_expansions[ADDRESS_EXPANSIONS_COUNT] = {
  &deliver_address_data,
  &deliver_domain,
  &deliver_domain_data,
  &deliver_domain_orig,
  &deliver_domain_parent,
  &deliver_localpart,
  &deliver_localpart_data,
  &deliver_localpart_orig,
  &deliver_localpart_parent,
  &deliver_localpart_prefix,
  &deliver_localpart_suffix,
  (uschar **)(&deliver_recipients),
  &deliver_host,
  &deliver_home,
  &address_file,
  &address_pipe,
  &self_hostname,
  NULL };

int address_expansions_count = sizeof(address_expansions)/sizeof(uschar **);

/* General global variables */

tree_node *acl_anchor          = NULL;
uschar *acl_not_smtp           = NULL;
uschar *acl_smtp_auth          = NULL;
uschar *acl_smtp_connect       = NULL;
uschar *acl_smtp_data          = NULL;
uschar *acl_smtp_etrn          = NULL;
uschar *acl_smtp_expn          = NULL;
uschar *acl_smtp_helo          = NULL;
uschar *acl_smtp_mail          = NULL;
uschar *acl_smtp_mailauth      = NULL;
uschar *acl_smtp_predata       = NULL;
uschar *acl_smtp_quit          = NULL;
uschar *acl_smtp_rcpt          = NULL;
uschar *acl_smtp_starttls      = NULL;
uschar *acl_smtp_vrfy          = NULL;
BOOL    acl_temp_details       = FALSE;
uschar *acl_var[ACL_C_MAX+ACL_M_MAX];
uschar *acl_verify_message     = NULL;
header_line *acl_warn_headers  = NULL;
string_item *acl_warn_logged   = NULL;

/* Names of SMTP places for use in ACL error messages, and corresponding SMTP
error codes - keep in step with definitions of ACL_WHERE_xxxx in macros.h. */

uschar *acl_wherenames[]       = { US"RCPT",
                                   US"MAIL",
                                   US"PREDATA",
                                   US"DATA",
                                   US"non-SMTP",
                                   US"AUTH",
                                   US"connection",
                                   US"ETRN",
                                   US"EXPN",
                                   US"EHLO or HELO",
                                   US"MAILAUTH",
                                   US"QUIT",
                                   US"STARTTLS",
                                   US"VRFY"
                                 };

int     acl_wherecodes[]       = { 550,     /* RCPT */
                                   550,     /* MAIL */
                                   550,     /* PREDATA */
                                   550,     /* DATA */
                                   0,       /* not SMTP; not relevant */
                                   503,     /* AUTH */
                                   550,     /* connect */
                                   458,     /* ETRN */
                                   550,     /* EXPN */
                                   550,     /* HELO/EHLO */
                                   0,       /* MAILAUTH; not relevant */
                                   0,       /* QUIT; not relevant */
                                   550,     /* STARTTLS */
                                   252      /* VRFY */
                                 };
                                 
BOOL    active_local_from_check = FALSE;
BOOL    active_local_sender_retain = FALSE;
BOOL    accept_8bitmime        = FALSE;
address_item  *addr_duplicate  = NULL;

address_item address_defaults = {
  NULL,                 /* next */
  NULL,                 /* parent */
  NULL,                 /* first */
  NULL,                 /* dupof */
  NULL,                 /* start_router */
  NULL,                 /* router */
  NULL,                 /* transport */
  NULL,                 /* host_list */
  NULL,                 /* host_used */
  NULL,                 /* fallback_hosts */
  NULL,                 /* reply */
  NULL,                 /* retries */
  NULL,                 /* address */
  NULL,                 /* unique */
  NULL,                 /* cc_local_part */
  NULL,                 /* lc_local_part */
  NULL,                 /* local_part */
  NULL,                 /* prefix */
  NULL,                 /* suffix */
  NULL,                 /* domain */
  NULL,                 /* address_retry_key */
  NULL,                 /* domain_retry_key */
  NULL,                 /* current_dir */
  NULL,                 /* home_dir */
  NULL,                 /* message */
  NULL,                 /* user_message */
  NULL,                 /* onetime_parent */
  NULL,                 /* pipe_expandn */
  NULL,                 /* return_filename */
  NULL,                 /* self_hostname */
  NULL,                 /* shadow_message */
  #ifdef SUPPORT_TLS
  NULL,                 /* cipher */
  NULL,                 /* peerdn */
  #endif
  (uid_t)(-1),          /* uid */
  (gid_t)(-1),          /* gid */
  0,                    /* flags */
  { 0 },                /* domain_cache - any larger array should be zeroed */
  { 0 },                /* localpart_cache - ditto */
  -1,                   /* mode */
  0,                    /* more_errno */
  ERRNO_UNKNOWNERROR,   /* basic_errno */
  0,                    /* child_count */
  -1,                   /* return_file */
  SPECIAL_NONE,         /* special_action */
  DEFER,                /* transport_return */
  {                     /* fields that are propagated to children */
    NULL,               /* address_data */
    NULL,               /* domain_data */
    NULL,               /* localpart_data */
    NULL,               /* errors_address */
    NULL,               /* extra_headers */
    NULL,               /* remove_headers */
  }
};

uschar *address_file           = NULL;
uschar *address_pipe           = NULL;
BOOL    address_test_mode      = FALSE;
tree_node *addresslist_anchor  = NULL;
int     addresslist_count      = 0;
gid_t  *admin_groups           = NULL;
BOOL    admin_user             = FALSE;
BOOL    allow_domain_literals  = FALSE;
BOOL    allow_mx_to_ip         = FALSE;
BOOL    allow_unqualified_recipient = TRUE;    /* For local messages */
BOOL    allow_unqualified_sender = TRUE;       /* Reset for SMTP */
BOOL    allow_utf8_domains     = FALSE;
uschar *authenticated_id       = NULL;
uschar *authenticated_sender   = NULL;
BOOL    authentication_failed  = FALSE;
auth_instance  *auths          = NULL;
uschar *auth_advertise_hosts   = US"*";
auth_instance auth_defaults    = {
    NULL,                      /* chain pointer */
    NULL,                      /* name */
    NULL,                      /* info */
    NULL,                      /* private options block pointer */
    NULL,                      /* driver_name */
    NULL,                      /* advertise_condition */
    NULL,                      /* public_name */
    NULL,                      /* set_id */
    NULL,                      /* server_mail_auth_condition */
    NULL,                      /* server_debug_string */
    FALSE,                     /* client */
    FALSE,                     /* server */
    FALSE                      /* advertised */
};

uschar *auth_defer_msg         = US"reason not recorded";
uschar *auth_defer_user_msg    = US"";
int     auto_thaw              = 0;

BOOL    background_daemon      = TRUE;
uschar *base62_chars=
    US"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
uschar *bi_command             = NULL;
uschar *big_buffer             = NULL;
int     big_buffer_size        = BIG_BUFFER_SIZE;
int     body_linecount         = 0;
int     body_zerocount         = 0;
uschar *bounce_message_file    = NULL;
uschar *bounce_message_text    = NULL;
uschar *bounce_recipient       = NULL;
BOOL    bounce_return_body     = TRUE;
BOOL    bounce_return_message  = TRUE;
int     bounce_return_size_limit = 100*1024;
uschar *bounce_sender_authentication = NULL;
int     bsmtp_transaction_linecount = 0;

int     callout_cache_domain_positive_expire = 7*24*60*60;
int     callout_cache_domain_negative_expire = 3*60*60;
int     callout_cache_positive_expire = 24*60*60;
int     callout_cache_negative_expire = 2*60*60;
uschar *callout_random_local_part = US"$primary_hostname-$tod_epoch-testing";
uschar *check_dns_names_pattern= US"(?i)^(?>(?(1)\\.|())[^\\W_](?>[a-z0-9-]*[^\\W_])?)+$";
int     check_log_inodes       = 0;
int     check_log_space        = 0;
int     check_spool_inodes     = 0;
int     check_spool_space      = 0;
int     clmacro_count          = 0;
uschar *clmacros[MAX_CLMACROS];
BOOL    config_changed         = FALSE;
FILE   *config_file            = NULL;
uschar *config_filename        = NULL;
int     config_lineno          = 0;
#ifdef CONFIGURE_GROUP
gid_t   config_gid             = CONFIGURE_GROUP;
#endif
uschar *config_main_filelist   = US CONFIGURE_FILE
                         "\0<-----------Space to patch configure_filename->";
uschar *config_main_filename   = NULL;

#ifdef CONFIGURE_OWNER
uid_t   config_uid             = CONFIGURE_OWNER;
#endif

int     connection_max_messages= -1;
uschar *continue_hostname      = NULL;
uschar *continue_host_address  = NULL;
BOOL    continue_more          = FALSE;
int     continue_sequence      = 1;
uschar *continue_transport     = NULL;

BOOL    daemon_listen          = FALSE;
uschar *daemon_smtp_port       = US"smtp";
int     debug_fd               = -1;
FILE   *debug_file             = NULL;
bit_table debug_options[]      = {
  { US"acl",            D_acl },
  { US"all",            D_all },
  { US"auth",           D_auth },
  { US"deliver",        D_deliver },
  { US"dns",            D_dns },
  { US"dnsbl",          D_dnsbl },
  { US"exec",           D_exec },
  { US"expand",         D_expand },
  { US"filter",         D_filter },
  { US"hints_lookup",   D_hints_lookup },
  { US"host_lookup",    D_host_lookup },
  { US"ident",          D_ident },
  { US"interface",      D_interface },
  { US"lists",          D_lists },
  { US"load",           D_load },
  { US"local_scan",     D_local_scan },
  { US"lookup",         D_lookup },
  { US"memory",         D_memory },
  { US"pid",            D_pid },
  { US"process_info",   D_process_info },
  { US"queue_run",      D_queue_run },
  { US"receive",        D_receive },
  { US"resolver",       D_resolver },
  { US"retry",          D_retry },
  { US"rewrite",        D_rewrite },
  { US"route",          D_route },
  { US"timestamp",      D_timestamp },
  { US"tls",            D_tls },
  { US"transport",      D_transport },
  { US"uid",            D_uid },
  { US"verify",         D_verify }
};
int     debug_options_count    = sizeof(debug_options)/sizeof(bit_table);
unsigned int debug_selector    = 0;
int     delay_warning[DELAY_WARNING_SIZE] = { DELAY_WARNING_SIZE, 1, 24*60*60 };
uschar *delay_warning_condition= US"${if match{$h_precedence:}{(?i)bulk|list|junk}{no}{yes}}";
BOOL    delivery_date_remove   = TRUE;
uschar *deliver_address_data   = NULL;
int     deliver_datafile       = -1;
uschar *deliver_domain         = NULL;
uschar *deliver_domain_data    = NULL;
uschar *deliver_domain_orig    = NULL;
uschar *deliver_domain_parent  = NULL;
BOOL    deliver_drop_privilege = FALSE;
BOOL    deliver_firsttime      = FALSE;
BOOL    deliver_force          = FALSE;
BOOL    deliver_freeze         = FALSE;
int     deliver_frozen_at      = 0;
uschar *deliver_home           = NULL;
uschar *deliver_host           = NULL;
uschar *deliver_host_address   = NULL;
uschar *deliver_in_buffer      = NULL;
ino_t   deliver_inode          = 0;
uschar *deliver_localpart      = NULL;
uschar *deliver_localpart_data = NULL;
uschar *deliver_localpart_orig = NULL;
uschar *deliver_localpart_parent = NULL;
uschar *deliver_localpart_prefix = NULL;
uschar *deliver_localpart_suffix = NULL;
BOOL    deliver_force_thaw     = FALSE;
BOOL    deliver_manual_thaw    = FALSE;
uschar *deliver_out_buffer     = NULL;
int     deliver_queue_load_max = -1;
address_item  *deliver_recipients = NULL;
uschar *deliver_selectstring   = NULL;
BOOL    deliver_selectstring_regex = FALSE;
uschar *deliver_selectstring_sender = NULL;
BOOL    deliver_selectstring_sender_regex = FALSE;
BOOL    disable_logging        = FALSE;

uschar *dns_again_means_nonexist = NULL;
uschar *dns_ipv4_lookup        = NULL;
int     dns_retrans            = 0;
int     dns_retry              = 0;
uschar *dnslist_domain         = NULL;
uschar *dnslist_text           = NULL;
uschar *dnslist_value          = NULL;
tree_node *domainlist_anchor   = NULL;
int     domainlist_count       = 0;
BOOL    dont_deliver           = FALSE;
BOOL    dot_ends               = TRUE;
BOOL    drop_cr                = FALSE;         /* No longer used */

BOOL    enable_dollar_recipients = FALSE;
BOOL    envelope_to_remove     = TRUE;
int     errno_quota            = ERRNO_QUOTA;
uschar *errors_copy            = NULL;
int     error_handling         = ERRORS_SENDER;
uschar *errors_reply_to        = NULL;
int     errors_sender_rc       = EXIT_FAILURE;

gid_t   exim_gid               = EXIM_GID;
BOOL    exim_gid_set           = TRUE;          /* This gid is always set */
uschar *exim_path              = US BIN_DIRECTORY "/exim"
                        "\0<---------------Space to patch exim_path->";
uid_t   exim_uid               = EXIM_UID;
BOOL    exim_uid_set           = TRUE;          /* This uid is always set */
int     expand_forbid          = 0;
int     expand_nlength[EXPAND_MAXN+1];
int     expand_nmax            = -1;
uschar *expand_nstring[EXPAND_MAXN+1];
BOOL    expand_string_forcedfail = FALSE;
uschar *expand_string_message;
BOOL    extract_addresses_remove_arguments = TRUE;
uschar *extra_local_interfaces = NULL;

int     filter_n[FILTER_VARIABLE_COUNT];
BOOL    filter_running         = FALSE;
int     filter_sn[FILTER_VARIABLE_COUNT];
uschar *filter_test            = NULL;
uschar *filter_thisaddress     = NULL;
int     finduser_retries       = 0;
uid_t   fixed_never_users[]    = { FIXED_NEVER_USERS };
uschar *freeze_tell            = NULL;
uschar *fudged_queue_times     = US"";

uschar *gecos_name             = NULL;
uschar *gecos_pattern          = NULL;
rewrite_rule  *global_rewrite_rules = NULL;

uschar *headers_charset        = US HEADERS_CHARSET;
int     header_insert_maxlen   = 64 * 1024;
header_line  *header_last      = NULL;
header_line  *header_list      = NULL;
int     header_maxsize         = HEADER_MAXSIZE;
int     header_line_maxsize    = 0;

header_name header_names[] = {
  { US"bcc",            3, TRUE,  htype_bcc },
  { US"cc",             2, TRUE,  htype_cc },
  { US"date",           4, TRUE,  htype_date },
  { US"delivery-date", 13, FALSE, htype_delivery_date },
  { US"envelope-to",   11, FALSE, htype_envelope_to },
  { US"from",           4, TRUE,  htype_from },
  { US"message-id",    10, TRUE,  htype_id },
  { US"received",       8, FALSE, htype_received },
  { US"reply-to",       8, FALSE, htype_reply_to },
  { US"return-path",   11, FALSE, htype_return_path },
  { US"sender",         6, TRUE,  htype_sender },
  { US"subject",        7, FALSE, htype_subject },
  { US"to",             2, TRUE,  htype_to }
};

int header_names_size          = sizeof(header_names)/sizeof(header_name);

BOOL    header_rewritten       = FALSE;
uschar *helo_accept_junk_hosts = NULL;
uschar *helo_allow_chars       = US"";
uschar *helo_lookup_domains    = US"@ : @[]";
uschar *helo_try_verify_hosts  = NULL;
BOOL    helo_verified          = FALSE;
uschar *helo_verify_hosts      = NULL;
uschar *hex_digits             = US"0123456789abcdef";
uschar *hold_domains           = NULL;
BOOL    host_checking          = FALSE;
BOOL    host_checking_callout  = FALSE;
uschar *host_data              = NULL;
BOOL    host_find_failed_syntax= FALSE;
uschar *host_lookup            = NULL;
BOOL    host_lookup_failed     = FALSE;
uschar *host_lookup_order      = US"bydns:byaddr";
uschar *host_lookup_msg        = US"";
int     host_number            = 0;
uschar *host_number_string     = NULL;
uschar *host_reject_connection = NULL;
tree_node *hostlist_anchor     = NULL;
int     hostlist_count         = 0;
uschar *hosts_treat_as_local   = NULL;
uschar *hosts_connection_nolog = NULL;

int     ignore_bounce_errors_after = 10*7*24*60*60;  /* 10 weeks */
BOOL    ignore_fromline_local  = FALSE;
uschar *ignore_fromline_hosts  = NULL;
uschar *interface_address      = NULL;
int     interface_port         = -1;
BOOL    is_inetd               = FALSE;

int     journal_fd             = -1;

int     keep_malformed         = 4*24*60*60;    /* 4 days */

uschar *eldap_dn               = NULL;
int     load_average           = -2;
BOOL    local_error_message    = FALSE;
BOOL    local_from_check       = TRUE;
uschar *local_from_prefix      = NULL;
uschar *local_from_suffix      = NULL;

#if HAVE_IPV6
uschar *local_interfaces       = US"<; ::0 ; 0.0.0.0";
#else
uschar *local_interfaces       = US"0.0.0.0";
#endif

uschar *local_scan_data        = NULL;
int     local_scan_timeout     = 5*60;
BOOL    local_sender_retain    = FALSE;
gid_t   local_user_gid         = (gid_t)(-1);
uid_t   local_user_uid         = (uid_t)(-1);

tree_node *localpartlist_anchor= NULL;
int     localpartlist_count    = 0;
uschar *log_buffer             = NULL;
unsigned int log_extra_selector = LX_default;
uschar *log_file_path          = US LOG_FILE_PATH
                           "\0<--------------Space to patch log_file_path->";

/* Those log options with L_xxx identifiers have values less than 0x800000 and
are the ones that get put into log_write_selector. They can be used in calls to
log_write() to test for the bit. The options with LX_xxx identifiers have
values greater than 0x80000000 and are put int log_extra_selector (without the
top bit). They are never used in calls to log_write(), but are tested
independently. This separation became necessary when the number of log
selectors was getting close to filling a 32-bit word. */

bit_table log_options[]        = {
  { US"address_rewrite",              L_address_rewrite },
  { US"all",                          L_all },
  { US"all_parents",                  L_all_parents },
  { US"arguments",                    LX_arguments },
  { US"connection_reject",            L_connection_reject },
  { US"delay_delivery",               L_delay_delivery },
  { US"deliver_time",                 LX_deliver_time },
  { US"delivery_size",                LX_delivery_size },
  { US"dnslist_defer",                L_dnslist_defer },
  { US"etrn",                         L_etrn },
  { US"host_lookup_failed",           L_host_lookup_failed },
  { US"ident_timeout",                LX_ident_timeout },
  { US"incoming_interface",           LX_incoming_interface },
  { US"incoming_port",                LX_incoming_port },
  { US"lost_incoming_connection",     L_lost_incoming_connection },
  { US"outgoing_port",                LX_outgoing_port },
  { US"queue_run",                    L_queue_run },
  { US"queue_time",                   LX_queue_time },
  { US"received_recipients",          LX_received_recipients },
  { US"received_sender",              LX_received_sender },
  { US"rejected_header",              LX_rejected_header },
  { US"rejected_headers",             LX_rejected_header },
  { US"retry_defer",                  L_retry_defer },
  { US"return_path_on_delivery",      LX_return_path_on_delivery },
  { US"sender_on_delivery",           LX_sender_on_delivery },
  { US"size_reject",                  L_size_reject },
  { US"skip_delivery",                L_skip_delivery },
  { US"smtp_confirmation",            LX_smtp_confirmation },
  { US"smtp_connection",              L_smtp_connection },
  { US"smtp_incomplete_transaction",  L_smtp_incomplete_transaction },
  { US"smtp_protocol_error",          L_smtp_protocol_error },
  { US"smtp_syntax_error",            L_smtp_syntax_error },
  { US"subject",                      LX_subject },
  { US"tls_certificate_verified",     LX_tls_certificate_verified },
  { US"tls_cipher",                   LX_tls_cipher },
  { US"tls_peerdn",                   LX_tls_peerdn }
};

int     log_options_count      = sizeof(log_options)/sizeof(bit_table);
unsigned int log_write_selector= L_default;
uschar *log_selector_string    = NULL;
FILE   *log_stderr             = NULL;
BOOL    log_testing_mode       = FALSE;
BOOL    log_timezone           = FALSE;
uschar *login_sender_address   = NULL;
int     lookup_open_max        = 25;
uschar *lookup_value           = NULL;

macro_item  *macros            = NULL;
uschar *mailstore_basename     = NULL;
int     max_username_length    = 0;
int     message_age            = 0;
uschar *message_body           = NULL;
uschar *message_body_end       = NULL;
int     message_body_size      = 0;
int     message_body_visible   = 500;
int     message_ended          = END_NOTSTARTED;
uschar *message_headers        = NULL;
uschar *message_id;
uschar *message_id_domain      = NULL;
uschar *message_id_text        = NULL;
struct timeval message_id_tv   = { 0, 0 };
uschar  message_id_option[MESSAGE_ID_LENGTH + 3];
uschar *message_id_external;
int     message_linecount      = 0;
BOOL    message_logs           = TRUE;
int     message_size           = 0;
uschar *message_size_limit     = US"50M";
uschar  message_subdir[2]      = { 0, 0 };
uschar *message_reference      = NULL;
BOOL    mua_wrapper            = FALSE;

uid_t  *never_users            = NULL;
BOOL    no_multiline_responses = FALSE;

uid_t   original_euid;
gid_t   originator_gid;
uschar *originator_login       = NULL;
uschar *originator_name        = NULL;
uid_t   originator_uid;
uschar *override_local_interfaces = NULL;
uschar *override_pid_file_path = NULL;

BOOL    parse_allow_group      = FALSE;
BOOL    parse_found_group      = FALSE;
uschar *percent_hack_domains   = NULL;
uschar *pid_file_path          = US PID_FILE_PATH
                           "\0<--------------Space to patch pid_file_path->";
uschar *pipelining_advertise_hosts = US"*";
BOOL    preserve_message_logs  = FALSE;
uschar *primary_hostname       = NULL;
BOOL    print_topbitchars      = FALSE;
uschar  process_info[PROCESS_INFO_SIZE];
uschar *process_log_path       = NULL;
BOOL    prod_requires_admin    = TRUE;

uschar *qualify_domain_recipient = NULL;
uschar *qualify_domain_sender  = NULL;
BOOL    queue_2stage           = FALSE;
uschar *queue_domains          = NULL;
int     queue_interval         = -1;
BOOL    queue_list_requires_admin = TRUE;
BOOL    queue_only             = FALSE;
uschar *queue_only_file        = NULL;
int     queue_only_load        = -1;
BOOL    queue_only_override    = TRUE;
BOOL    queue_only_policy      = FALSE;
BOOL    queue_run_first_delivery = FALSE;
BOOL    queue_run_force        = FALSE;
BOOL    queue_run_in_order     = FALSE;
BOOL    queue_run_local        = FALSE;
int     queue_run_max          = 5;
pid_t   queue_run_pid          = (pid_t)0;
int     queue_run_pipe         = -1;
BOOL    queue_running          = FALSE;
BOOL    queue_smtp             = FALSE;
uschar *queue_smtp_domains     = NULL;

unsigned int random_seed       = 0;
uschar *raw_active_hostname    = NULL;
uschar *raw_sender             = NULL;
uschar **raw_recipients        = NULL;
int     raw_recipients_count   = 0;

int     rcpt_count             = 0;
int     rcpt_fail_count        = 0;
int     rcpt_defer_count       = 0;
gid_t   real_gid;
uid_t   real_uid;
BOOL    really_exim            = TRUE;
BOOL    receive_call_bombout   = FALSE;
int     receive_linecount      = 0;
int     receive_messagecount   = 0;
int     receive_timeout        = 0;
int     received_count         = 0;
uschar *received_for           = NULL;

/*  This is the default text for Received headers generated by Exim. The
date  will be automatically added on the end. */

uschar *received_header_text   = US
     "Received: "
     "${if def:sender_rcvhost {from $sender_rcvhost\n\t}"
     "{${if def:sender_ident {from $sender_ident }}"
     "${if def:sender_helo_name {(helo=$sender_helo_name)\n\t}}}}"
     "by $primary_hostname "
     "${if def:received_protocol {with $received_protocol}} "
     #ifdef SUPPORT_TLS
     "${if def:tls_cipher {($tls_cipher)\n\t}}"
     #endif
     "(Exim $version_number)\n\t"
     "id $message_id"
     "${if def:received_for {\n\tfor $received_for}}"
     "\0<---------------Space to patch received_header_text->";

int     received_headers_max   = 30;
uschar *received_protocol      = NULL;
int     received_time          = 0;
uschar *recipient_data         = NULL;
uschar *recipient_unqualified_hosts = NULL;
int     recipients_count       = 0;
BOOL    recipients_discarded   = FALSE;
recipient_item  *recipients_list = NULL;
int     recipients_list_max    = 0;
int     recipients_max         = 0;
BOOL    recipients_max_reject  = FALSE;
const pcre *regex_AUTH         = NULL;
const pcre *regex_check_dns_names = NULL;
const pcre *regex_From         = NULL;
const pcre *regex_PIPELINING   = NULL;
const pcre *regex_SIZE         = NULL;
const pcre *regex_ismsgid      = NULL;
int     remote_delivery_count  = 0;
int     remote_max_parallel    = 2;
uschar *remote_sort_domains    = NULL;
int     retry_data_expire      = 7*24*60*60;
int     retry_interval_max     = 24*60*60;
int     retry_maximum_timeout  = 0;        /* set from retry config */
retry_config  *retries         = NULL;
uschar *return_path            = NULL;
BOOL    return_path_remove     = TRUE;
int     rewrite_existflags     = 0;
uschar *rfc1413_hosts          = US"*";
int     rfc1413_query_timeout  = 30;
/* BOOL    rfc821_domains         = FALSE;  <<< on the way out */
uid_t   root_uid               = ROOT_UID;

router_instance  *routers  = NULL;
router_instance  router_defaults = {
    NULL,                      /* chain pointer */
    NULL,                      /* name */
    NULL,                      /* info */
    NULL,                      /* private options block pointer */
    NULL,                      /* driver name */

    NULL,                      /* address_data */
    NULL,                      /* cannot_route_message */
    NULL,                      /* condition */
    NULL,                      /* current_directory */
    NULL,                      /* debug_string */
    NULL,                      /* domains */
    NULL,                      /* errors_to */
    NULL,                      /* expand_gid */
    NULL,                      /* expand_uid */
    NULL,                      /* expand_more */
    NULL,                      /* expand_unseen */
    NULL,                      /* extra_headers */
    NULL,                      /* fallback_hosts */
    NULL,                      /* home_directory */
    NULL,                      /* ignore_target_hosts */
    NULL,                      /* local_parts */
    NULL,                      /* pass_router_name */
    NULL,                      /* prefix */
    NULL,                      /* redirect_router_name */
    NULL,                      /* remove_headers */
    NULL,                      /* require_files */
    NULL,                      /* router_home_directory */
    US"freeze",                /* self */
    NULL,                      /* senders */
    NULL,                      /* suffix */
    NULL,                      /* translate_ip_address */
    NULL,                      /* transport_name */

    TRUE,                      /* address_test */
    TRUE,                      /* expn */
    FALSE,                     /* caseful_local_part */
    FALSE,                     /* check_local_user */
    FALSE,                     /* disable_logging */
    FALSE,                     /* fail_verify_recipient */
    FALSE,                     /* fail_verify_sender */
    FALSE,                     /* gid_set */
    FALSE,                     /* initgroups */
    TRUE_UNSET,                /* log_as_local */
    TRUE,                      /* more */
    FALSE,                     /* pass_on_timeout */
    FALSE,                     /* prefix_optional */
    TRUE,                      /* repeat_use */
    TRUE_UNSET,                /* retry_use_local_part - fudge "unset" */
    FALSE,                     /* same_domain_copy_routing */
    FALSE,                     /* self_rewrite */
    FALSE,                     /* suffix_optional */
    FALSE,                     /* verify_only */
    TRUE,                      /* verify_recipient */
    TRUE,                      /* verify_sender */
    FALSE,                     /* uid_set */
    FALSE,                     /* unseen */

    self_freeze,               /* self_code */
    (uid_t)(-1),               /* uid */
    (gid_t)(-1),               /* gid */

    NULL,                      /* fallback_hostlist */
    NULL,                      /* transport instance */
    NULL,                      /* pass_router */
    NULL                       /* redirect_router */
};

ip_address_item *running_interfaces = NULL;
BOOL    running_in_test_harness = FALSE;

/* This is a weird one. The following string gets patched in the binary by the
script that sets up a copy of Exim for running in the test harness. It seems
that compilers are now clever, and share constant strings if they can.
Elsewhere in Exim the string "<" is used. The compiler optimization seems to
make use of the end of this string in order to save space. So the patching then
wrecks this. We default this optimization by adding some additional characters
onto the end of the string. */

uschar *running_status         = US">>>running<<<" "\0EXTRA";

int     runrc                  = 0;

uschar *search_error_message   = NULL;
BOOL    search_find_defer      = FALSE;
uschar *self_hostname          = NULL;
uschar *sender_address         = NULL;
unsigned int sender_address_cache[(MAX_NAMED_LIST * 2)/32];
uschar *sender_address_data    = NULL;
BOOL    sender_address_forced  = FALSE;
uschar *sender_address_unrewritten = NULL;
uschar *sender_data            = NULL;
unsigned int sender_domain_cache[(MAX_NAMED_LIST * 2)/32];
uschar *sender_fullhost        = NULL;
uschar *sender_helo_name       = NULL;
uschar **sender_host_aliases   = &no_aliases;
uschar *sender_host_address    = NULL;
uschar *sender_host_authenticated = NULL;
unsigned int sender_host_cache[(MAX_NAMED_LIST * 2)/32];
uschar *sender_host_name       = NULL;
int     sender_host_port       = 0;
BOOL    sender_host_notsocket  = FALSE;
BOOL    sender_host_unknown    = FALSE;
uschar *sender_ident           = NULL;
BOOL    sender_local           = FALSE;
uschar *sender_rcvhost         = NULL;
BOOL    sender_set_untrusted   = FALSE;
uschar *sender_unqualified_hosts = NULL;
address_item *sender_verified_list  = NULL;
address_item *sender_verified_failed = NULL;
int     sender_verified_rc     = -1;
BOOL    sender_verified_responded = FALSE;
volatile  BOOL sigalrm_seen    = FALSE;
uschar **sighup_argv           = NULL;
int     smtp_accept_count      = 0;
BOOL    smtp_accept_keepalive  = TRUE;
int     smtp_accept_max        = 20;
int     smtp_accept_max_nonmail= 10;
uschar *smtp_accept_max_nonmail_hosts = US"*";
int     smtp_accept_max_per_connection = 1000;
uschar *smtp_accept_max_per_host = NULL;
int     smtp_accept_queue      = 0;
int     smtp_accept_queue_per_connection = 10;
int     smtp_accept_reserve    = 0;
uschar *smtp_active_hostname   = NULL;
BOOL    smtp_authenticated     = FALSE;
uschar *smtp_banner            = US"$primary_hostname ESMTP "
                             "Exim $version_number $tod_full"
                             "\0<---------------Space to patch smtp_banner->";
BOOL    smtp_batched_input     = FALSE;
BOOL    smtp_check_spool_space = TRUE;
uschar *smtp_command_argument  = NULL;
int     smtp_connect_backlog   = 20;
double  smtp_delay_mail        = 0.0;
double  smtp_delay_rcpt        = 0.0;
BOOL    smtp_enforce_sync      = TRUE;
FILE   *smtp_in                = NULL;
BOOL    smtp_input             = FALSE;
int     smtp_load_reserve      = -1;
int     smtp_mailcmd_count     = 0;
FILE   *smtp_out               = NULL;
uschar *smtp_etrn_command      = NULL;
BOOL    smtp_etrn_serialize    = TRUE;
int     smtp_max_synprot_errors= 3;
int     smtp_max_unknown_commands = 3;
uschar *smtp_ratelimit_hosts   = NULL;
uschar *smtp_ratelimit_mail    = NULL;
uschar *smtp_ratelimit_rcpt    = NULL;
uschar *smtp_read_error        = US"";
int     smtp_receive_timeout   = 5*60;
uschar *smtp_reserve_hosts     = NULL;
BOOL    smtp_return_error_details = FALSE;
int     smtp_rlm_base          = 0;
double  smtp_rlm_factor        = 0.0;
int     smtp_rlm_limit         = 0;
int     smtp_rlm_threshold     = INT_MAX;
int     smtp_rlr_base          = 0;
double  smtp_rlr_factor        = 0.0;
int     smtp_rlr_limit         = 0;
int     smtp_rlr_threshold     = INT_MAX;
BOOL    smtp_use_pipelining    = FALSE;
BOOL    smtp_use_size          = FALSE;
BOOL    split_spool_directory  = FALSE;
uschar *spool_directory        = US SPOOL_DIRECTORY
                           "\0<--------------Space to patch spool_directory->";
int     string_datestamp_offset= -1;
BOOL    strip_excess_angle_brackets = FALSE;
BOOL    strip_trailing_dot     = FALSE;
uschar *submission_domain      = NULL;
BOOL    submission_mode        = FALSE;
BOOL    synchronous_delivery   = FALSE;
BOOL    syslog_duplication     = TRUE;
int     syslog_facility        = LOG_MAIL;
uschar *syslog_processname     = US"exim";
BOOL    syslog_timestamp       = TRUE;
uschar *system_filter          = NULL;

uschar *system_filter_directory_transport = NULL;
uschar *system_filter_file_transport = NULL;
uschar *system_filter_pipe_transport = NULL;
uschar *system_filter_reply_transport = NULL;

gid_t   system_filter_gid      = 0;
BOOL    system_filter_gid_set  = FALSE;
uid_t   system_filter_uid      = 0;
BOOL    system_filter_uid_set  = FALSE;
BOOL    system_filtering       = FALSE;

BOOL    tcp_nodelay            = TRUE;
int     thismessage_size_limit = 0;
int     timeout_frozen_after   = 0;
BOOL    timestamps_utc         = FALSE;

transport_instance  *transports = NULL;

transport_instance  transport_defaults = {
    NULL,                     /* chain pointer */
    NULL,                     /* name */
    NULL,                     /* info */
    NULL,                     /* private options block pointer */
    NULL,                     /* driver name */
    NULL,                     /* setup entry point */
    1,                        /* batch_max */
    NULL,                     /* batch_id */
    NULL,                     /* home_dir */
    NULL,                     /* current_dir */
    TRUE,                     /* multi-domain */
    FALSE,                    /* overrides_hosts */
    100,                      /* max_addresses */
    500,                      /* connection_max_messages */
    FALSE,                    /* deliver_as_creator */
    FALSE,                    /* disable_logging */
    FALSE,                    /* initgroups */
    FALSE,                    /* uid_set */
    FALSE,                    /* gid_set */
    (uid_t)(-1),              /* uid */
    (gid_t)(-1),              /* gid */
    NULL,                     /* expand_uid */
    NULL,                     /* expand_gid */
    NULL,                     /* warn_message */
    NULL,                     /* shadow */
    NULL,                     /* shadow_condition */
    NULL,                     /* filter_command */
    NULL,                     /* add_headers */
    NULL,                     /* remove_headers */
    NULL,                     /* return_path */
    NULL,                     /* debug_string */
    NULL,                     /* message_size_limit */
    NULL,                     /* headers_rewrite */
    NULL,                     /* rewrite_rules */
    0,                        /* rewrite_existflags */
    300,                      /* filter_timeout */
    FALSE,                    /* body_only */
    FALSE,                    /* delivery_date_add */
    FALSE,                    /* envelope_to_add */
    FALSE,                    /* headers_only */
    FALSE,                    /* rcpt_include_affixes */
    FALSE,                    /* return_path_add */
    FALSE,                    /* return_output */
    FALSE,                    /* return_fail_output */
    FALSE,                    /* log_output */
    FALSE,                    /* log_fail_output */
    FALSE,                    /* log_defer_output */
    TRUE_UNSET                /* retry_use_local_part: BOOL, but set neither
                                 1 nor 0 so can detect unset */
};

int     transport_count;
uschar **transport_filter_argv  = NULL;
int     transport_filter_timeout;
int     transport_write_timeout= 0;

tree_node  *tree_dns_fails     = NULL;
tree_node  *tree_duplicates    = NULL;
tree_node  *tree_nonrecipients = NULL;
tree_node  *tree_unusable      = NULL;

BOOL    trusted_caller         = FALSE;
gid_t  *trusted_groups         = NULL;
uid_t  *trusted_users          = NULL;
uschar *timezone_string        = US TIMEZONE_DEFAULT;

uschar *unknown_login          = NULL;
uschar *unknown_username       = NULL;
uschar *untrusted_set_sender   = NULL;

/*  A regex for matching a "From_" line in an incoming message, in the form

    From ph10 Fri Jan  5 12:35 GMT 1996

which  the "mail" commands send to the MTA (undocumented, of course), or in
the  form

    From ph10 Fri, 7 Jan 97 14:00:00 GMT

which  is apparently used by some UUCPs, despite it not being in RFC 976.
Because  of variations in time formats, just match up to the minutes. That
should  be sufficient. Examples have been seen of time fields like 12:1:03,
so  just require one digit for hours and minutes. The weekday is also absent
in  some forms. */

uschar *uucp_from_pattern      = US
   "^From\\s+(\\S+)\\s+(?:[a-zA-Z]{3},?\\s+)?"    /* Common start */
   "(?:"                                          /* Non-extracting bracket */
   "[a-zA-Z]{3}\\s+\\d?\\d|"                      /* First form */
   "\\d?\\d\\s+[a-zA-Z]{3}\\s+\\d\\d(?:\\d\\d)?"  /* Second form */
   ")"                                            /* End alternation */
   "\\s+\\d\\d?:\\d\\d?";                         /* Start of time */

uschar *uucp_from_sender       = US"$1";

uschar *warn_message_file      = NULL;
uschar *warnmsg_delay          = NULL;
uschar *warnmsg_recipients     = NULL;
BOOL    write_rejectlog        = TRUE;

uschar *version_copyright      = US"Copyright (c) University of Cambridge 2004";
uschar *version_date           = US"?";
uschar *version_cnumber        = US"????";
uschar *version_string         = US"?";

int     warning_count          = 0;

/*  End of globals.c */
