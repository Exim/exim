/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */


/* Definitions of various structures. In addition, those that are visible for
the compilation of local_scan() are defined in local_scan.h. These are

  header_line
  optionlist
  recipient_item

For those declared here, we have to pre-declare some because of mutually
recursive definitions in the auths, routers, and transports blocks. */

struct address_item;
struct auth_info;
struct driver_info;
struct director_info;
struct smtp_inblock;
struct smtp_outblock;
struct transport_info;
struct router_info;

/* Structure for remembering macros for the configuration file */

typedef struct macro_item {
  struct  macro_item *next;
  BOOL    command_line;
  uschar *replacement;
  uschar  name[1];
} macro_item;

/* Structure for bit tables for debugging and logging */

typedef struct bit_table {
  uschar *name;
  unsigned int bit;
} bit_table;

/* Block for holding a uid and gid, possibly unset, and an initgroups flag. */

typedef struct ugid_block {
  uid_t   uid;
  gid_t   gid;
  BOOL    uid_set;
  BOOL    gid_set;
  BOOL    initgroups;
} ugid_block;

/* Structure for holding information about a host for use mainly by routers,
but also used when checking lists of hosts and when transporting. Looking up
host addresses is done using this structure. */

typedef enum {DS_UNK=-1, DS_NO, DS_YES} dnssec_status_t;

typedef struct host_item {
  struct host_item *next;
  const uschar *name;             /* Host name */
  const uschar *address;          /* IP address in text form */
  int     port;                   /* port value in host order (if SRV lookup) */
  int     mx;                     /* MX value if found via MX records */
  int     sort_key;               /* MX*1000 plus random "fraction" */
  int     status;                 /* Usable, unusable, or unknown */
  int     why;                    /* Why host is unusable */
  int     last_try;               /* Time of last try if known */
  dnssec_status_t dnssec;
} host_item;

/* Chain of rewrite rules, read from the rewrite config, or parsed from the
rewrite_headers field of a transport. */

typedef struct rewrite_rule {
  struct rewrite_rule *next;
  int     flags;
  uschar *key;
  uschar *replacement;
} rewrite_rule;

/* This structure is used to pass back configuration data from the smtp
transport to the outside world. It is used during callback processing. If ever
another remote transport were implemented, it could use the same structure. */

typedef struct transport_feedback {
  uschar *interface;
  uschar *port;
  uschar *protocol;
  uschar *hosts;
  uschar *helo_data;
  BOOL   hosts_override;
  BOOL   hosts_randomize;
  BOOL   gethostbyname;
  BOOL   qualify_single;
  BOOL   search_parents;
} transport_feedback;

/* Routers, transports, and authenticators have similar data blocks. Each
driver that is compiled into the code is represented by a xxx_info block; the
active drivers are represented by a chain of xxx_instance blocks. To make it
possible to use the same code for reading the configuration files for all
three, the layout of the start of the blocks is kept the same, and represented
by the generic structures driver_info and driver_instance. */

typedef struct driver_instance {
  struct driver_instance *next;
  uschar *name;                   /* Instance name */
  struct driver_info *info;       /* Points to info for this driver */
  void   *options_block;          /* Pointer to private options */
  uschar *driver_name;            /* All start with this generic option */
} driver_instance;

typedef struct driver_info {
  uschar *driver_name;            /* Name of driver */
  optionlist *options;            /* Table of private options names */
  int    *options_count;          /* -> Number of entries in table */
  void   *options_block;          /* Points to default private block */
  int     options_len;            /* Length of same in bytes */
  void  (*init)(                  /* Initialization entry point */
    struct driver_instance *);
} driver_info;


/* Structure for holding information about the configured transports. Some
of the generally accessible options are set from the configuration file; others
are set by transport initialization, since they can only be set for certain
transports. They need to be generally accessible, however, as they are used by
the main transport code. */

typedef struct transport_instance {
  struct transport_instance *next;
  uschar *name;                   /* Instance name */
  struct transport_info *info;    /* Info for this driver */
  void *options_block;            /* Pointer to private options */
  uschar *driver_name;            /* Must be first */
  int   (*setup)(                 /* Setup entry point */
    struct transport_instance *,
    struct address_item *,
    struct transport_feedback *,  /* For passing back config data */
    uid_t,                        /* The uid that will be used */
    gid_t,                        /* The gid that will be used */
    uschar **);                   /* For an error message */
                                  /**************************************/
  int     batch_max;              /* )                                  */
  uschar *batch_id;               /* )                                  */
  uschar *home_dir;               /* ) Used only for local transports   */
  uschar *current_dir;            /* )                                  */
                                  /**************************************/
  uschar *expand_multi_domain;    /* )                                  */
  BOOL    multi_domain;           /* )                                  */
  BOOL    overrides_hosts;        /* ) Used only for remote transports  */
  int     max_addresses;          /* )                                  */
  int     connection_max_messages;/* )                                  */
                                  /**************************************/
  BOOL    deliver_as_creator;     /* Used only by pipe at present */
  BOOL    disable_logging;        /* For very weird requirements */
  BOOL    initgroups;             /* Initialize groups when setting uid */
  BOOL    uid_set;                /* uid is set */
  BOOL    gid_set;                /* gid is set */
  uid_t   uid;
  gid_t   gid;
  uschar *expand_uid;             /* Variable uid */
  uschar *expand_gid;             /* Variable gid */
  uschar *warn_message;           /* Used only by appendfile at present */
  uschar *shadow;                 /* Name of shadow transport */
  uschar *shadow_condition;       /* Condition for running it */
  uschar *filter_command;         /* For on-the-fly-filtering */
  uschar *add_headers;            /* Add these headers */
  uschar *remove_headers;         /* Remove these headers */
  uschar *return_path;            /* Overriding (rewriting) return path */
  uschar *debug_string;           /* Debugging output */
  uschar *message_size_limit;     /* Biggest message this transport handles */
  uschar *headers_rewrite;        /* Rules for rewriting headers */
  rewrite_rule *rewrite_rules;    /* Parsed rewriting rules */
  int     rewrite_existflags;     /* Bits showing which headers are rewritten */
  int     filter_timeout;         /* For transport filter timing */
  BOOL    body_only;              /* Deliver only the body */
  BOOL    delivery_date_add;      /* Add Delivery-Date header */
  BOOL    envelope_to_add;        /* Add Envelope-To header */
  BOOL    headers_only;           /* Deliver only the headers */
  BOOL    rcpt_include_affixes;   /* TRUE to retain affixes in RCPT commands */
  BOOL    return_path_add;        /* Add Return-Path header */
  BOOL    return_output;          /* TRUE if output should always be returned */
  BOOL    return_fail_output;     /* ditto, but only on failure */
  BOOL    log_output;             /* Similarly for logging */
  BOOL    log_fail_output;
  BOOL    log_defer_output;
  BOOL    retry_use_local_part;   /* Defaults true for local, false for remote */
#ifdef EXPERIMENTAL_EVENT
  uschar  *event_action;          /* String to expand on notable events */
#endif
} transport_instance;


/* Structure for holding information about a type of transport. The first six
fields must match driver_info above. */

typedef struct transport_info {
  uschar *driver_name;            /* Driver name */
  optionlist *options;            /* Table of private options names */
  int    *options_count;          /* -> Number of entries in table */
  void   *options_block;          /* Points to default private block */
  int     options_len;            /* Length of same in bytes */
  void (*init)(                   /* Initialization function */
    struct transport_instance *);
/****/
  BOOL (*code)(                   /* Main entry point */
    transport_instance *,
    struct address_item *);
  void (*tidyup)(                 /* Tidyup function */
    struct transport_instance *);
  void  (*closedown)(             /* For closing down a passed channel */
    struct transport_instance *);
  BOOL    local;                  /* TRUE for local transports */
} transport_info;



typedef struct {
  uschar *request;
  uschar *require;
} dnssec_domains;

/* Structure for holding information about the configured routers. */

typedef struct router_instance {
  struct router_instance *next;
  uschar *name;
  struct router_info *info;
  void   *options_block;          /* Pointer to private options */
  uschar *driver_name;            /* Must be first */

  uschar *address_data;           /* Arbitrary data */
#ifdef EXPERIMENTAL_BRIGHTMAIL
  uschar *bmi_rule;               /* Brightmail AntiSpam rule checking */
#endif
  uschar *cannot_route_message;   /* Used when routing fails */
  uschar *condition;              /* General condition */
  uschar *current_directory;      /* For use during delivery */
  uschar *debug_string;           /* Debugging output */
  uschar *domains;                /* Specific domains */
  uschar *errors_to;              /* Errors address */
  uschar *expand_gid;             /* Expanded gid string */
  uschar *expand_uid;             /* Expanded uid string */
  uschar *expand_more;            /* Expanded more string */
  uschar *expand_unseen;          /* Expanded unseen string */
  uschar *extra_headers;          /* Additional headers */
  uschar *fallback_hosts;         /* For remote transports (text list) */
  uschar *home_directory;         /* For use during delivery */
  uschar *ignore_target_hosts;    /* Target hosts to ignore */
  uschar *local_parts;            /* Specific local parts */
  uschar *pass_router_name;       /* Router for passed address */
  uschar *prefix;                 /* Address prefix */
  uschar *redirect_router_name;   /* Router for generated address */
  uschar *remove_headers;         /* Removed headers */
  uschar *require_files;          /* File checks before router is run */
  uschar *router_home_directory;  /* For use while routing */
  uschar *self;                   /* Text option for handling self reference */
  uschar *senders;                /* Specific senders */
  uschar *suffix;                 /* Address suffix */
  uschar *translate_ip_address;   /* IP address translation fudgery */
  uschar *transport_name;         /* Transport name */

  BOOL    address_test;           /* Use this router when testing addresses */
#ifdef EXPERIMENTAL_BRIGHTMAIL
  BOOL    bmi_deliver_alternate;  /* TRUE => BMI said that message should be delivered to alternate location */
  BOOL    bmi_deliver_default;    /* TRUE => BMI said that message should be delivered to default location */
  BOOL    bmi_dont_deliver;       /* TRUE => BMI said that message should not be delivered at all */
#endif
  BOOL    expn;                   /* Use this router when processing EXPN */
  BOOL    caseful_local_part;     /* TRUE => don't lowercase */
  BOOL    check_local_user;       /* TRUE => check local user */
  BOOL    disable_logging;        /* For very weird requirements */
  BOOL    fail_verify_recipient;  /* Fail verify if recipient match this router */
  BOOL    fail_verify_sender;     /* Fail verify if sender match this router */
  BOOL    gid_set;                /* Flag to indicate gid is set */
  BOOL    initgroups;             /* TRUE if initgroups is required */
  BOOL    log_as_local;           /* TRUE logs as a local delivery */
  BOOL    more;                   /* If FALSE, do no more if this one fails */
  BOOL    pass_on_timeout;        /* Treat timeout DEFERs as fails */
  BOOL    prefix_optional;        /* Just what it says */
  BOOL    repeat_use;             /* If FALSE, skip if ancestor used it */
  BOOL    retry_use_local_part;   /* Just what it says */
  BOOL    same_domain_copy_routing; /* TRUE => copy routing for same domain */
  BOOL    self_rewrite;           /* TRUE to rewrite headers if making local */
  BOOL    suffix_optional;        /* As it says */
  BOOL    verify_only;            /* Skip this router if not verifying */
  BOOL    verify_recipient;       /* Use this router when verifying a recipient*/
  BOOL    verify_sender;          /* Use this router when verifying a sender */
  BOOL    uid_set;                /* Flag to indicate uid is set */
  BOOL    unseen;                 /* If TRUE carry on, even after success */
  BOOL    dsn_lasthop;            /* If TRUE, this router is a DSN endpoint */

  int     self_code;              /* Encoded version of "self" */
  uid_t   uid;                    /* Fixed uid value */
  gid_t   gid;                    /* Fixed gid value */

  host_item *fallback_hostlist;   /* For remote transport (block chain) */
  transport_instance *transport;  /* Transport block (when found) */
  struct router_instance *pass_router; /* Actual router for passed address */
  struct router_instance *redirect_router; /* Actual router for generated address */

  dnssec_domains dnssec;
} router_instance;


/* Structure for holding information about a type of router. The first six
fields must match driver_info above. */

typedef struct router_info {
  uschar *driver_name;
  optionlist *options;            /* Table of private options names */
  int    *options_count;          /* -> Number of entries in table */
  void   *options_block;          /* Points to default private block */
  int     options_len;            /* Length of same in bytes */
  void (*init)(                   /* Initialization function */
    struct router_instance *);
/****/
  int (*code)(                    /* Main entry point */
    router_instance *,
    struct address_item *,
    struct passwd *,
    int,
    struct address_item **,
    struct address_item **,
    struct address_item **,
    struct address_item **);
  void (*tidyup)(                 /* Tidyup function */
    struct router_instance *);
  int     ri_flags;               /* Descriptive flags */
} router_info;


/* Structure for holding information about a lookup type. */

#include "lookupapi.h"


/* Structure for holding information about the configured authentication
mechanisms */

typedef struct auth_instance {
  struct auth_instance *next;
  uschar *name;                   /* Exim instance name */
  struct auth_info *info;         /* Pointer to driver info block */
  void   *options_block;          /* Pointer to private options */
  uschar *driver_name;            /* Must be first */
  uschar *advertise_condition;    /* Are we going to advertise this?*/
  uschar *client_condition;       /* Should the client try this? */
  uschar *public_name;            /* Advertised name */
  uschar *set_id;                 /* String to set when server as authenticated id */
  uschar *set_client_id;          /* String to set when client as client_authenticated id */
  uschar *mail_auth_condition;    /* Condition for AUTH on MAIL command */
  uschar *server_debug_string;    /* Debugging output */
  uschar *server_condition;       /* Authorization condition */
  BOOL    client;                 /* TRUE if client option(s) set */
  BOOL    server;                 /* TRUE if server options(s) set */
  BOOL    advertised;             /* Set TRUE when advertised */
} auth_instance;


/* Structure for holding information about an authentication mechanism. The
first six fields must match driver_info above. */

typedef struct auth_info {
  uschar *driver_name;            /* e.g. "condition" */
  optionlist *options;            /* Table of private options names */
  int    *options_count;          /* -> Number of entries in table */
  void   *options_block;          /* Points to default private block */
  int     options_len;            /* Length of same in bytes */
  void (*init)(                   /* initialization function */
    struct auth_instance *);
/****/
  int (*servercode)(              /* server function */
    auth_instance *,              /* the instance data */
    uschar *);                    /* rest of AUTH command */
  int (*clientcode)(              /* client function */
    struct auth_instance *,
    struct smtp_inblock *,        /* socket and input buffer */
    struct smtp_outblock *,       /* socket and output buffer */
    int,                          /* command timeout */
    uschar *,                     /* buffer for reading response */
    int);                         /* sizeof buffer */
  void (*version_report)(         /* diagnostic version reporting */
    FILE *);                      /* I/O stream to print to */
} auth_info;


/* Structure for holding a single IP address and port; used for the chain of
addresses and ports for the local host. Make the char string large enough to
hold an IPv6 address. */

typedef struct ip_address_item {
  struct ip_address_item *next;
  int    port;
  BOOL   v6_include_v4;            /* Used in the daemon */
  uschar address[46];
} ip_address_item;

/* Structure for chaining together arbitrary strings. */

typedef struct string_item {
  struct string_item *next;
  uschar *text;
} string_item;

/* Information about a soft delivery failure, for use when calculating
retry information. It's separate from the address block, because there
can be a chain of them for SMTP deliveries where multiple IP addresses
can be tried. */

typedef struct retry_item {
  struct retry_item *next;        /* for chaining */
  uschar *key;                    /* string identifying host/address/message */
  int     basic_errno;            /* error code for this destination */
  int     more_errno;             /* additional error information */
  uschar *message;                /* local error message */
  int     flags;                  /* see below */
} retry_item;

/* Retry data flags */

#define rf_delete   0x0001        /* retry info is to be deleted */
#define rf_host     0x0002        /* retry info is for a remote host */
#define rf_message  0x0004        /* retry info is for a host+message */

/* Information about a constructed message that is to be sent using the
autoreply transport. This is pointed to from the address block. */

typedef struct reply_item {
  uschar *from;                   /* ) */
  uschar *reply_to;               /* ) */
  uschar *to;                     /* ) */
  uschar *cc;                     /* ) specific header fields */
  uschar *bcc;                    /* ) */
  uschar *subject;                /* ) */
  uschar *headers;                /* misc other headers, concatenated */
  uschar *text;                   /* text string body */
  uschar *file;                   /* file body */
  BOOL    file_expand;            /* expand the body */
  int     expand_forbid;          /* expansion lockout flags */
  uschar *logfile;                /* file to keep a log in */
  uschar *oncelog;                /* file to keep records in for once only */
  time_t  once_repeat;            /* time to repeat "once only" */
  BOOL    return_message;         /* send back the original message */
} reply_item;


/* The address_item structure contains many fields which are used at various
times while delivering a message. Some are used only for remote deliveries;
some only for local. A particular set of fields is copied whenever a child
address is created. For convenience, we keep those fields in a separate
sub-structure so they can be copied in one go. This also means I won't forget
to edit the various copying places when new to-be-copied fields are added. */

typedef struct address_item_propagated {
  uschar *address_data;           /* arbitrary data to keep with the address */
  uschar *domain_data;            /* from "domains" lookup */
  uschar *localpart_data;         /* from "local_parts" lookup */
  uschar *errors_address;         /* where to send errors (NULL => sender) */
  header_line *extra_headers;     /* additional headers */
  uschar *remove_headers;         /* list of those to remove */

  #ifdef EXPERIMENTAL_SRS
  uschar *srs_sender;             /* Change return path when delivering */
  #endif
  #ifdef EXPERIMENTAL_INTERNATIONAL
  BOOL    utf8_msg:1;		  /* requires SMTPUTF8 processing */
  BOOL	  utf8_downcvt:1;	  /* mandatory downconvert on delivery */
  BOOL	  utf8_downcvt_maybe:1;	  /* optional downconvert on delivery */
  #endif
} address_item_propagated;

/* Bits for the flags field below */

#define af_allow_file          0x00000001 /* allow file in generated address */
#define af_allow_pipe          0x00000002 /* allow pipe in generated address */
#define af_allow_reply         0x00000004 /* allow autoreply in generated address */
#define af_dr_retry_exists     0x00000008 /* router retry record exists */
#define af_expand_pipe         0x00000010 /* expand pipe arguments */
#define af_file                0x00000020 /* file delivery; always with pfr */
#define af_gid_set             0x00000040 /* gid field is set */
#define af_home_expanded       0x00000080 /* home_dir is already expanded */
#define af_ignore_error        0x00000100 /* ignore delivery error */
#define af_initgroups          0x00000200 /* use initgroups() for local transporting */
#define af_local_host_removed  0x00000400 /* local host was backup */
#define af_lt_retry_exists     0x00000800 /* local transport retry exists */
#define af_pfr                 0x00001000 /* pipe or file or reply delivery */
#define af_retry_skipped       0x00002000 /* true if retry caused some skipping */
#define af_retry_timedout      0x00004000 /* true if retry timed out */
#define af_uid_set             0x00008000 /* uid field is set */
#define af_hide_child          0x00010000 /* hide child in bounce/defer msgs */
#define af_sverify_told        0x00020000 /* sender verify failure notified */
#define af_verify_pmfail       0x00040000 /* verify failure was postmaster callout */
#define af_verify_nsfail       0x00080000 /* verify failure was null sender callout */
#define af_homonym             0x00100000 /* an ancestor has same address */
#define af_verify_routed       0x00200000 /* for cached sender verify: routed OK */
#define af_verify_callout      0x00400000 /* for cached sender verify: callout was specified */
#define af_include_affixes     0x00800000 /* delivered with affixes in RCPT */
#define af_cert_verified       0x01000000 /* delivered with verified TLS cert */
#define af_pass_message        0x02000000 /* pass message in bounces */
#define af_bad_reply           0x04000000 /* filter could not generate autoreply */
#ifndef DISABLE_PRDR
# define af_prdr_used          0x08000000 /* delivery used SMTP PRDR */
#endif
#define af_force_command       0x10000000 /* force_command in pipe transport */
#ifdef EXPERIMENTAL_DANE
# define af_dane_verified      0x20000000 /* TLS cert verify done with DANE */
#endif
#ifdef EXPERIMENTAL_INTERNATIONAL
# define af_utf8_downcvt       0x40000000 /* downconvert was done for delivery */
#endif

/* These flags must be propagated when a child is created */

#define af_propagate           (af_ignore_error)

/* The main address structure. Note that fields that are to be copied to
generated addresses should be put in the address_item_propagated structure (see
above) rather than directly into the address_item structure. */

typedef struct address_item {
  struct address_item *next;      /* for chaining addresses */
  struct address_item *parent;    /* parent address */
  struct address_item *first;     /* points to first after group delivery */
  struct address_item *dupof;     /* points to address this is a duplicate of */

  router_instance *start_router;  /* generated address starts here */
  router_instance *router;        /* the router that routed */
  transport_instance *transport;  /* the transport to use */

  host_item *host_list;           /* host data for the transport */
  host_item *host_used;           /* host that took delivery or failed hard */
  host_item *fallback_hosts;      /* to try if delivery defers */

  reply_item *reply;              /* data for autoreply */
  retry_item *retries;            /* chain of retry information */

  uschar *address;                /* address being delivered or routed */
  uschar *unique;                 /* used for disambiguating */
  uschar *cc_local_part;          /* caseful local part */
  uschar *lc_local_part;          /* lowercased local part */
  uschar *local_part;             /* points to cc or lc version */
  uschar *prefix;                 /* stripped prefix of local part */
  uschar *suffix;                 /* stripped suffix of local part */
  const uschar *domain;           /* working domain (lower cased) */

  uschar *address_retry_key;      /* retry key including full address */
  uschar *domain_retry_key;       /* retry key for domain only */

  uschar *current_dir;            /* current directory for transporting */
  uschar *home_dir;               /* home directory for transporting */
  uschar *message;                /* error message */
  uschar *user_message;           /* error message that can be sent over SMTP
                                     or quoted in bounce message */
  uschar *onetime_parent;         /* saved original parent for onetime */
  uschar **pipe_expandn;          /* numeric expansions for pipe from filter */
  uschar *return_filename;        /* name of return file */
  uschar *self_hostname;          /* after self=pass */
  uschar *shadow_message;         /* info about shadow transporting */

  #ifdef SUPPORT_TLS
  uschar *cipher;                 /* Cipher used for transport */
  void   *ourcert;                /* Certificate offered to peer, binary */
  void   *peercert;               /* Certificate from peer, binary */
  uschar *peerdn;                 /* DN of server's certificate */
  int    ocsp;			  /* OCSP status of peer cert */
  #endif

  uschar *authenticator;	  /* auth driver name used by transport */
  uschar *auth_id;		  /* auth "login" name used by transport */
  uschar *auth_sndr;		  /* AUTH arg to SMTP MAIL, used by transport */

  uschar *dsn_orcpt;              /* DSN orcpt value */
  int     dsn_flags;              /* DSN flags */
  int     dsn_aware;              /* DSN aware flag */

  uid_t   uid;                    /* uid for transporting */
  gid_t   gid;                    /* gid for transporting */

  unsigned int flags;             /* a row of bits, defined above */
  unsigned int domain_cache[(MAX_NAMED_LIST * 2)/32];
  unsigned int localpart_cache[(MAX_NAMED_LIST * 2)/32];
  int     mode;                   /* mode for local transporting to a file */
  int     more_errno;             /* additional error information */
                                  /* (may need to hold a timestamp) */

  short int basic_errno;          /* status after failure */
  short int child_count;          /* number of child addresses */
  short int return_file;          /* fileno of return data file */
  short int special_action;       /* ( used when when deferred or failed */
                                  /* (  also  */
                                  /* ( contains = or - when successful SMTP delivered */
                                  /* (  also  */
                                  /* ( contains verify rc in sender verify cache */
  short int transport_return;     /* result of delivery attempt */
  address_item_propagated prop;   /* fields that are propagated to children */
} address_item;

/* The table of header names consists of items of this type */

typedef struct {
  uschar *name;
  int     len;
  BOOL    allow_resent;
  int     htype;
} header_name;

/* Chain of information about errors (e.g. bad addresses) */

typedef struct error_block {
  struct error_block *next;
  const uschar *text1;
  uschar *text2;
} error_block;

/* Chain of file names when processing the queue */

typedef struct queue_filename {
  struct queue_filename *next;
  uschar dir_uschar;
  uschar text[1];
} queue_filename;

/* Chain of items of retry information, read from the retry config. */

typedef struct retry_rule {
  struct retry_rule *next;
  int    rule;
  int    timeout;
  int    p1;
  int    p2;
} retry_rule;

typedef struct retry_config {
  struct retry_config *next;
  uschar *pattern;
  int     basic_errno;
  int     more_errno;
  uschar *senders;
  retry_rule *rules;
} retry_config;

/* Structure for each node in a tree, of which there are various kinds */

typedef struct tree_node {
  struct tree_node *left;         /* pointer to left child */
  struct tree_node *right;        /* pointer to right child */
  union
    {
    void  *ptr;                   /* pointer to data */
    int val;                      /* or integer data */
    } data;
  uschar  balance;                /* balancing factor */
  uschar  name[1];                /* node name - variable length */
} tree_node;

/* Structure for holding the handle and the cached last lookup for searches.
This block is pointed to by the tree entry for the file. The file can get
closed if too many are opened at once. There is a LRU chain for deciding which
to close. */

typedef struct search_cache {
  void   *handle;                 /* lookup handle, or NULL if closed */
  int search_type;                /* search type */
  tree_node *up;                  /* LRU up pointer */
  tree_node *down;                /* LRU down pointer */
  tree_node *item_cache;          /* tree of cached results */
} search_cache;

/* Structure for holding a partially decoded DNS record; the name has been
uncompressed, but the data pointer is into the raw data. */

typedef struct {
  uschar  name[DNS_MAXNAME];      /* domain name */
  int     type;                   /* record type */
  int     size;                   /* size of data */
  uschar *data;                   /* pointer to data */
} dns_record;

/* Structure for holding the result of a DNS query. */

typedef struct {
  int     answerlen;              /* length of the answer */
  uschar  answer[MAXPACKET];      /* the answer itself */
} dns_answer;

/* Structure for holding the intermediate data while scanning a DNS answer
block. */

typedef struct {
  int     rrcount;                /* count of RRs in the answer */
  uschar *aptr;                   /* pointer in the answer while scanning */
  dns_record srr;                 /* data from current record in scan */
} dns_scan;

/* Structure for holding a chain of IP addresses that are extracted from
an A, AAAA, or A6 record. For the first two, there is only ever one address,
but the chaining feature of A6 allows for several addresses to be realized from
a single initial A6 record. The structure defines the address field of length
1. In use, a suitable sized block is obtained to hold the complete textual
address. */

typedef struct dns_address {
  struct dns_address *next;
  uschar  address[1];
} dns_address;

/* Structure used for holding intermediate data during MD5 computations. */

typedef struct md5 {
  unsigned int length;
  unsigned int abcd[4];
  }
md5;

/* Structure used for holding intermediate data during SHA-1 computations. */

typedef struct sha1 {
  unsigned int H[5];
  unsigned int length;
  }
sha1;

/* Structure used to hold incoming packets of SMTP responses for a specific
socket. The packets which may contain multiple lines (and in some cases,
multiple responses). */

typedef struct smtp_inblock {
  int     sock;                   /* the socket */
  int     buffersize;             /* the size of the buffer */
  uschar *ptr;                    /* current position in the buffer */
  uschar *ptrend;                 /* end of data in the buffer */
  uschar *buffer;                 /* the buffer itself */
} smtp_inblock;

/* Structure used to hold buffered outgoing packets of SMTP commands for a
specific socket. The packets which may contain multiple lines when pipelining
is in use. */

typedef struct smtp_outblock {
  int     sock;                   /* the socket */
  int     cmd_count;              /* count of buffered commands */
  int     buffersize;             /* the size of the buffer */
  BOOL    authenticating;         /* TRUE when authenticating */
  uschar *ptr;                    /* current position in the buffer */
  uschar *buffer;                 /* the buffer itself */
} smtp_outblock;

/* Structure to hold information about the source of redirection information */

typedef struct redirect_block {
  uschar *string;                 /* file name or string */
  uid_t  *owners;                 /* allowed file owners */
  gid_t  *owngroups;              /* allowed file groups */
  struct passwd *pw;              /* possible owner if not NULL */
  int     modemask;               /* forbidden bits */
  BOOL    isfile;                 /* TRUE if string is a file name */
  BOOL    check_owner;            /* TRUE, FALSE, or TRUE_UNSET */
  BOOL    check_group;            /* TRUE, FALSE, or TRUE_UNSET */
} redirect_block;

/* Structure for passing arguments to check_host() */

typedef struct check_host_block {
  const uschar *host_name;
  const uschar *host_address;
  const uschar *host_ipv4;
  BOOL   negative;
} check_host_block;

/* Structure for remembering lookup data when caching the result of
a lookup in a named list. */

typedef struct namedlist_cacheblock {
  struct namedlist_cacheblock *next;
  uschar *key;
  uschar *data;
} namedlist_cacheblock;

/* Structure for holding data for an entry in a named list */

typedef struct namedlist_block {
  const uschar *string;              /* the list string */
  namedlist_cacheblock *cache_data;  /* cached domain_data or localpart_data */
  int number;                        /* the number of the list for caching */
} namedlist_block;

/* Structures for Access Control Lists */

typedef struct acl_condition_block {
  struct acl_condition_block *next;
  uschar *arg;
  int type;
  union {
    BOOL negated;
    uschar *varname;
  } u;
} acl_condition_block;

typedef struct acl_block {
  struct acl_block *next;
  acl_condition_block *condition;
  int verb;
} acl_block;

/* smtp transport calc outbound_ip */
typedef BOOL (*oicf) (uschar *message_id, void *data);

/* End of structs.h */
