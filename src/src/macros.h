/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */


/* These two macros make it possible to obtain the result of macro-expanding
a string as a text string. This is sometimes useful for debugging output. */

#define mac_string(s) # s
#define mac_expanded_string(s) mac_string(s)

/* Number of elements of an array */
#define nelem(arr) (sizeof(arr) / sizeof(*arr))


/* When running in the test harness, the load average is fudged. */

#define OS_GETLOADAVG() \
  (running_in_test_harness? (test_harness_load_avg += 10) : os_getloadavg())


/* The address_item structure has a word full of 1-bit flags. These macros
manipulate them. */

#define setflag(addr,flag)    addr->flags |= (flag)
#define clearflag(addr,flag)  addr->flags &= ~(flag)

#define testflag(addr,flag)       ((addr->flags & (flag)) != 0)
#define testflagsall(addr,flag)   ((addr->flags & (flag)) == (flag))

#define copyflag(addrnew,addrold,flag) \
  addrnew->flags = (addrnew->flags & ~(flag)) | (addrold->flags & (flag))

#define orflag(addrnew,addrold,flag) \
  addrnew->flags |= addrold->flags & (flag)


/* For almost all calls to convert things to printing characters, we want to
allow tabs. A macro just makes life a bit easier. */

#define string_printing(s) string_printing2((s), TRUE)


/* We need a special return code for "no recipients and failed to send an error
message". ANSI C defines only EXIT_FAILURE and EXIT_SUCCESS. On the assumption
that these are always 1 and 0 on Unix systems ... */

#define EXIT_NORECIPIENTS 2


/* Character-handling macros. It seems that the set of standard functions in
ctype.h aren't actually all that useful. One reason for this is that email is
international, so the concept of using a locale to vary what they do is not
helpful. Another problem is that in different operating systems, the libraries
yield different results, even in the default locale. For example, Linux yields
TRUE for iscntrl() for all characters > 127, whereas many other systems yield
FALSE. For these reasons we define our own set of macros for a number of
character testing functions. Ensure that all these tests treat their arguments
as unsigned. */

#define mac_iscntrl(c) \
  ((uschar)(c) < 32 || (uschar)(c) == 127)

#define mac_iscntrl_or_special(c) \
  ((uschar)(c) < 32 || strchr(" ()<>@,;:\\\".[]\177", (uschar)(c)) != NULL)

#define mac_isgraph(c) \
  ((uschar)(c) > 32 && (uschar)(c) != 127)

#define mac_isprint(c) \
  (((uschar)(c) >= 32 && (uschar)(c) <= 126) || c == '\t' || \
  ((uschar)(c) > 127 && print_topbitchars))


/* Convenience for testing strings */

#define streqic(Foo, Bar) (strcmpic(Foo, Bar) == 0)


/* When built with TLS support, the act of flushing SMTP output becomes
a no-op once an SSL session is in progress. */

#ifdef SUPPORT_TLS
#define mac_smtp_fflush() if (tls_in.active < 0) fflush(smtp_out);
#else
#define mac_smtp_fflush() fflush(smtp_out);
#endif


/* Define which ends of pipes are for reading and writing, as some systems
don't make the file descriptors two-way. */

#define pipe_read  0
#define pipe_write 1

/* The RFC 1413 ident port */

#define IDENT_PORT 113

/* A macro to simplify testing bits in lookup types */

#define mac_islookup(a,b) ((lookup_list[a]->type & (b)) != 0)

/* Debugging control */

#define DEBUG(x)      if ((debug_selector & (x)) != 0)
#define HDEBUG(x)     if (host_checking || (debug_selector & (x)) != 0)

#define PTR_CHK(ptr) \
do { \
if ((void *)ptr > (void *)store_get(0)) \
  debug_printf("BUG: ptr '%s' beyond arena at %s:%d\n", \
       	mac_expanded_string(ptr), __FUNCTION__, __LINE__); \
} while(0)

/* The default From: text for DSNs */

#define DEFAULT_DSN_FROM "Mail Delivery System <Mailer-Daemon@$qualify_domain>"

/* The size of the vector for saving/restoring address expansion pointers while
verifying. This has to be explicit because it is referenced in more than one
source module. */

#define ADDRESS_EXPANSIONS_COUNT 18

/* The maximum permitted number of command-line (-D) macro definitions. We
need a limit only to make it easier to generate argument vectors for re-exec
of Exim. */

#define MAX_CLMACROS 10

/* The number of integer variables available in filter files. If this is
changed, then the tables in expand.c for accessing them must be changed too. */

#define FILTER_VARIABLE_COUNT 10

/* The size of the vector holding delay warning times */

#define DELAY_WARNING_SIZE 12

/* The size of the buffer holding the processing information string. */

#define PROCESS_INFO_SIZE 256

/* The size of buffer to get for constructing log entries. Make it big
enough to hold all the headers from a normal kind of message. */

#define LOG_BUFFER_SIZE 8192

/* The size of the circular buffer that remembers recent SMTP commands */

#define SMTP_HBUFF_SIZE 20

/* The initial size of a big buffer for use in various places. It gets put
into big_buffer_size and in some circumstances increased. It should be at least
as long as the maximum path length. */

#if defined PATH_MAX && PATH_MAX > 16384
# define BIG_BUFFER_SIZE PATH_MAX
#elif defined MAXPATHLEN && MAXPATHLEN > 16384
# define BIG_BUFFER_SIZE MAXPATHLEN
#else
# define BIG_BUFFER_SIZE 16384
#endif

/* header size of pipe content 
   currently: char id, char subid, char[5] length */
#define PIPE_HEADER_SIZE 7

/* This limits the length of data returned by local_scan(). Because it is
written on the spool, it gets read into big_buffer. */

#define LOCAL_SCAN_MAX_RETURN (BIG_BUFFER_SIZE - 24)

/* A limit to the length of an address. RFC 2821 limits the local part to 64
and the domain to 255, so this should be adequate, taking into account quotings
etc. */

#define ADDRESS_MAXLENGTH 512

/* The length of the base names of spool files, which consist of an internal
message id with a trailing "-H" or "-D" added. */

#define SPOOL_NAME_LENGTH (MESSAGE_ID_LENGTH+2)

/* The maximum number of message ids to store in a waiting database
record. */

#define WAIT_NAME_MAX 50

/* Wait this long before determining that a Proxy Protocol configured
host isn't speaking the protocol, and so is disallowed. Can be moved to
runtime configuration if per site settings become needed. */
#ifdef EXPERIMENTAL_PROXY
#define PROXY_NEGOTIATION_TIMEOUT_SEC 3
#define PROXY_NEGOTIATION_TIMEOUT_USEC 0
#endif

/* Fixed option values for all PCRE functions */

#define PCRE_COPT 0   /* compile */
#define PCRE_EOPT 0   /* exec */

/* Macros for trivial functions */

#define mac_ismsgid(s) \
  (pcre_exec(regex_ismsgid,NULL,CS s,Ustrlen(s),0,PCRE_EOPT,NULL,0) >= 0)


/* Options for dns_next_rr */

enum { RESET_NEXT, RESET_ANSWERS, RESET_AUTHORITY, RESET_ADDITIONAL };

/* Argument values for the time-of-day function */

enum { tod_log, tod_log_bare, tod_log_zone, tod_log_datestamp_daily,
       tod_log_datestamp_monthly, tod_zone, tod_full, tod_bsdin,
       tod_mbx, tod_epoch, tod_epoch_l, tod_zulu };

/* For identifying types of driver */

enum {
  DTYPE_NONE,
  DTYPE_ROUTER,
  DTYPE_TRANSPORT
};

/* Error numbers for generating error messages when reading a message on the
standard input. */

enum {
  ERRMESS_BADARGADDRESS,    /* Bad address via argument list */
  ERRMESS_BADADDRESS,       /* Bad address read via -t */
  ERRMESS_NOADDRESS,        /* Message has no addresses */
  ERRMESS_IGADDRESS,        /* All -t addresses ignored */
  ERRMESS_BADNOADDRESS,     /* Bad address via -t, leaving none */
  ERRMESS_IOERR,            /* I/O error while reading a message */
  ERRMESS_VLONGHEADER,      /* Excessively long message header */
  ERRMESS_VLONGHDRLINE,     /* Excessively long single line in header */
  ERRMESS_TOOBIG,           /* Message too big */
  ERRMESS_TOOMANYRECIP,     /* Too many recipients */
  ERRMESS_LOCAL_SCAN,       /* Rejected by local scan */
  ERRMESS_LOCAL_ACL         /* Rejected by non-SMTP ACL */
#ifdef EXPERIMENTAL_DMARC
 ,ERRMESS_DMARC_FORENSIC    /* DMARC Forensic Report */
#endif
};

/* Error handling styles - set by option, and apply only when receiving
a local message not via SMTP. */

enum {
  ERRORS_SENDER,            /* Return to sender (default) */
  ERRORS_STDERR             /* Write on stderr */
};

/* Exec control values when Exim execs itself via child_exec_exim. */

enum {
  CEE_RETURN_ARGV,          /* Don't exec, just build and return argv */
  CEE_EXEC_EXIT,            /* Just exit if exec fails */
  CEE_EXEC_PANIC            /* Panic-die if exec fails */
};

/* Bit values for filter_test */

#define FTEST_NONE     0    /* Not filter testing */
#define FTEST_USER     1    /* Testing user filter */
#define FTEST_SYSTEM   2    /* Testing system filter */

/* Returns from the routing, transport and authentication functions (not all
apply to all of them). Some other functions also use these convenient values,
and some additional values are used only by non-driver functions.

OK, FAIL, DEFER, ERROR, and FAIL_FORCED are also declared in local_scan.h for
use in the local_scan() function and in ${dlfunc loaded functions. Do not
change them unilaterally. */

#define  OK            0    /* Successful match */
#define  DEFER         1    /* Defer - some problem */
#define  FAIL          2    /* Matching failed */
#define  ERROR         3    /* Internal or config error */
#define  FAIL_FORCED   4    /* "Forced" failure */
/***********/
#define DECLINE        5    /* Declined to handle the address, pass to next
                                 router unless no_more is set */
#define PASS           6    /* Pass to next driver, or to pass_router,
                                 even if no_more is set */
#define DISCARD        7    /* Address routed to :blackhole: or "seen finish" */
#define SKIP           8    /* Skip this router (used in route_address only) */
#define REROUTED       9    /* Address was changed and child created*/
#define PANIC         10    /* Hard failed with internal error */
#define BAD64         11    /* Bad base64 data (auth) */
#define UNEXPECTED    12    /* Unexpected initial auth data */
#define CANCELLED     13    /* Authentication cancelled */
#define FAIL_SEND     14    /* send() failed in authenticator */
#define FAIL_DROP     15    /* Fail and drop connection (used in ACL) */

/* Returns from the deliver_message() function */

#define DELIVER_ATTEMPTED_NORMAL   0  /* Tried a normal delivery */
#define DELIVER_MUA_SUCCEEDED      1  /* Success when mua_wrapper is set */
#define DELIVER_MUA_FAILED         2  /* Failure when mua_wrapper is set */
#define DELIVER_NOT_ATTEMPTED      3  /* Not tried (no msg or is locked */

/* Returns from DNS lookup functions. */

enum { DNS_SUCCEED, DNS_NOMATCH, DNS_NODATA, DNS_AGAIN, DNS_FAIL };

/* Ending states when reading a message. The order is important. The test
for having to swallow the rest of an SMTP message is whether the value is
>= END_NOTENDED. */

#define END_NOTSTARTED 0    /* Message not started */
#define END_DOT        1    /* Message ended with '.' */
#define END_EOF        2    /* Message ended with EOF (error for SMTP) */
#define END_NOTENDED   3    /* Message reading not yet ended */
#define END_SIZE       4    /* Reading ended because message too big */
#define END_WERROR     5    /* Write error while reading the message */

/* Options bits for debugging; D_v and D_local_scan are also in local_scan.h */

#define D_v                          0x00000001
#define D_local_scan                 0x00000002

#define D_acl                        0x00000004
#define D_auth                       0x00000008
#define D_deliver                    0x00000010
#define D_dns                        0x00000020
#define D_dnsbl                      0x00000040
#define D_exec                       0x00000080
#define D_expand                     0x00000100
#define D_filter                     0x00000200
#define D_hints_lookup               0x00000400
#define D_host_lookup                0x00000800
#define D_ident                      0x00001000
#define D_interface                  0x00002000
#define D_lists                      0x00004000
#define D_load                       0x00008000
#define D_lookup                     0x00010000
#define D_memory                     0x00020000
#define D_pid                        0x00040000
#define D_process_info               0x00080000
#define D_queue_run                  0x00100000
#define D_receive                    0x00200000
#define D_resolver                   0x00400000
#define D_retry                      0x00800000
#define D_rewrite                    0x01000000
#define D_route                      0x02000000
#define D_timestamp                  0x04000000
#define D_tls                        0x08000000
#define D_transport                  0x10000000
#define D_uid                        0x20000000
#define D_verify                     0x40000000

/* The D_all value must always have all bits set, as it is recognized specially
by the function that decodes debug and log selectors. This is to enable it to
set all the bits in a multi-word selector. Debug doesn't use this yet, but we
are getting close. In fact, we want to omit "memory" for -d+all, but can't
handle this here. It is fudged externally. */

#define D_all                        0xffffffff

#define D_any                        (D_all & \
                                       ~(D_v           | \
                                         D_pid         | \
                                         D_timestamp)  )

#define D_default                    (0xffffffff & \
                                       ~(D_expand      | \
                                         D_filter      | \
                                         D_interface   | \
                                         D_load        | \
                                         D_local_scan  | \
                                         D_memory      | \
                                         D_pid         | \
                                         D_timestamp   | \
                                         D_resolver))

/* Options bits for logging. Those that will end up in log_write_selector have
values < 0x80000000. They can be used in calls to log_write(). The others have
values > 0x80000000 and are put into log_extra_selector (without the top bit).
These are only ever tested independently. "All" is a magic value that is used
only in the name table to set all options in both bit maps. */

/* The L_all value must always have all bits set, as it is recognized specially
by the function that decodes debug and log selectors. This is to enable it to
set all the bits in a multi-word selector. */

#define L_all                          0xffffffff

#define L_address_rewrite              0x00000001
#define L_all_parents                  0x00000002
#define L_connection_reject            0x00000004
#define L_delay_delivery               0x00000008
#define L_dnslist_defer                0x00000010
#define L_etrn                         0x00000020
#define L_host_lookup_failed           0x00000040
#define L_lost_incoming_connection     0x00000080
#define L_queue_run                    0x00000100
#define L_retry_defer                  0x00000200
#define L_size_reject                  0x00000400
#define L_skip_delivery                0x00000800
#define L_smtp_connection              0x00001000
#define L_smtp_incomplete_transaction  0x00002000
#define L_smtp_protocol_error          0x00004000
#define L_smtp_syntax_error            0x00008000

#define LX_acl_warn_skipped            0x80000001
#define LX_arguments                   0x80000002
#define LX_deliver_time                0x80000004
#define LX_delivery_size               0x80000008
#define LX_ident_timeout               0x80000010
#define LX_incoming_interface          0x80000020
#define LX_incoming_port               0x80000040
#define LX_outgoing_port               0x80000080
#define LX_pid                         0x80000100
#define LX_queue_time                  0x80000200
#define LX_queue_time_overall          0x80000400
#define LX_received_sender             0x80000800
#define LX_received_recipients         0x80001000
#define LX_rejected_header             0x80002000
#define LX_return_path_on_delivery     0x80004000
#define LX_sender_on_delivery          0x80008000
#define LX_sender_verify_fail          0x80010000
#define LX_smtp_confirmation           0x80020000
#define LX_smtp_no_mail                0x80040000
#define LX_subject                     0x80080000
#define LX_tls_certificate_verified    0x80100000
#define LX_tls_cipher                  0x80200000
#define LX_tls_peerdn                  0x80400000
#define LX_tls_sni                     0x80800000
#define LX_unknown_in_list             0x81000000
#define LX_8bitmime                    0x82000000
#define LX_smtp_mailauth               0x84000000
#define LX_proxy                       0x88000000

#define L_default     (L_connection_reject        | \
                       L_delay_delivery           | \
                       L_dnslist_defer            | \
                       L_etrn                     | \
                       L_host_lookup_failed       | \
                       L_lost_incoming_connection | \
                       L_queue_run                | \
                       L_retry_defer              | \
                       L_size_reject              | \
                       L_skip_delivery)

#define LX_default   ((LX_acl_warn_skipped        | \
                       LX_rejected_header         | \
                       LX_sender_verify_fail      | \
                       LX_smtp_confirmation       | \
                       LX_tls_certificate_verified| \
                       LX_tls_cipher) & 0x7fffffff)

/* Private error numbers for delivery failures, set negative so as not
to conflict with system errno values. */

#define ERRNO_UNKNOWNERROR    (-1)
#define ERRNO_USERSLASH       (-2)
#define ERRNO_EXISTRACE       (-3)
#define ERRNO_NOTREGULAR      (-4)
#define ERRNO_NOTDIRECTORY    (-5)
#define ERRNO_BADUGID         (-6)
#define ERRNO_BADMODE         (-7)
#define ERRNO_INODECHANGED    (-8)
#define ERRNO_LOCKFAILED      (-9)
#define ERRNO_BADADDRESS2    (-10)
#define ERRNO_FORBIDPIPE     (-11)
#define ERRNO_FORBIDFILE     (-12)
#define ERRNO_FORBIDREPLY    (-13)
#define ERRNO_MISSINGPIPE    (-14)
#define ERRNO_MISSINGFILE    (-15)
#define ERRNO_MISSINGREPLY   (-16)
#define ERRNO_BADREDIRECT    (-17)
#define ERRNO_SMTPCLOSED     (-18)
#define ERRNO_SMTPFORMAT     (-19)
#define ERRNO_SPOOLFORMAT    (-20)
#define ERRNO_NOTABSOLUTE    (-21)
#define ERRNO_EXIMQUOTA      (-22)   /* Exim-imposed quota */
#define ERRNO_HELD           (-23)
#define ERRNO_FILTER_FAIL    (-24)   /* Delivery filter process failure */
#define ERRNO_CHHEADER_FAIL  (-25)   /* Delivery add/remove header failure */
#define ERRNO_WRITEINCOMPLETE (-26)  /* Delivery write incomplete error */
#define ERRNO_EXPANDFAIL     (-27)   /* Some expansion failed */
#define ERRNO_GIDFAIL        (-28)   /* Failed to get gid */
#define ERRNO_UIDFAIL        (-29)   /* Failed to get uid */
#define ERRNO_BADTRANSPORT   (-30)   /* Unset or non-existent transport */
#define ERRNO_MBXLENGTH      (-31)   /* MBX length mismatch */
#define ERRNO_UNKNOWNHOST    (-32)   /* Lookup failed routing or in smtp tpt */
#define ERRNO_FORMATUNKNOWN  (-33)   /* Can't match format in appendfile */
#define ERRNO_BADCREATE      (-34)   /* Creation outside home in appendfile */
#define ERRNO_LISTDEFER      (-35)   /* Can't check a list; lookup defer */
#define ERRNO_DNSDEFER       (-36)   /* DNS lookup defer */
#define ERRNO_TLSFAILURE     (-37)   /* Failed to start TLS session */
#define ERRNO_TLSREQUIRED    (-38)   /* Mandatory TLS session not started */
#define ERRNO_CHOWNFAIL      (-39)   /* Failed to chown a file */
#define ERRNO_PIPEFAIL       (-40)   /* Failed to create a pipe */
#define ERRNO_CALLOUTDEFER   (-41)   /* When verifying */
#define ERRNO_AUTHFAIL       (-42)   /* When required by client */
#define ERRNO_CONNECTTIMEOUT (-43)   /* Used internally in smtp transport */
#define ERRNO_RCPT4XX        (-44)   /* RCPT gave 4xx error */
#define ERRNO_MAIL4XX        (-45)   /* MAIL gave 4xx error */
#define ERRNO_DATA4XX        (-46)   /* DATA gave 4xx error */
#define ERRNO_PROXYFAIL      (-47)   /* Negotiation failed for proxy configured host */
#define ERRNO_AUTHPROB       (-48)   /* Authenticator "other" failure */

#ifdef EXPERIMENTAL_INTERNATIONAL
# define ERRNO_UTF8_FWD      (-49)   /* target not supporting SMTPUTF8 */
#endif

/* These must be last, so all retry deferments can easily be identified */

#define ERRNO_RETRY_BASE     (-51)   /* Base to test against */
#define ERRNO_RRETRY         (-51)   /* Not time for routing */
#define ERRNO_LRETRY         (-52)   /* Not time for local delivery */
#define ERRNO_HRETRY         (-53)   /* Not time for any remote host */
#define ERRNO_LOCAL_ONLY     (-54)   /* Local-only delivery */
#define ERRNO_QUEUE_DOMAIN   (-55)   /* Domain in queue_domains */

/* Special actions to take after failure or deferment. */

enum {
  SPECIAL_NONE,             /* No special action */
  SPECIAL_FREEZE,           /* Freeze message */
  SPECIAL_FAIL,             /* Fail the delivery */
  SPECIAL_WARN              /* Send a warning message */
};

/* Flags that get ORed into the more_errno field of an address to give more
information about errors for retry purposes. They are greater than 256, because
the bottom byte contains 'A' or 'M' for remote addresses, to indicate whether
the name was looked up only via an address record or whether MX records were
used, respectively. */

#define RTEF_CTOUT     0x0100      /* Connection timed out */

/* Permission and other options for parse_extract_addresses(),
filter_interpret(), and rda_interpret(), i.e. what special things are allowed
in redirection operations. Not all apply to all cases. Some of the bits allow
and some forbid, reflecting the "allow" and "forbid" options in the redirect
router, which were chosen to represent the standard situation for users'
.forward files. */

#define RDO_BLACKHOLE    0x00000001  /* Forbid :blackhole: */
#define RDO_DEFER        0x00000002  /* Allow :defer: or "defer" */
#define RDO_EACCES       0x00000004  /* Ignore EACCES */
#define RDO_ENOTDIR      0x00000008  /* Ignore ENOTDIR */
#define RDO_EXISTS       0x00000010  /* Forbid "exists" in expansion in filter */
#define RDO_FAIL         0x00000020  /* Allow :fail: or "fail" */
#define RDO_FILTER       0x00000040  /* Allow a filter script */
#define RDO_FREEZE       0x00000080  /* Allow "freeze" */
#define RDO_INCLUDE      0x00000100  /* Forbid :include: */
#define RDO_LOG          0x00000200  /* Forbid "log" */
#define RDO_LOOKUP       0x00000400  /* Forbid "lookup" in expansion in filter */
#define RDO_PERL         0x00000800  /* Forbid "perl" in expansion in filter */
#define RDO_READFILE     0x00001000  /* Forbid "readfile" in exp in filter */
#define RDO_READSOCK     0x00002000  /* Forbid "readsocket" in exp in filter */
#define RDO_RUN          0x00004000  /* Forbid "run" in expansion in filter */
#define RDO_DLFUNC       0x00008000  /* Forbid "dlfunc" in expansion in filter */
#define RDO_REALLOG      0x00010000  /* Really do log (not testing/verifying) */
#define RDO_REWRITE      0x00020000  /* Rewrite generated addresses */
#define RDO_EXIM_FILTER  0x00040000  /* Forbid Exim filters */
#define RDO_SIEVE_FILTER 0x00080000  /* Forbid Sieve filters */
#define RDO_PREPEND_HOME 0x00100000  /* Prepend $home to relative paths in Exim filter save commands */

/* This is the set that apply to expansions in filters */

#define RDO_FILTER_EXPANSIONS \
  (RDO_EXISTS|RDO_LOOKUP|RDO_PERL|RDO_READFILE|RDO_READSOCK|RDO_RUN|RDO_DLFUNC)

/* As well as the RDO bits themselves, we need the bit numbers in order to
access (most of) the individual bits as separate options. This could be
automated, but I haven't bothered. Keep this list in step with the above! */

enum { RDON_BLACKHOLE, RDON_DEFER, RDON_EACCES, RDON_ENOTDIR, RDON_EXISTS,
  RDON_FAIL, RDON_FILTER, RDON_FREEZE, RDON_INCLUDE, RDON_LOG, RDON_LOOKUP,
  RDON_PERL, RDON_READFILE, RDON_READSOCK, RDON_RUN, RDON_DLFUNC, RDON_REALLOG,
  RDON_REWRITE, RDON_EXIM_FILTER, RDON_SIEVE_FILTER, RDON_PREPEND_HOME };

/* Results of filter or forward file processing. Some are only from a filter;
some are only from a forward file. */

enum {
  FF_DELIVERED,         /* Success, took significant action */
  FF_NOTDELIVERED,      /* Success, didn't take significant action */
  FF_BLACKHOLE,         /* Blackholing requested */
  FF_DEFER,             /* Defer requested */
  FF_FAIL,              /* Fail requested */
  FF_INCLUDEFAIL,       /* :include: failed */
  FF_NONEXIST,          /* Forward file does not exist */
  FF_FREEZE,            /* Freeze requested */
  FF_ERROR              /* We have a problem */
};

/* Values for identifying particular headers; printing characters are used, so
they can be read in the spool file for those headers that are permanently
marked. The lower case values don't get onto the spool; they are used only as
return values from header_checkname(). */

#define htype_other         ' '   /* Unspecified header */
#define htype_from          'F'
#define htype_to            'T'
#define htype_cc            'C'
#define htype_bcc           'B'
#define htype_id            'I'   /* for message-id */
#define htype_reply_to      'R'
#define htype_received      'P'   /* P for Postmark */
#define htype_sender        'S'
#define htype_old           '*'   /* Replaced header */

#define htype_date          'd'
#define htype_return_path   'p'
#define htype_delivery_date 'x'
#define htype_envelope_to   'e'
#define htype_subject       's'

/* These values are used only when adding new headers from an ACL; they too
never get onto the spool. The type of the added header is set by reference
to the header name, by calling header_checkname(). */

#define htype_add_top       'a'
#define htype_add_rec       'r'
#define htype_add_bot       'z'
#define htype_add_rfc       'f'

/* Types of item in options lists. These are the bottom 8 bits of the "type"
field, which is an int. The opt_void value is used for entries in tables that
point to special types of value that are accessed only indirectly (e.g. the
rewrite data that is built out of a string option.) We need to have some values
visible in local_scan, so the following are declared there:

  opt_stringptr, opt_int, opt_octint, opt_mkint, opt_Kint, opt_fixed, opt_time,
  opt_bool

To make sure we don't conflict, the local_scan.h values start from zero, and
those defined here start from 32. The boolean ones must all be together so they
can be easily tested as a group. That is the only use of opt_bool_last. */

enum { opt_bit = 32, opt_bool_verify, opt_bool_set, opt_expand_bool,
  opt_bool_last,
  opt_rewrite, opt_timelist, opt_uid, opt_gid, opt_uidlist, opt_gidlist,
  opt_expand_uid, opt_expand_gid, opt_func, opt_void };

/* There's a high-ish bit which is used to flag duplicate options, kept
for compatibility, which shouldn't be output. Also used for hidden options
that are automatically maintained from others. Another high bit is used to
flag driver options that although private (so as to be settable only on some
drivers), are stored in the instance block so as to be accessible from outside.
A third high bit is set when an option is read, so as to be able to give an
error if any option is set twice. Finally, there's a bit which is set when an
option is set with the "hide" prefix, to prevent -bP from showing it to
non-admin callers. The next byte up in the int is used to keep the bit number
for booleans that are kept in one bit. */

#define opt_hidden  0x100      /* Private to Exim */
#define opt_public  0x200      /* Stored in the main instance block */
#define opt_set     0x400      /* Option is set */
#define opt_secure  0x800      /* "hide" prefix used */
#define opt_rep_con 0x1000     /* Can be appended to by a repeated line (condition) */
#define opt_rep_str 0x2000     /* Can be appended to by a repeated line (string) */
#define opt_mask    0x00ff

/* Verify types when directing and routing */

enum { v_none, v_sender, v_recipient, v_expn };

/* Option flags for verify_address() */

#define vopt_fake_sender          0x0001   /* for verify=sender=<address> */
#define vopt_is_recipient         0x0002
#define vopt_qualify              0x0004
#define vopt_expn                 0x0008
#define vopt_callout_fullpm       0x0010   /* full postmaster during callout */
#define vopt_callout_random       0x0020   /* during callout */
#define vopt_callout_no_cache     0x0040   /* disable callout cache */
#define vopt_callout_recipsender  0x0080   /* use real sender to verify recip */
#define vopt_callout_recippmaster 0x0100   /* use postmaster to verify recip */
#define vopt_success_on_redirect  0x0200

/* Values for fields in callout cache records */

#define ccache_unknown         0       /* test hasn't been done */
#define ccache_accept          1
#define ccache_reject          2       /* All rejections except */
#define ccache_reject_mfnull   3       /* MAIL FROM:<> was rejected */

/* Options for lookup functions */

#define lookup_querystyle      1    /* query-style lookup */
#define lookup_absfile         2    /* requires absolute file name */
#define lookup_absfilequery    4    /* query-style starts with file name */

/* Status values for host_item blocks. Require hstatus_unusable and
hstatus_unusable_expired to be last. */

enum { hstatus_unknown, hstatus_usable, hstatus_unusable,
       hstatus_unusable_expired };

/* Reasons why a host is unusable (for clearer log messages) */

enum { hwhy_unknown, hwhy_retry, hwhy_failed, hwhy_deferred, hwhy_ignored };

/* Domain lookup types for routers */

enum { lk_default, lk_byname, lk_bydns };

/* Values for the self_code fields */

enum { self_freeze, self_defer, self_send, self_reroute, self_pass, self_fail };

/* Flags for rewrite rules */

#define rewrite_sender       0x0001
#define rewrite_from         0x0002
#define rewrite_to           0x0004
#define rewrite_cc           0x0008
#define rewrite_bcc          0x0010
#define rewrite_replyto      0x0020
#define rewrite_all_headers  0x003F  /* all header flags */

#define rewrite_envfrom      0x0040
#define rewrite_envto        0x0080
#define rewrite_all_envelope 0x00C0  /* all envelope flags */

#define rewrite_all      (rewrite_all_headers | rewrite_all_envelope)

#define rewrite_smtp         0x0100  /* rewrite at SMTP time */
#define rewrite_smtp_sender  0x0200  /* SMTP sender rewrite (allows <>) */
#define rewrite_qualify      0x0400  /* qualify if necessary */
#define rewrite_repeat       0x0800  /* repeat rewrite rule */

#define rewrite_whole        0x1000  /* option bit for headers */
#define rewrite_quit         0x2000  /* "no more" option */

/* Flags for log_write(); LOG_MAIN, LOG_PANIC, and LOG_REJECT are also in
local_scan.h */

#define LOG_MAIN           1      /* Write to the main log */
#define LOG_PANIC          2      /* Write to the panic log */
#define LOG_PANIC_DIE      6      /* Write to the panic log and then die */
#define LOG_REJECT        16      /* Write to the reject log, with headers */
#define LOG_SENDER        32      /* Add raw sender to the message */
#define LOG_RECIPIENTS    64      /* Add raw recipients to the message */
#define LOG_CONFIG       128      /* Add "Exim configuration error" */
#define LOG_CONFIG_FOR  (256+128) /* Add " for" instead of ":\n" */
#define LOG_CONFIG_IN   (512+128) /* Add " in line x[ of file y]" */

/* and for debug_bits() logging action control: */
#define DEBUG_FROM_CONFIG       0x0001

/* SMTP command identifiers for the smtp_connection_had field that records the
most recent SMTP commands. Must be kept in step with the list of names in
smtp_in.c that is used for creating the smtp_no_mail logging action. SCH_NONE
is "empty". */

enum { SCH_NONE, SCH_AUTH, SCH_DATA, SCH_EHLO, SCH_ETRN, SCH_EXPN, SCH_HELO,
       SCH_HELP, SCH_MAIL, SCH_NOOP, SCH_QUIT, SCH_RCPT, SCH_RSET, SCH_STARTTLS,
       SCH_VRFY };

/* Returns from host_find_by{name,dns}() */

enum {
  HOST_FIND_FAILED,     /* failed to find the host */
  HOST_FIND_AGAIN,      /* could not resolve at this time */
  HOST_FOUND,           /* found host */
  HOST_FOUND_LOCAL,     /* found, but MX points to local host */
  HOST_IGNORED          /* found but ignored - used internally only */
};

/* Flags for host_find_bydns() */

#define HOST_FIND_BY_SRV          0x0001
#define HOST_FIND_BY_MX           0x0002
#define HOST_FIND_BY_A            0x0004
#define HOST_FIND_QUALIFY_SINGLE  0x0008
#define HOST_FIND_SEARCH_PARENTS  0x0010

/* Actions applied to specific messages. */

enum { MSG_DELIVER, MSG_FREEZE, MSG_REMOVE, MSG_THAW, MSG_ADD_RECIPIENT,
       MSG_MARK_ALL_DELIVERED, MSG_MARK_DELIVERED, MSG_EDIT_SENDER,
       MSG_SHOW_COPY, MSG_LOAD,
       /* These ones must be last: a test for >= MSG_SHOW_BODY is used
       to test for actions that list individual spool files. */
       MSG_SHOW_BODY, MSG_SHOW_HEADER, MSG_SHOW_LOG };

/* Returns from the spool_read_header() function */

enum {
  spool_read_OK,        /* success */
  spool_read_notopen,   /* open failed */
  spool_read_enverror,  /* error in the envelope */
  spool_read_hdrerror   /* error in the headers */
};

/* Options for transport_write_message */

#define topt_add_return_path    0x001
#define topt_add_delivery_date  0x002
#define topt_add_envelope_to    0x004
#define topt_use_crlf           0x008  /* Terminate lines with CRLF */
#define topt_end_dot            0x010  /* Send terminting dot line */
#define topt_no_headers         0x020  /* Omit headers */
#define topt_no_body            0x040  /* Omit body */
#define topt_escape_headers     0x080  /* Apply escape check to headers */

/* Flags for recipient_block, used in DSN support */

#define rf_dsnlasthop           0x01  /* Do not propagate DSN any further */
#define rf_notify_never         0x02  /* NOTIFY= settings */
#define rf_notify_success       0x04
#define rf_notify_failure       0x08
#define rf_notify_delay         0x10

#define rf_dsnflags  (rf_notify_never | rf_notify_success | \
                      rf_notify_failure | rf_notify_delay)

/* DSN RET types */

#define dsn_ret_full            1
#define dsn_ret_hdrs            2

#define dsn_support_unknown     0
#define dsn_support_yes         1
#define dsn_support_no          2


/* Codes for the host_find_failed and host_all_ignored options. */

#define hff_freeze   0
#define hff_defer    1
#define hff_pass     2
#define hff_decline  3
#define hff_fail     4
#define hff_ignore   5

/* Router information flags */

#define ri_yestransport    0x0001    /* Must have a transport */
#define ri_notransport     0x0002    /* Must not have a transport */

/* Codes for match types in match_check_list; to any of them, MCL_NOEXPAND may
be added */

#define MCL_NOEXPAND  16

enum { MCL_STRING, MCL_DOMAIN, MCL_HOST, MCL_ADDRESS, MCL_LOCALPART };

/* Codes for the places from which ACLs can be called. These are cunningly
ordered to make it easy to implement tests for certain ACLs when processing
"control" modifiers, by means of a maximum "where" value. Do not modify this
order without checking carefully!

**** IMPORTANT***
****   Furthermore, remember to keep these in step with the tables
****   of names and response codes in globals.c.
**** IMPORTANT ****
*/

enum { ACL_WHERE_RCPT,       /* Some controls are for RCPT only */
       ACL_WHERE_MAIL,       /* )                                           */
       ACL_WHERE_PREDATA,    /* ) There are several tests for "in message", */
       ACL_WHERE_MIME,       /* ) implemented by <= WHERE_NOTSMTP           */
       ACL_WHERE_DKIM,       /* )                                           */
       ACL_WHERE_DATA,       /* )                                           */
#ifndef DISABLE_PRDR
       ACL_WHERE_PRDR,       /* )                                           */
#endif
       ACL_WHERE_NOTSMTP,    /* )                                           */

       ACL_WHERE_AUTH,       /* These remaining ones are not currently    */
       ACL_WHERE_CONNECT,    /* required to be in a special order so they */
       ACL_WHERE_ETRN,       /* are just alphabetical.                    */
       ACL_WHERE_EXPN,
       ACL_WHERE_HELO,
       ACL_WHERE_MAILAUTH,
       ACL_WHERE_NOTSMTP_START,
       ACL_WHERE_NOTQUIT,
       ACL_WHERE_QUIT,
       ACL_WHERE_STARTTLS,
       ACL_WHERE_VRFY,

       ACL_WHERE_DELIVERY,
       ACL_WHERE_UNKNOWN     /* Currently used by a ${acl:name} expansion */
     };

/* Situations for spool_write_header() */

enum { SW_RECEIVING, SW_DELIVERING, SW_MODIFYING };

/* MX fields for hosts not obtained from MX records are always negative.
MX_NONE is the default case; lesser values are used when the hosts are
randomized in batches. */

#define MX_NONE           (-1)

/* host_item.port defaults to PORT_NONE; the only current case where this
is changed before running the transport is when an dnslookup router sets an
explicit port number. */

#define PORT_NONE     (-1)

/* Flags for single-key search defaults */

#define SEARCH_STAR       0x01
#define SEARCH_STARAT     0x02

/* Filter types */

enum { FILTER_UNSET, FILTER_FORWARD, FILTER_EXIM, FILTER_SIEVE };

/* End of macros.h */
