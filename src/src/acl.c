/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012 */
/* See the file NOTICE for conditions of use and distribution. */

/* Code for handling Access Control Lists (ACLs) */

#include "exim.h"


/* Default callout timeout */

#define CALLOUT_TIMEOUT_DEFAULT 30

/* ACL verb codes - keep in step with the table of verbs that follows */

enum { ACL_ACCEPT, ACL_DEFER, ACL_DENY, ACL_DISCARD, ACL_DROP, ACL_REQUIRE,
       ACL_WARN };

/* ACL verbs */

static uschar *verbs[] =
  { US"accept", US"defer", US"deny", US"discard", US"drop", US"require",
    US"warn" };

/* For each verb, the conditions for which "message" or "log_message" are used
are held as a bitmap. This is to avoid expanding the strings unnecessarily. For
"accept", the FAIL case is used only after "endpass", but that is selected in
the code. */

static int msgcond[] = {
  (1<<OK) | (1<<FAIL) | (1<<FAIL_DROP),  /* accept */
  (1<<OK),                               /* defer */
  (1<<OK),                               /* deny */
  (1<<OK) | (1<<FAIL) | (1<<FAIL_DROP),  /* discard */
  (1<<OK),                               /* drop */
  (1<<FAIL) | (1<<FAIL_DROP),            /* require */
  (1<<OK)                                /* warn */
  };

/* ACL condition and modifier codes - keep in step with the table that
follows, and the cond_expand_at_top and uschar cond_modifiers tables lower
down. */

enum { ACLC_ACL,
       ACLC_ADD_HEADER,
       ACLC_AUTHENTICATED,
#ifdef EXPERIMENTAL_BRIGHTMAIL
       ACLC_BMI_OPTIN,
#endif
       ACLC_CONDITION,
       ACLC_CONTINUE,
       ACLC_CONTROL,
#ifdef EXPERIMENTAL_DCC
       ACLC_DCC,
#endif
#ifdef WITH_CONTENT_SCAN
       ACLC_DECODE,
#endif
       ACLC_DELAY,
#ifdef WITH_OLD_DEMIME
       ACLC_DEMIME,
#endif
#ifndef DISABLE_DKIM
       ACLC_DKIM_SIGNER,
       ACLC_DKIM_STATUS,
#endif
#ifdef EXPERIMENTAL_DMARC
       ACLC_DMARC_STATUS,
#endif
       ACLC_DNSLISTS,
       ACLC_DOMAINS,
       ACLC_ENCRYPTED,
       ACLC_ENDPASS,
       ACLC_HOSTS,
       ACLC_LOCAL_PARTS,
       ACLC_LOG_MESSAGE,
       ACLC_LOG_REJECT_TARGET,
       ACLC_LOGWRITE,
#ifdef WITH_CONTENT_SCAN
       ACLC_MALWARE,
#endif
       ACLC_MESSAGE,
#ifdef WITH_CONTENT_SCAN
       ACLC_MIME_REGEX,
#endif
       ACLC_RATELIMIT,
       ACLC_RECIPIENTS,
#ifdef WITH_CONTENT_SCAN
       ACLC_REGEX,
#endif
       ACLC_REMOVE_HEADER,
       ACLC_SENDER_DOMAINS,
       ACLC_SENDERS,
       ACLC_SET,
#ifdef WITH_CONTENT_SCAN
       ACLC_SPAM,
#endif
#ifdef EXPERIMENTAL_SPF
       ACLC_SPF,
       ACLC_SPF_GUESS,
#endif
       ACLC_VERIFY };

/* ACL conditions/modifiers: "delay", "control", "continue", "endpass",
"message", "log_message", "log_reject_target", "logwrite", and "set" are
modifiers that look like conditions but always return TRUE. They are used for
their side effects. */

static uschar *conditions[] = {
  US"acl",
  US"add_header",
  US"authenticated",
#ifdef EXPERIMENTAL_BRIGHTMAIL
  US"bmi_optin",
#endif
  US"condition",
  US"continue",
  US"control",
#ifdef EXPERIMENTAL_DCC
  US"dcc",
#endif
#ifdef WITH_CONTENT_SCAN
  US"decode",
#endif
  US"delay",
#ifdef WITH_OLD_DEMIME
  US"demime",
#endif
#ifndef DISABLE_DKIM
  US"dkim_signers",
  US"dkim_status",
#endif
#ifdef EXPERIMENTAL_DMARC
  US"dmarc_status",
#endif
  US"dnslists",
  US"domains",
  US"encrypted",
  US"endpass",
  US"hosts",
  US"local_parts",
  US"log_message",
  US"log_reject_target",
  US"logwrite",
#ifdef WITH_CONTENT_SCAN
  US"malware",
#endif
  US"message",
#ifdef WITH_CONTENT_SCAN
  US"mime_regex",
#endif
  US"ratelimit",
  US"recipients",
#ifdef WITH_CONTENT_SCAN
  US"regex",
#endif
  US"remove_header",
  US"sender_domains", US"senders", US"set",
#ifdef WITH_CONTENT_SCAN
  US"spam",
#endif
#ifdef EXPERIMENTAL_SPF
  US"spf",
  US"spf_guess",
#endif
  US"verify" };


/* Return values from decode_control(); keep in step with the table of names
that follows! */

enum {
  CONTROL_AUTH_UNADVERTISED,
  #ifdef EXPERIMENTAL_BRIGHTMAIL
  CONTROL_BMI_RUN,
  #endif
  CONTROL_DEBUG,
  #ifndef DISABLE_DKIM
  CONTROL_DKIM_VERIFY,
  #endif
  #ifdef EXPERIMENTAL_DMARC
  CONTROL_DMARC_VERIFY,
  CONTROL_DMARC_FORENSIC,
  #endif
  CONTROL_DSCP,
  CONTROL_ERROR,
  CONTROL_CASEFUL_LOCAL_PART,
  CONTROL_CASELOWER_LOCAL_PART,
  CONTROL_CUTTHROUGH_DELIVERY,
  CONTROL_ENFORCE_SYNC,
  CONTROL_NO_ENFORCE_SYNC,
  CONTROL_FREEZE,
  CONTROL_QUEUE_ONLY,
  CONTROL_SUBMISSION,
  CONTROL_SUPPRESS_LOCAL_FIXUPS,
  #ifdef WITH_CONTENT_SCAN
  CONTROL_NO_MBOX_UNSPOOL,
  #endif
  CONTROL_FAKEDEFER,
  CONTROL_FAKEREJECT,
  CONTROL_NO_MULTILINE,
  CONTROL_NO_PIPELINING,
  CONTROL_NO_DELAY_FLUSH,
  CONTROL_NO_CALLOUT_FLUSH
};

/* ACL control names; keep in step with the table above! This list is used for
turning ids into names. The actual list of recognized names is in the variable
control_def controls_list[] below. The fact that there are two lists is a mess
and should be tidied up. */

static uschar *controls[] = {
  US"allow_auth_unadvertised",
  #ifdef EXPERIMENTAL_BRIGHTMAIL
  US"bmi_run",
  #endif
  US"debug",
  #ifndef DISABLE_DKIM
  US"dkim_disable_verify",
  #endif
  #ifdef EXPERIMENTAL_DMARC
  US"dmarc_disable_verify",
  US"dmarc_enable_forensic",
  #endif
  US"dscp",
  US"error",
  US"caseful_local_part",
  US"caselower_local_part",
  US"cutthrough_delivery",
  US"enforce_sync",
  US"no_enforce_sync",
  US"freeze",
  US"queue_only",
  US"submission",
  US"suppress_local_fixups",
  #ifdef WITH_CONTENT_SCAN
  US"no_mbox_unspool",
  #endif
  US"fakedefer",
  US"fakereject",
  US"no_multiline_responses",
  US"no_pipelining",
  US"no_delay_flush",
  US"no_callout_flush"
};

/* Flags to indicate for which conditions/modifiers a string expansion is done
at the outer level. In the other cases, expansion already occurs in the
checking functions. */

static uschar cond_expand_at_top[] = {
  FALSE,   /* acl */
  TRUE,    /* add_header */
  FALSE,   /* authenticated */
#ifdef EXPERIMENTAL_BRIGHTMAIL
  TRUE,    /* bmi_optin */
#endif
  TRUE,    /* condition */
  TRUE,    /* continue */
  TRUE,    /* control */
#ifdef EXPERIMENTAL_DCC
  TRUE,    /* dcc */
#endif
#ifdef WITH_CONTENT_SCAN
  TRUE,    /* decode */
#endif
  TRUE,    /* delay */
#ifdef WITH_OLD_DEMIME
  TRUE,    /* demime */
#endif
#ifndef DISABLE_DKIM
  TRUE,    /* dkim_signers */
  TRUE,    /* dkim_status */
#endif
#ifdef EXPERIMENTAL_DMARC
  TRUE,    /* dmarc_status */
#endif
  TRUE,    /* dnslists */
  FALSE,   /* domains */
  FALSE,   /* encrypted */
  TRUE,    /* endpass */
  FALSE,   /* hosts */
  FALSE,   /* local_parts */
  TRUE,    /* log_message */
  TRUE,    /* log_reject_target */
  TRUE,    /* logwrite */
#ifdef WITH_CONTENT_SCAN
  TRUE,    /* malware */
#endif
  TRUE,    /* message */
#ifdef WITH_CONTENT_SCAN
  TRUE,    /* mime_regex */
#endif
  TRUE,    /* ratelimit */
  FALSE,   /* recipients */
#ifdef WITH_CONTENT_SCAN
  TRUE,    /* regex */
#endif
  TRUE,    /* remove_header */
  FALSE,   /* sender_domains */
  FALSE,   /* senders */
  TRUE,    /* set */
#ifdef WITH_CONTENT_SCAN
  TRUE,    /* spam */
#endif
#ifdef EXPERIMENTAL_SPF
  TRUE,    /* spf */
  TRUE,    /* spf_guess */
#endif
  TRUE     /* verify */
};

/* Flags to identify the modifiers */

static uschar cond_modifiers[] = {
  FALSE,   /* acl */
  TRUE,    /* add_header */
  FALSE,   /* authenticated */
#ifdef EXPERIMENTAL_BRIGHTMAIL
  TRUE,    /* bmi_optin */
#endif
  FALSE,   /* condition */
  TRUE,    /* continue */
  TRUE,    /* control */
#ifdef EXPERIMENTAL_DCC
  FALSE,   /* dcc */
#endif
#ifdef WITH_CONTENT_SCAN
  FALSE,   /* decode */
#endif
  TRUE,    /* delay */
#ifdef WITH_OLD_DEMIME
  FALSE,   /* demime */
#endif
#ifndef DISABLE_DKIM
  FALSE,   /* dkim_signers */
  FALSE,   /* dkim_status */
#endif
#ifdef EXPERIMENTAL_DMARC
  FALSE,   /* dmarc_status */
#endif
  FALSE,   /* dnslists */
  FALSE,   /* domains */
  FALSE,   /* encrypted */
  TRUE,    /* endpass */
  FALSE,   /* hosts */
  FALSE,   /* local_parts */
  TRUE,    /* log_message */
  TRUE,    /* log_reject_target */
  TRUE,    /* logwrite */
#ifdef WITH_CONTENT_SCAN
  FALSE,   /* malware */
#endif
  TRUE,    /* message */
#ifdef WITH_CONTENT_SCAN
  FALSE,   /* mime_regex */
#endif
  FALSE,   /* ratelimit */
  FALSE,   /* recipients */
#ifdef WITH_CONTENT_SCAN
  FALSE,   /* regex */
#endif
  TRUE,    /* remove_header */
  FALSE,   /* sender_domains */
  FALSE,   /* senders */
  TRUE,    /* set */
#ifdef WITH_CONTENT_SCAN
  FALSE,   /* spam */
#endif
#ifdef EXPERIMENTAL_SPF
  FALSE,   /* spf */
  FALSE,   /* spf_guess */
#endif
  FALSE    /* verify */
};

/* Bit map vector of which conditions and modifiers are not allowed at certain
times. For each condition and modifier, there's a bitmap of dis-allowed times.
For some, it is easier to specify the negation of a small number of allowed
times. */

static unsigned int cond_forbids[] = {
  0,                                               /* acl */

  (unsigned int)
  ~((1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)|       /* add_header */
    (1<<ACL_WHERE_PREDATA)|(1<<ACL_WHERE_DATA)|
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif
    (1<<ACL_WHERE_MIME)|(1<<ACL_WHERE_NOTSMTP)|
    (1<<ACL_WHERE_DKIM)|
    (1<<ACL_WHERE_NOTSMTP_START)),

  (1<<ACL_WHERE_NOTSMTP)|                          /* authenticated */
    (1<<ACL_WHERE_NOTSMTP_START)|
    (1<<ACL_WHERE_CONNECT)|(1<<ACL_WHERE_HELO),

  #ifdef EXPERIMENTAL_BRIGHTMAIL
  (1<<ACL_WHERE_AUTH)|                             /* bmi_optin */
    (1<<ACL_WHERE_CONNECT)|(1<<ACL_WHERE_HELO)|
    (1<<ACL_WHERE_DATA)|(1<<ACL_WHERE_MIME)|
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif
    (1<<ACL_WHERE_ETRN)|(1<<ACL_WHERE_EXPN)|
    (1<<ACL_WHERE_MAILAUTH)|
    (1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_STARTTLS)|
    (1<<ACL_WHERE_VRFY)|(1<<ACL_WHERE_PREDATA)|
    (1<<ACL_WHERE_NOTSMTP_START),
  #endif

  0,                                               /* condition */

  0,                                               /* continue */

  /* Certain types of control are always allowed, so we let it through
  always and check in the control processing itself. */

  0,                                               /* control */

  #ifdef EXPERIMENTAL_DCC
  (unsigned int)
  ~((1<<ACL_WHERE_DATA)|                           /* dcc */
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif /* EXPERIMENTAL_PRDR */
    (1<<ACL_WHERE_NOTSMTP)),
  #endif

  #ifdef WITH_CONTENT_SCAN
  (unsigned int)
  ~(1<<ACL_WHERE_MIME),                            /* decode */
  #endif

  (1<<ACL_WHERE_NOTQUIT),                          /* delay */

  #ifdef WITH_OLD_DEMIME
  (unsigned int)
  ~((1<<ACL_WHERE_DATA)|                           /* demime */
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif /* EXPERIMENTAL_PRDR */
    (1<<ACL_WHERE_NOTSMTP)),
  #endif

  #ifndef DISABLE_DKIM
  (unsigned int)
  ~(1<<ACL_WHERE_DKIM),                            /* dkim_signers */

  (unsigned int)
  ~(1<<ACL_WHERE_DKIM),                            /* dkim_status */
  #endif

  #ifdef EXPERIMENTAL_DMARC
  (unsigned int)
  ~(1<<ACL_WHERE_DATA),                            /* dmarc_status */
  #endif

  (1<<ACL_WHERE_NOTSMTP)|                          /* dnslists */
    (1<<ACL_WHERE_NOTSMTP_START),

  (unsigned int)
  ~((1<<ACL_WHERE_RCPT)                            /* domains */
  #ifdef EXPERIMENTAL_PRDR
    |(1<<ACL_WHERE_PRDR)
  #endif
    ),

  (1<<ACL_WHERE_NOTSMTP)|                          /* encrypted */
    (1<<ACL_WHERE_CONNECT)|
    (1<<ACL_WHERE_NOTSMTP_START)|
    (1<<ACL_WHERE_HELO),

  0,                                               /* endpass */

  (1<<ACL_WHERE_NOTSMTP)|                          /* hosts */
    (1<<ACL_WHERE_NOTSMTP_START),

  (unsigned int)
  ~((1<<ACL_WHERE_RCPT)                             /* local_parts */
  #ifdef EXPERIMENTAL_PRDR
    |(1<<ACL_WHERE_PRDR)
  #endif
    ),

  0,                                               /* log_message */

  0,                                               /* log_reject_target */

  0,                                               /* logwrite */

  #ifdef WITH_CONTENT_SCAN
  (unsigned int)
  ~((1<<ACL_WHERE_DATA)|                           /* malware */
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif /* EXPERIMENTAL_PRDR */
    (1<<ACL_WHERE_NOTSMTP)),
  #endif

  0,                                               /* message */

  #ifdef WITH_CONTENT_SCAN
  (unsigned int)
  ~(1<<ACL_WHERE_MIME),                            /* mime_regex */
  #endif

  0,                                               /* ratelimit */

  (unsigned int)
  ~(1<<ACL_WHERE_RCPT),                            /* recipients */

  #ifdef WITH_CONTENT_SCAN
  (unsigned int)
  ~((1<<ACL_WHERE_DATA)|                           /* regex */
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif /* EXPERIMENTAL_PRDR */
    (1<<ACL_WHERE_NOTSMTP)|
    (1<<ACL_WHERE_MIME)),
  #endif

  (unsigned int)
  ~((1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)|       /* remove_header */
    (1<<ACL_WHERE_PREDATA)|(1<<ACL_WHERE_DATA)|
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif
    (1<<ACL_WHERE_MIME)|(1<<ACL_WHERE_NOTSMTP)|
    (1<<ACL_WHERE_NOTSMTP_START)),

  (1<<ACL_WHERE_AUTH)|(1<<ACL_WHERE_CONNECT)|      /* sender_domains */
    (1<<ACL_WHERE_HELO)|
    (1<<ACL_WHERE_MAILAUTH)|(1<<ACL_WHERE_QUIT)|
    (1<<ACL_WHERE_ETRN)|(1<<ACL_WHERE_EXPN)|
    (1<<ACL_WHERE_STARTTLS)|(1<<ACL_WHERE_VRFY),

  (1<<ACL_WHERE_AUTH)|(1<<ACL_WHERE_CONNECT)|      /* senders */
    (1<<ACL_WHERE_HELO)|
    (1<<ACL_WHERE_MAILAUTH)|(1<<ACL_WHERE_QUIT)|
    (1<<ACL_WHERE_ETRN)|(1<<ACL_WHERE_EXPN)|
    (1<<ACL_WHERE_STARTTLS)|(1<<ACL_WHERE_VRFY),

  0,                                               /* set */

  #ifdef WITH_CONTENT_SCAN
  (unsigned int)
  ~((1<<ACL_WHERE_DATA)|                           /* spam */
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif /* EXPERIMENTAL_PRDR */
    (1<<ACL_WHERE_NOTSMTP)),
  #endif

  #ifdef EXPERIMENTAL_SPF
  (1<<ACL_WHERE_AUTH)|(1<<ACL_WHERE_CONNECT)|      /* spf */
    (1<<ACL_WHERE_HELO)|
    (1<<ACL_WHERE_MAILAUTH)|
    (1<<ACL_WHERE_ETRN)|(1<<ACL_WHERE_EXPN)|
    (1<<ACL_WHERE_STARTTLS)|(1<<ACL_WHERE_VRFY)|
    (1<<ACL_WHERE_NOTSMTP)|
    (1<<ACL_WHERE_NOTSMTP_START),

  (1<<ACL_WHERE_AUTH)|(1<<ACL_WHERE_CONNECT)|      /* spf_guess */
    (1<<ACL_WHERE_HELO)|
    (1<<ACL_WHERE_MAILAUTH)|
    (1<<ACL_WHERE_ETRN)|(1<<ACL_WHERE_EXPN)|
    (1<<ACL_WHERE_STARTTLS)|(1<<ACL_WHERE_VRFY)|
    (1<<ACL_WHERE_NOTSMTP)|
    (1<<ACL_WHERE_NOTSMTP_START),
  #endif

  /* Certain types of verify are always allowed, so we let it through
  always and check in the verify function itself */

  0                                                /* verify */
};


/* Bit map vector of which controls are not allowed at certain times. For
each control, there's a bitmap of dis-allowed times. For some, it is easier to
specify the negation of a small number of allowed times. */

static unsigned int control_forbids[] = {
  (unsigned int)
  ~((1<<ACL_WHERE_CONNECT)|(1<<ACL_WHERE_HELO)),   /* allow_auth_unadvertised */

  #ifdef EXPERIMENTAL_BRIGHTMAIL
  0,                                               /* bmi_run */
  #endif

  0,                                               /* debug */

  #ifndef DISABLE_DKIM
  (1<<ACL_WHERE_DATA)|(1<<ACL_WHERE_NOTSMTP)|      /* dkim_disable_verify */
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif /* EXPERIMENTAL_PRDR */
    (1<<ACL_WHERE_NOTSMTP_START),
  #endif

  #ifdef EXPERIMENTAL_DMARC
  (1<<ACL_WHERE_DATA)|(1<<ACL_WHERE_NOTSMTP)|      /* dmarc_disable_verify */
    (1<<ACL_WHERE_NOTSMTP_START),
  (1<<ACL_WHERE_DATA)|(1<<ACL_WHERE_NOTSMTP)|      /* dmarc_enable_forensic */
    (1<<ACL_WHERE_NOTSMTP_START),
  #endif

  (1<<ACL_WHERE_NOTSMTP)|
    (1<<ACL_WHERE_NOTSMTP_START)|
    (1<<ACL_WHERE_NOTQUIT),                        /* dscp */

  0,                                               /* error */

  (unsigned int)
  ~(1<<ACL_WHERE_RCPT),                            /* caseful_local_part */

  (unsigned int)
  ~(1<<ACL_WHERE_RCPT),                            /* caselower_local_part */

  (unsigned int)
  0,						   /* cutthrough_delivery */

  (1<<ACL_WHERE_NOTSMTP)|                          /* enforce_sync */
    (1<<ACL_WHERE_NOTSMTP_START),

  (1<<ACL_WHERE_NOTSMTP)|                          /* no_enforce_sync */
    (1<<ACL_WHERE_NOTSMTP_START),

  (unsigned int)
  ~((1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)|       /* freeze */
    (1<<ACL_WHERE_PREDATA)|(1<<ACL_WHERE_DATA)|
    // (1<<ACL_WHERE_PRDR)|    /* Not allow one user to freeze for all */
    (1<<ACL_WHERE_NOTSMTP)|(1<<ACL_WHERE_MIME)),

  (unsigned int)
  ~((1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)|       /* queue_only */
    (1<<ACL_WHERE_PREDATA)|(1<<ACL_WHERE_DATA)|
    // (1<<ACL_WHERE_PRDR)|    /* Not allow one user to freeze for all */
    (1<<ACL_WHERE_NOTSMTP)|(1<<ACL_WHERE_MIME)),

  (unsigned int)
  ~((1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)|       /* submission */
    (1<<ACL_WHERE_PREDATA)),

  (unsigned int)
  ~((1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)|       /* suppress_local_fixups */
    (1<<ACL_WHERE_PREDATA)|
    (1<<ACL_WHERE_NOTSMTP_START)),

  #ifdef WITH_CONTENT_SCAN
  (unsigned int)
  ~((1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)|       /* no_mbox_unspool */
    (1<<ACL_WHERE_PREDATA)|(1<<ACL_WHERE_DATA)|
    // (1<<ACL_WHERE_PRDR)|    /* Not allow one user to freeze for all */
    (1<<ACL_WHERE_MIME)),
  #endif

  (unsigned int)
  ~((1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)|       /* fakedefer */
    (1<<ACL_WHERE_PREDATA)|(1<<ACL_WHERE_DATA)|
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif /* EXPERIMENTAL_PRDR */
    (1<<ACL_WHERE_MIME)),

  (unsigned int)
  ~((1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)|       /* fakereject */
    (1<<ACL_WHERE_PREDATA)|(1<<ACL_WHERE_DATA)|
  #ifdef EXPERIMENTAL_PRDR
    (1<<ACL_WHERE_PRDR)|
  #endif /* EXPERIMENTAL_PRDR */
    (1<<ACL_WHERE_MIME)),

  (1<<ACL_WHERE_NOTSMTP)|                          /* no_multiline */
    (1<<ACL_WHERE_NOTSMTP_START),

  (1<<ACL_WHERE_NOTSMTP)|                          /* no_pipelining */
    (1<<ACL_WHERE_NOTSMTP_START),

  (1<<ACL_WHERE_NOTSMTP)|                          /* no_delay_flush */
    (1<<ACL_WHERE_NOTSMTP_START),

  (1<<ACL_WHERE_NOTSMTP)|                          /* no_callout_flush */
    (1<<ACL_WHERE_NOTSMTP_START)
};

/* Structure listing various control arguments, with their characteristics. */

typedef struct control_def {
  uschar *name;
  int    value;                  /* CONTROL_xxx value */
  BOOL   has_option;             /* Has /option(s) following */
} control_def;

static control_def controls_list[] = {
  { US"allow_auth_unadvertised", CONTROL_AUTH_UNADVERTISED, FALSE },
#ifdef EXPERIMENTAL_BRIGHTMAIL
  { US"bmi_run",                 CONTROL_BMI_RUN, FALSE },
#endif
  { US"debug",                   CONTROL_DEBUG, TRUE },
#ifndef DISABLE_DKIM
  { US"dkim_disable_verify",     CONTROL_DKIM_VERIFY, FALSE },
#endif
#ifdef EXPERIMENTAL_DMARC
  { US"dmarc_disable_verify",    CONTROL_DMARC_VERIFY, FALSE },
  { US"dmarc_enable_forensic",   CONTROL_DMARC_FORENSIC, FALSE },
#endif
  { US"dscp",                    CONTROL_DSCP, TRUE },
  { US"caseful_local_part",      CONTROL_CASEFUL_LOCAL_PART, FALSE },
  { US"caselower_local_part",    CONTROL_CASELOWER_LOCAL_PART, FALSE },
  { US"enforce_sync",            CONTROL_ENFORCE_SYNC, FALSE },
  { US"freeze",                  CONTROL_FREEZE, TRUE },
  { US"no_callout_flush",        CONTROL_NO_CALLOUT_FLUSH, FALSE },
  { US"no_delay_flush",          CONTROL_NO_DELAY_FLUSH, FALSE },
  { US"no_enforce_sync",         CONTROL_NO_ENFORCE_SYNC, FALSE },
  { US"no_multiline_responses",  CONTROL_NO_MULTILINE, FALSE },
  { US"no_pipelining",           CONTROL_NO_PIPELINING, FALSE },
  { US"queue_only",              CONTROL_QUEUE_ONLY, FALSE },
#ifdef WITH_CONTENT_SCAN
  { US"no_mbox_unspool",         CONTROL_NO_MBOX_UNSPOOL, FALSE },
#endif
  { US"fakedefer",               CONTROL_FAKEDEFER, TRUE },
  { US"fakereject",              CONTROL_FAKEREJECT, TRUE },
  { US"submission",              CONTROL_SUBMISSION, TRUE },
  { US"suppress_local_fixups",   CONTROL_SUPPRESS_LOCAL_FIXUPS, FALSE },
  { US"cutthrough_delivery",     CONTROL_CUTTHROUGH_DELIVERY, FALSE }
  };

/* Support data structures for Client SMTP Authorization. acl_verify_csa()
caches its result in a tree to avoid repeated DNS queries. The result is an
integer code which is used as an index into the following tables of
explanatory strings and verification return codes. */

static tree_node *csa_cache = NULL;

enum { CSA_UNKNOWN, CSA_OK, CSA_DEFER_SRV, CSA_DEFER_ADDR,
 CSA_FAIL_EXPLICIT, CSA_FAIL_DOMAIN, CSA_FAIL_NOADDR, CSA_FAIL_MISMATCH };

/* The acl_verify_csa() return code is translated into an acl_verify() return
code using the following table. It is OK unless the client is definitely not
authorized. This is because CSA is supposed to be optional for sending sites,
so recipients should not be too strict about checking it - especially because
DNS problems are quite likely to occur. It's possible to use $csa_status in
further ACL conditions to distinguish ok, unknown, and defer if required, but
the aim is to make the usual configuration simple. */

static int csa_return_code[] = {
  OK, OK, OK, OK,
  FAIL, FAIL, FAIL, FAIL
};

static uschar *csa_status_string[] = {
  US"unknown", US"ok", US"defer", US"defer",
  US"fail", US"fail", US"fail", US"fail"
};

static uschar *csa_reason_string[] = {
  US"unknown",
  US"ok",
  US"deferred (SRV lookup failed)",
  US"deferred (target address lookup failed)",
  US"failed (explicit authorization required)",
  US"failed (host name not authorized)",
  US"failed (no authorized addresses)",
  US"failed (client address mismatch)"
};

/* Options for the ratelimit condition. Note that there are two variants of
the per_rcpt option, depending on the ACL that is used to measure the rate.
However any ACL must be able to look up per_rcpt rates in /noupdate mode,
so the two variants must have the same internal representation as well as
the same configuration string. */

enum {
  RATE_PER_WHAT, RATE_PER_CLASH, RATE_PER_ADDR, RATE_PER_BYTE, RATE_PER_CMD,
  RATE_PER_CONN, RATE_PER_MAIL, RATE_PER_RCPT, RATE_PER_ALLRCPTS
};

#define RATE_SET(var,new) \
  (((var) == RATE_PER_WHAT) ? ((var) = RATE_##new) : ((var) = RATE_PER_CLASH))

static uschar *ratelimit_option_string[] = {
  US"?", US"!", US"per_addr", US"per_byte", US"per_cmd",
  US"per_conn", US"per_mail", US"per_rcpt", US"per_rcpt"
};

/* Enable recursion between acl_check_internal() and acl_check_condition() */

static int acl_check_wargs(int, address_item *, uschar *, int, uschar **,
    uschar **);


/*************************************************
*         Pick out name from list                *
*************************************************/

/* Use a binary chop method

Arguments:
  name        name to find
  list        list of names
  end         size of list

Returns:      offset in list, or -1 if not found
*/

static int
acl_checkname(uschar *name, uschar **list, int end)
{
int start = 0;

while (start < end)
  {
  int mid = (start + end)/2;
  int c = Ustrcmp(name, list[mid]);
  if (c == 0) return mid;
  if (c < 0) end = mid; else start = mid + 1;
  }

return -1;
}


/*************************************************
*            Read and parse one ACL              *
*************************************************/

/* This function is called both from readconf in order to parse the ACLs in the
configuration file, and also when an ACL is encountered dynamically (e.g. as
the result of an expansion). It is given a function to call in order to
retrieve the lines of the ACL. This function handles skipping comments and
blank lines (where relevant).

Arguments:
  func        function to get next line of ACL
  error       where to put an error message

Returns:      pointer to ACL, or NULL
              NULL can be legal (empty ACL); in this case error will be NULL
*/

acl_block *
acl_read(uschar *(*func)(void), uschar **error)
{
acl_block *yield = NULL;
acl_block **lastp = &yield;
acl_block *this = NULL;
acl_condition_block *cond;
acl_condition_block **condp = NULL;
uschar *s;

*error = NULL;

while ((s = (*func)()) != NULL)
  {
  int v, c;
  BOOL negated = FALSE;
  uschar *saveline = s;
  uschar name[64];

  /* Conditions (but not verbs) are allowed to be negated by an initial
  exclamation mark. */

  while (isspace(*s)) s++;
  if (*s == '!')
    {
    negated = TRUE;
    s++;
    }

  /* Read the name of a verb or a condition, or the start of a new ACL, which
  can be started by a name, or by a macro definition. */

  s = readconf_readname(name, sizeof(name), s);
  if (*s == ':' || (isupper(name[0]) && *s == '=')) return yield;

  /* If a verb is unrecognized, it may be another condition or modifier that
  continues the previous verb. */

  v = acl_checkname(name, verbs, sizeof(verbs)/sizeof(char *));
  if (v < 0)
    {
    if (this == NULL)
      {
      *error = string_sprintf("unknown ACL verb \"%s\" in \"%s\"", name,
        saveline);
      return NULL;
      }
    }

  /* New verb */

  else
    {
    if (negated)
      {
      *error = string_sprintf("malformed ACL line \"%s\"", saveline);
      return NULL;
      }
    this = store_get(sizeof(acl_block));
    *lastp = this;
    lastp = &(this->next);
    this->next = NULL;
    this->verb = v;
    this->condition = NULL;
    condp = &(this->condition);
    if (*s == 0) continue;               /* No condition on this line */
    if (*s == '!')
      {
      negated = TRUE;
      s++;
      }
    s = readconf_readname(name, sizeof(name), s);  /* Condition name */
    }

  /* Handle a condition or modifier. */

  c = acl_checkname(name, conditions, sizeof(conditions)/sizeof(char *));
  if (c < 0)
    {
    *error = string_sprintf("unknown ACL condition/modifier in \"%s\"",
      saveline);
    return NULL;
    }

  /* The modifiers may not be negated */

  if (negated && cond_modifiers[c])
    {
    *error = string_sprintf("ACL error: negation is not allowed with "
      "\"%s\"", conditions[c]);
    return NULL;
    }

  /* ENDPASS may occur only with ACCEPT or DISCARD. */

  if (c == ACLC_ENDPASS &&
      this->verb != ACL_ACCEPT &&
      this->verb != ACL_DISCARD)
    {
    *error = string_sprintf("ACL error: \"%s\" is not allowed with \"%s\"",
      conditions[c], verbs[this->verb]);
    return NULL;
    }

  cond = store_get(sizeof(acl_condition_block));
  cond->next = NULL;
  cond->type = c;
  cond->u.negated = negated;

  *condp = cond;
  condp = &(cond->next);

  /* The "set" modifier is different in that its argument is "name=value"
  rather than just a value, and we can check the validity of the name, which
  gives us a variable name to insert into the data block. The original ACL
  variable names were acl_c0 ... acl_c9 and acl_m0 ... acl_m9. This was
  extended to 20 of each type, but after that people successfully argued for
  arbitrary names. In the new scheme, the names must start with acl_c or acl_m.
  After that, we allow alphanumerics and underscores, but the first character
  after c or m must be a digit or an underscore. This retains backwards
  compatibility. */

  if (c == ACLC_SET)
    {
    uschar *endptr;

    if (Ustrncmp(s, "acl_c", 5) != 0 &&
        Ustrncmp(s, "acl_m", 5) != 0)
      {
      *error = string_sprintf("invalid variable name after \"set\" in ACL "
        "modifier \"set %s\" (must start \"acl_c\" or \"acl_m\")", s);
      return NULL;
      }

    endptr = s + 5;
    if (!isdigit(*endptr) && *endptr != '_')
      {
      *error = string_sprintf("invalid variable name after \"set\" in ACL "
        "modifier \"set %s\" (digit or underscore must follow acl_c or acl_m)",
        s);
      return NULL;
      }

    while (*endptr != 0 && *endptr != '=' && !isspace(*endptr))
      {
      if (!isalnum(*endptr) && *endptr != '_')
        {
        *error = string_sprintf("invalid character \"%c\" in variable name "
          "in ACL modifier \"set %s\"", *endptr, s);
        return NULL;
        }
      endptr++;
      }

    cond->u.varname = string_copyn(s + 4, endptr - s - 4);
    s = endptr;
    while (isspace(*s)) s++;
    }

  /* For "set", we are now positioned for the data. For the others, only
  "endpass" has no data */

  if (c != ACLC_ENDPASS)
    {
    if (*s++ != '=')
      {
      *error = string_sprintf("\"=\" missing after ACL \"%s\" %s", name,
        cond_modifiers[c]? US"modifier" : US"condition");
      return NULL;
      }
    while (isspace(*s)) s++;
    cond->arg = string_copy(s);
    }
  }

return yield;
}



/*************************************************
*         Set up added header line(s)            *
*************************************************/

/* This function is called by the add_header modifier, and also from acl_warn()
to implement the now-deprecated way of adding header lines using "message" on a
"warn" verb. The argument is treated as a sequence of header lines which are
added to a chain, provided there isn't an identical one already there.

Argument:   string of header lines
Returns:    nothing
*/

static void
setup_header(uschar *hstring)
{
uschar *p, *q;
int hlen = Ustrlen(hstring);

/* Ignore any leading newlines */
while (*hstring == '\n') hstring++, hlen--;

/* An empty string does nothing; ensure exactly one final newline. */
if (hlen <= 0) return;
if (hstring[--hlen] != '\n') hstring = string_sprintf("%s\n", hstring);
else while(hstring[--hlen] == '\n') hstring[hlen+1] = '\0';

/* Loop for multiple header lines, taking care about continuations */

for (p = q = hstring; *p != 0; )
  {
  uschar *s;
  int newtype = htype_add_bot;
  header_line **hptr = &acl_added_headers;

  /* Find next header line within the string */

  for (;;)
    {
    q = Ustrchr(q, '\n');
    if (*(++q) != ' ' && *q != '\t') break;
    }

  /* If the line starts with a colon, interpret the instruction for where to
  add it. This temporarily sets up a new type. */

  if (*p == ':')
    {
    if (strncmpic(p, US":after_received:", 16) == 0)
      {
      newtype = htype_add_rec;
      p += 16;
      }
    else if (strncmpic(p, US":at_start_rfc:", 14) == 0)
      {
      newtype = htype_add_rfc;
      p += 14;
      }
    else if (strncmpic(p, US":at_start:", 10) == 0)
      {
      newtype = htype_add_top;
      p += 10;
      }
    else if (strncmpic(p, US":at_end:", 8) == 0)
      {
      newtype = htype_add_bot;
      p += 8;
      }
    while (*p == ' ' || *p == '\t') p++;
    }

  /* See if this line starts with a header name, and if not, add X-ACL-Warn:
  to the front of it. */

  for (s = p; s < q - 1; s++)
    {
    if (*s == ':' || !isgraph(*s)) break;
    }

  s = string_sprintf("%s%.*s", (*s == ':')? "" : "X-ACL-Warn: ", (int) (q - p), p);
  hlen = Ustrlen(s);

  /* See if this line has already been added */

  while (*hptr != NULL)
    {
    if (Ustrncmp((*hptr)->text, s, hlen) == 0) break;
    hptr = &((*hptr)->next);
    }

  /* Add if not previously present */

  if (*hptr == NULL)
    {
    header_line *h = store_get(sizeof(header_line));
    h->text = s;
    h->next = NULL;
    h->type = newtype;
    h->slen = hlen;
    *hptr = h;
    hptr = &(h->next);
    }

  /* Advance for next header line within the string */

  p = q;
  }
}



/*************************************************
*        List the added header lines		 *
*************************************************/
uschar *
fn_hdrs_added(void)
{
uschar * ret = NULL;
header_line * h = acl_added_headers;
uschar * s;
uschar * cp;
int size = 0;
int ptr = 0;

if (!h) return NULL;

do
  {
  s = h->text;
  while ((cp = Ustrchr(s, '\n')) != NULL)
    {
    if (cp[1] == '\0') break;

    /* contains embedded newline; needs doubling */
    ret = string_cat(ret, &size, &ptr, s, cp-s+1);
    ret = string_cat(ret, &size, &ptr, US"\n", 1);
    s = cp+1;
    }
  /* last bit of header */

  ret = string_cat(ret, &size, &ptr, s, cp-s+1);	/* newline-sep list */
  }
while((h = h->next));

ret[ptr-1] = '\0';	/* overwrite last newline */
return ret;
}


/*************************************************
*        Set up removed header line(s)           *
*************************************************/

/* This function is called by the remove_header modifier.  The argument is
treated as a sequence of header names which are added to a colon separated
list, provided there isn't an identical one already there.

Argument:   string of header names
Returns:    nothing
*/

static void
setup_remove_header(uschar *hnames)
{
if (*hnames != 0)
  {
  if (acl_removed_headers == NULL)
    acl_removed_headers = hnames;
  else
    acl_removed_headers = string_sprintf("%s : %s", acl_removed_headers, hnames);
  }
}



/*************************************************
*               Handle warnings                  *
*************************************************/

/* This function is called when a WARN verb's conditions are true. It adds to
the message's headers, and/or writes information to the log. In each case, this
only happens once (per message for headers, per connection for log).

** NOTE: The header adding action using the "message" setting is historic, and
its use is now deprecated. The new add_header modifier should be used instead.

Arguments:
  where          ACL_WHERE_xxxx indicating which ACL this is
  user_message   message for adding to headers
  log_message    message for logging, if different

Returns:         nothing
*/

static void
acl_warn(int where, uschar *user_message, uschar *log_message)
{
if (log_message != NULL && log_message != user_message)
  {
  uschar *text;
  string_item *logged;

  text = string_sprintf("%s Warning: %s",  host_and_ident(TRUE),
    string_printing(log_message));

  /* If a sender verification has failed, and the log message is "sender verify
  failed", add the failure message. */

  if (sender_verified_failed != NULL &&
      sender_verified_failed->message != NULL &&
      strcmpic(log_message, US"sender verify failed") == 0)
    text = string_sprintf("%s: %s", text, sender_verified_failed->message);

  /* Search previously logged warnings. They are kept in malloc
  store so they can be freed at the start of a new message. */

  for (logged = acl_warn_logged; logged != NULL; logged = logged->next)
    if (Ustrcmp(logged->text, text) == 0) break;

  if (logged == NULL)
    {
    int length = Ustrlen(text) + 1;
    log_write(0, LOG_MAIN, "%s", text);
    logged = store_malloc(sizeof(string_item) + length);
    logged->text = (uschar *)logged + sizeof(string_item);
    memcpy(logged->text, text, length);
    logged->next = acl_warn_logged;
    acl_warn_logged = logged;
    }
  }

/* If there's no user message, we are done. */

if (user_message == NULL) return;

/* If this isn't a message ACL, we can't do anything with a user message.
Log an error. */

if (where > ACL_WHERE_NOTSMTP)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "ACL \"warn\" with \"message\" setting "
    "found in a non-message (%s) ACL: cannot specify header lines here: "
    "message ignored", acl_wherenames[where]);
  return;
  }

/* The code for setting up header lines is now abstracted into a separate
function so that it can be used for the add_header modifier as well. */

setup_header(user_message);
}



/*************************************************
*         Verify and check reverse DNS           *
*************************************************/

/* Called from acl_verify() below. We look up the host name(s) of the client IP
address if this has not yet been done. The host_name_lookup() function checks
that one of these names resolves to an address list that contains the client IP
address, so we don't actually have to do the check here.

Arguments:
  user_msgptr  pointer for user message
  log_msgptr   pointer for log message

Returns:       OK        verification condition succeeded
               FAIL      verification failed
               DEFER     there was a problem verifying
*/

static int
acl_verify_reverse(uschar **user_msgptr, uschar **log_msgptr)
{
int rc;

user_msgptr = user_msgptr;  /* stop compiler warning */

/* Previous success */

if (sender_host_name != NULL) return OK;

/* Previous failure */

if (host_lookup_failed)
  {
  *log_msgptr = string_sprintf("host lookup failed%s", host_lookup_msg);
  return FAIL;
  }

/* Need to do a lookup */

HDEBUG(D_acl)
  debug_printf("looking up host name to force name/address consistency check\n");

if ((rc = host_name_lookup()) != OK)
  {
  *log_msgptr = (rc == DEFER)?
    US"host lookup deferred for reverse lookup check"
    :
    string_sprintf("host lookup failed for reverse lookup check%s",
      host_lookup_msg);
  return rc;    /* DEFER or FAIL */
  }

host_build_sender_fullhost();
return OK;
}



/*************************************************
*   Check client IP address matches CSA target   *
*************************************************/

/* Called from acl_verify_csa() below. This routine scans a section of a DNS
response for address records belonging to the CSA target hostname. The section
is specified by the reset argument, either RESET_ADDITIONAL or RESET_ANSWERS.
If one of the addresses matches the client's IP address, then the client is
authorized by CSA. If there are target IP addresses but none of them match
then the client is using an unauthorized IP address. If there are no target IP
addresses then the client cannot be using an authorized IP address. (This is
an odd configuration - why didn't the SRV record have a weight of 1 instead?)

Arguments:
  dnsa       the DNS answer block
  dnss       a DNS scan block for us to use
  reset      option specifing what portion to scan, as described above
  target     the target hostname to use for matching RR names

Returns:     CSA_OK             successfully authorized
             CSA_FAIL_MISMATCH  addresses found but none matched
             CSA_FAIL_NOADDR    no target addresses found
*/

static int
acl_verify_csa_address(dns_answer *dnsa, dns_scan *dnss, int reset,
                       uschar *target)
{
dns_record *rr;
dns_address *da;

BOOL target_found = FALSE;

for (rr = dns_next_rr(dnsa, dnss, reset);
     rr != NULL;
     rr = dns_next_rr(dnsa, dnss, RESET_NEXT))
  {
  /* Check this is an address RR for the target hostname. */

  if (rr->type != T_A
    #if HAVE_IPV6
      && rr->type != T_AAAA
      #ifdef SUPPORT_A6
        && rr->type != T_A6
      #endif
    #endif
  ) continue;

  if (strcmpic(target, rr->name) != 0) continue;

  target_found = TRUE;

  /* Turn the target address RR into a list of textual IP addresses and scan
  the list. There may be more than one if it is an A6 RR. */

  for (da = dns_address_from_rr(dnsa, rr); da != NULL; da = da->next)
    {
    /* If the client IP address matches the target IP address, it's good! */

    DEBUG(D_acl) debug_printf("CSA target address is %s\n", da->address);

    if (strcmpic(sender_host_address, da->address) == 0) return CSA_OK;
    }
  }

/* If we found some target addresses but none of them matched, the client is
using an unauthorized IP address, otherwise the target has no authorized IP
addresses. */

if (target_found) return CSA_FAIL_MISMATCH;
else return CSA_FAIL_NOADDR;
}



/*************************************************
*       Verify Client SMTP Authorization         *
*************************************************/

/* Called from acl_verify() below. This routine calls dns_lookup_special()
to find the CSA SRV record corresponding to the domain argument, or
$sender_helo_name if no argument is provided. It then checks that the
client is authorized, and that its IP address corresponds to the SRV
target's address by calling acl_verify_csa_address() above. The address
should have been returned in the DNS response's ADDITIONAL section, but if
not we perform another DNS lookup to get it.

Arguments:
  domain    pointer to optional parameter following verify = csa

Returns:    CSA_UNKNOWN    no valid CSA record found
            CSA_OK         successfully authorized
            CSA_FAIL_*     client is definitely not authorized
            CSA_DEFER_*    there was a DNS problem
*/

static int
acl_verify_csa(uschar *domain)
{
tree_node *t;
uschar *found, *p;
int priority, weight, port;
dns_answer dnsa;
dns_scan dnss;
dns_record *rr;
int rc, type;
uschar target[256];

/* Work out the domain we are using for the CSA lookup. The default is the
client's HELO domain. If the client has not said HELO, use its IP address
instead. If it's a local client (exim -bs), CSA isn't applicable. */

while (isspace(*domain) && *domain != '\0') ++domain;
if (*domain == '\0') domain = sender_helo_name;
if (domain == NULL) domain = sender_host_address;
if (sender_host_address == NULL) return CSA_UNKNOWN;

/* If we have an address literal, strip off the framing ready for turning it
into a domain. The framing consists of matched square brackets possibly
containing a keyword and a colon before the actual IP address. */

if (domain[0] == '[')
  {
  uschar *start = Ustrchr(domain, ':');
  if (start == NULL) start = domain;
  domain = string_copyn(start + 1, Ustrlen(start) - 2);
  }

/* Turn domains that look like bare IP addresses into domains in the reverse
DNS. This code also deals with address literals and $sender_host_address. It's
not quite kosher to treat bare domains such as EHLO 192.0.2.57 the same as
address literals, but it's probably the most friendly thing to do. This is an
extension to CSA, so we allow it to be turned off for proper conformance. */

if (string_is_ip_address(domain, NULL) != 0)
  {
  if (!dns_csa_use_reverse) return CSA_UNKNOWN;
  dns_build_reverse(domain, target);
  domain = target;
  }

/* Find out if we've already done the CSA check for this domain. If we have,
return the same result again. Otherwise build a new cached result structure
for this domain. The name is filled in now, and the value is filled in when
we return from this function. */

t = tree_search(csa_cache, domain);
if (t != NULL) return t->data.val;

t = store_get_perm(sizeof(tree_node) + Ustrlen(domain));
Ustrcpy(t->name, domain);
(void)tree_insertnode(&csa_cache, t);

/* Now we are ready to do the actual DNS lookup(s). */

found = domain;
switch (dns_special_lookup(&dnsa, domain, T_CSA, &found))
  {
  /* If something bad happened (most commonly DNS_AGAIN), defer. */

  default:
  return t->data.val = CSA_DEFER_SRV;

  /* If we found nothing, the client's authorization is unknown. */

  case DNS_NOMATCH:
  case DNS_NODATA:
  return t->data.val = CSA_UNKNOWN;

  /* We got something! Go on to look at the reply in more detail. */

  case DNS_SUCCEED:
  break;
  }

/* Scan the reply for well-formed CSA SRV records. */

for (rr = dns_next_rr(&dnsa, &dnss, RESET_ANSWERS);
     rr != NULL;
     rr = dns_next_rr(&dnsa, &dnss, RESET_NEXT))
  {
  if (rr->type != T_SRV) continue;

  /* Extract the numerical SRV fields (p is incremented) */

  p = rr->data;
  GETSHORT(priority, p);
  GETSHORT(weight, p);
  GETSHORT(port, p);

  DEBUG(D_acl)
    debug_printf("CSA priority=%d weight=%d port=%d\n", priority, weight, port);

  /* Check the CSA version number */

  if (priority != 1) continue;

  /* If the domain does not have a CSA SRV record of its own (i.e. the domain
  found by dns_special_lookup() is a parent of the one we asked for), we check
  the subdomain assertions in the port field. At the moment there's only one
  assertion: legitimate SMTP clients are all explicitly authorized with CSA
  SRV records of their own. */

  if (found != domain)
    {
    if (port & 1)
      return t->data.val = CSA_FAIL_EXPLICIT;
    else
      return t->data.val = CSA_UNKNOWN;
    }

  /* This CSA SRV record refers directly to our domain, so we check the value
  in the weight field to work out the domain's authorization. 0 and 1 are
  unauthorized; 3 means the client is authorized but we can't check the IP
  address in order to authenticate it, so we treat it as unknown; values
  greater than 3 are undefined. */

  if (weight < 2) return t->data.val = CSA_FAIL_DOMAIN;

  if (weight > 2) continue;

  /* Weight == 2, which means the domain is authorized. We must check that the
  client's IP address is listed as one of the SRV target addresses. Save the
  target hostname then break to scan the additional data for its addresses. */

  (void)dn_expand(dnsa.answer, dnsa.answer + dnsa.answerlen, p,
    (DN_EXPAND_ARG4_TYPE)target, sizeof(target));

  DEBUG(D_acl) debug_printf("CSA target is %s\n", target);

  break;
  }

/* If we didn't break the loop then no appropriate records were found. */

if (rr == NULL) return t->data.val = CSA_UNKNOWN;

/* Do not check addresses if the target is ".", in accordance with RFC 2782.
A target of "." indicates there are no valid addresses, so the client cannot
be authorized. (This is an odd configuration because weight=2 target=. is
equivalent to weight=1, but we check for it in order to keep load off the
root name servers.) Note that dn_expand() turns "." into "". */

if (Ustrcmp(target, "") == 0) return t->data.val = CSA_FAIL_NOADDR;

/* Scan the additional section of the CSA SRV reply for addresses belonging
to the target. If the name server didn't return any additional data (e.g.
because it does not fully support SRV records), we need to do another lookup
to obtain the target addresses; otherwise we have a definitive result. */

rc = acl_verify_csa_address(&dnsa, &dnss, RESET_ADDITIONAL, target);
if (rc != CSA_FAIL_NOADDR) return t->data.val = rc;

/* The DNS lookup type corresponds to the IP version used by the client. */

#if HAVE_IPV6
if (Ustrchr(sender_host_address, ':') != NULL)
  type = T_AAAA;
else
#endif /* HAVE_IPV6 */
  type = T_A;


#if HAVE_IPV6 && defined(SUPPORT_A6)
DNS_LOOKUP_AGAIN:
#endif

switch (dns_lookup(&dnsa, target, type, NULL))
  {
  /* If something bad happened (most commonly DNS_AGAIN), defer. */

  default:
  return t->data.val = CSA_DEFER_ADDR;

  /* If the query succeeded, scan the addresses and return the result. */

  case DNS_SUCCEED:
  rc = acl_verify_csa_address(&dnsa, &dnss, RESET_ANSWERS, target);
  if (rc != CSA_FAIL_NOADDR) return t->data.val = rc;
  /* else fall through */

  /* If the target has no IP addresses, the client cannot have an authorized
  IP address. However, if the target site uses A6 records (not AAAA records)
  we have to do yet another lookup in order to check them. */

  case DNS_NOMATCH:
  case DNS_NODATA:

  #if HAVE_IPV6 && defined(SUPPORT_A6)
  if (type == T_AAAA) { type = T_A6; goto DNS_LOOKUP_AGAIN; }
  #endif

  return t->data.val = CSA_FAIL_NOADDR;
  }
}



/*************************************************
*     Handle verification (address & other)      *
*************************************************/

enum { VERIFY_REV_HOST_LKUP, VERIFY_CERT, VERIFY_HELO, VERIFY_CSA, VERIFY_HDR_SYNTAX,
  VERIFY_NOT_BLIND, VERIFY_HDR_SNDR, VERIFY_SNDR, VERIFY_RCPT
  };
typedef struct {
  uschar * name;
  int	   value;
  unsigned where_allowed;	/* bitmap */
  BOOL	   no_options;		/* Never has /option(s) following */
  unsigned alt_opt_sep;		/* >0 Non-/ option separator (custom parser) */
  } verify_type_t;
static verify_type_t verify_type_list[] = {
    { US"reverse_host_lookup",	VERIFY_REV_HOST_LKUP,	~0,	TRUE, 0 },
    { US"certificate",	  	VERIFY_CERT,	 	~0,	TRUE, 0 },
    { US"helo",	  		VERIFY_HELO,	 	~0,	TRUE, 0 },
    { US"csa",	  		VERIFY_CSA,	 	~0,	FALSE, 0 },
    { US"header_syntax",	VERIFY_HDR_SYNTAX,	(1<<ACL_WHERE_DATA)|(1<<ACL_WHERE_NOTSMTP), TRUE, 0 },
    { US"not_blind",	  	VERIFY_NOT_BLIND,	(1<<ACL_WHERE_DATA)|(1<<ACL_WHERE_NOTSMTP), TRUE, 0 },
    { US"header_sender",	VERIFY_HDR_SNDR,	(1<<ACL_WHERE_DATA)|(1<<ACL_WHERE_NOTSMTP), FALSE, 0 },
    { US"sender",	  	VERIFY_SNDR,		(1<<ACL_WHERE_MAIL)|(1<<ACL_WHERE_RCPT)
			|(1<<ACL_WHERE_PREDATA)|(1<<ACL_WHERE_DATA)|(1<<ACL_WHERE_NOTSMTP),
										FALSE, 6 },
    { US"recipient",	  	VERIFY_RCPT,	 	(1<<ACL_WHERE_RCPT),	FALSE, 0 }
  };


enum { CALLOUT_DEFER_OK, CALLOUT_NOCACHE, CALLOUT_RANDOM, CALLOUT_USE_SENDER,
  CALLOUT_USE_POSTMASTER, CALLOUT_POSTMASTER, CALLOUT_FULLPOSTMASTER,
  CALLOUT_MAILFROM, CALLOUT_POSTMASTER_MAILFROM, CALLOUT_MAXWAIT, CALLOUT_CONNECT,
  CALLOUT_TIME
  };
typedef struct {
  uschar * name;
  int      value;
  int	   flag;
  BOOL     has_option;	/* Has =option(s) following */
  BOOL     timeval;	/* Has a time value */
  } callout_opt_t;
static callout_opt_t callout_opt_list[] = {
    { US"defer_ok",   	  CALLOUT_DEFER_OK,	 0,				FALSE, FALSE },
    { US"no_cache",   	  CALLOUT_NOCACHE,	 vopt_callout_no_cache,		FALSE, FALSE },
    { US"random",	  CALLOUT_RANDOM,	 vopt_callout_random,		FALSE, FALSE },
    { US"use_sender",     CALLOUT_USE_SENDER,	 vopt_callout_recipsender,	FALSE, FALSE },
    { US"use_postmaster", CALLOUT_USE_POSTMASTER,vopt_callout_recippmaster,	FALSE, FALSE },
    { US"postmaster_mailfrom",CALLOUT_POSTMASTER_MAILFROM,0,			TRUE,  FALSE },
    { US"postmaster",	  CALLOUT_POSTMASTER,	 0,				FALSE, FALSE },
    { US"fullpostmaster", CALLOUT_FULLPOSTMASTER,vopt_callout_fullpm,		FALSE, FALSE },
    { US"mailfrom",	  CALLOUT_MAILFROM,	 0,				TRUE,  FALSE },
    { US"maxwait",	  CALLOUT_MAXWAIT,	 0,				TRUE,  TRUE },
    { US"connect",	  CALLOUT_CONNECT,	 0,				TRUE,  TRUE },
    { NULL,		  CALLOUT_TIME,		 0,				FALSE, TRUE }
  };



/* This function implements the "verify" condition. It is called when
encountered in any ACL, because some tests are almost always permitted. Some
just don't make sense, and always fail (for example, an attempt to test a host
lookup for a non-TCP/IP message). Others are restricted to certain ACLs.

Arguments:
  where        where called from
  addr         the recipient address that the ACL is handling, or NULL
  arg          the argument of "verify"
  user_msgptr  pointer for user message
  log_msgptr   pointer for log message
  basic_errno  where to put verify errno

Returns:       OK        verification condition succeeded
               FAIL      verification failed
               DEFER     there was a problem verifying
               ERROR     syntax error
*/

static int
acl_verify(int where, address_item *addr, uschar *arg,
  uschar **user_msgptr, uschar **log_msgptr, int *basic_errno)
{
int sep = '/';
int callout = -1;
int callout_overall = -1;
int callout_connect = -1;
int verify_options = 0;
int rc;
BOOL verify_header_sender = FALSE;
BOOL defer_ok = FALSE;
BOOL callout_defer_ok = FALSE;
BOOL no_details = FALSE;
BOOL success_on_redirect = FALSE;
address_item *sender_vaddr = NULL;
uschar *verify_sender_address = NULL;
uschar *pm_mailfrom = NULL;
uschar *se_mailfrom = NULL;

/* Some of the verify items have slash-separated options; some do not. Diagnose
an error if options are given for items that don't expect them.
*/

uschar *slash = Ustrchr(arg, '/');
uschar *list = arg;
uschar *ss = string_nextinlist(&list, &sep, big_buffer, big_buffer_size);
verify_type_t * vp;

if (ss == NULL) goto BAD_VERIFY;

/* Handle name/address consistency verification in a separate function. */

for (vp= verify_type_list;
     (char *)vp < (char *)verify_type_list + sizeof(verify_type_list);
     vp++
    )
  if (vp->alt_opt_sep ? strncmpic(ss, vp->name, vp->alt_opt_sep) == 0
                      : strcmpic (ss, vp->name) == 0)
   break;
if ((char *)vp >= (char *)verify_type_list + sizeof(verify_type_list))
  goto BAD_VERIFY;

if (vp->no_options && slash != NULL)
  {
  *log_msgptr = string_sprintf("unexpected '/' found in \"%s\" "
    "(this verify item has no options)", arg);
  return ERROR;
  }
if (!(vp->where_allowed & (1<<where)))
  {
  *log_msgptr = string_sprintf("cannot verify %s in ACL for %s", vp->name, acl_wherenames[where]);
  return ERROR;
  }
switch(vp->value)
  {
  case VERIFY_REV_HOST_LKUP:
    if (sender_host_address == NULL) return OK;
    return acl_verify_reverse(user_msgptr, log_msgptr);

  case VERIFY_CERT:
    /* TLS certificate verification is done at STARTTLS time; here we just
    test whether it was successful or not. (This is for optional verification; for
    mandatory verification, the connection doesn't last this long.) */

      if (tls_in.certificate_verified) return OK;
      *user_msgptr = US"no verified certificate";
      return FAIL;

  case VERIFY_HELO:
    /* We can test the result of optional HELO verification that might have
    occurred earlier. If not, we can attempt the verification now. */

      if (!helo_verified && !helo_verify_failed) smtp_verify_helo();
      return helo_verified? OK : FAIL;

  case VERIFY_CSA:
    /* Do Client SMTP Authorization checks in a separate function, and turn the
    result code into user-friendly strings. */

      rc = acl_verify_csa(list);
      *log_msgptr = *user_msgptr = string_sprintf("client SMTP authorization %s",
                                              csa_reason_string[rc]);
      csa_status = csa_status_string[rc];
      DEBUG(D_acl) debug_printf("CSA result %s\n", csa_status);
      return csa_return_code[rc];

  case VERIFY_HDR_SYNTAX:
    /* Check that all relevant header lines have the correct syntax. If there is
    a syntax error, we return details of the error to the sender if configured to
    send out full details. (But a "message" setting on the ACL can override, as
    always). */

    rc = verify_check_headers(log_msgptr);
    if (rc != OK && smtp_return_error_details && *log_msgptr != NULL)
      *user_msgptr = string_sprintf("Rejected after DATA: %s", *log_msgptr);
    return rc;

  case VERIFY_NOT_BLIND:
    /* Check that no recipient of this message is "blind", that is, every envelope
    recipient must be mentioned in either To: or Cc:. */

    rc = verify_check_notblind();
    if (rc != OK)
      {
      *log_msgptr = string_sprintf("bcc recipient detected");
      if (smtp_return_error_details)
        *user_msgptr = string_sprintf("Rejected after DATA: %s", *log_msgptr);
      }
    return rc;

  /* The remaining verification tests check recipient and sender addresses,
  either from the envelope or from the header. There are a number of
  slash-separated options that are common to all of them. */

  case VERIFY_HDR_SNDR:
    verify_header_sender = TRUE;
    break;

  case VERIFY_SNDR:
    /* In the case of a sender, this can optionally be followed by an address to use
    in place of the actual sender (rare special-case requirement). */
    {
    uschar *s = ss + 6;
    if (*s == 0)
      verify_sender_address = sender_address;
    else
      {
      while (isspace(*s)) s++;
      if (*s++ != '=') goto BAD_VERIFY;
      while (isspace(*s)) s++;
      verify_sender_address = string_copy(s);
      }
    }
    break;

  case VERIFY_RCPT:
    break;
  }



/* Remaining items are optional; they apply to sender and recipient
verification, including "header sender" verification. */

while ((ss = string_nextinlist(&list, &sep, big_buffer, big_buffer_size))
      != NULL)
  {
  if (strcmpic(ss, US"defer_ok") == 0) defer_ok = TRUE;
  else if (strcmpic(ss, US"no_details") == 0) no_details = TRUE;
  else if (strcmpic(ss, US"success_on_redirect") == 0) success_on_redirect = TRUE;

  /* These two old options are left for backwards compatibility */

  else if (strcmpic(ss, US"callout_defer_ok") == 0)
    {
    callout_defer_ok = TRUE;
    if (callout == -1) callout = CALLOUT_TIMEOUT_DEFAULT;
    }

  else if (strcmpic(ss, US"check_postmaster") == 0)
     {
     pm_mailfrom = US"";
     if (callout == -1) callout = CALLOUT_TIMEOUT_DEFAULT;
     }

  /* The callout option has a number of sub-options, comma separated */

  else if (strncmpic(ss, US"callout", 7) == 0)
    {
    callout = CALLOUT_TIMEOUT_DEFAULT;
    ss += 7;
    if (*ss != 0)
      {
      while (isspace(*ss)) ss++;
      if (*ss++ == '=')
        {
        int optsep = ',';
        uschar *opt;
        uschar buffer[256];
        while (isspace(*ss)) ss++;

        while ((opt = string_nextinlist(&ss, &optsep, buffer, sizeof(buffer)))
              != NULL)
          {
	  callout_opt_t * op;
	  double period = 1.0F;

	  for (op= callout_opt_list; op->name; op++)
	    if (strncmpic(opt, op->name, Ustrlen(op->name)) == 0)
	      break;

	  verify_options |= op->flag;
	  if (op->has_option)
	    {
	    opt += Ustrlen(op->name);
            while (isspace(*opt)) opt++;
            if (*opt++ != '=')
              {
              *log_msgptr = string_sprintf("'=' expected after "
                "\"%s\" in ACL verify condition \"%s\"", op->name, arg);
              return ERROR;
              }
            while (isspace(*opt)) opt++;
	    }
	  if (op->timeval)
	    {
            period = readconf_readtime(opt, 0, FALSE);
            if (period < 0)
              {
              *log_msgptr = string_sprintf("bad time value in ACL condition "
                "\"verify %s\"", arg);
              return ERROR;
              }
	    }

	  switch(op->value)
	    {
            case CALLOUT_DEFER_OK:		callout_defer_ok = TRUE; break;
            case CALLOUT_POSTMASTER:		pm_mailfrom = US"";	break;
            case CALLOUT_FULLPOSTMASTER:	pm_mailfrom = US"";	break;
            case CALLOUT_MAILFROM:
              if (!verify_header_sender)
                {
                *log_msgptr = string_sprintf("\"mailfrom\" is allowed as a "
                  "callout option only for verify=header_sender (detected in ACL "
                  "condition \"%s\")", arg);
                return ERROR;
                }
              se_mailfrom = string_copy(opt);
  	      break;
            case CALLOUT_POSTMASTER_MAILFROM:	pm_mailfrom = string_copy(opt); break;
            case CALLOUT_MAXWAIT:		callout_overall = period;	break;
            case CALLOUT_CONNECT:		callout_connect = period;	break;
            case CALLOUT_TIME:			callout = period;		break;
	    }
          }
        }
      else
        {
        *log_msgptr = string_sprintf("'=' expected after \"callout\" in "
          "ACL condition \"%s\"", arg);
        return ERROR;
        }
      }
    }

  /* Option not recognized */

  else
    {
    *log_msgptr = string_sprintf("unknown option \"%s\" in ACL "
      "condition \"verify %s\"", ss, arg);
    return ERROR;
    }
  }

if ((verify_options & (vopt_callout_recipsender|vopt_callout_recippmaster)) ==
      (vopt_callout_recipsender|vopt_callout_recippmaster))
  {
  *log_msgptr = US"only one of use_sender and use_postmaster can be set "
    "for a recipient callout";
  return ERROR;
  }

/* Handle sender-in-header verification. Default the user message to the log
message if giving out verification details. */

if (verify_header_sender)
  {
  int verrno;
  rc = verify_check_header_address(user_msgptr, log_msgptr, callout,
    callout_overall, callout_connect, se_mailfrom, pm_mailfrom, verify_options,
    &verrno);
  if (rc != OK)
    {
    *basic_errno = verrno;
    if (smtp_return_error_details)
      {
      if (*user_msgptr == NULL && *log_msgptr != NULL)
        *user_msgptr = string_sprintf("Rejected after DATA: %s", *log_msgptr);
      if (rc == DEFER) acl_temp_details = TRUE;
      }
    }
  }

/* Handle a sender address. The default is to verify *the* sender address, but
optionally a different address can be given, for special requirements. If the
address is empty, we are dealing with a bounce message that has no sender, so
we cannot do any checking. If the real sender address gets rewritten during
verification (e.g. DNS widening), set the flag to stop it being rewritten again
during message reception.

A list of verified "sender" addresses is kept to try to avoid doing to much
work repetitively when there are multiple recipients in a message and they all
require sender verification. However, when callouts are involved, it gets too
complicated because different recipients may require different callout options.
Therefore, we always do a full sender verify when any kind of callout is
specified. Caching elsewhere, for instance in the DNS resolver and in the
callout handling, should ensure that this is not terribly inefficient. */

else if (verify_sender_address != NULL)
  {
  if ((verify_options & (vopt_callout_recipsender|vopt_callout_recippmaster))
       != 0)
    {
    *log_msgptr = US"use_sender or use_postmaster cannot be used for a "
      "sender verify callout";
    return ERROR;
    }

  sender_vaddr = verify_checked_sender(verify_sender_address);
  if (sender_vaddr != NULL &&               /* Previously checked */
      callout <= 0)                         /* No callout needed this time */
    {
    /* If the "routed" flag is set, it means that routing worked before, so
    this check can give OK (the saved return code value, if set, belongs to a
    callout that was done previously). If the "routed" flag is not set, routing
    must have failed, so we use the saved return code. */

    if (testflag(sender_vaddr, af_verify_routed)) rc = OK; else
      {
      rc = sender_vaddr->special_action;
      *basic_errno = sender_vaddr->basic_errno;
      }
    HDEBUG(D_acl) debug_printf("using cached sender verify result\n");
    }

  /* Do a new verification, and cache the result. The cache is used to avoid
  verifying the sender multiple times for multiple RCPTs when callouts are not
  specified (see comments above).

  The cache is also used on failure to give details in response to the first
  RCPT that gets bounced for this reason. However, this can be suppressed by
  the no_details option, which sets the flag that says "this detail has already
  been sent". The cache normally contains just one address, but there may be
  more in esoteric circumstances. */

  else
    {
    BOOL routed = TRUE;
    uschar *save_address_data = deliver_address_data;

    sender_vaddr = deliver_make_addr(verify_sender_address, TRUE);
    if (no_details) setflag(sender_vaddr, af_sverify_told);
    if (verify_sender_address[0] != 0)
      {
      /* If this is the real sender address, save the unrewritten version
      for use later in receive. Otherwise, set a flag so that rewriting the
      sender in verify_address() does not update sender_address. */

      if (verify_sender_address == sender_address)
        sender_address_unrewritten = sender_address;
      else
        verify_options |= vopt_fake_sender;

      if (success_on_redirect)
        verify_options |= vopt_success_on_redirect;

      /* The recipient, qualify, and expn options are never set in
      verify_options. */

      rc = verify_address(sender_vaddr, NULL, verify_options, callout,
        callout_overall, callout_connect, se_mailfrom, pm_mailfrom, &routed);

      HDEBUG(D_acl) debug_printf("----------- end verify ------------\n");

      if (rc == OK)
        {
        if (Ustrcmp(sender_vaddr->address, verify_sender_address) != 0)
          {
          DEBUG(D_acl) debug_printf("sender %s verified ok as %s\n",
            verify_sender_address, sender_vaddr->address);
          }
        else
          {
          DEBUG(D_acl) debug_printf("sender %s verified ok\n",
            verify_sender_address);
          }
        }
      else *basic_errno = sender_vaddr->basic_errno;
      }
    else rc = OK;  /* Null sender */

    /* Cache the result code */

    if (routed) setflag(sender_vaddr, af_verify_routed);
    if (callout > 0) setflag(sender_vaddr, af_verify_callout);
    sender_vaddr->special_action = rc;
    sender_vaddr->next = sender_verified_list;
    sender_verified_list = sender_vaddr;

    /* Restore the recipient address data, which might have been clobbered by
    the sender verification. */

    deliver_address_data = save_address_data;
    }

  /* Put the sender address_data value into $sender_address_data */

  sender_address_data = sender_vaddr->p.address_data;
  }

/* A recipient address just gets a straightforward verify; again we must handle
the DEFER overrides. */

else
  {
  address_item addr2;

  if (success_on_redirect)
    verify_options |= vopt_success_on_redirect;

  /* We must use a copy of the address for verification, because it might
  get rewritten. */

  addr2 = *addr;
  rc = verify_address(&addr2, NULL, verify_options|vopt_is_recipient, callout,
    callout_overall, callout_connect, se_mailfrom, pm_mailfrom, NULL);
  HDEBUG(D_acl) debug_printf("----------- end verify ------------\n");

  *basic_errno = addr2.basic_errno;
  *log_msgptr = addr2.message;
  *user_msgptr = (addr2.user_message != NULL)?
    addr2.user_message : addr2.message;

  /* Allow details for temporary error if the address is so flagged. */
  if (testflag((&addr2), af_pass_message)) acl_temp_details = TRUE;

  /* Make $address_data visible */
  deliver_address_data = addr2.p.address_data;
  }

/* We have a result from the relevant test. Handle defer overrides first. */

if (rc == DEFER && (defer_ok ||
   (callout_defer_ok && *basic_errno == ERRNO_CALLOUTDEFER)))
  {
  HDEBUG(D_acl) debug_printf("verify defer overridden by %s\n",
    defer_ok? "defer_ok" : "callout_defer_ok");
  rc = OK;
  }

/* If we've failed a sender, set up a recipient message, and point
sender_verified_failed to the address item that actually failed. */

if (rc != OK && verify_sender_address != NULL)
  {
  if (rc != DEFER)
    {
    *log_msgptr = *user_msgptr = US"Sender verify failed";
    }
  else if (*basic_errno != ERRNO_CALLOUTDEFER)
    {
    *log_msgptr = *user_msgptr = US"Could not complete sender verify";
    }
  else
    {
    *log_msgptr = US"Could not complete sender verify callout";
    *user_msgptr = smtp_return_error_details? sender_vaddr->user_message :
      *log_msgptr;
    }

  sender_verified_failed = sender_vaddr;
  }

/* Verifying an address messes up the values of $domain and $local_part,
so reset them before returning if this is a RCPT ACL. */

if (addr != NULL)
  {
  deliver_domain = addr->domain;
  deliver_localpart = addr->local_part;
  }
return rc;

/* Syntax errors in the verify argument come here. */

BAD_VERIFY:
*log_msgptr = string_sprintf("expected \"sender[=address]\", \"recipient\", "
  "\"helo\", \"header_syntax\", \"header_sender\" or "
  "\"reverse_host_lookup\" at start of ACL condition "
  "\"verify %s\"", arg);
return ERROR;
}




/*************************************************
*        Check argument for control= modifier    *
*************************************************/

/* Called from acl_check_condition() below

Arguments:
  arg         the argument string for control=
  pptr        set to point to the terminating character
  where       which ACL we are in
  log_msgptr  for error messages

Returns:      CONTROL_xxx value
*/

static int
decode_control(uschar *arg, uschar **pptr, int where, uschar **log_msgptr)
{
int len;
control_def *d;

for (d = controls_list;
     d < controls_list + sizeof(controls_list)/sizeof(control_def);
     d++)
  {
  len = Ustrlen(d->name);
  if (Ustrncmp(d->name, arg, len) == 0) break;
  }

if (d >= controls_list + sizeof(controls_list)/sizeof(control_def) ||
   (arg[len] != 0 && (!d->has_option || arg[len] != '/')))
  {
  *log_msgptr = string_sprintf("syntax error in \"control=%s\"", arg);
  return CONTROL_ERROR;
  }

*pptr = arg + len;
return d->value;
}




/*************************************************
*        Return a ratelimit error                *
*************************************************/

/* Called from acl_ratelimit() below

Arguments:
  log_msgptr  for error messages
  format      format string
  ...         supplementary arguments
  ss          ratelimit option name
  where       ACL_WHERE_xxxx indicating which ACL this is

Returns:      ERROR
*/

static int
ratelimit_error(uschar **log_msgptr, const char *format, ...)
{
va_list ap;
uschar buffer[STRING_SPRINTF_BUFFER_SIZE];
va_start(ap, format);
if (!string_vformat(buffer, sizeof(buffer), format, ap))
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "string_sprintf expansion was longer than " SIZE_T_FMT, sizeof(buffer));
va_end(ap);
*log_msgptr = string_sprintf(
  "error in arguments to \"ratelimit\" condition: %s", buffer);
return ERROR;
}




/*************************************************
*            Handle rate limiting                *
*************************************************/

/* Called by acl_check_condition() below to calculate the result
of the ACL ratelimit condition.

Note that the return value might be slightly unexpected: if the
sender's rate is above the limit then the result is OK. This is
similar to the dnslists condition, and is so that you can write
ACL clauses like: defer ratelimit = 15 / 1h

Arguments:
  arg         the option string for ratelimit=
  where       ACL_WHERE_xxxx indicating which ACL this is
  log_msgptr  for error messages

Returns:       OK        - Sender's rate is above limit
               FAIL      - Sender's rate is below limit
               DEFER     - Problem opening ratelimit database
               ERROR     - Syntax error in options.
*/

static int
acl_ratelimit(uschar *arg, int where, uschar **log_msgptr)
{
double limit, period, count;
uschar *ss;
uschar *key = NULL;
uschar *unique = NULL;
int sep = '/';
BOOL leaky = FALSE, strict = FALSE, readonly = FALSE;
BOOL noupdate = FALSE, badacl = FALSE;
int mode = RATE_PER_WHAT;
int old_pool, rc;
tree_node **anchor, *t;
open_db dbblock, *dbm;
int dbdb_size;
dbdata_ratelimit *dbd;
dbdata_ratelimit_unique *dbdb;
struct timeval tv;

/* Parse the first two options and record their values in expansion
variables. These variables allow the configuration to have informative
error messages based on rate limits obtained from a table lookup. */

/* First is the maximum number of messages per period / maximum burst
size, which must be greater than or equal to zero. Zero is useful for
rate measurement as opposed to rate limiting. */

sender_rate_limit = string_nextinlist(&arg, &sep, NULL, 0);
if (sender_rate_limit == NULL)
  limit = -1.0;
else
  {
  limit = Ustrtod(sender_rate_limit, &ss);
  if (tolower(*ss) == 'k') { limit *= 1024.0; ss++; }
  else if (tolower(*ss) == 'm') { limit *= 1024.0*1024.0; ss++; }
  else if (tolower(*ss) == 'g') { limit *= 1024.0*1024.0*1024.0; ss++; }
  }
if (limit < 0.0 || *ss != '\0')
  return ratelimit_error(log_msgptr,
    "\"%s\" is not a positive number", sender_rate_limit);

/* Second is the rate measurement period / exponential smoothing time
constant. This must be strictly greater than zero, because zero leads to
run-time division errors. */

sender_rate_period = string_nextinlist(&arg, &sep, NULL, 0);
if (sender_rate_period == NULL) period = -1.0;
else period = readconf_readtime(sender_rate_period, 0, FALSE);
if (period <= 0.0)
  return ratelimit_error(log_msgptr,
    "\"%s\" is not a time value", sender_rate_period);

/* By default we are counting one of something, but the per_rcpt,
per_byte, and count options can change this. */

count = 1.0;

/* Parse the other options. */

while ((ss = string_nextinlist(&arg, &sep, big_buffer, big_buffer_size))
       != NULL)
  {
  if (strcmpic(ss, US"leaky") == 0) leaky = TRUE;
  else if (strcmpic(ss, US"strict") == 0) strict = TRUE;
  else if (strcmpic(ss, US"noupdate") == 0) noupdate = TRUE;
  else if (strcmpic(ss, US"readonly") == 0) readonly = TRUE;
  else if (strcmpic(ss, US"per_cmd") == 0) RATE_SET(mode, PER_CMD);
  else if (strcmpic(ss, US"per_conn") == 0)
    {
    RATE_SET(mode, PER_CONN);
    if (where == ACL_WHERE_NOTSMTP || where == ACL_WHERE_NOTSMTP_START)
      badacl = TRUE;
    }
  else if (strcmpic(ss, US"per_mail") == 0)
    {
    RATE_SET(mode, PER_MAIL);
    if (where > ACL_WHERE_NOTSMTP) badacl = TRUE;
    }
  else if (strcmpic(ss, US"per_rcpt") == 0)
    {
    /* If we are running in the RCPT ACL, then we'll count the recipients
    one by one, but if we are running when we have accumulated the whole
    list then we'll add them all in one batch. */
    if (where == ACL_WHERE_RCPT)
      RATE_SET(mode, PER_RCPT);
    else if (where >= ACL_WHERE_PREDATA && where <= ACL_WHERE_NOTSMTP)
      RATE_SET(mode, PER_ALLRCPTS), count = (double)recipients_count;
    else if (where == ACL_WHERE_MAIL || where > ACL_WHERE_NOTSMTP)
      RATE_SET(mode, PER_RCPT), badacl = TRUE;
    }
  else if (strcmpic(ss, US"per_byte") == 0)
    {
    /* If we have not yet received the message data and there was no SIZE
    declaration on the MAIL comand, then it's safe to just use a value of
    zero and let the recorded rate decay as if nothing happened. */
    RATE_SET(mode, PER_MAIL);
    if (where > ACL_WHERE_NOTSMTP) badacl = TRUE;
      else count = message_size < 0 ? 0.0 : (double)message_size;
    }
  else if (strcmpic(ss, US"per_addr") == 0)
    {
    RATE_SET(mode, PER_RCPT);
    if (where != ACL_WHERE_RCPT) badacl = TRUE, unique = US"*";
      else unique = string_sprintf("%s@%s", deliver_localpart, deliver_domain);
    }
  else if (strncmpic(ss, US"count=", 6) == 0)
    {
    uschar *e;
    count = Ustrtod(ss+6, &e);
    if (count < 0.0 || *e != '\0')
      return ratelimit_error(log_msgptr,
	"\"%s\" is not a positive number", ss);
    }
  else if (strncmpic(ss, US"unique=", 7) == 0)
    unique = string_copy(ss + 7);
  else if (key == NULL)
    key = string_copy(ss);
  else
    key = string_sprintf("%s/%s", key, ss);
  }

/* Sanity check. When the badacl flag is set the update mode must either
be readonly (which is the default if it is omitted) or, for backwards
compatibility, a combination of noupdate and strict or leaky. */

if (mode == RATE_PER_CLASH)
  return ratelimit_error(log_msgptr, "conflicting per_* options");
if (leaky + strict + readonly > 1)
  return ratelimit_error(log_msgptr, "conflicting update modes");
if (badacl && (leaky || strict) && !noupdate)
  return ratelimit_error(log_msgptr,
    "\"%s\" must not have /leaky or /strict option in %s ACL",
    ratelimit_option_string[mode], acl_wherenames[where]);

/* Set the default values of any unset options. In readonly mode we
perform the rate computation without any increment so that its value
decays to eventually allow over-limit senders through. */

if (noupdate) readonly = TRUE, leaky = strict = FALSE;
if (badacl) readonly = TRUE;
if (readonly) count = 0.0;
if (!strict && !readonly) leaky = TRUE;
if (mode == RATE_PER_WHAT) mode = RATE_PER_MAIL;

/* Create the lookup key. If there is no explicit key, use sender_host_address.
If there is no sender_host_address (e.g. -bs or acl_not_smtp) then we simply
omit it. The smoothing constant (sender_rate_period) and the per_xxx options
are added to the key because they alter the meaning of the stored data. */

if (key == NULL)
  key = (sender_host_address == NULL)? US"" : sender_host_address;

key = string_sprintf("%s/%s/%s%s",
  sender_rate_period,
  ratelimit_option_string[mode],
  unique == NULL ? "" : "unique/",
  key);

HDEBUG(D_acl)
  debug_printf("ratelimit condition count=%.0f %.1f/%s\n", count, limit, key);

/* See if we have already computed the rate by looking in the relevant tree.
For per-connection rate limiting, store tree nodes and dbdata in the permanent
pool so that they survive across resets. In readonly mode we only remember the
result for the rest of this command in case a later command changes it. After
this bit of logic the code is independent of the per_* mode. */

old_pool = store_pool;

if (readonly)
  anchor = &ratelimiters_cmd;
else switch(mode) {
case RATE_PER_CONN:
  anchor = &ratelimiters_conn;
  store_pool = POOL_PERM;
  break;
case RATE_PER_BYTE:
case RATE_PER_MAIL:
case RATE_PER_ALLRCPTS:
  anchor = &ratelimiters_mail;
  break;
case RATE_PER_ADDR:
case RATE_PER_CMD:
case RATE_PER_RCPT:
  anchor = &ratelimiters_cmd;
  break;
default:
  anchor = NULL; /* silence an "unused" complaint */
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "internal ACL error: unknown ratelimit mode %d", mode);
  break;
}

t = tree_search(*anchor, key);
if (t != NULL)
  {
  dbd = t->data.ptr;
  /* The following few lines duplicate some of the code below. */
  rc = (dbd->rate < limit)? FAIL : OK;
  store_pool = old_pool;
  sender_rate = string_sprintf("%.1f", dbd->rate);
  HDEBUG(D_acl)
    debug_printf("ratelimit found pre-computed rate %s\n", sender_rate);
  return rc;
  }

/* We aren't using a pre-computed rate, so get a previously recorded rate
from the database, which will be updated and written back if required. */

dbm = dbfn_open(US"ratelimit", O_RDWR, &dbblock, TRUE);
if (dbm == NULL)
  {
  store_pool = old_pool;
  sender_rate = NULL;
  HDEBUG(D_acl) debug_printf("ratelimit database not available\n");
  *log_msgptr = US"ratelimit database not available";
  return DEFER;
  }
dbdb = dbfn_read_with_length(dbm, key, &dbdb_size);
dbd = NULL;

gettimeofday(&tv, NULL);

if (dbdb != NULL)
  {
  /* Locate the basic ratelimit block inside the DB data. */
  HDEBUG(D_acl) debug_printf("ratelimit found key in database\n");
  dbd = &dbdb->dbd;

  /* Forget the old Bloom filter if it is too old, so that we count each
  repeating event once per period. We don't simply clear and re-use the old
  filter because we want its size to change if the limit changes. Note that
  we keep the dbd pointer for copying the rate into the new data block. */

  if(unique != NULL && tv.tv_sec > dbdb->bloom_epoch + period)
    {
    HDEBUG(D_acl) debug_printf("ratelimit discarding old Bloom filter\n");
    dbdb = NULL;
    }

  /* Sanity check. */

  if(unique != NULL && dbdb_size < sizeof(*dbdb))
    {
    HDEBUG(D_acl) debug_printf("ratelimit discarding undersize Bloom filter\n");
    dbdb = NULL;
    }
  }

/* Allocate a new data block if the database lookup failed
or the Bloom filter passed its age limit. */

if (dbdb == NULL)
  {
  if (unique == NULL)
    {
    /* No Bloom filter. This basic ratelimit block is initialized below. */
    HDEBUG(D_acl) debug_printf("ratelimit creating new rate data block\n");
    dbdb_size = sizeof(*dbd);
    dbdb = store_get(dbdb_size);
    }
  else
    {
    int extra;
    HDEBUG(D_acl) debug_printf("ratelimit creating new Bloom filter\n");

    /* See the long comment below for an explanation of the magic number 2.
    The filter has a minimum size in case the rate limit is very small;
    this is determined by the definition of dbdata_ratelimit_unique. */

    extra = (int)limit * 2 - sizeof(dbdb->bloom);
    if (extra < 0) extra = 0;
    dbdb_size = sizeof(*dbdb) + extra;
    dbdb = store_get(dbdb_size);
    dbdb->bloom_epoch = tv.tv_sec;
    dbdb->bloom_size = sizeof(dbdb->bloom) + extra;
    memset(dbdb->bloom, 0, dbdb->bloom_size);

    /* Preserve any basic ratelimit data (which is our longer-term memory)
    by copying it from the discarded block. */

    if (dbd != NULL)
      {
      dbdb->dbd = *dbd;
      dbd = &dbdb->dbd;
      }
    }
  }

/* If we are counting unique events, find out if this event is new or not.
If the client repeats the event during the current period then it should be
counted. We skip this code in readonly mode for efficiency, because any
changes to the filter will be discarded and because count is already set to
zero. */

if (unique != NULL && !readonly)
  {
  /* We identify unique events using a Bloom filter. (You can find my
  notes on Bloom filters at http://fanf.livejournal.com/81696.html)
  With the per_addr option, an "event" is a recipient address, though the
  user can use the unique option to define their own events. We only count
  an event if we have not seen it before.

  We size the filter according to the rate limit, which (in leaky mode)
  is the limit on the population of the filter. We allow 16 bits of space
  per entry (see the construction code above) and we set (up to) 8 of them
  when inserting an element (see the loop below). The probability of a false
  positive (an event we have not seen before but which we fail to count) is

    size    = limit * 16
    numhash = 8
    allzero = exp(-numhash * pop / size)
            = exp(-0.5 * pop / limit)
    fpr     = pow(1 - allzero, numhash)

  For senders at the limit the fpr is      0.06%    or  1 in 1700
  and for senders at half the limit it is  0.0006%  or  1 in 170000

  In strict mode the Bloom filter can fill up beyond the normal limit, in
  which case the false positive rate will rise. This means that the
  measured rate for very fast senders can bogusly drop off after a while.

  At twice the limit, the fpr is  2.5%  or  1 in 40
  At four times the limit, it is  31%   or  1 in 3.2

  It takes ln(pop/limit) periods for an over-limit burst of pop events to
  decay below the limit, and if this is more than one then the Bloom filter
  will be discarded before the decay gets that far. The false positive rate
  at this threshold is 9.3% or 1 in 10.7. */

  BOOL seen;
  unsigned n, hash, hinc;
  uschar md5sum[16];
  md5 md5info;

  /* Instead of using eight independent hash values, we combine two values
  using the formula h1 + n * h2. This does not harm the Bloom filter's
  performance, and means the amount of hash we need is independent of the
  number of bits we set in the filter. */

  md5_start(&md5info);
  md5_end(&md5info, unique, Ustrlen(unique), md5sum);
  hash = md5sum[0] | md5sum[1] << 8 | md5sum[2] << 16 | md5sum[3] << 24;
  hinc = md5sum[4] | md5sum[5] << 8 | md5sum[6] << 16 | md5sum[7] << 24;

  /* Scan the bits corresponding to this event. A zero bit means we have
  not seen it before. Ensure all bits are set to record this event. */

  HDEBUG(D_acl) debug_printf("ratelimit checking uniqueness of %s\n", unique);

  seen = TRUE;
  for (n = 0; n < 8; n++, hash += hinc)
    {
    int bit = 1 << (hash % 8);
    int byte = (hash / 8) % dbdb->bloom_size;
    if ((dbdb->bloom[byte] & bit) == 0)
      {
      dbdb->bloom[byte] |= bit;
      seen = FALSE;
      }
    }

  /* If this event has occurred before, do not count it. */

  if (seen)
    {
    HDEBUG(D_acl) debug_printf("ratelimit event found in Bloom filter\n");
    count = 0.0;
    }
  else
    HDEBUG(D_acl) debug_printf("ratelimit event added to Bloom filter\n");
  }

/* If there was no previous ratelimit data block for this key, initialize
the new one, otherwise update the block from the database. The initial rate
is what would be computed by the code below for an infinite interval. */

if (dbd == NULL)
  {
  HDEBUG(D_acl) debug_printf("ratelimit initializing new key's rate data\n");
  dbd = &dbdb->dbd;
  dbd->time_stamp = tv.tv_sec;
  dbd->time_usec = tv.tv_usec;
  dbd->rate = count;
  }
else
  {
  /* The smoothed rate is computed using an exponentially weighted moving
  average adjusted for variable sampling intervals. The standard EWMA for
  a fixed sampling interval is:  f'(t) = (1 - a) * f(t) + a * f'(t - 1)
  where f() is the measured value and f'() is the smoothed value.

  Old data decays out of the smoothed value exponentially, such that data n
  samples old is multiplied by a^n. The exponential decay time constant p
  is defined such that data p samples old is multiplied by 1/e, which means
  that a = exp(-1/p). We can maintain the same time constant for a variable
  sampling interval i by using a = exp(-i/p).

  The rate we are measuring is messages per period, suitable for directly
  comparing with the limit. The average rate between now and the previous
  message is period / interval, which we feed into the EWMA as the sample.

  It turns out that the number of messages required for the smoothed rate
  to reach the limit when they are sent in a burst is equal to the limit.
  This can be seen by analysing the value of the smoothed rate after N
  messages sent at even intervals. Let k = (1 - a) * p/i

    rate_1 = (1 - a) * p/i + a * rate_0
           = k + a * rate_0
    rate_2 = k + a * rate_1
           = k + a * k + a^2 * rate_0
    rate_3 = k + a * k + a^2 * k + a^3 * rate_0
    rate_N = rate_0 * a^N + k * SUM(x=0..N-1)(a^x)
           = rate_0 * a^N + k * (1 - a^N) / (1 - a)
           = rate_0 * a^N + p/i * (1 - a^N)

  When N is large, a^N -> 0 so rate_N -> p/i as desired.

    rate_N = p/i + (rate_0 - p/i) * a^N
    a^N = (rate_N - p/i) / (rate_0 - p/i)
    N * -i/p = log((rate_N - p/i) / (rate_0 - p/i))
    N = p/i * log((rate_0 - p/i) / (rate_N - p/i))

  Numerical analysis of the above equation, setting the computed rate to
  increase from rate_0 = 0 to rate_N = limit, shows that for large sending
  rates, p/i, the number of messages N = limit. So limit serves as both the
  maximum rate measured in messages per period, and the maximum number of
  messages that can be sent in a fast burst. */

  double this_time = (double)tv.tv_sec
                   + (double)tv.tv_usec / 1000000.0;
  double prev_time = (double)dbd->time_stamp
                   + (double)dbd->time_usec / 1000000.0;

  /* We must avoid division by zero, and deal gracefully with the clock going
  backwards. If we blunder ahead when time is in reverse then the computed
  rate will be bogus. To be safe we clamp interval to a very small number. */

  double interval = this_time - prev_time <= 0.0 ? 1e-9
                  : this_time - prev_time;

  double i_over_p = interval / period;
  double a = exp(-i_over_p);

  /* Combine the instantaneous rate (period / interval) with the previous rate
  using the smoothing factor a. In order to measure sized events, multiply the
  instantaneous rate by the count of bytes or recipients etc. */

  dbd->time_stamp = tv.tv_sec;
  dbd->time_usec = tv.tv_usec;
  dbd->rate = (1 - a) * count / i_over_p + a * dbd->rate;

  /* When events are very widely spaced the computed rate tends towards zero.
  Although this is accurate it turns out not to be useful for our purposes,
  especially when the first event after a long silence is the start of a spam
  run. A more useful model is that the rate for an isolated event should be the
  size of the event per the period size, ignoring the lack of events outside
  the current period and regardless of where the event falls in the period. So,
  if the interval was so long that the calculated rate is unhelpfully small, we
  re-intialize the rate. In the absence of higher-rate bursts, the condition
  below is true if the interval is greater than the period. */

  if (dbd->rate < count) dbd->rate = count;
  }

/* Clients sending at the limit are considered to be over the limit.
This matters for edge cases such as a limit of zero, when the client
should be completely blocked. */

rc = (dbd->rate < limit)? FAIL : OK;

/* Update the state if the rate is low or if we are being strict. If we
are in leaky mode and the sender's rate is too high, we do not update
the recorded rate in order to avoid an over-aggressive sender's retry
rate preventing them from getting any email through. If readonly is set,
neither leaky nor strict are set, so we do not do any updates. */

if ((rc == FAIL && leaky) || strict)
  {
  dbfn_write(dbm, key, dbdb, dbdb_size);
  HDEBUG(D_acl) debug_printf("ratelimit db updated\n");
  }
else
  {
  HDEBUG(D_acl) debug_printf("ratelimit db not updated: %s\n",
    readonly? "readonly mode" : "over the limit, but leaky");
  }

dbfn_close(dbm);

/* Store the result in the tree for future reference. */

t = store_get(sizeof(tree_node) + Ustrlen(key));
t->data.ptr = dbd;
Ustrcpy(t->name, key);
(void)tree_insertnode(anchor, t);

/* We create the formatted version of the sender's rate very late in
order to ensure that it is done using the correct storage pool. */

store_pool = old_pool;
sender_rate = string_sprintf("%.1f", dbd->rate);

HDEBUG(D_acl)
  debug_printf("ratelimit computed rate %s\n", sender_rate);

return rc;
}



/*************************************************
*   Handle conditions/modifiers on an ACL item   *
*************************************************/

/* Called from acl_check() below.

Arguments:
  verb         ACL verb
  cb           ACL condition block - if NULL, result is OK
  where        where called from
  addr         the address being checked for RCPT, or NULL
  level        the nesting level
  epp          pointer to pass back TRUE if "endpass" encountered
                 (applies only to "accept" and "discard")
  user_msgptr  user message pointer
  log_msgptr   log message pointer
  basic_errno  pointer to where to put verify error

Returns:       OK        - all conditions are met
               DISCARD   - an "acl" condition returned DISCARD - only allowed
                             for "accept" or "discard" verbs
               FAIL      - at least one condition fails
               FAIL_DROP - an "acl" condition returned FAIL_DROP
               DEFER     - can't tell at the moment (typically, lookup defer,
                             but can be temporary callout problem)
               ERROR     - ERROR from nested ACL or expansion failure or other
                             error
*/

static int
acl_check_condition(int verb, acl_condition_block *cb, int where,
  address_item *addr, int level, BOOL *epp, uschar **user_msgptr,
  uschar **log_msgptr, int *basic_errno)
{
uschar *user_message = NULL;
uschar *log_message = NULL;
uschar *debug_tag = NULL;
uschar *debug_opts = NULL;
uschar *p = NULL;
int rc = OK;
#ifdef WITH_CONTENT_SCAN
int sep = '/';
#endif

for (; cb != NULL; cb = cb->next)
  {
  uschar *arg;
  int control_type;

  /* The message and log_message items set up messages to be used in
  case of rejection. They are expanded later. */

  if (cb->type == ACLC_MESSAGE)
    {
    user_message = cb->arg;
    continue;
    }

  if (cb->type == ACLC_LOG_MESSAGE)
    {
    log_message = cb->arg;
    continue;
    }

  /* The endpass "condition" just sets a flag to show it occurred. This is
  checked at compile time to be on an "accept" or "discard" item. */

  if (cb->type == ACLC_ENDPASS)
    {
    *epp = TRUE;
    continue;
    }

  /* For other conditions and modifiers, the argument is expanded now for some
  of them, but not for all, because expansion happens down in some lower level
  checking functions in some cases. */

  if (cond_expand_at_top[cb->type])
    {
    arg = expand_string(cb->arg);
    if (arg == NULL)
      {
      if (expand_string_forcedfail) continue;
      *log_msgptr = string_sprintf("failed to expand ACL string \"%s\": %s",
        cb->arg, expand_string_message);
      return search_find_defer? DEFER : ERROR;
      }
    }
  else arg = cb->arg;

  /* Show condition, and expanded condition if it's different */

  HDEBUG(D_acl)
    {
    int lhswidth = 0;
    debug_printf("check %s%s %n",
      (!cond_modifiers[cb->type] && cb->u.negated)? "!":"",
      conditions[cb->type], &lhswidth);

    if (cb->type == ACLC_SET)
      {
      debug_printf("acl_%s ", cb->u.varname);
      lhswidth += 5 + Ustrlen(cb->u.varname);
      }

    debug_printf("= %s\n", cb->arg);

    if (arg != cb->arg)
      debug_printf("%.*s= %s\n", lhswidth,
      US"                             ", CS arg);
    }

  /* Check that this condition makes sense at this time */

  if ((cond_forbids[cb->type] & (1 << where)) != 0)
    {
    *log_msgptr = string_sprintf("cannot %s %s condition in %s ACL",
      cond_modifiers[cb->type]? "use" : "test",
      conditions[cb->type], acl_wherenames[where]);
    return ERROR;
    }

  /* Run the appropriate test for each condition, or take the appropriate
  action for the remaining modifiers. */

  switch(cb->type)
    {
    case ACLC_ADD_HEADER:
    setup_header(arg);
    break;

    /* A nested ACL that returns "discard" makes sense only for an "accept" or
    "discard" verb. */

    case ACLC_ACL:
      rc = acl_check_wargs(where, addr, arg, level+1, user_msgptr, log_msgptr);
      if (rc == DISCARD && verb != ACL_ACCEPT && verb != ACL_DISCARD)
        {
        *log_msgptr = string_sprintf("nested ACL returned \"discard\" for "
          "\"%s\" command (only allowed with \"accept\" or \"discard\")",
          verbs[verb]);
        return ERROR;
        }
    break;

    case ACLC_AUTHENTICATED:
    rc = (sender_host_authenticated == NULL)? FAIL :
      match_isinlist(sender_host_authenticated, &arg, 0, NULL, NULL, MCL_STRING,
        TRUE, NULL);
    break;

    #ifdef EXPERIMENTAL_BRIGHTMAIL
    case ACLC_BMI_OPTIN:
      {
      int old_pool = store_pool;
      store_pool = POOL_PERM;
      bmi_current_optin = string_copy(arg);
      store_pool = old_pool;
      }
    break;
    #endif

    case ACLC_CONDITION:
    /* The true/false parsing here should be kept in sync with that used in
    expand.c when dealing with ECOND_BOOL so that we don't have too many
    different definitions of what can be a boolean. */
    if (Ustrspn(arg, "0123456789") == Ustrlen(arg))     /* Digits, or empty */
      rc = (Uatoi(arg) == 0)? FAIL : OK;
    else
      rc = (strcmpic(arg, US"no") == 0 ||
            strcmpic(arg, US"false") == 0)? FAIL :
           (strcmpic(arg, US"yes") == 0 ||
            strcmpic(arg, US"true") == 0)? OK : DEFER;
    if (rc == DEFER)
      *log_msgptr = string_sprintf("invalid \"condition\" value \"%s\"", arg);
    break;

    case ACLC_CONTINUE:    /* Always succeeds */
    break;

    case ACLC_CONTROL:
    control_type = decode_control(arg, &p, where, log_msgptr);

    /* Check if this control makes sense at this time */

    if ((control_forbids[control_type] & (1 << where)) != 0)
      {
      *log_msgptr = string_sprintf("cannot use \"control=%s\" in %s ACL",
        controls[control_type], acl_wherenames[where]);
      return ERROR;
      }

    switch(control_type)
      {
      case CONTROL_AUTH_UNADVERTISED:
      allow_auth_unadvertised = TRUE;
      break;

      #ifdef EXPERIMENTAL_BRIGHTMAIL
      case CONTROL_BMI_RUN:
      bmi_run = 1;
      break;
      #endif

      #ifndef DISABLE_DKIM
      case CONTROL_DKIM_VERIFY:
      dkim_disable_verify = TRUE;
      #ifdef EXPERIMENTAL_DMARC
      /* Since DKIM was blocked, skip DMARC too */
      dmarc_disable_verify = TRUE;
      dmarc_enable_forensic = FALSE;
      #endif
      break;
      #endif

      #ifdef EXPERIMENTAL_DMARC
      case CONTROL_DMARC_VERIFY:
      dmarc_disable_verify = TRUE;
      break;

      case CONTROL_DMARC_FORENSIC:
      dmarc_enable_forensic = TRUE;
      break;
      #endif

      case CONTROL_DSCP:
      if (*p == '/')
        {
        int fd, af, level, optname, value;
        /* If we are acting on stdin, the setsockopt may fail if stdin is not
        a socket; we can accept that, we'll just debug-log failures anyway. */
        fd = fileno(smtp_in);
        af = ip_get_address_family(fd);
        if (af < 0)
          {
          HDEBUG(D_acl)
            debug_printf("smtp input is probably not a socket [%s], not setting DSCP\n",
                strerror(errno));
          break;
          }
        if (dscp_lookup(p+1, af, &level, &optname, &value))
          {
          if (setsockopt(fd, level, optname, &value, sizeof(value)) < 0)
            {
            HDEBUG(D_acl) debug_printf("failed to set input DSCP[%s]: %s\n",
                p+1, strerror(errno));
            }
          else
            {
            HDEBUG(D_acl) debug_printf("set input DSCP to \"%s\"\n", p+1);
            }
          }
        else
          {
          *log_msgptr = string_sprintf("unrecognised DSCP value in \"control=%s\"", arg);
          return ERROR;
          }
        }
      else
        {
        *log_msgptr = string_sprintf("syntax error in \"control=%s\"", arg);
        return ERROR;
        }
      break;

      case CONTROL_ERROR:
      return ERROR;

      case CONTROL_CASEFUL_LOCAL_PART:
      deliver_localpart = addr->cc_local_part;
      break;

      case CONTROL_CASELOWER_LOCAL_PART:
      deliver_localpart = addr->lc_local_part;
      break;

      case CONTROL_ENFORCE_SYNC:
      smtp_enforce_sync = TRUE;
      break;

      case CONTROL_NO_ENFORCE_SYNC:
      smtp_enforce_sync = FALSE;
      break;

      #ifdef WITH_CONTENT_SCAN
      case CONTROL_NO_MBOX_UNSPOOL:
      no_mbox_unspool = TRUE;
      break;
      #endif

      case CONTROL_NO_MULTILINE:
      no_multiline_responses = TRUE;
      break;

      case CONTROL_NO_PIPELINING:
      pipelining_enable = FALSE;
      break;

      case CONTROL_NO_DELAY_FLUSH:
      disable_delay_flush = TRUE;
      break;

      case CONTROL_NO_CALLOUT_FLUSH:
      disable_callout_flush = TRUE;
      break;

      case CONTROL_FAKEDEFER:
      case CONTROL_FAKEREJECT:
      fake_response = (control_type == CONTROL_FAKEDEFER) ? DEFER : FAIL;
      if (*p == '/')
        {
        uschar *pp = p + 1;
        while (*pp != 0) pp++;
        fake_response_text = expand_string(string_copyn(p+1, pp-p-1));
        p = pp;
        }
       else
        {
        /* Explicitly reset to default string */
        fake_response_text = US"Your message has been rejected but is being kept for evaluation.\nIf it was a legitimate message, it may still be delivered to the target recipient(s).";
        }
      break;

      case CONTROL_FREEZE:
      deliver_freeze = TRUE;
      deliver_frozen_at = time(NULL);
      freeze_tell = freeze_tell_config;       /* Reset to configured value */
      if (Ustrncmp(p, "/no_tell", 8) == 0)
        {
        p += 8;
        freeze_tell = NULL;
        }
      if (*p != 0)
        {
        *log_msgptr = string_sprintf("syntax error in \"control=%s\"", arg);
        return ERROR;
        }
      break;

      case CONTROL_QUEUE_ONLY:
      queue_only_policy = TRUE;
      break;

      case CONTROL_SUBMISSION:
      originator_name = US"";
      submission_mode = TRUE;
      while (*p == '/')
        {
        if (Ustrncmp(p, "/sender_retain", 14) == 0)
          {
          p += 14;
          active_local_sender_retain = TRUE;
          active_local_from_check = FALSE;
          }
        else if (Ustrncmp(p, "/domain=", 8) == 0)
          {
          uschar *pp = p + 8;
          while (*pp != 0 && *pp != '/') pp++;
          submission_domain = string_copyn(p+8, pp-p-8);
          p = pp;
          }
        /* The name= option must be last, because it swallows the rest of
        the string. */
        else if (Ustrncmp(p, "/name=", 6) == 0)
          {
          uschar *pp = p + 6;
          while (*pp != 0) pp++;
          submission_name = string_copy(parse_fix_phrase(p+6, pp-p-6,
            big_buffer, big_buffer_size));
          p = pp;
          }
        else break;
        }
      if (*p != 0)
        {
        *log_msgptr = string_sprintf("syntax error in \"control=%s\"", arg);
        return ERROR;
        }
      break;

      case CONTROL_DEBUG:
      while (*p == '/')
        {
        if (Ustrncmp(p, "/tag=", 5) == 0)
          {
          uschar *pp = p + 5;
          while (*pp != '\0' && *pp != '/') pp++;
          debug_tag = string_copyn(p+5, pp-p-5);
          p = pp;
          }
        else if (Ustrncmp(p, "/opts=", 6) == 0)
          {
          uschar *pp = p + 6;
          while (*pp != '\0' && *pp != '/') pp++;
          debug_opts = string_copyn(p+6, pp-p-6);
          p = pp;
          }
        }
        debug_logging_activate(debug_tag, debug_opts);
      break;

      case CONTROL_SUPPRESS_LOCAL_FIXUPS:
      suppress_local_fixups = TRUE;
      break;

      case CONTROL_CUTTHROUGH_DELIVERY:
      if (deliver_freeze)
        {
        *log_msgptr = string_sprintf("\"control=%s\" on frozen item", arg);
        return ERROR;
        }
       if (queue_only_policy)
        {
        *log_msgptr = string_sprintf("\"control=%s\" on queue-only item", arg);
        return ERROR;
        }
      cutthrough_delivery = TRUE;
      break;
      }
    break;

    #ifdef EXPERIMENTAL_DCC
    case ACLC_DCC:
      {
      /* Seperate the regular expression and any optional parameters. */
      uschar *ss = string_nextinlist(&arg, &sep, big_buffer, big_buffer_size);
      /* Run the dcc backend. */
      rc = dcc_process(&ss);
      /* Modify return code based upon the existance of options. */
      while ((ss = string_nextinlist(&arg, &sep, big_buffer, big_buffer_size))
            != NULL) {
        if (strcmpic(ss, US"defer_ok") == 0 && rc == DEFER)
          {
          /* FAIL so that the message is passed to the next ACL */
          rc = FAIL;
          }
        }
      }
    break;
    #endif

    #ifdef WITH_CONTENT_SCAN
    case ACLC_DECODE:
    rc = mime_decode(&arg);
    break;
    #endif

    case ACLC_DELAY:
      {
      int delay = readconf_readtime(arg, 0, FALSE);
      if (delay < 0)
        {
        *log_msgptr = string_sprintf("syntax error in argument for \"delay\" "
          "modifier: \"%s\" is not a time value", arg);
        return ERROR;
        }
      else
        {
        HDEBUG(D_acl) debug_printf("delay modifier requests %d-second delay\n",
          delay);
        if (host_checking)
          {
          HDEBUG(D_acl)
            debug_printf("delay skipped in -bh checking mode\n");
          }

        /* It appears to be impossible to detect that a TCP/IP connection has
        gone away without reading from it. This means that we cannot shorten
        the delay below if the client goes away, because we cannot discover
        that the client has closed its end of the connection. (The connection
        is actually in a half-closed state, waiting for the server to close its
        end.) It would be nice to be able to detect this state, so that the
        Exim process is not held up unnecessarily. However, it seems that we
        can't. The poll() function does not do the right thing, and in any case
        it is not always available.

        NOTE 1: If ever this state of affairs changes, remember that we may be
        dealing with stdin/stdout here, in addition to TCP/IP connections.
        Also, delays may be specified for non-SMTP input, where smtp_out and
        smtp_in will be NULL. Whatever is done must work in all cases.

        NOTE 2: The added feature of flushing the output before a delay must
        apply only to SMTP input. Hence the test for smtp_out being non-NULL.
        */

        else
          {
          if (smtp_out != NULL && !disable_delay_flush) mac_smtp_fflush();
          while (delay > 0) delay = sleep(delay);
          }
        }
      }
    break;

    #ifdef WITH_OLD_DEMIME
    case ACLC_DEMIME:
      rc = demime(&arg);
    break;
    #endif

    #ifndef DISABLE_DKIM
    case ACLC_DKIM_SIGNER:
    if (dkim_cur_signer != NULL)
      rc = match_isinlist(dkim_cur_signer,
                          &arg,0,NULL,NULL,MCL_STRING,TRUE,NULL);
    else
       rc = FAIL;
    break;

    case ACLC_DKIM_STATUS:
    rc = match_isinlist(dkim_exim_expand_query(DKIM_VERIFY_STATUS),
                        &arg,0,NULL,NULL,MCL_STRING,TRUE,NULL);
    break;
    #endif

    #ifdef EXPERIMENTAL_DMARC
    case ACLC_DMARC_STATUS:
    if (dmarc_has_been_checked++ == 0)
      dmarc_process();
    /* used long way of dmarc_exim_expand_query() in case we need more
     * view into the process in the future. */
    rc = match_isinlist(dmarc_exim_expand_query(DMARC_VERIFY_STATUS),
                        &arg,0,NULL,NULL,MCL_STRING,TRUE,NULL);
    break;
    #endif

    case ACLC_DNSLISTS:
    rc = verify_check_dnsbl(&arg);
    break;

    case ACLC_DOMAINS:
    rc = match_isinlist(addr->domain, &arg, 0, &domainlist_anchor,
      addr->domain_cache, MCL_DOMAIN, TRUE, &deliver_domain_data);
    break;

    /* The value in tls_cipher is the full cipher name, for example,
    TLSv1:DES-CBC3-SHA:168, whereas the values to test for are just the
    cipher names such as DES-CBC3-SHA. But program defensively. We don't know
    what may in practice come out of the SSL library - which at the time of
    writing is poorly documented. */

    case ACLC_ENCRYPTED:
    if (tls_in.cipher == NULL) rc = FAIL; else
      {
      uschar *endcipher = NULL;
      uschar *cipher = Ustrchr(tls_in.cipher, ':');
      if (cipher == NULL) cipher = tls_in.cipher; else
        {
        endcipher = Ustrchr(++cipher, ':');
        if (endcipher != NULL) *endcipher = 0;
        }
      rc = match_isinlist(cipher, &arg, 0, NULL, NULL, MCL_STRING, TRUE, NULL);
      if (endcipher != NULL) *endcipher = ':';
      }
    break;

    /* Use verify_check_this_host() instead of verify_check_host() so that
    we can pass over &host_data to catch any looked up data. Once it has been
    set, it retains its value so that it's still there if another ACL verb
    comes through here and uses the cache. However, we must put it into
    permanent store in case it is also expected to be used in a subsequent
    message in the same SMTP connection. */

    case ACLC_HOSTS:
    rc = verify_check_this_host(&arg, sender_host_cache, NULL,
      (sender_host_address == NULL)? US"" : sender_host_address, &host_data);
    if (host_data != NULL) host_data = string_copy_malloc(host_data);
    break;

    case ACLC_LOCAL_PARTS:
    rc = match_isinlist(addr->cc_local_part, &arg, 0,
      &localpartlist_anchor, addr->localpart_cache, MCL_LOCALPART, TRUE,
      &deliver_localpart_data);
    break;

    case ACLC_LOG_REJECT_TARGET:
      {
      int logbits = 0;
      int sep = 0;
      uschar *s = arg;
      uschar *ss;
      while ((ss = string_nextinlist(&s, &sep, big_buffer, big_buffer_size))
              != NULL)
        {
        if (Ustrcmp(ss, "main") == 0) logbits |= LOG_MAIN;
        else if (Ustrcmp(ss, "panic") == 0) logbits |= LOG_PANIC;
        else if (Ustrcmp(ss, "reject") == 0) logbits |= LOG_REJECT;
        else
          {
          logbits |= LOG_MAIN|LOG_REJECT;
          log_write(0, LOG_MAIN|LOG_PANIC, "unknown log name \"%s\" in "
            "\"log_reject_target\" in %s ACL", ss, acl_wherenames[where]);
          }
        }
      log_reject_target = logbits;
      }
    break;

    case ACLC_LOGWRITE:
      {
      int logbits = 0;
      uschar *s = arg;
      if (*s == ':')
        {
        s++;
        while (*s != ':')
          {
          if (Ustrncmp(s, "main", 4) == 0)
            { logbits |= LOG_MAIN; s += 4; }
          else if (Ustrncmp(s, "panic", 5) == 0)
            { logbits |= LOG_PANIC; s += 5; }
          else if (Ustrncmp(s, "reject", 6) == 0)
            { logbits |= LOG_REJECT; s += 6; }
          else
            {
            logbits = LOG_MAIN|LOG_PANIC;
            s = string_sprintf(":unknown log name in \"%s\" in "
              "\"logwrite\" in %s ACL", arg, acl_wherenames[where]);
            }
          if (*s == ',') s++;
          }
        s++;
        }
      while (isspace(*s)) s++;


      if (logbits == 0) logbits = LOG_MAIN;
      log_write(0, logbits, "%s", string_printing(s));
      }
    break;

    #ifdef WITH_CONTENT_SCAN
    case ACLC_MALWARE:
      {
      /* Separate the regular expression and any optional parameters. */
      uschar *ss = string_nextinlist(&arg, &sep, big_buffer, big_buffer_size);
      /* Run the malware backend. */
      rc = malware(&ss);
      /* Modify return code based upon the existance of options. */
      while ((ss = string_nextinlist(&arg, &sep, big_buffer, big_buffer_size))
            != NULL) {
        if (strcmpic(ss, US"defer_ok") == 0 && rc == DEFER)
          {
          /* FAIL so that the message is passed to the next ACL */
          rc = FAIL;
          }
        }
      }
    break;

    case ACLC_MIME_REGEX:
    rc = mime_regex(&arg);
    break;
    #endif

    case ACLC_RATELIMIT:
    rc = acl_ratelimit(arg, where, log_msgptr);
    break;

    case ACLC_RECIPIENTS:
    rc = match_address_list(addr->address, TRUE, TRUE, &arg, NULL, -1, 0,
      &recipient_data);
    break;

    #ifdef WITH_CONTENT_SCAN
    case ACLC_REGEX:
    rc = regex(&arg);
    break;
    #endif

    case ACLC_REMOVE_HEADER:
    setup_remove_header(arg);
    break;

    case ACLC_SENDER_DOMAINS:
      {
      uschar *sdomain;
      sdomain = Ustrrchr(sender_address, '@');
      sdomain = (sdomain == NULL)? US"" : sdomain + 1;
      rc = match_isinlist(sdomain, &arg, 0, &domainlist_anchor,
        sender_domain_cache, MCL_DOMAIN, TRUE, NULL);
      }
    break;

    case ACLC_SENDERS:
    rc = match_address_list(sender_address, TRUE, TRUE, &arg,
      sender_address_cache, -1, 0, &sender_data);
    break;

    /* Connection variables must persist forever */

    case ACLC_SET:
      {
      int old_pool = store_pool;
      if (cb->u.varname[0] == 'c') store_pool = POOL_PERM;
      acl_var_create(cb->u.varname)->data.ptr = string_copy(arg);
      store_pool = old_pool;
      }
    break;

    #ifdef WITH_CONTENT_SCAN
    case ACLC_SPAM:
      {
      /* Seperate the regular expression and any optional parameters. */
      uschar *ss = string_nextinlist(&arg, &sep, big_buffer, big_buffer_size);
      /* Run the spam backend. */
      rc = spam(&ss);
      /* Modify return code based upon the existance of options. */
      while ((ss = string_nextinlist(&arg, &sep, big_buffer, big_buffer_size))
            != NULL) {
        if (strcmpic(ss, US"defer_ok") == 0 && rc == DEFER)
          {
          /* FAIL so that the message is passed to the next ACL */
          rc = FAIL;
          }
        }
      }
    break;
    #endif

    #ifdef EXPERIMENTAL_SPF
    case ACLC_SPF:
      rc = spf_process(&arg, sender_address, SPF_PROCESS_NORMAL);
    break;
    case ACLC_SPF_GUESS:
      rc = spf_process(&arg, sender_address, SPF_PROCESS_GUESS);
    break;
    #endif

    /* If the verb is WARN, discard any user message from verification, because
    such messages are SMTP responses, not header additions. The latter come
    only from explicit "message" modifiers. However, put the user message into
    $acl_verify_message so it can be used in subsequent conditions or modifiers
    (until something changes it). */

    case ACLC_VERIFY:
    rc = acl_verify(where, addr, arg, user_msgptr, log_msgptr, basic_errno);
    acl_verify_message = *user_msgptr;
    if (verb == ACL_WARN) *user_msgptr = NULL;
    break;

    default:
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "internal ACL error: unknown "
      "condition %d", cb->type);
    break;
    }

  /* If a condition was negated, invert OK/FAIL. */

  if (!cond_modifiers[cb->type] && cb->u.negated)
    {
    if (rc == OK) rc = FAIL;
      else if (rc == FAIL || rc == FAIL_DROP) rc = OK;
    }

  if (rc != OK) break;   /* Conditions loop */
  }


/* If the result is the one for which "message" and/or "log_message" are used,
handle the values of these modifiers. If there isn't a log message set, we make
it the same as the user message.

"message" is a user message that will be included in an SMTP response. Unless
it is empty, it overrides any previously set user message.

"log_message" is a non-user message, and it adds to any existing non-user
message that is already set.

Most verbs have but a single return for which the messages are relevant, but
for "discard", it's useful to have the log message both when it succeeds and
when it fails. For "accept", the message is used in the OK case if there is no
"endpass", but (for backwards compatibility) in the FAIL case if "endpass" is
present. */

if (*epp && rc == OK) user_message = NULL;

if (((1<<rc) & msgcond[verb]) != 0)
  {
  uschar *expmessage;
  uschar *old_user_msgptr = *user_msgptr;
  uschar *old_log_msgptr = (*log_msgptr != NULL)? *log_msgptr : old_user_msgptr;

  /* If the verb is "warn", messages generated by conditions (verification or
  nested ACLs) are always discarded. This also happens for acceptance verbs
  when they actually do accept. Only messages specified at this level are used.
  However, the value of an existing message is available in $acl_verify_message
  during expansions. */

  if (verb == ACL_WARN ||
      (rc == OK && (verb == ACL_ACCEPT || verb == ACL_DISCARD)))
    *log_msgptr = *user_msgptr = NULL;

  if (user_message != NULL)
    {
    acl_verify_message = old_user_msgptr;
    expmessage = expand_string(user_message);
    if (expmessage == NULL)
      {
      if (!expand_string_forcedfail)
        log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand ACL message \"%s\": %s",
          user_message, expand_string_message);
      }
    else if (expmessage[0] != 0) *user_msgptr = expmessage;
    }

  if (log_message != NULL)
    {
    acl_verify_message = old_log_msgptr;
    expmessage = expand_string(log_message);
    if (expmessage == NULL)
      {
      if (!expand_string_forcedfail)
        log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand ACL message \"%s\": %s",
          log_message, expand_string_message);
      }
    else if (expmessage[0] != 0)
      {
      *log_msgptr = (*log_msgptr == NULL)? expmessage :
        string_sprintf("%s: %s", expmessage, *log_msgptr);
      }
    }

  /* If no log message, default it to the user message */

  if (*log_msgptr == NULL) *log_msgptr = *user_msgptr;
  }

acl_verify_message = NULL;
return rc;
}





/*************************************************
*        Get line from a literal ACL             *
*************************************************/

/* This function is passed to acl_read() in order to extract individual lines
of a literal ACL, which we access via static pointers. We can destroy the
contents because this is called only once (the compiled ACL is remembered).

This code is intended to treat the data in the same way as lines in the main
Exim configuration file. That is:

  . Leading spaces are ignored.

  . A \ at the end of a line is a continuation - trailing spaces after the \
    are permitted (this is because I don't believe in making invisible things
    significant). Leading spaces on the continued part of a line are ignored.

  . Physical lines starting (significantly) with # are totally ignored, and
    may appear within a sequence of backslash-continued lines.

  . Blank lines are ignored, but will end a sequence of continuations.

Arguments: none
Returns:   a pointer to the next line
*/


static uschar *acl_text;          /* Current pointer in the text */
static uschar *acl_text_end;      /* Points one past the terminating '0' */


static uschar *
acl_getline(void)
{
uschar *yield;

/* This loop handles leading blank lines and comments. */

for(;;)
  {
  while (isspace(*acl_text)) acl_text++;   /* Leading spaces/empty lines */
  if (*acl_text == 0) return NULL;         /* No more data */
  yield = acl_text;                        /* Potential data line */

  while (*acl_text != 0 && *acl_text != '\n') acl_text++;

  /* If we hit the end before a newline, we have the whole logical line. If
  it's a comment, there's no more data to be given. Otherwise, yield it. */

  if (*acl_text == 0) return (*yield == '#')? NULL : yield;

  /* After reaching a newline, end this loop if the physical line does not
  start with '#'. If it does, it's a comment, and the loop continues. */

  if (*yield != '#') break;
  }

/* This loop handles continuations. We know we have some real data, ending in
newline. See if there is a continuation marker at the end (ignoring trailing
white space). We know that *yield is not white space, so no need to test for
cont > yield in the backwards scanning loop. */

for(;;)
  {
  uschar *cont;
  for (cont = acl_text - 1; isspace(*cont); cont--);

  /* If no continuation follows, we are done. Mark the end of the line and
  return it. */

  if (*cont != '\\')
    {
    *acl_text++ = 0;
    return yield;
    }

  /* We have encountered a continuation. Skip over whitespace at the start of
  the next line, and indeed the whole of the next line or lines if they are
  comment lines. */

  for (;;)
    {
    while (*(++acl_text) == ' ' || *acl_text == '\t');
    if (*acl_text != '#') break;
    while (*(++acl_text) != 0 && *acl_text != '\n');
    }

  /* We have the start of a continuation line. Move all the rest of the data
  to join onto the previous line, and then find its end. If the end is not a
  newline, we are done. Otherwise loop to look for another continuation. */

  memmove(cont, acl_text, acl_text_end - acl_text);
  acl_text_end -= acl_text - cont;
  acl_text = cont;
  while (*acl_text != 0 && *acl_text != '\n') acl_text++;
  if (*acl_text == 0) return yield;
  }

/* Control does not reach here */
}





/*************************************************
*        Check access using an ACL               *
*************************************************/

/* This function is called from address_check. It may recurse via
acl_check_condition() - hence the use of a level to stop looping. The ACL is
passed as a string which is expanded. A forced failure implies no access check
is required. If the result is a single word, it is taken as the name of an ACL
which is sought in the global ACL tree. Otherwise, it is taken as literal ACL
text, complete with newlines, and parsed as such. In both cases, the ACL check
is then run. This function uses an auxiliary function for acl_read() to call
for reading individual lines of a literal ACL. This is acl_getline(), which
appears immediately above.

Arguments:
  where        where called from
  addr         address item when called from RCPT; otherwise NULL
  s            the input string; NULL is the same as an empty ACL => DENY
  level        the nesting level
  user_msgptr  where to put a user error (for SMTP response)
  log_msgptr   where to put a logging message (not for SMTP response)

Returns:       OK         access is granted
               DISCARD    access is apparently granted...
               FAIL       access is denied
               FAIL_DROP  access is denied; drop the connection
               DEFER      can't tell at the moment
               ERROR      disaster
*/

static int
acl_check_internal(int where, address_item *addr, uschar *s, int level,
  uschar **user_msgptr, uschar **log_msgptr)
{
int fd = -1;
acl_block *acl = NULL;
uschar *acl_name = US"inline ACL";
uschar *ss;

/* Catch configuration loops */

if (level > 20)
  {
  *log_msgptr = US"ACL nested too deep: possible loop";
  return ERROR;
  }

if (s == NULL)
  {
  HDEBUG(D_acl) debug_printf("ACL is NULL: implicit DENY\n");
  return FAIL;
  }

/* At top level, we expand the incoming string. At lower levels, it has already
been expanded as part of condition processing. */

if (level == 0)
  {
  ss = expand_string(s);
  if (ss == NULL)
    {
    if (expand_string_forcedfail) return OK;
    *log_msgptr = string_sprintf("failed to expand ACL string \"%s\": %s", s,
      expand_string_message);
    return ERROR;
    }
  }
else ss = s;

while (isspace(*ss))ss++;

/* If we can't find a named ACL, the default is to parse it as an inline one.
(Unless it begins with a slash; non-existent files give rise to an error.) */

acl_text = ss;

/* Handle the case of a string that does not contain any spaces. Look for a
named ACL among those read from the configuration, or a previously read file.
It is possible that the pointer to the ACL is NULL if the configuration
contains a name with no data. If not found, and the text begins with '/',
read an ACL from a file, and save it so it can be re-used. */

if (Ustrchr(ss, ' ') == NULL)
  {
  tree_node *t = tree_search(acl_anchor, ss);
  if (t != NULL)
    {
    acl = (acl_block *)(t->data.ptr);
    if (acl == NULL)
      {
      HDEBUG(D_acl) debug_printf("ACL \"%s\" is empty: implicit DENY\n", ss);
      return FAIL;
      }
    acl_name = string_sprintf("ACL \"%s\"", ss);
    HDEBUG(D_acl) debug_printf("using ACL \"%s\"\n", ss);
    }

  else if (*ss == '/')
    {
    struct stat statbuf;
    fd = Uopen(ss, O_RDONLY, 0);
    if (fd < 0)
      {
      *log_msgptr = string_sprintf("failed to open ACL file \"%s\": %s", ss,
        strerror(errno));
      return ERROR;
      }

    if (fstat(fd, &statbuf) != 0)
      {
      *log_msgptr = string_sprintf("failed to fstat ACL file \"%s\": %s", ss,
        strerror(errno));
      return ERROR;
      }

    acl_text = store_get(statbuf.st_size + 1);
    acl_text_end = acl_text + statbuf.st_size + 1;

    if (read(fd, acl_text, statbuf.st_size) != statbuf.st_size)
      {
      *log_msgptr = string_sprintf("failed to read ACL file \"%s\": %s",
        ss, strerror(errno));
      return ERROR;
      }
    acl_text[statbuf.st_size] = 0;
    (void)close(fd);

    acl_name = string_sprintf("ACL \"%s\"", ss);
    HDEBUG(D_acl) debug_printf("read ACL from file %s\n", ss);
    }
  }

/* Parse an ACL that is still in text form. If it came from a file, remember it
in the ACL tree, having read it into the POOL_PERM store pool so that it
persists between multiple messages. */

if (acl == NULL)
  {
  int old_pool = store_pool;
  if (fd >= 0) store_pool = POOL_PERM;
  acl = acl_read(acl_getline, log_msgptr);
  store_pool = old_pool;
  if (acl == NULL && *log_msgptr != NULL) return ERROR;
  if (fd >= 0)
    {
    tree_node *t = store_get_perm(sizeof(tree_node) + Ustrlen(ss));
    Ustrcpy(t->name, ss);
    t->data.ptr = acl;
    (void)tree_insertnode(&acl_anchor, t);
    }
  }

/* Now we have an ACL to use. It's possible it may be NULL. */

while (acl != NULL)
  {
  int cond;
  int basic_errno = 0;
  BOOL endpass_seen = FALSE;

  *log_msgptr = *user_msgptr = NULL;
  acl_temp_details = FALSE;

  if ((where == ACL_WHERE_QUIT || where == ACL_WHERE_NOTQUIT) &&
      acl->verb != ACL_ACCEPT &&
      acl->verb != ACL_WARN)
    {
    *log_msgptr = string_sprintf("\"%s\" is not allowed in a QUIT or not-QUIT ACL",
      verbs[acl->verb]);
    return ERROR;
    }

  HDEBUG(D_acl) debug_printf("processing \"%s\"\n", verbs[acl->verb]);

  /* Clear out any search error message from a previous check before testing
  this condition. */

  search_error_message = NULL;
  cond = acl_check_condition(acl->verb, acl->condition, where, addr, level,
    &endpass_seen, user_msgptr, log_msgptr, &basic_errno);

  /* Handle special returns: DEFER causes a return except on a WARN verb;
  ERROR always causes a return. */

  switch (cond)
    {
    case DEFER:
    HDEBUG(D_acl) debug_printf("%s: condition test deferred in %s\n", verbs[acl->verb], acl_name);
    if (basic_errno != ERRNO_CALLOUTDEFER)
      {
      if (search_error_message != NULL && *search_error_message != 0)
        *log_msgptr = search_error_message;
      if (smtp_return_error_details) acl_temp_details = TRUE;
      }
    else
      {
      acl_temp_details = TRUE;
      }
    if (acl->verb != ACL_WARN) return DEFER;
    break;

    default:      /* Paranoia */
    case ERROR:
    HDEBUG(D_acl) debug_printf("%s: condition test error in %s\n", verbs[acl->verb], acl_name);
    return ERROR;

    case OK:
    HDEBUG(D_acl) debug_printf("%s: condition test succeeded in %s\n",
      verbs[acl->verb], acl_name);
    break;

    case FAIL:
    HDEBUG(D_acl) debug_printf("%s: condition test failed in %s\n", verbs[acl->verb], acl_name);
    break;

    /* DISCARD and DROP can happen only from a nested ACL condition, and
    DISCARD can happen only for an "accept" or "discard" verb. */

    case DISCARD:
    HDEBUG(D_acl) debug_printf("%s: condition test yielded \"discard\" in %s\n",
      verbs[acl->verb], acl_name);
    break;

    case FAIL_DROP:
    HDEBUG(D_acl) debug_printf("%s: condition test yielded \"drop\" in %s\n",
      verbs[acl->verb], acl_name);
    break;
    }

  /* At this point, cond for most verbs is either OK or FAIL or (as a result of
  a nested ACL condition) FAIL_DROP. However, for WARN, cond may be DEFER, and
  for ACCEPT and DISCARD, it may be DISCARD after a nested ACL call. */

  switch(acl->verb)
    {
    case ACL_ACCEPT:
    if (cond == OK || cond == DISCARD) return cond;
    if (endpass_seen)
      {
      HDEBUG(D_acl) debug_printf("accept: endpass encountered - denying access\n");
      return cond;
      }
    break;

    case ACL_DEFER:
    if (cond == OK)
      {
      acl_temp_details = TRUE;
      return DEFER;
      }
    break;

    case ACL_DENY:
    if (cond == OK) return FAIL;
    break;

    case ACL_DISCARD:
    if (cond == OK || cond == DISCARD) return DISCARD;
    if (endpass_seen)
      {
      HDEBUG(D_acl) debug_printf("discard: endpass encountered - denying access\n");
      return cond;
      }
    break;

    case ACL_DROP:
    if (cond == OK) return FAIL_DROP;
    break;

    case ACL_REQUIRE:
    if (cond != OK) return cond;
    break;

    case ACL_WARN:
    if (cond == OK)
      acl_warn(where, *user_msgptr, *log_msgptr);
    else if (cond == DEFER && (log_extra_selector & LX_acl_warn_skipped) != 0)
      log_write(0, LOG_MAIN, "%s Warning: ACL \"warn\" statement skipped: "
        "condition test deferred%s%s", host_and_ident(TRUE),
        (*log_msgptr == NULL)? US"" : US": ",
        (*log_msgptr == NULL)? US"" : *log_msgptr);
    *log_msgptr = *user_msgptr = NULL;  /* In case implicit DENY follows */
    break;

    default:
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "internal ACL error: unknown verb %d",
      acl->verb);
    break;
    }

  /* Pass to the next ACL item */

  acl = acl->next;
  }

/* We have reached the end of the ACL. This is an implicit DENY. */

HDEBUG(D_acl) debug_printf("end of %s: implicit DENY\n", acl_name);
return FAIL;
}




/* Same args as acl_check_internal() above, but the string s is
the name of an ACL followed optionally by up to 9 space-separated arguments.
The name and args are separately expanded.  Args go into $acl_arg globals. */
static int
acl_check_wargs(int where, address_item *addr, uschar *s, int level,
  uschar **user_msgptr, uschar **log_msgptr)
{
uschar * tmp;
uschar * tmp_arg[9];	/* must match acl_arg[] */
uschar * sav_arg[9];	/* must match acl_arg[] */
int sav_narg;
uschar * name;
int i;
int ret;

if (!(tmp = string_dequote(&s)) || !(name = expand_string(tmp)))
  goto bad;

for (i = 0; i < 9; i++)
  {
  while (*s && isspace(*s)) s++;
  if (!*s) break;
  if (!(tmp = string_dequote(&s)) || !(tmp_arg[i] = expand_string(tmp)))
    {
    tmp = name;
    goto bad;
    }
  }

sav_narg = acl_narg;
acl_narg = i;
for (i = 0; i < acl_narg; i++)
  {
  sav_arg[i] = acl_arg[i];
  acl_arg[i] = tmp_arg[i];
  }
while (i < 9)
  {
  sav_arg[i] = acl_arg[i];
  acl_arg[i++] = NULL;
  }

ret = acl_check_internal(where, addr, name, level, user_msgptr, log_msgptr);

acl_narg = sav_narg;
for (i = 0; i < 9; i++) acl_arg[i] = sav_arg[i];
return ret;

bad:
if (expand_string_forcedfail) return ERROR;
*log_msgptr = string_sprintf("failed to expand ACL string \"%s\": %s",
  tmp, expand_string_message);
return search_find_defer?DEFER:ERROR;
}



/*************************************************
*        Check access using an ACL               *
*************************************************/

/* Alternate interface for ACL, used by expansions */
int
acl_eval(int where, uschar *s, uschar **user_msgptr, uschar **log_msgptr)
{
address_item adb;
address_item *addr = NULL;

*user_msgptr = *log_msgptr = NULL;
sender_verified_failed = NULL;
ratelimiters_cmd = NULL;
log_reject_target = LOG_MAIN|LOG_REJECT;

if (where == ACL_WHERE_RCPT)
  {
  adb = address_defaults;
  addr = &adb;
  addr->address = expand_string(US"$local_part@$domain");
  addr->domain = deliver_domain;
  addr->local_part = deliver_localpart;
  addr->cc_local_part = deliver_localpart;
  addr->lc_local_part = deliver_localpart;
  }

return acl_check_internal(where, addr, s, 0, user_msgptr, log_msgptr);
}



/* This is the external interface for ACL checks. It sets up an address and the
expansions for $domain and $local_part when called after RCPT, then calls
acl_check_internal() to do the actual work.

Arguments:
  where        ACL_WHERE_xxxx indicating where called from
  recipient    RCPT address for RCPT check, else NULL
  s            the input string; NULL is the same as an empty ACL => DENY
  user_msgptr  where to put a user error (for SMTP response)
  log_msgptr   where to put a logging message (not for SMTP response)

Returns:       OK         access is granted by an ACCEPT verb
               DISCARD    access is granted by a DISCARD verb
               FAIL       access is denied
               FAIL_DROP  access is denied; drop the connection
               DEFER      can't tell at the moment
               ERROR      disaster
*/
int acl_where = ACL_WHERE_UNKNOWN;

int
acl_check(int where, uschar *recipient, uschar *s, uschar **user_msgptr,
  uschar **log_msgptr)
{
int rc;
address_item adb;
address_item *addr = NULL;

*user_msgptr = *log_msgptr = NULL;
sender_verified_failed = NULL;
ratelimiters_cmd = NULL;
log_reject_target = LOG_MAIN|LOG_REJECT;

#ifdef EXPERIMENTAL_PRDR
if (where == ACL_WHERE_RCPT || where == ACL_WHERE_PRDR )
#else
if (where == ACL_WHERE_RCPT )
#endif
  {
  adb = address_defaults;
  addr = &adb;
  addr->address = recipient;
  if (deliver_split_address(addr) == DEFER)
    {
    *log_msgptr = US"defer in percent_hack_domains check";
    return DEFER;
    }
  deliver_domain = addr->domain;
  deliver_localpart = addr->local_part;
  }

acl_where = where;
rc = acl_check_internal(where, addr, s, 0, user_msgptr, log_msgptr);
acl_where = ACL_WHERE_UNKNOWN;

/* Cutthrough - if requested,
and WHERE_RCPT and not yet opened conn as result of recipient-verify,
and rcpt acl returned accept,
and first recipient (cancel on any subsequents)
open one now and run it up to RCPT acceptance.
A failed verify should cancel cutthrough request.

Initial implementation:  dual-write to spool.
Assume the rxd datastream is now being copied byte-for-byte to an open cutthrough connection.

Cease cutthrough copy on rxd final dot; do not send one.

On a data acl, if not accept and a cutthrough conn is open, hard-close it (no SMTP niceness).

On data acl accept, terminate the dataphase on an open cutthrough conn.  If accepted or
perm-rejected, reflect that to the original sender - and dump the spooled copy.
If temp-reject, close the conn (and keep the spooled copy).
If conn-failure, no action (and keep the spooled copy).
*/
switch (where)
{
case ACL_WHERE_RCPT:
#ifdef EXPERIMENTAL_PRDR
case ACL_WHERE_PRDR:
#endif
  if( rcpt_count > 1 )
    cancel_cutthrough_connection("more than one recipient");
  else if (rc == OK  &&  cutthrough_delivery  &&  cutthrough_fd < 0)
    open_cutthrough_connection(addr);
  break;

case ACL_WHERE_PREDATA:
  if( rc == OK )
    cutthrough_predata();
  else
    cancel_cutthrough_connection("predata acl not ok");
  break;

case ACL_WHERE_QUIT:
case ACL_WHERE_NOTQUIT:
  cancel_cutthrough_connection("quit or notquit");
  break;

default:
  break;
}

deliver_domain = deliver_localpart = deliver_address_data =
  sender_address_data = NULL;

/* A DISCARD response is permitted only for message ACLs, excluding the PREDATA
ACL, which is really in the middle of an SMTP command. */

if (rc == DISCARD)
  {
  if (where > ACL_WHERE_NOTSMTP || where == ACL_WHERE_PREDATA)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "\"discard\" verb not allowed in %s "
      "ACL", acl_wherenames[where]);
    return ERROR;
    }
  return DISCARD;
  }

/* A DROP response is not permitted from MAILAUTH */

if (rc == FAIL_DROP && where == ACL_WHERE_MAILAUTH)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "\"drop\" verb not allowed in %s "
    "ACL", acl_wherenames[where]);
  return ERROR;
  }

/* Before giving a response, take a look at the length of any user message, and
split it up into multiple lines if possible. */

*user_msgptr = string_split_message(*user_msgptr);
if (fake_response != OK)
  fake_response_text = string_split_message(fake_response_text);

return rc;
}


/*************************************************
*             Create ACL variable                *
*************************************************/

/* Create an ACL variable or reuse an existing one. ACL variables are in a
binary tree (see tree.c) with acl_var_c and acl_var_m as root nodes.

Argument:
  name    pointer to the variable's name, starting with c or m

Returns   the pointer to variable's tree node
*/

tree_node *
acl_var_create(uschar *name)
{
tree_node *node, **root;
root = (name[0] == 'c')? &acl_var_c : &acl_var_m;
node = tree_search(*root, name);
if (node == NULL)
  {
  node = store_get(sizeof(tree_node) + Ustrlen(name));
  Ustrcpy(node->name, name);
  (void)tree_insertnode(root, node);
  }
node->data.ptr = NULL;
return node;
}



/*************************************************
*       Write an ACL variable in spool format    *
*************************************************/

/* This function is used as a callback for tree_walk when writing variables to
the spool file. To retain spool file compatibility, what is written is -aclc or
-aclm followed by the rest of the name and the data length, space separated,
then the value itself, starting on a new line, and terminated by an additional
newline. When we had only numbered ACL variables, the first line might look
like this: "-aclc 5 20". Now it might be "-aclc foo 20" for the variable called
acl_cfoo.

Arguments:
  name    of the variable
  value   of the variable
  ctx     FILE pointer (as a void pointer)

Returns:  nothing
*/

void
acl_var_write(uschar *name, uschar *value, void *ctx)
{
FILE *f = (FILE *)ctx;
fprintf(f, "-acl%c %s %d\n%s\n", name[0], name+1, Ustrlen(value), value);
}

/* End of acl.c */
