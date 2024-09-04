/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge, 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

gstring * dkim_exim_sign(int, off_t, uschar *, struct ob_dkim *, const uschar **);
uschar *dkim_exim_expand_query(int);


#define DKIM_ALGO               1
#define DKIM_BODYLENGTH         2
#define DKIM_CANON_BODY         3
#define DKIM_CANON_HEADERS      4
#define DKIM_COPIEDHEADERS      5
#define DKIM_CREATED            6
#define DKIM_EXPIRES            7
#define DKIM_HEADERNAMES        8
#define DKIM_IDENTITY           9
#define DKIM_KEY_GRANULARITY   10
#define DKIM_KEY_SRVTYPE       11
#define DKIM_KEY_NOTES         12
#define DKIM_KEY_TESTING       13
#define DKIM_NOSUBDOMAINS      14
#define DKIM_VERIFY_STATUS     15
#define DKIM_VERIFY_REASON     16


extern unsigned dkim_collect_input;    /* Runtime count of dkim signtures; tracks whether SMTP input is fed to DKIM validation */
extern uschar *dkim_cur_signer;        /* Expansion variable, holds the current "signer" domain or identity during a acl_smtp_dkim run */
extern int     dkim_key_length;        /* Expansion variable, length of signing key in bits */
extern void   *dkim_signatures;        /* Actually a (pdkim_signature *) but most files do not need to know */
extern uschar *dkim_signers;           /* Expansion variable, holds colon-separated list of domains and identities that have signed a message */
extern gstring *dkim_signing_record;   /* domains+selectors used */
extern uschar *dkim_signing_domain;    /* Expansion variable, domain used for signing a message. */
extern uschar *dkim_signing_selector;  /* Expansion variable, selector used for signing a message. */
extern uschar *dkim_verify_hashes;     /* Preference order for signatures */
extern uschar *dkim_verify_keytypes;   /* Preference order for signatures */
extern uschar *dkim_verify_min_keysizes; /* list of minimum key sizes, keyed by algo */
extern BOOL    dkim_verify_minimal;    /* Shortcircuit signature verification */
extern uschar *dkim_vdom_firstpass;    /* First successful domain verified, or null */
extern uschar *dkim_verify_signers;    /* Colon-separated list of domains for each of which we call the DKIM ACL */
extern uschar *dkim_verify_status;     /* result for this signature */
extern uschar *dkim_verify_reason;     /* result for this signature */

