/* $Cambridge: exim/src/src/expand.c,v 1.21 2005/05/10 10:19:11 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2005 */
/* See the file NOTICE for conditions of use and distribution. */


/* Functions for handling string expansion. */


#include "exim.h"

#ifdef STAND_ALONE
#ifndef SUPPORT_CRYPTEQ
#define SUPPORT_CRYPTEQ
#endif
#endif

#ifdef SUPPORT_CRYPTEQ
#ifdef CRYPT_H
#include <crypt.h>
#endif
#ifndef HAVE_CRYPT16
extern char* crypt16(char*, char*);
#endif
#endif

#ifdef LOOKUP_LDAP
#include "lookups/ldap.h"
#endif



/* Recursively called function */

static uschar *expand_string_internal(uschar *, BOOL, uschar **, BOOL);



/*************************************************
*            Local statics and tables            *
*************************************************/

/* Table of item names, and corresponding switch numbers. The names must be in
alphabetical order. */

static uschar *item_table[] = {
  US"dlfunc",
  US"extract",
  US"hash",
  US"hmac",
  US"if",
  US"length",
  US"lookup",
  US"nhash",
  US"perl",
  US"readfile",
  US"readsocket",
  US"run",
  US"sg",
  US"substr",
  US"tr" };

enum {
  EITEM_DLFUNC,
  EITEM_EXTRACT,
  EITEM_HASH,
  EITEM_HMAC,
  EITEM_IF,
  EITEM_LENGTH,
  EITEM_LOOKUP,
  EITEM_NHASH,
  EITEM_PERL,
  EITEM_READFILE,
  EITEM_READSOCK,
  EITEM_RUN,
  EITEM_SG,
  EITEM_SUBSTR,
  EITEM_TR };

/* Tables of operator names, and corresponding switch numbers. The names must be
in alphabetical order. There are two tables, because underscore is used in some
cases to introduce arguments, whereas for other it is part of the name. This is
an historical mis-design. */

static uschar *op_table_underscore[] = {
  US"from_utf8",
  US"local_part",
  US"quote_local_part",
  US"time_interval"};

enum {
  EOP_FROM_UTF8,
  EOP_LOCAL_PART,
  EOP_QUOTE_LOCAL_PART,
  EOP_TIME_INTERVAL };

static uschar *op_table_main[] = {
  US"address",
  US"base62",
  US"base62d",
  US"domain",
  US"escape",
  US"eval",
  US"eval10",
  US"expand",
  US"h",
  US"hash",
  US"hex2b64",
  US"l",
  US"lc",
  US"length",
  US"mask",
  US"md5",
  US"nh",
  US"nhash",
  US"quote",
  US"rfc2047",
  US"rxquote",
  US"s",
  US"sha1",
  US"stat",
  US"str2b64",
  US"strlen",
  US"substr",
  US"uc" };

enum {
  EOP_ADDRESS =  sizeof(op_table_underscore)/sizeof(uschar *),
  EOP_BASE62,
  EOP_BASE62D,
  EOP_DOMAIN,
  EOP_ESCAPE,
  EOP_EVAL,
  EOP_EVAL10,
  EOP_EXPAND,
  EOP_H,
  EOP_HASH,
  EOP_HEX2B64,
  EOP_L,
  EOP_LC,
  EOP_LENGTH,
  EOP_MASK,
  EOP_MD5,
  EOP_NH,
  EOP_NHASH,
  EOP_QUOTE,
  EOP_RFC2047,
  EOP_RXQUOTE,
  EOP_S,
  EOP_SHA1,
  EOP_STAT,
  EOP_STR2B64,
  EOP_STRLEN,
  EOP_SUBSTR,
  EOP_UC };


/* Table of condition names, and corresponding switch numbers. The names must
be in alphabetical order. */

static uschar *cond_table[] = {
  US"<",
  US"<=",
  US"=",
  US"==",     /* Backward compatibility */
  US">",
  US">=",
  US"and",
  US"crypteq",
  US"def",
  US"eq",
  US"eqi",
  US"exists",
  US"first_delivery",
  US"ge",
  US"gei",
  US"gt",
  US"gti",
  US"isip",
  US"isip4",
  US"isip6",
  US"ldapauth",
  US"le",
  US"lei",
  US"lt",
  US"lti",
  US"match",
  US"match_address",
  US"match_domain",
  US"match_local_part",
  US"or",
  US"pam",
  US"pwcheck",
  US"queue_running",
  US"radius",
  US"saslauthd"
};

enum {
  ECOND_NUM_L,
  ECOND_NUM_LE,
  ECOND_NUM_E,
  ECOND_NUM_EE,
  ECOND_NUM_G,
  ECOND_NUM_GE,
  ECOND_AND,
  ECOND_CRYPTEQ,
  ECOND_DEF,
  ECOND_STR_EQ,
  ECOND_STR_EQI,
  ECOND_EXISTS,
  ECOND_FIRST_DELIVERY,
  ECOND_STR_GE,
  ECOND_STR_GEI,
  ECOND_STR_GT,
  ECOND_STR_GTI,
  ECOND_ISIP,
  ECOND_ISIP4,
  ECOND_ISIP6,
  ECOND_LDAPAUTH,
  ECOND_STR_LE,
  ECOND_STR_LEI,
  ECOND_STR_LT,
  ECOND_STR_LTI,
  ECOND_MATCH,
  ECOND_MATCH_ADDRESS,
  ECOND_MATCH_DOMAIN,
  ECOND_MATCH_LOCAL_PART,
  ECOND_OR,
  ECOND_PAM,
  ECOND_PWCHECK,
  ECOND_QUEUE_RUNNING,
  ECOND_RADIUS,
  ECOND_SASLAUTHD
};


/* Type for main variable table */

typedef struct {
  char *name;
  int   type;
  void *value;
} var_entry;

/* Type for entries pointing to address/length pairs. Not currently
in use. */

typedef struct {
  uschar **address;
  int  *length;
} alblock;

/* Types of table entry */

enum {
  vtype_int,            /* value is address of int */
  vtype_filter_int,     /* ditto, but recognized only when filtering */
  vtype_ino,            /* value is address of ino_t (not always an int) */
  vtype_uid,            /* value is address of uid_t (not always an int) */
  vtype_gid,            /* value is address of gid_t (not always an int) */
  vtype_stringptr,      /* value is address of pointer to string */
  vtype_msgbody,        /* as stringptr, but read when first required */
  vtype_msgbody_end,    /* ditto, the end of the message */
  vtype_msgheaders,     /* the message's headers */
  vtype_localpart,      /* extract local part from string */
  vtype_domain,         /* extract domain from string */
  vtype_recipients,     /* extract recipients from recipients list */
                        /* (enabled only during system filtering */
  vtype_todbsdin,       /* value not used; generate BSD inbox tod */
  vtype_tode,           /* value not used; generate tod in epoch format */
  vtype_todf,           /* value not used; generate full tod */
  vtype_todl,           /* value not used; generate log tod */
  vtype_todlf,          /* value not used; generate log file datestamp tod */
  vtype_todzone,        /* value not used; generate time zone only */
  vtype_todzulu,        /* value not used; generate zulu tod */
  vtype_reply,          /* value not used; get reply from headers */
  vtype_pid,            /* value not used; result is pid */
  vtype_host_lookup,    /* value not used; get host name */
  vtype_load_avg,       /* value not used; result is int from os_getloadavg */
  vtype_pspace,         /* partition space; value is T/F for spool/log */
  vtype_pinodes         /* partition inodes; value is T/F for spool/log */
#ifdef EXPERIMENTAL_DOMAINKEYS
 ,vtype_dk_verify       /* Serve request out of DomainKeys verification structure */
#endif
  };

/* This table must be kept in alphabetical order. */

static var_entry var_table[] = {
  { "acl_c0",              vtype_stringptr,   &acl_var[0] },
  { "acl_c1",              vtype_stringptr,   &acl_var[1] },
  { "acl_c2",              vtype_stringptr,   &acl_var[2] },
  { "acl_c3",              vtype_stringptr,   &acl_var[3] },
  { "acl_c4",              vtype_stringptr,   &acl_var[4] },
  { "acl_c5",              vtype_stringptr,   &acl_var[5] },
  { "acl_c6",              vtype_stringptr,   &acl_var[6] },
  { "acl_c7",              vtype_stringptr,   &acl_var[7] },
  { "acl_c8",              vtype_stringptr,   &acl_var[8] },
  { "acl_c9",              vtype_stringptr,   &acl_var[9] },
  { "acl_m0",              vtype_stringptr,   &acl_var[10] },
  { "acl_m1",              vtype_stringptr,   &acl_var[11] },
  { "acl_m2",              vtype_stringptr,   &acl_var[12] },
  { "acl_m3",              vtype_stringptr,   &acl_var[13] },
  { "acl_m4",              vtype_stringptr,   &acl_var[14] },
  { "acl_m5",              vtype_stringptr,   &acl_var[15] },
  { "acl_m6",              vtype_stringptr,   &acl_var[16] },
  { "acl_m7",              vtype_stringptr,   &acl_var[17] },
  { "acl_m8",              vtype_stringptr,   &acl_var[18] },
  { "acl_m9",              vtype_stringptr,   &acl_var[19] },
  { "acl_verify_message",  vtype_stringptr,   &acl_verify_message },
  { "address_data",        vtype_stringptr,   &deliver_address_data },
  { "address_file",        vtype_stringptr,   &address_file },
  { "address_pipe",        vtype_stringptr,   &address_pipe },
  { "authenticated_id",    vtype_stringptr,   &authenticated_id },
  { "authenticated_sender",vtype_stringptr,   &authenticated_sender },
  { "authentication_failed",vtype_int,        &authentication_failed },
#ifdef EXPERIMENTAL_BRIGHTMAIL
  { "bmi_alt_location",    vtype_stringptr,   &bmi_alt_location },
  { "bmi_base64_tracker_verdict", vtype_stringptr, &bmi_base64_tracker_verdict },
  { "bmi_base64_verdict",  vtype_stringptr,   &bmi_base64_verdict },
  { "bmi_deliver",         vtype_int,         &bmi_deliver },
#endif
  { "body_linecount",      vtype_int,         &body_linecount },
  { "body_zerocount",      vtype_int,         &body_zerocount },
  { "bounce_recipient",    vtype_stringptr,   &bounce_recipient },
  { "bounce_return_size_limit", vtype_int,    &bounce_return_size_limit },
  { "caller_gid",          vtype_gid,         &real_gid },
  { "caller_uid",          vtype_uid,         &real_uid },
  { "compile_date",        vtype_stringptr,   &version_date },
  { "compile_number",      vtype_stringptr,   &version_cnumber },
  { "csa_status",          vtype_stringptr,   &csa_status },
#ifdef WITH_OLD_DEMIME
  { "demime_errorlevel",   vtype_int,         &demime_errorlevel },
  { "demime_reason",       vtype_stringptr,   &demime_reason },
#endif
#ifdef EXPERIMENTAL_DOMAINKEYS
  { "dk_domain",           vtype_stringptr,   &dk_signing_domain },
  { "dk_is_signed",        vtype_dk_verify,   NULL },
  { "dk_result",           vtype_dk_verify,   NULL },
  { "dk_selector",         vtype_stringptr,   &dk_signing_selector },
  { "dk_sender",           vtype_dk_verify,   NULL },
  { "dk_sender_domain",    vtype_dk_verify,   NULL },
  { "dk_sender_local_part",vtype_dk_verify,   NULL },
  { "dk_sender_source",    vtype_dk_verify,   NULL },
  { "dk_signsall",         vtype_dk_verify,   NULL },
  { "dk_status",           vtype_dk_verify,   NULL },
  { "dk_testing",          vtype_dk_verify,   NULL },
#endif
  { "dnslist_domain",      vtype_stringptr,   &dnslist_domain },
  { "dnslist_text",        vtype_stringptr,   &dnslist_text },
  { "dnslist_value",       vtype_stringptr,   &dnslist_value },
  { "domain",              vtype_stringptr,   &deliver_domain },
  { "domain_data",         vtype_stringptr,   &deliver_domain_data },
  { "exim_gid",            vtype_gid,         &exim_gid },
  { "exim_path",           vtype_stringptr,   &exim_path },
  { "exim_uid",            vtype_uid,         &exim_uid },
#ifdef WITH_OLD_DEMIME
  { "found_extension",     vtype_stringptr,   &found_extension },
#endif
  { "home",                vtype_stringptr,   &deliver_home },
  { "host",                vtype_stringptr,   &deliver_host },
  { "host_address",        vtype_stringptr,   &deliver_host_address },
  { "host_data",           vtype_stringptr,   &host_data },
  { "host_lookup_deferred",vtype_int,         &host_lookup_deferred },
  { "host_lookup_failed",  vtype_int,         &host_lookup_failed },
  { "inode",               vtype_ino,         &deliver_inode },
  { "interface_address",   vtype_stringptr,   &interface_address },
  { "interface_port",      vtype_int,         &interface_port },
  #ifdef LOOKUP_LDAP
  { "ldap_dn",             vtype_stringptr,   &eldap_dn },
  #endif
  { "load_average",        vtype_load_avg,    NULL },
  { "local_part",          vtype_stringptr,   &deliver_localpart },
  { "local_part_data",     vtype_stringptr,   &deliver_localpart_data },
  { "local_part_prefix",   vtype_stringptr,   &deliver_localpart_prefix },
  { "local_part_suffix",   vtype_stringptr,   &deliver_localpart_suffix },
  { "local_scan_data",     vtype_stringptr,   &local_scan_data },
  { "local_user_gid",      vtype_gid,         &local_user_gid },
  { "local_user_uid",      vtype_uid,         &local_user_uid },
  { "localhost_number",    vtype_int,         &host_number },
  { "log_inodes",          vtype_pinodes,     (void *)FALSE },
  { "log_space",           vtype_pspace,      (void *)FALSE },
  { "mailstore_basename",  vtype_stringptr,   &mailstore_basename },
#ifdef WITH_CONTENT_SCAN
  { "malware_name",        vtype_stringptr,   &malware_name },
#endif
  { "message_age",         vtype_int,         &message_age },
  { "message_body",        vtype_msgbody,     &message_body },
  { "message_body_end",    vtype_msgbody_end, &message_body_end },
  { "message_body_size",   vtype_int,         &message_body_size },
  { "message_headers",     vtype_msgheaders,  NULL },
  { "message_id",          vtype_stringptr,   &message_id },
  { "message_linecount",   vtype_int,         &message_linecount },
  { "message_size",        vtype_int,         &message_size },
#ifdef WITH_CONTENT_SCAN
  { "mime_anomaly_level",  vtype_int,         &mime_anomaly_level },
  { "mime_anomaly_text",   vtype_stringptr,   &mime_anomaly_text },
  { "mime_boundary",       vtype_stringptr,   &mime_boundary },
  { "mime_charset",        vtype_stringptr,   &mime_charset },
  { "mime_content_description", vtype_stringptr, &mime_content_description },
  { "mime_content_disposition", vtype_stringptr, &mime_content_disposition },
  { "mime_content_id",     vtype_stringptr,   &mime_content_id },
  { "mime_content_size",   vtype_int,         &mime_content_size },
  { "mime_content_transfer_encoding",vtype_stringptr, &mime_content_transfer_encoding },
  { "mime_content_type",   vtype_stringptr,   &mime_content_type },
  { "mime_decoded_filename", vtype_stringptr, &mime_decoded_filename },
  { "mime_filename",       vtype_stringptr,   &mime_filename },
  { "mime_is_coverletter", vtype_int,         &mime_is_coverletter },
  { "mime_is_multipart",   vtype_int,         &mime_is_multipart },
  { "mime_is_rfc822",      vtype_int,         &mime_is_rfc822 },
  { "mime_part_count",     vtype_int,         &mime_part_count },
#endif
  { "n0",                  vtype_filter_int,  &filter_n[0] },
  { "n1",                  vtype_filter_int,  &filter_n[1] },
  { "n2",                  vtype_filter_int,  &filter_n[2] },
  { "n3",                  vtype_filter_int,  &filter_n[3] },
  { "n4",                  vtype_filter_int,  &filter_n[4] },
  { "n5",                  vtype_filter_int,  &filter_n[5] },
  { "n6",                  vtype_filter_int,  &filter_n[6] },
  { "n7",                  vtype_filter_int,  &filter_n[7] },
  { "n8",                  vtype_filter_int,  &filter_n[8] },
  { "n9",                  vtype_filter_int,  &filter_n[9] },
  { "original_domain",     vtype_stringptr,   &deliver_domain_orig },
  { "original_local_part", vtype_stringptr,   &deliver_localpart_orig },
  { "originator_gid",      vtype_gid,         &originator_gid },
  { "originator_uid",      vtype_uid,         &originator_uid },
  { "parent_domain",       vtype_stringptr,   &deliver_domain_parent },
  { "parent_local_part",   vtype_stringptr,   &deliver_localpart_parent },
  { "pid",                 vtype_pid,         NULL },
  { "primary_hostname",    vtype_stringptr,   &primary_hostname },
  { "qualify_domain",      vtype_stringptr,   &qualify_domain_sender },
  { "qualify_recipient",   vtype_stringptr,   &qualify_domain_recipient },
  { "rcpt_count",          vtype_int,         &rcpt_count },
  { "rcpt_defer_count",    vtype_int,         &rcpt_defer_count },
  { "rcpt_fail_count",     vtype_int,         &rcpt_fail_count },
  { "received_count",      vtype_int,         &received_count },
  { "received_for",        vtype_stringptr,   &received_for },
  { "received_protocol",   vtype_stringptr,   &received_protocol },
  { "received_time",       vtype_int,         &received_time },
  { "recipient_data",      vtype_stringptr,   &recipient_data },
  { "recipient_verify_failure",vtype_stringptr,&recipient_verify_failure },
  { "recipients",          vtype_recipients,  NULL },
  { "recipients_count",    vtype_int,         &recipients_count },
#ifdef WITH_CONTENT_SCAN
  { "regex_match_string",  vtype_stringptr,   &regex_match_string },
#endif
  { "reply_address",       vtype_reply,       NULL },
  { "return_path",         vtype_stringptr,   &return_path },
  { "return_size_limit",   vtype_int,         &bounce_return_size_limit },
  { "runrc",               vtype_int,         &runrc },
  { "self_hostname",       vtype_stringptr,   &self_hostname },
  { "sender_address",      vtype_stringptr,   &sender_address },
  { "sender_address_data", vtype_stringptr,   &sender_address_data },
  { "sender_address_domain", vtype_domain,    &sender_address },
  { "sender_address_local_part", vtype_localpart, &sender_address },
  { "sender_data",         vtype_stringptr,   &sender_data },
  { "sender_fullhost",     vtype_stringptr,   &sender_fullhost },
  { "sender_helo_name",    vtype_stringptr,   &sender_helo_name },
  { "sender_host_address", vtype_stringptr,   &sender_host_address },
  { "sender_host_authenticated",vtype_stringptr, &sender_host_authenticated },
  { "sender_host_name",    vtype_host_lookup, NULL },
  { "sender_host_port",    vtype_int,         &sender_host_port },
  { "sender_ident",        vtype_stringptr,   &sender_ident },
  { "sender_rcvhost",      vtype_stringptr,   &sender_rcvhost },
  { "sender_verify_failure",vtype_stringptr,  &sender_verify_failure },
  { "smtp_active_hostname", vtype_stringptr,  &smtp_active_hostname },
  { "smtp_command_argument", vtype_stringptr, &smtp_command_argument },
  { "sn0",                 vtype_filter_int,  &filter_sn[0] },
  { "sn1",                 vtype_filter_int,  &filter_sn[1] },
  { "sn2",                 vtype_filter_int,  &filter_sn[2] },
  { "sn3",                 vtype_filter_int,  &filter_sn[3] },
  { "sn4",                 vtype_filter_int,  &filter_sn[4] },
  { "sn5",                 vtype_filter_int,  &filter_sn[5] },
  { "sn6",                 vtype_filter_int,  &filter_sn[6] },
  { "sn7",                 vtype_filter_int,  &filter_sn[7] },
  { "sn8",                 vtype_filter_int,  &filter_sn[8] },
  { "sn9",                 vtype_filter_int,  &filter_sn[9] },
#ifdef WITH_CONTENT_SCAN
  { "spam_bar",            vtype_stringptr,   &spam_bar },
  { "spam_report",         vtype_stringptr,   &spam_report },
  { "spam_score",          vtype_stringptr,   &spam_score },
  { "spam_score_int",      vtype_stringptr,   &spam_score_int },
#endif
#ifdef EXPERIMENTAL_SPF
  { "spf_header_comment",  vtype_stringptr,   &spf_header_comment },
  { "spf_received",        vtype_stringptr,   &spf_received },
  { "spf_result",          vtype_stringptr,   &spf_result },
  { "spf_smtp_comment",    vtype_stringptr,   &spf_smtp_comment },
#endif
  { "spool_directory",     vtype_stringptr,   &spool_directory },
  { "spool_inodes",        vtype_pinodes,     (void *)TRUE },
  { "spool_space",         vtype_pspace,      (void *)TRUE },
#ifdef EXPERIMENTAL_SRS
  { "srs_db_address",      vtype_stringptr,   &srs_db_address },
  { "srs_db_key",          vtype_stringptr,   &srs_db_key },
  { "srs_orig_recipient",  vtype_stringptr,   &srs_orig_recipient },
  { "srs_orig_sender",     vtype_stringptr,   &srs_orig_sender },
  { "srs_recipient",       vtype_stringptr,   &srs_recipient },
  { "srs_status",          vtype_stringptr,   &srs_status },
#endif
  { "thisaddress",         vtype_stringptr,   &filter_thisaddress },
  { "tls_certificate_verified", vtype_int,    &tls_certificate_verified },
  { "tls_cipher",          vtype_stringptr,   &tls_cipher },
  { "tls_peerdn",          vtype_stringptr,   &tls_peerdn },
  { "tod_bsdinbox",        vtype_todbsdin,    NULL },
  { "tod_epoch",           vtype_tode,        NULL },
  { "tod_full",            vtype_todf,        NULL },
  { "tod_log",             vtype_todl,        NULL },
  { "tod_logfile",         vtype_todlf,       NULL },
  { "tod_zone",            vtype_todzone,     NULL },
  { "tod_zulu",            vtype_todzulu,     NULL },
  { "value",               vtype_stringptr,   &lookup_value },
  { "version_number",      vtype_stringptr,   &version_string },
  { "warn_message_delay",  vtype_stringptr,   &warnmsg_delay },
  { "warn_message_recipient",vtype_stringptr, &warnmsg_recipients },
  { "warn_message_recipients",vtype_stringptr,&warnmsg_recipients },
  { "warnmsg_delay",       vtype_stringptr,   &warnmsg_delay },
  { "warnmsg_recipient",   vtype_stringptr,   &warnmsg_recipients },
  { "warnmsg_recipients",  vtype_stringptr,   &warnmsg_recipients }
};

static int var_table_size = sizeof(var_table)/sizeof(var_entry);
static uschar var_buffer[256];
static BOOL malformed_header;

/* For textual hashes */

static char *hashcodes = "abcdefghijklmnopqrtsuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "0123456789";

enum { HMAC_MD5, HMAC_SHA1 };

/* For numeric hashes */

static unsigned int prime[] = {
  2,   3,   5,   7,  11,  13,  17,  19,  23,  29,
 31,  37,  41,  43,  47,  53,  59,  61,  67,  71,
 73,  79,  83,  89,  97, 101, 103, 107, 109, 113};

/* For printing modes in symbolic form */

static uschar *mtable_normal[] =
  { US"---", US"--x", US"-w-", US"-wx", US"r--", US"r-x", US"rw-", US"rwx" };

static uschar *mtable_setid[] =
  { US"--S", US"--s", US"-wS", US"-ws", US"r-S", US"r-s", US"rwS", US"rws" };

static uschar *mtable_sticky[] =
  { US"--T", US"--t", US"-wT", US"-wt", US"r-T", US"r-t", US"rwT", US"rwt" };



/*************************************************
*           Tables for UTF-8 support             *
*************************************************/

/* Table of the number of extra characters, indexed by the first character
masked with 0x3f. The highest number for a valid UTF-8 character is in fact
0x3d. */

static uschar utf8_table1[] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5 };

/* These are the masks for the data bits in the first byte of a character,
indexed by the number of additional bytes. */

static int utf8_table2[] = { 0xff, 0x1f, 0x0f, 0x07, 0x03, 0x01};

/* Get the next UTF-8 character, advancing the pointer. */

#define GETUTF8INC(c, ptr) \
  c = *ptr++; \
  if ((c & 0xc0) == 0xc0) \
    { \
    int a = utf8_table1[c & 0x3f];  /* Number of additional bytes */ \
    int s = 6*a; \
    c = (c & utf8_table2[a]) << s; \
    while (a-- > 0) \
      { \
      s -= 6; \
      c |= (*ptr++ & 0x3f) << s; \
      } \
    }


/*************************************************
*           Binary chop search on a table        *
*************************************************/

/* This is used for matching expansion items and operators.

Arguments:
  name        the name that is being sought
  table       the table to search
  table_size  the number of items in the table

Returns:      the offset in the table, or -1
*/

static int
chop_match(uschar *name, uschar **table, int table_size)
{
uschar **bot = table;
uschar **top = table + table_size;

while (top > bot)
  {
  uschar **mid = bot + (top - bot)/2;
  int c = Ustrcmp(name, *mid);
  if (c == 0) return mid - table;
  if (c > 0) bot = mid + 1; else top = mid;
  }

return -1;
}



/*************************************************
*          Check a condition string              *
*************************************************/

/* This function is called to expand a string, and test the result for a "true"
or "false" value. Failure of the expansion yields FALSE; logged unless it was a
forced fail or lookup defer. All store used by the function can be released on
exit.

Arguments:
  condition     the condition string
  m1            text to be incorporated in panic error
  m2            ditto

Returns:        TRUE if condition is met, FALSE if not
*/

BOOL
expand_check_condition(uschar *condition, uschar *m1, uschar *m2)
{
int rc;
void *reset_point = store_get(0);
uschar *ss = expand_string(condition);
if (ss == NULL)
  {
  if (!expand_string_forcedfail && !search_find_defer)
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand condition \"%s\" "
      "for %s %s: %s", condition, m1, m2, expand_string_message);
  return FALSE;
  }
rc = ss[0] != 0 && Ustrcmp(ss, "0") != 0 && strcmpic(ss, US"no") != 0 &&
  strcmpic(ss, US"false") != 0;
store_reset(reset_point);
return rc;
}



/*************************************************
*             Pick out a name from a string      *
*************************************************/

/* If the name is too long, it is silently truncated.

Arguments:
  name      points to a buffer into which to put the name
  max       is the length of the buffer
  s         points to the first alphabetic character of the name
  extras    chars other than alphanumerics to permit

Returns:    pointer to the first character after the name

Note: The test for *s != 0 in the while loop is necessary because
Ustrchr() yields non-NULL if the character is zero (which is not something
I expected). */

static uschar *
read_name(uschar *name, int max, uschar *s, uschar *extras)
{
int ptr = 0;
while (*s != 0 && (isalnum(*s) || Ustrchr(extras, *s) != NULL))
  {
  if (ptr < max-1) name[ptr++] = *s;
  s++;
  }
name[ptr] = 0;
return s;
}



/*************************************************
*     Pick out the rest of a header name         *
*************************************************/

/* A variable name starting $header_ (or just $h_ for those who like
abbreviations) might not be the complete header name because headers can
contain any printing characters in their names, except ':'. This function is
called to read the rest of the name, chop h[eader]_ off the front, and put ':'
on the end, if the name was terminated by white space.

Arguments:
  name      points to a buffer in which the name read so far exists
  max       is the length of the buffer
  s         points to the first character after the name so far, i.e. the
            first non-alphameric character after $header_xxxxx

Returns:    a pointer to the first character after the header name
*/

static uschar *
read_header_name(uschar *name, int max, uschar *s)
{
int prelen = Ustrchr(name, '_') - name + 1;
int ptr = Ustrlen(name) - prelen;
if (ptr > 0) memmove(name, name+prelen, ptr);
while (mac_isgraph(*s) && *s != ':')
  {
  if (ptr < max-1) name[ptr++] = *s;
  s++;
  }
if (*s == ':') s++;
name[ptr++] = ':';
name[ptr] = 0;
return s;
}



/*************************************************
*           Pick out a number from a string      *
*************************************************/

/* Arguments:
  n     points to an integer into which to put the number
  s     points to the first digit of the number

Returns:  a pointer to the character after the last digit
*/

static uschar *
read_number(int *n, uschar *s)
{
*n = 0;
while (isdigit(*s)) *n = *n * 10 + (*s++ - '0');
return s;
}



/*************************************************
*        Extract keyed subfield from a string    *
*************************************************/

/* The yield is in dynamic store; NULL means that the key was not found.

Arguments:
  key       points to the name of the key
  s         points to the string from which to extract the subfield

Returns:    NULL if the subfield was not found, or
            a pointer to the subfield's data
*/

static uschar *
expand_getkeyed(uschar *key, uschar *s)
{
int length = Ustrlen(key);
while (isspace(*s)) s++;

/* Loop to search for the key */

while (*s != 0)
  {
  int dkeylength;
  uschar *data;
  uschar *dkey = s;

  while (*s != 0 && *s != '=' && !isspace(*s)) s++;
  dkeylength = s - dkey;
  while (isspace(*s)) s++;
  if (*s == '=') while (isspace((*(++s))));

  data = string_dequote(&s);
  if (length == dkeylength && strncmpic(key, dkey, length) == 0)
    return data;

  while (isspace(*s)) s++;
  }

return NULL;
}




/*************************************************
*   Extract numbered subfield from string        *
*************************************************/

/* Extracts a numbered field from a string that is divided by tokens - for
example a line from /etc/passwd is divided by colon characters.  First field is
numbered one.  Negative arguments count from the right. Zero returns the whole
string. Returns NULL if there are insufficient tokens in the string

***WARNING***
Modifies final argument - this is a dynamically generated string, so that's OK.

Arguments:
  field       number of field to be extracted,
                first field = 1, whole string = 0, last field = -1
  separators  characters that are used to break string into tokens
  s           points to the string from which to extract the subfield

Returns:      NULL if the field was not found,
              a pointer to the field's data inside s (modified to add 0)
*/

static uschar *
expand_gettokened (int field, uschar *separators, uschar *s)
{
int sep = 1;
int count;
uschar *ss = s;
uschar *fieldtext = NULL;

if (field == 0) return s;

/* Break the line up into fields in place; for field > 0 we stop when we have
done the number of fields we want. For field < 0 we continue till the end of
the string, counting the number of fields. */

count = (field > 0)? field : INT_MAX;

while (count-- > 0)
  {
  size_t len;

  /* Previous field was the last one in the string. For a positive field
  number, this means there are not enough fields. For a negative field number,
  check that there are enough, and scan back to find the one that is wanted. */

  if (sep == 0)
    {
    if (field > 0 || (-field) > (INT_MAX - count - 1)) return NULL;
    if ((-field) == (INT_MAX - count - 1)) return s;
    while (field++ < 0)
      {
      ss--;
      while (ss[-1] != 0) ss--;
      }
    fieldtext = ss;
    break;
    }

  /* Previous field was not last in the string; save its start and put a
  zero at its end. */

  fieldtext = ss;
  len = Ustrcspn(ss, separators);
  sep = ss[len];
  ss[len] = 0;
  ss += len + 1;
  }

return fieldtext;
}



/*************************************************
*        Extract a substring from a string       *
*************************************************/

/* Perform the ${substr or ${length expansion operations.

Arguments:
  subject     the input string
  value1      the offset from the start of the input string to the start of
                the output string; if negative, count from the right.
  value2      the length of the output string, or negative (-1) for unset
                if value1 is positive, unset means "all after"
                if value1 is negative, unset means "all before"
  len         set to the length of the returned string

Returns:      pointer to the output string, or NULL if there is an error
*/

static uschar *
extract_substr(uschar *subject, int value1, int value2, int *len)
{
int sublen = Ustrlen(subject);

if (value1 < 0)    /* count from right */
  {
  value1 += sublen;

  /* If the position is before the start, skip to the start, and adjust the
  length. If the length ends up negative, the substring is null because nothing
  can precede. This falls out naturally when the length is unset, meaning "all
  to the left". */

  if (value1 < 0)
    {
    value2 += value1;
    if (value2 < 0) value2 = 0;
    value1 = 0;
    }

  /* Otherwise an unset length => characters before value1 */

  else if (value2 < 0)
    {
    value2 = value1;
    value1 = 0;
    }
  }

/* For a non-negative offset, if the starting position is past the end of the
string, the result will be the null string. Otherwise, an unset length means
"rest"; just set it to the maximum - it will be cut down below if necessary. */

else
  {
  if (value1 > sublen)
    {
    value1 = sublen;
    value2 = 0;
    }
  else if (value2 < 0) value2 = sublen;
  }

/* Cut the length down to the maximum possible for the offset value, and get
the required characters. */

if (value1 + value2 > sublen) value2 = sublen - value1;
*len = value2;
return subject + value1;
}




/*************************************************
*            Old-style hash of a string          *
*************************************************/

/* Perform the ${hash expansion operation.

Arguments:
  subject     the input string (an expanded substring)
  value1      the length of the output string; if greater or equal to the
                length of the input string, the input string is returned
  value2      the number of hash characters to use, or 26 if negative
  len         set to the length of the returned string

Returns:      pointer to the output string, or NULL if there is an error
*/

static uschar *
compute_hash(uschar *subject, int value1, int value2, int *len)
{
int sublen = Ustrlen(subject);

if (value2 < 0) value2 = 26;
else if (value2 > Ustrlen(hashcodes))
  {
  expand_string_message =
    string_sprintf("hash count \"%d\" too big", value2);
  return NULL;
  }

/* Calculate the hash text. We know it is shorter than the original string, so
can safely place it in subject[] (we know that subject is always itself an
expanded substring). */

if (value1 < sublen)
  {
  int c;
  int i = 0;
  int j = value1;
  while ((c = (subject[j])) != 0)
    {
    int shift = (c + j++) & 7;
    subject[i] ^= (c << shift) | (c >> (8-shift));
    if (++i >= value1) i = 0;
    }
  for (i = 0; i < value1; i++)
    subject[i] = hashcodes[(subject[i]) % value2];
  }
else value1 = sublen;

*len = value1;
return subject;
}




/*************************************************
*             Numeric hash of a string           *
*************************************************/

/* Perform the ${nhash expansion operation. The first characters of the
string are treated as most important, and get the highest prime numbers.

Arguments:
  subject     the input string
  value1      the maximum value of the first part of the result
  value2      the maximum value of the second part of the result,
                or negative to produce only a one-part result
  len         set to the length of the returned string

Returns:  pointer to the output string, or NULL if there is an error.
*/

static uschar *
compute_nhash (uschar *subject, int value1, int value2, int *len)
{
uschar *s = subject;
int i = 0;
unsigned long int total = 0; /* no overflow */

while (*s != 0)
  {
  if (i == 0) i = sizeof(prime)/sizeof(int) - 1;
  total += prime[i--] * (unsigned int)(*s++);
  }

/* If value2 is unset, just compute one number */

if (value2 < 0)
  {
  s = string_sprintf("%d", total % value1);
  }

/* Otherwise do a div/mod hash */

else
  {
  total = total % (value1 * value2);
  s = string_sprintf("%d/%d", total/value2, total % value2);
  }

*len = Ustrlen(s);
return s;
}





/*************************************************
*     Find the value of a header or headers      *
*************************************************/

/* Multiple instances of the same header get concatenated, and this function
can also return a concatenation of all the header lines. When concatenating
specific headers that contain lists of addresses, a comma is inserted between
them. Otherwise we use a straight concatenation. Because some messages can have
pathologically large number of lines, there is a limit on the length that is
returned. Also, to avoid massive store use which would result from using
string_cat() as it copies and extends strings, we do a preliminary pass to find
out exactly how much store will be needed. On "normal" messages this will be
pretty trivial.

Arguments:
  name          the name of the header, without the leading $header_ or $h_,
                or NULL if a concatenation of all headers is required
  exists_only   TRUE if called from a def: test; don't need to build a string;
                just return a string that is not "" and not "0" if the header
                exists
  newsize       return the size of memory block that was obtained; may be NULL
                if exists_only is TRUE
  want_raw      TRUE if called for $rh_ or $rheader_ variables; no processing,
                other than concatenating, will be done on the header
  charset       name of charset to translate MIME words to; used only if
                want_raw is false; if NULL, no translation is done (this is
                used for $bh_ and $bheader_)

Returns:        NULL if the header does not exist, else a pointer to a new
                store block
*/

static uschar *
find_header(uschar *name, BOOL exists_only, int *newsize, BOOL want_raw,
  uschar *charset)
{
BOOL found = name == NULL;
int comma = 0;
int len = found? 0 : Ustrlen(name);
int i;
uschar *yield = NULL;
uschar *ptr = NULL;

/* Loop for two passes - saves code repetition */

for (i = 0; i < 2; i++)
  {
  int size = 0;
  header_line *h;

  for (h = header_list; size < header_insert_maxlen && h != NULL; h = h->next)
    {
    if (h->type != htype_old && h->text != NULL)  /* NULL => Received: placeholder */
      {
      if (name == NULL || (len <= h->slen && strncmpic(name, h->text, len) == 0))
        {
        int ilen;
        uschar *t;

        if (exists_only) return US"1";      /* don't need actual string */
        found = TRUE;
        t = h->text + len;                  /* text to insert */
        if (!want_raw)                      /* unless wanted raw, */
          while (isspace(*t)) t++;          /* remove leading white space */
        ilen = h->slen - (t - h->text);     /* length to insert */

        /* Set comma = 1 if handling a single header and it's one of those
        that contains an address list, except when asked for raw headers. Only
        need to do this once. */

        if (!want_raw && name != NULL && comma == 0 &&
            Ustrchr("BCFRST", h->type) != NULL)
          comma = 1;

        /* First pass - compute total store needed; second pass - compute
        total store used, including this header. */

        size += ilen + comma;

        /* Second pass - concatentate the data, up to a maximum. Note that
        the loop stops when size hits the limit. */

        if (i != 0)
          {
          if (size > header_insert_maxlen)
            {
            ilen -= size - header_insert_maxlen;
            comma = 0;
            }
          Ustrncpy(ptr, t, ilen);
          ptr += ilen;
          if (comma != 0 && ilen > 0)
            {
            ptr[-1] = ',';
            *ptr++ = '\n';
            }
          }
        }
      }
    }

  /* At end of first pass, truncate size if necessary, and get the buffer
  to hold the data, returning the buffer size. */

  if (i == 0)
    {
    if (!found) return NULL;
    if (size > header_insert_maxlen) size = header_insert_maxlen;
    *newsize = size + 1;
    ptr = yield = store_get(*newsize);
    }
  }

/* Remove a redundant added comma if present */

if (comma != 0 && ptr > yield) ptr -= 2;

/* That's all we do for raw header expansion. */

if (want_raw)
  {
  *ptr = 0;
  }

/* Otherwise, we remove trailing whitespace, including newlines. Then we do RFC
2047 decoding, translating the charset if requested. The rfc2047_decode2()
function can return an error with decoded data if the charset translation
fails. If decoding fails, it returns NULL. */

else
  {
  uschar *decoded, *error;
  while (ptr > yield && isspace(ptr[-1])) ptr--;
  *ptr = 0;
  decoded = rfc2047_decode2(yield, TRUE, charset, '?', NULL, newsize, &error);
  if (error != NULL)
    {
    DEBUG(D_any) debug_printf("*** error in RFC 2047 decoding: %s\n"
      "    input was: %s\n", error, yield);
    }
  if (decoded != NULL) yield = decoded;
  }

return yield;
}




/*************************************************
*               Find value of a variable         *
*************************************************/

/* The table of variables is kept in alphabetic order, so we can search it
using a binary chop. The "choplen" variable is nothing to do with the binary
chop.

Arguments:
  name          the name of the variable being sought
  exists_only   TRUE if this is a def: test; passed on to find_header()
  skipping      TRUE => skip any processing evaluation; this is not the same as
                  exists_only because def: may test for values that are first
                  evaluated here
  newsize       pointer to an int which is initially zero; if the answer is in
                a new memory buffer, *newsize is set to its size

Returns:        NULL if the variable does not exist, or
                a pointer to the variable's contents, or
                something non-NULL if exists_only is TRUE
*/

static uschar *
find_variable(uschar *name, BOOL exists_only, BOOL skipping, int *newsize)
{
int first = 0;
int last = var_table_size;

while (last > first)
  {
  uschar *s, *domain;
  uschar **ss;
  int middle = (first + last)/2;
  int c = Ustrcmp(name, var_table[middle].name);

  if (c > 0) { first = middle + 1; continue; }
  if (c < 0) { last = middle; continue; }

  /* Found an existing variable. If in skipping state, the value isn't needed,
  and we want to avoid processing (such as looking up up the host name). */

  if (skipping) return US"";

  switch (var_table[middle].type)
    {
    case vtype_filter_int:
    if (!filter_running) return NULL;
    /* Fall through */

#ifdef EXPERIMENTAL_DOMAINKEYS

    case vtype_dk_verify:
    if (dk_verify_block == NULL) return US"";
    s = NULL;
    if (Ustrcmp(var_table[middle].name, "dk_result") == 0)
      s = dk_verify_block->result_string;
    if (Ustrcmp(var_table[middle].name, "dk_sender") == 0)
      s = dk_verify_block->address;
    if (Ustrcmp(var_table[middle].name, "dk_sender_domain") == 0)
      s = dk_verify_block->domain;
    if (Ustrcmp(var_table[middle].name, "dk_sender_local_part") == 0)
      s = dk_verify_block->local_part;

    if (Ustrcmp(var_table[middle].name, "dk_sender_source") == 0)
      switch(dk_verify_block->address_source) {
        case DK_EXIM_ADDRESS_NONE: s = "0"; break;
        case DK_EXIM_ADDRESS_FROM_FROM: s = "from"; break;
        case DK_EXIM_ADDRESS_FROM_SENDER: s = "sender"; break;
      }

    if (Ustrcmp(var_table[middle].name, "dk_status") == 0)
      switch(dk_verify_block->result) {
        case DK_EXIM_RESULT_ERR: s = "error"; break;
        case DK_EXIM_RESULT_BAD_FORMAT: s = "bad format"; break;
        case DK_EXIM_RESULT_NO_KEY: s = "no key"; break;
        case DK_EXIM_RESULT_NO_SIGNATURE: s = "no signature"; break;
        case DK_EXIM_RESULT_REVOKED: s = "revoked"; break;
        case DK_EXIM_RESULT_NON_PARTICIPANT: s = "non-participant"; break;
        case DK_EXIM_RESULT_GOOD: s = "good"; break;
        case DK_EXIM_RESULT_BAD: s = "bad"; break;
      }

    if (Ustrcmp(var_table[middle].name, "dk_signsall") == 0)
      s = (dk_verify_block->signsall)? "1" : "0";

    if (Ustrcmp(var_table[middle].name, "dk_testing") == 0)
      s = (dk_verify_block->testing)? "1" : "0";

    if (Ustrcmp(var_table[middle].name, "dk_is_signed") == 0)
      s = (dk_verify_block->is_signed)? "1" : "0";

    return (s == NULL)? US"" : s;
#endif

    case vtype_int:
    sprintf(CS var_buffer, "%d", *(int *)(var_table[middle].value)); /* Integer */
    return var_buffer;

    case vtype_ino:
    sprintf(CS var_buffer, "%ld", (long int)(*(ino_t *)(var_table[middle].value))); /* Inode */
    return var_buffer;

    case vtype_gid:
    sprintf(CS var_buffer, "%ld", (long int)(*(gid_t *)(var_table[middle].value))); /* gid */
    return var_buffer;

    case vtype_uid:
    sprintf(CS var_buffer, "%ld", (long int)(*(uid_t *)(var_table[middle].value))); /* uid */
    return var_buffer;

    case vtype_stringptr:                      /* Pointer to string */
    s = *((uschar **)(var_table[middle].value));
    return (s == NULL)? US"" : s;

    case vtype_pid:
    sprintf(CS var_buffer, "%d", (int)getpid()); /* pid */
    return var_buffer;

    case vtype_load_avg:
    sprintf(CS var_buffer, "%d", os_getloadavg()); /* load_average */
    return var_buffer;

    case vtype_host_lookup:                    /* Lookup if not done so */
    if (sender_host_name == NULL && sender_host_address != NULL &&
        !host_lookup_failed && host_name_lookup() == OK)
      host_build_sender_fullhost();
    return (sender_host_name == NULL)? US"" : sender_host_name;

    case vtype_localpart:                      /* Get local part from address */
    s = *((uschar **)(var_table[middle].value));
    if (s == NULL) return US"";
    domain = Ustrrchr(s, '@');
    if (domain == NULL) return s;
    if (domain - s > sizeof(var_buffer) - 1)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "local part longer than %d in "
        "string expansion", sizeof(var_buffer));
    Ustrncpy(var_buffer, s, domain - s);
    var_buffer[domain - s] = 0;
    return var_buffer;

    case vtype_domain:                         /* Get domain from address */
    s = *((uschar **)(var_table[middle].value));
    if (s == NULL) return US"";
    domain = Ustrrchr(s, '@');
    return (domain == NULL)? US"" : domain + 1;

    case vtype_msgheaders:
    return find_header(NULL, exists_only, newsize, FALSE, NULL);

    case vtype_msgbody:                        /* Pointer to msgbody string */
    case vtype_msgbody_end:                    /* Ditto, the end of the msg */
    ss = (uschar **)(var_table[middle].value);
    if (*ss == NULL && deliver_datafile >= 0)  /* Read body when needed */
      {
      uschar *body;
      int start_offset = SPOOL_DATA_START_OFFSET;
      int len = message_body_visible;
      if (len > message_size) len = message_size;
      *ss = body = store_malloc(len+1);
      body[0] = 0;
      if (var_table[middle].type == vtype_msgbody_end)
        {
        struct stat statbuf;
        if (fstat(deliver_datafile, &statbuf) == 0)
          {
          start_offset = statbuf.st_size - len;
          if (start_offset < SPOOL_DATA_START_OFFSET)
            start_offset = SPOOL_DATA_START_OFFSET;
          }
        }
      lseek(deliver_datafile, start_offset, SEEK_SET);
      len = read(deliver_datafile, body, len);
      if (len > 0)
        {
        body[len] = 0;
        while (len > 0)
          {
          if (body[--len] == '\n' || body[len] == 0) body[len] = ' ';
          }
        }
      }
    return (*ss == NULL)? US"" : *ss;

    case vtype_todbsdin:                       /* BSD inbox time of day */
    return tod_stamp(tod_bsdin);

    case vtype_tode:                           /* Unix epoch time of day */
    return tod_stamp(tod_epoch);

    case vtype_todf:                           /* Full time of day */
    return tod_stamp(tod_full);

    case vtype_todl:                           /* Log format time of day */
    return tod_stamp(tod_log_bare);            /* (without timezone) */

    case vtype_todzone:                        /* Time zone offset only */
    return tod_stamp(tod_zone);

    case vtype_todzulu:                        /* Zulu time */
    return tod_stamp(tod_zulu);

    case vtype_todlf:                          /* Log file datestamp tod */
    return tod_stamp(tod_log_datestamp);

    case vtype_reply:                          /* Get reply address */
    s = find_header(US"reply-to:", exists_only, newsize, FALSE,
      headers_charset);
    if (s == NULL || *s == 0)
      s = find_header(US"from:", exists_only, newsize, FALSE, headers_charset);
    return (s == NULL)? US"" : s;

    /* A recipients list is available only during system message filtering,
    during ACL processing after DATA, and while expanding pipe commands
    generated from a system filter, but not elsewhere. */

    case vtype_recipients:
    if (!enable_dollar_recipients) return NULL; else
      {
      int size = 128;
      int ptr = 0;
      int i;
      s = store_get(size);
      for (i = 0; i < recipients_count; i++)
        {
        if (i != 0) s = string_cat(s, &size, &ptr, US", ", 2);
        s = string_cat(s, &size, &ptr, recipients_list[i].address,
          Ustrlen(recipients_list[i].address));
        }
      s[ptr] = 0;     /* string_cat() leaves room */
      }
    return s;

    case vtype_pspace:
      {
      int inodes;
      sprintf(CS var_buffer, "%d",
        receive_statvfs(var_table[middle].value == (void *)TRUE, &inodes));
      }
    return var_buffer;

    case vtype_pinodes:
      {
      int inodes;
      (void) receive_statvfs(var_table[middle].value == (void *)TRUE, &inodes);
      sprintf(CS var_buffer, "%d", inodes);
      }
    return var_buffer;
    }
  }

return NULL;          /* Unknown variable name */
}




/*************************************************
*           Read and expand substrings           *
*************************************************/

/* This function is called to read and expand argument substrings for various
expansion items. Some have a minimum requirement that is less than the maximum;
in these cases, the first non-present one is set to NULL.

Arguments:
  sub        points to vector of pointers to set
  n          maximum number of substrings
  m          minimum required
  sptr       points to current string pointer
  skipping   the skipping flag
  check_end  if TRUE, check for final '}'
  name       name of item, for error message

Returns:     0 OK; string pointer updated
             1 curly bracketing error (too few arguments)
             2 too many arguments (only if check_end is set); message set
             3 other error (expansion failure)
*/

static int
read_subs(uschar **sub, int n, int m, uschar **sptr, BOOL skipping,
  BOOL check_end, uschar *name)
{
int i;
uschar *s = *sptr;

while (isspace(*s)) s++;
for (i = 0; i < n; i++)
  {
  if (*s != '{')
    {
    if (i < m) return 1;
    sub[i] = NULL;
    break;
    }
  sub[i] = expand_string_internal(s+1, TRUE, &s, skipping);
  if (sub[i] == NULL) return 3;
  if (*s++ != '}') return 1;
  while (isspace(*s)) s++;
  }
if (check_end && *s++ != '}')
  {
  if (s[-1] == '{')
    {
    expand_string_message = string_sprintf("Too many arguments for \"%s\" "
      "(max is %d)", name, n);
    return 2;
    }
  return 1;
  }

*sptr = s;
return 0;
}




/*************************************************
*        Read and evaluate a condition           *
*************************************************/

/*
Arguments:
  s        points to the start of the condition text
  yield    points to a BOOL to hold the result of the condition test;
           if NULL, we are just reading through a condition that is
           part of an "or" combination to check syntax, or in a state
           where the answer isn't required

Returns:   a pointer to the first character after the condition, or
           NULL after an error
*/

static uschar *
eval_condition(uschar *s, BOOL *yield)
{
BOOL testfor = TRUE;
BOOL tempcond, combined_cond;
BOOL *subcondptr;
int i, rc, cond_type, roffset;
int num[2];
struct stat statbuf;
uschar name[256];
uschar *sub[4];

const pcre *re;
const uschar *rerror;

for (;;)
  {
  while (isspace(*s)) s++;
  if (*s == '!') { testfor = !testfor; s++; } else break;
  }

/* Numeric comparisons are symbolic */

if (*s == '=' || *s == '>' || *s == '<')
  {
  int p = 0;
  name[p++] = *s++;
  if (*s == '=')
    {
    name[p++] = '=';
    s++;
    }
  name[p] = 0;
  }

/* All other conditions are named */

else s = read_name(name, 256, s, US"_");

/* If we haven't read a name, it means some non-alpha character is first. */

if (name[0] == 0)
  {
  expand_string_message = string_sprintf("condition name expected, "
    "but found \"%.16s\"", s);
  return NULL;
  }

/* Find which condition we are dealing with, and switch on it */

cond_type = chop_match(name, cond_table, sizeof(cond_table)/sizeof(uschar *));
switch(cond_type)
  {
  /* def: tests for a non-zero or non-NULL variable, or for an existing
  header */

  case ECOND_DEF:
  if (*s != ':')
    {
    expand_string_message = US"\":\" expected after \"def\"";
    return NULL;
    }

  s = read_name(name, 256, s+1, US"_");

  /* Test for a header's existence */

  if (Ustrncmp(name, "h_", 2) == 0 ||
      Ustrncmp(name, "rh_", 3) == 0 ||
      Ustrncmp(name, "bh_", 3) == 0 ||
      Ustrncmp(name, "header_", 7) == 0 ||
      Ustrncmp(name, "rheader_", 8) == 0 ||
      Ustrncmp(name, "bheader_", 8) == 0)
    {
    s = read_header_name(name, 256, s);
    if (yield != NULL) *yield =
      (find_header(name, TRUE, NULL, FALSE, NULL) != NULL) == testfor;
    }

  /* Test for a variable's having a non-empty value. If yield == NULL we
  are in a skipping state, and don't care about the answer. */

  else
    {
    uschar *value = find_variable(name, TRUE, yield == NULL, NULL);
    if (value == NULL)
      {
      expand_string_message = (name[0] == 0)?
        string_sprintf("variable name omitted after \"def:\"") :
        string_sprintf("unknown variable \"%s\" after \"def:\"", name);
      return NULL;
      }
    if (yield != NULL)
      *yield = (value[0] != 0 && Ustrcmp(value, "0") != 0) == testfor;
    }

  return s;


  /* first_delivery tests for first delivery attempt */

  case ECOND_FIRST_DELIVERY:
  if (yield != NULL) *yield = deliver_firsttime == testfor;
  return s;


  /* queue_running tests for any process started by a queue runner */

  case ECOND_QUEUE_RUNNING:
  if (yield != NULL) *yield = (queue_run_pid != (pid_t)0) == testfor;
  return s;


  /* exists:  tests for file existence
       isip:  tests for any IP address
      isip4:  tests for an IPv4 address
      isip6:  tests for an IPv6 address
        pam:  does PAM authentication
     radius:  does RADIUS authentication
   ldapauth:  does LDAP authentication
    pwcheck:  does Cyrus SASL pwcheck authentication
  */

  case ECOND_EXISTS:
  case ECOND_ISIP:
  case ECOND_ISIP4:
  case ECOND_ISIP6:
  case ECOND_PAM:
  case ECOND_RADIUS:
  case ECOND_LDAPAUTH:
  case ECOND_PWCHECK:

  while (isspace(*s)) s++;
  if (*s != '{') goto COND_FAILED_CURLY_START;

  sub[0] = expand_string_internal(s+1, TRUE, &s, yield == NULL);
  if (sub[0] == NULL) return NULL;
  if (*s++ != '}') goto COND_FAILED_CURLY_END;

  if (yield == NULL) return s;   /* No need to run the test if skipping */

  switch(cond_type)
    {
    case ECOND_EXISTS:
    if ((expand_forbid & RDO_EXISTS) != 0)
      {
      expand_string_message = US"File existence tests are not permitted";
      return NULL;
      }
    *yield = (Ustat(sub[0], &statbuf) == 0) == testfor;
    break;

    case ECOND_ISIP:
    case ECOND_ISIP4:
    case ECOND_ISIP6:
    rc = string_is_ip_address(sub[0], NULL);
    *yield = ((cond_type == ECOND_ISIP)? (rc > 0) :
             (cond_type == ECOND_ISIP4)? (rc == 4) : (rc == 6)) == testfor;
    break;

    /* Various authentication tests - all optionally compiled */

    case ECOND_PAM:
    #ifdef SUPPORT_PAM
    rc = auth_call_pam(sub[0], &expand_string_message);
    goto END_AUTH;
    #else
    goto COND_FAILED_NOT_COMPILED;
    #endif  /* SUPPORT_PAM */

    case ECOND_RADIUS:
    #ifdef RADIUS_CONFIG_FILE
    rc = auth_call_radius(sub[0], &expand_string_message);
    goto END_AUTH;
    #else
    goto COND_FAILED_NOT_COMPILED;
    #endif  /* RADIUS_CONFIG_FILE */

    case ECOND_LDAPAUTH:
    #ifdef LOOKUP_LDAP
      {
      /* Just to keep the interface the same */
      BOOL do_cache;
      int old_pool = store_pool;
      store_pool = POOL_SEARCH;
      rc = eldapauth_find((void *)(-1), NULL, sub[0], Ustrlen(sub[0]), NULL,
        &expand_string_message, &do_cache);
      store_pool = old_pool;
      }
    goto END_AUTH;
    #else
    goto COND_FAILED_NOT_COMPILED;
    #endif  /* LOOKUP_LDAP */

    case ECOND_PWCHECK:
    #ifdef CYRUS_PWCHECK_SOCKET
    rc = auth_call_pwcheck(sub[0], &expand_string_message);
    goto END_AUTH;
    #else
    goto COND_FAILED_NOT_COMPILED;
    #endif  /* CYRUS_PWCHECK_SOCKET */

    #if defined(SUPPORT_PAM) || defined(RADIUS_CONFIG_FILE) || \
        defined(LOOKUP_LDAP) || defined(CYRUS_PWCHECK_SOCKET)
    END_AUTH:
    if (rc == ERROR || rc == DEFER) return NULL;
    *yield = (rc == OK) == testfor;
    #endif
    }
  return s;


  /* saslauthd: does Cyrus saslauthd authentication. Four parameters are used:

     ${if saslauthd {{username}{password}{service}{realm}}  {yes}[no}}

  However, the last two are optional. That is why the whole set is enclosed
  in their own set or braces. */

  case ECOND_SASLAUTHD:
  #ifndef CYRUS_SASLAUTHD_SOCKET
  goto COND_FAILED_NOT_COMPILED;
  #else
  while (isspace(*s)) s++;
  if (*s++ != '{') goto COND_FAILED_CURLY_START;
  switch(read_subs(sub, 4, 2, &s, yield == NULL, TRUE, US"saslauthd"))
    {
    case 1: expand_string_message = US"too few arguments or bracketing "
      "error for saslauthd";
    case 2:
    case 3: return NULL;
    }
  if (sub[2] == NULL) sub[3] = NULL;  /* realm if no service */
  if (yield != NULL)
    {
    int rc;
    rc = auth_call_saslauthd(sub[0], sub[1], sub[2], sub[3],
      &expand_string_message);
    if (rc == ERROR || rc == DEFER) return NULL;
    *yield = (rc == OK) == testfor;
    }
  return s;
  #endif /* CYRUS_SASLAUTHD_SOCKET */


  /* symbolic operators for numeric and string comparison, and a number of
  other operators, all requiring two arguments.

  match:             does a regular expression match and sets up the numerical
                       variables if it succeeds
  match_address:     matches in an address list
  match_domain:      matches in a domain list
  match_local_part:  matches in a local part list
  crypteq:           encrypts plaintext and compares against an encrypted text,
                       using crypt(), crypt16(), MD5 or SHA-1
  */

  case ECOND_MATCH:
  case ECOND_MATCH_ADDRESS:
  case ECOND_MATCH_DOMAIN:
  case ECOND_MATCH_LOCAL_PART:
  case ECOND_CRYPTEQ:

  case ECOND_NUM_L:     /* Numerical comparisons */
  case ECOND_NUM_LE:
  case ECOND_NUM_E:
  case ECOND_NUM_EE:
  case ECOND_NUM_G:
  case ECOND_NUM_GE:

  case ECOND_STR_LT:    /* String comparisons */
  case ECOND_STR_LTI:
  case ECOND_STR_LE:
  case ECOND_STR_LEI:
  case ECOND_STR_EQ:
  case ECOND_STR_EQI:
  case ECOND_STR_GT:
  case ECOND_STR_GTI:
  case ECOND_STR_GE:
  case ECOND_STR_GEI:

  for (i = 0; i < 2; i++)
    {
    while (isspace(*s)) s++;
    if (*s != '{')
      {
      if (i == 0) goto COND_FAILED_CURLY_START;
      expand_string_message = string_sprintf("missing 2nd string in {} "
        "after \"%s\"", name);
      return NULL;
      }
    sub[i] = expand_string_internal(s+1, TRUE, &s, yield == NULL);
    if (sub[i] == NULL) return NULL;
    if (*s++ != '}') goto COND_FAILED_CURLY_END;

    /* Convert to numerical if required; we know that the names of all the
    conditions that compare numbers do not start with a letter. This just saves
    checking for them individually. */

    if (!isalpha(name[0]))
      {
      uschar *endptr;
      num[i] = (int)Ustrtol((const uschar *)sub[i], &endptr, 10);
      if (tolower(*endptr) == 'k')
        {
        num[i] *= 1024;
        endptr++;
        }
      else if (tolower(*endptr) == 'm')
        {
        num[i] *= 1024*1024;
        endptr++;
        }
      while (isspace(*endptr)) endptr++;
      if (*endptr != 0)
        {
        expand_string_message = string_sprintf("\"%s\" is not a number",
          sub[i]);
        return NULL;
        }
      }
    }

  /* Result not required */

  if (yield == NULL) return s;

  /* Do an appropriate comparison */

  switch(cond_type)
    {
    case ECOND_NUM_E:
    case ECOND_NUM_EE:
    *yield = (num[0] == num[1]) == testfor;
    break;

    case ECOND_NUM_G:
    *yield = (num[0] > num[1]) == testfor;
    break;

    case ECOND_NUM_GE:
    *yield = (num[0] >= num[1]) == testfor;
    break;

    case ECOND_NUM_L:
    *yield = (num[0] < num[1]) == testfor;
    break;

    case ECOND_NUM_LE:
    *yield = (num[0] <= num[1]) == testfor;
    break;

    case ECOND_STR_LT:
    *yield = (Ustrcmp(sub[0], sub[1]) < 0) == testfor;
    break;

    case ECOND_STR_LTI:
    *yield = (strcmpic(sub[0], sub[1]) < 0) == testfor;
    break;

    case ECOND_STR_LE:
    *yield = (Ustrcmp(sub[0], sub[1]) <= 0) == testfor;
    break;

    case ECOND_STR_LEI:
    *yield = (strcmpic(sub[0], sub[1]) <= 0) == testfor;
    break;

    case ECOND_STR_EQ:
    *yield = (Ustrcmp(sub[0], sub[1]) == 0) == testfor;
    break;

    case ECOND_STR_EQI:
    *yield = (strcmpic(sub[0], sub[1]) == 0) == testfor;
    break;

    case ECOND_STR_GT:
    *yield = (Ustrcmp(sub[0], sub[1]) > 0) == testfor;
    break;

    case ECOND_STR_GTI:
    *yield = (strcmpic(sub[0], sub[1]) > 0) == testfor;
    break;

    case ECOND_STR_GE:
    *yield = (Ustrcmp(sub[0], sub[1]) >= 0) == testfor;
    break;

    case ECOND_STR_GEI:
    *yield = (strcmpic(sub[0], sub[1]) >= 0) == testfor;
    break;

    case ECOND_MATCH:   /* Regular expression match */
    re = pcre_compile(CS sub[1], PCRE_COPT, (const char **)&rerror, &roffset,
      NULL);
    if (re == NULL)
      {
      expand_string_message = string_sprintf("regular expression error in "
        "\"%s\": %s at offset %d", sub[1], rerror, roffset);
      return NULL;
      }
    *yield = regex_match_and_setup(re, sub[0], 0, -1) == testfor;
    break;

    case ECOND_MATCH_ADDRESS:  /* Match in an address list */
    rc = match_address_list(sub[0], TRUE, FALSE, &(sub[1]), NULL, -1, 0, NULL);
    goto MATCHED_SOMETHING;

    case ECOND_MATCH_DOMAIN:   /* Match in a domain list */
    rc = match_isinlist(sub[0], &(sub[1]), 0, &domainlist_anchor, NULL,
      MCL_DOMAIN + MCL_NOEXPAND, TRUE, NULL);
    goto MATCHED_SOMETHING;

    case ECOND_MATCH_LOCAL_PART:
    rc = match_isinlist(sub[0], &(sub[1]), 0, &localpartlist_anchor, NULL,
      MCL_LOCALPART + MCL_NOEXPAND, TRUE, NULL);
    /* Fall through */

    MATCHED_SOMETHING:
    switch(rc)
      {
      case OK:
      *yield = testfor;
      break;

      case FAIL:
      *yield = !testfor;
      break;

      case DEFER:
      expand_string_message = string_sprintf("unable to complete match "
        "against \"%s\": %s", sub[1], search_error_message);
      return NULL;
      }

    break;

    /* Various "encrypted" comparisons. If the second string starts with
    "{" then an encryption type is given. Default to crypt() or crypt16()
    (build-time choice). */

    case ECOND_CRYPTEQ:
    #ifndef SUPPORT_CRYPTEQ
    goto COND_FAILED_NOT_COMPILED;
    #else
    if (strncmpic(sub[1], US"{md5}", 5) == 0)
      {
      int sublen = Ustrlen(sub[1]+5);
      md5 base;
      uschar digest[16];

      md5_start(&base);
      md5_end(&base, (uschar *)sub[0], Ustrlen(sub[0]), digest);

      /* If the length that we are comparing against is 24, the MD5 digest
      is expressed as a base64 string. This is the way LDAP does it. However,
      some other software uses a straightforward hex representation. We assume
      this if the length is 32. Other lengths fail. */

      if (sublen == 24)
        {
        uschar *coded = auth_b64encode((uschar *)digest, 16);
        DEBUG(D_auth) debug_printf("crypteq: using MD5+B64 hashing\n"
          "  subject=%s\n  crypted=%s\n", coded, sub[1]+5);
        *yield = (Ustrcmp(coded, sub[1]+5) == 0) == testfor;
        }
      else if (sublen == 32)
        {
        int i;
        uschar coded[36];
        for (i = 0; i < 16; i++) sprintf(CS (coded+2*i), "%02X", digest[i]);
        coded[32] = 0;
        DEBUG(D_auth) debug_printf("crypteq: using MD5+hex hashing\n"
          "  subject=%s\n  crypted=%s\n", coded, sub[1]+5);
        *yield = (strcmpic(coded, sub[1]+5) == 0) == testfor;
        }
      else
        {
        DEBUG(D_auth) debug_printf("crypteq: length for MD5 not 24 or 32: "
          "fail\n  crypted=%s\n", sub[1]+5);
        *yield = !testfor;
        }
      }

    else if (strncmpic(sub[1], US"{sha1}", 6) == 0)
      {
      int sublen = Ustrlen(sub[1]+6);
      sha1 base;
      uschar digest[20];

      sha1_start(&base);
      sha1_end(&base, (uschar *)sub[0], Ustrlen(sub[0]), digest);

      /* If the length that we are comparing against is 28, assume the SHA1
      digest is expressed as a base64 string. If the length is 40, assume a
      straightforward hex representation. Other lengths fail. */

      if (sublen == 28)
        {
        uschar *coded = auth_b64encode((uschar *)digest, 20);
        DEBUG(D_auth) debug_printf("crypteq: using SHA1+B64 hashing\n"
          "  subject=%s\n  crypted=%s\n", coded, sub[1]+6);
        *yield = (Ustrcmp(coded, sub[1]+6) == 0) == testfor;
        }
      else if (sublen == 40)
        {
        int i;
        uschar coded[44];
        for (i = 0; i < 20; i++) sprintf(CS (coded+2*i), "%02X", digest[i]);
        coded[40] = 0;
        DEBUG(D_auth) debug_printf("crypteq: using SHA1+hex hashing\n"
          "  subject=%s\n  crypted=%s\n", coded, sub[1]+6);
        *yield = (strcmpic(coded, sub[1]+6) == 0) == testfor;
        }
      else
        {
        DEBUG(D_auth) debug_printf("crypteq: length for SHA-1 not 28 or 40: "
          "fail\n  crypted=%s\n", sub[1]+6);
        *yield = !testfor;
        }
      }

    else   /* {crypt} or {crypt16} and non-{ at start */
      {
      int which = 0;
      uschar *coded;

      if (strncmpic(sub[1], US"{crypt}", 7) == 0)
        {
        sub[1] += 7;
        which = 1;
        }
      else if (strncmpic(sub[1], US"{crypt16}", 9) == 0)
        {
        sub[1] += 9;
        which = 2;
        }
      else if (sub[1][0] == '{')
        {
        expand_string_message = string_sprintf("unknown encryption mechanism "
          "in \"%s\"", sub[1]);
        return NULL;
        }

      switch(which)
        {
        case 0:  coded = US DEFAULT_CRYPT(CS sub[0], CS sub[1]); break;
        case 1:  coded = US crypt(CS sub[0], CS sub[1]); break;
        default: coded = US crypt16(CS sub[0], CS sub[1]); break;
        }

      #define STR(s) # s
      #define XSTR(s) STR(s)
      DEBUG(D_auth) debug_printf("crypteq: using %s()\n"
        "  subject=%s\n  crypted=%s\n",
        (which == 0)? XSTR(DEFAULT_CRYPT) : (which == 1)? "crypt" : "crypt16",
        coded, sub[1]);
      #undef STR
      #undef XSTR

      /* If the encrypted string contains fewer than two characters (for the
      salt), force failure. Otherwise we get false positives: with an empty
      string the yield of crypt() is an empty string! */

      *yield = (Ustrlen(sub[1]) < 2)? !testfor :
        (Ustrcmp(coded, sub[1]) == 0) == testfor;
      }
    break;
    #endif  /* SUPPORT_CRYPTEQ */
    }   /* Switch for comparison conditions */

  return s;    /* End of comparison conditions */


  /* and/or: computes logical and/or of several conditions */

  case ECOND_AND:
  case ECOND_OR:
  subcondptr = (yield == NULL)? NULL : &tempcond;
  combined_cond = (cond_type == ECOND_AND);

  while (isspace(*s)) s++;
  if (*s++ != '{') goto COND_FAILED_CURLY_START;

  for (;;)
    {
    while (isspace(*s)) s++;
    if (*s == '}') break;
    if (*s != '{')
      {
      expand_string_message = string_sprintf("each subcondition "
        "inside an \"%s{...}\" condition must be in its own {}", name);
      return NULL;
      }

    s = eval_condition(s+1, subcondptr);
    if (s == NULL)
      {
      expand_string_message = string_sprintf("%s inside \"%s{...}\" condition",
        expand_string_message, name);
      return NULL;
      }
    while (isspace(*s)) s++;

    if (*s++ != '}')
      {
      expand_string_message = string_sprintf("missing } at end of condition "
        "inside \"%s\" group", name);
      return NULL;
      }

    if (yield != NULL)
      {
      if (cond_type == ECOND_AND)
        {
        combined_cond &= tempcond;
        if (!combined_cond) subcondptr = NULL;  /* once false, don't */
        }                                       /* evaluate any more */
      else
        {
        combined_cond |= tempcond;
        if (combined_cond) subcondptr = NULL;   /* once true, don't */
        }                                       /* evaluate any more */
      }
    }

  if (yield != NULL) *yield = (combined_cond == testfor);
  return ++s;


  /* Unknown condition */

  default:
  expand_string_message = string_sprintf("unknown condition \"%s\"", name);
  return NULL;
  }   /* End switch on condition type */

/* Missing braces at start and end of data */

COND_FAILED_CURLY_START:
expand_string_message = string_sprintf("missing { after \"%s\"", name);
return NULL;

COND_FAILED_CURLY_END:
expand_string_message = string_sprintf("missing } at end of \"%s\" condition",
  name);
return NULL;

/* A condition requires code that is not compiled */

#if !defined(SUPPORT_PAM) || !defined(RADIUS_CONFIG_FILE) || \
    !defined(LOOKUP_LDAP) || !defined(CYRUS_PWCHECK_SOCKET) || \
    !defined(SUPPORT_CRYPTEQ) || !defined(CYRUS_SASLAUTHD_SOCKET)
COND_FAILED_NOT_COMPILED:
expand_string_message = string_sprintf("support for \"%s\" not compiled",
  name);
return NULL;
#endif
}




/*************************************************
*          Save numerical variables              *
*************************************************/

/* This function is called from items such as "if" that want to preserve and
restore the numbered variables.

Arguments:
  save_expand_string    points to an array of pointers to set
  save_expand_nlength   points to an array of ints for the lengths

Returns:                the value of expand max to save
*/

static int
save_expand_strings(uschar **save_expand_nstring, int *save_expand_nlength)
{
int i;
for (i = 0; i <= expand_nmax; i++)
  {
  save_expand_nstring[i] = expand_nstring[i];
  save_expand_nlength[i] = expand_nlength[i];
  }
return expand_nmax;
}



/*************************************************
*           Restore numerical variables          *
*************************************************/

/* This function restored saved values of numerical strings.

Arguments:
  save_expand_nmax      the number of strings to restore
  save_expand_string    points to an array of pointers
  save_expand_nlength   points to an array of ints

Returns:                nothing
*/

static void
restore_expand_strings(int save_expand_nmax, uschar **save_expand_nstring,
  int *save_expand_nlength)
{
int i;
expand_nmax = save_expand_nmax;
for (i = 0; i <= expand_nmax; i++)
  {
  expand_nstring[i] = save_expand_nstring[i];
  expand_nlength[i] = save_expand_nlength[i];
  }
}





/*************************************************
*            Handle yes/no substrings            *
*************************************************/

/* This function is used by ${if}, ${lookup} and ${extract} to handle the
alternative substrings that depend on whether or not the condition was true,
or the lookup or extraction succeeded. The substrings always have to be
expanded, to check their syntax, but "skipping" is set when the result is not
needed - this avoids unnecessary nested lookups.

Arguments:
  skipping       TRUE if we were skipping when this item was reached
  yes            TRUE if the first string is to be used, else use the second
  save_lookup    a value to put back into lookup_value before the 2nd expansion
  sptr           points to the input string pointer
  yieldptr       points to the output string pointer
  sizeptr        points to the output string size
  ptrptr         points to the output string pointer
  type           "lookup" or "if" or "extract" or "run", for error message

Returns:         0 OK; lookup_value has been reset to save_lookup
                 1 expansion failed
                 2 expansion failed because of bracketing error
*/

static int
process_yesno(BOOL skipping, BOOL yes, uschar *save_lookup, uschar **sptr,
  uschar **yieldptr, int *sizeptr, int *ptrptr, uschar *type)
{
int rc = 0;
uschar *s = *sptr;    /* Local value */
uschar *sub1, *sub2;

/* If there are no following strings, we substitute the contents of $value for
lookups and for extractions in the success case. For the ${if item, the string
"true" is substituted. In the fail case, nothing is substituted for all three
items. */

while (isspace(*s)) s++;
if (*s == '}')
  {
  if (type[0] == 'i')
    {
    if (yes) *yieldptr = string_cat(*yieldptr, sizeptr, ptrptr, US"true", 4);
    }
  else
    {
    if (yes && lookup_value != NULL)
      *yieldptr = string_cat(*yieldptr, sizeptr, ptrptr, lookup_value,
        Ustrlen(lookup_value));
    lookup_value = save_lookup;
    }
  s++;
  goto RETURN;
  }

/* Expand the first substring. Forced failures are noticed only if we actually
want this string. Set skipping in the call in the fail case (this will always
be the case if we were already skipping). */

sub1 = expand_string_internal(s+1, TRUE, &s, !yes);
if (sub1 == NULL && (yes || !expand_string_forcedfail)) goto FAILED;
expand_string_forcedfail = FALSE;
if (*s++ != '}') goto FAILED_CURLY;

/* If we want the first string, add it to the output */

if (yes)
  *yieldptr = string_cat(*yieldptr, sizeptr, ptrptr, sub1, Ustrlen(sub1));

/* If this is called from a lookup or an extract, we want to restore $value to
what it was at the start of the item, so that it has this value during the
second string expansion. For the call from "if" or "run" to this function,
save_lookup is set to lookup_value, so that this statement does nothing. */

lookup_value = save_lookup;

/* There now follows either another substring, or "fail", or nothing. This
time, forced failures are noticed only if we want the second string. We must
set skipping in the nested call if we don't want this string, or if we were
already skipping. */

while (isspace(*s)) s++;
if (*s == '{')
  {
  sub2 = expand_string_internal(s+1, TRUE, &s, yes || skipping);
  if (sub2 == NULL && (!yes || !expand_string_forcedfail)) goto FAILED;
  expand_string_forcedfail = FALSE;
  if (*s++ != '}') goto FAILED_CURLY;

  /* If we want the second string, add it to the output */

  if (!yes)
    *yieldptr = string_cat(*yieldptr, sizeptr, ptrptr, sub2, Ustrlen(sub2));
  }

/* If there is no second string, but the word "fail" is present when the use of
the second string is wanted, set a flag indicating it was a forced failure
rather than a syntactic error. Swallow the terminating } in case this is nested
inside another lookup or if or extract. */

else if (*s != '}')
  {
  uschar name[256];
  s = read_name(name, sizeof(name), s, US"_");
  if (Ustrcmp(name, "fail") == 0)
    {
    if (!yes && !skipping)
      {
      while (isspace(*s)) s++;
      if (*s++ != '}') goto FAILED_CURLY;
      expand_string_message =
        string_sprintf("\"%s\" failed and \"fail\" requested", type);
      expand_string_forcedfail = TRUE;
      goto FAILED;
      }
    }
  else
    {
    expand_string_message =
      string_sprintf("syntax error in \"%s\" item - \"fail\" expected", type);
    goto FAILED;
    }
  }

/* All we have to do now is to check on the final closing brace. */

while (isspace(*s)) s++;
if (*s++ == '}') goto RETURN;

/* Get here if there is a bracketing failure */

FAILED_CURLY:
rc++;

/* Get here for other failures */

FAILED:
rc++;

/* Update the input pointer value before returning */

RETURN:
*sptr = s;
return rc;
}






/*************************************************
*    Handle MD5 or SHA-1 computation for HMAC    *
*************************************************/

/* These are some wrapping functions that enable the HMAC code to be a bit
cleaner. A good compiler will spot the tail recursion.

Arguments:
  type         HMAC_MD5 or HMAC_SHA1
  remaining    are as for the cryptographic hash functions

Returns:       nothing
*/

static void
chash_start(int type, void *base)
{
if (type == HMAC_MD5)
  md5_start((md5 *)base);
else
  sha1_start((sha1 *)base);
}

static void
chash_mid(int type, void *base, uschar *string)
{
if (type == HMAC_MD5)
  md5_mid((md5 *)base, string);
else
  sha1_mid((sha1 *)base, string);
}

static void
chash_end(int type, void *base, uschar *string, int length, uschar *digest)
{
if (type == HMAC_MD5)
  md5_end((md5 *)base, string, length, digest);
else
  sha1_end((sha1 *)base, string, length, digest);
}





/*************************************************
*        Join a file onto the output string      *
*************************************************/

/* This is used for readfile and after a run expansion. It joins the contents
of a file onto the output string, globally replacing newlines with a given
string (optionally). The file is closed at the end.

Arguments:
  f            the FILE
  yield        pointer to the expandable string
  sizep        pointer to the current size
  ptrp         pointer to the current position
  eol          newline replacement string, or NULL

Returns:       new value of string pointer
*/

static uschar *
cat_file(FILE *f, uschar *yield, int *sizep, int *ptrp, uschar *eol)
{
int eollen;
uschar buffer[1024];

eollen = (eol == NULL)? 0 : Ustrlen(eol);

while (Ufgets(buffer, sizeof(buffer), f) != NULL)
  {
  int len = Ustrlen(buffer);
  if (eol != NULL && buffer[len-1] == '\n') len--;
  yield = string_cat(yield, sizep, ptrp, buffer, len);
  if (buffer[len] != 0)
    yield = string_cat(yield, sizep, ptrp, eol, eollen);
  }

if (yield != NULL) yield[*ptrp] = 0;

return yield;
}




/*************************************************
*          Evaluate numeric expression           *
*************************************************/

/* This is a set of mutually recursive functions that evaluate a simple
arithmetic expression involving only + - * / and parentheses. The only one that
is called from elsewhere is eval_expr, whose interface is:

Arguments:
  sptr          pointer to the pointer to the string - gets updated
  decimal       TRUE if numbers are to be assumed decimal
  error         pointer to where to put an error message - must be NULL on input
  endket        TRUE if ')' must terminate - FALSE for external call


Returns:        on success: the value of the expression, with *error still NULL
                on failure: an undefined value, with *error = a message
*/

static int eval_sumterm(uschar **, BOOL, uschar **);

static int
eval_expr(uschar **sptr, BOOL decimal, uschar **error, BOOL endket)
{
uschar *s = *sptr;
int x = eval_sumterm(&s, decimal, error);
if (*error == NULL)
  {
  while (*s == '+' || *s == '-')
    {
    int op = *s++;
    int y = eval_sumterm(&s, decimal, error);
    if (*error != NULL) break;
    if (op == '+') x += y; else x -= y;
    }
  if (*error == NULL)
    {
    if (endket)
      {
      if (*s != ')')
        *error = US"expecting closing parenthesis";
      else
        while (isspace(*(++s)));
      }
    else if (*s != 0) *error = US"expecting + or -";
    }
  }

*sptr = s;
return x;
}

static int
eval_term(uschar **sptr, BOOL decimal, uschar **error)
{
register int c;
int n;
uschar *s = *sptr;
while (isspace(*s)) s++;
c = *s;
if (isdigit(c) || ((c == '-' || c == '+') && isdigit(s[1])))
  {
  int count;
  (void)sscanf(CS s, (decimal? "%d%n" : "%i%n"), &n, &count);
  s += count;
  if (tolower(*s) == 'k') { n *= 1024; s++; }
    else if (tolower(*s) == 'm') { n *= 1024*1024; s++; }
  while (isspace (*s)) s++;
  }
else if (c == '(')
  {
  s++;
  n = eval_expr(&s, decimal, error, 1);
  }
else
  {
  *error = US"expecting number or opening parenthesis";
  n = 0;
  }
*sptr = s;
return n;
}

static int eval_sumterm(uschar **sptr, BOOL decimal, uschar **error)
{
uschar *s = *sptr;
int x = eval_term(&s, decimal, error);
if (*error == NULL)
  {
  while (*s == '*' || *s == '/')
    {
    int op = *s++;
    int y = eval_term(&s, decimal, error);
    if (*error != NULL) break;
    if (op == '*') x *= y; else x /= y;
    }
  }
*sptr = s;
return x;
}




/*************************************************
*                 Expand string                  *
*************************************************/

/* Returns either an unchanged string, or the expanded string in stacking pool
store. Interpreted sequences are:

   \...                    normal escaping rules
   $name                   substitutes the variable
   ${name}                 ditto
   ${op:string}            operates on the expanded string value
   ${item{arg1}{arg2}...}  expands the args and then does the business
                             some literal args are not enclosed in {}

There are now far too many operators and item types to make it worth listing
them here in detail any more.

We use an internal routine recursively to handle embedded substrings. The
external function follows. The yield is NULL if the expansion failed, and there
are two cases: if something collapsed syntactically, or if "fail" was given
as the action on a lookup failure. These can be distinguised by looking at the
variable expand_string_forcedfail, which is TRUE in the latter case.

The skipping flag is set true when expanding a substring that isn't actually
going to be used (after "if" or "lookup") and it prevents lookups from
happening lower down.

Store usage: At start, a store block of the length of the input plus 64
is obtained. This is expanded as necessary by string_cat(), which might have to
get a new block, or might be able to expand the original. At the end of the
function we can release any store above that portion of the yield block that
was actually used. In many cases this will be optimal.

However: if the first item in the expansion is a variable name or header name,
we reset the store before processing it; if the result is in fresh store, we
use that without copying. This is helpful for expanding strings like
$message_headers which can get very long.

Arguments:
  string         the string to be expanded
  ket_ends       true if expansion is to stop at }
  left           if not NULL, a pointer to the first character after the
                 expansion is placed here (typically used with ket_ends)
  skipping       TRUE for recursive calls when the value isn't actually going
                 to be used (to allow for optimisation)

Returns:         NULL if expansion fails:
                   expand_string_forcedfail is set TRUE if failure was forced
                   expand_string_message contains a textual error message
                 a pointer to the expanded string on success
*/

static uschar *
expand_string_internal(uschar *string, BOOL ket_ends, uschar **left,
  BOOL skipping)
{
int ptr = 0;
int size = Ustrlen(string)+ 64;
int item_type;
uschar *yield = store_get(size);
uschar *s = string;
uschar *save_expand_nstring[EXPAND_MAXN+1];
int save_expand_nlength[EXPAND_MAXN+1];

expand_string_forcedfail = FALSE;
expand_string_message = US"";

while (*s != 0)
  {
  uschar *value;
  uschar name[256];

  /* \ escapes the next character, which must exist, or else
  the expansion fails. There's a special escape, \N, which causes
  copying of the subject verbatim up to the next \N. Otherwise,
  the escapes are the standard set. */

  if (*s == '\\')
    {
    if (s[1] == 0)
      {
      expand_string_message = US"\\ at end of string";
      goto EXPAND_FAILED;
      }

    if (s[1] == 'N')
      {
      uschar *t = s + 2;
      for (s = t; *s != 0; s++) if (*s == '\\' && s[1] == 'N') break;
      yield = string_cat(yield, &size, &ptr, t, s - t);
      if (*s != 0) s += 2;
      }

    else
      {
      uschar ch[1];
      ch[0] = string_interpret_escape(&s);
      s++;
      yield = string_cat(yield, &size, &ptr, ch, 1);
      }

    continue;
    }

  /* Anything other than $ is just copied verbatim, unless we are
  looking for a terminating } character. */

  if (ket_ends && *s == '}') break;

  if (*s != '$')
    {
    yield = string_cat(yield, &size, &ptr, s++, 1);
    continue;
    }

  /* No { after the $ - must be a plain name or a number for string
  match variable. There has to be a fudge for variables that are the
  names of header fields preceded by "$header_" because header field
  names can contain any printing characters except space and colon.
  For those that don't like typing this much, "$h_" is a synonym for
  "$header_". A non-existent header yields a NULL value; nothing is
  inserted. */

  if (isalpha((*(++s))))
    {
    int len;
    int newsize = 0;

    s = read_name(name, sizeof(name), s, US"_");

    /* If this is the first thing to be expanded, release the pre-allocated
    buffer. */

    if (ptr == 0 && yield != NULL)
      {
      store_reset(yield);
      yield = NULL;
      size = 0;
      }

    /* Header */

    if (Ustrncmp(name, "h_", 2) == 0 ||
        Ustrncmp(name, "rh_", 3) == 0 ||
        Ustrncmp(name, "bh_", 3) == 0 ||
        Ustrncmp(name, "header_", 7) == 0 ||
        Ustrncmp(name, "rheader_", 8) == 0 ||
        Ustrncmp(name, "bheader_", 8) == 0)
      {
      BOOL want_raw = (name[0] == 'r')? TRUE : FALSE;
      uschar *charset = (name[0] == 'b')? NULL : headers_charset;
      s = read_header_name(name, sizeof(name), s);
      value = find_header(name, FALSE, &newsize, want_raw, charset);

      /* If we didn't find the header, and the header contains a closing brace
      characters, this may be a user error where the terminating colon
      has been omitted. Set a flag to adjust the error message in this case.
      But there is no error here - nothing gets inserted. */

      if (value == NULL)
        {
        if (Ustrchr(name, '}') != NULL) malformed_header = TRUE;
        continue;
        }
      }

    /* Variable */

    else
      {
      value = find_variable(name, FALSE, skipping, &newsize);
      if (value == NULL)
        {
        expand_string_message =
          string_sprintf("unknown variable name \"%s\"", name);
        goto EXPAND_FAILED;
        }
      }

    /* If the data is known to be in a new buffer, newsize will be set to the
    size of that buffer. If this is the first thing in an expansion string,
    yield will be NULL; just point it at the new store instead of copying. Many
    expansion strings contain just one reference, so this is a useful
    optimization, especially for humungous headers. */

    len = Ustrlen(value);
    if (yield == NULL && newsize != 0)
      {
      yield = value;
      size = newsize;
      ptr = len;
      }
    else yield = string_cat(yield, &size, &ptr, value, len);

    continue;
    }

  if (isdigit(*s))
    {
    int n;
    s = read_number(&n, s);
    if (n >= 0 && n <= expand_nmax)
      yield = string_cat(yield, &size, &ptr, expand_nstring[n],
        expand_nlength[n]);
    continue;
    }

  /* Otherwise, if there's no '{' after $ it's an error. */

  if (*s != '{')
    {
    expand_string_message = US"$ not followed by letter, digit, or {";
    goto EXPAND_FAILED;
    }

  /* After { there can be various things, but they all start with
  an initial word, except for a number for a string match variable. */

  if (isdigit((*(++s))))
    {
    int n;
    s = read_number(&n, s);
    if (*s++ != '}')
      {
      expand_string_message = US"} expected after number";
      goto EXPAND_FAILED;
      }
    if (n >= 0 && n <= expand_nmax)
      yield = string_cat(yield, &size, &ptr, expand_nstring[n],
        expand_nlength[n]);
    continue;
    }

  if (!isalpha(*s))
    {
    expand_string_message = US"letter or digit expected after ${";
    goto EXPAND_FAILED;
    }

  /* Allow "-" in names to cater for substrings with negative
  arguments. Since we are checking for known names after { this is
  OK. */

  s = read_name(name, sizeof(name), s, US"_-");
  item_type = chop_match(name, item_table, sizeof(item_table)/sizeof(uschar *));

  switch(item_type)
    {
    /* Handle conditionals - preserve the values of the numerical expansion
    variables in case they get changed by a regular expression match in the
    condition. If not, they retain their external settings. At the end
    of this "if" section, they get restored to their previous values. */

    case EITEM_IF:
      {
      BOOL cond = FALSE;
      uschar *next_s;
      int save_expand_nmax =
        save_expand_strings(save_expand_nstring, save_expand_nlength);

      while (isspace(*s)) s++;
      next_s = eval_condition(s, skipping? NULL : &cond);
      if (next_s == NULL) goto EXPAND_FAILED;  /* message already set */

      DEBUG(D_expand)
        debug_printf("condition: %.*s\n   result: %s\n", (int)(next_s - s), s,
          cond? "true" : "false");

      s = next_s;

      /* The handling of "yes" and "no" result strings is now in a separate
      function that is also used by ${lookup} and ${extract} and ${run}. */

      switch(process_yesno(
               skipping,                     /* were previously skipping */
               cond,                         /* success/failure indicator */
               lookup_value,                 /* value to reset for string2 */
               &s,                           /* input pointer */
               &yield,                       /* output pointer */
               &size,                        /* output size */
               &ptr,                         /* output current point */
               US"if"))                      /* condition type */
        {
        case 1: goto EXPAND_FAILED;          /* when all is well, the */
        case 2: goto EXPAND_FAILED_CURLY;    /* returned value is 0 */
        }

      /* Restore external setting of expansion variables for continuation
      at this level. */

      restore_expand_strings(save_expand_nmax, save_expand_nstring,
        save_expand_nlength);
      continue;
      }

    /* Handle database lookups unless locked out. If "skipping" is TRUE, we are
    expanding an internal string that isn't actually going to be used. All we
    need to do is check the syntax, so don't do a lookup at all. Preserve the
    values of the numerical expansion variables in case they get changed by a
    partial lookup. If not, they retain their external settings. At the end
    of this "lookup" section, they get restored to their previous values. */

    case EITEM_LOOKUP:
      {
      int stype, partial, affixlen, starflags;
      int expand_setup = 0;
      int nameptr = 0;
      uschar *key, *filename, *affix;
      uschar *save_lookup_value = lookup_value;
      int save_expand_nmax =
        save_expand_strings(save_expand_nstring, save_expand_nlength);

      if ((expand_forbid & RDO_LOOKUP) != 0)
        {
        expand_string_message = US"lookup expansions are not permitted";
        goto EXPAND_FAILED;
        }

      /* Get the key we are to look up for single-key+file style lookups.
      Otherwise set the key NULL pro-tem. */

      while (isspace(*s)) s++;
      if (*s == '{')
        {
        key = expand_string_internal(s+1, TRUE, &s, skipping);
        if (key == NULL) goto EXPAND_FAILED;
        if (*s++ != '}') goto EXPAND_FAILED_CURLY;
        while (isspace(*s)) s++;
        }
      else key = NULL;

      /* Find out the type of database */

      if (!isalpha(*s))
        {
        expand_string_message = US"missing lookup type";
        goto EXPAND_FAILED;
        }

      /* The type is a string that may contain special characters of various
      kinds. Allow everything except space or { to appear; the actual content
      is checked by search_findtype_partial. */

      while (*s != 0 && *s != '{' && !isspace(*s))
        {
        if (nameptr < sizeof(name) - 1) name[nameptr++] = *s;
        s++;
        }
      name[nameptr] = 0;
      while (isspace(*s)) s++;

      /* Now check for the individual search type and any partial or default
      options. Only those types that are actually in the binary are valid. */

      stype = search_findtype_partial(name, &partial, &affix, &affixlen,
        &starflags);
      if (stype < 0)
        {
        expand_string_message = search_error_message;
        goto EXPAND_FAILED;
        }

      /* Check that a key was provided for those lookup types that need it,
      and was not supplied for those that use the query style. */

      if (!mac_islookup(stype, lookup_querystyle))
        {
        if (key == NULL)
          {
          expand_string_message = string_sprintf("missing {key} for single-"
            "key \"%s\" lookup", name);
          goto EXPAND_FAILED;
          }
        }
      else
        {
        if (key != NULL)
          {
          expand_string_message = string_sprintf("a single key was given for "
            "lookup type \"%s\", which is not a single-key lookup type", name);
          goto EXPAND_FAILED;
          }
        }

      /* Get the next string in brackets and expand it. It is the file name for
      single-key+file lookups, and the whole query otherwise. */

      if (*s != '{') goto EXPAND_FAILED_CURLY;
      filename = expand_string_internal(s+1, TRUE, &s, skipping);
      if (filename == NULL) goto EXPAND_FAILED;
      if (*s++ != '}') goto EXPAND_FAILED_CURLY;
      while (isspace(*s)) s++;

      /* If this isn't a single-key+file lookup, re-arrange the variables
      to be appropriate for the search_ functions. */

      if (key == NULL)
        {
        key = filename;
        filename = NULL;
        }

      /* If skipping, don't do the next bit - just lookup_value == NULL, as if
      the entry was not found. Note that there is no search_close() function.
      Files are left open in case of re-use. At suitable places in higher logic,
      search_tidyup() is called to tidy all open files. This can save opening
      the same file several times. However, files may also get closed when
      others are opened, if too many are open at once. The rule is that a
      handle should not be used after a second search_open().

      Request that a partial search sets up $1 and maybe $2 by passing
      expand_setup containing zero. If its value changes, reset expand_nmax,
      since new variables will have been set. Note that at the end of this
      "lookup" section, the old numeric variables are restored. */

      if (skipping)
        lookup_value = NULL;
      else
        {
        void *handle = search_open(filename, stype, 0, NULL, NULL);
        if (handle == NULL)
          {
          expand_string_message = search_error_message;
          goto EXPAND_FAILED;
          }
        lookup_value = search_find(handle, filename, key, partial, affix,
          affixlen, starflags, &expand_setup);
        if (search_find_defer)
          {
          expand_string_message =
            string_sprintf("lookup of \"%s\" gave DEFER: %s", key,
              search_error_message);
          goto EXPAND_FAILED;
          }
        if (expand_setup > 0) expand_nmax = expand_setup;
        }

      /* The handling of "yes" and "no" result strings is now in a separate
      function that is also used by ${if} and ${extract}. */

      switch(process_yesno(
               skipping,                     /* were previously skipping */
               lookup_value != NULL,         /* success/failure indicator */
               save_lookup_value,            /* value to reset for string2 */
               &s,                           /* input pointer */
               &yield,                       /* output pointer */
               &size,                        /* output size */
               &ptr,                         /* output current point */
               US"lookup"))                  /* condition type */
        {
        case 1: goto EXPAND_FAILED;          /* when all is well, the */
        case 2: goto EXPAND_FAILED_CURLY;    /* returned value is 0 */
        }

      /* Restore external setting of expansion variables for carrying on
      at this level, and continue. */

      restore_expand_strings(save_expand_nmax, save_expand_nstring,
        save_expand_nlength);
      continue;
      }

    /* If Perl support is configured, handle calling embedded perl subroutines,
    unless locked out at this time. Syntax is ${perl{sub}} or ${perl{sub}{arg}}
    or ${perl{sub}{arg1}{arg2}} or up to a maximum of EXIM_PERL_MAX_ARGS
    arguments (defined below). */

    #define EXIM_PERL_MAX_ARGS 8

    case EITEM_PERL:
    #ifndef EXIM_PERL
    expand_string_message = US"\"${perl\" encountered, but this facility "
      "is not included in this binary";
    goto EXPAND_FAILED;

    #else   /* EXIM_PERL */
      {
      uschar *sub_arg[EXIM_PERL_MAX_ARGS + 2];
      uschar *new_yield;

      if ((expand_forbid & RDO_PERL) != 0)
        {
        expand_string_message = US"Perl calls are not permitted";
        goto EXPAND_FAILED;
        }

      switch(read_subs(sub_arg, EXIM_PERL_MAX_ARGS + 1, 1, &s, skipping, TRUE,
           US"perl"))
        {
        case 1: goto EXPAND_FAILED_CURLY;
        case 2:
        case 3: goto EXPAND_FAILED;
        }

      /* If skipping, we don't actually do anything */

      if (skipping) continue;

      /* Start the interpreter if necessary */

      if (!opt_perl_started)
        {
        uschar *initerror;
        if (opt_perl_startup == NULL)
          {
          expand_string_message = US"A setting of perl_startup is needed when "
            "using the Perl interpreter";
          goto EXPAND_FAILED;
          }
        DEBUG(D_any) debug_printf("Starting Perl interpreter\n");
        initerror = init_perl(opt_perl_startup);
        if (initerror != NULL)
          {
          expand_string_message =
            string_sprintf("error in perl_startup code: %s\n", initerror);
          goto EXPAND_FAILED;
          }
        opt_perl_started = TRUE;
        }

      /* Call the function */

      sub_arg[EXIM_PERL_MAX_ARGS + 1] = NULL;
      new_yield = call_perl_cat(yield, &size, &ptr, &expand_string_message,
        sub_arg[0], sub_arg + 1);

      /* NULL yield indicates failure; if the message pointer has been set to
      NULL, the yield was undef, indicating a forced failure. Otherwise the
      message will indicate some kind of Perl error. */

      if (new_yield == NULL)
        {
        if (expand_string_message == NULL)
          {
          expand_string_message =
            string_sprintf("Perl subroutine \"%s\" returned undef to force "
              "failure", sub_arg[0]);
          expand_string_forcedfail = TRUE;
          }
        goto EXPAND_FAILED;
        }

      /* Yield succeeded. Ensure forcedfail is unset, just in case it got
      set during a callback from Perl. */

      expand_string_forcedfail = FALSE;
      yield = new_yield;
      continue;
      }
    #endif /* EXIM_PERL */

    /* Handle "readfile" to insert an entire file */

    case EITEM_READFILE:
      {
      FILE *f;
      uschar *sub_arg[2];

      if ((expand_forbid & RDO_READFILE) != 0)
        {
        expand_string_message = US"file insertions are not permitted";
        goto EXPAND_FAILED;
        }

      switch(read_subs(sub_arg, 2, 1, &s, skipping, TRUE, US"readfile"))
        {
        case 1: goto EXPAND_FAILED_CURLY;
        case 2:
        case 3: goto EXPAND_FAILED;
        }

      /* If skipping, we don't actually do anything */

      if (skipping) continue;

      /* Open the file and read it */

      f = Ufopen(sub_arg[0], "rb");
      if (f == NULL)
        {
        expand_string_message = string_open_failed(errno, "%s", sub_arg[0]);
        goto EXPAND_FAILED;
        }

      yield = cat_file(f, yield, &size, &ptr, sub_arg[1]);
      fclose(f);
      continue;
      }

    /* Handle "readsocket" to insert data from a Unix domain socket */

    case EITEM_READSOCK:
      {
      int fd;
      int timeout = 5;
      int save_ptr = ptr;
      FILE *f;
      struct sockaddr_un sockun;         /* don't call this "sun" ! */
      uschar *arg;
      uschar *sub_arg[4];

      if ((expand_forbid & RDO_READSOCK) != 0)
        {
        expand_string_message = US"socket insertions are not permitted";
        goto EXPAND_FAILED;
        }

      /* Read up to 4 arguments, but don't do the end of item check afterwards,
      because there may be a string for expansion on failure. */

      switch(read_subs(sub_arg, 4, 2, &s, skipping, FALSE, US"readsocket"))
        {
        case 1: goto EXPAND_FAILED_CURLY;
        case 2:                             /* Won't occur: no end check */
        case 3: goto EXPAND_FAILED;
        }

      /* Sort out timeout, if given */

      if (sub_arg[2] != NULL)
        {
        timeout = readconf_readtime(sub_arg[2], 0, FALSE);
        if (timeout < 0)
          {
          expand_string_message = string_sprintf("bad time value %s",
            sub_arg[2]);
          goto EXPAND_FAILED;
          }
        }
      else sub_arg[3] = NULL;                     /* No eol if no timeout */

      /* If skipping, we don't actually do anything */

      if (!skipping)
        {
        /* Make a connection to the socket */

        if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
          {
          expand_string_message = string_sprintf("failed to create socket: %s",
            strerror(errno));
          goto SOCK_FAIL;
          }

        sockun.sun_family = AF_UNIX;
        sprintf(sockun.sun_path, "%.*s", (int)(sizeof(sockun.sun_path)-1),
          sub_arg[0]);
        if(connect(fd, (struct sockaddr *)(&sockun), sizeof(sockun)) == -1)
          {
          expand_string_message = string_sprintf("failed to connect to socket "
            "%s: %s", sub_arg[0], strerror(errno));
          goto SOCK_FAIL;
          }
        DEBUG(D_expand) debug_printf("connected to socket %s\n", sub_arg[0]);

        /* Write the request string, if not empty */

        if (sub_arg[1][0] != 0)
          {
          int len = Ustrlen(sub_arg[1]);
          DEBUG(D_expand) debug_printf("writing \"%s\" to socket\n",
            sub_arg[1]);
          if (write(fd, sub_arg[1], len) != len)
            {
            expand_string_message = string_sprintf("request write to socket "
              "failed: %s", strerror(errno));
            goto SOCK_FAIL;
            }
          }

        /* Now we need to read from the socket, under a timeout. The function
        that reads a file can be used. */

        f = fdopen(fd, "rb");
        sigalrm_seen = FALSE;
        alarm(timeout);
        yield = cat_file(f, yield, &size, &ptr, sub_arg[3]);
        alarm(0);
        fclose(f);

        /* After a timeout, we restore the pointer in the result, that is,
        make sure we add nothing from the socket. */

        if (sigalrm_seen)
          {
          ptr = save_ptr;
          expand_string_message = US"socket read timed out";
          goto SOCK_FAIL;
          }
        }

      /* The whole thing has worked (or we were skipping). If there is a
      failure string following, we need to skip it. */

      if (*s == '{')
        {
        if (expand_string_internal(s+1, TRUE, &s, TRUE) == NULL)
          goto EXPAND_FAILED;
        if (*s++ != '}') goto EXPAND_FAILED_CURLY;
        while (isspace(*s)) s++;
        }
      if (*s++ != '}') goto EXPAND_FAILED_CURLY;
      continue;

      /* Come here on failure to create socket, connect socket, write to the
      socket, or timeout on reading. If another substring follows, expand and
      use it. Otherwise, those conditions give expand errors. */

      SOCK_FAIL:
      if (*s != '{') goto EXPAND_FAILED;
      DEBUG(D_any) debug_printf("%s\n", expand_string_message);
      arg = expand_string_internal(s+1, TRUE, &s, FALSE);
      if (arg == NULL) goto EXPAND_FAILED;
      yield = string_cat(yield, &size, &ptr, arg, Ustrlen(arg));
      if (*s++ != '}') goto EXPAND_FAILED_CURLY;
      while (isspace(*s)) s++;
      if (*s++ != '}') goto EXPAND_FAILED_CURLY;
      continue;
      }

    /* Handle "run" to execute a program. */

    case EITEM_RUN:
      {
      FILE *f;
      uschar *arg;
      uschar **argv;
      pid_t pid;
      int fd_in, fd_out;
      int lsize = 0;
      int lptr = 0;

      if ((expand_forbid & RDO_RUN) != 0)
        {
        expand_string_message = US"running a command is not permitted";
        goto EXPAND_FAILED;
        }

      while (isspace(*s)) s++;
      if (*s != '{') goto EXPAND_FAILED_CURLY;
      arg = expand_string_internal(s+1, TRUE, &s, skipping);
      if (arg == NULL) goto EXPAND_FAILED;
      while (isspace(*s)) s++;
      if (*s++ != '}') goto EXPAND_FAILED_CURLY;

      if (skipping)   /* Just pretend it worked when we're skipping */
        {
        runrc = 0;
        }
      else
        {
        if (!transport_set_up_command(&argv,    /* anchor for arg list */
            arg,                                /* raw command */
            FALSE,                              /* don't expand the arguments */
            0,                                  /* not relevant when... */
            NULL,                               /* no transporting address */
            US"${run} expansion",               /* for error messages */
            &expand_string_message))            /* where to put error message */
          {
          goto EXPAND_FAILED;
          }

        /* Create the child process, making it a group leader. */

        pid = child_open(argv, NULL, 0077, &fd_in, &fd_out, TRUE);

        if (pid < 0)
          {
          expand_string_message =
            string_sprintf("couldn't create child process: %s", strerror(errno));
          goto EXPAND_FAILED;
          }

        /* Nothing is written to the standard input. */

        close(fd_in);

        /* Wait for the process to finish, applying the timeout, and inspect its
        return code for serious disasters. Simple non-zero returns are passed on.
        */

        if ((runrc = child_close(pid, 60)) < 0)
          {
          if (runrc == -256)
            {
            expand_string_message = string_sprintf("command timed out");
            killpg(pid, SIGKILL);       /* Kill the whole process group */
            }

          else if (runrc == -257)
            expand_string_message = string_sprintf("wait() failed: %s",
              strerror(errno));

          else
            expand_string_message = string_sprintf("command killed by signal %d",
              -runrc);

          goto EXPAND_FAILED;
          }

        /* Read the pipe to get the command's output into $value (which is kept
        in lookup_value). */

        f = fdopen(fd_out, "rb");
        lookup_value = NULL;
        lookup_value = cat_file(f, lookup_value, &lsize, &lptr, NULL);
        fclose(f);
        }

      /* Process the yes/no strings; $value may be useful in both cases */

      switch(process_yesno(
               skipping,                     /* were previously skipping */
               runrc == 0,                   /* success/failure indicator */
               lookup_value,                 /* value to reset for string2 */
               &s,                           /* input pointer */
               &yield,                       /* output pointer */
               &size,                        /* output size */
               &ptr,                         /* output current point */
               US"run"))                     /* condition type */
        {
        case 1: goto EXPAND_FAILED;          /* when all is well, the */
        case 2: goto EXPAND_FAILED_CURLY;    /* returned value is 0 */
        }

      continue;
      }

    /* Handle character translation for "tr" */

    case EITEM_TR:
      {
      int oldptr = ptr;
      int o2m;
      uschar *sub[3];

      switch(read_subs(sub, 3, 3, &s, skipping, TRUE, US"tr"))
        {
        case 1: goto EXPAND_FAILED_CURLY;
        case 2:
        case 3: goto EXPAND_FAILED;
        }

      yield = string_cat(yield, &size, &ptr, sub[0], Ustrlen(sub[0]));
      o2m = Ustrlen(sub[2]) - 1;

      if (o2m >= 0) for (; oldptr < ptr; oldptr++)
        {
        uschar *m = Ustrrchr(sub[1], yield[oldptr]);
        if (m != NULL)
          {
          int o = m - sub[1];
          yield[oldptr] = sub[2][(o < o2m)? o : o2m];
          }
        }

      continue;
      }

    /* Handle "hash", "length", "nhash", and "substr" when they are given with
    expanded arguments. */

    case EITEM_HASH:
    case EITEM_LENGTH:
    case EITEM_NHASH:
    case EITEM_SUBSTR:
      {
      int i;
      int len;
      uschar *ret;
      int val[2] = { 0, -1 };
      uschar *sub[3];

      /* "length" takes only 2 arguments whereas the others take 2 or 3.
      Ensure that sub[2] is set in the ${length case. */

      sub[2] = NULL;
      switch(read_subs(sub, (item_type == EITEM_LENGTH)? 2:3, 2, &s, skipping,
             TRUE, name))
        {
        case 1: goto EXPAND_FAILED_CURLY;
        case 2:
        case 3: goto EXPAND_FAILED;
        }

      /* Juggle the arguments if there are only two of them: always move the
      string to the last position and make ${length{n}{str}} equivalent to
      ${substr{0}{n}{str}}. See the defaults for val[] above. */

      if (sub[2] == NULL)
        {
        sub[2] = sub[1];
        sub[1] = NULL;
        if (item_type == EITEM_LENGTH)
          {
          sub[1] = sub[0];
          sub[0] = NULL;
          }
        }

      for (i = 0; i < 2; i++)
        {
        if (sub[i] == NULL) continue;
        val[i] = (int)Ustrtol(sub[i], &ret, 10);
        if (*ret != 0 || (i != 0 && val[i] < 0))
          {
          expand_string_message = string_sprintf("\"%s\" is not a%s number "
            "(in \"%s\" expansion)", sub[i], (i != 0)? " positive" : "", name);
          goto EXPAND_FAILED;
          }
        }

      ret =
        (item_type == EITEM_HASH)?
          compute_hash(sub[2], val[0], val[1], &len) :
        (item_type == EITEM_NHASH)?
          compute_nhash(sub[2], val[0], val[1], &len) :
          extract_substr(sub[2], val[0], val[1], &len);

      if (ret == NULL) goto EXPAND_FAILED;
      yield = string_cat(yield, &size, &ptr, ret, len);
      continue;
      }

    /* Handle HMAC computation: ${hmac{<algorithm>}{<secret>}{<text>}}
    This code originally contributed by Steve Haslam. It currently supports
    the use of MD5 and SHA-1 hashes.

    We need some workspace that is large enough to handle all the supported
    hash types. Use macros to set the sizes rather than be too elaborate. */

    #define MAX_HASHLEN      20
    #define MAX_HASHBLOCKLEN 64

    case EITEM_HMAC:
      {
      uschar *sub[3];
      md5 md5_base;
      sha1 sha1_base;
      void *use_base;
      int type, i;
      int hashlen;      /* Number of octets for the hash algorithm's output */
      int hashblocklen; /* Number of octets the hash algorithm processes */
      uschar *keyptr, *p;
      unsigned int keylen;

      uschar keyhash[MAX_HASHLEN];
      uschar innerhash[MAX_HASHLEN];
      uschar finalhash[MAX_HASHLEN];
      uschar finalhash_hex[2*MAX_HASHLEN];
      uschar innerkey[MAX_HASHBLOCKLEN];
      uschar outerkey[MAX_HASHBLOCKLEN];

      switch (read_subs(sub, 3, 3, &s, skipping, TRUE, name))
        {
        case 1: goto EXPAND_FAILED_CURLY;
        case 2:
        case 3: goto EXPAND_FAILED;
        }

      if (Ustrcmp(sub[0], "md5") == 0)
        {
        type = HMAC_MD5;
        use_base = &md5_base;
        hashlen = 16;
        hashblocklen = 64;
        }
      else if (Ustrcmp(sub[0], "sha1") == 0)
        {
        type = HMAC_SHA1;
        use_base = &sha1_base;
        hashlen = 20;
        hashblocklen = 64;
        }
      else
        {
        expand_string_message =
          string_sprintf("hmac algorithm \"%s\" is not recognised", sub[0]);
        goto EXPAND_FAILED;
        }

      keyptr = sub[1];
      keylen = Ustrlen(keyptr);

      /* If the key is longer than the hash block length, then hash the key
      first */

      if (keylen > hashblocklen)
        {
        chash_start(type, use_base);
        chash_end(type, use_base, keyptr, keylen, keyhash);
        keyptr = keyhash;
        keylen = hashlen;
        }

      /* Now make the inner and outer key values */

      memset(innerkey, 0x36, hashblocklen);
      memset(outerkey, 0x5c, hashblocklen);

      for (i = 0; i < keylen; i++)
        {
        innerkey[i] ^= keyptr[i];
        outerkey[i] ^= keyptr[i];
        }

      /* Now do the hashes */

      chash_start(type, use_base);
      chash_mid(type, use_base, innerkey);
      chash_end(type, use_base, sub[2], Ustrlen(sub[2]), innerhash);

      chash_start(type, use_base);
      chash_mid(type, use_base, outerkey);
      chash_end(type, use_base, innerhash, hashlen, finalhash);

      /* Encode the final hash as a hex string */

      p = finalhash_hex;
      for (i = 0; i < hashlen; i++)
        {
        *p++ = hex_digits[(finalhash[i] & 0xf0) >> 4];
        *p++ = hex_digits[finalhash[i] & 0x0f];
        }

      DEBUG(D_any) debug_printf("HMAC[%s](%.*s,%.*s)=%.*s\n", sub[0],
        (int)keylen, keyptr, Ustrlen(sub[2]), sub[2], hashlen*2, finalhash_hex);

      yield = string_cat(yield, &size, &ptr, finalhash_hex, hashlen*2);
      }

    continue;

    /* Handle global substitution for "sg" - like Perl's s/xxx/yyy/g operator.
    We have to save the numerical variables and restore them afterwards. */

    case EITEM_SG:
      {
      const pcre *re;
      int moffset, moffsetextra, slen;
      int roffset;
      int emptyopt;
      const uschar *rerror;
      uschar *subject;
      uschar *sub[3];
      int save_expand_nmax =
        save_expand_strings(save_expand_nstring, save_expand_nlength);

      switch(read_subs(sub, 3, 3, &s, skipping, TRUE, US"sg"))
        {
        case 1: goto EXPAND_FAILED_CURLY;
        case 2:
        case 3: goto EXPAND_FAILED;
        }

      /* Compile the regular expression */

      re = pcre_compile(CS sub[1], PCRE_COPT, (const char **)&rerror, &roffset,
        NULL);

      if (re == NULL)
        {
        expand_string_message = string_sprintf("regular expression error in "
          "\"%s\": %s at offset %d", sub[1], rerror, roffset);
        goto EXPAND_FAILED;
        }

      /* Now run a loop to do the substitutions as often as necessary. It ends
      when there are no more matches. Take care over matches of the null string;
      do the same thing as Perl does. */

      subject = sub[0];
      slen = Ustrlen(sub[0]);
      moffset = moffsetextra = 0;
      emptyopt = 0;

      for (;;)
        {
        int ovector[3*(EXPAND_MAXN+1)];
        int n = pcre_exec(re, NULL, CS subject, slen, moffset + moffsetextra,
          PCRE_EOPT | emptyopt, ovector, sizeof(ovector)/sizeof(int));
        int nn;
        uschar *insert;

        /* No match - if we previously set PCRE_NOTEMPTY after a null match, this
        is not necessarily the end. We want to repeat the match from one
        character further along, but leaving the basic offset the same (for
        copying below). We can't be at the end of the string - that was checked
        before setting PCRE_NOTEMPTY. If PCRE_NOTEMPTY is not set, we are
        finished; copy the remaining string and end the loop. */

        if (n < 0)
          {
          if (emptyopt != 0)
            {
            moffsetextra = 1;
            emptyopt = 0;
            continue;
            }
          yield = string_cat(yield, &size, &ptr, subject+moffset, slen-moffset);
          break;
          }

        /* Match - set up for expanding the replacement. */

        if (n == 0) n = EXPAND_MAXN + 1;
        expand_nmax = 0;
        for (nn = 0; nn < n*2; nn += 2)
          {
          expand_nstring[expand_nmax] = subject + ovector[nn];
          expand_nlength[expand_nmax++] = ovector[nn+1] - ovector[nn];
          }
        expand_nmax--;

        /* Copy the characters before the match, plus the expanded insertion. */

        yield = string_cat(yield, &size, &ptr, subject + moffset,
          ovector[0] - moffset);
        insert = expand_string(sub[2]);
        if (insert == NULL) goto EXPAND_FAILED;
        yield = string_cat(yield, &size, &ptr, insert, Ustrlen(insert));

        moffset = ovector[1];
        moffsetextra = 0;
        emptyopt = 0;

        /* If we have matched an empty string, first check to see if we are at
        the end of the subject. If so, the loop is over. Otherwise, mimic
        what Perl's /g options does. This turns out to be rather cunning. First
        we set PCRE_NOTEMPTY and PCRE_ANCHORED and try the match a non-empty
        string at the same point. If this fails (picked up above) we advance to
        the next character. */

        if (ovector[0] == ovector[1])
          {
          if (ovector[0] == slen) break;
          emptyopt = PCRE_NOTEMPTY | PCRE_ANCHORED;
          }
        }

      /* All done - restore numerical variables. */

      restore_expand_strings(save_expand_nmax, save_expand_nstring,
        save_expand_nlength);
      continue;
      }

    /* Handle keyed and numbered substring extraction. If the first argument
    consists entirely of digits, then a numerical extraction is assumed. */

    case EITEM_EXTRACT:
      {
      int i;
      int j = 2;
      int field_number = 1;
      BOOL field_number_set = FALSE;
      uschar *save_lookup_value = lookup_value;
      uschar *sub[3];
      int save_expand_nmax =
        save_expand_strings(save_expand_nstring, save_expand_nlength);

      /* Read the arguments */

      for (i = 0; i < j; i++)
        {
        while (isspace(*s)) s++;
        if (*s == '{')
          {
          sub[i] = expand_string_internal(s+1, TRUE, &s, skipping);
          if (sub[i] == NULL) goto EXPAND_FAILED;
          if (*s++ != '}') goto EXPAND_FAILED_CURLY;

          /* After removal of leading and trailing white space, the first
          argument must not be empty; if it consists entirely of digits
          (optionally preceded by a minus sign), this is a numerical
          extraction, and we expect 3 arguments. */

          if (i == 0)
            {
            int len;
            int x = 0;
            uschar *p = sub[0];

            while (isspace(*p)) p++;
            sub[0] = p;

            len = Ustrlen(p);
            while (len > 0 && isspace(p[len-1])) len--;
            p[len] = 0;

            if (*p == 0)
              {
              expand_string_message = US"first argument of \"expand\" must not "
                "be empty";
              goto EXPAND_FAILED;
              }

            if (*p == '-')
              {
              field_number = -1;
              p++;
              }
            while (*p != 0 && isdigit(*p)) x = x * 10 + *p++ - '0';
            if (*p == 0)
              {
              field_number *= x;
              j = 3;               /* Need 3 args */
              field_number_set = TRUE;
              }
            }
          }
        else goto EXPAND_FAILED_CURLY;
        }

      /* Extract either the numbered or the keyed substring into $value. If
      skipping, just pretend the extraction failed. */

      lookup_value = skipping? NULL : field_number_set?
        expand_gettokened(field_number, sub[1], sub[2]) :
        expand_getkeyed(sub[0], sub[1]);

      /* If no string follows, $value gets substituted; otherwise there can
      be yes/no strings, as for lookup or if. */

      switch(process_yesno(
               skipping,                     /* were previously skipping */
               lookup_value != NULL,         /* success/failure indicator */
               save_lookup_value,            /* value to reset for string2 */
               &s,                           /* input pointer */
               &yield,                       /* output pointer */
               &size,                        /* output size */
               &ptr,                         /* output current point */
               US"extract"))                 /* condition type */
        {
        case 1: goto EXPAND_FAILED;          /* when all is well, the */
        case 2: goto EXPAND_FAILED_CURLY;    /* returned value is 0 */
        }

      /* All done - restore numerical variables. */

      restore_expand_strings(save_expand_nmax, save_expand_nstring,
        save_expand_nlength);

      continue;
      }


    /* If ${dlfunc support is configured, handle calling dynamically-loaded
    functions, unless locked out at this time. Syntax is ${dlfunc{file}{func}}
    or ${dlfunc{file}{func}{arg}} or ${dlfunc{file}{func}{arg1}{arg2}} or up to
    a maximum of EXPAND_DLFUNC_MAX_ARGS arguments (defined below). */

    #define EXPAND_DLFUNC_MAX_ARGS 8

    case EITEM_DLFUNC:
    #ifndef EXPAND_DLFUNC
    expand_string_message = US"\"${dlfunc\" encountered, but this facility "
      "is not included in this binary";
    goto EXPAND_FAILED;

    #else   /* EXPAND_DLFUNC */
      {
      tree_node *t;
      exim_dlfunc_t *func;
      uschar *result;
      int status, argc;
      uschar *argv[EXPAND_DLFUNC_MAX_ARGS + 3];

      if ((expand_forbid & RDO_DLFUNC) != 0)
        {
        expand_string_message =
          US"dynamically-loaded functions are not permitted";
        goto EXPAND_FAILED;
        }

      switch(read_subs(argv, EXPAND_DLFUNC_MAX_ARGS + 2, 2, &s, skipping,
           TRUE, US"dlfunc"))
        {
        case 1: goto EXPAND_FAILED_CURLY;
        case 2:
        case 3: goto EXPAND_FAILED;
        }

      /* If skipping, we don't actually do anything */

      if (skipping) continue;

      /* Look up the dynamically loaded object handle in the tree. If it isn't
      found, dlopen() the file and put the handle in the tree for next time. */

      t = tree_search(dlobj_anchor, argv[0]);
      if (t == NULL)
        {
        void *handle = dlopen(CS argv[0], RTLD_LAZY);
        if (handle == NULL)
          {
          expand_string_message = string_sprintf("dlopen \"%s\" failed: %s",
            argv[0], dlerror());
          log_write(0, LOG_MAIN|LOG_PANIC, "%s", expand_string_message);
          goto EXPAND_FAILED;
          }
        t = store_get_perm(sizeof(tree_node) + Ustrlen(argv[0]));
        Ustrcpy(t->name, argv[0]);
        t->data.ptr = handle;
        (void)tree_insertnode(&dlobj_anchor, t);
        }

      /* Having obtained the dynamically loaded object handle, look up the
      function pointer. */

      func = (exim_dlfunc_t *)dlsym(t->data.ptr, CS argv[1]);
      if (func == NULL)
        {
        expand_string_message = string_sprintf("dlsym \"%s\" in \"%s\" failed: "
          "%s", argv[1], argv[0], dlerror());
        log_write(0, LOG_MAIN|LOG_PANIC, "%s", expand_string_message);
        goto EXPAND_FAILED;
        }

      /* Call the function and work out what to do with the result. If it
      returns OK, we have a replacement string; if it returns DEFER then
      expansion has failed in a non-forced manner; if it returns FAIL then
      failure was forced; if it returns ERROR or any other value there's a
      problem, so panic slightly. */

      result = NULL;
      for (argc = 0; argv[argc] != NULL; argc++);
      status = func(&result, argc - 2, &argv[2]);
      if(status == OK)
        {
        if (result == NULL) result = US"";
        yield = string_cat(yield, &size, &ptr, result, Ustrlen(result));
        continue;
        }
      else
        {
        expand_string_message = result == NULL ? US"(no message)" : result;
        if(status == FAIL_FORCED) expand_string_forcedfail = TRUE;
          else if(status != FAIL)
            log_write(0, LOG_MAIN|LOG_PANIC, "dlfunc{%s}{%s} failed (%d): %s",
              argv[0], argv[1], status, expand_string_message);
        goto EXPAND_FAILED;
        }
      }
    #endif /* EXPAND_DLFUNC */
    }

  /* Control reaches here if the name is not recognized as one of the more
  complicated expansion items. Check for the "operator" syntax (name terminated
  by a colon). Some of the operators have arguments, separated by _ from the
  name. */

  if (*s == ':')
    {
    int c;
    uschar *arg = NULL;
    uschar *sub = expand_string_internal(s+1, TRUE, &s, skipping);
    if (sub == NULL) goto EXPAND_FAILED;
    s++;

    /* Owing to an historical mis-design, an underscore may be part of the
    operator name, or it may introduce arguments.  We therefore first scan the
    table of names that contain underscores. If there is no match, we cut off
    the arguments and then scan the main table. */

    c = chop_match(name, op_table_underscore,
      sizeof(op_table_underscore)/sizeof(uschar *));

    if (c < 0)
      {
      arg = Ustrchr(name, '_');
      if (arg != NULL) *arg = 0;
      c = chop_match(name, op_table_main,
        sizeof(op_table_main)/sizeof(uschar *));
      if (c >= 0) c += sizeof(op_table_underscore)/sizeof(uschar *);
      if (arg != NULL) *arg++ = '_';   /* Put back for error messages */
      }

    /* If we are skipping, we don't need to perform the operation at all.
    This matters for operations like "mask", because the data may not be
    in the correct format when skipping. For example, the expression may test
    for the existence of $sender_host_address before trying to mask it. For
    other operations, doing them may not fail, but it is a waste of time. */

    if (skipping && c >= 0) continue;

    /* Otherwise, switch on the operator type */

    switch(c)
      {
      case EOP_BASE62:
        {
        uschar *t;
        unsigned long int n = Ustrtoul(sub, &t, 10);
        if (*t != 0)
          {
          expand_string_message = string_sprintf("argument for base62 "
            "operator is \"%s\", which is not a decimal number", sub);
          goto EXPAND_FAILED;
          }
        t = string_base62(n);
        yield = string_cat(yield, &size, &ptr, t, Ustrlen(t));
        continue;
        }

      case EOP_BASE62D:
        {
        uschar buf[16];
        uschar *tt = sub;
        unsigned long int n = 0;
        while (*tt != 0)
          {
          uschar *t = Ustrchr(base62_chars, *tt++);
          if (t == NULL)
            {
            expand_string_message = string_sprintf("argument for base62d "
              "operator is \"%s\", which is not a base 62 number", sub);
            goto EXPAND_FAILED;
            }
          n = n * 62 + (t - base62_chars);
          }
        (void)sprintf(CS buf, "%ld", n);
        yield = string_cat(yield, &size, &ptr, buf, Ustrlen(buf));
        continue;
        }

      case EOP_EXPAND:
        {
        uschar *expanded = expand_string_internal(sub, FALSE, NULL, skipping);
        if (expanded == NULL)
          {
          expand_string_message =
            string_sprintf("internal expansion of \"%s\" failed: %s", sub,
              expand_string_message);
          goto EXPAND_FAILED;
          }
        yield = string_cat(yield, &size, &ptr, expanded, Ustrlen(expanded));
        continue;
        }

      case EOP_LC:
        {
        int count = 0;
        uschar *t = sub - 1;
        while (*(++t) != 0) { *t = tolower(*t); count++; }
        yield = string_cat(yield, &size, &ptr, sub, count);
        continue;
        }

      case EOP_UC:
        {
        int count = 0;
        uschar *t = sub - 1;
        while (*(++t) != 0) { *t = toupper(*t); count++; }
        yield = string_cat(yield, &size, &ptr, sub, count);
        continue;
        }

      case EOP_MD5:
        {
        md5 base;
        uschar digest[16];
        int j;
        char st[33];
        md5_start(&base);
        md5_end(&base, sub, Ustrlen(sub), digest);
        for(j = 0; j < 16; j++) sprintf(st+2*j, "%02x", digest[j]);
        yield = string_cat(yield, &size, &ptr, US st, (int)strlen(st));
        continue;
        }

      case EOP_SHA1:
        {
        sha1 base;
        uschar digest[20];
        int j;
        char st[41];
        sha1_start(&base);
        sha1_end(&base, sub, Ustrlen(sub), digest);
        for(j = 0; j < 20; j++) sprintf(st+2*j, "%02X", digest[j]);
        yield = string_cat(yield, &size, &ptr, US st, (int)strlen(st));
        continue;
        }

      /* Convert hex encoding to base64 encoding */

      case EOP_HEX2B64:
        {
        int c = 0;
        int b = -1;
        uschar *in = sub;
        uschar *out = sub;
        uschar *enc;

        for (enc = sub; *enc != 0; enc++)
          {
          if (!isxdigit(*enc))
            {
            expand_string_message = string_sprintf("\"%s\" is not a hex "
              "string", sub);
            goto EXPAND_FAILED;
            }
          c++;
          }

        if ((c & 1) != 0)
          {
          expand_string_message = string_sprintf("\"%s\" contains an odd "
            "number of characters", sub);
          goto EXPAND_FAILED;
          }

        while ((c = *in++) != 0)
          {
          if (isdigit(c)) c -= '0';
          else c = toupper(c) - 'A' + 10;
          if (b == -1)
            {
            b = c << 4;
            }
          else
            {
            *out++ = b | c;
            b = -1;
            }
          }

        enc = auth_b64encode(sub, out - sub);
        yield = string_cat(yield, &size, &ptr, enc, Ustrlen(enc));
        continue;
        }

      /* mask applies a mask to an IP address; for example the result of
      ${mask:131.111.10.206/28} is 131.111.10.192/28. */

      case EOP_MASK:
        {
        int count;
        uschar *endptr;
        int binary[4];
        int mask, maskoffset;
        int type = string_is_ip_address(sub, &maskoffset);
        uschar buffer[64];

        if (type == 0)
          {
          expand_string_message = string_sprintf("\"%s\" is not an IP address",
           sub);
          goto EXPAND_FAILED;
          }

        if (maskoffset == 0)
          {
          expand_string_message = string_sprintf("missing mask value in \"%s\"",
            sub);
          goto EXPAND_FAILED;
          }

        mask = Ustrtol(sub + maskoffset + 1, &endptr, 10);

        if (*endptr != 0 || mask < 0 || mask > ((type == 4)? 32 : 128))
          {
          expand_string_message = string_sprintf("mask value too big in \"%s\"",
            sub);
          goto EXPAND_FAILED;
          }

        /* Convert the address to binary integer(s) and apply the mask */

        sub[maskoffset] = 0;
        count = host_aton(sub, binary);
        host_mask(count, binary, mask);

        /* Convert to masked textual format and add to output. */

        yield = string_cat(yield, &size, &ptr, buffer,
          host_nmtoa(count, binary, mask, buffer, '.'));
        continue;
        }

      case EOP_ADDRESS:
      case EOP_LOCAL_PART:
      case EOP_DOMAIN:
        {
        uschar *error;
        int start, end, domain;
        uschar *t = parse_extract_address(sub, &error, &start, &end, &domain,
          FALSE);
        if (t != NULL)
          {
          if (c != EOP_DOMAIN)
            {
            if (c == EOP_LOCAL_PART && domain != 0) end = start + domain - 1;
            yield = string_cat(yield, &size, &ptr, sub+start, end-start);
            }
          else if (domain != 0)
            {
            domain += start;
            yield = string_cat(yield, &size, &ptr, sub+domain, end-domain);
            }
          }
        continue;
        }

      /* quote puts a string in quotes if it is empty or contains anything
      other than alphamerics, underscore, dot, or hyphen.

      quote_local_part puts a string in quotes if RFC 2821/2822 requires it to
      be quoted in order to be a valid local part.

      In both cases, newlines and carriage returns are converted into \n and \r
      respectively */

      case EOP_QUOTE:
      case EOP_QUOTE_LOCAL_PART:
      if (arg == NULL)
        {
        BOOL needs_quote = (*sub == 0);      /* TRUE for empty string */
        uschar *t = sub - 1;

        if (c == EOP_QUOTE)
          {
          while (!needs_quote && *(++t) != 0)
            needs_quote = !isalnum(*t) && !strchr("_-.", *t);
          }
        else  /* EOP_QUOTE_LOCAL_PART */
          {
          while (!needs_quote && *(++t) != 0)
            needs_quote = !isalnum(*t) &&
              strchr("!#$%&'*+-/=?^_`{|}~", *t) == NULL &&
              (*t != '.' || t == sub || t[1] == 0);
          }

        if (needs_quote)
          {
          yield = string_cat(yield, &size, &ptr, US"\"", 1);
          t = sub - 1;
          while (*(++t) != 0)
            {
            if (*t == '\n')
              yield = string_cat(yield, &size, &ptr, US"\\n", 2);
            else if (*t == '\r')
              yield = string_cat(yield, &size, &ptr, US"\\r", 2);
            else
              {
              if (*t == '\\' || *t == '"')
                yield = string_cat(yield, &size, &ptr, US"\\", 1);
              yield = string_cat(yield, &size, &ptr, t, 1);
              }
            }
          yield = string_cat(yield, &size, &ptr, US"\"", 1);
          }
        else yield = string_cat(yield, &size, &ptr, sub, Ustrlen(sub));
        continue;
        }

      /* quote_lookuptype does lookup-specific quoting */

      else
        {
        int n;
        uschar *opt = Ustrchr(arg, '_');

        if (opt != NULL) *opt++ = 0;

        n = search_findtype(arg, Ustrlen(arg));
        if (n < 0)
          {
          expand_string_message = search_error_message;
          goto EXPAND_FAILED;
          }

        if (lookup_list[n].quote != NULL)
          sub = (lookup_list[n].quote)(sub, opt);
        else if (opt != NULL) sub = NULL;

        if (sub == NULL)
          {
          expand_string_message = string_sprintf(
            "\"%s\" unrecognized after \"${quote_%s\"",
            opt, arg);
          goto EXPAND_FAILED;
          }

        yield = string_cat(yield, &size, &ptr, sub, Ustrlen(sub));
        continue;
        }

      /* rx quote sticks in \ before any non-alphameric character so that
      the insertion works in a regular expression. */

      case EOP_RXQUOTE:
        {
        uschar *t = sub - 1;
        while (*(++t) != 0)
          {
          if (!isalnum(*t))
            yield = string_cat(yield, &size, &ptr, US"\\", 1);
          yield = string_cat(yield, &size, &ptr, t, 1);
          }
        continue;
        }

      /* RFC 2047 encodes, assuming headers_charset (default ISO 8859-1) as
      prescribed by the RFC, if there are characters that need to be encoded */

      case EOP_RFC2047:
        {
        uschar buffer[2048];
        uschar *string = parse_quote_2047(sub, Ustrlen(sub), headers_charset,
          buffer, sizeof(buffer));
        yield = string_cat(yield, &size, &ptr, string, Ustrlen(string));
        continue;
        }

      /* from_utf8 converts UTF-8 to 8859-1, turning non-existent chars into
      underscores */

      case EOP_FROM_UTF8:
        {
        while (*sub != 0)
          {
          int c;
          uschar buff[4];
          GETUTF8INC(c, sub);
          if (c > 255) c = '_';
          buff[0] = c;
          yield = string_cat(yield, &size, &ptr, buff, 1);
          }
        continue;
        }

      /* escape turns all non-printing characters into escape sequences. */

      case EOP_ESCAPE:
        {
        uschar *t = string_printing(sub);
        yield = string_cat(yield, &size, &ptr, t, Ustrlen(t));
        continue;
        }

      /* Handle numeric expression evaluation */

      case EOP_EVAL:
      case EOP_EVAL10:
        {
        uschar *save_sub = sub;
        uschar *error = NULL;
        int n = eval_expr(&sub, (c == EOP_EVAL10), &error, FALSE);
        if (error != NULL)
          {
          expand_string_message = string_sprintf("error in expression "
            "evaluation: %s (after processing \"%.*s\")", error, sub-save_sub,
              save_sub);
          goto EXPAND_FAILED;
          }
        sprintf(CS var_buffer, "%d", n);
        yield = string_cat(yield, &size, &ptr, var_buffer, Ustrlen(var_buffer));
        continue;
        }

      /* Handle time period formating */

      case EOP_TIME_INTERVAL:
        {
        int n;
        uschar *t = read_number(&n, sub);
        if (*t != 0) /* Not A Number*/
          {
          expand_string_message = string_sprintf("string \"%s\" is not a "
            "positive number in \"%s\" operator", sub, name);
          goto EXPAND_FAILED;
          }
        t = readconf_printtime(n);
        yield = string_cat(yield, &size, &ptr, t, Ustrlen(t));
        continue;
        }

      /* Convert string to base64 encoding */

      case EOP_STR2B64:
        {
        uschar *encstr = auth_b64encode(sub, Ustrlen(sub));
        yield = string_cat(yield, &size, &ptr, encstr, Ustrlen(encstr));
        continue;
        }

      /* strlen returns the length of the string */

      case EOP_STRLEN:
        {
        uschar buff[24];
        (void)sprintf(CS buff, "%d", Ustrlen(sub));
        yield = string_cat(yield, &size, &ptr, buff, Ustrlen(buff));
        continue;
        }

      /* length_n or l_n takes just the first n characters or the whole string,
      whichever is the shorter;

      substr_m_n, and s_m_n take n characters from offset m; negative m take
      from the end; l_n is synonymous with s_0_n. If n is omitted in substr it
      takes the rest, either to the right or to the left.

      hash_n or h_n makes a hash of length n from the string, yielding n
      characters from the set a-z; hash_n_m makes a hash of length n, but
      uses m characters from the set a-zA-Z0-9.

      nhash_n returns a single number between 0 and n-1 (in text form), while
      nhash_n_m returns a div/mod hash as two numbers "a/b". The first lies
      between 0 and n-1 and the second between 0 and m-1. */

      case EOP_LENGTH:
      case EOP_L:
      case EOP_SUBSTR:
      case EOP_S:
      case EOP_HASH:
      case EOP_H:
      case EOP_NHASH:
      case EOP_NH:
        {
        int sign = 1;
        int value1 = 0;
        int value2 = -1;
        int *pn;
        int len;
        uschar *ret;

        if (arg == NULL)
          {
          expand_string_message = string_sprintf("missing values after %s",
            name);
          goto EXPAND_FAILED;
          }

        /* "length" has only one argument, effectively being synonymous with
        substr_0_n. */

        if (c == EOP_LENGTH || c == EOP_L)
          {
          pn = &value2;
          value2 = 0;
          }

        /* The others have one or two arguments; for "substr" the first may be
        negative. The second being negative means "not supplied". */

        else
          {
          pn = &value1;
          if (name[0] == 's' && *arg == '-') { sign = -1; arg++; }
          }

        /* Read up to two numbers, separated by underscores */

        ret = arg;
        while (*arg != 0)
          {
          if (arg != ret && *arg == '_' && pn == &value1)
            {
            pn = &value2;
            value2 = 0;
            if (arg[1] != 0) arg++;
            }
          else if (!isdigit(*arg))
            {
            expand_string_message =
              string_sprintf("non-digit after underscore in \"%s\"", name);
            goto EXPAND_FAILED;
            }
          else *pn = (*pn)*10 + *arg++ - '0';
          }
        value1 *= sign;

        /* Perform the required operation */

        ret =
          (c == EOP_HASH || c == EOP_H)?
             compute_hash(sub, value1, value2, &len) :
          (c == EOP_NHASH || c == EOP_NH)?
             compute_nhash(sub, value1, value2, &len) :
             extract_substr(sub, value1, value2, &len);

        if (ret == NULL) goto EXPAND_FAILED;
        yield = string_cat(yield, &size, &ptr, ret, len);
        continue;
        }

      /* Stat a path */

      case EOP_STAT:
        {
        uschar *s;
        uschar smode[12];
        uschar **modetable[3];
        int i;
        mode_t mode;
        struct stat st;

        if (stat(CS sub, &st) < 0)
          {
          expand_string_message = string_sprintf("stat(%s) failed: %s",
            sub, strerror(errno));
          goto EXPAND_FAILED;
          }
        mode = st.st_mode;
        switch (mode & S_IFMT)
          {
          case S_IFIFO: smode[0] = 'p'; break;
          case S_IFCHR: smode[0] = 'c'; break;
          case S_IFDIR: smode[0] = 'd'; break;
          case S_IFBLK: smode[0] = 'b'; break;
          case S_IFREG: smode[0] = '-'; break;
          default: smode[0] = '?'; break;
          }

        modetable[0] = ((mode & 01000) == 0)? mtable_normal : mtable_sticky;
        modetable[1] = ((mode & 02000) == 0)? mtable_normal : mtable_setid;
        modetable[2] = ((mode & 04000) == 0)? mtable_normal : mtable_setid;

        for (i = 0; i < 3; i++)
          {
          memcpy(CS(smode + 7 - i*3), CS(modetable[i][mode & 7]), 3);
          mode >>= 3;
          }

        smode[10] = 0;
        s = string_sprintf("mode=%04lo smode=%s inode=%ld device=%ld links=%ld "
          "uid=%ld gid=%ld size=%ld atime=%ld mtime=%ld ctime=%ld",
          (long)(st.st_mode & 077777), smode, (long)st.st_ino,
          (long)st.st_dev, (long)st.st_nlink, (long)st.st_uid,
          (long)st.st_gid, (long)st.st_size, (long)st.st_atime,
          (long)st.st_mtime, (long)st.st_ctime);
        yield = string_cat(yield, &size, &ptr, s, Ustrlen(s));
        continue;
        }

      /* Unknown operator */

      default:
      expand_string_message =
        string_sprintf("unknown expansion operator \"%s\"", name);
      goto EXPAND_FAILED;
      }
    }

  /* Handle a plain name. If this is the first thing in the expansion, release
  the pre-allocated buffer. If the result data is known to be in a new buffer,
  newsize will be set to the size of that buffer, and we can just point at that
  store instead of copying. Many expansion strings contain just one reference,
  so this is a useful optimization, especially for humungous headers
  ($message_headers). */

  if (*s++ == '}')
    {
    int len;
    int newsize = 0;
    if (ptr == 0)
      {
      store_reset(yield);
      yield = NULL;
      size = 0;
      }
    value = find_variable(name, FALSE, skipping, &newsize);
    if (value == NULL)
      {
      expand_string_message =
        string_sprintf("unknown variable in \"${%s}\"", name);
      goto EXPAND_FAILED;
      }
    len = Ustrlen(value);
    if (yield == NULL && newsize != 0)
      {
      yield = value;
      size = newsize;
      ptr = len;
      }
    else yield = string_cat(yield, &size, &ptr, value, len);
    continue;
    }

  /* Else there's something wrong */

  expand_string_message =
    string_sprintf("\"${%s\" is not a known operator (or a } is missing "
    "in a variable reference)", name);
  goto EXPAND_FAILED;
  }

/* If we hit the end of the string when ket_ends is set, there is a missing
terminating brace. */

if (ket_ends && *s == 0)
  {
  expand_string_message = malformed_header?
    US"missing } at end of string - could be header name not terminated by colon"
    :
    US"missing } at end of string";
  goto EXPAND_FAILED;
  }

/* Expansion succeeded; yield may still be NULL here if nothing was actually
added to the string. If so, set up an empty string. Add a terminating zero. If
left != NULL, return a pointer to the terminator. */

if (yield == NULL) yield = store_get(1);
yield[ptr] = 0;
if (left != NULL) *left = s;

/* Any stacking store that was used above the final string is no longer needed.
In many cases the final string will be the first one that was got and so there
will be optimal store usage. */

store_reset(yield + ptr + 1);
DEBUG(D_expand)
  {
  debug_printf("expanding: %.*s\n   result: %s\n", (int)(s - string), string,
    yield);
  if (skipping) debug_printf("skipping: result is not used\n");
  }
return yield;

/* This is the failure exit: easiest to program with a goto. We still need
to update the pointer to the terminator, for cases of nested calls with "fail".
*/

EXPAND_FAILED_CURLY:
expand_string_message = malformed_header?
  US"missing or misplaced { or } - could be header name not terminated by colon"
  :
  US"missing or misplaced { or }";

/* At one point, Exim reset the store to yield (if yield was not NULL), but
that is a bad idea, because expand_string_message is in dynamic store. */

EXPAND_FAILED:
if (left != NULL) *left = s;
DEBUG(D_expand)
  {
  debug_printf("failed to expand: %s\n", string);
  debug_printf("   error message: %s\n", expand_string_message);
  if (expand_string_forcedfail) debug_printf("failure was forced\n");
  }
return NULL;
}


/* This is the external function call. Do a quick check for any expansion
metacharacters, and if there are none, just return the input string.

Argument: the string to be expanded
Returns:  the expanded string, or NULL if expansion failed; if failure was
          due to a lookup deferring, search_find_defer will be TRUE
*/

uschar *
expand_string(uschar *string)
{
search_find_defer = FALSE;
malformed_header = FALSE;
return (Ustrpbrk(string, "$\\") == NULL)? string :
  expand_string_internal(string, FALSE, NULL, FALSE);
}



/*************************************************
*              Expand and copy                   *
*************************************************/

/* Now and again we want to expand a string and be sure that the result is in a
new bit of store. This function does that.

Argument: the string to be expanded
Returns:  the expanded string, always in a new bit of store, or NULL
*/

uschar *
expand_string_copy(uschar *string)
{
uschar *yield = expand_string(string);
if (yield == string) yield = string_copy(string);
return yield;
}



/*************************************************
*        Expand and interpret as an integer      *
*************************************************/

/* Expand a string, and convert the result into an integer.

Argument: the string to be expanded

Returns:  the integer value, or
          -1 for an expansion error               ) in both cases, message in
          -2 for an integer interpretation error  ) expand_string_message

*/

int
expand_string_integer(uschar *string)
{
long int value;
uschar *s = expand_string(string);
uschar *msg = US"invalid integer \"%s\"";
uschar *endptr;

if (s == NULL) return -1;

/* On an overflow, strtol() returns LONG_MAX or LONG_MIN, and sets errno
to ERANGE. When there isn't an overflow, errno is not changed, at least on some
systems, so we set it zero ourselves. */

errno = 0;
value = strtol(CS s, CSS &endptr, 0);

if (endptr == s)
  {
  msg = US"integer expected but \"%s\" found";
  }
else
  {
  /* Ensure we can cast this down to an int */
  if (value > INT_MAX  || value < INT_MIN) errno = ERANGE;

  if (errno != ERANGE)
    {
    if (tolower(*endptr) == 'k')
      {
      if (value > INT_MAX/1024 || value < INT_MIN/1024) errno = ERANGE;
        else value *= 1024;
      endptr++;
      }
    else if (tolower(*endptr) == 'm')
      {
      if (value > INT_MAX/(1024*1024) || value < INT_MIN/(1024*1024))
        errno = ERANGE;
      else value *= 1024*1024;
      endptr++;
      }
    }
  if (errno == ERANGE)
    msg = US"absolute value of integer \"%s\" is too large (overflow)";
  else
    {
    while (isspace(*endptr)) endptr++;
    if (*endptr == 0) return (int)value;
    }
  }

expand_string_message = string_sprintf(CS msg, s);
return -2;
}



/*************************************************
**************************************************
*             Stand-alone test program           *
**************************************************
*************************************************/

#ifdef STAND_ALONE


BOOL
regex_match_and_setup(const pcre *re, uschar *subject, int options, int setup)
{
int ovector[3*(EXPAND_MAXN+1)];
int n = pcre_exec(re, NULL, subject, Ustrlen(subject), 0, PCRE_EOPT|options,
  ovector, sizeof(ovector)/sizeof(int));
BOOL yield = n >= 0;
if (n == 0) n = EXPAND_MAXN + 1;
if (yield)
  {
  int nn;
  expand_nmax = (setup < 0)? 0 : setup + 1;
  for (nn = (setup < 0)? 0 : 2; nn < n*2; nn += 2)
    {
    expand_nstring[expand_nmax] = subject + ovector[nn];
    expand_nlength[expand_nmax++] = ovector[nn+1] - ovector[nn];
    }
  expand_nmax--;
  }
return yield;
}


int main(int argc, uschar **argv)
{
int i;
uschar buffer[1024];

debug_selector = D_v;
debug_file = stderr;
debug_fd = fileno(debug_file);
big_buffer = malloc(big_buffer_size);

for (i = 1; i < argc; i++)
  {
  if (argv[i][0] == '+')
    {
    debug_trace_memory = 2;
    argv[i]++;
    }
  if (isdigit(argv[i][0]))
    debug_selector = Ustrtol(argv[i], NULL, 0);
  else
    if (Ustrspn(argv[i], "abcdefghijklmnopqrtsuvwxyz0123456789-.:/") ==
        Ustrlen(argv[i]))
      {
      #ifdef LOOKUP_LDAP
      eldap_default_servers = argv[i];
      #endif
      #ifdef LOOKUP_MYSQL
      mysql_servers = argv[i];
      #endif
      #ifdef LOOKUP_PGSQL
      pgsql_servers = argv[i];
      #endif
      }
  #ifdef EXIM_PERL
  else opt_perl_startup = argv[i];
  #endif
  }

printf("Testing string expansion: debug_level = %d\n\n", debug_level);

expand_nstring[1] = US"string 1....";
expand_nlength[1] = 8;
expand_nmax = 1;

#ifdef EXIM_PERL
if (opt_perl_startup != NULL)
  {
  uschar *errstr;
  printf("Starting Perl interpreter\n");
  errstr = init_perl(opt_perl_startup);
  if (errstr != NULL)
    {
    printf("** error in perl_startup code: %s\n", errstr);
    return EXIT_FAILURE;
    }
  }
#endif /* EXIM_PERL */

while (fgets(buffer, sizeof(buffer), stdin) != NULL)
  {
  void *reset_point = store_get(0);
  uschar *yield = expand_string(buffer);
  if (yield != NULL)
    {
    printf("%s\n", yield);
    store_reset(reset_point);
    }
  else
    {
    if (search_find_defer) printf("search_find deferred\n");
    printf("Failed: %s\n", expand_string_message);
    if (expand_string_forcedfail) printf("Forced failure\n");
    printf("\n");
    }
  }

search_tidyup();

return 0;
}

#endif

/* End of expand.c */
