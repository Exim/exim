/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This header file contains the definitions of the structures used in the
various hints databases are also kept in this file, which is used by the
maintenance utilities as well as the main Exim binary. */

#ifndef HINTSDB_STRUCTS_H
#define HINTSDB_STRUCTS_H


/* Structure for carrying around an open DBM file, and an open locking file
that relates to it. */

typedef struct {
  void *	dbptr;
  int		lockfd;
  BOOL		readonly;
} open_db;


/* Structures for records stored in exim database hints files. They all
start with the same fields, described in the generic type.
DBM databases are used for hints files.
*/


typedef struct {
  unsigned version;
  BOOL	 tainted;	/* metadata for the "value" part of the record */
  time_t time_stamp;	/* Timestamp of writing */
} dbdata_generic;

#define	HINTS_VERSION	2


/* This structure keeps track of retry information for a host or a local
address. */

typedef struct {
  dbdata_generic gen;
  /*************/
  time_t first_failed;    /* Time of first failure */
  time_t last_try;        /* Time of last try */
  time_t next_try;        /* Time of next try */
  BOOL   expired;         /* Retry time has expired */
  int    basic_errno;     /* Errno of last failure */
  int    more_errno;      /* Additional information */
  uschar text[1];         /* Text message for last failure */
} dbdata_retry;

/* These structures keep track of addresses that have had callout verification
performed on them. There are two groups of records:

1. keyed by localpart@domain -
     Full address was tested and record holds result

2. keyed by domain -
     Domain response upto MAIL FROM:<>, postmaster, random local part;

If a record exists, the result field is either ccache_accept or ccache_reject,
or, for a domain record only, ccache_reject_mfnull when MAIL FROM:<> was
rejected. The other fields, however, (which are only relevant to domain
records) may also contain ccache_unknown if that particular test has not been
done.

Originally, there was only one structure, used for both types. However, it got
expanded for domain records, so it got split. To make it possible for Exim to
handle the old type of record, we retain the old definition. The different
kinds of record can be distinguished by their different lengths. */

typedef struct {
  dbdata_generic gen;
  /*************/
  int   result;
  int   postmaster_result; /* Postmaster is accepted */
  int   random_result;     /* Random local part was accepted */
} dbdata_callout_cache_obs;

typedef struct {
  dbdata_generic gen;		/* Timestamp of last address check */
  /*************/
  int   result;            /* accept or reject */
} dbdata_callout_cache_address;

/* For this new layout, we put the additional fields (the timestamps)
last so that if somebody reverts to an older Exim, the new records will
still make sense because they match the old layout. */

typedef struct {
  dbdata_generic gen;		/* Time stamp of last connection */
  /*************/
  int   result;            /* Domain reject or accept */
  int   postmaster_result; /* Postmaster result */
  int   random_result;     /* Random result */
  time_t postmaster_stamp; /* Timestamp of postmaster check */
  time_t random_stamp;     /* Timestamp of random check */
} dbdata_callout_cache;

/* This structure keeps track of messages that are waiting for a particular
host for a particular transport. */

typedef struct {
  dbdata_generic gen;
  /*************/
  int    count;           /* Count of message ids */
  int    sequence;        /* Sequence for continued records */
  uschar text[1];         /* One long character string */
} dbdata_wait;


/* The contents of the "misc" database are a mixture of different kinds of
record, as defined below. The keys used for a specific type all start with a
given string such as "etrn-" or "host-serialize-". */


/* This structure records a connection to a particular host, for the
purpose of serializing access to certain hosts. For possible future extension,
a field is defined for holding the count of connections, but it is not
at present in use. The same structure is used for recording a running ETRN
process. */

typedef struct {
  dbdata_generic gen;
  /*************/
  int    count;           /* Reserved for possible connection count */
} dbdata_serialize;


/* This structure records the information required for the ratelimit
ACL condition. */

typedef struct {
  dbdata_generic gen;
  /*************/
  int    time_usec;       /* Fractional part of time, from gettimeofday() */
  double rate;            /* Smoothed sending rate at that time */
} dbdata_ratelimit;

/* Same as above, plus a Bloom filter for uniquifying events. */

typedef struct {
  dbdata_ratelimit dbd;
  time_t   bloom_epoch;   /* When the Bloom filter was last reset */
  unsigned bloom_size;    /* Number of bytes in the Bloom filter */
  uschar   bloom[40];     /* Bloom filter which may be larger than this */
} dbdata_ratelimit_unique;


/* For "seen" ACL condition */
typedef struct {
  dbdata_generic gen;
} dbdata_seen;

#ifndef DISABLE_PIPE_CONNECT
/* This structure records the EHLO responses, cleartext and crypted,
for an IP, as bitmasks (cf. OPTION_TLS).  For LIMITS, also values
advertised for MAILMAX, RCPTMAX and RCPTDOMAINMAX; zero meaning no
value advertised. */

typedef struct {
  unsigned short cleartext_features;
  unsigned short crypted_features;
  unsigned short cleartext_auths;
  unsigned short crypted_auths;

# ifndef DISABLE_ESMTP_LIMITS
  unsigned int limit_mail;
  unsigned int limit_rcpt;
  unsigned int limit_rcptdom;
# endif
} ehlo_resp_precis;

typedef struct {
  dbdata_generic gen;
  /*************/
  ehlo_resp_precis data;
} dbdata_ehlo_resp;
#endif

typedef struct {
  dbdata_generic gen;
  /*************/
  uschar verify_override:1;
  uschar ocsp:3;
  uschar session[1];
} dbdata_tls_session;


#endif	/* whole file */
/* End of hintsdb_structs.h */
