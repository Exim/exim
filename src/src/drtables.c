/* $Cambridge: exim/src/src/drtables.c,v 1.10 2009/06/10 07:34:04 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */


#include "exim.h"


/* This module contains tables that define the lookup methods and drivers
that are actually included in the binary. Its contents are controlled by
various macros in config.h that ultimately come from Local/Makefile. They are
all described in src/EDITME. */


/* The OSF1 (Digital Unix) linker puts out a worrying warning if any sections
contain no executable code. It says

Warning: Linking some objects which contain exception information sections
        and some which do not. This may cause fatal runtime exception handling
        problems.

As this may cause people to worry needlessly, include a dummy function here
to stop the message from appearing. Make it call itself to stop picky compilers
compilers complaining that it is unused, and put in a dummy argument to stop
even pickier compilers complaining about infinite loops. */

static void dummy(int x) { dummy(x-1); }


/* Table of information about all possible lookup methods. The entries are
always present, but the "open" and "find" functions are set to NULL for those
that are not compiled into the binary. The "check" and "close" functions can
be NULL for methods that don't need them. */

#ifdef LOOKUP_CDB
#include "lookups/cdb.h"
#endif

#ifdef LOOKUP_DBM
#include "lookups/dbmdb.h"
#endif

#ifdef LOOKUP_DNSDB
#include "lookups/dnsdb.h"
#endif

#ifdef LOOKUP_DSEARCH
#include "lookups/dsearch.h"
#endif

#ifdef LOOKUP_IBASE
#include "lookups/ibase.h"
#endif

#ifdef LOOKUP_LDAP
#include "lookups/ldap.h"
#endif

#ifdef LOOKUP_LSEARCH
#include "lookups/lsearch.h"
#endif

#ifdef LOOKUP_MYSQL
#include "lookups/mysql.h"
#endif

#ifdef LOOKUP_NIS
#include "lookups/nis.h"
#endif

#ifdef LOOKUP_NISPLUS
#include "lookups/nisplus.h"
#endif

#ifdef LOOKUP_ORACLE
#include "lookups/oracle.h"
#endif

#ifdef LOOKUP_PASSWD
#include "lookups/passwd.h"
#endif

#ifdef LOOKUP_PGSQL
#include "lookups/pgsql.h"
#endif

#ifdef EXPERIMENTAL_SPF
#include "lookups/spf.h"
#endif

#ifdef LOOKUP_SQLITE
#include "lookups/sqlite.h"
#endif

#ifdef LOOKUP_TESTDB
#include "lookups/testdb.h"
#endif

#ifdef LOOKUP_WHOSON
#include "lookups/whoson.h"
#endif

/* The second field in each item below is a set of bit flags:

  lookup_querystyle     => this is a query-style lookup,
                             else single-key (+ file) style
  lookup_absfile        => an absolute file name is required,
                             (for single-key style only)

This list must be in alphabetical order of lookup name because it is
searched by binary chop, having got rather large for the original linear
searching. */

lookup_info lookup_list[] = {

/* cdb lookup in single file */

  {
  US"cdb",                       /* lookup name */
  lookup_absfile,                /* uses absolute file name */
#ifdef LOOKUP_CDB
  cdb_open,                      /* open function */
  cdb_check,                     /* check function */
  cdb_find,                      /* find function */
  cdb_close,                     /* close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* DBM file lookup; called "dbm" because that is the name in Exim,
but the code is called dbmdb to avoid name clashes. */

  {
  US"dbm",                       /* lookup name */
  lookup_absfile,                /* uses absolute file name */
#ifdef LOOKUP_DBM
  dbmdb_open,                    /* open function */
  dbmdb_check,                   /* check function */
  dbmdb_find,                    /* find function */
  dbmdb_close,                   /* close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* This variant of DBM does not include the binary zero on the end
of the key strings. */

  {
  US"dbmnz",                     /* lookup name */
  lookup_absfile,                /* uses absolute file name */
#ifdef LOOKUP_DBM
  dbmdb_open,      /* sic */     /* open function */
  dbmdb_check,     /* sic */     /* check function */
  dbmnz_find,                    /* find function */
  dbmdb_close,     /* sic */     /* close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* Using DNS TXT records as a database */

  {
  US"dnsdb",                     /* lookup name */
  lookup_querystyle,             /* query style */
#ifdef LOOKUP_DNSDB
  dnsdb_open,                    /* open function */
  NULL,                          /* check function */
  dnsdb_find,                    /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* Search of files in a directory */

  {
  US"dsearch",                   /* lookup name */
  lookup_absfile,                /* uses absolute file name */
#ifdef LOOKUP_DSEARCH
  dsearch_open,                  /* open function */
  dsearch_check,                 /* check function */
  dsearch_find,                  /* find function */
  dsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* Interbase lookup */

  {
  US"ibase",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_IBASE
  ibase_open,                    /* open function */
  NULL,                          /* no check function */
  ibase_find,                    /* find function */
  NULL,                          /* no close function */
  ibase_tidy,                    /* tidy function */
  ibase_quote                    /* quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* Linear search of single file with ip-addresses and networks; shares many
functions with lsearch. */

  {
  US"iplsearch",                 /* lookup name */
  lookup_absfile,                /* uses absolute file name */
#ifdef LOOKUP_LSEARCH
  lsearch_open,                  /* open function */
  lsearch_check,                 /* check function */
  iplsearch_find,                /* find function */
  lsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* LDAP lookup, allowing data from only one entry to be returned */

  {
  US"ldap",                      /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_LDAP
  eldap_open,                    /* open function */
  NULL,                          /* check function */
  eldap_find,                    /* find function */
  NULL,                          /* no close function */
  eldap_tidy,                    /* tidy function */
  eldap_quote                    /* quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* LDAP lookup, allowing the DN from more one entry to be returned */

  {
  US"ldapdn",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_LDAP
  eldap_open,       /* sic */    /* open function */
  NULL,                          /* check function */
  eldapdn_find,                  /* find function */
  NULL,                          /* no close function */
  eldap_tidy,       /* sic */    /* tidy function */
  eldap_quote       /* sic */    /* quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* LDAP lookup, allowing data from more than one entry to be returned */

  {
  US"ldapm",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_LDAP
  eldap_open,       /* sic */    /* open function */
  NULL,                          /* check function */
  eldapm_find,                   /* find function */
  NULL,                          /* no close function */
  eldap_tidy,       /* sic */    /* tidy function */
  eldap_quote       /* sic */    /* quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* Linear search of single file */

  {
  US"lsearch",                   /* lookup name */
  lookup_absfile,                /* uses absolute file name */
#ifdef LOOKUP_LSEARCH
  lsearch_open,                  /* open function */
  lsearch_check,                 /* check function */
  lsearch_find,                  /* find function */
  lsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* MYSQL lookup */

  {
  US"mysql",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_MYSQL
  mysql_open,                    /* open function */
  NULL,                          /* no check function */
  mysql_find,                    /* find function */
  NULL,                          /* no close function */
  mysql_tidy,                    /* tidy function */
  mysql_quote                    /* quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* NIS lookup, excluding trailing 0 from key */

  {
  US"nis",                       /* lookup name */
  0,                             /* not abs file, not query style*/
#ifdef LOOKUP_NIS
  nis_open,                      /* open function */
  NULL,                          /* check function */
  nis_find,                      /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* NIS lookup, including trailing 0 in key */

  {
  US"nis0",                      /* lookup name */
  0,                             /* not absfile, not query style */
#ifdef LOOKUP_NIS
  nis_open,    /* sic */         /* open function */
  NULL,                          /* check function */
  nis0_find,                     /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* NIS+ lookup */

  {
  US"nisplus",                   /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_NISPLUS
  nisplus_open,                  /* open function */
  NULL,                          /* check function */
  nisplus_find,                  /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  nisplus_quote                  /* quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* Linear search of single file, with wildcarding but no pattern expansion.
Shares many functions with lsearch. */

  {
  US"nwildlsearch",              /* lookup name */
  lookup_absfile,                /* uses absolute file name */
#ifdef LOOKUP_LSEARCH
  lsearch_open,                  /* open function */
  lsearch_check,                 /* check function */
  nwildlsearch_find,             /* find function */
  lsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* Oracle lookup */

  {
  US"oracle",                    /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_ORACLE
  oracle_open,                   /* open function */
  NULL,                          /* check function */
  oracle_find,                   /* find function */
  NULL,                          /* no close function */
  oracle_tidy,                   /* tidy function */
  oracle_quote                   /* quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* passwd lookup */

  {
  US"passwd",                    /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_PASSWD
  passwd_open,                   /* open function */
  NULL,                          /* no check function */
  passwd_find,                   /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL   /* lookup not present */
#endif
  },

/* PGSQL lookup */

  {
  US"pgsql",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_PGSQL
  pgsql_open,                    /* open function */
  NULL,                          /* no check function */
  pgsql_find,                    /* find function */
  NULL,                          /* no close function */
  pgsql_tidy,                    /* tidy function */
  pgsql_quote                    /* quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL   /* lookup not present */
#endif
  },

/* SPF lookup */

  {
  US"spf",                       /* lookup name */
  0,                             /* not absfile, not query style */
#ifdef EXPERIMENTAL_SPF
  spf_open,                      /* open function */
  NULL,                          /* no check function */
  spf_find,                      /* find function */
  spf_close,                     /* close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* sqlite lookup */

  {
  US"sqlite",                    /* lookup name */
  lookup_absfilequery,           /* query-style lookup, starts with file name */
#ifdef LOOKUP_SQLITE
  sqlite_open,                   /* open function */
  NULL,                          /* no check function */
  sqlite_find,                   /* find function */
  sqlite_close,                  /* close function */
  NULL,                          /* no tidy function */
  sqlite_quote                   /* quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  },

/* Testdb lookup is for testing Exim, not useful for normal running.
For that reason, we omit the entry entirely when not building it into
the binary, so that attempts to use it give "unknown lookup type" instead
of "lookup type not available". */

#ifdef LOOKUP_TESTDB
  {
  US"testdb",                    /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  testdb_open,                   /* open function */
  NULL,                          /* check function */
  testdb_find,                   /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
  },
#endif

/* "Whoson" lookup */

  {
  US"whoson",                    /* lookup name */
  lookup_querystyle,             /* query-style lookup */
#ifdef LOOKUP_WHOSON
  whoson_open,                   /* open function */
  NULL,                          /* check function */
  whoson_find,                   /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL   /* lookup not present */
#endif
  },

/* Linear search of single file, with wildcarding and pattern expansion. Shares
many functions with lsearch. */

  {
  US"wildlsearch",               /* lookup name */
  lookup_absfile,                /* uses absolute file name */
#ifdef LOOKUP_LSEARCH
  lsearch_open,                  /* open function */
  lsearch_check,                 /* check function */
  wildlsearch_find,              /* find function */
  lsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL                           /* no quoting function */
#else
  NULL, NULL, NULL, NULL, NULL, NULL /* lookup not present */
#endif
  }
};

/* Number of entries in the list */

int lookup_list_count = sizeof(lookup_list)/sizeof(lookup_info);



/* Table of information about all possible authentication mechamisms. All
entries are always present if any mechanism is declared, but the functions are
set to NULL for those that are not compiled into the binary. */

#ifdef AUTH_CRAM_MD5
#include "auths/cram_md5.h"
#endif

#ifdef AUTH_CYRUS_SASL
#include "auths/cyrus_sasl.h"
#endif

#ifdef AUTH_DOVECOT
#include "auths/dovecot.h"
#endif

#ifdef AUTH_PLAINTEXT
#include "auths/plaintext.h"
#endif

#ifdef AUTH_SPA
#include "auths/spa.h"
#endif

auth_info auths_available[] = {

/* Checking by an expansion condition on plain text */

#ifdef AUTH_CRAM_MD5
  {
  US"cram_md5",                              /* lookup name */
  auth_cram_md5_options,
  &auth_cram_md5_options_count,
  &auth_cram_md5_option_defaults,
  sizeof(auth_cram_md5_options_block),
  auth_cram_md5_init,                        /* init function */
  auth_cram_md5_server,                      /* server function */
  auth_cram_md5_client                       /* client function */
  },
#endif

#ifdef AUTH_CYRUS_SASL
  {
  US"cyrus_sasl",           /* lookup name */
  auth_cyrus_sasl_options,
  &auth_cyrus_sasl_options_count,
  &auth_cyrus_sasl_option_defaults,
  sizeof(auth_cyrus_sasl_options_block),
  auth_cyrus_sasl_init,                      /* init function */
  auth_cyrus_sasl_server,                    /* server function */
  NULL                                       /* client function */
  },
#endif

#ifdef AUTH_DOVECOT
  {
  US"dovecot",                                /* lookup name */
  auth_dovecot_options,
  &auth_dovecot_options_count,
  &auth_dovecot_option_defaults,
  sizeof(auth_dovecot_options_block),
  auth_dovecot_init,                          /* init function */
  auth_dovecot_server,                        /* server function */
  NULL                                        /* client function */
  },
#endif

#ifdef AUTH_PLAINTEXT
  {
  US"plaintext",                             /* lookup name */
  auth_plaintext_options,
  &auth_plaintext_options_count,
  &auth_plaintext_option_defaults,
  sizeof(auth_plaintext_options_block),
  auth_plaintext_init,                       /* init function */
  auth_plaintext_server,                     /* server function */
  auth_plaintext_client                      /* client function */
  },
#endif

#ifdef AUTH_SPA
  {
  US"spa",                                   /* lookup name */
  auth_spa_options,
  &auth_spa_options_count,
  &auth_spa_option_defaults,
  sizeof(auth_spa_options_block),
  auth_spa_init,                             /* init function */
  auth_spa_server,                           /* server function */
  auth_spa_client                            /* client function */
  },
#endif

{ US"", NULL, NULL, NULL, 0, NULL, NULL, NULL  }
};


/* Tables of information about which routers and transports are included in the
exim binary. */

/* Pull in the necessary header files */

#include "routers/rf_functions.h"

#ifdef ROUTER_ACCEPT
#include "routers/accept.h"
#endif

#ifdef ROUTER_DNSLOOKUP
#include "routers/dnslookup.h"
#endif

#ifdef ROUTER_MANUALROUTE
#include "routers/manualroute.h"
#endif

#ifdef ROUTER_IPLITERAL
#include "routers/ipliteral.h"
#endif

#ifdef ROUTER_IPLOOKUP
#include "routers/iplookup.h"
#endif

#ifdef ROUTER_QUERYPROGRAM
#include "routers/queryprogram.h"
#endif

#ifdef ROUTER_REDIRECT
#include "routers/redirect.h"
#endif

#ifdef TRANSPORT_APPENDFILE
#include "transports/appendfile.h"
#endif

#ifdef TRANSPORT_AUTOREPLY
#include "transports/autoreply.h"
#endif

#ifdef TRANSPORT_LMTP
#include "transports/lmtp.h"
#endif

#ifdef TRANSPORT_PIPE
#include "transports/pipe.h"
#endif

#ifdef TRANSPORT_SMTP
#include "transports/smtp.h"
#endif


/* Now set up the structures, terminated by an entry with a null name. */

router_info routers_available[] = {
#ifdef ROUTER_ACCEPT
  {
  US"accept",
  accept_router_options,
  &accept_router_options_count,
  &accept_router_option_defaults,
  sizeof(accept_router_options_block),
  accept_router_init,
  accept_router_entry,
  NULL,     /* no tidyup entry */
  ri_yestransport
  },
#endif
#ifdef ROUTER_DNSLOOKUP
  {
  US"dnslookup",
  dnslookup_router_options,
  &dnslookup_router_options_count,
  &dnslookup_router_option_defaults,
  sizeof(dnslookup_router_options_block),
  dnslookup_router_init,
  dnslookup_router_entry,
  NULL,     /* no tidyup entry */
  ri_yestransport
  },
#endif
#ifdef ROUTER_IPLITERAL
  {
  US"ipliteral",
  ipliteral_router_options,
  &ipliteral_router_options_count,
  &ipliteral_router_option_defaults,
  sizeof(ipliteral_router_options_block),
  ipliteral_router_init,
  ipliteral_router_entry,
  NULL,     /* no tidyup entry */
  ri_yestransport
  },
#endif
#ifdef ROUTER_IPLOOKUP
  {
  US"iplookup",
  iplookup_router_options,
  &iplookup_router_options_count,
  &iplookup_router_option_defaults,
  sizeof(iplookup_router_options_block),
  iplookup_router_init,
  iplookup_router_entry,
  NULL,     /* no tidyup entry */
  ri_notransport
  },
#endif
#ifdef ROUTER_MANUALROUTE
  {
  US"manualroute",
  manualroute_router_options,
  &manualroute_router_options_count,
  &manualroute_router_option_defaults,
  sizeof(manualroute_router_options_block),
  manualroute_router_init,
  manualroute_router_entry,
  NULL,     /* no tidyup entry */
  0
  },
#endif
#ifdef ROUTER_QUERYPROGRAM
  {
  US"queryprogram",
  queryprogram_router_options,
  &queryprogram_router_options_count,
  &queryprogram_router_option_defaults,
  sizeof(queryprogram_router_options_block),
  queryprogram_router_init,
  queryprogram_router_entry,
  NULL,     /* no tidyup entry */
  0
  },
#endif
#ifdef ROUTER_REDIRECT
  {
  US"redirect",
  redirect_router_options,
  &redirect_router_options_count,
  &redirect_router_option_defaults,
  sizeof(redirect_router_options_block),
  redirect_router_init,
  redirect_router_entry,
  NULL,     /* no tidyup entry */
  ri_notransport
  },
#endif
{ US"", NULL, NULL, NULL, 0, NULL, NULL, NULL, 0 }
};



transport_info transports_available[] = {
#ifdef TRANSPORT_APPENDFILE
  {
  US"appendfile",                              /* driver name */
  appendfile_transport_options,                /* local options table */
  &appendfile_transport_options_count,         /* number of entries */
  &appendfile_transport_option_defaults,       /* private options defaults */
  sizeof(appendfile_transport_options_block),  /* size of private block */
  appendfile_transport_init,                   /* init entry point */
  appendfile_transport_entry,                  /* main entry point */
  NULL,                                        /* no tidyup entry */
  NULL,                                        /* no closedown entry */
  TRUE,                                        /* local flag */
  },
#endif
#ifdef TRANSPORT_AUTOREPLY
  {
  US"autoreply",                               /* driver name */
  autoreply_transport_options,                 /* local options table */
  &autoreply_transport_options_count,          /* number of entries */
  &autoreply_transport_option_defaults,        /* private options defaults */
  sizeof(autoreply_transport_options_block),   /* size of private block */
  autoreply_transport_init,                    /* init entry point */
  autoreply_transport_entry,                   /* main entry point */
  NULL,                                        /* no tidyup entry */
  NULL,                                        /* no closedown entry */
  TRUE                                         /* local flag */
  },
#endif
#ifdef TRANSPORT_LMTP
  {
  US"lmtp",                                    /* driver name */
  lmtp_transport_options,                      /* local options table */
  &lmtp_transport_options_count,               /* number of entries */
  &lmtp_transport_option_defaults,             /* private options defaults */
  sizeof(lmtp_transport_options_block),        /* size of private block */
  lmtp_transport_init,                         /* init entry point */
  lmtp_transport_entry,                        /* main entry point */
  NULL,                                        /* no tidyup entry */
  NULL,                                        /* no closedown entry */
  TRUE                                         /* local flag */
  },
#endif
#ifdef TRANSPORT_PIPE
  {
  US"pipe",                                    /* driver name */
  pipe_transport_options,                      /* local options table */
  &pipe_transport_options_count,               /* number of entries */
  &pipe_transport_option_defaults,             /* private options defaults */
  sizeof(pipe_transport_options_block),        /* size of private block */
  pipe_transport_init,                         /* init entry point */
  pipe_transport_entry,                        /* main entry point */
  NULL,                                        /* no tidyup entry */
  NULL,                                        /* no closedown entry */
  TRUE                                         /* local flag */
  },
#endif
#ifdef TRANSPORT_SMTP
  {
  US"smtp",                                    /* driver name */
  smtp_transport_options,                      /* local options table */
  &smtp_transport_options_count,               /* number of entries */
  &smtp_transport_option_defaults,             /* private options defaults */
  sizeof(smtp_transport_options_block),        /* size of private block */
  smtp_transport_init,                         /* init entry point */
  smtp_transport_entry,                        /* main entry point */
  NULL,                                        /* no tidyup entry */
  smtp_transport_closedown,                    /* close down passed channel */
  FALSE                                        /* local flag */
  },
#endif
{ US"", NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, FALSE }
};

/* End of drtables.c */
