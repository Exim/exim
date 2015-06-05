/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */


#include "exim.h"

#include <string.h>

/* This module contains tables that define the lookup methods and drivers
that are actually included in the binary. Its contents are controlled by
various macros in config.h that ultimately come from Local/Makefile. They are
all described in src/EDITME. */


lookup_info **lookup_list;
int lookup_list_count = 0;

static int lookup_list_init_done = 0;

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

#ifdef AUTH_GSASL
#include "auths/gsasl_exim.h"
#endif

#ifdef AUTH_HEIMDAL_GSSAPI
#include "auths/heimdal_gssapi.h"
#endif

#ifdef AUTH_PLAINTEXT
#include "auths/plaintext.h"
#endif

#ifdef AUTH_SPA
#include "auths/spa.h"
#endif

#ifdef AUTH_TLS
#include "auths/tls.h"
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
  auth_cram_md5_client,                      /* client function */
  NULL                                       /* diagnostic function */
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
  NULL,                                      /* client function */
  auth_cyrus_sasl_version_report             /* diagnostic function */
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
  NULL,                                       /* client function */
  NULL                                        /* diagnostic function */
  },
#endif

#ifdef AUTH_GSASL
  {
  US"gsasl",                                  /* lookup name */
  auth_gsasl_options,
  &auth_gsasl_options_count,
  &auth_gsasl_option_defaults,
  sizeof(auth_gsasl_options_block),
  auth_gsasl_init,                            /* init function */
  auth_gsasl_server,                          /* server function */
  NULL,                                       /* client function */
  auth_gsasl_version_report                   /* diagnostic function */
  },
#endif

#ifdef AUTH_HEIMDAL_GSSAPI
  {
  US"heimdal_gssapi",                         /* lookup name */
  auth_heimdal_gssapi_options,
  &auth_heimdal_gssapi_options_count,
  &auth_heimdal_gssapi_option_defaults,
  sizeof(auth_heimdal_gssapi_options_block),
  auth_heimdal_gssapi_init,                   /* init function */
  auth_heimdal_gssapi_server,                 /* server function */
  NULL,                                       /* client function */
  auth_heimdal_gssapi_version_report          /* diagnostic function */
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
  auth_plaintext_client,                     /* client function */
  NULL                                       /* diagnostic function */
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
  auth_spa_client,                           /* client function */
  NULL                                       /* diagnostic function */
  },
#endif

#ifdef AUTH_TLS
  {
  US"tls",                                   /* lookup name */
  auth_tls_options,
  &auth_tls_options_count,
  &auth_tls_option_defaults,
  sizeof(auth_tls_options_block),
  auth_tls_init,                             /* init function */
  auth_tls_server,                           /* server function */
  NULL,                                      /* client function */
  NULL                                       /* diagnostic function */
  },
#endif

{ US"", NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL  }
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

struct lookupmodulestr
{
  void *dl;
  struct lookup_module_info *info;
  struct lookupmodulestr *next;
};

static struct lookupmodulestr *lookupmodules = NULL;

static void addlookupmodule(void *dl, struct lookup_module_info *info)
{
  struct lookupmodulestr *p = store_malloc(sizeof(struct lookupmodulestr));
  p->dl = dl;
  p->info = info;
  p->next = lookupmodules;
  lookupmodules = p;
  lookup_list_count += info->lookupcount;
}

/* only valid after lookup_list and lookup_list_count are assigned */
static void add_lookup_to_list(lookup_info *info)
{
  /* need to add the lookup to lookup_list, sorted */
  int pos = 0;

  /* strategy is to go through the list until we find
   * either an empty spot or a name that is higher.
   * this can't fail because we have enough space. */
  while (lookup_list[pos]
      && (Ustrcmp(lookup_list[pos]->name, info->name) <= 0)) {
    pos++;
  }
  if (lookup_list[pos]) {
    /* need to insert it, so move all the other items up
     * (last slot is still empty, of course) */
    memmove(&lookup_list[pos+1],
            &lookup_list[pos],
            sizeof(lookup_info **) * (lookup_list_count-pos-1));
  }
  lookup_list[pos] = info;
}


/* These need to be at file level for old versions of gcc (2.95.2 reported),
 * which give parse errors on an extern in function scope.  Each entry needs
 * to also be invoked in init_lookup_list() below  */

#if defined(LOOKUP_WHOSON) && LOOKUP_WHOSON!=2
extern lookup_module_info whoson_lookup_module_info;
#endif
#if defined(LOOKUP_TESTDB) && LOOKUP_TESTDB!=2
extern lookup_module_info testdb_lookup_module_info;
#endif
#if defined(LOOKUP_SQLITE) && LOOKUP_SQLITE!=2
extern lookup_module_info sqlite_lookup_module_info;
#endif
#ifdef EXPERIMENTAL_SPF
extern lookup_module_info spf_lookup_module_info;
#endif
#ifdef EXPERIMENTAL_REDIS
extern lookup_module_info redis_lookup_module_info;
#endif
#if defined(LOOKUP_PGSQL) && LOOKUP_PGSQL!=2
extern lookup_module_info pgsql_lookup_module_info;
#endif
#if defined(LOOKUP_PASSWD) && LOOKUP_PASSWD!=2
extern lookup_module_info passwd_lookup_module_info;
#endif
#if defined(LOOKUP_ORACLE) && LOOKUP_ORACLE!=2
extern lookup_module_info oracle_lookup_module_info;
#endif
#if defined(LOOKUP_NISPLUS) && LOOKUP_NISPLUS!=2
extern lookup_module_info nisplus_lookup_module_info;
#endif
#if defined(LOOKUP_NIS) && LOOKUP_NIS!=2
extern lookup_module_info nis_lookup_module_info;
#endif
#if defined(LOOKUP_MYSQL) && LOOKUP_MYSQL!=2
extern lookup_module_info mysql_lookup_module_info;
#endif
#if defined(LOOKUP_LSEARCH) && LOOKUP_LSEARCH!=2
extern lookup_module_info lsearch_lookup_module_info;
#endif
#ifdef LOOKUP_LDAP
extern lookup_module_info ldap_lookup_module_info;
#endif
#if defined(LOOKUP_IBASE) && LOOKUP_IBASE!=2
extern lookup_module_info ibase_lookup_module_info;
#endif
#if defined(LOOKUP_DSEARCH) && LOOKUP_DSEARCH!=2
extern lookup_module_info dsearch_lookup_module_info;
#endif
#if defined(LOOKUP_DNSDB) && LOOKUP_DNSDB!=2
extern lookup_module_info dnsdb_lookup_module_info;
#endif
#if defined(LOOKUP_DBM) && LOOKUP_DBM!=2
extern lookup_module_info dbmdb_lookup_module_info;
#endif
#if defined(LOOKUP_CDB) && LOOKUP_CDB!=2
extern lookup_module_info cdb_lookup_module_info;
#endif

void init_lookup_list(void)
{
#ifdef LOOKUP_MODULE_DIR
  DIR *dd;
  struct dirent *ent;
  int countmodules = 0;
  int moduleerrors = 0;
#endif
  struct lookupmodulestr *p;
  const pcre *regex_islookupmod = regex_must_compile(
      US"\\." DYNLIB_FN_EXT "$", FALSE, TRUE);

  if (lookup_list_init_done)
    return;
  lookup_list_init_done = 1;

#if defined(LOOKUP_CDB) && LOOKUP_CDB!=2
  addlookupmodule(NULL, &cdb_lookup_module_info);
#endif

#if defined(LOOKUP_DBM) && LOOKUP_DBM!=2
  addlookupmodule(NULL, &dbmdb_lookup_module_info);
#endif

#if defined(LOOKUP_DNSDB) && LOOKUP_DNSDB!=2
  addlookupmodule(NULL, &dnsdb_lookup_module_info);
#endif

#if defined(LOOKUP_DSEARCH) && LOOKUP_DSEARCH!=2
  addlookupmodule(NULL, &dsearch_lookup_module_info);
#endif

#if defined(LOOKUP_IBASE) && LOOKUP_IBASE!=2
  addlookupmodule(NULL, &ibase_lookup_module_info);
#endif

#ifdef LOOKUP_LDAP
  addlookupmodule(NULL, &ldap_lookup_module_info);
#endif

#if defined(LOOKUP_LSEARCH) && LOOKUP_LSEARCH!=2
  addlookupmodule(NULL, &lsearch_lookup_module_info);
#endif

#if defined(LOOKUP_MYSQL) && LOOKUP_MYSQL!=2
  addlookupmodule(NULL, &mysql_lookup_module_info);
#endif

#if defined(LOOKUP_NIS) && LOOKUP_NIS!=2
  addlookupmodule(NULL, &nis_lookup_module_info);
#endif

#if defined(LOOKUP_NISPLUS) && LOOKUP_NISPLUS!=2
  addlookupmodule(NULL, &nisplus_lookup_module_info);
#endif

#if defined(LOOKUP_ORACLE) && LOOKUP_ORACLE!=2
  addlookupmodule(NULL, &oracle_lookup_module_info);
#endif

#if defined(LOOKUP_PASSWD) && LOOKUP_PASSWD!=2
  addlookupmodule(NULL, &passwd_lookup_module_info);
#endif

#if defined(LOOKUP_PGSQL) && LOOKUP_PGSQL!=2
  addlookupmodule(NULL, &pgsql_lookup_module_info);
#endif

#ifdef EXPERIMENTAL_REDIS
  addlookupmodule(NULL, &redis_lookup_module_info);
#endif

#ifdef EXPERIMENTAL_SPF
  addlookupmodule(NULL, &spf_lookup_module_info);
#endif

#if defined(LOOKUP_SQLITE) && LOOKUP_SQLITE!=2
  addlookupmodule(NULL, &sqlite_lookup_module_info);
#endif

#if defined(LOOKUP_TESTDB) && LOOKUP_TESTDB!=2
  addlookupmodule(NULL, &testdb_lookup_module_info);
#endif

#if defined(LOOKUP_WHOSON) && LOOKUP_WHOSON!=2
  addlookupmodule(NULL, &whoson_lookup_module_info);
#endif

#ifdef LOOKUP_MODULE_DIR
  dd = opendir(LOOKUP_MODULE_DIR);
  if (dd == NULL) {
    DEBUG(D_lookup) debug_printf("Couldn't open %s: not loading lookup modules\n", LOOKUP_MODULE_DIR);
    log_write(0, LOG_MAIN, "Couldn't open %s: not loading lookup modules\n", LOOKUP_MODULE_DIR);
  }
  else {
    DEBUG(D_lookup) debug_printf("Loading lookup modules from %s\n", LOOKUP_MODULE_DIR);
    while ((ent = readdir(dd)) != NULL) {
      char *name = ent->d_name;
      int len = (int)strlen(name);
      if (pcre_exec(regex_islookupmod, NULL, name, len, 0, PCRE_EOPT, NULL, 0) >= 0) {
        int pathnamelen = len + (int)strlen(LOOKUP_MODULE_DIR) + 2;
        void *dl;
        struct lookup_module_info *info;
        const char *errormsg;

        /* SRH: am I being paranoid here or what? */
        if (pathnamelen > big_buffer_size) {
          fprintf(stderr, "Loading lookup modules: %s/%s: name too long\n", LOOKUP_MODULE_DIR, name);
          log_write(0, LOG_MAIN|LOG_PANIC, "%s/%s: name too long\n", LOOKUP_MODULE_DIR, name);
          continue;
        }

        /* SRH: snprintf here? */
        sprintf(CS big_buffer, "%s/%s", LOOKUP_MODULE_DIR, name);

        dl = dlopen(CS big_buffer, RTLD_NOW);// TJ was LAZY
        if (dl == NULL) {
          fprintf(stderr, "Error loading %s: %s\n", name, dlerror());
          moduleerrors++;
          log_write(0, LOG_MAIN|LOG_PANIC, "Error loading lookup module %s: %s\n", name, dlerror());
          continue;
        }

        /* FreeBSD nsdispatch() can trigger dlerror() errors about
         * _nss_cache_cycle_prevention_function; we need to clear the dlerror()
         * state before calling dlsym(), so that any error afterwards only
         * comes from dlsym().
         */
        errormsg = dlerror();

        info = (struct lookup_module_info*) dlsym(dl, "_lookup_module_info");
        if ((errormsg = dlerror()) != NULL) {
          fprintf(stderr, "%s does not appear to be a lookup module (%s)\n", name, errormsg);
          dlclose(dl);
          moduleerrors++;
          log_write(0, LOG_MAIN|LOG_PANIC, "%s does not appear to be a lookup module (%s)\n", name, errormsg);
          continue;
        }
        if (info->magic != LOOKUP_MODULE_INFO_MAGIC) {
          fprintf(stderr, "Lookup module %s is not compatible with this version of Exim\n", name);
          dlclose(dl);
          moduleerrors++;
          log_write(0, LOG_MAIN|LOG_PANIC, "Lookup module %s is not compatible with this version of Exim\n", name);
          continue;
        }

        addlookupmodule(dl, info);
        DEBUG(D_lookup) debug_printf("Loaded \"%s\" (%d lookup types)\n", name, info->lookupcount);
        countmodules++;
      }
    }
    closedir(dd);
  }

  DEBUG(D_lookup) debug_printf("Loaded %d lookup modules\n", countmodules);
#endif

  store_free((void*)regex_islookupmod);

  DEBUG(D_lookup) debug_printf("Total %d lookups\n", lookup_list_count);

  lookup_list = store_malloc(sizeof(lookup_info *) * lookup_list_count);
  memset(lookup_list, 0, sizeof(lookup_info *) * lookup_list_count);

  /* now add all lookups to the real list */
  p = lookupmodules;
  while (p) {
    int j;
    struct lookupmodulestr *pnext;

    for (j = 0; j < p->info->lookupcount; j++)
      add_lookup_to_list(p->info->lookups[j]);

    pnext = p->next;
    store_free(p);
    p = pnext;
  }
  /* just to be sure */
  lookupmodules = NULL;
}

/* End of drtables.c */
