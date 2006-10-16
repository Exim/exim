/* $Cambridge: exim/src/src/auths/cyrus_sasl.c,v 1.5 2006/10/16 15:44:36 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2003 */
/* See the file NOTICE for conditions of use and distribution. */

/* This code was originally contributed by Matthew Byng-Maddick */

/* Copyright (c) A L Digital 2004 */

/* A generic (mechanism independent) Cyrus SASL authenticator. */


#include "../exim.h"


/* We can't just compile this code and allow the library mechanism to omit the
functions if they are not wanted, because we need to have the Cyrus SASL header
available for compiling. Therefore, compile these functions only if
AUTH_CYRUS_SASL is defined. However, some compilers don't like compiling empty
modules, so keep them happy with a dummy when skipping the rest. Make it
reference itself to stop picky compilers complaining that it is unused, and put
in a dummy argument to stop even pickier compilers complaining about infinite
loops. */

#ifndef AUTH_CYRUS_SASL
static void dummy(int x) { dummy(x-1); }
#else


#include <sasl/sasl.h>
#include "cyrus_sasl.h"

/* Options specific to the cyrus_sasl authentication mechanism. */

optionlist auth_cyrus_sasl_options[] = {
  { "server_hostname",      opt_stringptr,
      (void *)(offsetof(auth_cyrus_sasl_options_block, server_hostname)) },
  { "server_mech",          opt_stringptr,
      (void *)(offsetof(auth_cyrus_sasl_options_block, server_mech)) },
  { "server_realm",         opt_stringptr,
      (void *)(offsetof(auth_cyrus_sasl_options_block, server_realm)) },
  { "server_service",       opt_stringptr,
      (void *)(offsetof(auth_cyrus_sasl_options_block, server_service)) }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int auth_cyrus_sasl_options_count =
  sizeof(auth_cyrus_sasl_options)/sizeof(optionlist);

/* Default private options block for the cyrus_sasl authentication method. */

auth_cyrus_sasl_options_block auth_cyrus_sasl_option_defaults = {
  US"smtp",         /* server_service */
  US"$primary_hostname", /* server_hostname */
  NULL,             /* server_realm */
  NULL              /* server_mech */
};


/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */


/* Auxiliary function, passed in data to sasl_server_init(). */

static int
mysasl_config(void *context,
              const char *plugin_name,
              const char *option,
              const char **result,
              unsigned int *len)
{
if (context && !strcmp(option, "mech_list"))
  {
  *result = context;
  if (len != NULL) *len = strlen(*result);
  return SASL_OK;
  }
return SASL_FAIL;
}

/* Here's the real function */

void
auth_cyrus_sasl_init(auth_instance *ablock)
{
auth_cyrus_sasl_options_block *ob =
  (auth_cyrus_sasl_options_block *)(ablock->options_block);
uschar *list, *listptr, *buffer;
int rc, i;
unsigned int len;
uschar *rs_point;

sasl_conn_t *conn;
sasl_callback_t cbs[]={
  {SASL_CB_GETOPT, NULL, NULL },
  {SASL_CB_LIST_END, NULL, NULL}};

/* default the mechanism to our "public name" */
if(ob->server_mech == NULL)
  ob->server_mech=string_copy(ablock->public_name);

/* we're going to initialise the library to check that there is an
 * authenticator of type whatever mechanism we're using
 */

cbs[0].proc = &mysasl_config;
cbs[0].context = ob->server_mech;

rc=sasl_server_init(cbs, "exim");

if( rc != SASL_OK )
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "couldn't initialise Cyrus SASL library.", ablock->name);

rc=sasl_server_new(CS ob->server_service, CS primary_hostname,
                   CS ob->server_realm, NULL, NULL, NULL, 0, &conn);
if( rc != SASL_OK )
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "couldn't initialise Cyrus SASL server connection.", ablock->name);

rc=sasl_listmech(conn, NULL, "", ":", "", (const char **)(&list), &len, &i);
if( rc != SASL_OK )
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "couldn't get Cyrus SASL mechanism list.", ablock->name);

i=':';
listptr=list;

HDEBUG(D_auth) debug_printf("Cyrus SASL knows about: %s\n", list);

/* the store_get / store_reset mechanism is hierarchical
 * the hierarchy is stored for us behind our back. This point
 * creates a hierarchy point for this function.
 */
rs_point=store_get(0);

/* loop until either we get to the end of the list, or we match the
 * public name of this authenticator
 */
while( ( buffer = string_nextinlist(&listptr, &i, NULL, 0) ) &&
       strcmpic(buffer,ob->server_mech) );

if(!buffer)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "Cyrus SASL doesn't know about mechanism %s.", ablock->name, ob->server_mech);

store_reset(rs_point);

HDEBUG(D_auth) debug_printf("Cyrus SASL driver %s: %s initialised\n", ablock->name, ablock->public_name);

/* make sure that if we get here then we're allowed to advertise. */
ablock->server = TRUE;

sasl_dispose(&conn);
sasl_done();
}

/*************************************************
*             Server entry point                 *
*************************************************/

/* For interface, see auths/README */

/* note, we don't care too much about memory allocation in this, because this is entirely
 * within a shortlived child
 */

int
auth_cyrus_sasl_server(auth_instance *ablock, uschar *data)
{
auth_cyrus_sasl_options_block *ob =
  (auth_cyrus_sasl_options_block *)(ablock->options_block);
uschar *output, *out2, *input, *clear, *hname;
uschar *debug = NULL;   /* Stops compiler complaining */
sasl_callback_t cbs[]={{SASL_CB_LIST_END, NULL, NULL}};
sasl_conn_t *conn;
int rc, firsttime=1, clen;
unsigned int inlen, outlen;

input=data;
inlen=Ustrlen(data);

HDEBUG(D_auth) debug=string_copy(data);

hname=expand_string(ob->server_hostname);
if(hname == NULL)
  {
  auth_defer_msg = expand_string_message;
  return DEFER;
  }

if(inlen)
  {
  clen=auth_b64decode(input, &clear);
  if(clen < 0)
    {
    return BAD64;
    }
  input=clear;
  inlen=clen;
  }

rc=sasl_server_init(cbs, "exim");
if (rc != SASL_OK)
  {
  auth_defer_msg = US"couldn't initialise Cyrus SASL library";
  return DEFER;
  }

rc=sasl_server_new(CS ob->server_service, CS hname, CS ob->server_realm, NULL,
  NULL, NULL, 0, &conn);

if( rc != SASL_OK )
  {
  auth_defer_msg = US"couldn't initialise Cyrus SASL connection";
  sasl_done();
  return DEFER;
  }

rc=SASL_CONTINUE;

while(rc==SASL_CONTINUE)
  {
  if(firsttime)
    {
    firsttime=0;
    HDEBUG(D_auth) debug_printf("Calling sasl_server_start(%s,\"%s\")\n", ob->server_mech, debug);
    rc=sasl_server_start(conn, CS ob->server_mech, inlen?CS input:NULL, inlen,
           (const char **)(&output), &outlen);
    }
  else
    {
    /* make sure that we have a null-terminated string */
    out2=store_get(outlen+1);
    memcpy(out2,output,outlen);
    out2[outlen]='\0';
    if((rc=auth_get_data(&input, out2, outlen))!=OK)
      {
      /* we couldn't get the data, so free up the library before
       * returning whatever error we get */
      sasl_dispose(&conn);
      sasl_done();
      return rc;
      }
    inlen=Ustrlen(input);

    HDEBUG(D_auth) debug=string_copy(input);
    if(inlen)
      {
      clen=auth_b64decode(input, &clear);
      if(clen < 0)
       {
        sasl_dispose(&conn);
        sasl_done();
       return BAD64;
       }
      input=clear;
      inlen=clen;
      }

    HDEBUG(D_auth) debug_printf("Calling sasl_server_step(\"%s\")\n", debug);
    rc=sasl_server_step(conn, CS input, inlen, (const char **)(&output), &outlen);
    }
  if(rc==SASL_BADPROT)
    {
    sasl_dispose(&conn);
    sasl_done();
    return UNEXPECTED;
    }
  else if( rc==SASL_FAIL     || rc==SASL_BUFOVER
       || rc==SASL_BADMAC   || rc==SASL_BADAUTH
       || rc==SASL_NOAUTHZ  || rc==SASL_ENCRYPT
       || rc==SASL_EXPIRED  || rc==SASL_DISABLED
       || rc==SASL_NOUSER   )
    {
    /* these are considered permanent failure codes */
    HDEBUG(D_auth)
      debug_printf("Cyrus SASL permanent failure %d (%s)\n", rc, sasl_errstring(rc, NULL, NULL));
    log_write(0, LOG_REJECT, "%s authenticator (%s):\n  "
       "Cyrus SASL permanent failure: %s", ablock->name, ob->server_mech,
       sasl_errstring(rc, NULL, NULL));
    sasl_dispose(&conn);
    sasl_done();
    return FAIL;
    }
  else if(rc==SASL_NOMECH)
    {
    /* this is a temporary failure, because the mechanism is not
     * available for this user. If it wasn't available at all, we
     * shouldn't have got here in the first place...
     */
    HDEBUG(D_auth)
      debug_printf("Cyrus SASL temporary failure %d (%s)\n", rc, sasl_errstring(rc, NULL, NULL));
    auth_defer_msg =
        string_sprintf("Cyrus SASL: mechanism %s not available", ob->server_mech);
    sasl_dispose(&conn);
    sasl_done();
    return DEFER;
    }
  else if(!(rc==SASL_OK || rc==SASL_CONTINUE))
    {
    /* Anything else is a temporary failure, and we'll let SASL print out
     * the error string for us
     */
    HDEBUG(D_auth)
      debug_printf("Cyrus SASL temporary failure %d (%s)\n", rc, sasl_errstring(rc, NULL, NULL));
    auth_defer_msg =
        string_sprintf("Cyrus SASL: %s", sasl_errstring(rc, NULL, NULL));
    sasl_dispose(&conn);
    sasl_done();
    return DEFER;
    }
  else if(rc==SASL_OK)
    {
    /* Get the username and copy it into $auth1 and $1. The former is now the
    preferred variable; the latter is the original variable. */
    rc = sasl_getprop(conn, SASL_USERNAME, (const void **)(&out2));
    auth_vars[0] = expand_nstring[1] = string_copy(out2);
    expand_nlength[1] = Ustrlen(expand_nstring[1]);
    expand_nmax = 1;

    HDEBUG(D_auth)
      debug_printf("Cyrus SASL %s authentication succeeded for %s\n", ob->server_mech, out2);
    /* close down the connection, freeing up library's memory */
    sasl_dispose(&conn);
    sasl_done();

    /* Expand server_condition as an authorization check */
    return auth_check_serv_cond(ablock);
    }
  }
/* NOTREACHED */
return 0;  /* Stop compiler complaints */
}

/*************************************************
*              Client entry point                *
*************************************************/

/* For interface, see auths/README */

int
auth_cyrus_sasl_client(
  auth_instance *ablock,                 /* authenticator block */
  smtp_inblock *inblock,                 /* input connection */
  smtp_outblock *outblock,               /* output connection */
  int timeout,                           /* command timeout */
  uschar *buffer,                          /* for reading response */
  int buffsize)                          /* size of buffer */
{
/* We don't support clients (yet) in this implementation of cyrus_sasl */
return FAIL;
}

#endif  /* AUTH_CYRUS_SASL */

/* End of cyrus_sasl.c */
