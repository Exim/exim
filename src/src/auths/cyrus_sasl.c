/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2023 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

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
static void dummy(int x);
static void dummy2(int x) { dummy(x-1); }
static void dummy(int x) { dummy2(x-1); }
#else


#include <sasl/sasl.h>
#include "cyrus_sasl.h"

/* Options specific to the cyrus_sasl authentication mechanism. */

optionlist auth_cyrus_sasl_options[] = {
  { "server_hostname",      opt_stringptr,
      OPT_OFF(auth_cyrus_sasl_options_block, server_hostname) },
  { "server_mech",          opt_stringptr,
      OPT_OFF(auth_cyrus_sasl_options_block, server_mech) },
  { "server_realm",         opt_stringptr,
      OPT_OFF(auth_cyrus_sasl_options_block, server_realm) },
  { "server_service",       opt_stringptr,
      OPT_OFF(auth_cyrus_sasl_options_block, server_service) }
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


#ifdef MACRO_PREDEF

/* Dummy values */
void auth_cyrus_sasl_init(auth_instance *ablock) {}
int auth_cyrus_sasl_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_cyrus_sasl_client(auth_instance *ablock, void * sx,
  int timeout, uschar *buffer, int buffsize) {return 0;}
gstring * auth_cyrus_sasl_version_report(gstring * g) {return NULL;}

#else   /*!MACRO_PREDEF*/




/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */


/* Auxiliary function, passed in data to sasl_server_init(). */

static int
mysasl_config(void *context, const char *plugin_name, const char *option,
      const char **result, unsigned int *len)
{
if (context && !strcmp(option, "mech_list"))
  {
  *result = context;
  if (len) *len = strlen(*result);
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
const uschar *list, *listptr, *buffer;
int rc, i;
unsigned int len;
rmark rs_point;
uschar *expanded_hostname;
char *realm_expanded;

sasl_conn_t *conn;
sasl_callback_t cbs[] = {
  {SASL_CB_GETOPT, NULL, NULL },
  {SASL_CB_LIST_END, NULL, NULL}};

/* default the mechanism to our "public name" */

if (!ob->server_mech) ob->server_mech = string_copy(ablock->public_name);

if (!(expanded_hostname = expand_string(ob->server_hostname)))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "couldn't expand server_hostname [%s]: %s",
      ablock->name, ob->server_hostname, expand_string_message);

realm_expanded = NULL;
if (  ob->server_realm
   && !(realm_expanded = CS expand_string(ob->server_realm)))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "couldn't expand server_realm [%s]: %s",
      ablock->name, ob->server_realm, expand_string_message);

/* we're going to initialise the library to check that there is an
authenticator of type whatever mechanism we're using */

cbs[0].proc = (int(*)(void)) &mysasl_config;
cbs[0].context = ob->server_mech;

if ((rc = sasl_server_init(cbs, "exim")) != SASL_OK)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "couldn't initialise Cyrus SASL library.", ablock->name);

if ((rc = sasl_server_new(CS ob->server_service, CS expanded_hostname,
                   realm_expanded, NULL, NULL, NULL, 0, &conn)) != SASL_OK)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "couldn't initialise Cyrus SASL server connection.", ablock->name);

if ((rc = sasl_listmech(conn, NULL, "", ":", "", CCSS &list, &len, &i)) != SASL_OK)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "couldn't get Cyrus SASL mechanism list.", ablock->name);

i = ':';
listptr = list;

HDEBUG(D_auth)
  {
  debug_printf("Initialised Cyrus SASL service=\"%s\" fqdn=\"%s\" realm=\"%s\"\n",
      ob->server_service, expanded_hostname, realm_expanded);
  debug_printf("Cyrus SASL knows mechanisms: %s\n", list);
  }

/* the store_get / store_reset mechanism is hierarchical
 the hierarchy is stored for us behind our back. This point
 creates a hierarchy point for this function.  */

rs_point = store_mark();

/* loop until either we get to the end of the list, or we match the
public name of this authenticator */

while (  (buffer = string_nextinlist(&listptr, &i, NULL, 0))
      && strcmpic(buffer,ob->server_mech) );

if (!buffer)
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
within a shortlived child */

int
auth_cyrus_sasl_server(auth_instance * ablock, uschar * data)
{
auth_cyrus_sasl_options_block * ob =
  (auth_cyrus_sasl_options_block *)(ablock->options_block);
uschar * output, * out2, * input, * clear, * hname;
uschar * debug = NULL;   /* Stops compiler complaining */
sasl_callback_t cbs[] = {{SASL_CB_LIST_END, NULL, NULL}};
sasl_conn_t * conn;
char * realm_expanded = NULL;
int rc, firsttime = 1, clen, * negotiated_ssf_ptr = NULL, negotiated_ssf;
unsigned int inlen, outlen;

input = data;
inlen = Ustrlen(data);

HDEBUG(D_auth) debug = string_copy(data);

hname = expand_string(ob->server_hostname);
if (hname && ob->server_realm)
  realm_expanded = CS expand_string(ob->server_realm);
if (!hname  ||  !realm_expanded  && ob->server_realm)
  {
  auth_defer_msg = expand_string_message;
  return DEFER;
  }

if (inlen)
  {
  if ((clen = b64decode(input, &clear, input)) < 0)
    return BAD64;
  input = clear;
  inlen = clen;
  }

if ((rc = sasl_server_init(cbs, "exim")) != SASL_OK)
  {
  auth_defer_msg = US"couldn't initialise Cyrus SASL library";
  return DEFER;
  }

rc = sasl_server_new(CS ob->server_service, CS hname, realm_expanded, NULL,
  NULL, NULL, 0, &conn);

HDEBUG(D_auth)
  debug_printf("Initialised Cyrus SASL server connection; service=\"%s\" fqdn=\"%s\" realm=\"%s\"\n",
      ob->server_service, hname, realm_expanded);

if (rc != SASL_OK )
  {
  auth_defer_msg = US"couldn't initialise Cyrus SASL connection";
  sasl_done();
  return DEFER;
  }

if (tls_in.cipher)
  {
  if ((rc = sasl_setprop(conn, SASL_SSF_EXTERNAL, (sasl_ssf_t *) &tls_in.bits)) != SASL_OK)
    {
    HDEBUG(D_auth) debug_printf("Cyrus SASL EXTERNAL SSF set %d failed: %s\n",
        tls_in.bits, sasl_errstring(rc, NULL, NULL));
    auth_defer_msg = US"couldn't set Cyrus SASL EXTERNAL SSF";
    sasl_done();
    return DEFER;
    }
  else
    HDEBUG(D_auth) debug_printf("Cyrus SASL set EXTERNAL SSF to %d\n", tls_in.bits);

  /*XXX Set channel-binding here with sasl_channel_binding_t / SASL_CHANNEL_BINDING
  Unclear what the "name" element does though, ditto the "critical" flag. */
  }
else
  HDEBUG(D_auth) debug_printf("Cyrus SASL: no TLS, no EXTERNAL SSF set\n");

/* So sasl_setprop() documents non-shorted IPv6 addresses which is incredibly
annoying; looking at cyrus-imapd-2.3.x source, the IP address is constructed
with their iptostring() function, which just wraps
getnameinfo(..., NI_NUMERICHOST|NI_NUMERICSERV), which is equivalent to the
inet_ntop which we wrap in our host_ntoa() function.

So the docs are too strict and we shouldn't worry about :: contractions. */

/* Set properties for remote and local host-ip;port */
for (int i = 0; i < 2; ++i)
  {
  int propnum;
  const uschar * label;
  uschar * address_port;
  const char *s_err;

  if (i)
    {
    propnum = SASL_IPREMOTEPORT;
    label = CUS"peer";
    address_port = string_sprintf("%s;%d",
				  sender_host_address, sender_host_port);
    }
  else
    {
    propnum = SASL_IPLOCALPORT;
    label = CUS"local";
    address_port = string_sprintf("%s;%d", interface_address, interface_port);
    }

  if ((rc = sasl_setprop(conn, propnum, address_port)) != SASL_OK)
    {
    HDEBUG(D_auth)
      {
      s_err = sasl_errdetail(conn);
      debug_printf("Failed to set %s SASL property: [%d] %s\n",
          label, rc, s_err ? s_err : "<unknown reason>");
      }
    break;
    }
  HDEBUG(D_auth) debug_printf("Cyrus SASL set %s hostport to: %s\n",
      label, address_port);
  }

for (rc = SASL_CONTINUE; rc == SASL_CONTINUE; )
  {
  if (firsttime)
    {
    firsttime = 0;
    HDEBUG(D_auth) debug_printf("Calling sasl_server_start(%s,\"%s\")\n", ob->server_mech, debug);
    rc = sasl_server_start(conn, CS ob->server_mech, inlen ? CS input : NULL, inlen,
           CCSS &output, &outlen);
    }
  else
    {
    /* auth_get_data() takes a length-specfied block of binary
    which can include zeroes; no terminating NUL is needed */

    if ((rc = auth_get_data(&input, output, outlen)) != OK)
      {
      /* we couldn't get the data, so free up the library before
      returning whatever error we get */
      sasl_dispose(&conn);
      sasl_done();
      return rc;
      }
    inlen = Ustrlen(input);

    HDEBUG(D_auth) debug = string_copy_taint(input, GET_TAINTED);
    if (inlen)
      {
      if ((clen = b64decode(input, &clear, GET_TAINTED)) < 0)
       {
       sasl_dispose(&conn);
       sasl_done();
       return BAD64;
       }
      input = clear;
      inlen = clen;
      }

    HDEBUG(D_auth) debug_printf("Calling sasl_server_step(\"%s\")\n", debug);
    rc = sasl_server_step(conn, CS input, inlen, CCSS &output, &outlen);
    }

  if (rc == SASL_BADPROT)
    {
    sasl_dispose(&conn);
    sasl_done();
    return UNEXPECTED;
    }
  if (rc == SASL_CONTINUE)
    continue;

  /* Get the username and copy it into $auth1 and $1. The former is now the
  preferred variable; the latter is the original variable. */

  if ((sasl_getprop(conn, SASL_USERNAME, (const void **)&out2)) != SASL_OK)
    {
    HDEBUG(D_auth)
      debug_printf("Cyrus SASL library will not tell us the username: %s\n",
	  sasl_errstring(rc, NULL, NULL));
    log_write(0, LOG_REJECT, "%s authenticator (%s): "
       "Cyrus SASL username fetch problem: %s", ablock->name, ob->server_mech,
       sasl_errstring(rc, NULL, NULL));
    sasl_dispose(&conn);
    sasl_done();
    return FAIL;
    }
  auth_vars[0] = expand_nstring[1] = string_copy(out2);
  expand_nlength[1] = Ustrlen(out2);
  expand_nmax = 1;

  switch (rc)
    {
    case SASL_FAIL: case SASL_BUFOVER: case SASL_BADMAC: case SASL_BADAUTH:
    case SASL_NOAUTHZ: case SASL_ENCRYPT: case SASL_EXPIRED:
    case SASL_DISABLED: case SASL_NOUSER:
      /* these are considered permanent failure codes */
      HDEBUG(D_auth)
	debug_printf("Cyrus SASL permanent failure %d (%s)\n", rc, sasl_errstring(rc, NULL, NULL));
      log_write(0, LOG_REJECT, "%s authenticator (%s): "
	 "Cyrus SASL permanent failure: %s", ablock->name, ob->server_mech,
	 sasl_errstring(rc, NULL, NULL));
      sasl_dispose(&conn);
      sasl_done();
      return FAIL;

    case SASL_NOMECH:
      /* this is a temporary failure, because the mechanism is not
      available for this user. If it wasn't available at all, we
      shouldn't have got here in the first place...  */

      HDEBUG(D_auth)
	debug_printf("Cyrus SASL temporary failure %d (%s)\n", rc, sasl_errstring(rc, NULL, NULL));
      auth_defer_msg =
	  string_sprintf("Cyrus SASL: mechanism %s not available", ob->server_mech);
      sasl_dispose(&conn);
      sasl_done();
      return DEFER;

    case SASL_OK:
      HDEBUG(D_auth)
	debug_printf("Cyrus SASL %s authentication succeeded for %s\n",
	    ob->server_mech, auth_vars[0]);

      if ((rc = sasl_getprop(conn, SASL_SSF, (const void **)(&negotiated_ssf_ptr)))!= SASL_OK)
	{
	HDEBUG(D_auth)
	  debug_printf("Cyrus SASL library will not tell us the SSF: %s\n",
	      sasl_errstring(rc, NULL, NULL));
	log_write(0, LOG_REJECT, "%s authenticator (%s): "
	    "Cyrus SASL SSF value not available: %s", ablock->name, ob->server_mech,
	    sasl_errstring(rc, NULL, NULL));
	sasl_dispose(&conn);
	sasl_done();
	return FAIL;
	}
      negotiated_ssf = *negotiated_ssf_ptr;
      HDEBUG(D_auth)
	debug_printf("Cyrus SASL %s negotiated SSF: %d\n", ob->server_mech, negotiated_ssf);
      if (negotiated_ssf > 0)
	{
	HDEBUG(D_auth)
	  debug_printf("Exim does not implement SASL wrapping (needed for SSF %d).\n", negotiated_ssf);
	log_write(0, LOG_REJECT, "%s authenticator (%s): "
	    "Cyrus SASL SSF %d not supported by Exim", ablock->name, ob->server_mech, negotiated_ssf);
	sasl_dispose(&conn);
	sasl_done();
	return FAIL;
	}

      /* close down the connection, freeing up library's memory */
      sasl_dispose(&conn);
      sasl_done();

      /* Expand server_condition as an authorization check */
      return auth_check_serv_cond(ablock);

    default:
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
  }
/* NOTREACHED */
return 0;  /* Stop compiler complaints */
}

/*************************************************
*                Diagnostic API                  *
*************************************************/

gstring *
auth_cyrus_sasl_version_report(gstring * g)
{
const char * implementation, * version;
sasl_version_info(&implementation, &version, NULL, NULL, NULL, NULL);
g = string_fmt_append(g,
	"Library version: Cyrus SASL: Compile: %d.%d.%d\n"
	"                             Runtime: %s [%s]\n",
	SASL_VERSION_MAJOR, SASL_VERSION_MINOR, SASL_VERSION_STEP,
	version, implementation);
return g;
}

/*************************************************
*              Client entry point                *
*************************************************/

/* For interface, see auths/README */

int
auth_cyrus_sasl_client(
  auth_instance *ablock,                 /* authenticator block */
  void * sx,			 	 /* connexction */
  int timeout,                           /* command timeout */
  uschar *buffer,                        /* for reading response */
  int buffsize)                          /* size of buffer */
{
/* We don't support clients (yet) in this implementation of cyrus_sasl */
return FAIL;
}

#endif   /*!MACRO_PREDEF*/
#endif  /* AUTH_CYRUS_SASL */

/* End of cyrus_sasl.c */
