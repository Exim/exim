/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2019-2020 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Copyright (c) Twitter Inc 2012
   Author: Phil Pennock <pdp@exim.org> */
/* Copyright (c) Phil Pennock 2012 */

/* Interface to GNU SASL library for generic authentication. */

/* Trade-offs:

GNU SASL does not provide authentication data itself, so we have to expose
that decision to configuration.  For some mechanisms, we need to act much
like plaintext.  For others, we only need to be able to provide some
evaluated data on demand.  There's no abstracted way (ie, without hardcoding
knowledge of authenticators here) to know which need what properties; we
can't query a session or the library for "we will need these for mechanism X".

So: we always require server_condition, even if sometimes it will just be
set as "yes".  We do provide a number of other hooks, which might not make
sense in all contexts.  For some, we can do checks at init time.
*/

#include "../exim.h"
#define CHANNELBIND_HACK

#ifndef AUTH_GSASL
/* dummy function to satisfy compilers when we link in an "empty" file. */
static void dummy(int x);
static void dummy2(int x) { dummy(x-1); }
static void dummy(int x) { dummy2(x-1); }
#else

#include <gsasl.h>
#include "gsasl_exim.h"


#if GSASL_VERSION_MINOR >= 9
# define EXIM_GSASL_HAVE_SCRAM_SHA_256

# if GSASL_VERSION_PATCH >= 1
#  define EXIM_GSASL_SCRAM_S_KEY
# endif
#endif


/* Authenticator-specific options. */
/* I did have server_*_condition options for various mechanisms, but since
we only ever handle one mechanism at a time, I didn't see the point in keeping
that.  In case someone sees a point, I've left the condition_check() API
alone. */
#define LOFF(field) OPT_OFF(auth_gsasl_options_block, field)

optionlist auth_gsasl_options[] = {
  { "client_authz",		opt_stringptr,	LOFF(client_authz) },
  { "client_channelbinding",	opt_bool,	LOFF(client_channelbinding) },
  { "client_password",		opt_stringptr,	LOFF(client_password) },
  { "client_spassword",		opt_stringptr,	LOFF(client_spassword) },
  { "client_username",		opt_stringptr,	LOFF(client_username) },

  { "server_channelbinding",	opt_bool,	LOFF(server_channelbinding) },
  { "server_hostname",		opt_stringptr,	LOFF(server_hostname) },
#ifdef EXIM_GSASL_SCRAM_S_KEY
  { "server_key",		opt_stringptr,	LOFF(server_key) },
#endif
  { "server_mech",		opt_stringptr,	LOFF(server_mech) },
  { "server_password",		opt_stringptr,	LOFF(server_password) },
  { "server_realm",		opt_stringptr,	LOFF(server_realm) },
  { "server_scram_iter",	opt_stringptr,	LOFF(server_scram_iter) },
  { "server_scram_salt",	opt_stringptr,	LOFF(server_scram_salt) },
#ifdef EXIM_GSASL_SCRAM_S_KEY
  { "server_skey",		opt_stringptr,	LOFF(server_s_key) },
#endif
  { "server_service",		opt_stringptr,	LOFF(server_service) }
};

int auth_gsasl_options_count =
  sizeof(auth_gsasl_options)/sizeof(optionlist);

/* Defaults for the authenticator-specific options. */
auth_gsasl_options_block auth_gsasl_option_defaults = {
  .server_service = US"smtp",
  .server_hostname = US"$primary_hostname",
  .server_scram_iter = US"4096",
  /* all others zero/null */
};


#ifdef MACRO_PREDEF
# include "../macro_predef.h"

/* Dummy values */
void auth_gsasl_init(auth_instance *ablock) {}
int auth_gsasl_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_gsasl_client(auth_instance *ablock, void * sx,
  int timeout, uschar *buffer, int buffsize) {return 0;}
void auth_gsasl_version_report(FILE *f) {}

void
auth_gsasl_macros(void)
{
# ifdef EXIM_GSASL_HAVE_SCRAM_SHA_256
  builtin_macro_create(US"_HAVE_AUTH_GSASL_SCRAM_SHA_256");
# endif
# ifdef EXIM_GSASL_SCRAM_S_KEY
  builtin_macro_create(US"_HAVE_AUTH_GSASL_SCRAM_S_KEY");
# endif
}

#else   /*!MACRO_PREDEF*/



/* "Globals" for managing the gsasl interface. */

static Gsasl *gsasl_ctx = NULL;
static int
  main_callback(Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop);
static int
  server_callback(Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop, auth_instance *ablock);
static int
  client_callback(Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop, auth_instance *ablock);

static BOOL sasl_error_should_defer = FALSE;
static Gsasl_property callback_loop = 0;
static BOOL checked_server_condition = FALSE;

enum { CURRENTLY_SERVER = 1, CURRENTLY_CLIENT = 2 };

struct callback_exim_state {
  auth_instance *ablock;
  int currently;
};


/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
auth_gsasl_init(auth_instance *ablock)
{
static char * once = NULL;
int rc;
auth_gsasl_options_block *ob =
  (auth_gsasl_options_block *)(ablock->options_block);

/* As per existing Cyrus glue, use the authenticator's public name as
the default for the mechanism name; we don't handle multiple mechanisms
in one authenticator, but the same driver can be used multiple times. */

if (!ob->server_mech)
  ob->server_mech = string_copy(ablock->public_name);

/* Can get multiple session contexts from one library context, so just
initialise the once. */

if (!gsasl_ctx)
  {
  if ((rc = gsasl_init(&gsasl_ctx)) != GSASL_OK)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
	      "couldn't initialise GNU SASL library: %s (%s)",
	      ablock->name, gsasl_strerror_name(rc), gsasl_strerror(rc));

  gsasl_callback_set(gsasl_ctx, main_callback);
  }

/* We don't need this except to log it for debugging. */

HDEBUG(D_auth) if (!once)
  {
  if ((rc = gsasl_server_mechlist(gsasl_ctx, &once)) != GSASL_OK)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
	      "failed to retrieve list of mechanisms: %s (%s)",
	      ablock->name,  gsasl_strerror_name(rc), gsasl_strerror(rc));

  debug_printf("GNU SASL supports: %s\n", once);
  }

if (!gsasl_client_support_p(gsasl_ctx, CCS ob->server_mech))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
	    "GNU SASL does not support mechanism \"%s\"",
	    ablock->name, ob->server_mech);

ablock->server = TRUE;

if (  !ablock->server_condition
   && (  streqic(ob->server_mech, US"EXTERNAL")
      || streqic(ob->server_mech, US"ANONYMOUS")
      || streqic(ob->server_mech, US"PLAIN")
      || streqic(ob->server_mech, US"LOGIN")
   )  )
  {
  ablock->server = FALSE;
  HDEBUG(D_auth) debug_printf("%s authenticator:  "
	    "Need server_condition for %s mechanism\n",
	    ablock->name, ob->server_mech);
  }

/* This does *not* scale to new SASL mechanisms.  Need a better way to ask
which properties will be needed. */

if (  !ob->server_realm
   && streqic(ob->server_mech, US"DIGEST-MD5"))
  {
  ablock->server = FALSE;
  HDEBUG(D_auth) debug_printf("%s authenticator:  "
	    "Need server_realm for %s mechanism\n",
	    ablock->name, ob->server_mech);
  }

/* At present, for mechanisms we don't panic on absence of server_condition;
need to figure out the most generically correct approach to deciding when
it's critical and when it isn't.  Eg, for simple validation (PLAIN mechanism,
etc) it clearly is critical.
*/

ablock->client = ob->client_username && ob->client_password;
}


/* GNU SASL uses one top-level callback, registered at library level.
We dispatch to client and server functions instead. */

static int
main_callback(Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop)
{
int rc = 0;
struct callback_exim_state *cb_state =
  (struct callback_exim_state *)gsasl_session_hook_get(sctx);

if (!cb_state)
  {
  HDEBUG(D_auth) debug_printf("gsasl callback (%d) not from our server/client processing\n", prop);
#ifdef CHANNELBIND_HACK
  if (prop == GSASL_CB_TLS_UNIQUE)
    {
    uschar * s;
    if ((s = gsasl_callback_hook_get(ctx)))
      {
      HDEBUG(D_auth) debug_printf("GSASL_CB_TLS_UNIQUE from ctx hook\n");
      gsasl_property_set(sctx, GSASL_CB_TLS_UNIQUE, CS s);
      }
    else
      {
      HDEBUG(D_auth) debug_printf("GSASL_CB_TLS_UNIQUE!  dummy for now\n");
      gsasl_property_set(sctx, GSASL_CB_TLS_UNIQUE, "");
      }
    return GSASL_OK;
    }
#endif
  return GSASL_NO_CALLBACK;
  }

HDEBUG(D_auth)
  debug_printf("GNU SASL Callback entered, prop=%d (loop prop=%d)\n",
      prop, callback_loop);

if (callback_loop > 0)
  {
  /* Most likely is that we were asked for property FOO, and to
  expand the string we asked for property BAR to put into an auth
  variable, but property BAR is not supplied for this mechanism. */
  HDEBUG(D_auth)
    debug_printf("Loop, asked for property %d while handling property %d\n",
	prop, callback_loop);
  return GSASL_NO_CALLBACK;
  }
callback_loop = prop;

if (cb_state->currently == CURRENTLY_CLIENT)
  rc = client_callback(ctx, sctx, prop, cb_state->ablock);
else if (cb_state->currently == CURRENTLY_SERVER)
  rc = server_callback(ctx, sctx, prop, cb_state->ablock);
else
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
      "unhandled callback state, bug in Exim", cb_state->ablock->name);
  /* NOTREACHED */

callback_loop = 0;
return rc;
}


/*************************************************
*             Debug service function             *
*************************************************/
static const uschar * 
gsasl_prop_code_to_name(Gsasl_property prop)
{
switch (prop)
  {
  case GSASL_AUTHID: return US"AUTHID";
  case GSASL_AUTHZID: return US"AUTHZID";
  case GSASL_PASSWORD: return US"PASSWORD";
  case GSASL_ANONYMOUS_TOKEN: return US"ANONYMOUS_TOKEN";
  case GSASL_SERVICE: return US"SERVICE";
  case GSASL_HOSTNAME: return US"HOSTNAME";
  case GSASL_GSSAPI_DISPLAY_NAME: return US"GSSAPI_DISPLAY_NAME";
  case GSASL_PASSCODE: return US"PASSCODE";
  case GSASL_SUGGESTED_PIN: return US"SUGGESTED_PIN";
  case GSASL_PIN: return US"PIN";
  case GSASL_REALM: return US"REALM";
  case GSASL_DIGEST_MD5_HASHED_PASSWORD: return US"DIGEST_MD5_HASHED_PASSWORD";
  case GSASL_QOPS: return US"QOPS";
  case GSASL_QOP: return US"QOP";
  case GSASL_SCRAM_ITER: return US"SCRAM_ITER";
  case GSASL_SCRAM_SALT: return US"SCRAM_SALT";
  case GSASL_SCRAM_SALTED_PASSWORD: return US"SCRAM_SALTED_PASSWORD";
#ifdef EXIM_GSASL_SCRAM_S_KEY
  case GSASL_SCRAM_STOREDKEY: return US"SCRAM_STOREDKEY";
  case GSASL_SCRAM_SERVERKEY: return US"SCRAM_SERVERKEY";
#endif
  case GSASL_CB_TLS_UNIQUE: return US"CB_TLS_UNIQUE";
  case GSASL_SAML20_IDP_IDENTIFIER: return US"SAML20_IDP_IDENTIFIER";
  case GSASL_SAML20_REDIRECT_URL: return US"SAML20_REDIRECT_URL";
  case GSASL_OPENID20_REDIRECT_URL: return US"OPENID20_REDIRECT_URL";
  case GSASL_OPENID20_OUTCOME_DATA: return US"OPENID20_OUTCOME_DATA";
  case GSASL_SAML20_AUTHENTICATE_IN_BROWSER: return US"SAML20_AUTHENTICATE_IN_BROWSER";
  case GSASL_OPENID20_AUTHENTICATE_IN_BROWSER: return US"OPENID20_AUTHENTICATE_IN_BROWSER";
#ifdef EXIM_GSASL_SCRAM_S_KEY
  case GSASL_SCRAM_CLIENTKEY: return US"SCRAM_CLIENTKEY";
#endif
  case GSASL_VALIDATE_SIMPLE: return US"VALIDATE_SIMPLE";
  case GSASL_VALIDATE_EXTERNAL: return US"VALIDATE_EXTERNAL";
  case GSASL_VALIDATE_ANONYMOUS: return US"VALIDATE_ANONYMOUS";
  case GSASL_VALIDATE_GSSAPI: return US"VALIDATE_GSSAPI";
  case GSASL_VALIDATE_SECURID: return US"VALIDATE_SECURID";
  case GSASL_VALIDATE_SAML20: return US"VALIDATE_SAML20";
  case GSASL_VALIDATE_OPENID20: return US"VALIDATE_OPENID20";
  }
return CUS string_sprintf("(unknown prop: %d)", (int)prop);
}

/*************************************************
*             Server entry point                 *
*************************************************/

/* For interface, see auths/README */

int
auth_gsasl_server(auth_instance *ablock, uschar *initial_data)
{
char *tmps;
char *to_send, *received;
Gsasl_session *sctx = NULL;
auth_gsasl_options_block *ob =
  (auth_gsasl_options_block *)(ablock->options_block);
struct callback_exim_state cb_state;
int rc, auth_result, exim_error, exim_error_override;

HDEBUG(D_auth)
  debug_printf("GNU SASL: initialising session for %s, mechanism %s\n",
      ablock->name, ob->server_mech);

#ifndef DISABLE_TLS
if (tls_in.channelbinding && ob->server_channelbinding)
  {
# ifdef EXPERIMENTAL_TLS_RESUME
  if (!tls_in.ext_master_secret && tls_in.resumption == RESUME_USED)
    {		/* per RFC 7677 section 4 */
    HDEBUG(D_auth) debug_printf(
      "channel binding not usable on resumed TLS without extended-master-secret");
    return FAIL;
    }
# endif
# ifdef CHANNELBIND_HACK
/* This is a gross hack to get around the library a) requiring that
c-b was already set, at the _start() call, and b) caching a b64'd
version of the binding then which it never updates. */

  gsasl_callback_hook_set(gsasl_ctx, tls_in.channelbinding);
# endif
  }
#endif

if ((rc = gsasl_server_start(gsasl_ctx, CCS ob->server_mech, &sctx)) != GSASL_OK)
  {
  auth_defer_msg = string_sprintf("GNU SASL: session start failure: %s (%s)",
      gsasl_strerror_name(rc), gsasl_strerror(rc));
  HDEBUG(D_auth) debug_printf("%s\n", auth_defer_msg);
  return DEFER;
  }
/* Hereafter: gsasl_finish(sctx) please */

cb_state.ablock = ablock;
cb_state.currently = CURRENTLY_SERVER;
gsasl_session_hook_set(sctx, &cb_state);

tmps = CS expand_string(ob->server_service);
gsasl_property_set(sctx, GSASL_SERVICE, tmps);
tmps = CS expand_string(ob->server_hostname);
gsasl_property_set(sctx, GSASL_HOSTNAME, tmps);
if (ob->server_realm)
  {
  tmps = CS expand_string(ob->server_realm);
  if (tmps && *tmps)
    gsasl_property_set(sctx, GSASL_REALM, tmps);
  }
/* We don't support protection layers. */
gsasl_property_set(sctx, GSASL_QOPS, "qop-auth");

#ifndef DISABLE_TLS
if (tls_in.channelbinding)
  {
  /* Some auth mechanisms can ensure that both sides are talking withing the
  same security context; for TLS, this means that even if a bad certificate
  has been accepted, they remain MitM-proof because both sides must be within
  the same negotiated session; if someone is terminating one session and
  proxying data on within a second, authentication will fail.

  We might not have this available, depending upon TLS implementation,
  ciphersuite, phase of moon ...

  If we do, it results in extra SASL mechanisms being available; here,
  Exim's one-mechanism-per-authenticator potentially causes problems.
  It depends upon how GNU SASL will implement the PLUS variants of GS2
  and whether it automatically mandates a switch to the bound PLUS
  if the data is available.  Since default-on, despite being more secure,
  would then result in mechanism name changes on a library update, we
  have little choice but to default it off and let the admin choose to
  enable it.  *sigh*
  */
  if (ob->server_channelbinding)
    {
    HDEBUG(D_auth) debug_printf("Auth %s: Enabling channel-binding\n",
	ablock->name);
# ifndef CHANNELBIND_HACK
    gsasl_property_set(sctx, GSASL_CB_TLS_UNIQUE, CCS tls_in.channelbinding);
# endif
    }
  else
    HDEBUG(D_auth)
      debug_printf("Auth %s: Not enabling channel-binding (data available)\n",
	  ablock->name);
  }
else
  HDEBUG(D_auth)
    debug_printf("Auth %s: no channel-binding data available\n",
	ablock->name);
#endif

checked_server_condition = FALSE;

received = CS initial_data;
to_send = NULL;
exim_error = exim_error_override = OK;

do {
  switch (rc = gsasl_step64(sctx, received, &to_send))
    {
    case GSASL_OK:
      if (!to_send)
	goto STOP_INTERACTION;
      break;

    case GSASL_NEEDS_MORE:
      break;

    case GSASL_AUTHENTICATION_ERROR:
    case GSASL_INTEGRITY_ERROR:
    case GSASL_NO_AUTHID:
    case GSASL_NO_ANONYMOUS_TOKEN:
    case GSASL_NO_AUTHZID:
    case GSASL_NO_PASSWORD:
    case GSASL_NO_PASSCODE:
    case GSASL_NO_PIN:
    case GSASL_BASE64_ERROR:
      HDEBUG(D_auth) debug_printf("GNU SASL permanent error: %s (%s)\n",
	  gsasl_strerror_name(rc), gsasl_strerror(rc));
      log_write(0, LOG_REJECT, "%s authenticator (%s):\n  "
	  "GNU SASL permanent failure: %s (%s)",
	  ablock->name, ob->server_mech,
	  gsasl_strerror_name(rc), gsasl_strerror(rc));
      if (rc == GSASL_BASE64_ERROR)
	exim_error_override = BAD64;
      goto STOP_INTERACTION;

    default:
      auth_defer_msg = string_sprintf("GNU SASL temporary error: %s (%s)",
	  gsasl_strerror_name(rc), gsasl_strerror(rc));
      HDEBUG(D_auth) debug_printf("%s\n", auth_defer_msg);
      exim_error_override = DEFER;
      goto STOP_INTERACTION;
    }

  /*XXX having our caller send the final smtp "235" is unfortunate; wastes a roundtrip */
  if ((rc == GSASL_NEEDS_MORE) || (to_send && *to_send))
    exim_error = auth_get_no64_data(USS &received, US to_send);

  if (to_send)
    {
    free(to_send);
    to_send = NULL;
    }

  if (exim_error)
    break; /* handles * cancelled check */

  } while (rc == GSASL_NEEDS_MORE);

STOP_INTERACTION:
auth_result = rc;

HDEBUG(D_auth)
  {
  const uschar * s;
  if ((s = CUS gsasl_property_fast(sctx, GSASL_SCRAM_ITER)))
    debug_printf(" - itercnt:   '%s'\n", s);
  if ((s = CUS gsasl_property_fast(sctx, GSASL_SCRAM_SALT)))
    debug_printf(" - salt:      '%s'\n", s);
#ifdef EXIM_GSASL_SCRAM_S_KEY
  if ((s = CUS gsasl_property_fast(sctx, GSASL_SCRAM_SERVERKEY)))
    debug_printf(" - ServerKey: '%s'\n", s);
  if ((s = CUS gsasl_property_fast(sctx, GSASL_SCRAM_STOREDKEY)))
    debug_printf(" - StoredKey: '%s'\n", s);
#endif
  }

gsasl_finish(sctx);

/* Can return: OK DEFER FAIL CANCELLED BAD64 UNEXPECTED */

if (exim_error != OK)
  return exim_error;

if (auth_result != GSASL_OK)
  {
  HDEBUG(D_auth) debug_printf("authentication returned %s (%s)\n",
      gsasl_strerror_name(auth_result), gsasl_strerror(auth_result));
  if (exim_error_override != OK)
    return exim_error_override; /* might be DEFER */
  if (sasl_error_should_defer) /* overriding auth failure SASL error */
    return DEFER;
  return FAIL;
  }

/* Auth succeeded, check server_condition unless already done in callback */
return checked_server_condition ? OK : auth_check_serv_cond(ablock);
}


/* returns the GSASL status of expanding the Exim string given */
static int
condition_check(auth_instance *ablock, uschar *label, uschar *condition_string)
{
int exim_rc = auth_check_some_cond(ablock, label, condition_string, FAIL);
switch (exim_rc)
  {
  case OK:	return GSASL_OK;
  case DEFER:	sasl_error_should_defer = TRUE;
		return GSASL_AUTHENTICATION_ERROR;
  case FAIL:	return GSASL_AUTHENTICATION_ERROR;
  default:	log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:  "
		  "Unhandled return from checking %s: %d",
		  ablock->name, label, exim_rc);
  }

/* NOTREACHED */
return GSASL_AUTHENTICATION_ERROR;
}


static void
set_exim_authvar_from_prop(Gsasl_session * sctx, Gsasl_property prop)
{
uschar * propval = US gsasl_property_fast(sctx, prop);
int i = expand_nmax, j = i + 1;
propval = propval ? string_copy(propval) : US"";
auth_vars[i] = expand_nstring[j] = propval;
expand_nlength[j] = Ustrlen(propval);
expand_nmax = j;
}

static void
set_exim_authvars_from_a_az_r_props(Gsasl_session * sctx)
{
if (expand_nmax > 0 ) return;

/* Asking for GSASL_AUTHZID calls back into us if we use
gsasl_property_get(), thus the use of gsasl_property_fast().
Do we really want to hardcode limits per mechanism?  What happens when
a new mechanism is added to the library.  It *shouldn't* result in us
needing to add more glue, since avoiding that is a large part of the
point of SASL. */

set_exim_authvar_from_prop(sctx, GSASL_AUTHID);
set_exim_authvar_from_prop(sctx, GSASL_AUTHZID);
set_exim_authvar_from_prop(sctx, GSASL_REALM);
}


static int
prop_from_option(Gsasl_session * sctx, Gsasl_property prop,
  const uschar * option)
{
HDEBUG(D_auth) debug_printf(" %s\n", gsasl_prop_code_to_name(prop));
if (option)
  {
  set_exim_authvars_from_a_az_r_props(sctx);
  option = expand_cstring(option);
  HDEBUG(D_auth) debug_printf("  '%s'\n", option);
  if (*option)
    gsasl_property_set(sctx, prop, CCS option);
  return GSASL_OK;
  }
HDEBUG(D_auth) debug_printf("  option not set\n");
return GSASL_NO_CALLBACK;
}

static int
server_callback(Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop,
  auth_instance *ablock)
{
char *tmps;
uschar *s, *propval;
int cbrc = GSASL_NO_CALLBACK;
auth_gsasl_options_block *ob =
  (auth_gsasl_options_block *)(ablock->options_block);

HDEBUG(D_auth) debug_printf("GNU SASL callback %s for %s/%s as server\n",
	    gsasl_prop_code_to_name(prop), ablock->name, ablock->public_name);

for (int i = 0; i < AUTH_VARS; i++) auth_vars[i] = NULL;
expand_nmax = 0;

switch (prop)
  {
  case GSASL_VALIDATE_SIMPLE:
    /* GSASL_AUTHID, GSASL_AUTHZID, and GSASL_PASSWORD */
    set_exim_authvar_from_prop(sctx, GSASL_AUTHID);
    set_exim_authvar_from_prop(sctx, GSASL_AUTHZID);
    set_exim_authvar_from_prop(sctx, GSASL_PASSWORD);

    cbrc = condition_check(ablock, US"server_condition", ablock->server_condition);
    checked_server_condition = TRUE;
    break;

  case GSASL_VALIDATE_EXTERNAL:
    if (!ablock->server_condition)
      {
      HDEBUG(D_auth) debug_printf("No server_condition supplied, to validate EXTERNAL\n");
      cbrc = GSASL_AUTHENTICATION_ERROR;
      break;
      }
    set_exim_authvar_from_prop(sctx, GSASL_AUTHZID);

    cbrc = condition_check(ablock,
	US"server_condition (EXTERNAL)", ablock->server_condition);
    checked_server_condition = TRUE;
    break;

  case GSASL_VALIDATE_ANONYMOUS:
    if (!ablock->server_condition)
      {
      HDEBUG(D_auth) debug_printf("No server_condition supplied, to validate ANONYMOUS\n");
      cbrc = GSASL_AUTHENTICATION_ERROR;
      break;
      }
    set_exim_authvar_from_prop(sctx, GSASL_ANONYMOUS_TOKEN);

    cbrc = condition_check(ablock,
	US"server_condition (ANONYMOUS)", ablock->server_condition);
    checked_server_condition = TRUE;
    break;

  case GSASL_VALIDATE_GSSAPI:
    /* GSASL_AUTHZID and GSASL_GSSAPI_DISPLAY_NAME
    The display-name is authenticated as part of GSS, the authzid is claimed
    by the SASL integration after authentication; protected against tampering
    (if the SASL mechanism supports that, which Kerberos does) but is
    unverified, same as normal for other mechanisms.
     First coding, we had these values swapped, but for consistency and prior
    to the first release of Exim with this authenticator, they've been
    switched to match the ordering of GSASL_VALIDATE_SIMPLE. */

    set_exim_authvar_from_prop(sctx, GSASL_GSSAPI_DISPLAY_NAME);
    set_exim_authvar_from_prop(sctx, GSASL_AUTHZID);

    /* In this one case, it perhaps makes sense to default back open?
    But for consistency, let's just mandate server_condition here too. */

    cbrc = condition_check(ablock,
	US"server_condition (GSSAPI family)", ablock->server_condition);
    checked_server_condition = TRUE;
    break;

  case GSASL_SCRAM_ITER:
    cbrc = prop_from_option(sctx, prop, ob->server_scram_iter);
    break;

  case GSASL_SCRAM_SALT:
    cbrc = prop_from_option(sctx, prop, ob->server_scram_salt);
    break;

#ifdef EXIM_GSASL_SCRAM_S_KEY
  case GSASL_SCRAM_STOREDKEY:
    cbrc = prop_from_option(sctx, prop, ob->server_s_key);
    break;

  case GSASL_SCRAM_SERVERKEY:
    cbrc = prop_from_option(sctx, prop, ob->server_key);
    break;
#endif

  case GSASL_PASSWORD:
    /* SCRAM-*: GSASL_AUTHID, GSASL_AUTHZID and GSASL_REALM
       DIGEST-MD5: GSASL_AUTHID, GSASL_AUTHZID and GSASL_REALM
       CRAM-MD5: GSASL_AUTHID
       PLAIN: GSASL_AUTHID and GSASL_AUTHZID
       LOGIN: GSASL_AUTHID
     */
    set_exim_authvars_from_a_az_r_props(sctx);

    if (!(s = ob->server_password))
      {
      HDEBUG(D_auth) debug_printf("option not set\n");
      break;
      }
    if (!(tmps = CS expand_string(s)))
      {
      sasl_error_should_defer = !f.expand_string_forcedfail;
      HDEBUG(D_auth) debug_printf("server_password expansion failed, so "
	  "can't tell GNU SASL library the password for %s\n", auth_vars[0]);
      return GSASL_AUTHENTICATION_ERROR;
      }
    HDEBUG(D_auth) debug_printf("  set\n");
    gsasl_property_set(sctx, GSASL_PASSWORD, tmps);

    /* This is inadequate; don't think Exim's store stacks are geared
    for memory wiping, so expanding strings will leave stuff laying around.
    But no need to compound the problem, so get rid of the one we can. */

    memset(tmps, '\0', strlen(tmps));
    cbrc = GSASL_OK;
    break;

  default:
    HDEBUG(D_auth) debug_printf(" Unrecognised callback: %d\n", prop);
    cbrc = GSASL_NO_CALLBACK;
  }

HDEBUG(D_auth) debug_printf("Returning %s (%s)\n",
    gsasl_strerror_name(cbrc), gsasl_strerror(cbrc));

return cbrc;
}


/******************************************************************************/

#define PROP_OPTIONAL	BIT(0)

static BOOL
set_client_prop(Gsasl_session * sctx, Gsasl_property prop, uschar * val,
  unsigned flags, uschar * buffer, int buffsize)
{
uschar * s;
int rc;

if (!val) return !!(flags & PROP_OPTIONAL);
if (!(s = expand_string(val)) || !(flags & PROP_OPTIONAL) && !*s)
  {
  string_format(buffer, buffsize, "%s", expand_string_message);
  return FALSE;
  }
if (*s)
  {
  HDEBUG(D_auth) debug_printf("%s: set %s = '%s'\n", __FUNCTION__,
    gsasl_prop_code_to_name(prop), s);
  gsasl_property_set(sctx, prop, CS s);
  }

return TRUE;
}

/*************************************************
*              Client entry point                *
*************************************************/

/* For interface, see auths/README */

int
auth_gsasl_client(
  auth_instance *ablock,		/* authenticator block */
  void * sx,				/* connection */
  int timeout,				/* command timeout */
  uschar *buffer,			/* buffer for reading response */
  int buffsize)				/* size of buffer */
{
auth_gsasl_options_block *ob =
  (auth_gsasl_options_block *)(ablock->options_block);
Gsasl_session * sctx = NULL;
struct callback_exim_state cb_state;
uschar * s;
BOOL initial = TRUE;
int rc, yield = FAIL;

HDEBUG(D_auth)
  debug_printf("GNU SASL: initialising session for %s, mechanism %s\n",
      ablock->name, ob->server_mech);

*buffer = 0;

#ifndef DISABLE_TLS
if (tls_out.channelbinding && ob->client_channelbinding)
  {
# ifdef EXPERIMENTAL_TLS_RESUME
  if (!tls_out.ext_master_secret && tls_out.resumption == RESUME_USED)
    {		/* per RFC 7677 section 4 */
    string_format(buffer, buffsize, "%s",
      "channel binding not usable on resumed TLS without extended-master-secret");
    return FAIL;
    }
# endif
# ifdef CHANNELBIND_HACK
  /* This is a gross hack to get around the library a) requiring that
  c-b was already set, at the _start() call, and b) caching a b64'd
  version of the binding then which it never updates. */

  gsasl_callback_hook_set(gsasl_ctx, tls_out.channelbinding);
# endif
  }
#endif

if ((rc = gsasl_client_start(gsasl_ctx, CCS ob->server_mech, &sctx)) != GSASL_OK)
  {
  string_format(buffer, buffsize, "GNU SASL: session start failure: %s (%s)",
      gsasl_strerror_name(rc), gsasl_strerror(rc));
  HDEBUG(D_auth) debug_printf("%s\n", buffer);
  return ERROR;
  }

cb_state.ablock = ablock;
cb_state.currently = CURRENTLY_CLIENT;
gsasl_session_hook_set(sctx, &cb_state);

/* Set properties */

if (  !set_client_prop(sctx, GSASL_SCRAM_SALTED_PASSWORD, ob->client_spassword,
		  0, buffer, buffsize)
      &&
      !set_client_prop(sctx, GSASL_PASSWORD, ob->client_password,
		  0, buffer, buffsize)
   || !set_client_prop(sctx, GSASL_AUTHID, ob->client_username,
		  0, buffer, buffsize)
   || !set_client_prop(sctx, GSASL_AUTHZID, ob->client_authz,
		  PROP_OPTIONAL, buffer, buffsize)
   )
  return ERROR;

#ifndef DISABLE_TLS
if (tls_out.channelbinding)
  if (ob->client_channelbinding)
    {
    HDEBUG(D_auth) debug_printf("Auth %s: Enabling channel-binding\n",
	ablock->name);
# ifndef CHANNELBIND_HACK
    gsasl_property_set(sctx, GSASL_CB_TLS_UNIQUE, CCS tls_out.channelbinding);
# endif
    }
  else
    HDEBUG(D_auth)
      debug_printf("Auth %s: Not enabling channel-binding (data available)\n",
	  ablock->name);
#endif

/* Run the SASL conversation with the server */

for(s = NULL; ;)
  {
  uschar * outstr;
  BOOL fail;

  rc = gsasl_step64(sctx, CS s, CSS &outstr);

  fail = initial
    ? smtp_write_command(sx, SCMD_FLUSH,
			outstr ? "AUTH %s %s\r\n" : "AUTH %s\r\n",
			ablock->public_name, outstr) <= 0
    : outstr
    ? smtp_write_command(sx, SCMD_FLUSH, "%s\r\n", outstr) <= 0
    : FALSE;
  if (outstr && *outstr) free(outstr);
  if (fail)
    {
    yield = FAIL_SEND;
    goto done;
    }
  initial = FALSE;

  if (rc != GSASL_NEEDS_MORE)
    {
    if (rc != GSASL_OK)
      {
      string_format(buffer, buffsize, "gsasl: %s", gsasl_strerror(rc));
      break;
      }

    /* expecting a final 2xx from the server, accepting the AUTH */

    if (smtp_read_response(sx, buffer, buffsize, '2', timeout))
      yield = OK;
    break;	/* from SASL sequence loop */
    }

  /* 2xx or 3xx response is acceptable.  If 2xx, no further input */

  if (!smtp_read_response(sx, buffer, buffsize, '3', timeout))
    if (errno == 0 && buffer[0] == '2')
      buffer[4] = '\0';
    else
      {
      yield = FAIL;
      goto done;
      }
  s = buffer + 4;
  }

done:
HDEBUG(D_auth)
  {
  const uschar * s = CUS gsasl_property_fast(sctx, GSASL_SCRAM_SALTED_PASSWORD);
  if (s) debug_printf(" - SaltedPassword: '%s'\n", s);
  }

gsasl_finish(sctx);
return yield;
}

static int
client_callback(Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop, auth_instance *ablock)
{
HDEBUG(D_auth) debug_printf("GNU SASL callback %s for %s/%s as client\n",
	    gsasl_prop_code_to_name(prop), ablock->name, ablock->public_name);
switch (prop)
  {
  case GSASL_CB_TLS_UNIQUE:
    HDEBUG(D_auth)
      debug_printf(" filling in\n");
    gsasl_property_set(sctx, GSASL_CB_TLS_UNIQUE, CCS tls_out.channelbinding);
    break;
  default:
    HDEBUG(D_auth)
      debug_printf(" not providing one\n");
    break;
  }
return GSASL_NO_CALLBACK;
}

/*************************************************
*                Diagnostic API                  *
*************************************************/

void
auth_gsasl_version_report(FILE *f)
{
const char *runtime;
runtime = gsasl_check_version(NULL);
fprintf(f, "Library version: GNU SASL: Compile: %s\n"
	   "                           Runtime: %s\n",
	GSASL_VERSION, runtime);
}



/* Dummy */
void auth_gsasl_macros(void) {}

#endif   /*!MACRO_PREDEF*/
#endif  /* AUTH_GSASL */

/* End of gsasl_exim.c */
