/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module provides TLS (aka SSL) support for Exim. The code for OpenSSL is
based on a patch that was originally contributed by Steve Haslam. It was
adapted from stunnel, a GPL program by Michal Trojnara. The code for GNU TLS is
based on a patch contributed by Nikos Mavrogiannopoulos. Because these packages
are so very different, the functions for each are kept in separate files. The
relevant file is #included as required, after any any common functions.

No cryptographic code is included in Exim. All this module does is to call
functions from the OpenSSL or GNU TLS libraries. */


#include "exim.h"
#include "transports/smtp.h"

#if !defined(DISABLE_TLS) && !defined(USE_OPENSSL) && !defined(USE_GNUTLS)
# error One of USE_OPENSSL or USE_GNUTLS must be defined for a TLS build
#endif


#if defined(MACRO_PREDEF) && !defined(DISABLE_TLS)
# include "macro_predef.h"
# ifdef USE_GNUTLS
#  include "tls-gnu.c"
# else
#  include "tls-openssl.c"
# endif
#endif

#ifndef MACRO_PREDEF

/* This module is compiled only when it is specifically requested in the
build-time configuration. However, some compilers don't like compiling empty
modules, so keep them happy with a dummy when skipping the rest. Make it
reference itself to stop picky compilers complaining that it is unused, and put
in a dummy argument to stop even pickier compilers complaining about infinite
loops. */

#ifdef DISABLE_TLS
static void dummy(int x) { dummy(x-1); }
#else

/* Static variables that are used for buffering data by both sets of
functions and the common functions below.

We're moving away from this; GnuTLS is already using a state, which
can switch, so we can do TLS callouts during ACLs. */

static const int ssl_xfer_buffer_size = 4096;
#ifdef USE_OPENSSL
static uschar *ssl_xfer_buffer = NULL;
static int ssl_xfer_buffer_lwm = 0;
static int ssl_xfer_buffer_hwm = 0;
static int ssl_xfer_eof = FALSE;
static BOOL ssl_xfer_error = FALSE;
#endif


/*************************************************
*       Expand string; give error on failure     *
*************************************************/

/* If expansion is forced to fail, set the result NULL and return TRUE.
Other failures return FALSE. For a server, an SMTP response is given.

Arguments:
  s         the string to expand; if NULL just return TRUE
  name      name of string being expanded (for error)
  result    where to put the result

Returns:    TRUE if OK; result may still be NULL after forced failure
*/

static BOOL
expand_check(const uschar *s, const uschar *name, uschar **result, uschar ** errstr)
{
if (!s)
  *result = NULL;
else if (  !(*result = expand_string(US s)) /* need to clean up const more */
	&& !f.expand_string_forcedfail
	)
  {
  *errstr = US"Internal error";
  log_write(0, LOG_MAIN|LOG_PANIC, "expansion of %s failed: %s", name,
    expand_string_message);
  return FALSE;
  }
return TRUE;
}


/*************************************************
*        Timezone environment flipping           *
*************************************************/

static uschar *
to_tz(uschar * tz)
{
uschar * old = US getenv("TZ");
(void) setenv("TZ", CCS tz, 1);
tzset();
return old;
}

static void
restore_tz(uschar * tz)
{
if (tz)
  (void) setenv("TZ", CCS tz, 1);
else
  (void) os_unsetenv(US"TZ");
tzset();
}

/*************************************************
*        Many functions are package-specific     *
*************************************************/

#ifdef USE_GNUTLS
# include "tls-gnu.c"
# include "tlscert-gnu.c"
# define ssl_xfer_buffer (state_server.xfer_buffer)
# define ssl_xfer_buffer_lwm (state_server.xfer_buffer_lwm)
# define ssl_xfer_buffer_hwm (state_server.xfer_buffer_hwm)
# define ssl_xfer_eof (state_server.xfer_eof)
# define ssl_xfer_error (state_server.xfer_error)
#endif

#ifdef USE_OPENSSL
# include "tls-openssl.c"
# include "tlscert-openssl.c"
#endif



/*************************************************
*           TLS version of ungetc                *
*************************************************/

/* Puts a character back in the input buffer. Only ever
called once.
Only used by the server-side TLS.

Arguments:
  ch           the character

Returns:       the character
*/

int
tls_ungetc(int ch)
{
if (ssl_xfer_buffer_lwm <= 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "buffer underflow in tls_ungetc");

ssl_xfer_buffer[--ssl_xfer_buffer_lwm] = ch;
return ch;
}



/*************************************************
*           TLS version of feof                  *
*************************************************/

/* Tests for a previous EOF
Only used by the server-side TLS.

Arguments:     none
Returns:       non-zero if the eof flag is set
*/

int
tls_feof(void)
{
return (int)ssl_xfer_eof;
}



/*************************************************
*              TLS version of ferror             *
*************************************************/

/* Tests for a previous read error, and returns with errno
restored to what it was when the error was detected.
Only used by the server-side TLS.

>>>>> Hmm. Errno not handled yet. Where do we get it from?  >>>>>

Arguments:     none
Returns:       non-zero if the error flag is set
*/

int
tls_ferror(void)
{
return (int)ssl_xfer_error;
}


/*************************************************
*           TLS version of smtp_buffered         *
*************************************************/

/* Tests for unused chars in the TLS input buffer.
Only used by the server-side TLS.

Arguments:     none
Returns:       TRUE/FALSE
*/

BOOL
tls_smtp_buffered(void)
{
return ssl_xfer_buffer_lwm < ssl_xfer_buffer_hwm;
}


#endif  /*DISABLE_TLS*/

void
tls_modify_variables(tls_support * dest_tsp)
{
modify_variable(US"tls_bits",                 &dest_tsp->bits);
modify_variable(US"tls_certificate_verified", &dest_tsp->certificate_verified);
modify_variable(US"tls_cipher",               &dest_tsp->cipher);
modify_variable(US"tls_peerdn",               &dest_tsp->peerdn);
#ifdef USE_OPENSSL
modify_variable(US"tls_sni",                  &dest_tsp->sni);
#endif
}


#ifndef DISABLE_TLS
/************************************************
*	TLS certificate name operations         *
************************************************/

/* Convert an rfc4514 DN to an exim comma-sep list.
Backslashed commas need to be replaced by doublecomma
for Exim's list quoting.  We modify the given string
inplace.
*/

static void
dn_to_list(uschar * dn)
{
for (uschar * cp = dn; *cp; cp++)
  if (cp[0] == '\\' && cp[1] == ',')
    *cp++ = ',';
}


/* Extract fields of a given type from an RFC4514-
format Distinguished Name.  Return an Exim list.
NOTE: We modify the supplied dn string during operation.

Arguments:
	dn	Distinguished Name string
	mod	list containing optional output list-sep and
		field selector match, comma-separated
Return:
	allocated string with list of matching fields,
	field type stripped
*/

uschar *
tls_field_from_dn(uschar * dn, const uschar * mod)
{
int insep = ',';
uschar outsep = '\n';
uschar * ele;
uschar * match = NULL;
int len;
gstring * list = NULL;

while ((ele = string_nextinlist(&mod, &insep, NULL, 0)))
  if (ele[0] != '>')
    match = ele;	/* field tag to match */
  else if (ele[1])
    outsep = ele[1];	/* nondefault output separator */

dn_to_list(dn);
insep = ',';
len = match ? Ustrlen(match) : -1;
while ((ele = string_nextinlist(CUSS &dn, &insep, NULL, 0)))
  if (  !match
     || Ustrncmp(ele, match, len) == 0 && ele[len] == '='
     )
    list = string_append_listele(list, outsep, ele+len+1);
return string_from_gstring(list);
}


/* Compare a domain name with a possibly-wildcarded name. Wildcards
are restricted to a single one, as the first element of patterns
having at least three dot-separated elements.  Case-independent.
Return TRUE for a match
*/
static BOOL
is_name_match(const uschar * name, const uschar * pat)
{
uschar * cp;
return *pat == '*'		/* possible wildcard match */
  ?    *++pat == '.'		/* starts star, dot              */
    && !Ustrchr(++pat, '*')	/* has no more stars             */
    && Ustrchr(pat, '.')	/* and has another dot.          */
    && (cp = Ustrchr(name, '.'))/* The name has at least one dot */
    && strcmpic(++cp, pat) == 0 /* and we only compare after it. */
  :    !Ustrchr(pat+1, '*')
    && strcmpic(name, pat) == 0;
}

/* Compare a list of names with the dnsname elements
of the Subject Alternate Name, if any, and the
Subject otherwise.

Arguments:
	namelist names to compare
	cert	 certificate

Returns:
	TRUE/FALSE
*/

BOOL
tls_is_name_for_cert(const uschar * namelist, void * cert)
{
uschar * altnames = tls_cert_subject_altname(cert, US"dns");
uschar * subjdn;
uschar * certname;
int cmp_sep = 0;
uschar * cmpname;

if ((altnames = tls_cert_subject_altname(cert, US"dns")))
  {
  int alt_sep = '\n';
  while ((cmpname = string_nextinlist(&namelist, &cmp_sep, NULL, 0)))
    {
    const uschar * an = altnames;
    while ((certname = string_nextinlist(&an, &alt_sep, NULL, 0)))
      if (is_name_match(cmpname, certname))
	return TRUE;
    }
  }

else if ((subjdn = tls_cert_subject(cert, NULL)))
  {
  int sn_sep = ',';

  dn_to_list(subjdn);
  while ((cmpname = string_nextinlist(&namelist, &cmp_sep, NULL, 0)))
    {
    const uschar * sn = subjdn;
    while ((certname = string_nextinlist(&sn, &sn_sep, NULL, 0)))
      if (  *certname++ == 'C'
	 && *certname++ == 'N'
	 && *certname++ == '='
	 && is_name_match(cmpname, certname)
	 )
	return TRUE;
    }
  }
return FALSE;
}


/* Environment cleanup: The GnuTLS library uses SSLKEYLOGFILE in the environment
and writes a file by that name.  Our OpenSSL code does the same, using keying
info from the library API.
The GnuTLS support only works if exim is run by root, not taking advantage of
the setuid bit.
You can use either the external environment (modulo the keep_environment config)
or the add_environment config option for SSLKEYLOGFILE; the latter takes
precedence.

If the path is absolute, require it starts with the spooldir; otherwise delete
the env variable.  If relative, prefix the spooldir.
*/
void
tls_clean_env(void)
{
uschar * path = US getenv("SSLKEYLOGFILE");
if (path)
  if (!*path)
    unsetenv("SSLKEYLOGFILE");
  else if (*path != '/')
    {
    DEBUG(D_tls)
      debug_printf("prepending spooldir to  env SSLKEYLOGFILE\n");
    setenv("SSLKEYLOGFILE", CCS string_sprintf("%s/%s", spool_directory, path), 1);
    }
  else if (Ustrncmp(path, spool_directory, Ustrlen(spool_directory)) != 0)
    {
    DEBUG(D_tls)
      debug_printf("removing env SSLKEYLOGFILE=%s: not under spooldir\n", path);
    unsetenv("SSLKEYLOGFILE");
    }
}

/*************************************************
*       Drop privs for checking TLS config      *
*************************************************/

/* We want to validate TLS options during readconf, but do not want to be
root when we call into the TLS library, in case of library linkage errors
which cause segfaults; before this check, those were always done as the Exim
runtime user and it makes sense to continue with that.

Assumes:  tls_require_ciphers has been set, if it will be
          exim_user has been set, if it will be
          exim_group has been set, if it will be

Returns:  bool for "okay"; false will cause caller to immediately exit.
*/

BOOL
tls_dropprivs_validate_require_cipher(BOOL nowarn)
{
const uschar *errmsg;
pid_t pid;
int rc, status;
void (*oldsignal)(int);

/* If TLS will never be used, no point checking ciphers */

if (  !tls_advertise_hosts
   || !*tls_advertise_hosts
   || Ustrcmp(tls_advertise_hosts, ":") == 0
   )
  return TRUE;
else if (!nowarn && !tls_certificate)
  log_write(0, LOG_MAIN,
    "Warning: No server certificate defined; will use a selfsigned one.\n"
    " Suggested action: either install a certificate or change tls_advertise_hosts option");

oldsignal = signal(SIGCHLD, SIG_DFL);

fflush(NULL);
if ((pid = exim_fork(US"cipher-validate")) < 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "fork failed for TLS check");

if (pid == 0)
  {
  /* in some modes, will have dropped privilege already */
  if (!geteuid())
    exim_setugid(exim_uid, exim_gid, FALSE,
        US"calling tls_validate_require_cipher");

  if ((errmsg = tls_validate_require_cipher()))
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
        "tls_require_ciphers invalid: %s", errmsg);
  fflush(NULL);
  exim_underbar_exit(EXIT_SUCCESS);
  }

do {
  rc = waitpid(pid, &status, 0);
} while (rc < 0 && errno == EINTR);

DEBUG(D_tls)
  debug_printf("tls_validate_require_cipher child %d ended: status=0x%x\n",
      (int)pid, status);

signal(SIGCHLD, oldsignal);

return status == 0;
}




#endif	/*!DISABLE_TLS*/
#endif	/*!MACRO_PREDEF*/

/* vi: aw ai sw=2
*/
/* End of tls.c */
