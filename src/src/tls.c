/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

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

static void tls_per_lib_daemon_init(void);
static void tls_per_lib_daemon_tick(void);
static unsigned  tls_server_creds_init(void);
static void tls_client_creds_init(transport_instance *, BOOL);
static void tls_daemon_creds_reload(void);
static BOOL opt_set_and_noexpand(const uschar *);
static BOOL opt_unset_or_noexpand(const uschar *);

#if defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT)
static void tls_server_creds_invalidate(void);
static void tls_client_creds_invalidate(transport_instance *);
#endif



/* This module is compiled only when it is specifically requested in the
build-time configuration. However, some compilers don't like compiling empty
modules, so keep them happy with a dummy when skipping the rest. Make it
reference itself to stop picky compilers complaining that it is unused, and put
in a dummy argument to stop even pickier compilers complaining about infinite
loops. */

#ifdef DISABLE_TLS
static void dummy(int x) { dummy(x-1); }
#else	/* most of the rest of the file */

const exim_tlslib_state	null_tls_preload = {0};

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

#ifdef EXIM_HAVE_KEVENT
# define KEV_SIZE 16	/* Eight file,dir pairs */
static struct kevent kev[KEV_SIZE];
static int kev_used = 0;
#endif

static unsigned tls_creds_expire = 0;

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
expand_check(const uschar * s, const uschar * name,
  uschar ** result, uschar ** errstr)
{
if (!s)
  {
  f.expand_string_forcedfail = FALSE;
  *result = NULL;
  }
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


#if defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT)
/* Add the directory for a filename to the inotify handle, creating that if
needed.  This is enough to see changes to files in that dir.
Return boolean success.

The word "system" fails, which is on the safe side as we don't know what
directory it implies nor if the TLS library handles a watch for us.

The string "system,cache" is recognised and explicitly accepted without
setting a watch.  This permits the system CA bundle to be cached even though
we have no way to tell when it gets modified by an update.
The call chain for OpenSSL uses a (undocumented) call into the library
to discover the actual file.  We don't know what GnuTLS uses.

A full set of caching including the CAs takes 35ms output off of the
server tls_init() (GnuTLS, Fedora 32, 2018-class x86_64 laptop hardware).
*/
static BOOL
tls_set_one_watch(const uschar * filename)
# ifdef EXIM_HAVE_INOTIFY
{
uschar buf[PATH_MAX];
ssize_t len;
uschar * s;

if (Ustrcmp(filename, "system,cache") == 0) return TRUE;
if (!(s = Ustrrchr(filename, '/'))) return FALSE;

for (unsigned loop = 20;
     (len = readlink(CCS filename, CS buf, sizeof(buf))) >= 0; )
  {						/* a symlink */
  if (--loop == 0) { errno = ELOOP; return FALSE; }
  filename = buf[0] == '/'
    ? string_copyn(buf, (unsigned)len)	/* mem released by tls_set_watch */
    : string_sprintf("%.*s/%.*s", (int)(s - filename), filename, (int)len, buf);
  s = Ustrrchr(filename, '/');
  }
if (errno != EINVAL)
  return FALSE;					/* other error */

/* not a symlink */
s = string_copyn(filename, s - filename);	/* mem released by tls_set_watch */

DEBUG(D_tls) debug_printf("watch dir '%s'\n", s);

if (inotify_add_watch(tls_watch_fd, CCS s,
      IN_ONESHOT | IN_CLOSE_WRITE | IN_DELETE | IN_DELETE_SELF
      | IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF) >= 0)
  return TRUE;
DEBUG(D_tls) debug_printf("notify_add_watch: %s\n", strerror(errno));
return FALSE;
}
# endif
# ifdef EXIM_HAVE_KEVENT
{
uschar * s, * t;
int fd1, fd2, i, j, cnt = 0;
struct stat sb;
#ifdef OpenBSD
struct kevent k_dummy;
struct timespec ts = {0};
#endif

errno = 0;
if (Ustrcmp(filename, "system,cache") == 0) return TRUE;

for (;;)
  {
  if (kev_used > KEV_SIZE-2) { s = US"out of kev space"; goto bad; }
  if (!(s = Ustrrchr(filename, '/'))) return FALSE;
  s = string_copyn(filename, s - filename);	/* mem released by tls_set_watch */

  /* The dir open will fail if there is a symlink on the path. Fine; it's too
  much effort to handle all possible cases; just refuse the preload. */

  if ((fd2 = open(CCS s, O_RDONLY | O_NOFOLLOW)) < 0) { s = US"open dir"; goto bad; }

  if ((lstat(CCS filename, &sb)) < 0) { s = US"lstat"; goto bad; }
  if (!S_ISLNK(sb.st_mode))
    {
    if ((fd1 = open(CCS filename, O_RDONLY | O_NOFOLLOW)) < 0)
      { s = US"open file"; goto bad; }
    DEBUG(D_tls) debug_printf("watch file '%s':\t%d\n", filename, fd1);
    EV_SET(&kev[kev_used++],
	(uintptr_t)fd1,
	EVFILT_VNODE,
	EV_ADD | EV_ENABLE | EV_ONESHOT,
	NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND
	| NOTE_ATTRIB | NOTE_RENAME | NOTE_REVOKE,
	0,
	NULL);
    cnt++;
    }
  DEBUG(D_tls) debug_printf("watch dir  '%s':\t%d\n", s, fd2);
  EV_SET(&kev[kev_used++],
	(uintptr_t)fd2,
	EVFILT_VNODE,
	EV_ADD | EV_ENABLE | EV_ONESHOT,
	NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND
	| NOTE_ATTRIB | NOTE_RENAME | NOTE_REVOKE,
	0,
	NULL);
  cnt++;

  if (!(S_ISLNK(sb.st_mode))) break;

  t = store_get(1024, GET_UNTAINTED);
  Ustrncpy(t, s, 1022);
  j = Ustrlen(s);
  t[j++] = '/';
  if ((i = readlink(CCS filename, (void *)(t+j), 1023-j)) < 0) { s = US"readlink"; goto bad; }
  filename = t;
  *(t += i+j) = '\0';
  store_release_above(t+1);
  }

#ifdef OpenBSD
if (kevent(tls_watch_fd, &kev[kev_used-cnt], cnt, &k_dummy, 1, &ts) >= 0)
  return TRUE;
#else
if (kevent(tls_watch_fd, &kev[kev_used-cnt], cnt, NULL, 0, NULL) >= 0)
  return TRUE;
#endif
s = US"kevent";

bad:
DEBUG(D_tls)
  if (errno)
    debug_printf("%s: %s: %s\n", __FUNCTION__, s, strerror(errno));
  else
    debug_printf("%s: %s\n", __FUNCTION__, s);
return FALSE;
}
# endif	/*EXIM_HAVE_KEVENT*/


/* Create an inotify facility if needed.
Then set watches on the dir containing the given file or (optionally)
list of files.  Return boolean success. */

static BOOL
tls_set_watch(const uschar * filename, BOOL list)
{
rmark r;
BOOL rc = FALSE;

if (!filename || !*filename) return TRUE;
if (Ustrncmp(filename, "system", 6) == 0) return TRUE;

DEBUG(D_tls) debug_printf("tls_set_watch: '%s'\n", filename);

if (  tls_watch_fd < 0
# ifdef EXIM_HAVE_INOTIFY
   && (tls_watch_fd = inotify_init1(O_CLOEXEC)) < 0
# endif
# ifdef EXIM_HAVE_KEVENT
   && (tls_watch_fd = kqueue()) < 0
# endif
   )
    {
    DEBUG(D_tls) debug_printf("inotify_init: %s\n", strerror(errno));
    return FALSE;
    }

r = store_mark();

if (list)
  {
  int sep = 0;
  for (uschar * s; s = string_nextinlist(&filename, &sep, NULL, 0); )
    if (!(rc = tls_set_one_watch(s))) break;
  }
else
  rc = tls_set_one_watch(filename);

store_reset(r);
if (!rc) DEBUG(D_tls) debug_printf("tls_set_watch() fail on '%s': %s\n", filename, strerror(errno));
return rc;
}


void
tls_watch_discard_event(int fd)
{
#ifdef EXIM_HAVE_INOTIFY
(void) read(fd, big_buffer, big_buffer_size);
#endif
#ifdef EXIM_HAVE_KEVENT
struct kevent kev;
struct timespec t = {0};
(void) kevent(fd, NULL, 0, &kev, 1, &t);
#endif
}
#endif	/*EXIM_HAVE_INOTIFY*/


void
tls_client_creds_reload(BOOL watch)
{
for(transport_instance * t = transports; t; t = t->next)
  if (Ustrcmp(t->driver_name, "smtp") == 0)
    {
#if defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT)
    tls_client_creds_invalidate(t);
#endif
    tls_client_creds_init(t, watch);
    }
}


void
tls_watch_invalidate(void)
{
if (tls_watch_fd < 0) return;

#ifdef EXIM_HAVE_KEVENT
/* Close the files we had open for kevent */
for (int i = 0; i < kev_used; i++)
  {
  DEBUG(D_tls) debug_printf("closing watch fd: %d\n", (int) kev[i].ident);
  (void) close((int) kev[i].ident);
  kev[i].ident = (uintptr_t)-1;
  }
kev_used = 0;
#endif

close(tls_watch_fd);
tls_watch_fd = -1;
}


static void
tls_daemon_creds_reload(void)
{
unsigned lifetime;

#ifdef EXIM_HAVE_KEVENT
tls_watch_invalidate();
#endif

#if defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT)
tls_server_creds_invalidate();
#endif

/* _expire is for a time-limited selfsign server cert */
tls_creds_expire = (lifetime = tls_server_creds_init())
  ? time(NULL) + lifetime : 0;

tls_client_creds_reload(TRUE);
}


/* Utility predicates for use by the per-library code */
static BOOL
opt_set_and_noexpand(const uschar * opt)
{ return opt && *opt && Ustrchr(opt, '$') == NULL; }

static BOOL
opt_unset_or_noexpand(const uschar * opt)
{ return !opt || Ustrchr(opt, '$') == NULL; }



/* Called every time round the daemon loop.

If we reloaded fd-watcher, return the old watch fd
having modified the global for the new one. Otherwise
return -1.
*/

int
tls_daemon_tick(void)
{
int old_watch_fd = tls_watch_fd;

tls_per_lib_daemon_tick();
#if defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT)
if (tls_creds_expire && time(NULL) >= tls_creds_expire)
  {
  /* The server cert is a selfsign, with limited lifetime.  Dump it and
  generate a new one.  Reload the rest of the creds also as the machinery
  is all there. */

  DEBUG(D_tls) debug_printf("selfsign cert rotate\n");
  tls_creds_expire = 0;
  tls_daemon_creds_reload();
  return old_watch_fd;
  }
else if (tls_watch_trigger_time && time(NULL) >= tls_watch_trigger_time + 5)
  {
  /* Called, after a delay for multiple file ops to get done, from
  the daemon when any of the watches added (above) fire.
  Dump the set of watches and arrange to reload cached creds (which
  will set up new watches). */

  DEBUG(D_tls) debug_printf("watch triggered\n");
  tls_watch_trigger_time = tls_creds_expire = 0;
  tls_daemon_creds_reload();
  return old_watch_fd;
  }
#endif
return -1;
}

/* Called once at daemon startup */

void
tls_daemon_init(void)
{
tls_per_lib_daemon_init();
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
/* Forward decl. */
static void tls_client_resmption_key(tls_support *, smtp_connect_args *,
  smtp_transport_options_block *);


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
uschar * altnames, * subjdn, * certname, * cmpname;
int cmp_sep = 0;

if ((altnames = tls_cert_subject_altname(cert, US"dns")))
  {
  int alt_sep = '\n';
  DEBUG(D_tls|D_lookup) debug_printf_indent("cert has SAN\n");
  while ((cmpname = string_nextinlist(&namelist, &cmp_sep, NULL, 0)))
    {
    const uschar * an = altnames;
    DEBUG(D_tls|D_lookup) debug_printf_indent(" %s in SANs?", cmpname);
    while ((certname = string_nextinlist(&an, &alt_sep, NULL, 0)))
      if (is_name_match(cmpname, certname))
	{
	DEBUG(D_tls|D_lookup) debug_printf_indent("  yes (matched %s)\n", certname);
	return TRUE;
	}
    DEBUG(D_tls|D_lookup) debug_printf_indent(" no (end of SAN list)\n");
    }
  }

else if ((subjdn = tls_cert_subject(cert, NULL)))
  {
  int sn_sep = ',';

  dn_to_list(subjdn);
  while ((cmpname = string_nextinlist(&namelist, &cmp_sep, NULL, 0)))
    {
    const uschar * sn = subjdn;
    DEBUG(D_tls|D_lookup) debug_printf_indent(" %s in SN?", cmpname);
    while ((certname = string_nextinlist(&sn, &sn_sep, NULL, 0)))
      if (  *certname++ == 'C'
	 && *certname++ == 'N'
	 && *certname++ == '='
	 && is_name_match(cmpname, certname)
	 )
	{
	DEBUG(D_tls|D_lookup) debug_printf_indent("  yes (matched %s)\n", certname);
	return TRUE;
	}
    DEBUG(D_tls|D_lookup) debug_printf_indent(" no (end of CN)\n");
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




static void
tls_client_resmption_key(tls_support * tlsp, smtp_connect_args * conn_args,
  smtp_transport_options_block * ob)
{
#ifndef DISABLE_TLS_RESUME
hctx * h = &tlsp->resume_hctx;
blob b;
gstring * g;

DEBUG(D_tls) if (conn_args->host_lbserver)
  debug_printf("TLS: lbserver '%s'\n", conn_args->host_lbserver);

# ifdef EXIM_HAVE_SHA2
exim_sha_init(h, HASH_SHA2_256);
# else
exim_sha_init(h, HASH_SHA1);
# endif
exim_sha_update_string(h, conn_args->host_lbserver);
# ifdef SUPPORT_DANE
if (conn_args->dane)
  exim_sha_update(h,  CUS &conn_args->tlsa_dnsa, sizeof(dns_answer));
# endif
exim_sha_update_string(h, conn_args->host->address);
exim_sha_update(h,   CUS &conn_args->host->port, sizeof(conn_args->host->port));
exim_sha_update_string(h, conn_args->sending_ip_address);
exim_sha_update_string(h, openssl_options);
exim_sha_update_string(h, ob->tls_require_ciphers);
exim_sha_update_string(h, tlsp->sni);
# ifdef EXIM_HAVE_ALPN
exim_sha_update_string(h, ob->tls_alpn);
# endif
exim_sha_finish(h, &b);
for (g = string_get(b.len*2+1); b.len-- > 0; )
  g = string_fmt_append(g, "%02x", *b.data++);
tlsp->resume_index = string_from_gstring(g);
DEBUG(D_tls) debug_printf("TLS: resume session index %s\n", tlsp->resume_index);
#endif
}



/* Start TLS as a client for an ajunct connection, eg. readsocket
Return boolean success.
*/

BOOL
tls_client_adjunct_start(host_item * host, client_conn_ctx * cctx,
  const uschar * sni, uschar ** errmsg)
{
union sockaddr_46 interface_sock;
EXIM_SOCKLEN_T size = sizeof(interface_sock);
smtp_connect_args conn_args = {.host = host };
tls_support tls_dummy = { .sni = NULL };
uschar * errstr;

if (getsockname(cctx->sock, (struct sockaddr *) &interface_sock, &size) == 0)
  conn_args.sending_ip_address = host_ntoa(-1, &interface_sock, NULL, NULL);
else
  {
  *errmsg = string_sprintf("getsockname failed: %s", strerror(errno));
  return FALSE;
  }

/* To handle SNI we need to emulate more of a real transport because the
base tls code assumes that is where the SNI string lives. */

if (*sni)
  {
  transport_instance * tb;
  smtp_transport_options_block * ob;

  conn_args.tblock = tb = store_get(sizeof(*tb), GET_UNTAINTED);
  memset(tb, 0, sizeof(*tb));

  tb->options_block = ob = store_get(sizeof(*ob), GET_UNTAINTED);
  memcpy(ob, &smtp_transport_option_defaults, sizeof(*ob));

  ob->tls_sni = sni;
  }

if (!tls_client_start(cctx, &conn_args, NULL, &tls_dummy, &errstr))
  {
  *errmsg = string_sprintf("TLS connect failed: %s", errstr);
  return FALSE;
  }
return TRUE;
}



#endif	/*!DISABLE_TLS*/
#endif	/*!MACRO_PREDEF*/

/* vi: aw ai sw=2
*/
/* End of tls.c */
