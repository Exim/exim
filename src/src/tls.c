/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module provides TLS (aka SSL) support for Exim. The code for OpenSSL is
based on a patch that was originally contributed by Steve Haslam. It was
adapted from stunnel, a GPL program by Michal Trojnara. The code for GNU TLS is
based on a patch contributed by Nikos Mavroyanopoulos. Because these packages
are so very different, the functions for each are kept in separate files. The
relevant file is #included as required, after any any common functions.

No cryptographic code is included in Exim. All this module does is to call
functions from the OpenSSL or GNU TLS libraries. */


#include "exim.h"

/* This module is compiled only when it is specifically requested in the
build-time configuration. However, some compilers don't like compiling empty
modules, so keep them happy with a dummy when skipping the rest. Make it
reference itself to stop picky compilers complaining that it is unused, and put
in a dummy argument to stop even pickier compilers complaining about infinite
loops. */

#ifndef SUPPORT_TLS
static void dummy(int x) { dummy(x-1); }
#else

/* Static variables that are used for buffering data by both sets of
functions and the common functions below. */


static uschar *ssl_xfer_buffer = NULL;
static int ssl_xfer_buffer_size = 4096;
static int ssl_xfer_buffer_lwm = 0;
static int ssl_xfer_buffer_hwm = 0;
static int ssl_xfer_eof = 0;
static int ssl_xfer_error = 0;

uschar *tls_channelbinding_b64 = NULL;


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
expand_check(uschar *s, uschar *name, uschar **result)
{
if (s == NULL) *result = NULL; else
  {
  *result = expand_string(s);
  if (*result == NULL && !expand_string_forcedfail)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "expansion of %s failed: %s", name,
      expand_string_message);
    return FALSE;
    }
  }
return TRUE;
}


/*************************************************
*        Many functions are package-specific     *
*************************************************/

#ifdef USE_GNUTLS
#include "tls-gnu.c"
#else
#include "tls-openssl.c"
#endif



/*************************************************
*           TLS version of ungetc                *
*************************************************/

/* Puts a character back in the input buffer. Only ever
called once.

Arguments:
  ch           the character

Returns:       the character
*/

int
tls_ungetc(int ch)
{
ssl_xfer_buffer[--ssl_xfer_buffer_lwm] = ch;
return ch;
}



/*************************************************
*           TLS version of feof                  *
*************************************************/

/* Tests for a previous EOF

Arguments:     none
Returns:       non-zero if the eof flag is set
*/

int
tls_feof(void)
{
return ssl_xfer_eof;
}



/*************************************************
*              TLS version of ferror             *
*************************************************/

/* Tests for a previous read error, and returns with errno
restored to what it was when the error was detected.

>>>>> Hmm. Errno not handled yet. Where do we get it from?  >>>>>

Arguments:     none
Returns:       non-zero if the error flag is set
*/

int
tls_ferror(void)
{
return ssl_xfer_error;
}


/*************************************************
*           TLS version of smtp_buffered         *
*************************************************/

/* Tests for unused chars in the TLS input buffer.

Arguments:     none
Returns:       TRUE/FALSE
*/

BOOL
tls_smtp_buffered(void)
{
return ssl_xfer_buffer_lwm < ssl_xfer_buffer_hwm;
}


#endif  /* SUPPORT_TLS */

/* End of tls.c */
