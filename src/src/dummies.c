/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* Copyright (c) The Exim Maintainers 2021 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This file is not part of the main Exim code. There are little bits of test
code for some of Exim's modules, and when they are used, the module they are
testing may call other main Exim functions that are not available and/or
should not be used in a test. The classic case is log_write(). This module
contains dummy versions of such functions - well not really dummies, more like
alternates. */

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

/* We don't have the full Exim headers dragged in, but this function
is used for debugging output. */

extern gstring * string_vformat(gstring *, unsigned, const char *, va_list);


/*************************************************
*         Handle calls to write the log          *
*************************************************/

/* The message gets written to stderr when log_write() is called from a
utility. The message always gets '\n' added on the end of it.

Arguments:
  selector  not relevant when running a utility
  flags     not relevant when running a utility
  format    a printf() format
  ...       arguments for format

Returns:    nothing
*/

void
log_write(unsigned int selector, int flags, char *format, ...)
{
va_list ap;
va_start(ap, format);
vfprintf(stderr, format, ap);
fprintf(stderr, "\n");
va_end(ap);
}


/*************************************************
*      Handle calls to print debug output        *
*************************************************/

/* The message just gets written to stderr.
We use tainted memory to format into just so that we can handle
tainted arguments.

Arguments:
  format    a printf() format
  ...       arguments for format

Returns:    nothing
*/

void
debug_printf(char *format, ...)
{
va_list ap;
rmark reset_point = store_mark();
gstring * g = string_get_tainted(1024, TRUE);

va_start(ap, format);

if (!string_vformat(g, 0, format, ap))
  {
  const char * s = "**** debug string overflowed buffer ****\n";
  char * p = CS g->s + g->ptr;
  int maxlen = g->size - (int)strlen(s) - 3;
  if (p > g->s + maxlen) p = g->s + maxlen;
  if (p > g->s && p[-1] != '\n') *p++ = '\n';
  strcpy(p, s);
  }

fprintf(stderr, "%s", string_from_gstring(g));
fflush(stderr);
store_reset(reset_point);
va_end(ap);
}



/*************************************************
*              SIGALRM handler                   *
*************************************************/

extern int sigalrm_seen;

void
sigalrm_handler(int sig)
{
sigalrm_seen = TRUE;
}



/*************************************************
*              Complete Dummies                  *
*************************************************/

int
header_checkname(const void * h, const char * name, int len)
{
return 0;
}

void
directory_make(const char * parent, const char * name, int mode, int panic)
{
}

void
host_build_sender_fullhost(void) { }

/* This one isn't needed for test_host */

#ifndef TEST_HOST
char *
host_ntoa(int type, const void * arg, const char * buffer, const int * portptr)
{
return NULL;
}
#endif


/* End of dummies.c */
