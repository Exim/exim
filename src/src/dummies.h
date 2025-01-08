/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2025 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

					/* dummies needed by Solaris build */
void
millisleep(int msec)
{}
uschar *
readconf_printtime(int t)
{ return NULL; }
void *
store_get_3(int size, const void * proto_mem, const char *filename, int linenumber)
{ return NULL; }
void **
store_reset_3(void **ptr, const char *filename, int linenumber)
{ return NULL; }
void
store_release_above_3(void *ptr, const char *func, int linenumber)
{ }
gstring *
string_catn(gstring * g, const uschar * s, int count)
{ return NULL; }
gstring *
string_vformat_trc(gstring * g, const uschar * func, unsigned line,
  unsigned size_limit, unsigned flags, const char *format, va_list ap)
{ return NULL; }
uschar *
string_sprintf_trc(const char * a, const uschar * b, unsigned c, ...)
{ return NULL; }
BOOL
string_format_trc(uschar * buf, int len, const uschar * func, unsigned line,
  const char * fmt, ...)
{ return FALSE; }
void
log_write(unsigned int selector, int flags, const char *format, ...)
{ }


/******************************************************************************/
/* Solaris needs this one for the macro expand_string() */
const uschar * expand_string_2(const uschar * string, BOOL * textonly_p)
{return NULL; }

/* End of dummies.h */
