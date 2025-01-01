/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2022 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "exim.h"


/*************************************************
*          Encode byte-string in xtext           *
*************************************************/

/* This function encodes a string of bytes, containing any values whatsoever,
as "xtext", as defined in RFC 1891 and required by the SMTP AUTH extension (RFC
2554).

Arguments:
  clear       points to the clear text bytes
  len         the number of bytes to encode

Returns:      a pointer to the zero-terminated xtext string, which
              is in working store
*/

#ifndef COMPILE_UTILITY
uschar *
xtextencode(const uschar * clear, int len)
{
gstring * g = NULL;
for(uschar ch; len > 0; len--, clear++)
  g = (ch = *clear) < 33 || ch > 126 || ch == '+' || ch == '='
    ? string_fmt_append(g, "+%.02X", ch)
    : string_catn(g, clear, 1);
gstring_release_unused(g);
return string_from_gstring(g);
}

#else	/*COMPILE_UTILITY*/
uschar *
xtextencode(const uschar * clear, int len)
{
int enc_len = 1, i = len;	/* enc_len includes space for terminating NUL */
uschar * yield, * s;

for (const uschar * t = clear; i; i--, t++)
  {
  uschar ch = *t;
  enc_len += ch < 33 || ch > 126 || ch == '+' || ch == '='
	      ? 3 : 1;
  }
if (!(s = yield = malloc(enc_len)))
  return NULL;
for(uschar ch; len > 0; len--, clear++)
  if ((ch = *clear) < 33 || ch > 126 || ch == '+' || ch == '=')
    s += sprintf(CS s, "+%.02X", ch);
  else
    *s++ = ch;
*s = '\0';
return yield;
}

#endif	/*COMPILE_UTILITY*/

/*************************************************
*          Decode byte-string in xtext           *
*************************************************/

/* This function decodes a string in xtextformat as defined in RFC 1891 and
required by the SMTP AUTH extension (RFC 2554). We put the result in a piece of
store of equal length - it cannot be longer than this. Although in general the
result of decoding an xtext may be binary, in the context in which it is used
by Exim (for decoding the value of AUTH on a MAIL command), the result is
expected to be an addr-spec. We therefore add on a terminating zero, for
convenience.

Arguments:
  code        points to the coded string, zero-terminated
  ptr         where to put the pointer to the result, which is in
              dynamic store

Returns:      the number of bytes in the result, excluding the final zero;
              -1 if the input is malformed
*/

int
xtextdecode(const uschar * code, uschar ** ptr)
{
int x;
#ifdef COMPILE_UTILITY
uschar * result = malloc(Ustrlen(code) + 1);
#else
uschar * result = store_get(Ustrlen(code) + 1, code);
#endif

*ptr = result;
while ((x = (*code++)))
  {
  if (x < 33 || x > 127 || x == '=') return -1;
  if (x == '+')
    {
    int y;
    if (!isxdigit((x = (*code++)))) return -1;
    y = ((isdigit(x))? x - '0' : (tolower(x) - 'a' + 10)) << 4;
    if (!isxdigit((x = (*code++)))) return -1;
    *result++ = y | ((isdigit(x))? x - '0' : (tolower(x) - 'a' + 10));
    }
  else
    *result++ = x;
  }

*result = '\0';
return result - *ptr;
}

/* End of xtextencode.c */
/* vi: aw ai sw=2
*/
