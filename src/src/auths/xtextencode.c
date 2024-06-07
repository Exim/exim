/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2022 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../exim.h"


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

uschar *
auth_xtextencode(uschar *clear, int len)
{
gstring * g = NULL;
for(uschar ch; len > 0; len--, clear++)
  g = (ch = *clear) < 33 || ch > 126 || ch == '+' || ch == '='
    ? string_fmt_append(g, "+%.02X", ch)
    : string_catn(g, clear, 1);
gstring_release_unused(g);
return string_from_gstring(g);
}


/* End of xtextencode.c */
/* vi: aw ai sw=2
*/
