/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"


/*************************************************
*          Encode byte-string in base 64         *
*************************************************/

/* This function encodes a string of bytes, containing any values whatsoever,
in base 64 as defined in RFC 2045 (MIME) and required by the SMTP AUTH
extension (RFC 2554). The encoding algorithm is written out in a
straightforward way. Turning it into some kind of compact loop is messy and
would probably run more slowly.

Arguments:
  clear       points to the clear text bytes
  len         the number of bytes to encode

Returns:      a pointer to the zero-terminated base 64 string, which
              is in working store
*/

static uschar *enc64table =
  US"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uschar *
auth_b64encode(uschar *clear, int len)
{
uschar *code = store_get(4*((len+2)/3) + 1);
uschar *p = code;

while (len-- >0)
  {
  register int x, y;

  x = *clear++;
  *p++ = enc64table[(x >> 2) & 63];

  if (len-- <= 0)
    {
    *p++ = enc64table[(x << 4) & 63];
    *p++ = '=';
    *p++ = '=';
    break;
    }

  y = *clear++;
  *p++ = enc64table[((x << 4) | ((y >> 4) & 15)) & 63];

  if (len-- <= 0)
    {
    *p++ = enc64table[(y << 2) & 63];
    *p++ = '=';
    break;
    }

  x = *clear++;
  *p++ = enc64table[((y << 2) | ((x >> 6) & 3)) & 63];

  *p++ = enc64table[x & 63];
  }

*p = 0;

return code;
}

/* End of b64encode.c */
