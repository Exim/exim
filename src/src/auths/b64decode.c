/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"


/*************************************************
*          Decode byte-string in base 64         *
*************************************************/

/* This function decodes a string in base 64 format as defined in RFC 2045
(MIME) and required by the SMTP AUTH extension (RFC 2554). The decoding
algorithm is written out in a straightforward way. Turning it into some kind of
compact loop is messy and would probably run more slowly.

Arguments:
  code        points to the coded string, zero-terminated
  ptr         where to put the pointer to the result, which is in
              dynamic store, and zero-terminated

Returns:      the number of bytes in the result,
              or -1 if the input was malformed

A zero is added on to the end to make it easy in cases where the result is to
be interpreted as text. This is not included in the count. */

static uschar dec64table[] = {
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, /*  0-15 */
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, /* 16-31 */
  255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63, /* 32-47 */
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255, /* 48-63 */
  255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 64-79 */
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255, /* 80-95 */
  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 96-111 */
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255  /* 112-127*/
};

int
auth_b64decode(uschar *code, uschar **ptr)
{
register int x, y;
uschar *result = store_get(3*(Ustrlen(code)/4) + 1);

*ptr = result;

/* Each cycle of the loop handles a quantum of 4 input bytes. For the last
quantum this may decode to 1, 2, or 3 output bytes. */

while ((x = (*code++)) != 0)
  {
  if (x > 127 || (x = dec64table[x]) == 255) return -1;
  if ((y = (*code++)) == 0 || (y = dec64table[y]) == 255)
    return -1;
  *result++ = (x << 2) | (y >> 4);

  if ((x = (*code++)) == '=')
    {
    if (*code++ != '=' || *code != 0) return -1;
    }
  else
    {
    if (x > 127 || (x = dec64table[x]) == 255) return -1;
    *result++ = (y << 4) | (x >> 2);
    if ((y = (*code++)) == '=')
      {
      if (*code != 0) return -1;
      }
    else
      {
      if (y > 127 || (y = dec64table[y]) == 255) return -1;
      *result++ = (x << 6) | y;
      }
    }
  }

*result = 0;
return result - *ptr;
}

/* End of b64decode.c */
