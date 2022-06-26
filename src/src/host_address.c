/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "exim.h"

/*************************************************
*        Extract port from address string        *
*************************************************/

/* In the spool file, and in the -oMa and -oMi options, a host plus port is
given as an IP address followed by a dot and a port number. This function
decodes this.

An alternative format for the -oMa and -oMi options is [ip address]:port which
is what Exim 4 uses for output, because it seems to becoming commonly used,
whereas the dot form confuses some programs/people. So we recognize that form
too.

Argument:
  address    points to the string; if there is a port, the '.' in the string
             is overwritten with zero to terminate the address; if the string
             is in the [xxx]:ppp format, the address is shifted left and the
             brackets are removed

Returns:     0 if there is no port, else the port number. If there's a syntax
             error, leave the incoming address alone, and return 0.
*/

int
host_address_extract_port(uschar * address)
{
int port = 0;
uschar *endptr;

/* Handle the "bracketed with colon on the end" format */

if (*address == '[')
  {
  uschar *rb = address + 1;
  while (*rb != 0 && *rb != ']') rb++;
  if (*rb++ == 0) return 0;        /* Missing ]; leave invalid address */
  if (*rb == ':')
    {
    port = Ustrtol(rb + 1, &endptr, 10);
    if (*endptr != 0) return 0;    /* Invalid port; leave invalid address */
    }
  else if (*rb != 0) return 0;     /* Bad syntax; leave invalid address */
  memmove(address, address + 1, rb - address - 2);
  rb[-2] = 0;
  }

/* Handle the "dot on the end" format */

else
  {
  int skip = -3;                   /* Skip 3 dots in IPv4 addresses */
  address--;
  while (*(++address) != 0)
    {
    int ch = *address;
    if (ch == ':') skip = 0;       /* Skip 0 dots in IPv6 addresses */
      else if (ch == '.' && skip++ >= 0) break;
    }
  if (*address == 0) return 0;
  port = Ustrtol(address + 1, &endptr, 10);
  if (*endptr != 0) return 0;      /* Invalid port; leave invalid address */
  *address = 0;
  }

return port;
}

/* vi: aw ai sw=2
*/
/* End of host.c */
