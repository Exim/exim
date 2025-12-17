/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* DSCP support for Exim
   Copyright (c) The Exim Maintainers - 2025
   License: GPL
   SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "../exim.h"
#if defined SUPPORT_DSCP

# include "../functions.h"

/******************************************************************************/
/* Utility functions */

/*************************************************
*    Lookup address family of potential socket   *
*************************************************/

/* Given a file-descriptor, check to see if it's a socket and, if so,
return the address family; detects IPv4 vs IPv6.  If not a socket then
return -1.

The value 0 is typically AF_UNSPEC, which should not be seen on a connected
fd.  If the return is -1, the errno will be from getsockname(); probably
ENOTSOCK or ECONNRESET.

Arguments:     socket-or-not fd
Returns:       address family or -1
*/

static int
ip_get_address_family(int fd)
{
struct sockaddr_storage ss;
socklen_t sslen = sizeof(ss);

if (getsockname(fd, (struct sockaddr *) &ss, &sslen) < 0)
  return -1;

return (int) ss.ss_family;
}



/*************************************************
*       Lookup DSCP settings for a socket        *
*************************************************/

struct dscp_name_tableentry {
  const uschar *name;
  int value;
};
/* Keep both of these tables sorted! */
static struct dscp_name_tableentry dscp_table[] = {
#ifdef IPTOS_DSCP_AF11
    { CUS"af11", IPTOS_DSCP_AF11 },
    { CUS"af12", IPTOS_DSCP_AF12 },
    { CUS"af13", IPTOS_DSCP_AF13 },
    { CUS"af21", IPTOS_DSCP_AF21 },
    { CUS"af22", IPTOS_DSCP_AF22 },
    { CUS"af23", IPTOS_DSCP_AF23 },
    { CUS"af31", IPTOS_DSCP_AF31 },
    { CUS"af32", IPTOS_DSCP_AF32 },
    { CUS"af33", IPTOS_DSCP_AF33 },
    { CUS"af41", IPTOS_DSCP_AF41 },
    { CUS"af42", IPTOS_DSCP_AF42 },
    { CUS"af43", IPTOS_DSCP_AF43 },
    { CUS"ef", IPTOS_DSCP_EF },
#endif
#ifdef IPTOS_LOWCOST
    { CUS"lowcost", IPTOS_LOWCOST },
#endif
    { CUS"lowdelay", IPTOS_LOWDELAY },
#ifdef IPTOS_MINCOST
    { CUS"mincost", IPTOS_MINCOST },
#endif
    { CUS"reliability", IPTOS_RELIABILITY },
    { CUS"throughput", IPTOS_THROUGHPUT }
};
static int dscp_table_size =
  sizeof(dscp_table) / sizeof(struct dscp_name_tableentry);

/* DSCP values change by protocol family, and so do the options used for
setsockopt(); this utility does all the lookups.  It takes an unexpanded
option string, expands it, strips off affix whitespace, then checks if it's
a number.  If all of what's left is a number, then that's how the option will
be parsed and success/failure is a range check.  If it's not all a number,
then it must be a supported keyword.

Arguments:
  dscp_name   a string, so far unvalidated
  af          address_family in use
  level       setsockopt level to use
  optname     setsockopt name to use
  dscp_value  value for dscp_name

Returns: TRUE if okay to setsockopt(), else FALSE

*level and *optname may be set even if FALSE is returned
*/

static BOOL
dscp_lookup(const uschar * dscp_name, int af,
    int * level, int * optname, int * dscp_value)
{
uschar * dscp_lookup, * p;
int first, last;
long rawlong;

if (af == AF_INET)
  { *level = IPPROTO_IP; *optname = IP_TOS; }
#if HAVE_IPV6 && defined(IPV6_TCLASS)
else if (af == AF_INET6)
  { *level = IPPROTO_IPV6; *optname = IPV6_TCLASS; }
#endif
else
  {
  DEBUG(D_transport)
    debug_printf("Unhandled address family %d in dscp_lookup()\n", af);
  return FALSE;
  }
if (!dscp_name)
  {
  DEBUG(D_transport)
    debug_printf("[empty DSCP]\n");
  return FALSE;
  }
dscp_lookup = expand_string_copy(dscp_name);
if (!dscp_lookup || !*dscp_lookup)
  return FALSE;

p = dscp_lookup + Ustrlen(dscp_lookup) - 1;
while (isspace(*p)) *p-- = '\0';
while (isspace(*dscp_lookup) && dscp_lookup < p) dscp_lookup++;
if (*dscp_lookup == '\0')
  return FALSE;

rawlong = Ustrtol(dscp_lookup, &p, 0);
if (p != dscp_lookup && *p == '\0')
  {
  /* We have six bits available, which will end up shifted to fit in 0xFC mask.
  RFC 2597 defines the values unshifted. */
  if (rawlong < 0 || rawlong > 0x3F)
    {
    DEBUG(D_transport)
      debug_printf("DSCP value %ld out of range, ignored.\n", rawlong);
    return FALSE;
    }
  *dscp_value = rawlong << 2;
  return TRUE;
  }

first = 0;
last = dscp_table_size;
while (last > first)
  {
  int middle = (first + last)/2;
  int c = Ustrcmp(dscp_lookup, dscp_table[middle].name);
  if (c == 0)
    {
    *dscp_value = dscp_table[middle].value;
    return TRUE;
    }
  else if (c > 0)
    first = middle + 1;
  else
    last = middle;
  }
return FALSE;
}

/******************************************************************************/

/*API
Set DSCP on stdin.  Called from ACL control.
Return error message on fail, NULL on ok.
*/

static uschar *
dscp_acl(const uschar * control, const uschar * opt)
{
int af, socklevel, optname, value;

if (*opt != '/')
  return string_sprintf("syntax error in \"control=%s\"", control);

/* If we are acting on stdin, the setsockopt may fail if stdin is
not a socket; we can accept that, we'll just debug-log failures
anyway. */
if (smtp_in_fd < 0) return US"no stdin";
if ((af = ip_get_address_family(smtp_in_fd)) < 0)
  {
  HDEBUG(D_acl) debug_printf_indent(
    "smtp input is probably not a socket [%s], not setting DSCP\n",
    strerror(errno));
  return NULL;
  }
if (!dscp_lookup(++opt, af, &socklevel, &optname, &value))
  return string_sprintf("unrecognised DSCP value in \"control=%s\"", control);

value = setsockopt(smtp_in_fd, socklevel, optname,
		    &value, sizeof(value));
HDEBUG(D_acl)
  if (value < 0)
    debug_printf_indent("failed to set input DSCP[%s]: %s\n",
      opt, strerror(errno));
  else
    debug_printf_indent("set input DSCP to %q\n", opt);
return NULL;
}


/*API
Set DSCP on given socket; called from smtp transport.
Can silently fail.
*/

static void
dscp_transport(int sock, const uschar * dscp_str, int host_af)
{
int dscp_value, dscp_level, dscp_option;

if (  dscp_str
   && dscp_lookup(dscp_str, host_af, &dscp_level, &dscp_option, &dscp_value)
   )
  {
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf_indent("DSCP %q=%x ", dscp_str, dscp_value);

  if (setsockopt(sock, dscp_level, dscp_option, &dscp_value, sizeof(dscp_value)) < 0)
    HDEBUG(D_transport|D_acl|D_v)
      debug_printf_indent("failed to set DSCP: %s ", strerror(errno));

  /* If the kernel supports IPv4 and IPv6 on an IPv6 socket, we need to set the
  option for both; ignore failures here */

  if (  host_af == AF_INET6
     && dscp_lookup(dscp_str, AF_INET, &dscp_level, &dscp_option, &dscp_value)
     )
    (void) setsockopt(sock, dscp_level, dscp_option, &dscp_value, sizeof(dscp_value));
  }
}


/*API: output known DSCP names */
static void
dscp_keywords(FILE * stream)
{
for (int i = 0; i < dscp_table_size; ++i)
  fprintf(stream, "%s\n", dscp_table[i].name);
}

/******************************************************************************/
/* Module API */

static void * dscp_functions[] = {
  [DSCP_ACL] =		(void *) dscp_acl,
  [DSCP_TRANSPORT] =	(void *) dscp_transport,
  [DSCP_KEYWORDS] =	(void *) dscp_keywords,
};

misc_module_info dscp_module_info =
{
  .name =		US"dscp",
# ifdef DYNLOOKUP
  .dyn_magic =		MISC_MODULE_MAGIC,
# endif
  .functions =		dscp_functions,
  .functions_count =	nelem(dscp_functions),
};

#endif /* SUPPORT_DSCP */
/* vi: aw ai sw=2
 */
