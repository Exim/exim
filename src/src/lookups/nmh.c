/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * Exim - NMH database lookup module
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Copyright (c) The Exim Maintainers 2025
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include "../exim.h"
#include "lf_functions.h"

#define MODE_ADD        '+'
#define MODE_SUB        '-'
#define MODE_ASK        '?'

/* Structure and anchor for caching connections. */

typedef struct nmh_connection {
  struct nmh_connection * next;
  const uschar *	proto;
  const uschar *	server;
  int			port;
  int			socket;
} nmh_connection;

static nmh_connection * nmh_connections = NULL;

/* Service functions */


/* Get a connectionless unix-domain socket, bound to the remote server
*/
static int
mk_unix_sock(const uschar * server, uschar ** errmsg)
{
struct sockaddr_un s_un = { .sun_family = AF_UNIX, .sun_path = "" };
ssize_t slen = offsetof(struct sockaddr_un, sun_path) + strlen(s_un.sun_path);
uschar * server_copy = string_copy(server);
int fd, len;

/* Set up the socket and bind the local name */

s_un.sun_path[0] = '\0';        /* marker for abstract local socket addr */
snprintf(s_un.sun_path+1, sizeof(s_un.sun_path)-1,
	"exim-nmh-%lx", (unsigned long) getpid());

if ((fd = socket(PF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)) < 0)
  {
  *errmsg= US"socket";
  return -1;
  }
if (bind(fd, (const struct sockaddr *)&s_un, (socklen_t)slen) < 0)
  {
  *errmsg= US"bind";
  return -1;
  }
#ifdef SO_PASSRIGHTS
  {
  int zero = 0;
  if (setsockopt(fd, SOL_SOCKET, SO_PASSRIGHTS, &zero, sizeof(zero)) != 0)
    {
    *errmsg= US"setsockopt";
    return -1;
    }
  }
#endif


/* Bind the remote address */

if (*server_copy = '@')	/* exim syntax for abstract name */
  {
  *server_copy = '\0';	/* abstract remote socket name */
  len = Ustrlen(server_copy + 1) + 1;
  }
else
  len = Ustrlen(server_copy);
if (len > sizeof(s_un.sun_path)-1)
  len = sizeof(s_un.sun_path)-1;

memcpy(s_un.sun_path, server_copy, len);
s_un.sun_path[len] = '\0';
slen = offsetof(struct sockaddr_un, sun_path) + len;

if (connect(fd, (const struct sockaddr *)&s_un, (socklen_t)slen) < 0)
  {
  (void) close(fd);
  *errmsg= string_sprintf("connect '%s': %s", server, strerror(errno));
  log_write(0, LOG_MAIN|LOG_PANIC, "nmh lookup: %s\n", *errmsg);
  return -1;
  }
return fd;
}

static int
mk_udp_sock(const uschar * server, int port, uschar ** errmsg)
{
if (port > 0)
  {
  int fd = ip_connectedsocket(SOCK_DGRAM, server, port, port,
			    5, NULL, errmsg, NULL);
  callout_address = NULL;
  return fd;
  }

errno = ENXIO;
*errmsg = US"bad port number";
return -1;
}

static int
mk_tcp_sock(const uschar * server, int port, uschar ** errmsg)
{
#ifdef notyet
/*XXX consider lazy-TFO */
if (port > 0)
  {
  int fd = ip_connectedsocket(SOCK_STREAM, server, port, port,
			    5, NULL, errmsg, NULL);
  callout_address = NULL;
  return fd;
  }

errno = ENXIO;
*errmsg = US"bad port number";
#else
*errmsg = US"tcp is not supported for nmh at this time";
#endif
return -1;
}

static int
mk_sock(const uschar * proto, const uschar * server, int port, uschar ** errmsg)
{
if (Ustrcmp(proto, "unix") == 0) return mk_unix_sock(server, errmsg);
if (Ustrcmp(proto, "udp") == 0) return mk_udp_sock(server, port, errmsg);
if (Ustrcmp(proto, "tcp") == 0) return mk_tcp_sock(server, port, errmsg);
errno = EPFNOSUPPORT;
*errmsg = US"bad protocol name";
return -1;
}

/******************************************************************************/

/*************************************************
*             Open entry point                   *
*************************************************/

/* The api doesn't give us the options, which we need for the type
of connection.  So wait until the find call, just like lookup_querystyle
"traditionally" does (according to README).  Sadly, this means we have to
maintain our own cache of connections rather than having the framework able
to do it.
*/

static void *
nmh_open(const uschar * filename, uschar ** errmsg)
{
return (void *)(1);    /* Just return something non-null */
}

/*************************************************
*              Find entry point                  *
*************************************************/

/* Arguments:
	handle		dummy, from nmh_open()
	filename	server to contact, interpretation depends on options
	keystring	key for the lookup
	key_len		number of chars in keystring
	result		where to pass back the result
	errmsg		where to pass back an error message
	do_cache	to be set if data is changed
	opts		options, comma-separated list

Returns:		OK/DEFER/FAIL (?)
*/

static int
nmh_find(void * handle, const uschar * filename, const uschar * keystring,
  int key_len, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
const uschar * proto = US"unix";
int sep = ',', sock, read_timeout = 5;
uschar mode = MODE_ASK;
BOOL partial = FALSE;
uschar * s;
int port = -1, i;
const uschar * table = US"default";
uschar resp[1];
nmh_connection * cn;
gstring * g;

/* Scan the options */

for (const uschar * s; s = string_nextinlist(&opts, &sep, NULL, 0); )
  if (  Ustrcmp(s, "unix") == 0
     || Ustrcmp(s, "udp") == 0 || Ustrcmp(s, "tcp") == 0)
    proto = s;
  else if (Ustrcmp(s, "add") == 0)
    { mode = MODE_ADD; *do_cache = 0; }
  else if (Ustrcmp(s, "sub") == 0)
    { mode = MODE_SUB; *do_cache = 0; }
  else if (Ustrcmp(s, "partial") == 0)
    partial = TRUE;
  else if (Ustrncmp(s, "table=", 6) == 0)
    table = s+6;
  else if (Ustrncmp(s, "tmo=", 4) == 0)
    {
    if ((read_timeout = strtol(CS s+4, NULL, 10)) == 0)
      {
      errno = ENXIO;
      *errmsg = US"missing value in timeout spec";
      return DEFER;
      }
    }
  else if (Ustrncmp(s, "port=", 5) == 0)
    if ((port = strtol(CS s+5, NULL, 10)) == 0)
      {
      errno = ENXIO;
      *errmsg = US"missing port in server spec";
      return DEFER;
      }
    else
      proto = US"udp";

/* See if we have a cached connection to the server */

for (cn = nmh_connections; cn; cn = cn->next)
  if (  Ustrcmp(cn->proto, proto) == 0
     && Ustrcmp(cn->server, filename) == 0
     && cn->port == port)
    { sock = cn->socket; break; }

if (!cn)
  {
  if ((sock = mk_sock(proto, filename, port, errmsg)) < 0)
    return DEFER;

  /* Add the connection to the cache */

  cn = store_get(sizeof(nmh_connection), GET_UNTAINTED);
  cn->proto = proto;
  cn->server = string_copy(filename);
  cn->port = port;
  cn->socket = sock;
  cn->next = nmh_connections;
  nmh_connections = cn;
  }
else DEBUG(D_lookup)
  debug_printf_indent("cached socket\n");

/* Build and send the query string */

g = string_fmt_append(NULL, "%s%c%n%c%s",
      table, '\0', &i, mode, keystring);
s = string_from_gstring(g);

DEBUG(D_lookup)
  debug_printf("%s %d: send '%s\\0%s'\n", __FUNCTION__, __LINE__, s, s + i);

i = write(sock, s, gstring_length(g));
if (i != gstring_length(g))
  {
  *errmsg = US"error in write";
  return DEFER;
  }

/* Read and interpret the reponse */

if (!poll_one_fd(sock, POLLIN, read_timeout * 1000))
  {
  *errmsg = US"read timed out";
  log_write(0, LOG_MAIN|LOG_PANIC, "Timeout on nmh lookup on %q\n", filename);
  return DEFER;
  }
if (read(sock, resp, 1) != 1)
  {
  *errmsg = US"error in read";
  return DEFER;
  }

DEBUG(D_lookup)
  debug_printf("%s %d: recv '%.1s'\n", __FUNCTION__, __LINE__, resp);

switch (resp[0])
  {
  case '0': *result = NULL; break;
  case '1': *result = partial ? US"yes" : NULL; break;
  case '2': *result = US"yes"; break;
  default: *errmsg = US"bad response value"; return DEFER;
  }
return OK;
}


/*************************************************
*               Tidy entry point                 *
*************************************************/

/* See local README for interface description. */

static void
nmh_tidy(void)
{
nmh_connection *cn;
while ((cn = nmh_connections))
  {
  nmh_connections = cn->next;
  DEBUG(D_lookup) debug_printf_indent("close NMH connection: %s\n", cn->server);
  close(cn->socket);
  }
}




/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
nmh_version_report(gstring * g)
{
#ifdef DYNLOOKUP
g = string_fmt_append(g, "Library version: NMH: Exim version %s\n", EXIM_VERSION_STR);
#endif
return g;
}


lookup_info nmh_lookup_info = {
  .name = US"nmh",			/* lookup name */
  .type = lookup_absfile,		/* absolute file name */
  .open = nmh_open,			/* open function (dummy) */
  .check = NULL,			/* no check function */
  .find = nmh_find,			/* find function */
  .close = NULL,			/* no close function */
  .tidy = nmh_tidy,			/* tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = nmh_version_report             /* version reporting */
};

#ifdef DYNLOOKUP
# define nmh_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &nmh_lookup_info };
lookup_module_info nmh_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/nmh.c */
