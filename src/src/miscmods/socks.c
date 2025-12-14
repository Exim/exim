/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2021 - 2025 */
/* Copyright (c) Jeremy Harris 2015 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* SOCKS version 5 proxy, client-mode */

#include "../exim.h"
#include "../transports/smtp.h"

#ifdef SUPPORT_SOCKS /* entire file */

/* Defaults */
#define SOCKS_PORT	1080
#define SOCKS_TIMEOUT	5
#define SOCKS_WEIGHT	1
#define SOCKS_PRIORITY	1

#define AUTH_NONE	0
#define AUTH_NAME	2		/* user/password per RFC 1929 */
#define AUTH_NAME_VER	1

struct socks_err
  {
  uschar *	reason;
  int		errcode;
  } socks_errs[] =
  {
    {NULL, 0},
    {US"general SOCKS server failure",		EIO},
    {US"connection not allowed by ruleset",	EACCES},
    {US"Network unreachable",			ENETUNREACH},
    {US"Host unreachable",			EHOSTUNREACH},
    {US"Connection refused",			ECONNREFUSED},
    {US"TTL expired",				ECANCELED},
    {US"Command not supported",			EOPNOTSUPP},
    {US"Address type not supported",		EAFNOSUPPORT}
  };

typedef struct
  {
  const uschar *	proxy_host;
  uschar		auth_type;	/* RFC 1928 encoding */
  const uschar *	auth_name;
  const uschar *	auth_pwd;
  short			port;
  BOOL			is_failed;
  unsigned		timeout;
  unsigned		weight;
  unsigned		priority;
  } socks_opts;

static void
socks_option_defaults(socks_opts * sob)
{
sob->proxy_host = NULL;
sob->auth_type =  AUTH_NONE;
sob->auth_name =  US"";
sob->auth_pwd =   US"";
sob->is_failed =  FALSE;
sob->port =	  SOCKS_PORT;
sob->timeout =	  SOCKS_TIMEOUT;
sob->weight =	  SOCKS_WEIGHT;
sob->priority =   SOCKS_PRIORITY;
}

static void
socks_option(socks_opts * sob, const uschar * opt)
{
if (Ustrncmp(opt, "auth=", 5) == 0)
  {
  opt += 5;
  if (Ustrcmp(opt, "none") == 0) 	sob->auth_type = AUTH_NONE;
  else if (Ustrcmp(opt, "name") == 0)	sob->auth_type = AUTH_NAME;
  }
else if (Ustrncmp(opt, "name=", 5) == 0)
  sob->auth_name = opt + 5;
else if (Ustrncmp(opt, "pass=", 5) == 0)
  sob->auth_pwd = opt + 5;
else if (Ustrncmp(opt, "port=", 5) == 0)
  sob->port = atoi(CCS opt + 5);
else if (Ustrncmp(opt, "tmo=", 4) == 0)
  sob->timeout = atoi(CCS opt + 4);
else if (Ustrncmp(opt, "pri=", 4) == 0)
  sob->priority = atoi(CCS opt + 4);
else if (Ustrncmp(opt, "weight=", 7) == 0)
  sob->weight = atoi(CCS opt + 7);
return;
}

static int
socks_auth(int fd, int method, socks_opts * sob, time_t tmo)
{
uschar * s;
int len, i, j;

switch(method)
  {
  default:
    log_write(0, LOG_MAIN|LOG_PANIC,
      "Unrecognised socks auth method %d", method);
    return FAIL;
  case AUTH_NONE:
    return OK;
  case AUTH_NAME:
    HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  socks auth NAME '%s' '%s'\n",
      sob->auth_name, sob->auth_pwd);
    i = Ustrlen(sob->auth_name);
    j = Ustrlen(sob->auth_pwd);
    s = string_sprintf("%c%c%.255s%c%.255s%n", AUTH_NAME_VER,
      i, sob->auth_name, j, sob->auth_pwd, &len);

    HDEBUG(D_transport|D_acl|D_v)
      debug_printf_indent("  SOCKS>>%3.*H\n", len, s);
    if (send(fd, s, len, 0) < 0)
      return FAIL;
#ifdef TCP_QUICKACK
    (void) setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, US &off, sizeof(off));
#endif
    if (!fd_ready(fd, tmo) || read(fd, s, 2) != 2)
      return FAIL;
    HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  SOCKS<<%3.2H\n", s);
    if (s[0] == AUTH_NAME_VER && s[1] == 0)
      {
      HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  socks auth OK\n");
      return OK;
      }

    log_write(0, LOG_MAIN|LOG_PANIC, "socks auth failed");
    errno = EPROTO;
    return FAIL;
  }
}



/* Find a suitable proxy to use from the list.
Possible common code with spamd_get_server() ?

Return: index into proxy spec array, or -1
*/

static int
socks_get_proxy(socks_opts * proxies, unsigned nproxies)
{
unsigned int i;
const socks_opts * sd, * lim = &proxies[nproxies];
long rnd, weights;
unsigned pri;

if (nproxies == 1)		/* shortcut, if we have only 1 server */
  return (proxies[0].is_failed ? -1 : 0);

/* scan for highest pri */
for (pri = 0, sd = proxies; sd < lim; sd++)
  if (!sd->is_failed && sd->priority > pri)
    pri = sd->priority;

/* get sum of weights at this pri */
for (weights = 0, sd = proxies; sd < lim; sd++)
  if (!sd->is_failed && sd->priority == pri)
    weights += sd->weight;
if (weights == 0)       /* all servers failed */
  return -1;

for (rnd = random_number(weights), i = 0; i < nproxies; i++)
  {
  sd = &proxies[i];
  if (!sd->is_failed && sd->priority == pri)
    if ((rnd -= sd->weight) < 0)
      return i;
  }

log_write(0, LOG_MAIN|LOG_PANIC,
  "%s unknown error (memory/cpu corruption?)", __FUNCTION__);
return -1;
}



/*API: Make a connection via a socks proxy

Arguments:
 sc		details for making connection: host, af, interface, transport
 early_data	data to send down the smtp channel (once proxied)

Return value:
 connected file descriptor on success; -1 on failure, with errno set
*/

static int
socks_sock_connect(const smtp_connect_args * sc, const blob * early_data)
{
transport_instance * tb = sc->tblock;
smtp_transport_options_block * ob = tb->drinst.options_block;
int timeout = ob->connect_timeout;
const uschar * proxy_list = ob->socks_proxy,	/* already expanded */
	      * proxy_spec;
int sep = 0;
int fd;
time_t tmo;
const uschar * state;
uschar buf[24];
socks_opts proxies[32];			/* max #proxies handled */
unsigned nproxies;
socks_opts * sob = NULL;
unsigned size;
blob proxy_early_data;

if (!timeout) timeout = 24*60*60;	/* use 1 day for "indefinite" */
tmo = time(NULL) + timeout;

/* Read proxy list */

for (nproxies = 0;
        nproxies < nelem(proxies)
     && (proxy_spec = string_nextinlist(&proxy_list, &sep, NULL, 0));
     nproxies++)
  {
  int subsep = -' ';
  const uschar * option;

  socks_option_defaults(sob = &proxies[nproxies]);

  if (!(sob->proxy_host = string_nextinlist(&proxy_spec, &subsep, NULL, 0)))
    {
    /* paniclog config error */
    return -1;
    }

  /*XXX consider global options eg. "hide socks_password = wibble" on the tpt */
  /* extract any further per-proxy options */
  while ((option = string_nextinlist(&proxy_spec, &subsep, NULL, 0)))
    socks_option(sob, option);
  }
if (!sob) return -1;

/* Set up the socks protocol method-selection message,
for sending on connection */

state = US"method select";
buf[0] = 5; buf[1] = 1; buf[2] = sob->auth_type;
proxy_early_data.data = buf;
proxy_early_data.len = 3;

/* Try proxies until a connection succeeds */

for(;;)
  {
  int idx;
  host_item proxy;

  /* Large (64k if DANE supported) */
  smtp_connect_args proxy_sc = {.sock = -1};

  if ((idx = socks_get_proxy(proxies, nproxies)) < 0)
    {
    HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  no proxies left\n");
    errno = EBUSY;
    return -1;
    }
  sob = &proxies[idx];

  /* bodge up a host struct for the proxy */
  proxy.address = proxy.name = sob->proxy_host;
  proxy.port = sob->port;

  proxy_sc.tblock = tb;
  proxy_sc.ob = ob;
  proxy_sc.host = &proxy;
  proxy_sc.host_af = Ustrchr(sob->proxy_host, ':') ? AF_INET6 : AF_INET;
  proxy_sc.interface = sc->interface;

  /*XXX we trust that the method-select command is idempotent */
  if ((fd = smtp_sock_connect(&proxy_sc, sob->timeout, &proxy_early_data)) >= 0)
    {
    proxy_local_address = string_copy(proxy.address);
    proxy_local_port = sob->port;
    break;
    }

  log_write(0, LOG_MAIN, "%s: %s", __FUNCTION__, strerror(errno));
  sob->is_failed = TRUE;
  }

/* Do the socks protocol stuff */

HDEBUG(D_transport|D_acl|D_v)
  debug_printf_indent("  SOCKS>> 05 01 %02x\n", sob->auth_type);

/* expect method response */

#ifdef TCP_QUICKACK
(void) setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, US &off, sizeof(off));
#endif

if (  !fd_ready(fd, tmo)
   || read(fd, buf, 2) != 2
   )
  goto rcv_err;
HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  SOCKS<<%3.2H\n", buf);
if (  buf[0] != 5
   || socks_auth(fd, buf[1], sob, tmo) != OK
   )
  goto proxy_err;

 {
  int host_af = sc->host_af;
  const host_item * host = sc->host;
  union sockaddr_46 sin;
  (void) ip_addr(&sin, host_af, host->address, host->port);

  /* send connect (ipver, ipaddr, port) */

  buf[0] = 5; buf[1] = 1; buf[2] = 0; buf[3] = host_af == AF_INET6 ? 4 : 1;
  #if HAVE_IPV6
  if (host_af == AF_INET6)
    {
    memcpy(buf+4, &sin.v6.sin6_addr,       sizeof(sin.v6.sin6_addr));
    memcpy(buf+4+sizeof(sin.v6.sin6_addr),
      &sin.v6.sin6_port, sizeof(sin.v6.sin6_port));
    size = 4+sizeof(sin.v6.sin6_addr)+sizeof(sin.v6.sin6_port);
    }
  else
  #endif
    {
    memcpy(buf+4, &sin.v4.sin_addr.s_addr, sizeof(sin.v4.sin_addr.s_addr));
    memcpy(buf+4+sizeof(sin.v4.sin_addr.s_addr),
      &sin.v4.sin_port, sizeof(sin.v4.sin_port));
    size = 4+sizeof(sin.v4.sin_addr.s_addr)+sizeof(sin.v4.sin_port);
    }
 }

state = US"connect";
HDEBUG(D_transport|D_acl|D_v)
  debug_printf_indent("  SOCKS>>%3.*H\n", (int)size, buf);
if (send(fd, buf, size, 0) < 0)
  goto snd_err;

/* expect conn-reply (success, local(ipver, addr, port))
of same length as conn-request, or non-success fail code */

if (  !fd_ready(fd, tmo)
   || (size = read(fd, buf, size)) < 2
   )
  goto rcv_err;
HDEBUG(D_transport|D_acl|D_v)
  debug_printf_indent("  SOCKS<<%3.*H\n", (int)size, buf);

if (  buf[0] != 5
   || buf[1] != 0
   )
  goto proxy_err;

proxy_external_address = string_copy(
  host_ntoa(buf[3] == 4 ? AF_INET6 : AF_INET, buf+4, NULL, NULL));
proxy_external_port = ntohs(*((uint16_t *)(buf + (buf[3] == 4 ? 20 : 8))));
proxy_session = TRUE;

HDEBUG(D_transport|D_acl|D_v)
  debug_printf_indent("  proxy farside: [%s]:%d\n", proxy_external_address, proxy_external_port);

if (early_data && early_data->data && early_data->len)
  if (send(fd, early_data->data, early_data->len, 0) < 0)
    {
    int save_errno = errno;
    HDEBUG(D_transport|D_acl|D_v)
      {
      debug_printf_indent("failed: %s", CUstrerror(save_errno));
      if (save_errno == ETIMEDOUT)
	debug_printf(" (timeout=%s)", readconf_printtime(ob->connect_timeout));
      debug_printf("\n");
      }
    (void)close(fd);
    fd= -1;
    errno = save_errno;
    }

return fd;

snd_err:
  HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  proxy snd_err %s: %s\n", state, strerror(errno));
  return -1;

proxy_err:
  {
  struct socks_err * se =
    buf[1] > nelem(socks_errs) ? NULL : socks_errs + buf[1];
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf_indent("  proxy %s: %s\n", state, se ? se->reason : US"unknown error code received");
  errno = se ? se->errcode : EPROTO;
  }

rcv_err:
  HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  proxy rcv_err %s: %s\n", state, strerror(errno));
  if (!errno) errno = EPROTO;
  else if (errno == ENOENT) errno = ECONNABORTED;
  return -1;
}

/******************************************************************************/
/* Module API */

static void * socks_functions[] = {
  [SOCKS_CONNECT] =	(void *) socks_sock_connect,
};

misc_module_info socks_module_info =
{
  .name =		US"socks",
# ifdef DYNLOOKUP
  .dyn_magic =		MISC_MODULE_MAGIC,
# endif

  .functions =		socks_functions,
  .functions_count =	nelem(socks_functions),
};

#endif	/* entire file */
/* vi: aw ai sw=2
*/
