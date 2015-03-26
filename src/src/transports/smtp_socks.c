/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* SOCKS version 5 proxy, client-mode */

#include "../exim.h"
#include "smtp.h"

#ifdef EXPERIMENTAL_SOCKS	/* entire file */

#ifndef nelem
# define nelem(arr) (sizeof(arr)/sizeof(*arr))
#endif


/* Defaults */
#define SOCKS_PORT	1080
#define SOCKS_TIMEOUT	5

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
  uschar		auth_type;	/* RFC 1928 encoding */
  const uschar *	auth_name;
  const uschar *	auth_pwd;
  short			port;
  unsigned		timeout;
  } socks_opts;

static void
socks_option_defaults(socks_opts * sob)
{
sob->auth_type = AUTH_NONE;
sob->auth_name = US"";
sob->auth_pwd = US"";
sob->port = SOCKS_PORT;
sob->timeout = SOCKS_TIMEOUT;
}

static void
socks_option(socks_opts * sob, const uschar * opt)
{
const uschar * s;

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
  sob->port = atoi(opt + 5);
else if (Ustrncmp(opt, "tmo=", 4) == 0)
  sob->timeout = atoi(opt + 4);
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
    HDEBUG(D_transport|D_acl|D_v) debug_printf("  socks auth NAME '%s' '%s'\n",
      sob->auth_name, sob->auth_pwd);
    i = Ustrlen(sob->auth_name);
    j = Ustrlen(sob->auth_pwd);
    s = string_sprintf("%c%c%.255s%c%.255s", AUTH_NAME_VER,
      i, sob->auth_name, j, sob->auth_pwd);
    len = i + j + 3;
    HDEBUG(D_transport|D_acl|D_v)
      {
      int i;
      debug_printf("  SOCKS>>");
      for (i = 0; i<len; i++) debug_printf(" %02x", s[i]);
      debug_printf("\n");
      }
    if (  send(fd, s, len, 0) < 0
       || !fd_ready(fd, tmo-time(NULL))
       || read(fd, s, 2) != 2
       )
      return FAIL;
    HDEBUG(D_transport|D_acl|D_v)
      debug_printf("  SOCKS<< %02x %02x\n", s[0], s[1]);
    if (s[0] == AUTH_NAME_VER && s[1] == 0)
      {
      HDEBUG(D_transport|D_acl|D_v) debug_printf("  socks auth OK\n");
      return OK;
      }

    log_write(0, LOG_MAIN|LOG_PANIC, "socks auth failed");
    errno = EPROTO;
    return FAIL;
  }
}



/* Make a connection via a socks proxy

Arguments:
 host		smtp target host
 host_af	address family
 port		remote tcp port number
 interface	local interface
 tb		transport
 timeout	connection timeout (zero for indefinite)

Return value:
 0 on success; -1 on failure, with errno set
*/

int
socks_sock_connect(host_item * host, int host_af, int port, uschar * interface,
  transport_instance * tb, int timeout)

{
smtp_transport_options_block * ob =
  (smtp_transport_options_block *)tb->options_block;
const uschar * proxy_list;
const uschar * proxy_spec;
int sep = 0;
int fd;
time_t tmo;
const uschar * state;
uschar buf[24];

if (!timeout) timeout = 24*60*60;	/* use 1 day for "indefinite" */
tmo = time(NULL) + timeout;

if (!(proxy_list = expand_string(ob->socks_proxy)))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "Bad expansion for socks_proxy in %s",
    tb->name);
  return -1;
  }

/* Loop over proxy list, trying in order until one works */
while ((proxy_spec = string_nextinlist(&proxy_list, &sep, NULL, 0)))
  {
  const uschar * proxy_host;
  int subsep = -' ';
  host_item proxy;
  int proxy_af;
  union sockaddr_46 sin;
  unsigned size;
  socks_opts sob;
  const uschar * option;

  if (!(proxy_host = string_nextinlist(&proxy_spec, &subsep, NULL, 0)))
    {
    /* paniclog config error */
    return -1;
    }

  /*XXX consider global options eg. "hide socks_password = wibble" on the tpt */
  socks_option_defaults(&sob);

  /* extract any further per-proxy options */
  while ((option = string_nextinlist(&proxy_spec, &subsep, NULL, 0)))
    socks_option(&sob, option);

  /* bodge up a host struct for the proxy */
  proxy.address = proxy_host;
  proxy_af = Ustrchr(proxy_host, ':') ? AF_INET6 : AF_INET;

  if ((fd = smtp_sock_connect(&proxy, proxy_af, sob.port,
	      interface, tb, sob.timeout)) < 0)
    continue;

  /* Do the socks protocol stuff */
  /* Send method-selection */
  state = US"method select";
  HDEBUG(D_transport|D_acl|D_v) debug_printf("  SOCKS>> 05 01 %02x\n", sob.auth_type);
  buf[0] = 5; buf[1] = 1; buf[2] = sob.auth_type;
  if (send(fd, buf, 3, 0) < 0)
    goto snd_err;

  /* expect method response */
  if (  !fd_ready(fd, tmo-time(NULL))
     || read(fd, buf, 2) != 2
     )
    goto rcv_err;
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf("  SOCKS<< %02x %02x\n", buf[0], buf[1]);
  if (  buf[0] != 5
     || socks_auth(fd, buf[1], &sob, tmo) != OK
     )
    goto proxy_err;

  (void) ip_addr(&sin, host_af, host->address, port);

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

  state = US"connect";
  HDEBUG(D_transport|D_acl|D_v)
    {
    int i;
    debug_printf("  SOCKS>>");
    for (i = 0; i<size; i++) debug_printf(" %02x", buf[i]);
    debug_printf("\n");
    }
  if (send(fd, buf, size, 0) < 0)
    goto snd_err;

  /* expect conn-reply (success, local(ipver, addr, port))
  of same length as conn-request, or non-success fail code */
  if (  !fd_ready(fd, tmo-time(NULL))
     || (size = read(fd, buf, size)) < 2
     )
    goto rcv_err;
  HDEBUG(D_transport|D_acl|D_v)
    {
    int i;
    debug_printf("  SOCKS>>");
    for (i = 0; i<size; i++) debug_printf(" %02x", buf[i]);
    debug_printf("\n");
    }
  if (  buf[0] != 5
     || buf[1] != 0
     )
    goto proxy_err;

  /*XXX log proxy outbound addr/port? */
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf("  proxy farside local: [%s]:%d\n",
      host_ntoa(buf[3] == 4 ? AF_INET6 : AF_INET, buf+4, NULL, NULL),
      ntohs(*((uint16_t *)(buf + (buf[3] == 4 ? 20 : 8)))));

  return fd;
  }

HDEBUG(D_transport|D_acl|D_v) debug_printf("  no proxies left\n");
return -1;

snd_err:
  HDEBUG(D_transport|D_acl|D_v) debug_printf("  proxy snd_err %s: %s\n", state, strerror(errno));
  return -1;

proxy_err:
  {
  struct socks_err * se =
    buf[1] > nelem(socks_errs) ? NULL : socks_errs + buf[1];
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf("  proxy %s: %s\n", state, se ? se->reason : US"unknown error code received");
  errno = se ? se->errcode : EPROTO;
  }

rcv_err:
  HDEBUG(D_transport|D_acl|D_v) debug_printf("  proxy rcv_err %s: %s\n", state, strerror(errno));
  if (!errno) errno = EPROTO;
  else if (errno == ENOENT) errno = ECONNABORTED;
  return -1;
}

#endif	/* entire file */
/* vi: aw ai sw=2
*/
