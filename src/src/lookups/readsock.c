/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2020 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"


static int
internal_readsock_open(client_conn_ctx * cctx, const uschar * sspec,
  int timeout, BOOL do_tls, uschar ** errmsg)
{
int sep = ',';
uschar * ele;
const uschar * server_name;
host_item host;

if (Ustrncmp(sspec, "inet:", 5) == 0)
  {
  int port;
  uschar * port_name;

  DEBUG(D_lookup)
    debug_printf_indent("  new inet socket needed for readsocket\n");

  server_name = sspec + 5;
  port_name = Ustrrchr(server_name, ':');

  /* Sort out the port */

  if (!port_name)
    {
    /* expand_string_message results in an EXPAND_FAIL, from our
    only caller.  Lack of it gets a SOCK_FAIL; we feed back via errmsg
    for that, which gets copied to search_error_message. */

    expand_string_message =
      string_sprintf("missing port for readsocket %s", sspec);
    return FAIL;
    }
  *port_name++ = 0;           /* Terminate server name */

  if (isdigit(*port_name))
    {
    uschar *end;
    port = Ustrtol(port_name, &end, 0);
    if (end != port_name + Ustrlen(port_name))
      {
      expand_string_message =
	string_sprintf("invalid port number %s", port_name);
      return FAIL;
      }
    }
  else
    {
    struct servent *service_info = getservbyname(CS port_name, "tcp");
    if (!service_info)
      {
      expand_string_message = string_sprintf("unknown port \"%s\"",
	port_name);
      return FAIL;
      }
    port = ntohs(service_info->s_port);
    }

  /* Not having the request-string here in the open routine means
  that we cannot do TFO; a pity */

  cctx->sock = ip_connectedsocket(SOCK_STREAM, server_name, port, port,
	  timeout, &host, errmsg, NULL);
  callout_address = NULL;
  if (cctx->sock < 0)
    return FAIL;
  }

else
  {
  struct sockaddr_un sockun;         /* don't call this "sun" ! */
  int rc;

  DEBUG(D_lookup)
    debug_printf_indent("  new unix socket needed for readsocket\n");

  if ((cctx->sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
    {
    *errmsg = string_sprintf("failed to create socket: %s", strerror(errno));
    return FAIL;
    }

  sockun.sun_family = AF_UNIX;
  sprintf(sockun.sun_path, "%.*s", (int)(sizeof(sockun.sun_path)-1),
    sspec);
  server_name = US sockun.sun_path;

  sigalrm_seen = FALSE;
  ALARM(timeout);
  rc = connect(cctx->sock, (struct sockaddr *)(&sockun), sizeof(sockun));
  ALARM_CLR(0);
  if (sigalrm_seen)
    {
    *errmsg = US "socket connect timed out";
    goto bad;
    }
  if (rc < 0)
    {
    *errmsg = string_sprintf("failed to connect to socket "
      "%s: %s", sspec, strerror(errno));
    goto bad;
    }
  host.name = server_name;
  host.address = US"";
  }

#ifndef DISABLE_TLS
if (do_tls)
  {
  smtp_connect_args conn_args = {.host = &host };
  tls_support tls_dummy = {.sni=NULL};
  uschar * errstr;

  if (!tls_client_start(cctx, &conn_args, NULL, &tls_dummy, &errstr))
    {
    *errmsg = string_sprintf("TLS connect failed: %s", errstr);
    goto bad;
    }
  }
#endif

DEBUG(D_expand|D_lookup) debug_printf_indent("  connected to socket %s\n", sspec);
return OK;

bad:
  close(cctx->sock);
  return FAIL;
}

/* All use of allocations will be done against the POOL_SEARCH memory,
which is freed once by search_tidyup(). */

/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */
/* We just create a placeholder record with a closed socket, so
that connection cacheing at the framework layer works. */

static void *
readsock_open(const uschar * filename, uschar ** errmsg)
{
client_conn_ctx * cctx = store_get(sizeof(*cctx), FALSE);
cctx->sock = -1;
cctx->tls_ctx = NULL;
DEBUG(D_lookup) debug_printf_indent("readsock: allocated context\n");
return cctx;
}





/*************************************************
*         Find entry point for lsearch           *
*************************************************/

/* See local README for interface description */

static int
readsock_find(void * handle, const uschar * filename, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
client_conn_ctx * cctx = handle;
int sep = ',';
struct {
	BOOL do_shutdown:1;
	BOOL do_tls:1;
	BOOL cache:1;
} lf = {.do_shutdown = TRUE};
uschar * eol = NULL;
int timeout = 5;
FILE * fp;
gstring * yield;
int ret = DEFER;

DEBUG(D_lookup)
  debug_printf_indent("readsock: file=\"%s\" key=\"%s\" len=%d opts=\"%s\"\n",
    filename, keystring, length, opts);

/* Parse options */

if (opts) for (uschar * s; s = string_nextinlist(&opts, &sep, NULL, 0); )
  if (Ustrncmp(s, "timeout=", 8) == 0)
    timeout = readconf_readtime(s + 8, 0, FALSE);
  else if (Ustrncmp(s, "shutdown=", 9) == 0)
    lf.do_shutdown = Ustrcmp(s + 9, "no") != 0;
#ifndef DISABLE_TLS
  else if (Ustrncmp(s, "tls=", 4) == 0 && Ustrcmp(s + 4, US"no") != 0)
    lf.do_tls = TRUE;
#endif
  else if (Ustrncmp(s, "eol=", 4) == 0)
    eol = string_unprinting(s + 4);
  else if (Ustrcmp(s, "cache=yes") == 0)
    lf.cache = TRUE;
  else if (Ustrcmp(s, "send=no") == 0)
    length = 0;

if (!filename) return FAIL;	/* Server spec is required */

/* Open the socket, if not cached */

if (cctx->sock == -1)
  if (internal_readsock_open(cctx, filename, timeout, lf.do_tls, errmsg) != OK)
    return ret;

testharness_pause_ms(100);	/* Allow sequencing of test actions */

/* Write the request string, if not empty or already done */

if (length)
  {
  if ((
#ifndef DISABLE_TLS
      cctx->tls_ctx ? tls_write(cctx->tls_ctx, keystring, length, FALSE) :
#endif
		      write(cctx->sock, keystring, length)) != length)
    {
    *errmsg = string_sprintf("request write to socket "
      "failed: %s", strerror(errno));
    goto out;
    }
  }

/* Shut down the sending side of the socket. This helps some servers to
recognise that it is their turn to do some work. Just in case some
system doesn't have this function, make it conditional. */

#ifdef SHUT_WR
if (!cctx->tls_ctx && lf.do_shutdown)
  shutdown(cctx->sock, SHUT_WR);
#endif

testharness_pause_ms(100);

/* Now we need to read from the socket, under a timeout. The function
that reads a file can be used.  If we're using a stdio buffered read,
and might need later write ops on the socket, the stdio must be in
writable mode or the underlying socket goes non-writable. */

if (!cctx->tls_ctx)
  fp = fdopen(cctx->sock, lf.do_shutdown ? "rb" : "wb");

sigalrm_seen = FALSE;
ALARM(timeout);
yield =
#ifndef DISABLE_TLS
  cctx->tls_ctx ? cat_file_tls(cctx->tls_ctx, NULL, eol) :
#endif
		  cat_file(fp, NULL, eol);
ALARM_CLR(0);

if (sigalrm_seen)
  { *errmsg = US "socket read timed out"; goto out; }

*result = yield ? string_from_gstring(yield) : US"";
ret = OK;
if (!lf.cache) *do_cache = 0;

out:

(void) close(cctx->sock);
cctx->sock = -1;
return ret;
}



/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

static void
readsock_close(void * handle)
{
client_conn_ctx * cctx = handle;
if (cctx->sock < 0) return;
#ifndef DISABLE_TLS
if (cctx->tls_ctx) tls_close(cctx->tls_ctx, TRUE);
#endif
close(cctx->sock);
cctx->sock = -1;
}



static lookup_info readsock_lookup_info = {
  .name = US"readsock",			/* lookup name */
  .type = lookup_querystyle,
  .open = readsock_open,		/* open function */
  .check = NULL,
  .find = readsock_find,		/* find function */
  .close = readsock_close,
  .tidy = NULL,
  .quote = NULL,			/* no quoting function */
  .version_report = NULL
};


#ifdef DYNLOOKUP
#define readsock_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &readsock_lookup_info };
lookup_module_info readsock_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/readsock.c */
