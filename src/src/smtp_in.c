/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for handling an incoming SMTP call. */


#include "exim.h"


/* Initialize for TCP wrappers if so configured. It appears that the macro
HAVE_IPV6 is used in some versions of the tcpd.h header, so we unset it before
including that header, and restore its value afterwards. */

#ifdef USE_TCP_WRAPPERS

  #if HAVE_IPV6
  #define EXIM_HAVE_IPV6
  #endif
  #undef HAVE_IPV6
  #include <tcpd.h>
  #undef HAVE_IPV6
  #ifdef EXIM_HAVE_IPV6
  #define HAVE_IPV6 TRUE
  #endif

int allow_severity = LOG_INFO;
int deny_severity  = LOG_NOTICE;
uschar *tcp_wrappers_name;
#endif


/* Size of buffer for reading SMTP commands. We used to use 512, as defined
by RFC 821. However, RFC 1869 specifies that this must be increased for SMTP
commands that accept arguments, and this in particular applies to AUTH, where
the data can be quite long.  More recently this value was 2048 in Exim; 
however, RFC 4954 (circa 2007) recommends 12288 bytes to handle AUTH.  Clients
such as Thunderbird will send an AUTH with an initial-response for GSSAPI. 
The maximum size of a Kerberos ticket under Windows 2003 is 12000 bytes, and 
we need room to handle large base64-encoded AUTHs for GSSAPI.
*/

#define smtp_cmd_buffer_size  16384

/* Size of buffer for reading SMTP incoming packets */

#define in_buffer_size  8192

/* Structure for SMTP command list */

typedef struct {
  const char *name;
  int len;
  short int cmd;
  short int has_arg;
  short int is_mail_cmd;
} smtp_cmd_list;

/* Codes for identifying commands. We order them so that those that come first
are those for which synchronization is always required. Checking this can help
block some spam.  */

enum {
  /* These commands are required to be synchronized, i.e. to be the last in a
  block of commands when pipelining. */

  HELO_CMD, EHLO_CMD, DATA_CMD, /* These are listed in the pipelining */
  VRFY_CMD, EXPN_CMD, NOOP_CMD, /* RFC as requiring synchronization */
  ETRN_CMD,                     /* This by analogy with TURN from the RFC */
  STARTTLS_CMD,                 /* Required by the STARTTLS RFC */
  TLS_AUTH_CMD,			/* auto-command at start of SSL */

  /* This is a dummy to identify the non-sync commands when pipelining */

  NON_SYNC_CMD_PIPELINING,

  /* These commands need not be synchronized when pipelining */

  MAIL_CMD, RCPT_CMD, RSET_CMD,

  /* This is a dummy to identify the non-sync commands when not pipelining */

  NON_SYNC_CMD_NON_PIPELINING,

  /* I have been unable to find a statement about the use of pipelining
  with AUTH, so to be on the safe side it is here, though I kind of feel
  it should be up there with the synchronized commands. */

  AUTH_CMD,

  /* I'm not sure about these, but I don't think they matter. */

  QUIT_CMD, HELP_CMD,

#ifdef EXPERIMENTAL_PROXY
  PROXY_FAIL_IGNORE_CMD,
#endif

  /* These are specials that don't correspond to actual commands */

  EOF_CMD, OTHER_CMD, BADARG_CMD, BADCHAR_CMD, BADSYN_CMD,
  TOO_MANY_NONMAIL_CMD };


/* This is a convenience macro for adding the identity of an SMTP command
to the circular buffer that holds a list of the last n received. */

#define HAD(n) \
    smtp_connection_had[smtp_ch_index++] = n; \
    if (smtp_ch_index >= SMTP_HBUFF_SIZE) smtp_ch_index = 0


/*************************************************
*                Local static variables          *
*************************************************/

static auth_instance *authenticated_by;
static BOOL auth_advertised;
#ifdef SUPPORT_TLS
static BOOL tls_advertised;
#endif
static BOOL dsn_advertised;
static BOOL esmtp;
static BOOL helo_required = FALSE;
static BOOL helo_verify = FALSE;
static BOOL helo_seen;
static BOOL helo_accept_junk;
static BOOL count_nonmail;
static BOOL pipelining_advertised;
static BOOL rcpt_smtp_response_same;
static BOOL rcpt_in_progress;
static int  nonmail_command_count;
static BOOL smtp_exit_function_called = 0;
#ifdef EXPERIMENTAL_INTERNATIONAL
static BOOL smtputf8_advertised;
#endif
static int  synprot_error_count;
static int  unknown_command_count;
static int  sync_cmd_limit;
static int  smtp_write_error = 0;

static uschar *rcpt_smtp_response;
static uschar *smtp_data_buffer;
static uschar *smtp_cmd_data;

/* We need to know the position of RSET, HELO, EHLO, AUTH, and STARTTLS. Their
final fields of all except AUTH are forced TRUE at the start of a new message
setup, to allow one of each between messages that is not counted as a nonmail
command. (In fact, only one of HELO/EHLO is not counted.) Also, we have to
allow a new EHLO after starting up TLS.

AUTH is "falsely" labelled as a mail command initially, so that it doesn't get
counted. However, the flag is changed when AUTH is received, so that multiple
failing AUTHs will eventually hit the limit. After a successful AUTH, another
AUTH is already forbidden. After a TLS session is started, AUTH's flag is again
forced TRUE, to allow for the re-authentication that can happen at that point.

QUIT is also "falsely" labelled as a mail command so that it doesn't up the
count of non-mail commands and possibly provoke an error.

tls_auth is a pseudo-command, never expected in input.  It is activated
on TLS startup and looks for a tls authenticator. */

static smtp_cmd_list cmd_list[] = {
  /* name         len                     cmd     has_arg is_mail_cmd */

  { "rset",       sizeof("rset")-1,       RSET_CMD, FALSE, FALSE },  /* First */
  { "helo",       sizeof("helo")-1,       HELO_CMD, TRUE,  FALSE },
  { "ehlo",       sizeof("ehlo")-1,       EHLO_CMD, TRUE,  FALSE },
  { "auth",       sizeof("auth")-1,       AUTH_CMD, TRUE,  TRUE  },
  #ifdef SUPPORT_TLS
  { "starttls",   sizeof("starttls")-1,   STARTTLS_CMD, FALSE, FALSE },
  { "tls_auth",   0,                      TLS_AUTH_CMD, FALSE, TRUE },
  #endif

/* If you change anything above here, also fix the definitions below. */

  { "mail from:", sizeof("mail from:")-1, MAIL_CMD, TRUE,  TRUE  },
  { "rcpt to:",   sizeof("rcpt to:")-1,   RCPT_CMD, TRUE,  TRUE  },
  { "data",       sizeof("data")-1,       DATA_CMD, FALSE, TRUE  },
  { "quit",       sizeof("quit")-1,       QUIT_CMD, FALSE, TRUE  },
  { "noop",       sizeof("noop")-1,       NOOP_CMD, TRUE,  FALSE },
  { "etrn",       sizeof("etrn")-1,       ETRN_CMD, TRUE,  FALSE },
  { "vrfy",       sizeof("vrfy")-1,       VRFY_CMD, TRUE,  FALSE },
  { "expn",       sizeof("expn")-1,       EXPN_CMD, TRUE,  FALSE },
  { "help",       sizeof("help")-1,       HELP_CMD, TRUE,  FALSE }
};

static smtp_cmd_list *cmd_list_end =
  cmd_list + sizeof(cmd_list)/sizeof(smtp_cmd_list);

#define CMD_LIST_RSET      0
#define CMD_LIST_HELO      1
#define CMD_LIST_EHLO      2
#define CMD_LIST_AUTH      3
#define CMD_LIST_STARTTLS  4
#define CMD_LIST_TLS_AUTH  5

/* This list of names is used for performing the smtp_no_mail logging action.
It must be kept in step with the SCH_xxx enumerations. */

static uschar *smtp_names[] =
  {
  US"NONE", US"AUTH", US"DATA", US"EHLO", US"ETRN", US"EXPN", US"HELO",
  US"HELP", US"MAIL", US"NOOP", US"QUIT", US"RCPT", US"RSET", US"STARTTLS",
  US"VRFY" };

static uschar *protocols_local[] = {
  US"local-smtp",        /* HELO */
  US"local-smtps",       /* The rare case EHLO->STARTTLS->HELO */
  US"local-esmtp",       /* EHLO */
  US"local-esmtps",      /* EHLO->STARTTLS->EHLO */
  US"local-esmtpa",      /* EHLO->AUTH */
  US"local-esmtpsa"      /* EHLO->STARTTLS->EHLO->AUTH */
  };
static uschar *protocols[] = {
  US"smtp",              /* HELO */
  US"smtps",             /* The rare case EHLO->STARTTLS->HELO */
  US"esmtp",             /* EHLO */
  US"esmtps",            /* EHLO->STARTTLS->EHLO */
  US"esmtpa",            /* EHLO->AUTH */
  US"esmtpsa"            /* EHLO->STARTTLS->EHLO->AUTH */
  };

#define pnormal  0
#define pextend  2
#define pcrpted  1  /* added to pextend or pnormal */
#define pauthed  2  /* added to pextend */

/* Sanity check and validate optional args to MAIL FROM: envelope */
enum {
  ENV_MAIL_OPT_SIZE, ENV_MAIL_OPT_BODY, ENV_MAIL_OPT_AUTH,
#ifndef DISABLE_PRDR
  ENV_MAIL_OPT_PRDR,
#endif
  ENV_MAIL_OPT_RET, ENV_MAIL_OPT_ENVID,
#ifdef EXPERIMENTAL_INTERNATIONAL
  ENV_MAIL_OPT_UTF8,
#endif
  ENV_MAIL_OPT_NULL
  };
typedef struct {
  uschar *   name;  /* option requested during MAIL cmd */
  int       value;  /* enum type */
  BOOL need_value;  /* TRUE requires value (name=value pair format)
                       FALSE is a singleton */
  } env_mail_type_t;
static env_mail_type_t env_mail_type_list[] = {
    { US"SIZE",   ENV_MAIL_OPT_SIZE,   TRUE  },
    { US"BODY",   ENV_MAIL_OPT_BODY,   TRUE  },
    { US"AUTH",   ENV_MAIL_OPT_AUTH,   TRUE  },
#ifndef DISABLE_PRDR
    { US"PRDR",   ENV_MAIL_OPT_PRDR,   FALSE },
#endif
    { US"RET",    ENV_MAIL_OPT_RET,    TRUE },
    { US"ENVID",  ENV_MAIL_OPT_ENVID,  TRUE },
#ifdef EXPERIMENTAL_INTERNATIONAL
    { US"SMTPUTF8",ENV_MAIL_OPT_UTF8,  FALSE },		/* rfc6531 */
#endif
    { US"NULL",   ENV_MAIL_OPT_NULL,   FALSE }
  };

/* When reading SMTP from a remote host, we have to use our own versions of the
C input-reading functions, in order to be able to flush the SMTP output only
when about to read more data from the socket. This is the only way to get
optimal performance when the client is using pipelining. Flushing for every
command causes a separate packet and reply packet each time; saving all the
responses up (when pipelining) combines them into one packet and one response.

For simplicity, these functions are used for *all* SMTP input, not only when
receiving over a socket. However, after setting up a secure socket (SSL), input
is read via the OpenSSL library, and another set of functions is used instead
(see tls.c).

These functions are set in the receive_getc etc. variables and called with the
same interface as the C functions. However, since there can only ever be
one incoming SMTP call, we just use a single buffer and flags. There is no need
to implement a complicated private FILE-like structure.*/

static uschar *smtp_inbuffer;
static uschar *smtp_inptr;
static uschar *smtp_inend;
static int     smtp_had_eof;
static int     smtp_had_error;


/*************************************************
*          SMTP version of getc()                *
*************************************************/

/* This gets the next byte from the SMTP input buffer. If the buffer is empty,
it flushes the output, and refills the buffer, with a timeout. The signal
handler is set appropriately by the calling function. This function is not used
after a connection has negotated itself into an TLS/SSL state.

Arguments:  none
Returns:    the next character or EOF
*/

int
smtp_getc(void)
{
if (smtp_inptr >= smtp_inend)
  {
  int rc, save_errno;
  fflush(smtp_out);
  if (smtp_receive_timeout > 0) alarm(smtp_receive_timeout);
  rc = read(fileno(smtp_in), smtp_inbuffer, in_buffer_size);
  save_errno = errno;
  alarm(0);
  if (rc <= 0)
    {
    /* Must put the error text in fixed store, because this might be during
    header reading, where it releases unused store above the header. */
    if (rc < 0)
      {
      smtp_had_error = save_errno;
      smtp_read_error = string_copy_malloc(
        string_sprintf(" (error: %s)", strerror(save_errno)));
      }
    else smtp_had_eof = 1;
    return EOF;
    }
#ifndef DISABLE_DKIM
  dkim_exim_verify_feed(smtp_inbuffer, rc);
#endif
  smtp_inend = smtp_inbuffer + rc;
  smtp_inptr = smtp_inbuffer;
  }
return *smtp_inptr++;
}



/*************************************************
*          SMTP version of ungetc()              *
*************************************************/

/* Puts a character back in the input buffer. Only ever
called once.

Arguments:
  ch           the character

Returns:       the character
*/

int
smtp_ungetc(int ch)
{
*(--smtp_inptr) = ch;
return ch;
}




/*************************************************
*          SMTP version of feof()                *
*************************************************/

/* Tests for a previous EOF

Arguments:     none
Returns:       non-zero if the eof flag is set
*/

int
smtp_feof(void)
{
return smtp_had_eof;
}




/*************************************************
*          SMTP version of ferror()              *
*************************************************/

/* Tests for a previous read error, and returns with errno
restored to what it was when the error was detected.

Arguments:     none
Returns:       non-zero if the error flag is set
*/

int
smtp_ferror(void)
{
errno = smtp_had_error;
return smtp_had_error;
}



/*************************************************
*      Test for characters in the SMTP buffer    *
*************************************************/

/* Used at the end of a message

Arguments:     none
Returns:       TRUE/FALSE
*/

BOOL
smtp_buffered(void)
{
return smtp_inptr < smtp_inend;
}



/*************************************************
*     Write formatted string to SMTP channel     *
*************************************************/

/* This is a separate function so that we don't have to repeat everything for
TLS support or debugging. It is global so that the daemon and the
authentication functions can use it. It does not return any error indication,
because major problems such as dropped connections won't show up till an output
flush for non-TLS connections. The smtp_fflush() function is available for
checking that: for convenience, TLS output errors are remembered here so that
they are also picked up later by smtp_fflush().

Arguments:
  format      format string
  ...         optional arguments

Returns:      nothing
*/

void
smtp_printf(const char *format, ...)
{
va_list ap;

va_start(ap, format);
smtp_vprintf(format, ap);
va_end(ap);
}

/* This is split off so that verify.c:respond_printf() can, in effect, call
smtp_printf(), bearing in mind that in C a vararg function can't directly
call another vararg function, only a function which accepts a va_list. */

void
smtp_vprintf(const char *format, va_list ap)
{
BOOL yield;

yield = string_vformat(big_buffer, big_buffer_size, format, ap);

DEBUG(D_receive)
  {
  void *reset_point = store_get(0);
  uschar *msg_copy, *cr, *end;
  msg_copy = string_copy(big_buffer);
  end = msg_copy + Ustrlen(msg_copy);
  while ((cr = Ustrchr(msg_copy, '\r')) != NULL)   /* lose CRs */
  memmove(cr, cr + 1, (end--) - cr);
  debug_printf("SMTP>> %s", msg_copy);
  store_reset(reset_point);
  }

if (!yield)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "string too large in smtp_printf()");
  smtp_closedown(US"Unexpected error");
  exim_exit(EXIT_FAILURE);
  }

/* If this is the first output for a (non-batch) RCPT command, see if all RCPTs
have had the same. Note: this code is also present in smtp_respond(). It would
be tidier to have it only in one place, but when it was added, it was easier to
do it that way, so as not to have to mess with the code for the RCPT command,
which sometimes uses smtp_printf() and sometimes smtp_respond(). */

if (rcpt_in_progress)
  {
  if (rcpt_smtp_response == NULL)
    rcpt_smtp_response = string_copy(big_buffer);
  else if (rcpt_smtp_response_same &&
           Ustrcmp(rcpt_smtp_response, big_buffer) != 0)
    rcpt_smtp_response_same = FALSE;
  rcpt_in_progress = FALSE;
  }

/* Now write the string */

#ifdef SUPPORT_TLS
if (tls_in.active >= 0)
  {
  if (tls_write(TRUE, big_buffer, Ustrlen(big_buffer)) < 0)
    smtp_write_error = -1;
  }
else
#endif

if (fprintf(smtp_out, "%s", big_buffer) < 0) smtp_write_error = -1;
}



/*************************************************
*        Flush SMTP out and check for error      *
*************************************************/

/* This function isn't currently used within Exim (it detects errors when it
tries to read the next SMTP input), but is available for use in local_scan().
For non-TLS connections, it flushes the output and checks for errors. For
TLS-connections, it checks for a previously-detected TLS write error.

Arguments:  none
Returns:    0 for no error; -1 after an error
*/

int
smtp_fflush(void)
{
if (tls_in.active < 0 && fflush(smtp_out) != 0) smtp_write_error = -1;
return smtp_write_error;
}



/*************************************************
*          SMTP command read timeout             *
*************************************************/

/* Signal handler for timing out incoming SMTP commands. This attempts to
finish off tidily.

Argument: signal number (SIGALRM)
Returns:  nothing
*/

static void
command_timeout_handler(int sig)
{
sig = sig;    /* Keep picky compilers happy */
log_write(L_lost_incoming_connection,
          LOG_MAIN, "SMTP command timeout on%s connection from %s",
          (tls_in.active >= 0)? " TLS" : "",
          host_and_ident(FALSE));
if (smtp_batched_input)
  moan_smtp_batch(NULL, "421 SMTP command timeout");  /* Does not return */
smtp_notquit_exit(US"command-timeout", US"421",
  US"%s: SMTP command timeout - closing connection", smtp_active_hostname);
exim_exit(EXIT_FAILURE);
}



/*************************************************
*               SIGTERM received                 *
*************************************************/

/* Signal handler for handling SIGTERM. Again, try to finish tidily.

Argument: signal number (SIGTERM)
Returns:  nothing
*/

static void
command_sigterm_handler(int sig)
{
sig = sig;    /* Keep picky compilers happy */
log_write(0, LOG_MAIN, "%s closed after SIGTERM", smtp_get_connection_info());
if (smtp_batched_input)
  moan_smtp_batch(NULL, "421 SIGTERM received");  /* Does not return */
smtp_notquit_exit(US"signal-exit", US"421",
  US"%s: Service not available - closing connection", smtp_active_hostname);
exim_exit(EXIT_FAILURE);
}




#ifdef EXPERIMENTAL_PROXY
/*************************************************
*     Restore socket timeout to previous value   *
*************************************************/
/* If the previous value was successfully retrieved, restore
it before returning control to the non-proxy routines

Arguments: fd     - File descriptor for input
           get_ok - Successfully retrieved previous values
           tvtmp  - Time struct with previous values
           vslen  - Length of time struct
Returns:   none
*/
static void
restore_socket_timeout(int fd, int get_ok, struct timeval tvtmp, socklen_t vslen)
{
if (get_ok == 0)
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tvtmp, vslen);
}

/*************************************************
*       Check if host is required proxy host     *
*************************************************/
/* The function determines if inbound host will be a regular smtp host
or if it is configured that it must use Proxy Protocol.

Arguments: none
Returns:   bool
*/

static BOOL
check_proxy_protocol_host()
{
int rc;
/* Cannot configure local connection as a proxy inbound */
if (sender_host_address == NULL) return proxy_session;

rc = verify_check_this_host(&proxy_required_hosts, NULL, NULL,
                           sender_host_address, NULL);
if (rc == OK)
  {
  DEBUG(D_receive)
    debug_printf("Detected proxy protocol configured host\n");
  proxy_session = TRUE;
  }
return proxy_session;
}


/*************************************************
*         Setup host for proxy protocol          *
*************************************************/
/* The function configures the connection based on a header from the
inbound host to use Proxy Protocol. The specification is very exact
so exit with an error if do not find the exact required pieces. This
includes an incorrect number of spaces separating args.

Arguments: none
Returns:   int
*/

static BOOL
setup_proxy_protocol_host()
{
union {
  struct {
    uschar line[108];
  } v1;
  struct {
    uschar sig[12];
    uint8_t ver_cmd;
    uint8_t fam;
    uint16_t len;
    union {
      struct { /* TCP/UDP over IPv4, len = 12 */
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
      } ip4;
      struct { /* TCP/UDP over IPv6, len = 36 */
        uint8_t  src_addr[16];
        uint8_t  dst_addr[16];
        uint16_t src_port;
        uint16_t dst_port;
      } ip6;
      struct { /* AF_UNIX sockets, len = 216 */
        uschar   src_addr[108];
        uschar   dst_addr[108];
      } unx;
    } addr;
  } v2;
} hdr;

/* Temp variables used in PPv2 address:port parsing */
uint16_t tmpport;
char tmpip[INET_ADDRSTRLEN];
struct sockaddr_in tmpaddr;
char tmpip6[INET6_ADDRSTRLEN];
struct sockaddr_in6 tmpaddr6;

int get_ok = 0;
int size, ret, fd;
const char v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
uschar *iptype;  /* To display debug info */
struct timeval tv;
socklen_t vslen = 0;
struct timeval tvtmp;

vslen = sizeof(struct timeval);

fd = fileno(smtp_in);

/* Save current socket timeout values */
get_ok = getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tvtmp,
                    &vslen);

/* Proxy Protocol host must send header within a short time
(default 3 seconds) or it's considered invalid */
tv.tv_sec  = PROXY_NEGOTIATION_TIMEOUT_SEC;
tv.tv_usec = PROXY_NEGOTIATION_TIMEOUT_USEC;
setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
           sizeof(struct timeval));

do
  {
  /* The inbound host was declared to be a Proxy Protocol host, so
     don't do a PEEK into the data, actually slurp it up. */
  ret = recv(fd, &hdr, sizeof(hdr), 0);
  }
  while (ret == -1 && errno == EINTR);

if (ret == -1)
  {
  restore_socket_timeout(fd, get_ok, tvtmp, vslen);
  return (errno == EAGAIN) ? 0 : ERRNO_PROXYFAIL;
  }

if (ret >= 16 &&
    memcmp(&hdr.v2, v2sig, 12) == 0)
  {
  uint8_t ver, cmd;

  /* May 2014: haproxy combined the version and command into one byte to
     allow two full bytes for the length field in order to proxy SSL
     connections.  SSL Proxy is not supported in this version of Exim, but
     must still seperate values here. */
  ver = (hdr.v2.ver_cmd & 0xf0) >> 4;
  cmd = (hdr.v2.ver_cmd & 0x0f);

  if (ver != 0x02)
    {
    DEBUG(D_receive) debug_printf("Invalid Proxy Protocol version: %d\n", ver);
    goto proxyfail;
    }
  DEBUG(D_receive) debug_printf("Detected PROXYv2 header\n");
  /* The v2 header will always be 16 bytes per the spec. */
  size = 16 + hdr.v2.len;
  if (ret < size)
    {
    DEBUG(D_receive) debug_printf("Truncated or too large PROXYv2 header (%d/%d)\n",
                                  ret, size);
    goto proxyfail;
    }
  switch (cmd)
    {
    case 0x01: /* PROXY command */
      switch (hdr.v2.fam)
        {
        case 0x11:  /* TCPv4 address type */
          iptype = US"IPv4";
          tmpaddr.sin_addr.s_addr = hdr.v2.addr.ip4.src_addr;
          inet_ntop(AF_INET, &(tmpaddr.sin_addr), (char *)&tmpip, sizeof(tmpip));
          if (!string_is_ip_address(US tmpip,NULL))
            {
            DEBUG(D_receive) debug_printf("Invalid %s source IP\n", iptype);
            return ERRNO_PROXYFAIL;
            }
          proxy_host_address  = sender_host_address;
          sender_host_address = string_copy(US tmpip);
          tmpport             = ntohs(hdr.v2.addr.ip4.src_port);
          proxy_host_port     = sender_host_port;
          sender_host_port    = tmpport;
          /* Save dest ip/port */
          tmpaddr.sin_addr.s_addr = hdr.v2.addr.ip4.dst_addr;
          inet_ntop(AF_INET, &(tmpaddr.sin_addr), (char *)&tmpip, sizeof(tmpip));
          if (!string_is_ip_address(US tmpip,NULL))
            {
            DEBUG(D_receive) debug_printf("Invalid %s dest port\n", iptype);
            return ERRNO_PROXYFAIL;
            }
          proxy_target_address = string_copy(US tmpip);
          tmpport              = ntohs(hdr.v2.addr.ip4.dst_port);
          proxy_target_port    = tmpport;
          goto done;
        case 0x21:  /* TCPv6 address type */
          iptype = US"IPv6";
          memmove(tmpaddr6.sin6_addr.s6_addr, hdr.v2.addr.ip6.src_addr, 16);
          inet_ntop(AF_INET6, &(tmpaddr6.sin6_addr), (char *)&tmpip6, sizeof(tmpip6));
          if (!string_is_ip_address(US tmpip6,NULL))
            {
            DEBUG(D_receive) debug_printf("Invalid %s source IP\n", iptype);
            return ERRNO_PROXYFAIL;
            }
          proxy_host_address  = sender_host_address;
          sender_host_address = string_copy(US tmpip6);
          tmpport             = ntohs(hdr.v2.addr.ip6.src_port);
          proxy_host_port     = sender_host_port;
          sender_host_port    = tmpport;
          /* Save dest ip/port */
          memmove(tmpaddr6.sin6_addr.s6_addr, hdr.v2.addr.ip6.dst_addr, 16);
          inet_ntop(AF_INET6, &(tmpaddr6.sin6_addr), (char *)&tmpip6, sizeof(tmpip6));
          if (!string_is_ip_address(US tmpip6,NULL))
            {
            DEBUG(D_receive) debug_printf("Invalid %s dest port\n", iptype);
            return ERRNO_PROXYFAIL;
            }
          proxy_target_address = string_copy(US tmpip6);
          tmpport              = ntohs(hdr.v2.addr.ip6.dst_port);
          proxy_target_port    = tmpport;
          goto done;
        default:
          DEBUG(D_receive)
            debug_printf("Unsupported PROXYv2 connection type: 0x%02x\n",
                         hdr.v2.fam);
          goto proxyfail;
        }
      /* Unsupported protocol, keep local connection address */
      break;
    case 0x00: /* LOCAL command */
      /* Keep local connection address for LOCAL */
      break;
    default:
      DEBUG(D_receive)
        debug_printf("Unsupported PROXYv2 command: 0x%x\n", cmd);
      goto proxyfail;
    }
  }
else if (ret >= 8 &&
         memcmp(hdr.v1.line, "PROXY", 5) == 0)
  {
  uschar *p = string_copy(hdr.v1.line);
  uschar *end = memchr(p, '\r', ret - 1);
  uschar *sp;     /* Utility variables follow */
  int     tmp_port;
  char   *endc;

  if (!end || end[1] != '\n')
    {
    DEBUG(D_receive) debug_printf("Partial or invalid PROXY header\n");
    goto proxyfail;
    }
  *end = '\0'; /* Terminate the string */
  size = end + 2 - hdr.v1.line; /* Skip header + CRLF */
  DEBUG(D_receive) debug_printf("Detected PROXYv1 header\n");
  /* Step through the string looking for the required fields. Ensure
     strict adherance to required formatting, exit for any error. */
  p += 5;
  if (!isspace(*(p++)))
    {
    DEBUG(D_receive) debug_printf("Missing space after PROXY command\n");
    goto proxyfail;
    }
  if (!Ustrncmp(p, CCS"TCP4", 4))
    iptype = US"IPv4";
  else if (!Ustrncmp(p,CCS"TCP6", 4))
    iptype = US"IPv6";
  else if (!Ustrncmp(p,CCS"UNKNOWN", 7))
    {
    iptype = US"Unknown";
    goto done;
    }
  else
    {
    DEBUG(D_receive) debug_printf("Invalid TCP type\n");
    goto proxyfail;
    }

  p += Ustrlen(iptype);
  if (!isspace(*(p++)))
    {
    DEBUG(D_receive) debug_printf("Missing space after TCP4/6 command\n");
    goto proxyfail;
    }
  /* Find the end of the arg */
  if ((sp = Ustrchr(p, ' ')) == NULL)
    {
    DEBUG(D_receive)
      debug_printf("Did not find proxied src %s\n", iptype);
    goto proxyfail;
    }
  *sp = '\0';
  if(!string_is_ip_address(p,NULL))
    {
    DEBUG(D_receive)
      debug_printf("Proxied src arg is not an %s address\n", iptype);
    goto proxyfail;
    }
  proxy_host_address = sender_host_address;
  sender_host_address = p;
  p = sp + 1;
  if ((sp = Ustrchr(p, ' ')) == NULL)
    {
    DEBUG(D_receive)
      debug_printf("Did not find proxy dest %s\n", iptype);
    goto proxyfail;
    }
  *sp = '\0';
  if(!string_is_ip_address(p,NULL))
    {
    DEBUG(D_receive)
      debug_printf("Proxy dest arg is not an %s address\n", iptype);
    goto proxyfail;
    }
  proxy_target_address = p;
  p = sp + 1;
  if ((sp = Ustrchr(p, ' ')) == NULL)
    {
    DEBUG(D_receive) debug_printf("Did not find proxied src port\n");
    goto proxyfail;
    }
  *sp = '\0';
  tmp_port = strtol(CCS p,&endc,10);
  if (*endc || tmp_port == 0)
    {
    DEBUG(D_receive)
      debug_printf("Proxied src port '%s' not an integer\n", p);
    goto proxyfail;
    }
  proxy_host_port = sender_host_port;
  sender_host_port = tmp_port;
  p = sp + 1;
  if ((sp = Ustrchr(p, '\0')) == NULL)
    {
    DEBUG(D_receive) debug_printf("Did not find proxy dest port\n");
    goto proxyfail;
    }
  tmp_port = strtol(CCS p,&endc,10);
  if (*endc || tmp_port == 0)
    {
    DEBUG(D_receive)
      debug_printf("Proxy dest port '%s' not an integer\n", p);
    goto proxyfail;
    }
  proxy_target_port = tmp_port;
  /* Already checked for /r /n above. Good V1 header received. */
  goto done;
  }
else
  {
  /* Wrong protocol */
  DEBUG(D_receive) debug_printf("Invalid proxy protocol version negotiation\n");
  goto proxyfail;
  }

proxyfail:
restore_socket_timeout(fd, get_ok, tvtmp, vslen);
/* Don't flush any potential buffer contents. Any input should cause a
   synchronization failure */
return FALSE;

done:
restore_socket_timeout(fd, get_ok, tvtmp, vslen);
DEBUG(D_receive)
  debug_printf("Valid %s sender from Proxy Protocol header\n", iptype);
return proxy_session;
}
#endif

/*************************************************
*           Read one command line                *
*************************************************/

/* Strictly, SMTP commands coming over the net are supposed to end with CRLF.
There are sites that don't do this, and in any case internal SMTP probably
should check only for LF. Consequently, we check here for LF only. The line
ends up with [CR]LF removed from its end. If we get an overlong line, treat as
an unknown command. The command is read into the global smtp_cmd_buffer so that
it is available via $smtp_command.

The character reading routine sets up a timeout for each block actually read
from the input (which may contain more than one command). We set up a special
signal handler that closes down the session on a timeout. Control does not
return when it runs.

Arguments:
  check_sync   if TRUE, check synchronization rules if global option is TRUE

Returns:       a code identifying the command (enumerated above)
*/

static int
smtp_read_command(BOOL check_sync)
{
int c;
int ptr = 0;
smtp_cmd_list *p;
BOOL hadnull = FALSE;

os_non_restarting_signal(SIGALRM, command_timeout_handler);

while ((c = (receive_getc)()) != '\n' && c != EOF)
  {
  if (ptr >= smtp_cmd_buffer_size)
    {
    os_non_restarting_signal(SIGALRM, sigalrm_handler);
    return OTHER_CMD;
    }
  if (c == 0)
    {
    hadnull = TRUE;
    c = '?';
    }
  smtp_cmd_buffer[ptr++] = c;
  }

receive_linecount++;    /* For BSMTP errors */
os_non_restarting_signal(SIGALRM, sigalrm_handler);

/* If hit end of file, return pseudo EOF command. Whether we have a
part-line already read doesn't matter, since this is an error state. */

if (c == EOF) return EOF_CMD;

/* Remove any CR and white space at the end of the line, and terminate the
string. */

while (ptr > 0 && isspace(smtp_cmd_buffer[ptr-1])) ptr--;
smtp_cmd_buffer[ptr] = 0;

DEBUG(D_receive) debug_printf("SMTP<< %s\n", smtp_cmd_buffer);

/* NULLs are not allowed in SMTP commands */

if (hadnull) return BADCHAR_CMD;

/* Scan command list and return identity, having set the data pointer
to the start of the actual data characters. Check for SMTP synchronization
if required. */

for (p = cmd_list; p < cmd_list_end; p++)
  {
  #ifdef EXPERIMENTAL_PROXY
  /* Only allow QUIT command if Proxy Protocol parsing failed */
  if (proxy_session && proxy_session_failed)
    {
    if (p->cmd != QUIT_CMD)
      continue;
    }
  #endif
  if (  p->len
     && strncmpic(smtp_cmd_buffer, US p->name, p->len) == 0
     && (  smtp_cmd_buffer[p->len-1] == ':'    /* "mail from:" or "rcpt to:" */
        || smtp_cmd_buffer[p->len] == 0
	|| smtp_cmd_buffer[p->len] == ' '
     )  )
    {
    if (smtp_inptr < smtp_inend &&                     /* Outstanding input */
        p->cmd < sync_cmd_limit &&                     /* Command should sync */
        check_sync &&                                  /* Local flag set */
        smtp_enforce_sync &&                           /* Global flag set */
        sender_host_address != NULL &&                 /* Not local input */
        !sender_host_notsocket)                        /* Really is a socket */
      return BADSYN_CMD;

    /* The variables $smtp_command and $smtp_command_argument point into the
    unmodified input buffer. A copy of the latter is taken for actual
    processing, so that it can be chopped up into separate parts if necessary,
    for example, when processing a MAIL command options such as SIZE that can
    follow the sender address. */

    smtp_cmd_argument = smtp_cmd_buffer + p->len;
    while (isspace(*smtp_cmd_argument)) smtp_cmd_argument++;
    Ustrcpy(smtp_data_buffer, smtp_cmd_argument);
    smtp_cmd_data = smtp_data_buffer;

    /* Count non-mail commands from those hosts that are controlled in this
    way. The default is all hosts. We don't waste effort checking the list
    until we get a non-mail command, but then cache the result to save checking
    again. If there's a DEFER while checking the host, assume it's in the list.

    Note that one instance of RSET, EHLO/HELO, and STARTTLS is allowed at the
    start of each incoming message by fiddling with the value in the table. */

    if (!p->is_mail_cmd)
      {
      if (count_nonmail == TRUE_UNSET) count_nonmail =
        verify_check_host(&smtp_accept_max_nonmail_hosts) != FAIL;
      if (count_nonmail && ++nonmail_command_count > smtp_accept_max_nonmail)
        return TOO_MANY_NONMAIL_CMD;
      }

    /* If there is data for a command that does not expect it, generate the
    error here. */

    return (p->has_arg || *smtp_cmd_data == 0)? p->cmd : BADARG_CMD;
    }
  }

#ifdef EXPERIMENTAL_PROXY
/* Only allow QUIT command if Proxy Protocol parsing failed */
if (proxy_session && proxy_session_failed)
  return PROXY_FAIL_IGNORE_CMD;
#endif

/* Enforce synchronization for unknown commands */

if (smtp_inptr < smtp_inend &&                     /* Outstanding input */
    check_sync &&                                  /* Local flag set */
    smtp_enforce_sync &&                           /* Global flag set */
    sender_host_address != NULL &&                 /* Not local input */
    !sender_host_notsocket)                        /* Really is a socket */
  return BADSYN_CMD;

return OTHER_CMD;
}



/*************************************************
*          Recheck synchronization               *
*************************************************/

/* Synchronization checks can never be perfect because a packet may be on its
way but not arrived when the check is done. Such checks can in any case only be
done when TLS is not in use. Normally, the checks happen when commands are
read: Exim ensures that there is no more input in the input buffer. In normal
cases, the response to the command will be fast, and there is no further check.

However, for some commands an ACL is run, and that can include delays. In those
cases, it is useful to do another check on the input just before sending the
response. This also applies at the start of a connection. This function does
that check by means of the select() function, as long as the facility is not
disabled or inappropriate. A failure of select() is ignored.

When there is unwanted input, we read it so that it appears in the log of the
error.

Arguments: none
Returns:   TRUE if all is well; FALSE if there is input pending
*/

static BOOL
check_sync(void)
{
int fd, rc;
fd_set fds;
struct timeval tzero;

if (!smtp_enforce_sync || sender_host_address == NULL ||
    sender_host_notsocket || tls_in.active >= 0)
  return TRUE;

fd = fileno(smtp_in);
FD_ZERO(&fds);
FD_SET(fd, &fds);
tzero.tv_sec = 0;
tzero.tv_usec = 0;
rc = select(fd + 1, (SELECT_ARG2_TYPE *)&fds, NULL, NULL, &tzero);

if (rc <= 0) return TRUE;     /* Not ready to read */
rc = smtp_getc();
if (rc < 0) return TRUE;      /* End of file or error */

smtp_ungetc(rc);
rc = smtp_inend - smtp_inptr;
if (rc > 150) rc = 150;
smtp_inptr[rc] = 0;
return FALSE;
}



/*************************************************
*          Forced closedown of call              *
*************************************************/

/* This function is called from log.c when Exim is dying because of a serious
disaster, and also from some other places. If an incoming non-batched SMTP
channel is open, it swallows the rest of the incoming message if in the DATA
phase, sends the reply string, and gives an error to all subsequent commands
except QUIT. The existence of an SMTP call is detected by the non-NULLness of
smtp_in.

Arguments:
  message   SMTP reply string to send, excluding the code

Returns:    nothing
*/

void
smtp_closedown(uschar *message)
{
if (smtp_in == NULL || smtp_batched_input) return;
receive_swallow_smtp();
smtp_printf("421 %s\r\n", message);

for (;;)
  {
  switch(smtp_read_command(FALSE))
    {
    case EOF_CMD:
    return;

    case QUIT_CMD:
    smtp_printf("221 %s closing connection\r\n", smtp_active_hostname);
    mac_smtp_fflush();
    return;

    case RSET_CMD:
    smtp_printf("250 Reset OK\r\n");
    break;

    default:
    smtp_printf("421 %s\r\n", message);
    break;
    }
  }
}




/*************************************************
*        Set up connection info for logging      *
*************************************************/

/* This function is called when logging information about an SMTP connection.
It sets up appropriate source information, depending on the type of connection.
If sender_fullhost is NULL, we are at a very early stage of the connection;
just use the IP address.

Argument:    none
Returns:     a string describing the connection
*/

uschar *
smtp_get_connection_info(void)
{
uschar *hostname = (sender_fullhost == NULL)?
  sender_host_address : sender_fullhost;

if (host_checking)
  return string_sprintf("SMTP connection from %s", hostname);

if (sender_host_unknown || sender_host_notsocket)
  return string_sprintf("SMTP connection from %s", sender_ident);

if (is_inetd)
  return string_sprintf("SMTP connection from %s (via inetd)", hostname);

if ((log_extra_selector & LX_incoming_interface) != 0 &&
     interface_address != NULL)
  return string_sprintf("SMTP connection from %s I=[%s]:%d", hostname,
    interface_address, interface_port);

return string_sprintf("SMTP connection from %s", hostname);
}



#ifdef SUPPORT_TLS
/* Append TLS-related information to a log line

Arguments:
  s		String under construction: allocated string to extend, or NULL
  sizep		Pointer to current allocation size (update on return), or NULL
  ptrp		Pointer to index for new entries in string (update on return), or NULL

Returns:	Allocated string or NULL
*/
static uschar *
s_tlslog(uschar * s, int * sizep, int * ptrp)
{
  int size = sizep ? *sizep : 0;
  int ptr = ptrp ? *ptrp : 0;

  if ((log_extra_selector & LX_tls_cipher) != 0 && tls_in.cipher != NULL)
    s = string_append(s, &size, &ptr, 2, US" X=", tls_in.cipher);
  if ((log_extra_selector & LX_tls_certificate_verified) != 0 &&
       tls_in.cipher != NULL)
    s = string_append(s, &size, &ptr, 2, US" CV=",
      tls_in.certificate_verified? "yes":"no");
  if ((log_extra_selector & LX_tls_peerdn) != 0 && tls_in.peerdn != NULL)
    s = string_append(s, &size, &ptr, 3, US" DN=\"",
      string_printing(tls_in.peerdn), US"\"");
  if ((log_extra_selector & LX_tls_sni) != 0 && tls_in.sni != NULL)
    s = string_append(s, &size, &ptr, 3, US" SNI=\"",
      string_printing(tls_in.sni), US"\"");

  if (s)
    {
    s[ptr] = '\0';
    if (sizep) *sizep = size;
    if (ptrp) *ptrp = ptr;
    }
  return s;
}
#endif

/*************************************************
*      Log lack of MAIL if so configured         *
*************************************************/

/* This function is called when an SMTP session ends. If the log selector
smtp_no_mail is set, write a log line giving some details of what has happened
in the SMTP session.

Arguments:   none
Returns:     nothing
*/

void
smtp_log_no_mail(void)
{
int size, ptr, i;
uschar *s, *sep;

if (smtp_mailcmd_count > 0 || (log_extra_selector & LX_smtp_no_mail) == 0)
  return;

s = NULL;
size = ptr = 0;

if (sender_host_authenticated != NULL)
  {
  s = string_append(s, &size, &ptr, 2, US" A=", sender_host_authenticated);
  if (authenticated_id != NULL)
    s = string_append(s, &size, &ptr, 2, US":", authenticated_id);
  }

#ifdef SUPPORT_TLS
s = s_tlslog(s, &size, &ptr);
#endif

sep = (smtp_connection_had[SMTP_HBUFF_SIZE-1] != SCH_NONE)?
  US" C=..." : US" C=";
for (i = smtp_ch_index; i < SMTP_HBUFF_SIZE; i++)
  {
  if (smtp_connection_had[i] != SCH_NONE)
    {
    s = string_append(s, &size, &ptr, 2, sep,
      smtp_names[smtp_connection_had[i]]);
    sep = US",";
    }
  }

for (i = 0; i < smtp_ch_index; i++)
  {
  s = string_append(s, &size, &ptr, 2, sep, smtp_names[smtp_connection_had[i]]);
  sep = US",";
  }

if (s != NULL) s[ptr] = 0; else s = US"";
log_write(0, LOG_MAIN, "no MAIL in SMTP connection from %s D=%s%s",
  host_and_ident(FALSE),
  readconf_printtime( (int) ((long)time(NULL) - (long)smtp_connection_start)),
  s);
}



/*************************************************
*   Check HELO line and set sender_helo_name     *
*************************************************/

/* Check the format of a HELO line. The data for HELO/EHLO is supposed to be
the domain name of the sending host, or an ip literal in square brackets. The
arrgument is placed in sender_helo_name, which is in malloc store, because it
must persist over multiple incoming messages. If helo_accept_junk is set, this
host is permitted to send any old junk (needed for some broken hosts).
Otherwise, helo_allow_chars can be used for rogue characters in general
(typically people want to let in underscores).

Argument:
  s       the data portion of the line (already past any white space)

Returns:  TRUE or FALSE
*/

static BOOL
check_helo(uschar *s)
{
uschar *start = s;
uschar *end = s + Ustrlen(s);
BOOL yield = helo_accept_junk;

/* Discard any previous helo name */

if (sender_helo_name != NULL)
  {
  store_free(sender_helo_name);
  sender_helo_name = NULL;
  }

/* Skip tests if junk is permitted. */

if (!yield)
  {
  /* Allow the new standard form for IPv6 address literals, namely,
  [IPv6:....], and because someone is bound to use it, allow an equivalent
  IPv4 form. Allow plain addresses as well. */

  if (*s == '[')
    {
    if (end[-1] == ']')
      {
      end[-1] = 0;
      if (strncmpic(s, US"[IPv6:", 6) == 0)
        yield = (string_is_ip_address(s+6, NULL) == 6);
      else if (strncmpic(s, US"[IPv4:", 6) == 0)
        yield = (string_is_ip_address(s+6, NULL) == 4);
      else
        yield = (string_is_ip_address(s+1, NULL) != 0);
      end[-1] = ']';
      }
    }

  /* Non-literals must be alpha, dot, hyphen, plus any non-valid chars
  that have been configured (usually underscore - sigh). */

  else if (*s != 0)
    {
    yield = TRUE;
    while (*s != 0)
      {
      if (!isalnum(*s) && *s != '.' && *s != '-' &&
          Ustrchr(helo_allow_chars, *s) == NULL)
        {
        yield = FALSE;
        break;
        }
      s++;
      }
    }
  }

/* Save argument if OK */

if (yield) sender_helo_name = string_copy_malloc(start);
return yield;
}





/*************************************************
*         Extract SMTP command option            *
*************************************************/

/* This function picks the next option setting off the end of smtp_cmd_data. It
is called for MAIL FROM and RCPT TO commands, to pick off the optional ESMTP
things that can appear there.

Arguments:
   name           point this at the name
   value          point this at the data string

Returns:          TRUE if found an option
*/

static BOOL
extract_option(uschar **name, uschar **value)
{
uschar *n;
uschar *v = smtp_cmd_data + Ustrlen(smtp_cmd_data) - 1;
while (isspace(*v)) v--;
v[1] = 0;
while (v > smtp_cmd_data && *v != '=' && !isspace(*v)) v--;

n = v;
if (*v == '=')
{
  while(isalpha(n[-1])) n--;
  /* RFC says SP, but TAB seen in wild and other major MTAs accept it */
  if (!isspace(n[-1])) return FALSE;
  n[-1] = 0;
}
else
{
  n++;
  if (v == smtp_cmd_data) return FALSE;
}
*v++ = 0;
*name = n;
*value = v;
return TRUE;
}





/*************************************************
*         Reset for new message                  *
*************************************************/

/* This function is called whenever the SMTP session is reset from
within either of the setup functions.

Argument:   the stacking pool storage reset point
Returns:    nothing
*/

static void
smtp_reset(void *reset_point)
{
store_reset(reset_point);
recipients_list = NULL;
rcpt_count = rcpt_defer_count = rcpt_fail_count =
  raw_recipients_count = recipients_count = recipients_list_max = 0;
cancel_cutthrough_connection("smtp reset");
message_linecount = 0;
message_size = -1;
acl_added_headers = NULL;
acl_removed_headers = NULL;
queue_only_policy = FALSE;
rcpt_smtp_response = NULL;
rcpt_smtp_response_same = TRUE;
rcpt_in_progress = FALSE;
deliver_freeze = FALSE;                              /* Can be set by ACL */
freeze_tell = freeze_tell_config;                    /* Can be set by ACL */
fake_response = OK;                                  /* Can be set by ACL */
#ifdef WITH_CONTENT_SCAN
no_mbox_unspool = FALSE;                             /* Can be set by ACL */
#endif
submission_mode = FALSE;                             /* Can be set by ACL */
suppress_local_fixups = suppress_local_fixups_default; /* Can be set by ACL */
active_local_from_check = local_from_check;          /* Can be set by ACL */
active_local_sender_retain = local_sender_retain;    /* Can be set by ACL */
sender_address = NULL;
submission_name = NULL;                              /* Can be set by ACL */
raw_sender = NULL;                  /* After SMTP rewrite, before qualifying */
sender_address_unrewritten = NULL;  /* Set only after verify rewrite */
sender_verified_list = NULL;        /* No senders verified */
memset(sender_address_cache, 0, sizeof(sender_address_cache));
memset(sender_domain_cache, 0, sizeof(sender_domain_cache));

#ifndef DISABLE_PRDR
prdr_requested = FALSE;
#endif

/* Reset the DSN flags */
dsn_ret = 0;
dsn_envid = NULL;

authenticated_sender = NULL;
#ifdef EXPERIMENTAL_BRIGHTMAIL
bmi_run = 0;
bmi_verdicts = NULL;
#endif
#ifndef DISABLE_DKIM
dkim_signers = NULL;
dkim_disable_verify = FALSE;
dkim_collect_input = FALSE;
#endif
#ifdef EXPERIMENTAL_SPF
spf_header_comment = NULL;
spf_received = NULL;
spf_result = NULL;
spf_smtp_comment = NULL;
#endif
#ifdef EXPERIMENTAL_INTERNATIONAL
message_smtputf8 = FALSE;
#endif
body_linecount = body_zerocount = 0;

sender_rate = sender_rate_limit = sender_rate_period = NULL;
ratelimiters_mail = NULL;           /* Updated by ratelimit ACL condition */
                   /* Note that ratelimiters_conn persists across resets. */

/* Reset message ACL variables */

acl_var_m = NULL;

/* The message body variables use malloc store. They may be set if this is
not the first message in an SMTP session and the previous message caused them
to be referenced in an ACL. */

if (message_body != NULL)
  {
  store_free(message_body);
  message_body = NULL;
  }

if (message_body_end != NULL)
  {
  store_free(message_body_end);
  message_body_end = NULL;
  }

/* Warning log messages are also saved in malloc store. They are saved to avoid
repetition in the same message, but it seems right to repeat them for different
messages. */

while (acl_warn_logged != NULL)
  {
  string_item *this = acl_warn_logged;
  acl_warn_logged = acl_warn_logged->next;
  store_free(this);
  }
}





/*************************************************
*  Initialize for incoming batched SMTP message  *
*************************************************/

/* This function is called from smtp_setup_msg() in the case when
smtp_batched_input is true. This happens when -bS is used to pass a whole batch
of messages in one file with SMTP commands between them. All errors must be
reported by sending a message, and only MAIL FROM, RCPT TO, and DATA are
relevant. After an error on a sender, or an invalid recipient, the remainder
of the message is skipped. The value of received_protocol is already set.

Argument: none
Returns:  > 0 message successfully started (reached DATA)
          = 0 QUIT read or end of file reached
          < 0 should not occur
*/

static int
smtp_setup_batch_msg(void)
{
int done = 0;
void *reset_point = store_get(0);

/* Save the line count at the start of each transaction - single commands
like HELO and RSET count as whole transactions. */

bsmtp_transaction_linecount = receive_linecount;

if ((receive_feof)()) return 0;   /* Treat EOF as QUIT */

smtp_reset(reset_point);                /* Reset for start of message */

/* Deal with SMTP commands. This loop is exited by setting done to a POSITIVE
value. The values are 2 larger than the required yield of the function. */

while (done <= 0)
  {
  uschar *errmess;
  uschar *recipient = NULL;
  int start, end, sender_domain, recipient_domain;

  switch(smtp_read_command(FALSE))
    {
    /* The HELO/EHLO commands set sender_address_helo if they have
    valid data; otherwise they are ignored, except that they do
    a reset of the state. */

    case HELO_CMD:
    case EHLO_CMD:

    check_helo(smtp_cmd_data);
    /* Fall through */

    case RSET_CMD:
    smtp_reset(reset_point);
    bsmtp_transaction_linecount = receive_linecount;
    break;


    /* The MAIL FROM command requires an address as an operand. All we
    do here is to parse it for syntactic correctness. The form "<>" is
    a special case which converts into an empty string. The start/end
    pointers in the original are not used further for this address, as
    it is the canonical extracted address which is all that is kept. */

    case MAIL_CMD:
    smtp_mailcmd_count++;              /* Count for no-mail log */
    if (sender_address != NULL)
      /* The function moan_smtp_batch() does not return. */
      moan_smtp_batch(smtp_cmd_buffer, "503 Sender already given");

    if (smtp_cmd_data[0] == 0)
      /* The function moan_smtp_batch() does not return. */
      moan_smtp_batch(smtp_cmd_buffer, "501 MAIL FROM must have an address operand");

    /* Reset to start of message */

    smtp_reset(reset_point);

    /* Apply SMTP rewrite */

    raw_sender = ((rewrite_existflags & rewrite_smtp) != 0)?
      rewrite_one(smtp_cmd_data, rewrite_smtp|rewrite_smtp_sender, NULL, FALSE,
        US"", global_rewrite_rules) : smtp_cmd_data;

    /* Extract the address; the TRUE flag allows <> as valid */

    raw_sender =
      parse_extract_address(raw_sender, &errmess, &start, &end, &sender_domain,
        TRUE);

    if (raw_sender == NULL)
      /* The function moan_smtp_batch() does not return. */
      moan_smtp_batch(smtp_cmd_buffer, "501 %s", errmess);

    sender_address = string_copy(raw_sender);

    /* Qualify unqualified sender addresses if permitted to do so. */

    if (sender_domain == 0 && sender_address[0] != 0 && sender_address[0] != '@')
      {
      if (allow_unqualified_sender)
        {
        sender_address = rewrite_address_qualify(sender_address, FALSE);
        DEBUG(D_receive) debug_printf("unqualified address %s accepted "
          "and rewritten\n", raw_sender);
        }
      /* The function moan_smtp_batch() does not return. */
      else moan_smtp_batch(smtp_cmd_buffer, "501 sender address must contain "
        "a domain");
      }
    break;


    /* The RCPT TO command requires an address as an operand. All we do
    here is to parse it for syntactic correctness. There may be any number
    of RCPT TO commands, specifying multiple senders. We build them all into
    a data structure that is in argc/argv format. The start/end values
    given by parse_extract_address are not used, as we keep only the
    extracted address. */

    case RCPT_CMD:
    if (sender_address == NULL)
      /* The function moan_smtp_batch() does not return. */
      moan_smtp_batch(smtp_cmd_buffer, "503 No sender yet given");

    if (smtp_cmd_data[0] == 0)
      /* The function moan_smtp_batch() does not return. */
      moan_smtp_batch(smtp_cmd_buffer, "501 RCPT TO must have an address operand");

    /* Check maximum number allowed */

    if (recipients_max > 0 && recipients_count + 1 > recipients_max)
      /* The function moan_smtp_batch() does not return. */
      moan_smtp_batch(smtp_cmd_buffer, "%s too many recipients",
        recipients_max_reject? "552": "452");

    /* Apply SMTP rewrite, then extract address. Don't allow "<>" as a
    recipient address */

    recipient = ((rewrite_existflags & rewrite_smtp) != 0)?
      rewrite_one(smtp_cmd_data, rewrite_smtp, NULL, FALSE, US"",
        global_rewrite_rules) : smtp_cmd_data;

    /* rfc821_domains = TRUE; << no longer needed */
    recipient = parse_extract_address(recipient, &errmess, &start, &end,
      &recipient_domain, FALSE);
    /* rfc821_domains = FALSE; << no longer needed */

    if (recipient == NULL)
      /* The function moan_smtp_batch() does not return. */
      moan_smtp_batch(smtp_cmd_buffer, "501 %s", errmess);

    /* If the recipient address is unqualified, qualify it if permitted. Then
    add it to the list of recipients. */

    if (recipient_domain == 0)
      {
      if (allow_unqualified_recipient)
        {
        DEBUG(D_receive) debug_printf("unqualified address %s accepted\n",
          recipient);
        recipient = rewrite_address_qualify(recipient, TRUE);
        }
      /* The function moan_smtp_batch() does not return. */
      else moan_smtp_batch(smtp_cmd_buffer, "501 recipient address must contain "
        "a domain");
      }
    receive_add_recipient(recipient, -1);
    break;


    /* The DATA command is legal only if it follows successful MAIL FROM
    and RCPT TO commands. This function is complete when a valid DATA
    command is encountered. */

    case DATA_CMD:
    if (sender_address == NULL || recipients_count <= 0)
      {
      /* The function moan_smtp_batch() does not return. */
      if (sender_address == NULL)
        moan_smtp_batch(smtp_cmd_buffer,
          "503 MAIL FROM:<sender> command must precede DATA");
      else
        moan_smtp_batch(smtp_cmd_buffer,
          "503 RCPT TO:<recipient> must precede DATA");
      }
    else
      {
      done = 3;                      /* DATA successfully achieved */
      message_ended = END_NOTENDED;  /* Indicate in middle of message */
      }
    break;


    /* The VRFY, EXPN, HELP, ETRN, and NOOP commands are ignored. */

    case VRFY_CMD:
    case EXPN_CMD:
    case HELP_CMD:
    case NOOP_CMD:
    case ETRN_CMD:
    bsmtp_transaction_linecount = receive_linecount;
    break;


    case EOF_CMD:
    case QUIT_CMD:
    done = 2;
    break;


    case BADARG_CMD:
    /* The function moan_smtp_batch() does not return. */
    moan_smtp_batch(smtp_cmd_buffer, "501 Unexpected argument data");
    break;


    case BADCHAR_CMD:
    /* The function moan_smtp_batch() does not return. */
    moan_smtp_batch(smtp_cmd_buffer, "501 Unexpected NULL in SMTP command");
    break;


    default:
    /* The function moan_smtp_batch() does not return. */
    moan_smtp_batch(smtp_cmd_buffer, "500 Command unrecognized");
    break;
    }
  }

return done - 2;  /* Convert yield values */
}




/*************************************************
*          Start an SMTP session                 *
*************************************************/

/* This function is called at the start of an SMTP session. Thereafter,
smtp_setup_msg() is called to initiate each separate message. This
function does host-specific testing, and outputs the banner line.

Arguments:     none
Returns:       FALSE if the session can not continue; something has
               gone wrong, or the connection to the host is blocked
*/

BOOL
smtp_start_session(void)
{
int size = 256;
int ptr, esclen;
uschar *user_msg, *log_msg;
uschar *code, *esc;
uschar *p, *s, *ss;

smtp_connection_start = time(NULL);
for (smtp_ch_index = 0; smtp_ch_index < SMTP_HBUFF_SIZE; smtp_ch_index++)
  smtp_connection_had[smtp_ch_index] = SCH_NONE;
smtp_ch_index = 0;

/* Default values for certain variables */

helo_seen = esmtp = helo_accept_junk = FALSE;
smtp_mailcmd_count = 0;
count_nonmail = TRUE_UNSET;
synprot_error_count = unknown_command_count = nonmail_command_count = 0;
smtp_delay_mail = smtp_rlm_base;
auth_advertised = FALSE;
pipelining_advertised = FALSE;
pipelining_enable = TRUE;
sync_cmd_limit = NON_SYNC_CMD_NON_PIPELINING;
smtp_exit_function_called = FALSE;    /* For avoiding loop in not-quit exit */

memset(sender_host_cache, 0, sizeof(sender_host_cache));

/* If receiving by -bs from a trusted user, or testing with -bh, we allow
authentication settings from -oMaa to remain in force. */

if (!host_checking && !sender_host_notsocket) sender_host_authenticated = NULL;
authenticated_by = NULL;

#ifdef SUPPORT_TLS
tls_in.cipher = tls_in.peerdn = NULL;
tls_in.ourcert = tls_in.peercert = NULL;
tls_in.sni = NULL;
tls_in.ocsp = OCSP_NOT_REQ;
tls_advertised = FALSE;
#endif
dsn_advertised = FALSE;
#ifdef EXPERIMENTAL_INTERNATIONAL
smtputf8_advertised = FALSE;
#endif

/* Reset ACL connection variables */

acl_var_c = NULL;

/* Allow for trailing 0 in the command and data buffers. */

smtp_cmd_buffer = (uschar *)malloc(2*smtp_cmd_buffer_size + 2);
if (smtp_cmd_buffer == NULL)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "malloc() failed for SMTP command buffer");
smtp_cmd_buffer[0] = 0;
smtp_data_buffer = smtp_cmd_buffer + smtp_cmd_buffer_size + 1;

/* For batched input, the protocol setting can be overridden from the
command line by a trusted caller. */

if (smtp_batched_input)
  {
  if (received_protocol == NULL) received_protocol = US"local-bsmtp";
  }

/* For non-batched SMTP input, the protocol setting is forced here. It will be
reset later if any of EHLO/AUTH/STARTTLS are received. */

else
  received_protocol =
    (sender_host_address ? protocols : protocols_local) [pnormal];

/* Set up the buffer for inputting using direct read() calls, and arrange to
call the local functions instead of the standard C ones. */

smtp_inbuffer = (uschar *)malloc(in_buffer_size);
if (smtp_inbuffer == NULL)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "malloc() failed for SMTP input buffer");
receive_getc = smtp_getc;
receive_ungetc = smtp_ungetc;
receive_feof = smtp_feof;
receive_ferror = smtp_ferror;
receive_smtp_buffered = smtp_buffered;
smtp_inptr = smtp_inend = smtp_inbuffer;
smtp_had_eof = smtp_had_error = 0;

/* Set up the message size limit; this may be host-specific */

thismessage_size_limit = expand_string_integer(message_size_limit, TRUE);
if (expand_string_message != NULL)
  {
  if (thismessage_size_limit == -1)
    log_write(0, LOG_MAIN|LOG_PANIC, "unable to expand message_size_limit: "
      "%s", expand_string_message);
  else
    log_write(0, LOG_MAIN|LOG_PANIC, "invalid message_size_limit: "
      "%s", expand_string_message);
  smtp_closedown(US"Temporary local problem - please try later");
  return FALSE;
  }

/* When a message is input locally via the -bs or -bS options, sender_host_
unknown is set unless -oMa was used to force an IP address, in which case it
is checked like a real remote connection. When -bs is used from inetd, this
flag is not set, causing the sending host to be checked. The code that deals
with IP source routing (if configured) is never required for -bs or -bS and
the flag sender_host_notsocket is used to suppress it.

If smtp_accept_max and smtp_accept_reserve are set, keep some connections in
reserve for certain hosts and/or networks. */

if (!sender_host_unknown)
  {
  int rc;
  BOOL reserved_host = FALSE;

  /* Look up IP options (source routing info) on the socket if this is not an
  -oMa "host", and if any are found, log them and drop the connection.

  Linux (and others now, see below) is different to everyone else, so there
  has to be some conditional compilation here. Versions of Linux before 2.1.15
  used a structure whose name was "options". Somebody finally realized that
  this name was silly, and it got changed to "ip_options". I use the
  newer name here, but there is a fudge in the script that sets up os.h
  to define a macro in older Linux systems.

  Sigh. Linux is a fast-moving target. Another generation of Linux uses
  glibc 2, which has chosen ip_opts for the structure name. This is now
  really a glibc thing rather than a Linux thing, so the condition name
  has been changed to reflect this. It is relevant also to GNU/Hurd.

  Mac OS 10.x (Darwin) is like the later glibc versions, but without the
  setting of the __GLIBC__ macro, so we can't detect it automatically. There's
  a special macro defined in the os.h file.

  Some DGUX versions on older hardware appear not to support IP options at
  all, so there is now a general macro which can be set to cut out this
  support altogether.

  How to do this properly in IPv6 is not yet known. */

  #if !HAVE_IPV6 && !defined(NO_IP_OPTIONS)

  #ifdef GLIBC_IP_OPTIONS
    #if (!defined __GLIBC__) || (__GLIBC__ < 2)
    #define OPTSTYLE 1
    #else
    #define OPTSTYLE 2
    #endif
  #elif defined DARWIN_IP_OPTIONS
    #define OPTSTYLE 2
  #else
    #define OPTSTYLE 3
  #endif

  if (!host_checking && !sender_host_notsocket)
    {
    #if OPTSTYLE == 1
    EXIM_SOCKLEN_T optlen = sizeof(struct ip_options) + MAX_IPOPTLEN;
    struct ip_options *ipopt = store_get(optlen);
    #elif OPTSTYLE == 2
    struct ip_opts ipoptblock;
    struct ip_opts *ipopt = &ipoptblock;
    EXIM_SOCKLEN_T optlen = sizeof(ipoptblock);
    #else
    struct ipoption ipoptblock;
    struct ipoption *ipopt = &ipoptblock;
    EXIM_SOCKLEN_T optlen = sizeof(ipoptblock);
    #endif

    /* Occasional genuine failures of getsockopt() have been seen - for
    example, "reset by peer". Therefore, just log and give up on this
    call, unless the error is ENOPROTOOPT. This error is given by systems
    that have the interfaces but not the mechanism - e.g. GNU/Hurd at the time
    of writing. So for that error, carry on - we just can't do an IP options
    check. */

    DEBUG(D_receive) debug_printf("checking for IP options\n");

    if (getsockopt(fileno(smtp_out), IPPROTO_IP, IP_OPTIONS, (uschar *)(ipopt),
          &optlen) < 0)
      {
      if (errno != ENOPROTOOPT)
        {
        log_write(0, LOG_MAIN, "getsockopt() failed from %s: %s",
          host_and_ident(FALSE), strerror(errno));
        smtp_printf("451 SMTP service not available\r\n");
        return FALSE;
        }
      }

    /* Deal with any IP options that are set. On the systems I have looked at,
    the value of MAX_IPOPTLEN has been 40, meaning that there should never be
    more logging data than will fit in big_buffer. Nevertheless, after somebody
    questioned this code, I've added in some paranoid checking. */

    else if (optlen > 0)
      {
      uschar *p = big_buffer;
      uschar *pend = big_buffer + big_buffer_size;
      uschar *opt, *adptr;
      int optcount;
      struct in_addr addr;

      #if OPTSTYLE == 1
      uschar *optstart = (uschar *)(ipopt->__data);
      #elif OPTSTYLE == 2
      uschar *optstart = (uschar *)(ipopt->ip_opts);
      #else
      uschar *optstart = (uschar *)(ipopt->ipopt_list);
      #endif

      DEBUG(D_receive) debug_printf("IP options exist\n");

      Ustrcpy(p, "IP options on incoming call:");
      p += Ustrlen(p);

      for (opt = optstart; opt != NULL &&
           opt < (uschar *)(ipopt) + optlen;)
        {
        switch (*opt)
          {
          case IPOPT_EOL:
          opt = NULL;
          break;

          case IPOPT_NOP:
          opt++;
          break;

          case IPOPT_SSRR:
          case IPOPT_LSRR:
          if (!string_format(p, pend-p, " %s [@%s",
               (*opt == IPOPT_SSRR)? "SSRR" : "LSRR",
               #if OPTSTYLE == 1
               inet_ntoa(*((struct in_addr *)(&(ipopt->faddr))))))
               #elif OPTSTYLE == 2
               inet_ntoa(ipopt->ip_dst)))
               #else
               inet_ntoa(ipopt->ipopt_dst)))
               #endif
            {
            opt = NULL;
            break;
            }

          p += Ustrlen(p);
          optcount = (opt[1] - 3) / sizeof(struct in_addr);
          adptr = opt + 3;
          while (optcount-- > 0)
            {
            memcpy(&addr, adptr, sizeof(addr));
            if (!string_format(p, pend - p - 1, "%s%s",
                  (optcount == 0)? ":" : "@", inet_ntoa(addr)))
              {
              opt = NULL;
              break;
              }
            p += Ustrlen(p);
            adptr += sizeof(struct in_addr);
            }
          *p++ = ']';
          opt += opt[1];
          break;

          default:
            {
            int i;
            if (pend - p < 4 + 3*opt[1]) { opt = NULL; break; }
            Ustrcat(p, "[ ");
            p += 2;
            for (i = 0; i < opt[1]; i++)
              {
              sprintf(CS p, "%2.2x ", opt[i]);
              p += 3;
              }
            *p++ = ']';
            }
          opt += opt[1];
          break;
          }
        }

      *p = 0;
      log_write(0, LOG_MAIN, "%s", big_buffer);

      /* Refuse any call with IP options. This is what tcpwrappers 7.5 does. */

      log_write(0, LOG_MAIN|LOG_REJECT,
        "connection from %s refused (IP options)", host_and_ident(FALSE));

      smtp_printf("554 SMTP service not available\r\n");
      return FALSE;
      }

    /* Length of options = 0 => there are no options */

    else DEBUG(D_receive) debug_printf("no IP options found\n");
    }
  #endif  /* HAVE_IPV6 && !defined(NO_IP_OPTIONS) */

  /* Set keep-alive in socket options. The option is on by default. This
  setting is an attempt to get rid of some hanging connections that stick in
  read() when the remote end (usually a dialup) goes away. */

  if (smtp_accept_keepalive && !sender_host_notsocket)
    ip_keepalive(fileno(smtp_out), sender_host_address, FALSE);

  /* If the current host matches host_lookup, set the name by doing a
  reverse lookup. On failure, sender_host_name will be NULL and
  host_lookup_failed will be TRUE. This may or may not be serious - optional
  checks later. */

  if (verify_check_host(&host_lookup) == OK)
    {
    (void)host_name_lookup();
    host_build_sender_fullhost();
    }

  /* Delay this until we have the full name, if it is looked up. */

  set_process_info("handling incoming connection from %s",
    host_and_ident(FALSE));

  /* Expand smtp_receive_timeout, if needed */

  if (smtp_receive_timeout_s)
    {
    uschar * exp;
    if (  !(exp = expand_string(smtp_receive_timeout_s))
       || !(*exp)
       || (smtp_receive_timeout = readconf_readtime(exp, 0, FALSE)) < 0
       )
      log_write(0, LOG_MAIN|LOG_PANIC,
	"bad value for smtp_receive_timeout: '%s'", exp ? exp : US"");
    }

  /* Start up TLS if tls_on_connect is set. This is for supporting the legacy
  smtps port for use with older style SSL MTAs. */

  #ifdef SUPPORT_TLS
  if (tls_in.on_connect && tls_server_start(tls_require_ciphers) != OK)
    return FALSE;
  #endif

  /* Test for explicit connection rejection */

  if (verify_check_host(&host_reject_connection) == OK)
    {
    log_write(L_connection_reject, LOG_MAIN|LOG_REJECT, "refused connection "
      "from %s (host_reject_connection)", host_and_ident(FALSE));
    smtp_printf("554 SMTP service not available\r\n");
    return FALSE;
    }

  /* Test with TCP Wrappers if so configured. There is a problem in that
  hosts_ctl() returns 0 (deny) under a number of system failure circumstances,
  such as disks dying. In these cases, it is desirable to reject with a 4xx
  error instead of a 5xx error. There isn't a "right" way to detect such
  problems. The following kludge is used: errno is zeroed before calling
  hosts_ctl(). If the result is "reject", a 5xx error is given only if the
  value of errno is 0 or ENOENT (which happens if /etc/hosts.{allow,deny} does
  not exist). */

  #ifdef USE_TCP_WRAPPERS
  errno = 0;
  tcp_wrappers_name = expand_string(tcp_wrappers_daemon_name);
  if (tcp_wrappers_name == NULL)
    {
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Expansion of \"%s\" "
      "(tcp_wrappers_name) failed: %s", string_printing(tcp_wrappers_name),
        expand_string_message);
    }
  if (!hosts_ctl(tcp_wrappers_name,
         (sender_host_name == NULL)? STRING_UNKNOWN : CS sender_host_name,
         (sender_host_address == NULL)? STRING_UNKNOWN : CS sender_host_address,
         (sender_ident == NULL)? STRING_UNKNOWN : CS sender_ident))
    {
    if (errno == 0 || errno == ENOENT)
      {
      HDEBUG(D_receive) debug_printf("tcp wrappers rejection\n");
      log_write(L_connection_reject,
                LOG_MAIN|LOG_REJECT, "refused connection from %s "
                "(tcp wrappers)", host_and_ident(FALSE));
      smtp_printf("554 SMTP service not available\r\n");
      }
    else
      {
      int save_errno = errno;
      HDEBUG(D_receive) debug_printf("tcp wrappers rejected with unexpected "
        "errno value %d\n", save_errno);
      log_write(L_connection_reject,
                LOG_MAIN|LOG_REJECT, "temporarily refused connection from %s "
                "(tcp wrappers errno=%d)", host_and_ident(FALSE), save_errno);
      smtp_printf("451 Temporary local problem - please try later\r\n");
      }
    return FALSE;
    }
  #endif

  /* Check for reserved slots. The value of smtp_accept_count has already been
  incremented to include this process. */

  if (smtp_accept_max > 0 &&
      smtp_accept_count > smtp_accept_max - smtp_accept_reserve)
    {
    if ((rc = verify_check_host(&smtp_reserve_hosts)) != OK)
      {
      log_write(L_connection_reject,
        LOG_MAIN, "temporarily refused connection from %s: not in "
        "reserve list: connected=%d max=%d reserve=%d%s",
        host_and_ident(FALSE), smtp_accept_count - 1, smtp_accept_max,
        smtp_accept_reserve, (rc == DEFER)? " (lookup deferred)" : "");
      smtp_printf("421 %s: Too many concurrent SMTP connections; "
        "please try again later\r\n", smtp_active_hostname);
      return FALSE;
      }
    reserved_host = TRUE;
    }

  /* If a load level above which only messages from reserved hosts are
  accepted is set, check the load. For incoming calls via the daemon, the
  check is done in the superior process if there are no reserved hosts, to
  save a fork. In all cases, the load average will already be available
  in a global variable at this point. */

  if (smtp_load_reserve >= 0 &&
       load_average > smtp_load_reserve &&
       !reserved_host &&
       verify_check_host(&smtp_reserve_hosts) != OK)
    {
    log_write(L_connection_reject,
      LOG_MAIN, "temporarily refused connection from %s: not in "
      "reserve list and load average = %.2f", host_and_ident(FALSE),
      (double)load_average/1000.0);
    smtp_printf("421 %s: Too much load; please try again later\r\n",
      smtp_active_hostname);
    return FALSE;
    }

  /* Determine whether unqualified senders or recipients are permitted
  for this host. Unfortunately, we have to do this every time, in order to
  set the flags so that they can be inspected when considering qualifying
  addresses in the headers. For a site that permits no qualification, this
  won't take long, however. */

  allow_unqualified_sender =
    verify_check_host(&sender_unqualified_hosts) == OK;

  allow_unqualified_recipient =
    verify_check_host(&recipient_unqualified_hosts) == OK;

  /* Determine whether HELO/EHLO is required for this host. The requirement
  can be hard or soft. */

  helo_required = verify_check_host(&helo_verify_hosts) == OK;
  if (!helo_required)
    helo_verify = verify_check_host(&helo_try_verify_hosts) == OK;

  /* Determine whether this hosts is permitted to send syntactic junk
  after a HELO or EHLO command. */

  helo_accept_junk = verify_check_host(&helo_accept_junk_hosts) == OK;
  }

/* For batch SMTP input we are now done. */

if (smtp_batched_input) return TRUE;

#ifdef EXPERIMENTAL_PROXY
/* If valid Proxy Protocol source is connecting, set up session.
 * Failure will not allow any SMTP function other than QUIT. */
proxy_session = FALSE;
proxy_session_failed = FALSE;
if (check_proxy_protocol_host())
  {
  if (setup_proxy_protocol_host() == FALSE)
    {
    proxy_session_failed = TRUE;
    DEBUG(D_receive)
      debug_printf("Failure to extract proxied host, only QUIT allowed\n");
    }
  else
    {
    sender_host_name = NULL;
    (void)host_name_lookup();
    host_build_sender_fullhost();
    }
  }
#endif

/* Run the ACL if it exists */

user_msg = NULL;
if (acl_smtp_connect != NULL)
  {
  int rc;
  rc = acl_check(ACL_WHERE_CONNECT, NULL, acl_smtp_connect, &user_msg,
    &log_msg);
  if (rc != OK)
    {
    (void)smtp_handle_acl_fail(ACL_WHERE_CONNECT, rc, user_msg, log_msg);
    return FALSE;
    }
  }

/* Output the initial message for a two-way SMTP connection. It may contain
newlines, which then cause a multi-line response to be given. */

code = US"220";   /* Default status code */
esc = US"";       /* Default extended status code */
esclen = 0;       /* Length of esc */

if (user_msg == NULL)
  {
  s = expand_string(smtp_banner);
  if (s == NULL)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Expansion of \"%s\" (smtp_banner) "
      "failed: %s", smtp_banner, expand_string_message);
  }
else
  {
  int codelen = 3;
  s = user_msg;
  smtp_message_code(&code, &codelen, &s, NULL);
  if (codelen > 4)
    {
    esc = code + 4;
    esclen = codelen - 4;
    }
  }

/* Remove any terminating newlines; might as well remove trailing space too */

p = s + Ustrlen(s);
while (p > s && isspace(p[-1])) p--;
*p = 0;

/* It seems that CC:Mail is braindead, and assumes that the greeting message
is all contained in a single IP packet. The original code wrote out the
greeting using several calls to fprint/fputc, and on busy servers this could
cause it to be split over more than one packet - which caused CC:Mail to fall
over when it got the second part of the greeting after sending its first
command. Sigh. To try to avoid this, build the complete greeting message
first, and output it in one fell swoop. This gives a better chance of it
ending up as a single packet. */

ss = store_get(size);
ptr = 0;

p = s;
do       /* At least once, in case we have an empty string */
  {
  int len;
  uschar *linebreak = Ustrchr(p, '\n');
  ss = string_cat(ss, &size, &ptr, code, 3);
  if (linebreak == NULL)
    {
    len = Ustrlen(p);
    ss = string_cat(ss, &size, &ptr, US" ", 1);
    }
  else
    {
    len = linebreak - p;
    ss = string_cat(ss, &size, &ptr, US"-", 1);
    }
  ss = string_cat(ss, &size, &ptr, esc, esclen);
  ss = string_cat(ss, &size, &ptr, p, len);
  ss = string_cat(ss, &size, &ptr, US"\r\n", 2);
  p += len;
  if (linebreak != NULL) p++;
  }
while (*p != 0);

ss[ptr] = 0;  /* string_cat leaves room for this */

/* Before we write the banner, check that there is no input pending, unless
this synchronisation check is disabled. */

if (!check_sync())
  {
  log_write(0, LOG_MAIN|LOG_REJECT, "SMTP protocol "
    "synchronization error (input sent without waiting for greeting): "
    "rejected connection from %s input=\"%s\"", host_and_ident(TRUE),
    string_printing(smtp_inptr));
  smtp_printf("554 SMTP synchronization error\r\n");
  return FALSE;
  }

/* Now output the banner */

smtp_printf("%s", ss);
return TRUE;
}





/*************************************************
*     Handle SMTP syntax and protocol errors     *
*************************************************/

/* Write to the log for SMTP syntax errors in incoming commands, if configured
to do so. Then transmit the error response. The return value depends on the
number of syntax and protocol errors in this SMTP session.

Arguments:
  type      error type, given as a log flag bit
  code      response code; <= 0 means don't send a response
  data      data to reflect in the response (can be NULL)
  errmess   the error message

Returns:    -1   limit of syntax/protocol errors NOT exceeded
            +1   limit of syntax/protocol errors IS exceeded

These values fit in with the values of the "done" variable in the main
processing loop in smtp_setup_msg(). */

static int
synprot_error(int type, int code, uschar *data, uschar *errmess)
{
int yield = -1;

log_write(type, LOG_MAIN, "SMTP %s error in \"%s\" %s %s",
  (type == L_smtp_syntax_error)? "syntax" : "protocol",
  string_printing(smtp_cmd_buffer), host_and_ident(TRUE), errmess);

if (++synprot_error_count > smtp_max_synprot_errors)
  {
  yield = 1;
  log_write(0, LOG_MAIN|LOG_REJECT, "SMTP call from %s dropped: too many "
    "syntax or protocol errors (last command was \"%s\")",
    host_and_ident(FALSE), string_printing(smtp_cmd_buffer));
  }

if (code > 0)
  {
  smtp_printf("%d%c%s%s%s\r\n", code, (yield == 1)? '-' : ' ',
    (data == NULL)? US"" : data, (data == NULL)? US"" : US": ", errmess);
  if (yield == 1)
    smtp_printf("%d Too many syntax or protocol errors\r\n", code);
  }

return yield;
}




/*************************************************
*          Log incomplete transactions           *
*************************************************/

/* This function is called after a transaction has been aborted by RSET, QUIT,
connection drops or other errors. It logs the envelope information received
so far in order to preserve address verification attempts.

Argument:   string to indicate what aborted the transaction
Returns:    nothing
*/

static void
incomplete_transaction_log(uschar *what)
{
if (sender_address == NULL ||                 /* No transaction in progress */
    (log_write_selector & L_smtp_incomplete_transaction) == 0  /* Not logging */
  ) return;

/* Build list of recipients for logging */

if (recipients_count > 0)
  {
  int i;
  raw_recipients = store_get(recipients_count * sizeof(uschar *));
  for (i = 0; i < recipients_count; i++)
    raw_recipients[i] = recipients_list[i].address;
  raw_recipients_count = recipients_count;
  }

log_write(L_smtp_incomplete_transaction, LOG_MAIN|LOG_SENDER|LOG_RECIPIENTS,
  "%s incomplete transaction (%s)", host_and_ident(TRUE), what);
}




/*************************************************
*    Send SMTP response, possibly multiline      *
*************************************************/

/* There are, it seems, broken clients out there that cannot handle multiline
responses. If no_multiline_responses is TRUE (it can be set from an ACL), we
output nothing for non-final calls, and only the first line for anything else.

Arguments:
  code          SMTP code, may involve extended status codes
  codelen       length of smtp code; if > 4 there's an ESC
  final         FALSE if the last line isn't the final line
  msg           message text, possibly containing newlines

Returns:        nothing
*/

void
smtp_respond(uschar* code, int codelen, BOOL final, uschar *msg)
{
int esclen = 0;
uschar *esc = US"";

if (!final && no_multiline_responses) return;

if (codelen > 4)
  {
  esc = code + 4;
  esclen = codelen - 4;
  }

/* If this is the first output for a (non-batch) RCPT command, see if all RCPTs
have had the same. Note: this code is also present in smtp_printf(). It would
be tidier to have it only in one place, but when it was added, it was easier to
do it that way, so as not to have to mess with the code for the RCPT command,
which sometimes uses smtp_printf() and sometimes smtp_respond(). */

if (rcpt_in_progress)
  {
  if (rcpt_smtp_response == NULL)
    rcpt_smtp_response = string_copy(msg);
  else if (rcpt_smtp_response_same &&
           Ustrcmp(rcpt_smtp_response, msg) != 0)
    rcpt_smtp_response_same = FALSE;
  rcpt_in_progress = FALSE;
  }

/* Not output the message, splitting it up into multiple lines if necessary. */

for (;;)
  {
  uschar *nl = Ustrchr(msg, '\n');
  if (nl == NULL)
    {
    smtp_printf("%.3s%c%.*s%s\r\n", code, final? ' ':'-', esclen, esc, msg);
    return;
    }
  else if (nl[1] == 0 || no_multiline_responses)
    {
    smtp_printf("%.3s%c%.*s%.*s\r\n", code, final? ' ':'-', esclen, esc,
      (int)(nl - msg), msg);
    return;
    }
  else
    {
    smtp_printf("%.3s-%.*s%.*s\r\n", code, esclen, esc, (int)(nl - msg), msg);
    msg = nl + 1;
    while (isspace(*msg)) msg++;
    }
  }
}




/*************************************************
*            Parse user SMTP message             *
*************************************************/

/* This function allows for user messages overriding the response code details
by providing a suitable response code string at the start of the message
user_msg. Check the message for starting with a response code and optionally an
extended status code. If found, check that the first digit is valid, and if so,
change the code pointer and length to use the replacement. An invalid code
causes a panic log; in this case, if the log messages is the same as the user
message, we must also adjust the value of the log message to show the code that
is actually going to be used (the original one).

This function is global because it is called from receive.c as well as within
this module.

Note that the code length returned includes the terminating whitespace
character, which is always included in the regex match.

Arguments:
  code          SMTP code, may involve extended status codes
  codelen       length of smtp code; if > 4 there's an ESC
  msg           message text
  log_msg       optional log message, to be adjusted with the new SMTP code

Returns:        nothing
*/

void
smtp_message_code(uschar **code, int *codelen, uschar **msg, uschar **log_msg)
{
int n;
int ovector[3];

if (msg == NULL || *msg == NULL) return;

n = pcre_exec(regex_smtp_code, NULL, CS *msg, Ustrlen(*msg), 0,
  PCRE_EOPT, ovector, sizeof(ovector)/sizeof(int));
if (n < 0) return;

if ((*msg)[0] != (*code)[0])
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "configured error code starts with "
    "incorrect digit (expected %c) in \"%s\"", (*code)[0], *msg);
  if (log_msg != NULL && *log_msg == *msg)
    *log_msg = string_sprintf("%s %s", *code, *log_msg + ovector[1]);
  }
else
  {
  *code = *msg;
  *codelen = ovector[1];    /* Includes final space */
  }
*msg += ovector[1];         /* Chop the code off the message */
return;
}




/*************************************************
*           Handle an ACL failure                *
*************************************************/

/* This function is called when acl_check() fails. As well as calls from within
this module, it is called from receive.c for an ACL after DATA. It sorts out
logging the incident, and sets up the error response. A message containing
newlines is turned into a multiline SMTP response, but for logging, only the
first line is used.

There's a table of default permanent failure response codes to use in
globals.c, along with the table of names. VFRY is special. Despite RFC1123 it
defaults disabled in Exim. However, discussion in connection with RFC 821bis
(aka RFC 2821) has concluded that the response should be 252 in the disabled
state, because there are broken clients that try VRFY before RCPT. A 5xx
response should be given only when the address is positively known to be
undeliverable. Sigh. Also, for ETRN, 458 is given on refusal, and for AUTH,
503.

From Exim 4.63, it is possible to override the response code details by
providing a suitable response code string at the start of the message provided
in user_msg. The code's first digit is checked for validity.

Arguments:
  where      where the ACL was called from
  rc         the failure code
  user_msg   a message that can be included in an SMTP response
  log_msg    a message for logging

Returns:     0 in most cases
             2 if the failure code was FAIL_DROP, in which case the
               SMTP connection should be dropped (this value fits with the
               "done" variable in smtp_setup_msg() below)
*/

int
smtp_handle_acl_fail(int where, int rc, uschar *user_msg, uschar *log_msg)
{
BOOL drop = rc == FAIL_DROP;
int codelen = 3;
uschar *smtp_code;
uschar *lognl;
uschar *sender_info = US"";
uschar *what =
#ifdef WITH_CONTENT_SCAN
  (where == ACL_WHERE_MIME)? US"during MIME ACL checks" :
#endif
  (where == ACL_WHERE_PREDATA)? US"DATA" :
  (where == ACL_WHERE_DATA)? US"after DATA" :
#ifndef DISABLE_PRDR
  (where == ACL_WHERE_PRDR)? US"after DATA PRDR" :
#endif
  (smtp_cmd_data == NULL)?
    string_sprintf("%s in \"connect\" ACL", acl_wherenames[where]) :
    string_sprintf("%s %s", acl_wherenames[where], smtp_cmd_data);

if (drop) rc = FAIL;

/* Set the default SMTP code, and allow a user message to change it. */

smtp_code = (rc != FAIL)? US"451" : acl_wherecodes[where];
smtp_message_code(&smtp_code, &codelen, &user_msg, &log_msg);

/* We used to have sender_address here; however, there was a bug that was not
updating sender_address after a rewrite during a verify. When this bug was
fixed, sender_address at this point became the rewritten address. I'm not sure
this is what should be logged, so I've changed to logging the unrewritten
address to retain backward compatibility. */

#ifndef WITH_CONTENT_SCAN
if (where == ACL_WHERE_RCPT || where == ACL_WHERE_DATA)
#else
if (where == ACL_WHERE_RCPT || where == ACL_WHERE_DATA || where == ACL_WHERE_MIME)
#endif
  {
  sender_info = string_sprintf("F=<%s>%s%s%s%s ",
    sender_address_unrewritten ? sender_address_unrewritten : sender_address,
    sender_host_authenticated ? US" A="                                    : US"",
    sender_host_authenticated ? sender_host_authenticated                  : US"",
    sender_host_authenticated && authenticated_id ? US":"                  : US"",
    sender_host_authenticated && authenticated_id ? authenticated_id       : US""
    );
  }

/* If there's been a sender verification failure with a specific message, and
we have not sent a response about it yet, do so now, as a preliminary line for
failures, but not defers. However, always log it for defer, and log it for fail
unless the sender_verify_fail log selector has been turned off. */

if (sender_verified_failed != NULL &&
    !testflag(sender_verified_failed, af_sverify_told))
  {
  BOOL save_rcpt_in_progress = rcpt_in_progress;
  rcpt_in_progress = FALSE;  /* So as not to treat these as the error */

  setflag(sender_verified_failed, af_sverify_told);

  if (rc != FAIL || (log_extra_selector & LX_sender_verify_fail) != 0)
    log_write(0, LOG_MAIN|LOG_REJECT, "%s sender verify %s for <%s>%s",
      host_and_ident(TRUE),
      ((sender_verified_failed->special_action & 255) == DEFER)? "defer":"fail",
      sender_verified_failed->address,
      (sender_verified_failed->message == NULL)? US"" :
      string_sprintf(": %s", sender_verified_failed->message));

  if (rc == FAIL && sender_verified_failed->user_message != NULL)
    smtp_respond(smtp_code, codelen, FALSE, string_sprintf(
        testflag(sender_verified_failed, af_verify_pmfail)?
          "Postmaster verification failed while checking <%s>\n%s\n"
          "Several RFCs state that you are required to have a postmaster\n"
          "mailbox for each mail domain. This host does not accept mail\n"
          "from domains whose servers reject the postmaster address."
          :
        testflag(sender_verified_failed, af_verify_nsfail)?
          "Callback setup failed while verifying <%s>\n%s\n"
          "The initial connection, or a HELO or MAIL FROM:<> command was\n"
          "rejected. Refusing MAIL FROM:<> does not help fight spam, disregards\n"
          "RFC requirements, and stops you from receiving standard bounce\n"
          "messages. This host does not accept mail from domains whose servers\n"
          "refuse bounces."
          :
          "Verification failed for <%s>\n%s",
        sender_verified_failed->address,
        sender_verified_failed->user_message));

  rcpt_in_progress = save_rcpt_in_progress;
  }

/* Sort out text for logging */

log_msg = (log_msg == NULL)? US"" : string_sprintf(": %s", log_msg);
lognl = Ustrchr(log_msg, '\n');
if (lognl != NULL) *lognl = 0;

/* Send permanent failure response to the command, but the code used isn't
always a 5xx one - see comments at the start of this function. If the original
rc was FAIL_DROP we drop the connection and yield 2. */

if (rc == FAIL) smtp_respond(smtp_code, codelen, TRUE, (user_msg == NULL)?
  US"Administrative prohibition" : user_msg);

/* Send temporary failure response to the command. Don't give any details,
unless acl_temp_details is set. This is TRUE for a callout defer, a "defer"
verb, and for a header verify when smtp_return_error_details is set.

This conditional logic is all somewhat of a mess because of the odd
interactions between temp_details and return_error_details. One day it should
be re-implemented in a tidier fashion. */

else
  {
  if (acl_temp_details && user_msg != NULL)
    {
    if (smtp_return_error_details &&
        sender_verified_failed != NULL &&
        sender_verified_failed->message != NULL)
      {
      smtp_respond(smtp_code, codelen, FALSE, sender_verified_failed->message);
      }
    smtp_respond(smtp_code, codelen, TRUE, user_msg);
    }
  else
    smtp_respond(smtp_code, codelen, TRUE,
      US"Temporary local problem - please try later");
  }

/* Log the incident to the logs that are specified by log_reject_target
(default main, reject). This can be empty to suppress logging of rejections. If
the connection is not forcibly to be dropped, return 0. Otherwise, log why it
is closing if required and return 2.  */

if (log_reject_target != 0)
  {
#ifdef SUPPORT_TLS
  uschar * s = s_tlslog(NULL, NULL, NULL);
  if (!s) s = US"";
#else
  uschar * s = US"";
#endif
  log_write(0, log_reject_target, "%s%s %s%srejected %s%s",
    host_and_ident(TRUE), s,
    sender_info, (rc == FAIL)? US"" : US"temporarily ", what, log_msg);
  }

if (!drop) return 0;

log_write(L_smtp_connection, LOG_MAIN, "%s closed by DROP in ACL",
  smtp_get_connection_info());

/* Run the not-quit ACL, but without any custom messages. This should not be a
problem, because we get here only if some other ACL has issued "drop", and
in that case, *its* custom messages will have been used above. */

smtp_notquit_exit(US"acl-drop", NULL, NULL);
return 2;
}




/*************************************************
*     Handle SMTP exit when QUIT is not given    *
*************************************************/

/* This function provides a logging/statistics hook for when an SMTP connection
is dropped on the floor or the other end goes away. It's a global function
because it's called from receive.c as well as this module. As well as running
the NOTQUIT ACL, if there is one, this function also outputs a final SMTP
response, either with a custom message from the ACL, or using a default. There
is one case, however, when no message is output - after "drop". In that case,
the ACL that obeyed "drop" has already supplied the custom message, and NULL is
passed to this function.

In case things go wrong while processing this function, causing an error that
may re-enter this funtion, there is a recursion check.

Arguments:
  reason          What $smtp_notquit_reason will be set to in the ACL;
                    if NULL, the ACL is not run
  code            The error code to return as part of the response
  defaultrespond  The default message if there's no user_msg

Returns:          Nothing
*/

void
smtp_notquit_exit(uschar *reason, uschar *code, uschar *defaultrespond, ...)
{
int rc;
uschar *user_msg = NULL;
uschar *log_msg = NULL;

/* Check for recursive acll */

if (smtp_exit_function_called)
  {
  log_write(0, LOG_PANIC, "smtp_notquit_exit() called more than once (%s)",
    reason);
  return;
  }
smtp_exit_function_called = TRUE;

/* Call the not-QUIT ACL, if there is one, unless no reason is given. */

if (acl_smtp_notquit != NULL && reason != NULL)
  {
  smtp_notquit_reason = reason;
  rc = acl_check(ACL_WHERE_NOTQUIT, NULL, acl_smtp_notquit, &user_msg,
    &log_msg);
  if (rc == ERROR)
    log_write(0, LOG_MAIN|LOG_PANIC, "ACL for not-QUIT returned ERROR: %s",
      log_msg);
  }

/* Write an SMTP response if we are expected to give one. As the default
responses are all internal, they should always fit in the buffer, but code a
warning, just in case. Note that string_vformat() still leaves a complete
string, even if it is incomplete. */

if (code != NULL && defaultrespond != NULL)
  {
  if (user_msg == NULL)
    {
    uschar buffer[128];
    va_list ap;
    va_start(ap, defaultrespond);
    if (!string_vformat(buffer, sizeof(buffer), CS defaultrespond, ap))
      log_write(0, LOG_MAIN|LOG_PANIC, "string too large in smtp_notquit_exit()");
    smtp_printf("%s %s\r\n", code, buffer);
    va_end(ap);
    }
  else
    smtp_respond(code, 3, TRUE, user_msg);
  mac_smtp_fflush();
  }
}




/*************************************************
*             Verify HELO argument               *
*************************************************/

/* This function is called if helo_verify_hosts or helo_try_verify_hosts is
matched. It is also called from ACL processing if verify = helo is used and
verification was not previously tried (i.e. helo_try_verify_hosts was not
matched). The result of its processing is to set helo_verified and
helo_verify_failed. These variables should both be FALSE for this function to
be called.

Note that EHLO/HELO is legitimately allowed to quote an address literal. Allow
for IPv6 ::ffff: literals.

Argument:   none
Returns:    TRUE if testing was completed;
            FALSE on a temporary failure
*/

BOOL
smtp_verify_helo(void)
{
BOOL yield = TRUE;

HDEBUG(D_receive) debug_printf("verifying EHLO/HELO argument \"%s\"\n",
  sender_helo_name);

if (sender_helo_name == NULL)
  {
  HDEBUG(D_receive) debug_printf("no EHLO/HELO command was issued\n");
  }

/* Deal with the case of -bs without an IP address */

else if (sender_host_address == NULL)
  {
  HDEBUG(D_receive) debug_printf("no client IP address: assume success\n");
  helo_verified = TRUE;
  }

/* Deal with the more common case when there is a sending IP address */

else if (sender_helo_name[0] == '[')
  {
  helo_verified = Ustrncmp(sender_helo_name+1, sender_host_address,
    Ustrlen(sender_host_address)) == 0;

  #if HAVE_IPV6
  if (!helo_verified)
    {
    if (strncmpic(sender_host_address, US"::ffff:", 7) == 0)
      helo_verified = Ustrncmp(sender_helo_name + 1,
        sender_host_address + 7, Ustrlen(sender_host_address) - 7) == 0;
    }
  #endif

  HDEBUG(D_receive)
    { if (helo_verified) debug_printf("matched host address\n"); }
  }

/* Do a reverse lookup if one hasn't already given a positive or negative
response. If that fails, or the name doesn't match, try checking with a forward
lookup. */

else
  {
  if (sender_host_name == NULL && !host_lookup_failed)
    yield = host_name_lookup() != DEFER;

  /* If a host name is known, check it and all its aliases. */

  if (sender_host_name)
    if ((helo_verified = strcmpic(sender_host_name, sender_helo_name) == 0))
      {
      sender_helo_dnssec = sender_host_dnssec;
      HDEBUG(D_receive) debug_printf("matched host name\n");
      }
    else
      {
      uschar **aliases = sender_host_aliases;
      while (*aliases)
        if ((helo_verified = strcmpic(*aliases++, sender_helo_name) == 0))
	  {
	  sender_helo_dnssec = sender_host_dnssec;
	  break;
	  }

      HDEBUG(D_receive) if (helo_verified)
          debug_printf("matched alias %s\n", *(--aliases));
      }

  /* Final attempt: try a forward lookup of the helo name */

  if (!helo_verified)
    {
    int rc;
    host_item h;
    dnssec_domains d;
    host_item *hh;

    h.name = sender_helo_name;
    h.address = NULL;
    h.mx = MX_NONE;
    h.next = NULL;
    d.request = US"*";
    d.require = US"";

    HDEBUG(D_receive) debug_printf("getting IP address for %s\n",
      sender_helo_name);
    rc = host_find_bydns(&h, NULL, HOST_FIND_BY_A,
			  NULL, NULL, NULL, &d, NULL, NULL);
    if (rc == HOST_FOUND || rc == HOST_FOUND_LOCAL)
      for (hh = &h; hh; hh = hh->next)
        if (Ustrcmp(hh->address, sender_host_address) == 0)
          {
          helo_verified = TRUE;
	  if (h.dnssec == DS_YES) sender_helo_dnssec = TRUE;
          HDEBUG(D_receive)
	    {
            debug_printf("IP address for %s matches calling address\n"
	      "Forward DNS security status: %sverified\n",
              sender_helo_name, sender_helo_dnssec ? "" : "un");
	    }
          break;
          }
    }
  }

if (!helo_verified) helo_verify_failed = TRUE;  /* We've tried ... */
return yield;
}




/*************************************************
*        Send user response message              *
*************************************************/

/* This function is passed a default response code and a user message. It calls
smtp_message_code() to check and possibly modify the response code, and then
calls smtp_respond() to transmit the response. I put this into a function
just to avoid a lot of repetition.

Arguments:
  code         the response code
  user_msg     the user message

Returns:       nothing
*/

static void
smtp_user_msg(uschar *code, uschar *user_msg)
{
int len = 3;
smtp_message_code(&code, &len, &user_msg, NULL);
smtp_respond(code, len, TRUE, user_msg);
}



static int
smtp_in_auth(auth_instance *au, uschar ** s, uschar ** ss)
{
const uschar *set_id = NULL;
int rc, i;

/* Run the checking code, passing the remainder of the command line as
data. Initials the $auth<n> variables as empty. Initialize $0 empty and set
it as the only set numerical variable. The authenticator may set $auth<n>
and also set other numeric variables. The $auth<n> variables are preferred
nowadays; the numerical variables remain for backwards compatibility.

Afterwards, have a go at expanding the set_id string, even if
authentication failed - for bad passwords it can be useful to log the
userid. On success, require set_id to expand and exist, and put it in
authenticated_id. Save this in permanent store, as the working store gets
reset at HELO, RSET, etc. */

for (i = 0; i < AUTH_VARS; i++) auth_vars[i] = NULL;
expand_nmax = 0;
expand_nlength[0] = 0;   /* $0 contains nothing */

rc = (au->info->servercode)(au, smtp_cmd_data);
if (au->set_id) set_id = expand_string(au->set_id);
expand_nmax = -1;        /* Reset numeric variables */
for (i = 0; i < AUTH_VARS; i++) auth_vars[i] = NULL;   /* Reset $auth<n> */

/* The value of authenticated_id is stored in the spool file and printed in
log lines. It must not contain binary zeros or newline characters. In
normal use, it never will, but when playing around or testing, this error
can (did) happen. To guard against this, ensure that the id contains only
printing characters. */

if (set_id) set_id = string_printing(set_id);

/* For the non-OK cases, set up additional logging data if set_id
is not empty. */

if (rc != OK)
  set_id = set_id && *set_id
    ? string_sprintf(" (set_id=%s)", set_id) : US"";

/* Switch on the result */

switch(rc)
  {
  case OK:
  if (!au->set_id || set_id)    /* Complete success */
    {
    if (set_id) authenticated_id = string_copy_malloc(set_id);
    sender_host_authenticated = au->name;
    authentication_failed = FALSE;
    authenticated_fail_id = NULL;   /* Impossible to already be set? */

    received_protocol =
      (sender_host_address ? protocols : protocols_local)
	[pextend + pauthed + (tls_in.active >= 0 ? pcrpted:0)];
    *s = *ss = US"235 Authentication succeeded";
    authenticated_by = au;
    break;
    }

  /* Authentication succeeded, but we failed to expand the set_id string.
  Treat this as a temporary error. */

  auth_defer_msg = expand_string_message;
  /* Fall through */

  case DEFER:
  if (set_id) authenticated_fail_id = string_copy_malloc(set_id);
  *s = string_sprintf("435 Unable to authenticate at present%s",
    auth_defer_user_msg);
  *ss = string_sprintf("435 Unable to authenticate at present%s: %s",
    set_id, auth_defer_msg);
  break;

  case BAD64:
  *s = *ss = US"501 Invalid base64 data";
  break;

  case CANCELLED:
  *s = *ss = US"501 Authentication cancelled";
  break;

  case UNEXPECTED:
  *s = *ss = US"553 Initial data not expected";
  break;

  case FAIL:
  if (set_id) authenticated_fail_id = string_copy_malloc(set_id);
  *s = US"535 Incorrect authentication data";
  *ss = string_sprintf("535 Incorrect authentication data%s", set_id);
  break;

  default:
  if (set_id) authenticated_fail_id = string_copy_malloc(set_id);
  *s = US"435 Internal error";
  *ss = string_sprintf("435 Internal error%s: return %d from authentication "
    "check", set_id, rc);
  break;
  }

return rc;
}



/*************************************************
*       Initialize for SMTP incoming message     *
*************************************************/

/* This function conducts the initial dialogue at the start of an incoming SMTP
message, and builds a list of recipients. However, if the incoming message
is part of a batch (-bS option) a separate function is called since it would
be messy having tests splattered about all over this function. This function
therefore handles the case where interaction is occurring. The input and output
files are set up in smtp_in and smtp_out.

The global recipients_list is set to point to a vector of recipient_item
blocks, whose number is given by recipients_count. This is extended by the
receive_add_recipient() function. The global variable sender_address is set to
the sender's address. The yield is +1 if a message has been successfully
started, 0 if a QUIT command was encountered or the connection was refused from
the particular host, or -1 if the connection was lost.

Argument: none

Returns:  > 0 message successfully started (reached DATA)
          = 0 QUIT read or end of file reached or call refused
          < 0 lost connection
*/

int
smtp_setup_msg(void)
{
int done = 0;
BOOL toomany = FALSE;
BOOL discarded = FALSE;
BOOL last_was_rej_mail = FALSE;
BOOL last_was_rcpt = FALSE;
void *reset_point = store_get(0);

DEBUG(D_receive) debug_printf("smtp_setup_msg entered\n");

/* Reset for start of new message. We allow one RSET not to be counted as a
nonmail command, for those MTAs that insist on sending it between every
message. Ditto for EHLO/HELO and for STARTTLS, to allow for going in and out of
TLS between messages (an Exim client may do this if it has messages queued up
for the host). Note: we do NOT reset AUTH at this point. */

smtp_reset(reset_point);
message_ended = END_NOTSTARTED;

cmd_list[CMD_LIST_RSET].is_mail_cmd = TRUE;
cmd_list[CMD_LIST_HELO].is_mail_cmd = TRUE;
cmd_list[CMD_LIST_EHLO].is_mail_cmd = TRUE;
#ifdef SUPPORT_TLS
cmd_list[CMD_LIST_STARTTLS].is_mail_cmd = TRUE;
cmd_list[CMD_LIST_TLS_AUTH].is_mail_cmd = TRUE;
#endif

/* Set the local signal handler for SIGTERM - it tries to end off tidily */

os_non_restarting_signal(SIGTERM, command_sigterm_handler);

/* Batched SMTP is handled in a different function. */

if (smtp_batched_input) return smtp_setup_batch_msg();

/* Deal with SMTP commands. This loop is exited by setting done to a POSITIVE
value. The values are 2 larger than the required yield of the function. */

while (done <= 0)
  {
  const uschar **argv;
  uschar *etrn_command;
  uschar *etrn_serialize_key;
  uschar *errmess;
  uschar *log_msg, *smtp_code;
  uschar *user_msg = NULL;
  uschar *recipient = NULL;
  uschar *hello = NULL;
  uschar *s, *ss;
  BOOL was_rej_mail = FALSE;
  BOOL was_rcpt = FALSE;
  void (*oldsignal)(int);
  pid_t pid;
  int start, end, sender_domain, recipient_domain;
  int ptr, size, rc;
  int c, i;
  auth_instance *au;
  uschar *orcpt = NULL;
  int flags;

#if defined(SUPPORT_TLS) && defined(AUTH_TLS)
  /* Check once per STARTTLS or SSL-on-connect for a TLS AUTH */
  if (  tls_in.active >= 0
     && tls_in.peercert
     && tls_in.certificate_verified
     && cmd_list[CMD_LIST_TLS_AUTH].is_mail_cmd
     )
    {
    cmd_list[CMD_LIST_TLS_AUTH].is_mail_cmd = FALSE;
    if (acl_smtp_auth)
      {
      rc = acl_check(ACL_WHERE_AUTH, NULL, acl_smtp_auth, &user_msg, &log_msg);
      if (rc != OK)
        {
        done = smtp_handle_acl_fail(ACL_WHERE_AUTH, rc, user_msg, log_msg);
        continue;
        }
      }

    for (au = auths; au; au = au->next)
      if (strcmpic(US"tls", au->driver_name) == 0)
	{
	smtp_cmd_data = NULL;

	if ((c = smtp_in_auth(au, &s, &ss)) != OK)
	  log_write(0, LOG_MAIN|LOG_REJECT, "%s authenticator failed for %s: %s",
	    au->name, host_and_ident(FALSE), ss);
	else
	  DEBUG(D_auth) debug_printf("tls auth succeeded\n");

	break;
	}
    }
#endif

  switch(smtp_read_command(TRUE))
    {
    /* The AUTH command is not permitted to occur inside a transaction, and may
    occur successfully only once per connection. Actually, that isn't quite
    true. When TLS is started, all previous information about a connection must
    be discarded, so a new AUTH is permitted at that time.

    AUTH may only be used when it has been advertised. However, it seems that
    there are clients that send AUTH when it hasn't been advertised, some of
    them even doing this after HELO. And there are MTAs that accept this. Sigh.
    So there's a get-out that allows this to happen.

    AUTH is initially labelled as a "nonmail command" so that one occurrence
    doesn't get counted. We change the label here so that multiple failing
    AUTHS will eventually hit the nonmail threshold. */

    case AUTH_CMD:
    HAD(SCH_AUTH);
    authentication_failed = TRUE;
    cmd_list[CMD_LIST_AUTH].is_mail_cmd = FALSE;

    if (!auth_advertised && !allow_auth_unadvertised)
      {
      done = synprot_error(L_smtp_protocol_error, 503, NULL,
        US"AUTH command used when not advertised");
      break;
      }
    if (sender_host_authenticated)
      {
      done = synprot_error(L_smtp_protocol_error, 503, NULL,
        US"already authenticated");
      break;
      }
    if (sender_address)
      {
      done = synprot_error(L_smtp_protocol_error, 503, NULL,
        US"not permitted in mail transaction");
      break;
      }

    /* Check the ACL */

    if (acl_smtp_auth)
      {
      rc = acl_check(ACL_WHERE_AUTH, NULL, acl_smtp_auth, &user_msg, &log_msg);
      if (rc != OK)
        {
        done = smtp_handle_acl_fail(ACL_WHERE_AUTH, rc, user_msg, log_msg);
        break;
        }
      }

    /* Find the name of the requested authentication mechanism. */

    s = smtp_cmd_data;
    while ((c = *smtp_cmd_data) != 0 && !isspace(c))
      {
      if (!isalnum(c) && c != '-' && c != '_')
        {
        done = synprot_error(L_smtp_syntax_error, 501, NULL,
          US"invalid character in authentication mechanism name");
        goto COMMAND_LOOP;
        }
      smtp_cmd_data++;
      }

    /* If not at the end of the line, we must be at white space. Terminate the
    name and move the pointer on to any data that may be present. */

    if (*smtp_cmd_data != 0)
      {
      *smtp_cmd_data++ = 0;
      while (isspace(*smtp_cmd_data)) smtp_cmd_data++;
      }

    /* Search for an authentication mechanism which is configured for use
    as a server and which has been advertised (unless, sigh, allow_auth_
    unadvertised is set). */

    for (au = auths; au; au = au->next)
      if (strcmpic(s, au->public_name) == 0 && au->server &&
          (au->advertised || allow_auth_unadvertised))
	break;

    if (au)
      {
      c = smtp_in_auth(au, &s, &ss);

      smtp_printf("%s\r\n", s);
      if (c != OK)
	log_write(0, LOG_MAIN|LOG_REJECT, "%s authenticator failed for %s: %s",
	  au->name, host_and_ident(FALSE), ss);
      }
    else
      done = synprot_error(L_smtp_protocol_error, 504, NULL,
        string_sprintf("%s authentication mechanism not supported", s));

    break;  /* AUTH_CMD */

    /* The HELO/EHLO commands are permitted to appear in the middle of a
    session as well as at the beginning. They have the effect of a reset in
    addition to their other functions. Their absence at the start cannot be
    taken to be an error.

    RFC 2821 says:

      If the EHLO command is not acceptable to the SMTP server, 501, 500,
      or 502 failure replies MUST be returned as appropriate.  The SMTP
      server MUST stay in the same state after transmitting these replies
      that it was in before the EHLO was received.

    Therefore, we do not do the reset until after checking the command for
    acceptability. This change was made for Exim release 4.11. Previously
    it did the reset first. */

    case HELO_CMD:
    HAD(SCH_HELO);
    hello = US"HELO";
    esmtp = FALSE;
    goto HELO_EHLO;

    case EHLO_CMD:
    HAD(SCH_EHLO);
    hello = US"EHLO";
    esmtp = TRUE;

    HELO_EHLO:      /* Common code for HELO and EHLO */
    cmd_list[CMD_LIST_HELO].is_mail_cmd = FALSE;
    cmd_list[CMD_LIST_EHLO].is_mail_cmd = FALSE;

    /* Reject the HELO if its argument was invalid or non-existent. A
    successful check causes the argument to be saved in malloc store. */

    if (!check_helo(smtp_cmd_data))
      {
      smtp_printf("501 Syntactically invalid %s argument(s)\r\n", hello);

      log_write(0, LOG_MAIN|LOG_REJECT, "rejected %s from %s: syntactically "
        "invalid argument(s): %s", hello, host_and_ident(FALSE),
        (*smtp_cmd_argument == 0)? US"(no argument given)" :
                           string_printing(smtp_cmd_argument));

      if (++synprot_error_count > smtp_max_synprot_errors)
        {
        log_write(0, LOG_MAIN|LOG_REJECT, "SMTP call from %s dropped: too many "
          "syntax or protocol errors (last command was \"%s\")",
          host_and_ident(FALSE), string_printing(smtp_cmd_buffer));
        done = 1;
        }

      break;
      }

    /* If sender_host_unknown is true, we have got here via the -bs interface,
    not called from inetd. Otherwise, we are running an IP connection and the
    host address will be set. If the helo name is the primary name of this
    host and we haven't done a reverse lookup, force one now. If helo_required
    is set, ensure that the HELO name matches the actual host. If helo_verify
    is set, do the same check, but softly. */

    if (!sender_host_unknown)
      {
      BOOL old_helo_verified = helo_verified;
      uschar *p = smtp_cmd_data;

      while (*p != 0 && !isspace(*p)) { *p = tolower(*p); p++; }
      *p = 0;

      /* Force a reverse lookup if HELO quoted something in helo_lookup_domains
      because otherwise the log can be confusing. */

      if (sender_host_name == NULL &&
           (deliver_domain = sender_helo_name,  /* set $domain */
            match_isinlist(sender_helo_name, CUSS &helo_lookup_domains, 0,
              &domainlist_anchor, NULL, MCL_DOMAIN, TRUE, NULL)) == OK)
        (void)host_name_lookup();

      /* Rebuild the fullhost info to include the HELO name (and the real name
      if it was looked up.) */

      host_build_sender_fullhost();  /* Rebuild */
      set_process_info("handling%s incoming connection from %s",
        (tls_in.active >= 0)? " TLS" : "", host_and_ident(FALSE));

      /* Verify if configured. This doesn't give much security, but it does
      make some people happy to be able to do it. If helo_required is set,
      (host matches helo_verify_hosts) failure forces rejection. If helo_verify
      is set (host matches helo_try_verify_hosts), it does not. This is perhaps
      now obsolescent, since the verification can now be requested selectively
      at ACL time. */

      helo_verified = helo_verify_failed = sender_helo_dnssec = FALSE;
      if (helo_required || helo_verify)
        {
        BOOL tempfail = !smtp_verify_helo();
        if (!helo_verified)
          {
          if (helo_required)
            {
            smtp_printf("%d %s argument does not match calling host\r\n",
              tempfail? 451 : 550, hello);
            log_write(0, LOG_MAIN|LOG_REJECT, "%srejected \"%s %s\" from %s",
              tempfail? "temporarily " : "",
              hello, sender_helo_name, host_and_ident(FALSE));
            helo_verified = old_helo_verified;
            break;                   /* End of HELO/EHLO processing */
            }
          HDEBUG(D_all) debug_printf("%s verification failed but host is in "
            "helo_try_verify_hosts\n", hello);
          }
        }
      }

#ifdef EXPERIMENTAL_SPF
    /* set up SPF context */
    spf_init(sender_helo_name, sender_host_address);
#endif

    /* Apply an ACL check if one is defined; afterwards, recheck
    synchronization in case the client started sending in a delay. */

    if (acl_smtp_helo != NULL)
      {
      rc = acl_check(ACL_WHERE_HELO, NULL, acl_smtp_helo, &user_msg, &log_msg);
      if (rc != OK)
        {
        done = smtp_handle_acl_fail(ACL_WHERE_HELO, rc, user_msg, log_msg);
        sender_helo_name = NULL;
        host_build_sender_fullhost();  /* Rebuild */
        break;
        }
      else if (!check_sync()) goto SYNC_FAILURE;
      }

    /* Generate an OK reply. The default string includes the ident if present,
    and also the IP address if present. Reflecting back the ident is intended
    as a deterrent to mail forgers. For maximum efficiency, and also because
    some broken systems expect each response to be in a single packet, arrange
    that the entire reply is sent in one write(). */

    auth_advertised = FALSE;
    pipelining_advertised = FALSE;
#ifdef SUPPORT_TLS
    tls_advertised = FALSE;
#endif
    dsn_advertised = FALSE;
#ifdef EXPERIMENTAL_INTERNATIONAL
    smtputf8_advertised = FALSE;
#endif

    smtp_code = US"250 ";        /* Default response code plus space*/
    if (user_msg == NULL)
      {
      s = string_sprintf("%.3s %s Hello %s%s%s",
        smtp_code,
        smtp_active_hostname,
        (sender_ident == NULL)?  US"" : sender_ident,
        (sender_ident == NULL)?  US"" : US" at ",
        (sender_host_name == NULL)? sender_helo_name : sender_host_name);

      ptr = Ustrlen(s);
      size = ptr + 1;

      if (sender_host_address != NULL)
        {
        s = string_cat(s, &size, &ptr, US" [", 2);
        s = string_cat(s, &size, &ptr, sender_host_address,
          Ustrlen(sender_host_address));
        s = string_cat(s, &size, &ptr, US"]", 1);
        }
      }

    /* A user-supplied EHLO greeting may not contain more than one line. Note
    that the code returned by smtp_message_code() includes the terminating
    whitespace character. */

    else
      {
      char *ss;
      int codelen = 4;
      smtp_message_code(&smtp_code, &codelen, &user_msg, NULL);
      s = string_sprintf("%.*s%s", codelen, smtp_code, user_msg);
      if ((ss = strpbrk(CS s, "\r\n")) != NULL)
        {
        log_write(0, LOG_MAIN|LOG_PANIC, "EHLO/HELO response must not contain "
          "newlines: message truncated: %s", string_printing(s));
        *ss = 0;
        }
      ptr = Ustrlen(s);
      size = ptr + 1;
      }

    s = string_cat(s, &size, &ptr, US"\r\n", 2);

    /* If we received EHLO, we must create a multiline response which includes
    the functions supported. */

    if (esmtp)
      {
      s[3] = '-';

      /* I'm not entirely happy with this, as an MTA is supposed to check
      that it has enough room to accept a message of maximum size before
      it sends this. However, there seems little point in not sending it.
      The actual size check happens later at MAIL FROM time. By postponing it
      till then, VRFY and EXPN can be used after EHLO when space is short. */

      if (thismessage_size_limit > 0)
        {
        sprintf(CS big_buffer, "%.3s-SIZE %d\r\n", smtp_code,
          thismessage_size_limit);
        s = string_cat(s, &size, &ptr, big_buffer, Ustrlen(big_buffer));
        }
      else
        {
        s = string_cat(s, &size, &ptr, smtp_code, 3);
        s = string_cat(s, &size, &ptr, US"-SIZE\r\n", 7);
        }

      /* Exim does not do protocol conversion or data conversion. It is 8-bit
      clean; if it has an 8-bit character in its hand, it just sends it. It
      cannot therefore specify 8BITMIME and remain consistent with the RFCs.
      However, some users want this option simply in order to stop MUAs
      mangling messages that contain top-bit-set characters. It is therefore
      provided as an option. */

      if (accept_8bitmime)
        {
        s = string_cat(s, &size, &ptr, smtp_code, 3);
        s = string_cat(s, &size, &ptr, US"-8BITMIME\r\n", 11);
        }

      /* Advertise DSN support if configured to do so. */
      if (verify_check_host(&dsn_advertise_hosts) != FAIL) 
        {
        s = string_cat(s, &size, &ptr, smtp_code, 3);
        s = string_cat(s, &size, &ptr, US"-DSN\r\n", 6);
        dsn_advertised = TRUE;
        }

      /* Advertise ETRN if there's an ACL checking whether a host is
      permitted to issue it; a check is made when any host actually tries. */

      if (acl_smtp_etrn != NULL)
        {
        s = string_cat(s, &size, &ptr, smtp_code, 3);
        s = string_cat(s, &size, &ptr, US"-ETRN\r\n", 7);
        }

      /* Advertise EXPN if there's an ACL checking whether a host is
      permitted to issue it; a check is made when any host actually tries. */

      if (acl_smtp_expn != NULL)
        {
        s = string_cat(s, &size, &ptr, smtp_code, 3);
        s = string_cat(s, &size, &ptr, US"-EXPN\r\n", 7);
        }

      /* Exim is quite happy with pipelining, so let the other end know that
      it is safe to use it, unless advertising is disabled. */

      if (pipelining_enable &&
          verify_check_host(&pipelining_advertise_hosts) == OK)
        {
        s = string_cat(s, &size, &ptr, smtp_code, 3);
        s = string_cat(s, &size, &ptr, US"-PIPELINING\r\n", 13);
        sync_cmd_limit = NON_SYNC_CMD_PIPELINING;
        pipelining_advertised = TRUE;
        }


      /* If any server authentication mechanisms are configured, advertise
      them if the current host is in auth_advertise_hosts. The problem with
      advertising always is that some clients then require users to
      authenticate (and aren't configurable otherwise) even though it may not
      be necessary (e.g. if the host is in host_accept_relay).

      RFC 2222 states that SASL mechanism names contain only upper case
      letters, so output the names in upper case, though we actually recognize
      them in either case in the AUTH command. */

      if (  auths
#if defined(SUPPORT_TLS) && defined(AUTH_TLS)
	 && !sender_host_authenticated
#endif
         && verify_check_host(&auth_advertise_hosts) == OK
	 )
	{
	auth_instance *au;
	BOOL first = TRUE;
	for (au = auths; au; au = au->next)
	  if (au->server && (au->advertise_condition == NULL ||
	      expand_check_condition(au->advertise_condition, au->name,
	      US"authenticator")))
	    {
	    int saveptr;
	    if (first)
	      {
	      s = string_cat(s, &size, &ptr, smtp_code, 3);
	      s = string_cat(s, &size, &ptr, US"-AUTH", 5);
	      first = FALSE;
	      auth_advertised = TRUE;
	      }
	    saveptr = ptr;
	    s = string_cat(s, &size, &ptr, US" ", 1);
	    s = string_cat(s, &size, &ptr, au->public_name,
	      Ustrlen(au->public_name));
	    while (++saveptr < ptr) s[saveptr] = toupper(s[saveptr]);
	    au->advertised = TRUE;
	    }
	  else
	    au->advertised = FALSE;

	if (!first) s = string_cat(s, &size, &ptr, US"\r\n", 2);
	}

      /* Advertise TLS (Transport Level Security) aka SSL (Secure Socket Layer)
      if it has been included in the binary, and the host matches
      tls_advertise_hosts. We must *not* advertise if we are already in a
      secure connection. */

#ifdef SUPPORT_TLS
      if (tls_in.active < 0 &&
          verify_check_host(&tls_advertise_hosts) != FAIL)
        {
        s = string_cat(s, &size, &ptr, smtp_code, 3);
        s = string_cat(s, &size, &ptr, US"-STARTTLS\r\n", 11);
        tls_advertised = TRUE;
        }
#endif

#ifndef DISABLE_PRDR
      /* Per Recipient Data Response, draft by Eric A. Hall extending RFC */
      if (prdr_enable)
        {
        s = string_cat(s, &size, &ptr, smtp_code, 3);
        s = string_cat(s, &size, &ptr, US"-PRDR\r\n", 7);
	}
#endif

#ifdef EXPERIMENTAL_INTERNATIONAL
      if (  accept_8bitmime
         && verify_check_host(&smtputf8_advertise_hosts) != FAIL)
	{
        s = string_cat(s, &size, &ptr, smtp_code, 3);
        s = string_cat(s, &size, &ptr, US"-SMTPUTF8\r\n", 11);
        smtputf8_advertised = TRUE;
	}
#endif

      /* Finish off the multiline reply with one that is always available. */

      s = string_cat(s, &size, &ptr, smtp_code, 3);
      s = string_cat(s, &size, &ptr, US" HELP\r\n", 7);
      }

    /* Terminate the string (for debug), write it, and note that HELO/EHLO
    has been seen. */

    s[ptr] = 0;

#ifdef SUPPORT_TLS
    if (tls_in.active >= 0) (void)tls_write(TRUE, s, ptr); else
#endif

      {
      int i = fwrite(s, 1, ptr, smtp_out); i = i; /* compiler quietening */
      }
    DEBUG(D_receive)
      {
      uschar *cr;
      while ((cr = Ustrchr(s, '\r')) != NULL)   /* lose CRs */
        memmove(cr, cr + 1, (ptr--) - (cr - s));
      debug_printf("SMTP>> %s", s);
      }
    helo_seen = TRUE;

    /* Reset the protocol and the state, abandoning any previous message. */
    received_protocol =
      (sender_host_address ? protocols : protocols_local)
	[ (esmtp
	  ? pextend + (sender_host_authenticated ? pauthed : 0)
	  : pnormal)
	+ (tls_in.active >= 0 ? pcrpted : 0)
	];
    smtp_reset(reset_point);
    toomany = FALSE;
    break;   /* HELO/EHLO */


    /* The MAIL command requires an address as an operand. All we do
    here is to parse it for syntactic correctness. The form "<>" is
    a special case which converts into an empty string. The start/end
    pointers in the original are not used further for this address, as
    it is the canonical extracted address which is all that is kept. */

    case MAIL_CMD:
    HAD(SCH_MAIL);
    smtp_mailcmd_count++;              /* Count for limit and ratelimit */
    was_rej_mail = TRUE;               /* Reset if accepted */
    env_mail_type_t * mail_args;       /* Sanity check & validate args */

    if (helo_required && !helo_seen)
      {
      smtp_printf("503 HELO or EHLO required\r\n");
      log_write(0, LOG_MAIN|LOG_REJECT, "rejected MAIL from %s: no "
        "HELO/EHLO given", host_and_ident(FALSE));
      break;
      }

    if (sender_address != NULL)
      {
      done = synprot_error(L_smtp_protocol_error, 503, NULL,
        US"sender already given");
      break;
      }

    if (smtp_cmd_data[0] == 0)
      {
      done = synprot_error(L_smtp_protocol_error, 501, NULL,
        US"MAIL must have an address operand");
      break;
      }

    /* Check to see if the limit for messages per connection would be
    exceeded by accepting further messages. */

    if (smtp_accept_max_per_connection > 0 &&
        smtp_mailcmd_count > smtp_accept_max_per_connection)
      {
      smtp_printf("421 too many messages in this connection\r\n");
      log_write(0, LOG_MAIN|LOG_REJECT, "rejected MAIL command %s: too many "
        "messages in one connection", host_and_ident(TRUE));
      break;
      }

    /* Reset for start of message - even if this is going to fail, we
    obviously need to throw away any previous data. */

    smtp_reset(reset_point);
    toomany = FALSE;
    sender_data = recipient_data = NULL;

    /* Loop, checking for ESMTP additions to the MAIL FROM command. */

    if (esmtp) for(;;)
      {
      uschar *name, *value, *end;
      unsigned long int size;
      BOOL arg_error = FALSE;

      if (!extract_option(&name, &value)) break;

      for (mail_args = env_mail_type_list;
           (char *)mail_args < (char *)env_mail_type_list + sizeof(env_mail_type_list);
           mail_args++
          )
        if (strcmpic(name, mail_args->name) == 0)
          break;
      if (mail_args->need_value && strcmpic(value, US"") == 0)
        break;

      switch(mail_args->value)
        {
        /* Handle SIZE= by reading the value. We don't do the check till later,
        in order to be able to log the sender address on failure. */
        case ENV_MAIL_OPT_SIZE:
          if (((size = Ustrtoul(value, &end, 10)), *end == 0))
            {
            if ((size == ULONG_MAX && errno == ERANGE) || size > INT_MAX)
              size = INT_MAX;
            message_size = (int)size;
            }
          else
            arg_error = TRUE;
          break;

        /* If this session was initiated with EHLO and accept_8bitmime is set,
        Exim will have indicated that it supports the BODY=8BITMIME option. In
        fact, it does not support this according to the RFCs, in that it does not
        take any special action for forwarding messages containing 8-bit
        characters. That is why accept_8bitmime is not the default setting, but
        some sites want the action that is provided. We recognize both "8BITMIME"
        and "7BIT" as body types, but take no action. */
        case ENV_MAIL_OPT_BODY:
          if (accept_8bitmime) {
            if (strcmpic(value, US"8BITMIME") == 0)
              body_8bitmime = 8;
            else if (strcmpic(value, US"7BIT") == 0)
              body_8bitmime = 7;
            else
	      {
              body_8bitmime = 0;
              done = synprot_error(L_smtp_syntax_error, 501, NULL,
                US"invalid data for BODY");
              goto COMMAND_LOOP;
              }
            DEBUG(D_receive) debug_printf("8BITMIME: %d\n", body_8bitmime);
	    break;
          }
          arg_error = TRUE;
          break;

        /* Handle the two DSN options, but only if configured to do so (which
        will have caused "DSN" to be given in the EHLO response). The code itself
        is included only if configured in at build time. */

        case ENV_MAIL_OPT_RET:
          if (dsn_advertised)
	    {
            /* Check if RET has already been set */
            if (dsn_ret > 0)
	      {
              synprot_error(L_smtp_syntax_error, 501, NULL,
                US"RET can be specified once only");
              goto COMMAND_LOOP;
	      }
            dsn_ret = strcmpic(value, US"HDRS") == 0
	      ? dsn_ret_hdrs
	      : strcmpic(value, US"FULL") == 0
	      ? dsn_ret_full
	      : 0;
            DEBUG(D_receive) debug_printf("DSN_RET: %d\n", dsn_ret);
            /* Check for invalid invalid value, and exit with error */
            if (dsn_ret == 0)
	      {
              synprot_error(L_smtp_syntax_error, 501, NULL,
                US"Value for RET is invalid");
              goto COMMAND_LOOP;
	      }
	    }
          break;
        case ENV_MAIL_OPT_ENVID:
          if (dsn_advertised)
	    {
            /* Check if the dsn envid has been already set */
            if (dsn_envid != NULL)
	      {
              synprot_error(L_smtp_syntax_error, 501, NULL,
                US"ENVID can be specified once only");
              goto COMMAND_LOOP;
	      }
            dsn_envid = string_copy(value);
            DEBUG(D_receive) debug_printf("DSN_ENVID: %s\n", dsn_envid);
	    }
          break;

        /* Handle the AUTH extension. If the value given is not "<>" and either
        the ACL says "yes" or there is no ACL but the sending host is
        authenticated, we set it up as the authenticated sender. However, if the
        authenticator set a condition to be tested, we ignore AUTH on MAIL unless
        the condition is met. The value of AUTH is an xtext, which means that +,
        = and cntrl chars are coded in hex; however "<>" is unaffected by this
        coding. */
        case ENV_MAIL_OPT_AUTH:
          if (Ustrcmp(value, "<>") != 0)
            {
            int rc;
            uschar *ignore_msg;

            if (auth_xtextdecode(value, &authenticated_sender) < 0)
              {
              /* Put back terminator overrides for error message */
              value[-1] = '=';
              name[-1] = ' ';
              done = synprot_error(L_smtp_syntax_error, 501, NULL,
                US"invalid data for AUTH");
              goto COMMAND_LOOP;
              }
            if (acl_smtp_mailauth == NULL)
              {
              ignore_msg = US"client not authenticated";
              rc = (sender_host_authenticated != NULL)? OK : FAIL;
              }
            else
              {
              ignore_msg = US"rejected by ACL";
              rc = acl_check(ACL_WHERE_MAILAUTH, NULL, acl_smtp_mailauth,
                &user_msg, &log_msg);
              }
  
            switch (rc)
              {
              case OK:
		if (authenticated_by == NULL ||
		    authenticated_by->mail_auth_condition == NULL ||
		    expand_check_condition(authenticated_by->mail_auth_condition,
			authenticated_by->name, US"authenticator"))
		  break;     /* Accept the AUTH */
    
		ignore_msg = US"server_mail_auth_condition failed";
		if (authenticated_id != NULL)
		  ignore_msg = string_sprintf("%s: authenticated ID=\"%s\"",
		    ignore_msg, authenticated_id);
  
              /* Fall through */
  
              case FAIL:
		authenticated_sender = NULL;
		log_write(0, LOG_MAIN, "ignoring AUTH=%s from %s (%s)",
		  value, host_and_ident(TRUE), ignore_msg);
		break;
  
              /* Should only get DEFER or ERROR here. Put back terminator
              overrides for error message */
  
              default:
		value[-1] = '=';
		name[-1] = ' ';
		(void)smtp_handle_acl_fail(ACL_WHERE_MAILAUTH, rc, user_msg,
		  log_msg);
		goto COMMAND_LOOP;
              }
            }
            break;

#ifndef DISABLE_PRDR
        case ENV_MAIL_OPT_PRDR:
          if (prdr_enable)
            prdr_requested = TRUE;
          break;
#endif

#ifdef EXPERIMENTAL_INTERNATIONAL
        case ENV_MAIL_OPT_UTF8:
	  if (smtputf8_advertised)
	    {
	    DEBUG(D_receive) debug_printf("smtputf8 requested\n");
	    message_smtputf8 = allow_utf8_domains = TRUE;
	    received_protocol = string_sprintf("utf8%s", received_protocol);
	    }
	  break;
#endif
        /* Unknown option. Stick back the terminator characters and break
        the loop.  Do the name-terminator second as extract_option sets
	value==name when it found no equal-sign.
	An error for a malformed address will occur. */
        default:
          value[-1] = '=';
          name[-1] = ' ';
          arg_error = TRUE;
          break;
        }
      /* Break out of for loop if switch() had bad argument or
         when start of the email address is reached */
      if (arg_error) break;
      }

    /* If we have passed the threshold for rate limiting, apply the current
    delay, and update it for next time, provided this is a limited host. */

    if (smtp_mailcmd_count > smtp_rlm_threshold &&
        verify_check_host(&smtp_ratelimit_hosts) == OK)
      {
      DEBUG(D_receive) debug_printf("rate limit MAIL: delay %.3g sec\n",
        smtp_delay_mail/1000.0);
      millisleep((int)smtp_delay_mail);
      smtp_delay_mail *= smtp_rlm_factor;
      if (smtp_delay_mail > (double)smtp_rlm_limit)
        smtp_delay_mail = (double)smtp_rlm_limit;
      }

    /* Now extract the address, first applying any SMTP-time rewriting. The
    TRUE flag allows "<>" as a sender address. */

    raw_sender = rewrite_existflags & rewrite_smtp
      ? rewrite_one(smtp_cmd_data, rewrite_smtp, NULL, FALSE, US"",
		    global_rewrite_rules)
      : smtp_cmd_data;

    /* rfc821_domains = TRUE; << no longer needed */
    raw_sender =
      parse_extract_address(raw_sender, &errmess, &start, &end, &sender_domain,
        TRUE);
    /* rfc821_domains = FALSE; << no longer needed */

    if (raw_sender == NULL)
      {
      done = synprot_error(L_smtp_syntax_error, 501, smtp_cmd_data, errmess);
      break;
      }

    sender_address = raw_sender;

    /* If there is a configured size limit for mail, check that this message
    doesn't exceed it. The check is postponed to this point so that the sender
    can be logged. */

    if (thismessage_size_limit > 0 && message_size > thismessage_size_limit)
      {
      smtp_printf("552 Message size exceeds maximum permitted\r\n");
      log_write(L_size_reject,
          LOG_MAIN|LOG_REJECT, "rejected MAIL FROM:<%s> %s: "
          "message too big: size%s=%d max=%d",
          sender_address,
          host_and_ident(TRUE),
          (message_size == INT_MAX)? ">" : "",
          message_size,
          thismessage_size_limit);
      sender_address = NULL;
      break;
      }

    /* Check there is enough space on the disk unless configured not to.
    When smtp_check_spool_space is set, the check is for thismessage_size_limit
    plus the current message - i.e. we accept the message only if it won't
    reduce the space below the threshold. Add 5000 to the size to allow for
    overheads such as the Received: line and storing of recipients, etc.
    By putting the check here, even when SIZE is not given, it allow VRFY
    and EXPN etc. to be used when space is short. */

    if (!receive_check_fs(
         (smtp_check_spool_space && message_size >= 0)?
            message_size + 5000 : 0))
      {
      smtp_printf("452 Space shortage, please try later\r\n");
      sender_address = NULL;
      break;
      }

    /* If sender_address is unqualified, reject it, unless this is a locally
    generated message, or the sending host or net is permitted to send
    unqualified addresses - typically local machines behaving as MUAs -
    in which case just qualify the address. The flag is set above at the start
    of the SMTP connection. */

    if (sender_domain == 0 && sender_address[0] != 0)
      {
      if (allow_unqualified_sender)
        {
        sender_domain = Ustrlen(sender_address) + 1;
        sender_address = rewrite_address_qualify(sender_address, FALSE);
        DEBUG(D_receive) debug_printf("unqualified address %s accepted\n",
          raw_sender);
        }
      else
        {
        smtp_printf("501 %s: sender address must contain a domain\r\n",
          smtp_cmd_data);
        log_write(L_smtp_syntax_error,
          LOG_MAIN|LOG_REJECT,
          "unqualified sender rejected: <%s> %s%s",
          raw_sender,
          host_and_ident(TRUE),
          host_lookup_msg);
        sender_address = NULL;
        break;
        }
      }

    /* Apply an ACL check if one is defined, before responding. Afterwards,
    when pipelining is not advertised, do another sync check in case the ACL
    delayed and the client started sending in the meantime. */

    if (acl_smtp_mail)
      {
      rc = acl_check(ACL_WHERE_MAIL, NULL, acl_smtp_mail, &user_msg, &log_msg);
      if (rc == OK && !pipelining_advertised && !check_sync())
        goto SYNC_FAILURE;
      }
    else
      rc = OK;

    if (rc == OK || rc == DISCARD)
      {
      if (!user_msg)
        smtp_printf("%s%s%s", US"250 OK",
                  #ifndef DISABLE_PRDR
                    prdr_requested ? US", PRDR Requested" : US"",
		  #else
                    US"",
                  #endif
                    US"\r\n");
      else 
        {
      #ifndef DISABLE_PRDR
        if (prdr_requested)
           user_msg = string_sprintf("%s%s", user_msg, US", PRDR Requested");
      #endif
        smtp_user_msg(US"250", user_msg);
        }
      smtp_delay_rcpt = smtp_rlr_base;
      recipients_discarded = (rc == DISCARD);
      was_rej_mail = FALSE;
      }
    else
      {
      done = smtp_handle_acl_fail(ACL_WHERE_MAIL, rc, user_msg, log_msg);
      sender_address = NULL;
      }
    break;


    /* The RCPT command requires an address as an operand. There may be any
    number of RCPT commands, specifying multiple recipients. We build them all
    into a data structure. The start/end values given by parse_extract_address
    are not used, as we keep only the extracted address. */

    case RCPT_CMD:
    HAD(SCH_RCPT);
    rcpt_count++;
    was_rcpt = rcpt_in_progress = TRUE;

    /* There must be a sender address; if the sender was rejected and
    pipelining was advertised, we assume the client was pipelining, and do not
    count this as a protocol error. Reset was_rej_mail so that further RCPTs
    get the same treatment. */

    if (sender_address == NULL)
      {
      if (pipelining_advertised && last_was_rej_mail)
        {
        smtp_printf("503 sender not yet given\r\n");
        was_rej_mail = TRUE;
        }
      else
        {
        done = synprot_error(L_smtp_protocol_error, 503, NULL,
          US"sender not yet given");
        was_rcpt = FALSE;             /* Not a valid RCPT */
        }
      rcpt_fail_count++;
      break;
      }

    /* Check for an operand */

    if (smtp_cmd_data[0] == 0)
      {
      done = synprot_error(L_smtp_syntax_error, 501, NULL,
        US"RCPT must have an address operand");
      rcpt_fail_count++;
      break;
      }

    /* Set the DSN flags orcpt and dsn_flags from the session*/
    orcpt = NULL;
    flags = 0;

    if (esmtp) for(;;)
      {
      uschar *name, *value;

      if (!extract_option(&name, &value))
        break;

      if (dsn_advertised && strcmpic(name, US"ORCPT") == 0)
        {
        /* Check whether orcpt has been already set */
        if (orcpt)
	  {
          synprot_error(L_smtp_syntax_error, 501, NULL,
            US"ORCPT can be specified once only");
          goto COMMAND_LOOP;
          }
        orcpt = string_copy(value);
        DEBUG(D_receive) debug_printf("DSN orcpt: %s\n", orcpt);
        }

      else if (dsn_advertised && strcmpic(name, US"NOTIFY") == 0)
        {
        /* Check if the notify flags have been already set */
        if (flags > 0)
	  {
          synprot_error(L_smtp_syntax_error, 501, NULL,
              US"NOTIFY can be specified once only");
          goto COMMAND_LOOP;
          }
        if (strcmpic(value, US"NEVER") == 0)
	  flags |= rf_notify_never;
	else
          {
          uschar *p = value;
          while (*p != 0)
            {
            uschar *pp = p;
            while (*pp != 0 && *pp != ',') pp++;
	    if (*pp == ',') *pp++ = 0;
            if (strcmpic(p, US"SUCCESS") == 0)
	      {
	      DEBUG(D_receive) debug_printf("DSN: Setting notify success\n");
	      flags |= rf_notify_success;
              }
            else if (strcmpic(p, US"FAILURE") == 0)
	      {
	      DEBUG(D_receive) debug_printf("DSN: Setting notify failure\n");
	      flags |= rf_notify_failure;
              }
            else if (strcmpic(p, US"DELAY") == 0)
	      {
	      DEBUG(D_receive) debug_printf("DSN: Setting notify delay\n");
	      flags |= rf_notify_delay;
              }
            else
	      {
              /* Catch any strange values */
              synprot_error(L_smtp_syntax_error, 501, NULL,
                US"Invalid value for NOTIFY parameter");
              goto COMMAND_LOOP;
              }
            p = pp;
            }
            DEBUG(D_receive) debug_printf("DSN Flags: %x\n", flags);
          }
        }

      /* Unknown option. Stick back the terminator characters and break
      the loop. An error for a malformed address will occur. */

      else
        {
        DEBUG(D_receive) debug_printf("Invalid RCPT option: %s : %s\n", name, value);
        name[-1] = ' ';
        value[-1] = '=';
        break;
        }
      }

    /* Apply SMTP rewriting then extract the working address. Don't allow "<>"
    as a recipient address */

    recipient = ((rewrite_existflags & rewrite_smtp) != 0)?
      rewrite_one(smtp_cmd_data, rewrite_smtp, NULL, FALSE, US"",
        global_rewrite_rules) : smtp_cmd_data;

    /* rfc821_domains = TRUE; << no longer needed */
    recipient = parse_extract_address(recipient, &errmess, &start, &end,
      &recipient_domain, FALSE);
    /* rfc821_domains = FALSE; << no longer needed */

    if (recipient == NULL)
      {
      done = synprot_error(L_smtp_syntax_error, 501, smtp_cmd_data, errmess);
      rcpt_fail_count++;
      break;
      }

    /* If the recipient address is unqualified, reject it, unless this is a
    locally generated message. However, unqualified addresses are permitted
    from a configured list of hosts and nets - typically when behaving as
    MUAs rather than MTAs. Sad that SMTP is used for both types of traffic,
    really. The flag is set at the start of the SMTP connection.

    RFC 1123 talks about supporting "the reserved mailbox postmaster"; I always
    assumed this meant "reserved local part", but the revision of RFC 821 and
    friends now makes it absolutely clear that it means *mailbox*. Consequently
    we must always qualify this address, regardless. */

    if (recipient_domain == 0)
      {
      if (allow_unqualified_recipient ||
          strcmpic(recipient, US"postmaster") == 0)
        {
        DEBUG(D_receive) debug_printf("unqualified address %s accepted\n",
          recipient);
        recipient_domain = Ustrlen(recipient) + 1;
        recipient = rewrite_address_qualify(recipient, TRUE);
        }
      else
        {
        rcpt_fail_count++;
        smtp_printf("501 %s: recipient address must contain a domain\r\n",
          smtp_cmd_data);
        log_write(L_smtp_syntax_error,
          LOG_MAIN|LOG_REJECT, "unqualified recipient rejected: "
          "<%s> %s%s", recipient, host_and_ident(TRUE),
          host_lookup_msg);
        break;
        }
      }

    /* Check maximum allowed */

    if (rcpt_count > recipients_max && recipients_max > 0)
      {
      if (recipients_max_reject)
        {
        rcpt_fail_count++;
        smtp_printf("552 too many recipients\r\n");
        if (!toomany)
          log_write(0, LOG_MAIN|LOG_REJECT, "too many recipients: message "
            "rejected: sender=<%s> %s", sender_address, host_and_ident(TRUE));
        }
      else
        {
        rcpt_defer_count++;
        smtp_printf("452 too many recipients\r\n");
        if (!toomany)
          log_write(0, LOG_MAIN|LOG_REJECT, "too many recipients: excess "
            "temporarily rejected: sender=<%s> %s", sender_address,
            host_and_ident(TRUE));
        }

      toomany = TRUE;
      break;
      }

    /* If we have passed the threshold for rate limiting, apply the current
    delay, and update it for next time, provided this is a limited host. */

    if (rcpt_count > smtp_rlr_threshold &&
        verify_check_host(&smtp_ratelimit_hosts) == OK)
      {
      DEBUG(D_receive) debug_printf("rate limit RCPT: delay %.3g sec\n",
        smtp_delay_rcpt/1000.0);
      millisleep((int)smtp_delay_rcpt);
      smtp_delay_rcpt *= smtp_rlr_factor;
      if (smtp_delay_rcpt > (double)smtp_rlr_limit)
        smtp_delay_rcpt = (double)smtp_rlr_limit;
      }

    /* If the MAIL ACL discarded all the recipients, we bypass ACL checking
    for them. Otherwise, check the access control list for this recipient. As
    there may be a delay in this, re-check for a synchronization error
    afterwards, unless pipelining was advertised. */

    if (recipients_discarded) rc = DISCARD; else
      {
      rc = acl_check(ACL_WHERE_RCPT, recipient, acl_smtp_rcpt, &user_msg,
        &log_msg);
      if (rc == OK && !pipelining_advertised && !check_sync())
        goto SYNC_FAILURE;
      }

    /* The ACL was happy */

    if (rc == OK)
      {
      if (user_msg == NULL) smtp_printf("250 Accepted\r\n");
        else smtp_user_msg(US"250", user_msg);
      receive_add_recipient(recipient, -1);
 
      /* Set the dsn flags in the recipients_list */
      recipients_list[recipients_count-1].orcpt = orcpt;
      recipients_list[recipients_count-1].dsn_flags = flags;

      DEBUG(D_receive) debug_printf("DSN: orcpt: %s  flags: %d\n",
	recipients_list[recipients_count-1].orcpt,
	recipients_list[recipients_count-1].dsn_flags);
      }

    /* The recipient was discarded */

    else if (rc == DISCARD)
      {
      if (user_msg == NULL) smtp_printf("250 Accepted\r\n");
        else smtp_user_msg(US"250", user_msg);
      rcpt_fail_count++;
      discarded = TRUE;
      log_write(0, LOG_MAIN|LOG_REJECT, "%s F=<%s> RCPT %s: "
        "discarded by %s ACL%s%s", host_and_ident(TRUE),
        sender_address_unrewritten? sender_address_unrewritten : sender_address,
        smtp_cmd_argument, recipients_discarded? "MAIL" : "RCPT",
        log_msg ? US": " : US"", log_msg ? log_msg : US"");
      }

    /* Either the ACL failed the address, or it was deferred. */

    else
      {
      if (rc == FAIL) rcpt_fail_count++; else rcpt_defer_count++;
      done = smtp_handle_acl_fail(ACL_WHERE_RCPT, rc, user_msg, log_msg);
      }
    break;


    /* The DATA command is legal only if it follows successful MAIL FROM
    and RCPT TO commands. However, if pipelining is advertised, a bad DATA is
    not counted as a protocol error if it follows RCPT (which must have been
    rejected if there are no recipients.) This function is complete when a
    valid DATA command is encountered.

    Note concerning the code used: RFC 2821 says this:

     -  If there was no MAIL, or no RCPT, command, or all such commands
        were rejected, the server MAY return a "command out of sequence"
        (503) or "no valid recipients" (554) reply in response to the
        DATA command.

    The example in the pipelining RFC 2920 uses 554, but I use 503 here
    because it is the same whether pipelining is in use or not.

    If all the RCPT commands that precede DATA provoked the same error message
    (often indicating some kind of system error), it is helpful to include it
    with the DATA rejection (an idea suggested by Tony Finch). */

    case DATA_CMD:
    HAD(SCH_DATA);
    if (!discarded && recipients_count <= 0)
      {
      if (rcpt_smtp_response_same && rcpt_smtp_response != NULL)
        {
        uschar *code = US"503";
        int len = Ustrlen(rcpt_smtp_response);
        smtp_respond(code, 3, FALSE, US"All RCPT commands were rejected with "
          "this error:");
        /* Responses from smtp_printf() will have \r\n on the end */
        if (len > 2 && rcpt_smtp_response[len-2] == '\r')
          rcpt_smtp_response[len-2] = 0;
        smtp_respond(code, 3, FALSE, rcpt_smtp_response);
        }
      if (pipelining_advertised && last_was_rcpt)
        smtp_printf("503 Valid RCPT command must precede DATA\r\n");
      else
        done = synprot_error(L_smtp_protocol_error, 503, NULL,
          US"valid RCPT command must precede DATA");
      break;
      }

    if (toomany && recipients_max_reject)
      {
      sender_address = NULL;  /* This will allow a new MAIL without RSET */
      sender_address_unrewritten = NULL;
      smtp_printf("554 Too many recipients\r\n");
      break;
      }

    /* If there is an ACL, re-check the synchronization afterwards, since the
    ACL may have delayed.  To handle cutthrough delivery enforce a dummy call
    to get the DATA command sent. */

    if (acl_smtp_predata == NULL && cutthrough.fd < 0) rc = OK; else
      {
      uschar * acl= acl_smtp_predata ? acl_smtp_predata : US"accept";
      enable_dollar_recipients = TRUE;
      rc = acl_check(ACL_WHERE_PREDATA, NULL, acl, &user_msg,
        &log_msg);
      enable_dollar_recipients = FALSE;
      if (rc == OK && !check_sync()) goto SYNC_FAILURE;
      }

    if (rc == OK)
      {
      uschar * code;
      code = US"354";
      if (user_msg == NULL)
        smtp_printf("%s Enter message, ending with \".\" on a line by itself\r\n", code);
      else smtp_user_msg(code, user_msg);
      done = 3;
      message_ended = END_NOTENDED;   /* Indicate in middle of data */
      }

    /* Either the ACL failed the address, or it was deferred. */

    else
      done = smtp_handle_acl_fail(ACL_WHERE_PREDATA, rc, user_msg, log_msg);
    break;


    case VRFY_CMD:
    HAD(SCH_VRFY);
    rc = acl_check(ACL_WHERE_VRFY, NULL, acl_smtp_vrfy, &user_msg, &log_msg);
    if (rc != OK)
      done = smtp_handle_acl_fail(ACL_WHERE_VRFY, rc, user_msg, log_msg);
    else
      {
      uschar *address;
      uschar *s = NULL;

      /* rfc821_domains = TRUE; << no longer needed */
      address = parse_extract_address(smtp_cmd_data, &errmess, &start, &end,
        &recipient_domain, FALSE);
      /* rfc821_domains = FALSE; << no longer needed */

      if (address == NULL)
        s = string_sprintf("501 %s", errmess);
      else
        {
        address_item *addr = deliver_make_addr(address, FALSE);
        switch(verify_address(addr, NULL, vopt_is_recipient | vopt_qualify, -1,
               -1, -1, NULL, NULL, NULL))
          {
          case OK:
          s = string_sprintf("250 <%s> is deliverable", address);
          break;

          case DEFER:
          s = (addr->user_message != NULL)?
            string_sprintf("451 <%s> %s", address, addr->user_message) :
            string_sprintf("451 Cannot resolve <%s> at this time", address);
          break;

          case FAIL:
          s = (addr->user_message != NULL)?
            string_sprintf("550 <%s> %s", address, addr->user_message) :
            string_sprintf("550 <%s> is not deliverable", address);
          log_write(0, LOG_MAIN, "VRFY failed for %s %s",
            smtp_cmd_argument, host_and_ident(TRUE));
          break;
          }
        }

      smtp_printf("%s\r\n", s);
      }
    break;


    case EXPN_CMD:
    HAD(SCH_EXPN);
    rc = acl_check(ACL_WHERE_EXPN, NULL, acl_smtp_expn, &user_msg, &log_msg);
    if (rc != OK)
      done = smtp_handle_acl_fail(ACL_WHERE_EXPN, rc, user_msg, log_msg);
    else
      {
      BOOL save_log_testing_mode = log_testing_mode;
      address_test_mode = log_testing_mode = TRUE;
      (void) verify_address(deliver_make_addr(smtp_cmd_data, FALSE),
        smtp_out, vopt_is_recipient | vopt_qualify | vopt_expn, -1, -1, -1,
        NULL, NULL, NULL);
      address_test_mode = FALSE;
      log_testing_mode = save_log_testing_mode;    /* true for -bh */
      }
    break;


    #ifdef SUPPORT_TLS

    case STARTTLS_CMD:
    HAD(SCH_STARTTLS);
    if (!tls_advertised)
      {
      done = synprot_error(L_smtp_protocol_error, 503, NULL,
        US"STARTTLS command used when not advertised");
      break;
      }

    /* Apply an ACL check if one is defined */

    if (acl_smtp_starttls != NULL)
      {
      rc = acl_check(ACL_WHERE_STARTTLS, NULL, acl_smtp_starttls, &user_msg,
        &log_msg);
      if (rc != OK)
        {
        done = smtp_handle_acl_fail(ACL_WHERE_STARTTLS, rc, user_msg, log_msg);
        break;
        }
      }

    /* RFC 2487 is not clear on when this command may be sent, though it
    does state that all information previously obtained from the client
    must be discarded if a TLS session is started. It seems reasonble to
    do an implied RSET when STARTTLS is received. */

    incomplete_transaction_log(US"STARTTLS");
    smtp_reset(reset_point);
    toomany = FALSE;
    cmd_list[CMD_LIST_STARTTLS].is_mail_cmd = FALSE;

    /* There's an attack where more data is read in past the STARTTLS command
    before TLS is negotiated, then assumed to be part of the secure session
    when used afterwards; we use segregated input buffers, so are not
    vulnerable, but we want to note when it happens and, for sheer paranoia,
    ensure that the buffer is "wiped".
    Pipelining sync checks will normally have protected us too, unless disabled
    by configuration. */

    if (receive_smtp_buffered())
      {
      DEBUG(D_any)
        debug_printf("Non-empty input buffer after STARTTLS; naive attack?");
      if (tls_in.active < 0)
        smtp_inend = smtp_inptr = smtp_inbuffer;
      /* and if TLS is already active, tls_server_start() should fail */
      }

    /* There is nothing we value in the input buffer and if TLS is succesfully
    negotiated, we won't use this buffer again; if TLS fails, we'll just read
    fresh content into it.  The buffer contains arbitrary content from an
    untrusted remote source; eg: NOOP <shellcode>\r\nSTARTTLS\r\n
    It seems safest to just wipe away the content rather than leave it as a
    target to jump to. */

    memset(smtp_inbuffer, 0, in_buffer_size);

    /* Attempt to start up a TLS session, and if successful, discard all
    knowledge that was obtained previously. At least, that's what the RFC says,
    and that's what happens by default. However, in order to work round YAEB,
    there is an option to remember the esmtp state. Sigh.

    We must allow for an extra EHLO command and an extra AUTH command after
    STARTTLS that don't add to the nonmail command count. */

    if ((rc = tls_server_start(tls_require_ciphers)) == OK)
      {
      if (!tls_remember_esmtp)
        helo_seen = esmtp = auth_advertised = pipelining_advertised = FALSE;
      cmd_list[CMD_LIST_EHLO].is_mail_cmd = TRUE;
      cmd_list[CMD_LIST_AUTH].is_mail_cmd = TRUE;
      cmd_list[CMD_LIST_TLS_AUTH].is_mail_cmd = TRUE;
      if (sender_helo_name != NULL)
        {
        store_free(sender_helo_name);
        sender_helo_name = NULL;
        host_build_sender_fullhost();  /* Rebuild */
        set_process_info("handling incoming TLS connection from %s",
          host_and_ident(FALSE));
        }
      received_protocol =
	(sender_host_address ? protocols : protocols_local)
	  [ (esmtp
	    ? pextend + (sender_host_authenticated ? pauthed : 0)
	    : pnormal)
	  + (tls_in.active >= 0 ? pcrpted : 0)
	  ];

      sender_host_authenticated = NULL;
      authenticated_id = NULL;
      sync_cmd_limit = NON_SYNC_CMD_NON_PIPELINING;
      DEBUG(D_tls) debug_printf("TLS active\n");
      break;     /* Successful STARTTLS */
      }

    /* Some local configuration problem was discovered before actually trying
    to do a TLS handshake; give a temporary error. */

    else if (rc == DEFER)
      {
      smtp_printf("454 TLS currently unavailable\r\n");
      break;
      }

    /* Hard failure. Reject everything except QUIT or closed connection. One
    cause for failure is a nested STARTTLS, in which case tls_in.active remains
    set, but we must still reject all incoming commands. */

    DEBUG(D_tls) debug_printf("TLS failed to start\n");
    while (done <= 0)
      {
      switch(smtp_read_command(FALSE))
        {
        case EOF_CMD:
        log_write(L_smtp_connection, LOG_MAIN, "%s closed by EOF",
          smtp_get_connection_info());
        smtp_notquit_exit(US"tls-failed", NULL, NULL);
        done = 2;
        break;

        /* It is perhaps arguable as to which exit ACL should be called here,
        but as it is probably a situation that almost never arises, it
        probably doesn't matter. We choose to call the real QUIT ACL, which in
        some sense is perhaps "right". */

        case QUIT_CMD:
        user_msg = NULL;
        if (acl_smtp_quit != NULL)
          {
          rc = acl_check(ACL_WHERE_QUIT, NULL, acl_smtp_quit, &user_msg,
            &log_msg);
          if (rc == ERROR)
            log_write(0, LOG_MAIN|LOG_PANIC, "ACL for QUIT returned ERROR: %s",
              log_msg);
          }
        if (user_msg == NULL)
          smtp_printf("221 %s closing connection\r\n", smtp_active_hostname);
        else
          smtp_respond(US"221", 3, TRUE, user_msg);
        log_write(L_smtp_connection, LOG_MAIN, "%s closed by QUIT",
          smtp_get_connection_info());
        done = 2;
        break;

        default:
        smtp_printf("554 Security failure\r\n");
        break;
        }
      }
    tls_close(TRUE, TRUE);
    break;
    #endif


    /* The ACL for QUIT is provided for gathering statistical information or
    similar; it does not affect the response code, but it can supply a custom
    message. */

    case QUIT_CMD:
    HAD(SCH_QUIT);
    incomplete_transaction_log(US"QUIT");
    if (acl_smtp_quit != NULL)
      {
      rc = acl_check(ACL_WHERE_QUIT, NULL, acl_smtp_quit, &user_msg, &log_msg);
      if (rc == ERROR)
        log_write(0, LOG_MAIN|LOG_PANIC, "ACL for QUIT returned ERROR: %s",
          log_msg);
      }
    if (user_msg == NULL)
      smtp_printf("221 %s closing connection\r\n", smtp_active_hostname);
    else
      smtp_respond(US"221", 3, TRUE, user_msg);

    #ifdef SUPPORT_TLS
    tls_close(TRUE, TRUE);
    #endif

    done = 2;
    log_write(L_smtp_connection, LOG_MAIN, "%s closed by QUIT",
      smtp_get_connection_info());
    break;


    case RSET_CMD:
    HAD(SCH_RSET);
    incomplete_transaction_log(US"RSET");
    smtp_reset(reset_point);
    toomany = FALSE;
    smtp_printf("250 Reset OK\r\n");
    cmd_list[CMD_LIST_RSET].is_mail_cmd = FALSE;
    break;


    case NOOP_CMD:
    HAD(SCH_NOOP);
    smtp_printf("250 OK\r\n");
    break;


    /* Show ETRN/EXPN/VRFY if there's an ACL for checking hosts; if actually
    used, a check will be done for permitted hosts. Show STARTTLS only if not
    already in a TLS session and if it would be advertised in the EHLO
    response. */

    case HELP_CMD:
    HAD(SCH_HELP);
    smtp_printf("214-Commands supported:\r\n");
      {
      uschar buffer[256];
      buffer[0] = 0;
      Ustrcat(buffer, " AUTH");
      #ifdef SUPPORT_TLS
      if (tls_in.active < 0 &&
          verify_check_host(&tls_advertise_hosts) != FAIL)
        Ustrcat(buffer, " STARTTLS");
      #endif
      Ustrcat(buffer, " HELO EHLO MAIL RCPT DATA");
      Ustrcat(buffer, " NOOP QUIT RSET HELP");
      if (acl_smtp_etrn != NULL) Ustrcat(buffer, " ETRN");
      if (acl_smtp_expn != NULL) Ustrcat(buffer, " EXPN");
      if (acl_smtp_vrfy != NULL) Ustrcat(buffer, " VRFY");
      smtp_printf("214%s\r\n", buffer);
      }
    break;


    case EOF_CMD:
    incomplete_transaction_log(US"connection lost");
    smtp_notquit_exit(US"connection-lost", US"421",
      US"%s lost input connection", smtp_active_hostname);

    /* Don't log by default unless in the middle of a message, as some mailers
    just drop the call rather than sending QUIT, and it clutters up the logs.
    */

    if (sender_address != NULL || recipients_count > 0)
      log_write(L_lost_incoming_connection,
          LOG_MAIN,
          "unexpected %s while reading SMTP command from %s%s",
          sender_host_unknown? "EOF" : "disconnection",
          host_and_ident(FALSE), smtp_read_error);

    else log_write(L_smtp_connection, LOG_MAIN, "%s lost%s",
      smtp_get_connection_info(), smtp_read_error);

    done = 1;
    break;


    case ETRN_CMD:
    HAD(SCH_ETRN);
    if (sender_address != NULL)
      {
      done = synprot_error(L_smtp_protocol_error, 503, NULL,
        US"ETRN is not permitted inside a transaction");
      break;
      }

    log_write(L_etrn, LOG_MAIN, "ETRN %s received from %s", smtp_cmd_argument,
      host_and_ident(FALSE));

    rc = acl_check(ACL_WHERE_ETRN, NULL, acl_smtp_etrn, &user_msg, &log_msg);
    if (rc != OK)
      {
      done = smtp_handle_acl_fail(ACL_WHERE_ETRN, rc, user_msg, log_msg);
      break;
      }

    /* Compute the serialization key for this command. */

    etrn_serialize_key = string_sprintf("etrn-%s\n", smtp_cmd_data);

    /* If a command has been specified for running as a result of ETRN, we
    permit any argument to ETRN. If not, only the # standard form is permitted,
    since that is strictly the only kind of ETRN that can be implemented
    according to the RFC. */

    if (smtp_etrn_command != NULL)
      {
      uschar *error;
      BOOL rc;
      etrn_command = smtp_etrn_command;
      deliver_domain = smtp_cmd_data;
      rc = transport_set_up_command(&argv, smtp_etrn_command, TRUE, 0, NULL,
        US"ETRN processing", &error);
      deliver_domain = NULL;
      if (!rc)
        {
        log_write(0, LOG_MAIN|LOG_PANIC, "failed to set up ETRN command: %s",
          error);
        smtp_printf("458 Internal failure\r\n");
        break;
        }
      }

    /* Else set up to call Exim with the -R option. */

    else
      {
      if (*smtp_cmd_data++ != '#')
        {
        done = synprot_error(L_smtp_syntax_error, 501, NULL,
          US"argument must begin with #");
        break;
        }
      etrn_command = US"exim -R";
      argv = CUSS child_exec_exim(CEE_RETURN_ARGV, TRUE, NULL, TRUE, 2, US"-R",
        smtp_cmd_data);
      }

    /* If we are host-testing, don't actually do anything. */

    if (host_checking)
      {
      HDEBUG(D_any)
        {
        debug_printf("ETRN command is: %s\n", etrn_command);
        debug_printf("ETRN command execution skipped\n");
        }
      if (user_msg == NULL) smtp_printf("250 OK\r\n");
        else smtp_user_msg(US"250", user_msg);
      break;
      }


    /* If ETRN queue runs are to be serialized, check the database to
    ensure one isn't already running. */

    if (smtp_etrn_serialize && !enq_start(etrn_serialize_key))
      {
      smtp_printf("458 Already processing %s\r\n", smtp_cmd_data);
      break;
      }

    /* Fork a child process and run the command. We don't want to have to
    wait for the process at any point, so set SIGCHLD to SIG_IGN before
    forking. It should be set that way anyway for external incoming SMTP,
    but we save and restore to be tidy. If serialization is required, we
    actually run the command in yet another process, so we can wait for it
    to complete and then remove the serialization lock. */

    oldsignal = signal(SIGCHLD, SIG_IGN);

    if ((pid = fork()) == 0)
      {
      smtp_input = FALSE;       /* This process is not associated with the */
      (void)fclose(smtp_in);    /* SMTP call any more. */
      (void)fclose(smtp_out);

      signal(SIGCHLD, SIG_DFL);      /* Want to catch child */

      /* If not serializing, do the exec right away. Otherwise, fork down
      into another process. */

      if (!smtp_etrn_serialize || (pid = fork()) == 0)
        {
        DEBUG(D_exec) debug_print_argv(argv);
        exim_nullstd();                   /* Ensure std{in,out,err} exist */
        execv(CS argv[0], (char *const *)argv);
        log_write(0, LOG_MAIN|LOG_PANIC_DIE, "exec of \"%s\" (ETRN) failed: %s",
          etrn_command, strerror(errno));
        _exit(EXIT_FAILURE);         /* paranoia */
        }

      /* Obey this if smtp_serialize and the 2nd fork yielded non-zero. That
      is, we are in the first subprocess, after forking again. All we can do
      for a failing fork is to log it. Otherwise, wait for the 2nd process to
      complete, before removing the serialization. */

      if (pid < 0)
        log_write(0, LOG_MAIN|LOG_PANIC, "2nd fork for serialized ETRN "
          "failed: %s", strerror(errno));
      else
        {
        int status;
        DEBUG(D_any) debug_printf("waiting for serialized ETRN process %d\n",
          (int)pid);
        (void)wait(&status);
        DEBUG(D_any) debug_printf("serialized ETRN process %d ended\n",
          (int)pid);
        }

      enq_end(etrn_serialize_key);
      _exit(EXIT_SUCCESS);
      }

    /* Back in the top level SMTP process. Check that we started a subprocess
    and restore the signal state. */

    if (pid < 0)
      {
      log_write(0, LOG_MAIN|LOG_PANIC, "fork of process for ETRN failed: %s",
        strerror(errno));
      smtp_printf("458 Unable to fork process\r\n");
      if (smtp_etrn_serialize) enq_end(etrn_serialize_key);
      }
    else
      {
      if (user_msg == NULL) smtp_printf("250 OK\r\n");
        else smtp_user_msg(US"250", user_msg);
      }

    signal(SIGCHLD, oldsignal);
    break;


    case BADARG_CMD:
    done = synprot_error(L_smtp_syntax_error, 501, NULL,
      US"unexpected argument data");
    break;


    /* This currently happens only for NULLs, but could be extended. */

    case BADCHAR_CMD:
    done = synprot_error(L_smtp_syntax_error, 0, NULL,       /* Just logs */
      US"NULL character(s) present (shown as '?')");
    smtp_printf("501 NULL characters are not allowed in SMTP commands\r\n");
    break;


    case BADSYN_CMD:
    SYNC_FAILURE:
    if (smtp_inend >= smtp_inbuffer + in_buffer_size)
      smtp_inend = smtp_inbuffer + in_buffer_size - 1;
    c = smtp_inend - smtp_inptr;
    if (c > 150) c = 150;
    smtp_inptr[c] = 0;
    incomplete_transaction_log(US"sync failure");
    log_write(0, LOG_MAIN|LOG_REJECT, "SMTP protocol synchronization error "
      "(next input sent too soon: pipelining was%s advertised): "
      "rejected \"%s\" %s next input=\"%s\"",
      pipelining_advertised? "" : " not",
      smtp_cmd_buffer, host_and_ident(TRUE),
      string_printing(smtp_inptr));
    smtp_notquit_exit(US"synchronization-error", US"554",
      US"SMTP synchronization error");
    done = 1;   /* Pretend eof - drops connection */
    break;


    case TOO_MANY_NONMAIL_CMD:
    s = smtp_cmd_buffer;
    while (*s != 0 && !isspace(*s)) s++;
    incomplete_transaction_log(US"too many non-mail commands");
    log_write(0, LOG_MAIN|LOG_REJECT, "SMTP call from %s dropped: too many "
      "nonmail commands (last was \"%.*s\")",  host_and_ident(FALSE),
      (int)(s - smtp_cmd_buffer), smtp_cmd_buffer);
    smtp_notquit_exit(US"bad-commands", US"554", US"Too many nonmail commands");
    done = 1;   /* Pretend eof - drops connection */
    break;

    #ifdef EXPERIMENTAL_PROXY
    case PROXY_FAIL_IGNORE_CMD:
    smtp_printf("503 Command refused, required Proxy negotiation failed\r\n");
    break;
    #endif

    default:
    if (unknown_command_count++ >= smtp_max_unknown_commands)
      {
      log_write(L_smtp_syntax_error, LOG_MAIN,
        "SMTP syntax error in \"%s\" %s %s",
        string_printing(smtp_cmd_buffer), host_and_ident(TRUE),
        US"unrecognized command");
      incomplete_transaction_log(US"unrecognized command");
      smtp_notquit_exit(US"bad-commands", US"500",
        US"Too many unrecognized commands");
      done = 2;
      log_write(0, LOG_MAIN|LOG_REJECT, "SMTP call from %s dropped: too many "
        "unrecognized commands (last was \"%s\")", host_and_ident(FALSE),
        string_printing(smtp_cmd_buffer));
      }
    else
      done = synprot_error(L_smtp_syntax_error, 500, NULL,
        US"unrecognized command");
    break;
    }

  /* This label is used by goto's inside loops that want to break out to
  the end of the command-processing loop. */

  COMMAND_LOOP:
  last_was_rej_mail = was_rej_mail;     /* Remember some last commands for */
  last_was_rcpt = was_rcpt;             /* protocol error handling */
  continue;
  }

return done - 2;  /* Convert yield values */
}

/* vi: aw ai sw=2
*/
/* End of smtp_in.c */
