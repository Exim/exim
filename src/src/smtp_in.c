/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Functions for handling an incoming SMTP call. */


#include "exim.h"
#include <assert.h>


/* Size of buffer for reading SMTP commands. We used to use 512, as defined
by RFC 821. However, RFC 1869 specifies that this must be increased for SMTP
commands that accept arguments, and this in particular applies to AUTH, where
the data can be quite long.  More recently this value was 2048 in Exim;
however, RFC 4954 (circa 2007) recommends 12288 bytes to handle AUTH.  Clients
such as Thunderbird will send an AUTH with an initial-response for GSSAPI.
The maximum size of a Kerberos ticket under Windows 2003 is 12000 bytes, and
we need room to handle large base64-encoded AUTHs for GSSAPI.
*/

#define SMTP_CMD_BUFFER_SIZE	16384

/* Size of buffer for reading SMTP incoming packets */

#define IN_BUFFER_SIZE		8192

/* Buffer for SMTP responses */

#define SMTP_RESP_BUFFER_SIZE	2048

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
  ATRN_CMD, ETRN_CMD,		/* This by analogy with TURN from the RFC */
  STARTTLS_CMD,                 /* Required by the STARTTLS RFC */
  TLS_AUTH_CMD,			/* auto-command at start of SSL */
#ifdef EXPERIMENTAL_XCLIENT
  XCLIENT_CMD,			/* per xlexkiro implementation */
#endif

  /* This is a dummy to identify the non-sync commands when pipelining */

  NON_SYNC_CMD_PIPELINING,

  /* These commands need not be synchronized when pipelining */

  MAIL_CMD, RCPT_CMD, RSET_CMD,
#ifndef DISABLE_WELLKNOWN
  WELLKNOWN_CMD,
#endif

  /* This is a dummy to identify the non-sync commands when not pipelining */

  NON_SYNC_CMD_NON_PIPELINING,

  /* RFC3030 section 2: "After all MAIL and RCPT responses are collected and
  processed the message is sent using a series of BDAT commands"
  implies that BDAT should be synchronized.  However, we see Google, at least,
  sending MAIL,RCPT,BDAT-LAST in a single packet, clearly not waiting for
  processing of the RCPT response(s).  We shall do the same, and not require
  synch for BDAT.  Worse, as the chunk may (very likely will) follow the
  command-header in the same packet we cannot do the usual "is there any
  follow-on data after the command line" even for non-pipeline mode.
  So we'll need an explicit check after reading the expected chunk amount
  when non-pipe, before sending the ACK. */

  BDAT_CMD,

  /* I have been unable to find a statement about the use of pipelining
  with AUTH, so to be on the safe side it is here, though I kind of feel
  it should be up there with the synchronized commands. */

  AUTH_CMD,

  /* I'm not sure about these, but I don't think they matter. */

  QUIT_CMD, HELP_CMD,

#ifdef SUPPORT_PROXY
  PROXY_FAIL_IGNORE_CMD,
#endif

  /* These are specials that don't correspond to actual commands */

  EOF_CMD, OTHER_CMD, BADARG_CMD, BADCHAR_CMD, BADSYN_CMD,
  TOO_MANY_NONMAIL_CMD
};


/* This is a convenience macro for adding the identity of an SMTP command
to the circular buffer that holds a list of the last n received. */

#define HAD(n) \
    smtp_connection_had[smtp_ch_index++] = n; \
    if (smtp_ch_index >= SMTP_HBUFF_SIZE) smtp_ch_index = 0


/*************************************************
*                Local static variables          *
*************************************************/

static struct {
  BOOL auth_advertised			:1;
#ifndef DISABLE_TLS
  BOOL tls_advertised			:1;
#endif
  BOOL dsn_advertised			:1;
  BOOL esmtp				:1;
  BOOL helo_verify_required		:1;
  BOOL helo_verify			:1;
  BOOL helo_seen			:1;
  BOOL helo_accept_junk			:1;
#ifndef DISABLE_PIPE_CONNECT
  BOOL pipe_connect_acceptable		:1;
#endif
  BOOL rcpt_smtp_response_same		:1;
  BOOL rcpt_in_progress			:1;
#ifdef SUPPORT_I18N
  BOOL smtputf8_advertised		:1;
#endif
} fl = {
  .helo_verify_required = FALSE,
  .helo_verify = FALSE,
};

static auth_instance *authenticated_by;
static int  count_nonmail;
static int  nonmail_command_count;
static int  synprot_error_count;
static int  unknown_command_count;
static int  sync_cmd_limit;
static int  smtp_write_error = 0;
static int  smtp_resp_ptr = 0;

static uschar *rcpt_smtp_response;
static uschar *smtp_data_buffer;
static uschar *smtp_cmd_data;
static uschar *smtp_resp_buffer;

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

enum {
	CL_RSET = 0,
	CL_HELO,
	CL_EHLO,
	CL_AUTH,
#ifndef DISABLE_TLS
	CL_STLS,
	CL_TLAU,
#endif
#ifdef EXPERIMENTAL_XCLIENT
	CL_XCLI,
#endif
};

static smtp_cmd_list cmd_list[] = {
  /*             name         len                     cmd     has_arg is_mail_cmd */

  [CL_RSET] = { "rset",       sizeof("rset")-1,       RSET_CMD,	FALSE, FALSE },  /* First */
  [CL_HELO] = { "helo",       sizeof("helo")-1,       HELO_CMD, TRUE,  FALSE },
  [CL_EHLO] = { "ehlo",       sizeof("ehlo")-1,       EHLO_CMD, TRUE,  FALSE },
  [CL_AUTH] = { "auth",       sizeof("auth")-1,       AUTH_CMD,     TRUE,  TRUE  },
#ifndef DISABLE_TLS
  [CL_STLS] = { "starttls",   sizeof("starttls")-1,   STARTTLS_CMD, FALSE, FALSE },
  [CL_TLAU] = { "tls_auth",   0,                      TLS_AUTH_CMD, FALSE, FALSE },
#endif
#ifdef EXPERIMENTAL_XCLIENT
  [CL_XCLI] = { "xclient",    sizeof("xclient")-1,    XCLIENT_CMD, TRUE,  FALSE },
#endif

  { "mail from:", sizeof("mail from:")-1, MAIL_CMD, TRUE,  TRUE  },
  { "rcpt to:",   sizeof("rcpt to:")-1,   RCPT_CMD, TRUE,  TRUE  },
  { "data",       sizeof("data")-1,       DATA_CMD, FALSE, TRUE  },
  { "bdat",       sizeof("bdat")-1,       BDAT_CMD, TRUE,  TRUE  },
  { "quit",       sizeof("quit")-1,       QUIT_CMD, FALSE, TRUE  },
  { "noop",       sizeof("noop")-1,       NOOP_CMD, TRUE,  FALSE },
  { "atrn",       sizeof("atrn")-1,       ATRN_CMD, TRUE,  FALSE },
  { "etrn",       sizeof("etrn")-1,       ETRN_CMD, TRUE,  FALSE },
  { "vrfy",       sizeof("vrfy")-1,       VRFY_CMD, TRUE,  FALSE },
  { "expn",       sizeof("expn")-1,       EXPN_CMD, TRUE,  FALSE },
  { "help",       sizeof("help")-1,       HELP_CMD, TRUE,  FALSE },
#ifndef DISABLE_WELLKNOWN
  { "wellknown",  sizeof("wellknown")-1,  WELLKNOWN_CMD, TRUE,  FALSE },
#endif
};

/* This list of names is used for performing the smtp_no_mail logging action.
It must have an entry for each SCH_ command code. */

uschar * smtp_names[] =
  {
  [SCH_NONE] = US"NONE",
  [SCH_AUTH] = US"AUTH",
  [SCH_DATA] = US"DATA",
  [SCH_BDAT] = US"BDAT",
  [SCH_EHLO] = US"EHLO",
  [SCH_ATRN] = US"ATRN",
  [SCH_ETRN] = US"ETRN",
  [SCH_EXPN] = US"EXPN",
  [SCH_HELO] = US"HELO",
  [SCH_HELP] = US"HELP",
  [SCH_MAIL] = US"MAIL",
  [SCH_NOOP] = US"NOOP",
  [SCH_QUIT] = US"QUIT",
  [SCH_RCPT] = US"RCPT",
  [SCH_RSET] = US"RSET",
  [SCH_STARTTLS] = US"STARTTLS",
  [SCH_VRFY] = US"VRFY",
#ifndef DISABLE_WELLKNOWN
  [SCH_WELLKNOWN] = US"WELLKNOWN",
#endif
#ifdef EXPERIMENTAL_XCLIENT
  [SCH_XCLIENT] = US"XCLIENT",
#endif
  };

static uschar *protocols_local[] = {
  US"local-smtp",	/* HELO */
  US"local-smtps",	/* The rare case EHLO->STARTTLS->HELO */
  US"local-esmtp",	/* EHLO */
  US"local-esmtps",	/* EHLO->STARTTLS->EHLO */
  US"local-esmtpa",	/* EHLO->AUTH */
  US"local-esmtpsa",	/* EHLO->STARTTLS->EHLO->AUTH */

  US"local-ssmtp",	/* tls-on-connect, HELO */
  US"local-essmtp",	/* tls-on-connect, EHLO */
  US"local-essmtpa",	/* tls-on-connect, EHLO, AUTH */
  };
static uschar *protocols[] = {
  US"smtp",		/* HELO */
  US"smtps",		/* The rare case EHLO->STARTTLS->HELO */
  US"esmtp",		/* EHLO */
  US"esmtps",		/* EHLO->STARTTLS->EHLO */
  US"esmtpa",		/* EHLO->AUTH */
  US"esmtpsa",		/* EHLO->STARTTLS->EHLO->AUTH */

  US"ssmtp",		/* tls-on-connect, HELO */
  US"essmtp",		/* tls-on-connect, EHLO */
  US"essmtpa",		/* tls-on-connect, EHLO, AUTH */
  };

#define pnormal  0
#define pextend  2
#define pcrpted  1  /* added to pextend or pnormal */
#define pauthed  2  /* added to pextend */
#define ponconn  6

/* Sanity check and validate optional args to MAIL FROM: envelope */
enum {
  ENV_MAIL_OPT_NULL,
  ENV_MAIL_OPT_SIZE, ENV_MAIL_OPT_BODY, ENV_MAIL_OPT_AUTH,
#ifndef DISABLE_PRDR
  ENV_MAIL_OPT_PRDR,
#endif
  ENV_MAIL_OPT_RET, ENV_MAIL_OPT_ENVID,
#ifdef SUPPORT_I18N
  ENV_MAIL_OPT_UTF8,
#endif
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
#ifdef SUPPORT_I18N
    { US"SMTPUTF8",ENV_MAIL_OPT_UTF8,  FALSE },		/* rfc6531 */
#endif
    /* keep this the last entry */
    { US"NULL",   ENV_MAIL_OPT_NULL,   FALSE },
  };

/* State names for debug of chunking */

static const uschar * chunking_states[] = {
  [CHUNKING_NOT_OFFERED] =	US"not-offered",
  [CHUNKING_OFFERED] =		US"offered",
  [CHUNKING_ACTIVE] =		US"active",
  [CHUNKING_LAST] =		US"last" };


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


/* forward declarations */
static int smtp_read_command(BOOL check_sync, unsigned buffer_lim);
static void smtp_quit_handler(uschar **, uschar **);
static void smtp_rset_handler(void);

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
incomplete_transaction_log(uschar * what)
{
if (!sender_address				/* No transaction in progress */
   || !LOGGING(smtp_incomplete_transaction))
  return;

/* Build list of recipients for logging */

if (recipients_count > 0)
  {
  raw_recipients = store_get(recipients_count * sizeof(uschar *), GET_UNTAINTED);
  for (int i = 0; i < recipients_count; i++)
    raw_recipients[i] = recipients_list[i].address;
  raw_recipients_count = recipients_count;
  }

log_write(L_smtp_incomplete_transaction, LOG_MAIN|LOG_SENDER|LOG_RECIPIENTS,
  "%s incomplete transaction (%s)", host_and_ident(TRUE), what);
}



static void
log_close_event(const uschar * reason)
{
log_write(L_smtp_connection, LOG_MAIN, "%s D=%s closed %s",
  smtp_get_connection_info(), string_timesince(&smtp_connection_start), reason);
}


void
smtp_command_timeout_exit(void)
{
log_write(L_lost_incoming_connection,
	  LOG_MAIN, "SMTP command timeout on%s connection from %s D=%s",
	  tls_in.active.sock >= 0 ? " TLS" : "", host_and_ident(FALSE),
	  string_timesince(&smtp_connection_start));
if (smtp_batched_input)
  moan_smtp_batch(NULL, "421 SMTP command timeout"); /* Does not return */
smtp_notquit_exit(US"command-timeout", US"421",
  US"%s: SMTP command timeout - closing connection",
  smtp_active_hostname);
exim_exit(EXIT_FAILURE);
}

void
smtp_command_sigterm_exit(void)
{
log_close_event(US"after SIGTERM");
if (smtp_batched_input)
  moan_smtp_batch(NULL, "421 SIGTERM received");  /* Does not return */
smtp_notquit_exit(US"signal-exit", US"421",
  US"%s: Service not available - closing connection", smtp_active_hostname);
exim_exit(EXIT_FAILURE);
}

void
smtp_data_timeout_exit(void)
{
log_write(L_lost_incoming_connection, LOG_MAIN,
  "SMTP data timeout (message abandoned) on connection from %s F=<%s> D=%s",
  sender_fullhost ? sender_fullhost : US"local process", sender_address,
  string_timesince(&smtp_connection_start));
receive_bomb_out(US"data-timeout", US"SMTP incoming data timeout");
/* Does not return */
}

void
smtp_data_sigint_exit(void)
{
log_close_event(had_data_sigint == SIGTERM ? US"SIGTERM":US"SIGINT");
receive_bomb_out(US"signal-exit",
  US"Service not available - SIGTERM or SIGINT received");
/* Does not return */
}


/******************************************************************************/
/* SMTP input buffer handling.  Most of these are similar to stdio routines.  */

static void
smtp_buf_init(void)
{
/* Set up the buffer for inputting using direct read() calls, and arrange to
call the local functions instead of the standard C ones.  Place a NUL at the
end of the buffer to safety-stop C-string reads from it. */

if (!(smtp_inbuffer = US malloc(IN_BUFFER_SIZE)))
  log_write_die(0, LOG_MAIN, "malloc() failed for SMTP input buffer");
smtp_inbuffer[IN_BUFFER_SIZE-1] = '\0';

smtp_inptr = smtp_inend = smtp_inbuffer;
smtp_had_eof = smtp_had_error = 0;
}



#ifndef DISABLE_DKIM
/* Feed received message data to the dkim module */
/*XXX maybe a global dkim_info? */
void
smtp_verify_feed(const uschar * s, unsigned n)
{
static misc_module_info * dkim_mi = NULL;
typedef void (*fn_t)(const uschar *, int);

if (!dkim_mi && !(dkim_mi = misc_mod_findonly(US"dkim")))
  return;

(((fn_t *) dkim_mi->functions)[DKIM_VERIFY_FEED]) (s, n);
}
#endif


/* Refill the buffer, and notify DKIM verification code.
Return false for error or EOF.
*/

static BOOL
smtp_refill(unsigned lim)
{
int rc, save_errno;

if (smtp_out_fd < 0 || smtp_in_fd < 0) return FALSE;

smtp_fflush(SFF_UNCORK);
if (smtp_receive_timeout > 0) ALARM(smtp_receive_timeout);

/* Limit amount read, so non-message data is not fed to DKIM.
Take care to not touch the safety NUL at the end of the buffer. */

rc = read(smtp_in_fd, smtp_inbuffer, MIN(IN_BUFFER_SIZE-1, lim));
save_errno = errno;
if (smtp_receive_timeout > 0) ALARM_CLR(0);
if (rc <= 0)
  {
  if (rc < 0)
    {
    if (had_command_timeout)		/* set by signal handler */
      smtp_command_timeout_exit();	/* does not return */
    if (had_command_sigterm)
      smtp_command_sigterm_exit();
    if (had_data_timeout)
      smtp_data_timeout_exit();
    if (had_data_sigint)
      smtp_data_sigint_exit();

    smtp_had_error = save_errno;
    }
  else
    smtp_had_eof = 1;
  return FALSE;
  }
#ifndef DISABLE_DKIM
smtp_verify_feed(smtp_inbuffer, rc);
#endif
smtp_inend = smtp_inbuffer + rc;
smtp_inptr = smtp_inbuffer;
return TRUE;
}


/* Check if there is buffered data */

BOOL
smtp_hasc(void)
{
return smtp_inptr < smtp_inend;
}

/* SMTP version of getc()

This gets the next byte from the SMTP input buffer. If the buffer is empty,
it flushes the output, and refills the buffer, with a timeout. The signal
handler is set appropriately by the calling function. This function is not used
after a connection has negotiated itself into an TLS/SSL state.

Arguments:  lim		Maximum amount to read/buffer
Returns:    the next character or EOF
*/

int
smtp_getc(unsigned lim)
{
if (!smtp_hasc() && !smtp_refill(lim)) return EOF;
return *smtp_inptr++;
}

/* Get many bytes, refilling buffer if needed. Can return NULL on EOF/errror. */

uschar *
smtp_getbuf(unsigned * len)
{
unsigned size;
uschar * buf;

if (!smtp_hasc() && !smtp_refill(*len))
  { *len = 0; return NULL; }

if ((size = smtp_inend - smtp_inptr) > *len) size = *len;
buf = smtp_inptr;
smtp_inptr += size;
*len = size;
return buf;
}

/* Copy buffered data to the dkim feed.
Called, unless TLS, just before starting to read message headers. */

void
smtp_get_cache(unsigned lim)
{
#ifndef DISABLE_DKIM
int n = smtp_inend - smtp_inptr;
if (n > lim)
  n = lim;
if (n > 0)
  smtp_verify_feed(smtp_inptr, n);
#endif
}


/* SMTP version of ungetc()
Puts a character back in the input buffer. Only ever called once.

Arguments:
  ch           the character

Returns:       the character
*/

int
smtp_ungetc(int ch)
{
if (smtp_inptr <= smtp_inbuffer)	/* NB: NOT smtp_hasc() ! */
  log_write_die(0, LOG_MAIN, "buffer underflow in smtp_ungetc");

*--smtp_inptr = ch;
return ch;
}


/* SMTP version of feof()
Tests for a previous EOF

Arguments:     none
Returns:       non-zero if the eof flag is set
*/

int
smtp_feof(void)
{
return smtp_had_eof;
}


/* SMTP version of ferror()
Tests for a previous read error, and returns with errno
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


/* Check if a getc will block or not */
/*XXX should convert from select() to poll() */

static BOOL
smtp_could_getc(BOOL eof_ok)
{
int rc;
fd_set fds;
struct timeval tzero = {.tv_sec = 0, .tv_usec = 0};

if (smtp_inptr < smtp_inend)
  return TRUE;		/* Previously buffered data available */

FD_ZERO(&fds);
FD_SET(smtp_in_fd, &fds);
rc = select(smtp_in_fd + 1, (SELECT_ARG2_TYPE *)&fds, NULL, NULL, &tzero);

if (rc <= 0) return FALSE;	/* Not ready to read */
if (eof_ok) return TRUE;	/* A read will not block */

/* Check for actual data */
rc = smtp_getc(GETC_BUFFER_UNLIMITED);
if (rc < 0) return FALSE;      /* End of file or error */

smtp_ungetc(rc);
return TRUE;
}


/******************************************************************************/
/*************************************************
*          Recheck synchronization               *
*************************************************/

/* Synchronization checks can never be perfect because a packet may be on its
way but not arrived when the check is done.  Normally, the checks happen when
commands are read: Exim ensures that there is no more input in the input buffer.
In normal cases, the response to the command will be fast, and there is no
further check.

However, for some commands an ACL is run, and that can include delays. In those
cases, it is useful to do another check on the input just before sending the
response. This also applies at the start of a connection. This function does
that check by means of the select() function, as long as the facility is not
disabled or inappropriate. A failure of select() is ignored.

When there is unwanted input, we read it so that it appears in the log of the
error.

Arguments: eof_ok	TRUE if EOF is enough to unblock; else need actual data
Returns:   TRUE if all is well; FALSE if there is input pending
*/

BOOL
wouldblock_reading(BOOL eof_ok)
{
if (smtp_in_fd < 0) return FALSE;

#ifndef DISABLE_TLS
if (tls_in.active.sock >= 0)
 return !tls_could_getc();
#endif

return !smtp_could_getc(eof_ok);
}

static BOOL
check_sync(BOOL eof_ok)
{
if (!smtp_enforce_sync || !sender_host_address || f.sender_host_notsocket)
  return TRUE;

return wouldblock_reading(eof_ok);
}


/******************************************************************************/
/* Variants of the smtp_* input handling functions for use in CHUNKING mode */

/* Forward declarations */
static inline void bdat_push_receive_functions(void);
static inline void bdat_pop_receive_functions(void);


/* Get a byte from the smtp input, in CHUNKING mode.  Handle ack of the
previous BDAT chunk and getting new ones when we run out.  Uses the
underlying smtp_getc or tls_getc both for that and for getting the
(buffered) data byte.  EOD signals (an expected) no further data.
ERR signals a protocol error, and EOF a closed input stream.

Called from read_bdat_smtp() in receive.c for the message body, but also
by the headers read loop in receive_msg(); manipulates chunking_state
to handle the BDAT command/response.
Placed here due to the correlation with the above smtp_getc(), which it wraps,
and also by the need to do smtp command/response handling.

Arguments:  lim		(ignored)
Returns:    the next character or ERR, EOD or EOF
*/

int
bdat_getc(unsigned lim)
{
uschar * user_msg = NULL, * log_msg;
int rc;

#ifndef DISABLE_DKIM
misc_module_info * dkim_info = misc_mod_findonly(US"dkim");
typedef void (*dkim_pause_t)(BOOL);
dkim_pause_t dkim_pause;

dkim_pause = dkim_info
  ? ((dkim_pause_t *) dkim_info->functions)[DKIM_VERIFY_PAUSE] : NULL;
#endif

for(;;)
  {

  if (chunking_data_left > 0)
    return lwr_receive_getc(chunking_data_left--);

  bdat_pop_receive_functions();
#ifndef DISABLE_DKIM
  if (dkim_pause) dkim_pause(TRUE);
#endif

  /* Unless PIPELINING was offered, there should be no next command
  until after we ack that chunk */

  if (!f.smtp_in_pipelining_advertised && !check_sync(WBR_DATA_ONLY))
    {
    unsigned nchars = 32;
    uschar * buf = receive_getbuf(&nchars);		/* destructive read */

    incomplete_transaction_log(US"sync failure");
    if (buf)
      log_write(0, LOG_MAIN|LOG_REJECT, "SMTP protocol synchronization error "
	"(next input sent too soon: pipelining was not advertised): "
	"rejected %q %s next input=%q%s",
	smtp_cmd_buffer, host_and_ident(TRUE),
	string_printing(string_copyn(buf, nchars)),
	smtp_inend - smtp_inptr > 0 ? "..." : "");
    else
      log_write(0, LOG_MAIN|LOG_REJECT, "Error or EOF on input from %s",
	host_and_ident(TRUE));
    (void) synprot_error(L_smtp_protocol_error, 554, NULL,
      US"SMTP synchronization error");
    goto repeat_until_rset;
    }

  /* If not the last, ack the received chunk.  The last response is delayed
  until after the data ACL decides on it */

  if (chunking_state == CHUNKING_LAST)
    {
#ifndef DISABLE_DKIM
    smtp_verify_feed(NULL, 0);	/* notify EOD */
#endif
    return EOD;
    }

  smtp_printf("250 %u byte chunk received\r\n", SP_NO_MORE, chunking_datasize);
  chunking_state = CHUNKING_OFFERED;
  DEBUG(D_receive)
    debug_printf("chunking state '%s'\n", chunking_states[chunking_state]);

  /* Expect another BDAT cmd from input. RFC 3030 says nothing about
  QUIT, RSET or NOOP but handling them seems obvious */

next_cmd:
  switch(smtp_read_command(TRUE, 1))
    {
    default:
      (void) synprot_error(L_smtp_protocol_error, 503, NULL,
	US"only BDAT permissible after non-LAST BDAT");

  repeat_until_rset:
      switch(rc = smtp_read_command(TRUE, 1))
	{
	case QUIT_CMD:	smtp_quit_handler(&user_msg, &log_msg);	/*FALLTHROUGH */
	case EOF_CMD:	return EOF;
	case RSET_CMD:	smtp_rset_handler(); return ERR;
	default:	if (synprot_error(L_smtp_protocol_error, 503, NULL,
					  US"only RSET accepted now") > 0)
			  return ERR;
			goto repeat_until_rset;
	}

    case QUIT_CMD:
      smtp_quit_handler(&user_msg, &log_msg);
      /*FALLTHROUGH*/
    case EOF_CMD:
      return EOF;

    case RSET_CMD:
      smtp_rset_handler();
      return ERR;

    case NOOP_CMD:
      HAD(SCH_NOOP);
      smtp_printf("250 OK\r\n", SP_NO_MORE);
      goto next_cmd;

    case BDAT_CMD:
      {
      int n;

      if (sscanf(CS smtp_cmd_data, "%u %n", &chunking_datasize, &n) < 1)
	{
	(void) synprot_error(L_smtp_protocol_error, 501, NULL,
	  US"missing size for BDAT command");
	return ERR;
	}
      chunking_state = strcmpic(smtp_cmd_data+n, US"LAST") == 0
	? CHUNKING_LAST : CHUNKING_ACTIVE;
      chunking_data_left = chunking_datasize;
      DEBUG(D_receive) debug_printf("chunking state '%s', %d bytes\n",
			chunking_states[chunking_state], chunking_data_left);

      if (chunking_datasize == 0)
	if (chunking_state == CHUNKING_LAST)
	  return EOD;
	else
	  {
	  (void) synprot_error(L_smtp_protocol_error, 504, NULL,
	    US"zero size for BDAT command");
	  goto repeat_until_rset;
	  }

      bdat_push_receive_functions();
#ifndef DISABLE_DKIM
      if (dkim_pause) dkim_pause(FALSE);
#endif
      break;	/* to top of main loop */
      }
    }
  }
}

BOOL
bdat_hasc(void)
{
if (chunking_data_left > 0)
  return lwr_receive_hasc();
return TRUE;
}

uschar *
bdat_getbuf(unsigned * len)
{
uschar * buf;

if (chunking_data_left == 0)
  { *len = 0; return NULL; }

if (*len > chunking_data_left) *len = chunking_data_left;
buf = lwr_receive_getbuf(len);	/* Either smtp_getbuf or tls_getbuf */
chunking_data_left -= *len;
return buf;
}

void
bdat_flush_data(void)
{
while (chunking_data_left)
  {
  unsigned n = chunking_data_left;
  if (!bdat_getbuf(&n)) break;
  }

bdat_pop_receive_functions();
chunking_state = CHUNKING_OFFERED;
DEBUG(D_receive)
  debug_printf("chunking state '%s'\n", chunking_states[chunking_state]);
}


static inline void
bdat_push_receive_functions(void)
{
/* push the current receive_* function on the "stack", and
replace them by bdat_getc(), which in turn will use the lwr_receive_*
functions to do the dirty work. */
if (!lwr_receive_getc)
  {
  lwr_receive_getc = receive_getc;
  lwr_receive_getbuf = receive_getbuf;
  lwr_receive_hasc = receive_hasc;
  lwr_receive_ungetc = receive_ungetc;
  }
else
  {
  DEBUG(D_receive) debug_printf("chunking double-push receive functions\n");
  }

receive_getc = bdat_getc;
receive_getbuf = bdat_getbuf;
receive_hasc = bdat_hasc;
receive_ungetc = bdat_ungetc;
}

static inline void
bdat_pop_receive_functions(void)
{
if (!lwr_receive_getc)
  {
  DEBUG(D_receive) debug_printf("chunking double-pop receive functions\n");
  return;
  }
receive_getc = lwr_receive_getc;
receive_getbuf = lwr_receive_getbuf;
receive_hasc = lwr_receive_hasc;
receive_ungetc = lwr_receive_ungetc;

lwr_receive_getc = NULL;
lwr_receive_getbuf = NULL;
lwr_receive_hasc = NULL;
lwr_receive_ungetc = NULL;
}

int
bdat_ungetc(int ch)
{
chunking_data_left++;
bdat_push_receive_functions();  /* we're not done yet, calling push is safe, because it checks the state before pushing anything */
return lwr_receive_ungetc(ch);
}



/******************************************************************************/

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

This function is exposed to the local_scan API; do not change the signature.

Arguments:
  format      format string
  more	      further data expected
  ...         optional arguments

Returns:      nothing
*/

void
smtp_printf(const char *format, BOOL more, ...)
{
va_list ap;

va_start(ap, more);
smtp_vprintf(format, more, ap);
va_end(ap);
}

/* This is split off so that verify.c:respond_printf() can, in effect, call
smtp_printf(), bearing in mind that in C a vararg function can't directly
call another vararg function, only a function which accepts a va_list.

This function is exposed to the local_scan API; do not change the signature.
*/
/*XXX consider passing caller-info in, for string_vformat-onward */

void
smtp_vprintf(const char * format, BOOL more, va_list ap)
{
gstring gs = { .size = big_buffer_size, .ptr = 0, .s = big_buffer };
BOOL yield;

/* Use taint-unchecked routines for writing into big_buffer, trusting
that we'll never expand it. */

yield = !! string_vformat(&gs, SVFMT_TAINT_NOCHK, format, ap);
string_from_gstring(&gs);

DEBUG(D_receive) for (const uschar * t, * s = gs.s;
		      s && (t = Ustrchr(s, '\r'));
		      s = t + 2)				/* \r\n */
    debug_printf("%s %.*s\n",
		  s == gs.s ? more ? "SMTP>|" : "SMTP>>" : "      ",
		  (int)(t - s), s);

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

if (fl.rcpt_in_progress)
  {
  if (!rcpt_smtp_response)
    rcpt_smtp_response = string_copy(big_buffer);
  else if (fl.rcpt_smtp_response_same &&
           Ustrcmp(rcpt_smtp_response, big_buffer) != 0)
    fl.rcpt_smtp_response_same = FALSE;
  fl.rcpt_in_progress = FALSE;
  }

/* Now write the string */

if (smtp_out_fd < 0)
  smtp_write_error = -1;
#ifndef DISABLE_TLS
else if (tls_in.active.sock >= 0)
  { if (tls_write(NULL, gs.s, gs.ptr, more) < 0) smtp_write_error = -1; }
#endif
else
  if (more)				/* stash for later if possible */
    {
    if (smtp_resp_ptr + gs.ptr <= SMTP_RESP_BUFFER_SIZE)
      {					/* can fit new */
      memcpy(smtp_resp_buffer + smtp_resp_ptr, gs.s, gs.ptr);
      smtp_resp_ptr += gs.ptr;
      }
    else
      {
      if (smtp_resp_ptr > 0)
	{					/* flush the old */
	if (write(smtp_out_fd, smtp_resp_buffer, smtp_resp_ptr) != smtp_resp_ptr)
	  smtp_write_error = -1;
	smtp_resp_ptr = 0;
	}
      if (gs.ptr <= SMTP_RESP_BUFFER_SIZE)
	{					/* can fit new */
	memcpy(smtp_resp_buffer + smtp_resp_ptr, gs.s, gs.ptr);
	smtp_resp_ptr = gs.ptr;
	}
      else					/* new too big */
	if (write (smtp_out_fd, gs.s, gs.ptr) != gs.ptr)
	  smtp_write_error = -1;
      }
    }
  else					/* send it now */
    if (smtp_resp_ptr > 0)			/* previously buffered */
      {
      if (smtp_resp_ptr + gs.ptr <= SMTP_RESP_BUFFER_SIZE)
	{					/* can fit new */
	int n = smtp_resp_ptr + gs.ptr;
	memcpy(smtp_resp_buffer + smtp_resp_ptr, gs.s, gs.ptr);
	if (write(smtp_out_fd, smtp_resp_buffer, n) != n)
	  smtp_write_error = -1;
	}
      else
	if (  write(smtp_out_fd, smtp_resp_buffer, smtp_resp_ptr)
	      != smtp_resp_ptr
	   || write (smtp_out_fd, gs.s, gs.ptr) != gs.ptr
	   )
	  smtp_write_error = -1;
      smtp_resp_ptr = 0;
      }
    else					/* nothing buffered */
      if (write (smtp_out_fd, gs.s, gs.ptr) != gs.ptr)
	smtp_write_error = -1;
}



/*************************************************
*        Flush SMTP out and check for error      *
*************************************************/

/* This function sets a flag for errors checked on read of the next SMTP input.
It flushes the output and checks for errors.

Arguments:  uncork	true to also uncork the socket layer
Returns:    0 for no error; -1 after an error
*/

int
smtp_fflush(BOOL uncork)
{
if (smtp_out_fd <= 0) return 0;

DEBUG(D_receive) debug_printf("SMTP>- %Vflush%V\n", "<", ">");

#ifndef DISABLE_TLS
if (tls_in.active.sock >= 0)
  { if (tls_write(NULL, NULL, 0, FALSE) < 0) smtp_write_error = -1; }
else
#endif

  {
  if (smtp_resp_ptr > 0)
    {
    if (write(smtp_out_fd, smtp_resp_buffer, smtp_resp_ptr) != smtp_resp_ptr)
      smtp_write_error = -1;
    smtp_resp_ptr = 0;
    }
#ifdef EXIM_TCP_CORK
  if (  uncork 
     && setsockopt(smtp_out_fd, IPPROTO_TCP, EXIM_TCP_CORK,
					  &off, sizeof(off)) != 0)
    smtp_write_error = -1;
#endif
  }

return smtp_write_error;
}




/* If there's input waiting (and we're doing pipelineing) then we can pipeline
a reponse with the one following. */

static BOOL
pipeline_response(void)
{
if (  !smtp_enforce_sync || !sender_host_address
   || f.sender_host_notsocket || !f.smtp_in_pipelining_advertised)
  return FALSE;

if (wouldblock_reading(WBR_DATA_OR_EOF)) return FALSE;
f.smtp_in_pipelining_used = TRUE;
return TRUE;
}


#ifndef DISABLE_PIPE_CONNECT
static BOOL
pipeline_connect_sends(void)
{
if (!sender_host_address || f.sender_host_notsocket || !fl.pipe_connect_acceptable)
  return FALSE;

if (wouldblock_reading(WBR_DATA_OR_EOF)) return FALSE;
f.smtp_in_early_pipe_used = TRUE;
return TRUE;
}
#endif

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
had_command_timeout = sig;
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
had_command_sigterm = sig;
}




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
  check_sync	if TRUE, check synchronization rules if global option is TRUE
  buffer_lim	maximum to buffer in lower layer

Returns:       a code identifying the command (enumerated above)
*/

static int
smtp_read_command(BOOL check_sync, unsigned buffer_lim)
{
int ptr = 0, c;
BOOL hadnull = FALSE;

had_command_timeout = 0;
os_non_restarting_signal(SIGALRM, command_timeout_handler);

/* Read up to end of line */

while ((c = (receive_getc)(buffer_lim)) != '\n')
  {
  /* If hit end of file, return pseudo EOF command. Whether we have a
  part-line already read doesn't matter, since this is an error state. */

  if (c < 0 || ptr >= SMTP_CMD_BUFFER_SIZE)
    {
    os_non_restarting_signal(SIGALRM, sigalrm_handler);
    /* c could be EOF, ERR, or a good (positive) value overflowing the buffer */
    DEBUG(D_receive)
      if (c < 0)
	debug_printf("SMTP(%s)<<\n", c == EOF ? "closed" : "error");
      else
	debug_printf("SMTP(overflow)<< '%.*s'\n",
		      SMTP_CMD_BUFFER_SIZE, smtp_cmd_buffer);
    return c == EOF ? EOF_CMD : OTHER_CMD;
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

for (smtp_cmd_list * p = cmd_list; p < cmd_list + nelem(cmd_list); p++)
  {
#ifdef SUPPORT_PROXY
  /* Only allow QUIT command if Proxy Protocol parsing failed */
  if (proxy_session && f.proxy_session_failed && p->cmd != QUIT_CMD)
    continue;
#endif
  if (  p->len
     && strncmpic(smtp_cmd_buffer, US p->name, p->len) == 0
     && (  smtp_cmd_buffer[p->len-1] == ':'    /* "mail from:" or "rcpt to:" */
        || smtp_cmd_buffer[p->len] == 0
	|| smtp_cmd_buffer[p->len] == ' '
     )  )
    {
    if (   smtp_inptr < smtp_inend		/* Outstanding input */
       &&  p->cmd < sync_cmd_limit		/* Command should sync */
       &&  check_sync				/* Local flag set */
       &&  smtp_enforce_sync			/* Global flag set */
       &&  sender_host_address != NULL		/* Not local input */
       &&  !f.sender_host_notsocket		/* Really is a socket */
       )
      return BADSYN_CMD;

    /* The variables $smtp_command and $smtp_command_argument point into the
    unmodified input buffer. A copy of the latter is taken for actual
    processing, so that it can be chopped up into separate parts if necessary,
    for example, when processing a MAIL command options such as SIZE that can
    follow the sender address. */

    smtp_cmd_argument = smtp_cmd_buffer + p->len;
    Uskip_whitespace(&smtp_cmd_argument);
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
    error here. Otherwise, return the command code. */

    return p->has_arg || *smtp_cmd_data == 0 ? p->cmd : BADARG_CMD;
    }
  }

#ifdef SUPPORT_PROXY
/* Only allow QUIT command if Proxy Protocol parsing failed */
if (proxy_session && f.proxy_session_failed)
  return PROXY_FAIL_IGNORE_CMD;
#endif

/* Enforce synchronization for unknown commands */

if (  smtp_inptr < smtp_inend		/* Outstanding input */
   && check_sync			/* Local flag set */
   && smtp_enforce_sync			/* Global flag set */
   && sender_host_address		/* Not local input */
   && !f.sender_host_notsocket		/* Really is a socket */
   )
  return BADSYN_CMD;

return OTHER_CMD;
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
smtp_closedown(uschar * message)
{
if (smtp_in_fd < 0 || smtp_batched_input) return;
receive_swallow_smtp();
smtp_printf("421 %s\r\n", SP_NO_MORE, message);

for (;;) switch(smtp_read_command(FALSE, GETC_BUFFER_UNLIMITED))
  {
  case EOF_CMD:
    return;

  case QUIT_CMD:
    f.smtp_in_quit = TRUE;
    smtp_printf("221 %s closing connection\r\n", SP_NO_MORE,
		smtp_active_hostname);
    return;

  case RSET_CMD:
    smtp_printf("250 Reset OK\r\n", SP_NO_MORE);
    break;

  default:
    smtp_printf("421 %s\r\n", SP_NO_MORE, message);
    break;
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
const uschar * hostname = sender_fullhost
  ? sender_fullhost : sender_host_address;
gstring * g = string_catn(NULL, US"SMTP connection", 15);

if (LOGGING(connection_id))
  g = string_fmt_append(g, " Ci=%s", connection_id);
g = string_catn(g, US" from ", 6);

if (host_checking)
  g = string_cat(g, hostname);

else if (f.sender_host_unknown || f.sender_host_notsocket)
  g = string_cat(g, sender_ident ? sender_ident : US"NULL");

else if (atrn_mode)
  g = string_append(g, 2, hostname, US" (ODMR customer)");

else if (f.is_inetd)
  g = string_append(g, 2, hostname, US" (via inetd)");

else if (LOGGING(incoming_interface) && interface_address)
  {
  g = string_fmt_append(g, "%s I=[%s]", hostname, interface_address);
  g = log_portnum(g, interface_port);
  }

else
  g = string_cat(g, hostname);

gstring_release_unused(g);
return string_from_gstring(g);
}



/* Append TLS-related information to a log line

Arguments:
  g		String under construction: allocated string to extend, or NULL

Returns:	Allocated string or NULL
*/
gstring *
add_tls_info_for_log(gstring * g)
{
#ifndef DISABLE_TLS
if (LOGGING(tls_cipher) && tls_in.cipher)
  {
  g = string_append(g, 2, US" X=", tls_in.cipher);
# ifndef DISABLE_TLS_RESUME
  if (LOGGING(tls_resumption) && tls_in.resumption & RESUME_USED)
    g = string_catn(g, US"*", 1);
# endif
  }
if (LOGGING(tls_certificate_verified) && tls_in.peercert)
  g = string_append(g, 2, US" CV=", tls_in.certificate_verified? "yes":"no");
if (LOGGING(tls_peerdn) && tls_in.peerdn)
  g = string_append(g, 3, US" DN=\"", string_printing(tls_in.peerdn), US"\"");
if (LOGGING(tls_sni) && tls_in.sni)
  g = string_append(g, 2, US" SNI=", string_printing2(tls_in.sni, SP_TAB|SP_SPACE));
return g;
#endif
}



static gstring *
s_connhad_log(gstring * g)
{
const uschar * sep = smtp_connection_had[SMTP_HBUFF_SIZE-1] != SCH_NONE
  ? US" C=..." : US" C=";

for (int i = smtp_ch_index; i < SMTP_HBUFF_SIZE; i++)
  if (smtp_connection_had[i] != SCH_NONE)
    {
    g = string_append(g, 2, sep, smtp_names[smtp_connection_had[i]]);
    sep = US",";
    }
for (int i = 0; i < smtp_ch_index; i++, sep = US",")
  g = string_append(g, 2, sep, smtp_names[smtp_connection_had[i]]);
return g;
}


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
gstring * g = NULL;

if (smtp_mailcmd_count > 0 || !LOGGING(smtp_no_mail))
  return;

if (sender_host_authenticated)
  {
  g = string_append(g, 2, US" A=", sender_host_authenticated);
  if (authenticated_id) g = string_append(g, 2, US":", authenticated_id);
  }

g = add_tls_info_for_log(g);
g = s_connhad_log(g);

log_write(0, LOG_MAIN, "no MAIL in %sSMTP connection from %s D=%s%#Y",
  f.tcp_in_fastopen ? f.tcp_in_fastopen_data ? US"TFO* " : US"TFO " : US"",
  host_and_ident(FALSE), string_timesince(&smtp_connection_start), g);
}


/* Return list of recent smtp commands */

uschar *
smtp_cmd_hist(void)
{
gstring * list = NULL;
uschar * s;

for (int i = smtp_ch_index; i < SMTP_HBUFF_SIZE; i++)
  if (smtp_connection_had[i] != SCH_NONE)
    list = string_append_listele(list, ',', smtp_names[smtp_connection_had[i]]);

for (int i = 0; i < smtp_ch_index; i++)
  list = string_append_listele(list, ',', smtp_names[smtp_connection_had[i]]);

s = string_from_gstring(list);
return s ? s : US"";
}




/*************************************************
*   Check HELO line and set sender_helo_name     *
*************************************************/

/* Check the format of a HELO line. The data for HELO/EHLO is supposed to be
the domain name of the sending host, or an ip literal in square brackets. The
argument is placed in sender_helo_name, which is in malloc store, because it
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
BOOL yield = fl.helo_accept_junk;

/* Discard any previous helo name */

sender_helo_name = NULL;

/* Skip tests if junk is permitted. */

if (!yield)

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

  else if (*s)
    for (yield = TRUE; *s; s++)
      if (!isalnum(*s) && *s != '.' && *s != '-' &&
          Ustrchr(helo_allow_chars, *s) == NULL)
        {
        yield = FALSE;
        break;
        }

/* Save argument if OK */

if (yield) sender_helo_name = string_copy_perm(start, TRUE);
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
uschar *v;
if (Ustrlen(smtp_cmd_data) <= 0) return FALSE;
v = smtp_cmd_data + Ustrlen(smtp_cmd_data) - 1;
while (v > smtp_cmd_data && isspace(*v)) v--;
v[1] = 0;

while (v > smtp_cmd_data && *v != '=' && !isspace(*v))
  {
  /* Take care to not stop at a space embedded in a quoted local-part */
  if (*v == '"')
    {
    do v--; while (v > smtp_cmd_data && *v != '"');
    if (v <= smtp_cmd_data) return FALSE;
    }
  v--;
  }
if (v <= smtp_cmd_data) return FALSE;

n = v;
if (*v == '=')
  {
  while (n > smtp_cmd_data && isalpha(n[-1])) n--;
  /* RFC says SP, but TAB seen in wild and other major MTAs accept it */
  if (n <= smtp_cmd_data || !isspace(n[-1])) return FALSE;
  n[-1] = 0;
  }
else
  {
  n++;
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
within either of the setup functions; also from the daemon loop.

Argument:   the stacking pool storage reset point
Returns:    a replacement reset point
*/

rmark
smtp_reset(rmark reset_point)
{
recipients_list = NULL;
rcpt_count = rcpt_defer_count = rcpt_fail_count =
  raw_recipients_count = recipients_count = recipients_list_max = 0;
message_linecount = 0;
message_size = -1;
message_body = message_body_end = NULL;
acl_added_headers = NULL;
acl_removed_headers = NULL;
f.queue_only_policy = FALSE;
rcpt_smtp_response = NULL;
fl.rcpt_smtp_response_same = TRUE;
fl.rcpt_in_progress = FALSE;
f.deliver_freeze = FALSE;				/* Can be set by ACL */
freeze_tell = freeze_tell_config;			/* Can be set by ACL */
fake_response = OK;					/* Can be set by ACL */
#ifdef WITH_CONTENT_SCAN
f.no_mbox_unspool = FALSE;				/* Can be set by ACL */
#endif
f.submission_mode = FALSE;				/* Can be set by ACL */
f.suppress_local_fixups = f.suppress_local_fixups_default; /* Can be set by ACL */
f.active_local_from_check = local_from_check;		/* Can be set by ACL */
f.active_local_sender_retain = local_sender_retain;	/* Can be set by ACL */
sending_ip_address = NULL;
return_path = sender_address = NULL;
deliver_localpart_data = deliver_domain_data =
recipient_data = sender_data = NULL;			/* Can be set by ACL */
recipient_verify_failure = NULL;
deliver_localpart_parent = deliver_localpart_orig = NULL;
deliver_domain_parent = deliver_domain_orig = NULL;
callout_address = NULL;
submission_name = NULL;					/* Can be set by ACL */
raw_sender = NULL;                  /* After SMTP rewrite, before qualifying */
sender_address_unrewritten = NULL;  /* Set only after verify rewrite */
sender_verified_list = NULL;        /* No senders verified */
memset(sender_address_cache, 0, sizeof(sender_address_cache));
memset(sender_domain_cache, 0, sizeof(sender_domain_cache));

authenticated_sender = NULL;
dnslist_domain = dnslist_matched = NULL;

dsn_ret = 0;
dsn_envid = NULL;
deliver_host = deliver_host_address = NULL;	/* Can be set by ACL */
#ifndef DISABLE_TLS
 memset(&tls_out, 0, sizeof(tls_out));		/* Can be set by callout */
 tls_out.active.sock = -1;
#endif
#ifndef DISABLE_PRDR
 prdr_requested = FALSE;
#endif
#ifdef SUPPORT_I18N
 message_smtputf8 = FALSE;
#endif
#ifdef SUPPORT_SRS
 srs_recipient = NULL;
#endif
#ifdef HAVE_LOCAL_SCAN
local_scan_data = NULL;
#endif
#ifdef WITH_CONTENT_SCAN
 regex_vars_clear();
 malware_name = NULL;
#endif
#ifdef EXPERIMENTAL_DCC
 dcc_header = dcc_result = NULL;
#endif

body_linecount = body_zerocount = 0;

lookup_value = NULL;				/* Can be set by ACL */
sender_rate = sender_rate_limit = sender_rate_period = NULL;
ratelimiters_mail = NULL;           /* Updated by ratelimit ACL condition */
                   /* Note that ratelimiters_conn persists across resets. */

/* Reset message ACL variables */

acl_var_m = NULL;

/* Warning log messages are saved in malloc store. They are saved to avoid
repetition in the same message, but it seems right to repeat them for different
messages. */

while (acl_warn_logged)
  {
  string_item *this = acl_warn_logged;
  acl_warn_logged = acl_warn_logged->next;
  store_free(this);
  }

misc_mod_smtp_reset();
message_tidyup();
store_reset(reset_point);

message_start();
return store_mark();
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
rmark reset_point = store_mark();

/* Save the line count at the start of each transaction - single commands
like HELO and RSET count as whole transactions. */

bsmtp_transaction_linecount = receive_linecount;

if ((receive_feof)()) return 0;   /* Treat EOF as QUIT */

cancel_cutthrough_connection(TRUE, US"smtp_setup_batch_msg");
reset_point = smtp_reset(reset_point);		/* Reset for start of message */

/* Deal with SMTP commands. This loop is exited by setting done to a POSITIVE
value. The values are 2 larger than the required yield of the function. */

while (done <= 0)
  {
  uschar *errmess;
  uschar *recipient = NULL;
  int start, end, sender_domain, recipient_domain;

  switch(smtp_read_command(FALSE, GETC_BUFFER_UNLIMITED))
    {
    /* The HELO/EHLO commands set sender_address_helo if they have
    valid data; otherwise they are ignored, except that they do
    a reset of the state. */

    case HELO_CMD:
    case EHLO_CMD:

      check_helo(smtp_cmd_data);
      /* Fall through */

    case RSET_CMD:
      cancel_cutthrough_connection(TRUE, US"RSET received");
      reset_point = smtp_reset(reset_point);
      bsmtp_transaction_linecount = receive_linecount;
      break;

    /* The MAIL FROM command requires an address as an operand. All we
    do here is to parse it for syntactic correctness. The form "<>" is
    a special case which converts into an empty string. The start/end
    pointers in the original are not used further for this address, as
    it is the canonical extracted address which is all that is kept. */

    case MAIL_CMD:
      smtp_mailcmd_count++;              /* Count for no-mail log */
      if (sender_address)
	/* The function moan_smtp_batch() does not return. */
	moan_smtp_batch(smtp_cmd_buffer, "503 Sender already given");

      if (smtp_cmd_data[0] == 0)
	/* The function moan_smtp_batch() does not return. */
	moan_smtp_batch(smtp_cmd_buffer, "501 MAIL FROM must have an address operand");

      /* Reset to start of message */

      cancel_cutthrough_connection(TRUE, US"MAIL received");
      reset_point = smtp_reset(reset_point);

      /* Apply SMTP rewrite */

      raw_sender = rewrite_existflags & rewrite_smtp
	/* deconst ok as smtp_cmd_data was not const */
        ? US rewrite_one(smtp_cmd_data, rewrite_smtp|rewrite_smtp_sender, NULL,
		      FALSE, US"", global_rewrite_rules)
	: smtp_cmd_data;

      /* Extract the address; the TRUE flag allows <> as valid */

      raw_sender =
	parse_extract_address(raw_sender, &errmess, &start, &end, &sender_domain,
	  TRUE);

      if (!raw_sender)
	/* The function moan_smtp_batch() does not return. */
	moan_smtp_batch(smtp_cmd_buffer, "501 %s", errmess);

      sender_address = string_copy(raw_sender);

      /* Qualify unqualified sender addresses if permitted to do so. */

      if (  !sender_domain
         && sender_address[0] != 0 && sender_address[0] != '@')
	if (f.allow_unqualified_sender)
	  {
	  /* deconst ok as sender_address was not const */
	  sender_address = US rewrite_address_qualify(sender_address, FALSE);
	  DEBUG(D_receive) debug_printf("unqualified address %s accepted "
	    "and rewritten\n", raw_sender);
	  }
	/* The function moan_smtp_batch() does not return. */
	else
	  moan_smtp_batch(smtp_cmd_buffer, "501 sender address must contain "
	    "a domain");
      break;


    /* The RCPT TO command requires an address as an operand. All we do
    here is to parse it for syntactic correctness. There may be any number
    of RCPT TO commands, specifying multiple senders. We build them all into
    a data structure that is in argc/argv format. The start/end values
    given by parse_extract_address are not used, as we keep only the
    extracted address. */

    case RCPT_CMD:
      if (!sender_address)
	/* The function moan_smtp_batch() does not return. */
	moan_smtp_batch(smtp_cmd_buffer, "503 No sender yet given");

      if (smtp_cmd_data[0] == 0)
	/* The function moan_smtp_batch() does not return. */
	moan_smtp_batch(smtp_cmd_buffer,
	  "501 RCPT TO must have an address operand");

      /* Check maximum number allowed */

      if (  recipients_max_expanded > 0
	 && recipients_count + 1 > recipients_max_expanded)
	/* The function moan_smtp_batch() does not return. */
	moan_smtp_batch(smtp_cmd_buffer, "%s too many recipients",
	  recipients_max_reject ? "552": "452");

      /* Apply SMTP rewrite, then extract address. Don't allow "<>" as a
      recipient address */

      recipient = rewrite_existflags & rewrite_smtp
	/* deconst ok as smtp_cmd_data was not const */
	? US rewrite_one(smtp_cmd_data, rewrite_smtp, NULL, FALSE, US"",
		      global_rewrite_rules)
	: smtp_cmd_data;

      recipient = parse_extract_address(recipient, &errmess, &start, &end,
	&recipient_domain, FALSE);

      if (!recipient)
	/* The function moan_smtp_batch() does not return. */
	moan_smtp_batch(smtp_cmd_buffer, "501 %s", errmess);

      /* If the recipient address is unqualified, qualify it if permitted. Then
      add it to the list of recipients. */

      if (!recipient_domain)
	if (f.allow_unqualified_recipient)
	  {
	  DEBUG(D_receive) debug_printf("unqualified address %s accepted\n",
	    recipient);
	  /* deconst ok as recipient was not const */
	  recipient = US rewrite_address_qualify(recipient, TRUE);
	  }
	/* The function moan_smtp_batch() does not return. */
	else
	  moan_smtp_batch(smtp_cmd_buffer,
	    "501 recipient address must contain a domain");

      receive_add_recipient(recipient, -1);
      break;


    /* The DATA command is legal only if it follows successful MAIL FROM
    and RCPT TO commands. This function is complete when a valid DATA
    command is encountered. */

    case DATA_CMD:
      if (!sender_address || recipients_count <= 0)
	/* The function moan_smtp_batch() does not return. */
	if (!sender_address)
	  moan_smtp_batch(smtp_cmd_buffer,
	    "503 MAIL FROM:<sender> command must precede DATA");
	else
	  moan_smtp_batch(smtp_cmd_buffer,
	    "503 RCPT TO:<recipient> must precede DATA");
      else
	{
	done = 3;                      /* DATA successfully achieved */
	message_ended = END_NOTENDED;  /* Indicate in middle of message */
	}
      break;


    /* The VRFY, EXPN, HELP, ETRN, ATRN and NOOP commands are ignored. */

    case VRFY_CMD: case EXPN_CMD: case HELP_CMD: case NOOP_CMD:
    case ETRN_CMD: case ATRN_CMD:
#ifndef DISABLE_WELLKNOWN
    case WELLKNOWN_CMD:
#endif
      bsmtp_transaction_linecount = receive_linecount;
      break;


    case QUIT_CMD:
      f.smtp_in_quit = TRUE;
    case OTHER_CMD:
    case EOF_CMD:
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




#ifndef DISABLE_TLS
static BOOL
smtp_log_tls_fail(const uschar * errstr)
{
const uschar * conn_info = smtp_get_connection_info();

if (Ustrncmp(conn_info, US"SMTP ", 5) == 0) conn_info += 5;
/* I'd like to get separated H= here, but too hard for now */

log_write(0, LOG_MAIN, "TLS error on %s %s", conn_info, errstr);
return FALSE;
}
#endif




#ifdef TCP_FASTOPEN
static void
tfo_in_check(void)
{
if (smtp_out_fd < 0)  return;

# ifdef __FreeBSD__
int is_fastopen;
socklen_t len = sizeof(is_fastopen);

/* The tinfo TCPOPT_FAST_OPEN bit seems unreliable, and we don't see state
TCP_SYN_RCV (as of 12.1) so no idea about data-use. */

if (getsockopt(smtp_out_fd, IPPROTO_TCP, TCP_FASTOPEN, &is_fastopen, &len) == 0)
  {
  if (is_fastopen)
    {
    DEBUG(D_receive)
      debug_printf("TFO mode connection (TCP_FASTOPEN getsockopt)\n");
    f.tcp_in_fastopen = TRUE;
    }
  }
else DEBUG(D_receive)
  debug_printf("TCP_FASTOPEN getsockopt: %s\n", strerror(errno));

# elif defined(TCP_INFO)
struct tcp_info tinfo;
socklen_t len = sizeof(tinfo);

if (getsockopt(smtp_out_fd, IPPROTO_TCP, TCP_INFO, &tinfo, &len) == 0)
  {
#  ifdef TCPI_OPT_SYN_DATA	/* FreeBSD 11,12 do not seem to have this yet */
  if (tinfo.tcpi_options & TCPI_OPT_SYN_DATA)
    {
    DEBUG(D_receive)
      debug_printf("TFO mode connection (ACKd data-on-SYN)\n");
    f.tcp_in_fastopen_data = f.tcp_in_fastopen = TRUE;
    }
#   ifdef TCPI_OPT_TFO_CHILD
  else if (tinfo.tcpi_options & TCPI_OPT_TFO_CHILD)
    {
    DEBUG(D_receive)
      debug_printf("TFO mode connection (SYN with TFO option)\n");
    f.tcp_in_fastopen = TRUE;
    }
#   endif
  else
#  endif

    /* Lacking any specific info (especially for a dataless-TFO) there is
    a faint hope of not having reached ESTABLISHED state (gotten the ACK of
    our SYN,ACK). This works for a link with roundtrip delay, but pretty much
    never for a loopback. We are called after being able to send our banner,
    and before ESTABLISHED that should only be possible on a TFO. */

    if (tinfo.tcpi_state == TCP_SYN_RECV)	/* Not seen on FreeBSD 12.1 */
    {
    DEBUG(D_receive)
      debug_printf("TFO mode connection (state TCP_SYN_RECV)\n");
    f.tcp_in_fastopen = TRUE;
    }
  }
else DEBUG(D_receive)
  debug_printf("TCP_INFO getsockopt: %s\n", strerror(errno));
# endif	/* TCP_INFO */
}
#endif	/* TCP_FASTOPEN */


static void
log_connect_tls_drop(const uschar * what, const uschar * log_msg)
{
if (log_reject_target)
  log_write(L_connection_reject,
    log_reject_target, "%s%s%#Y dropped by %s%s%s",
    LOGGING(dnssec) && sender_host_dnssec ? US" DS" : US"",
    host_and_ident(TRUE),
    add_tls_info_for_log(NULL),
    what,
    log_msg ? US": " : US"", log_msg);
}




#if !HAVE_IPV6 && !defined(NO_IP_OPTIONS)
/* IP options: log and reject the connection.

Deal with any IP options that are set. On the systems I have looked at,
the value of MAX_IPOPTLEN has been 40, meaning that there should never be
more logging data than will fit in big_buffer. Nevertheless, after somebody
questioned this code, I've added in some paranoid checking.

Given the disuse of options on the internet as of 2024 I'm tempted to
drop the detailed parsing and logging. */

# ifdef GLIBC_IP_OPTIONS
#  if (!defined __GLIBC__) || (__GLIBC__ < 2)
#   define OPTSTYLE 1
#  else
#   define OPTSTYLE 2
#  endif
# elif defined DARWIN_IP_OPTIONS
#  define OPTSTYLE 2
# elif defined MUSL_IP_OPTIONS
#  define OPTSTYLE 2
# else
#  define OPTSTYLE 3
#  endif

# if OPTSTYLE == 1
#  define EXIM_IP_OPT_T	struct ip_options
#  define OPTSTART	(ipopt->__data)
# elif OPTSTYLE == 2
#  define EXIM_IP_OPT_T	struct ip_opts
#  define OPTSTART	(ipopt->ip_opts);
# else
#  define EXIM_IP_OPT_T	struct ipoption
#  define OPTSTART	(ipopt->ipopt_list);
# endif

static BOOL
smtp_in_reject_options(EXIM_IP_OPT_T * ipopt, EXIM_SOCKLEN_T optlen)
{
uschar * p, * pend = big_buffer + big_buffer_size;
uschar * adptr;
int optcount, sprint_len;
struct in_addr addr;
uschar * optstart = US OPTSTART;

DEBUG(D_receive) debug_printf("IP options exist\n");

p = Ustpcpy(big_buffer, "IP options on incoming call:");

for (uschar * opt = optstart; opt && opt < US (ipopt) + optlen; )
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
      if (!
# if OPTSTYLE == 1
	   string_format(p, pend-p, " %s [@%s%n",
	     *opt == IPOPT_SSRR ? "SSRR" : "LSRR",
	     inet_ntoa(*(struct in_addr *)&ipopt->faddr),
	     &sprint_len)
# elif OPTSTYLE == 2
	   string_format(p, pend-p, " %s [@%s%n",
	     *opt == IPOPT_SSRR ? "SSRR" : "LSRR",
	     inet_ntoa(ipopt->ip_dst),
	     &sprint_len)
# else
	   string_format(p, pend-p, " %s [@%s%n",
	     *opt == IPOPT_SSRR ? "SSRR" : "LSRR",
	     inet_ntoa(ipopt->ipopt_dst),
	     &sprint_len)
# endif
	  )
	opt = NULL;
      else
	{
	p += sprint_len;
	optcount = (opt[1] - 3) / sizeof(struct in_addr);
	adptr = opt + 3;
	while (optcount-- > 0)
	  {
	  memcpy(&addr, adptr, sizeof(addr));
	  if (!string_format(p, pend - p - 1, "%s%s%n",
		optcount == 0 ? ":" : "@", inet_ntoa(addr), &sprint_len))
	    { opt = NULL; goto bad_srr; }
	  p += sprint_len;
	  adptr += sizeof(struct in_addr);
	  }
	*p++ = ']';
	opt += opt[1];
	}
bad_srr:    break;

    default:
      if (pend - p < 4 + 3*opt[1])
	opt = NULL;
      else
	{
	p = Ustpcpy(p, "[ ");
	for (int i = 0; i < opt[1]; i++)
	  p += sprintf(CS p, "%2.2x ", opt[i]);
	*p++ = ']';
	opt += opt[1];
	}
      break;
    }

*p = '\0';
log_write(0, LOG_MAIN, "%s", big_buffer);

/* Refuse any call with IP options. This is what tcpwrappers 7.5 does. */

log_write(0, LOG_MAIN|LOG_REJECT,
  "connection from %s refused (IP options)", host_and_ident(FALSE));

smtp_printf("554 SMTP service not available\r\n", SP_NO_MORE);
return FALSE;
}
#endif  /*!HAVE_IPV6 && !defined(NO_IP_OPTIONS)*/


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
int esclen;
uschar *user_msg, *log_msg;
uschar *code, *esc;
uschar *p, *s;
gstring * ss;

gettimeofday(&smtp_connection_start, NULL);
for (smtp_ch_index = 0; smtp_ch_index < SMTP_HBUFF_SIZE; smtp_ch_index++)
  smtp_connection_had[smtp_ch_index] = SCH_NONE;
smtp_ch_index = 0;

/* Default values for certain variables */

fl.helo_seen = fl.esmtp = fl.helo_accept_junk = FALSE;
smtp_mailcmd_count = 0;
count_nonmail = TRUE_UNSET;
synprot_error_count = unknown_command_count = nonmail_command_count = 0;
smtp_delay_mail = smtp_rlm_base;
fl.auth_advertised = FALSE;
f.smtp_in_pipelining_advertised = f.smtp_in_pipelining_used = FALSE;
f.pipelining_enable = TRUE;
sync_cmd_limit = NON_SYNC_CMD_NON_PIPELINING;
smtp_notquit_reason = NULL;		/* For avoiding loop in not-quit exit */

/* If receiving by -bs from a trusted user, or testing with -bh, we allow
authentication settings from -oMaa to remain in force. */

if (!host_checking && !f.sender_host_notsocket)
  sender_host_auth_pubname = sender_host_authenticated = NULL;
authenticated_by = NULL;

#ifndef DISABLE_TLS
if (!atrn_mode)
  {
  tls_in.ver = tls_in.cipher = tls_in.peerdn = NULL;
  tls_in.ourcert = tls_in.peercert = NULL;
  tls_in.sni = NULL;
  tls_in.ocsp = OCSP_NOT_REQ;
  }
fl.tls_advertised = FALSE;
#endif
fl.dsn_advertised = FALSE;
#ifdef SUPPORT_I18N
fl.smtputf8_advertised = FALSE;
#endif

/* Reset ACL connection variables */

acl_var_c = NULL;

/* Allow for trailing 0 in the command and data buffers.  Tainted. */

smtp_cmd_buffer = store_get_perm(2*SMTP_CMD_BUFFER_SIZE + 2, GET_TAINTED);

smtp_cmd_buffer[0] = 0;
smtp_data_buffer = smtp_cmd_buffer + SMTP_CMD_BUFFER_SIZE + 1;

smtp_resp_buffer = store_get_perm(SMTP_RESP_BUFFER_SIZE, GET_UNTAINTED);

/* For batched input, the protocol setting can be overridden from the
command line by a trusted caller. */

if (smtp_batched_input)
  { if (!received_protocol) received_protocol = US"local-bsmtp"; }

/* For non-batched SMTP input, the protocol setting is forced here. It will be
reset later if any of EHLO/AUTH/STARTTLS are received. */

else
  received_protocol =
    (sender_host_address ? protocols : protocols_local) [pnormal];

/* Set up the buffer for inputting using direct read() calls, and arrange to
call the local functions instead of the standard C ones. */

smtp_buf_init();

#ifndef DISABLE_TLS
if (atrn_mode && tls_in.active.sock >= 0)
  {
  receive_getc = tls_getc;
  receive_getbuf = tls_getbuf;
  receive_get_cache = tls_get_cache;
  receive_hasc = tls_hasc;
  receive_ungetc = tls_ungetc;
  receive_feof = tls_feof;
  receive_ferror = tls_ferror;
  }
else
#endif
  {
  receive_getc = smtp_getc;
  receive_getbuf = smtp_getbuf;
  receive_get_cache = smtp_get_cache;
  receive_hasc = smtp_hasc;
  receive_ungetc = smtp_ungetc;
  receive_feof = smtp_feof;
  receive_ferror = smtp_ferror;
  }
lwr_receive_getc = NULL;
lwr_receive_getbuf = NULL;
lwr_receive_hasc = NULL;
lwr_receive_ungetc = NULL;

/* Set up the message size limit; this may be host-specific */

GET_OPTION("message_size_limit");
thismessage_size_limit = expand_string_integer(message_size_limit, TRUE);
if (expand_string_message)
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

if (!f.sender_host_unknown)
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

  if (!host_checking && !f.sender_host_notsocket)
    {
# if OPTSTYLE == 1
    EXIM_SOCKLEN_T optlen = sizeof(EXIM_IP_OPT_T) + MAX_IPOPTLEN;
    EXIM_IP_OPT_T * ipopt = store_get(optlen, GET_UNTAINTED);
# else
    EXIM_IP_OPT_T ipoptblock;
    EXIM_IP_OPT_T * ipopt = &ipoptblock;
    EXIM_SOCKLEN_T optlen = sizeof(EXIM_IP_OPT_T);
# endif

    /* Occasional genuine failures of getsockopt() have been seen - for
    example, "reset by peer". Therefore, just log and give up on this
    call, unless the error is ENOPROTOOPT. This error is given by systems
    that have the interfaces but not the mechanism - e.g. GNU/Hurd at the time
    of writing. So for that error, carry on - we just can't do an IP options
    check. */

    DEBUG(D_receive) debug_printf("checking for IP options\n");

    if (  smtp_out_fd < 0
       || getsockopt(smtp_out_fd, IPPROTO_IP, IP_OPTIONS, US ipopt,
		    &optlen) < 0)
      {
      if (errno != ENOPROTOOPT)
        {
        log_write(0, LOG_MAIN, "getsockopt() failed from %s: %s",
          host_and_ident(FALSE), strerror(errno));
        smtp_printf("451 SMTP service not available\r\n", SP_NO_MORE);
        return FALSE;
        }
      }

    /* Deal with any IP options that are set. On the systems I have looked at,
    the value of MAX_IPOPTLEN has been 40, meaning that there should never be
    more logging data than will fit in big_buffer. Nevertheless, after somebody
    questioned this code, I've added in some paranoid checking. */

    else if (optlen > 0)
      return smtp_in_reject_options(ipopt, optlen);

    /* Length of options = 0 => there are no options */

    else DEBUG(D_receive) debug_printf("no IP options found\n");
    }
#endif  /* HAVE_IPV6 && !defined(NO_IP_OPTIONS) */

  /* Set keep-alive in socket options. The option is on by default. This
  setting is an attempt to get rid of some hanging connections that stick in
  read() when the remote end (usually a dialup) goes away. */

  if (smtp_accept_keepalive && !f.sender_host_notsocket && smtp_out_fd >= 0)
    ip_keepalive(smtp_out_fd, sender_host_address, FALSE);

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

  /* Test for explicit connection rejection */

  if (verify_check_host(&host_reject_connection) == OK)
    {
    log_write(L_connection_reject, LOG_MAIN|LOG_REJECT, "refused connection "
      "from %s (host_reject_connection)", host_and_ident(FALSE));
#ifndef DISABLE_TLS
    if (!tls_in.on_connect)
#endif
      smtp_printf("554 SMTP service not available\r\n", SP_NO_MORE);
    return FALSE;
    }

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
        "please try again later\r\n", SP_NO_MORE, smtp_active_hostname);
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
    smtp_printf("421 %s: Too much load; please try again later\r\n", SP_NO_MORE,
      smtp_active_hostname);
    return FALSE;
    }

  /* Determine whether unqualified senders or recipients are permitted
  for this host. Unfortunately, we have to do this every time, in order to
  set the flags so that they can be inspected when considering qualifying
  addresses in the headers. For a site that permits no qualification, this
  won't take long, however. */

  f.allow_unqualified_sender =
    verify_check_host(&sender_unqualified_hosts) == OK;

  f.allow_unqualified_recipient =
    verify_check_host(&recipient_unqualified_hosts) == OK;

  /* Determine whether HELO/EHLO is required for this host. The requirement
  can be hard or soft. */

  fl.helo_verify_required = verify_check_host(&helo_verify_hosts) == OK;
  if (!fl.helo_verify_required)
    fl.helo_verify = verify_check_host(&helo_try_verify_hosts) == OK;

  /* Determine whether this hosts is permitted to send syntactic junk
  after a HELO or EHLO command. */

  fl.helo_accept_junk = verify_check_host(&helo_accept_junk_hosts) == OK;
  }

/* Expand recipients_max, if needed */
 {
  const uschar * rme = expand_string(recipients_max);
  recipients_max_expanded = atoi(CCS rme);
 }
/* For batch SMTP input we are now done. */

if (smtp_batched_input) return TRUE;

#if defined(SUPPORT_PROXY) || defined(SUPPORT_SOCKS) || defined(EXPERIMENTAL_XCLIENT)
proxy_session = FALSE;
#endif

#ifdef SUPPORT_PROXY
/* If valid Proxy Protocol source is connecting, set up session.
Failure will not allow any SMTP function other than QUIT. */

f.proxy_session_failed = FALSE;
if (proxy_protocol_host())
  {
  os_non_restarting_signal(SIGALRM, command_timeout_handler);
  proxy_protocol_setup();
  }
#endif

/* Run the connect ACL if it exists */

user_msg = NULL;
GET_OPTION("acl_smtp_connect");
if (acl_smtp_connect)
  {
  int rc;
  if ((rc = acl_check(ACL_WHERE_CONNECT, NULL, acl_smtp_connect, &user_msg,
		      &log_msg)) != OK)
    {
#ifndef DISABLE_TLS
    if (tls_in.on_connect)
      log_connect_tls_drop(US"'connect' ACL", log_msg);
    else
#endif
      (void) smtp_handle_acl_fail(ACL_WHERE_CONNECT, rc, user_msg, log_msg);
    return FALSE;
    }
  }

/* Set up the initial message for a two-way SMTP connection. It may contain
newlines, which then cause a multi-line response to be given. */

code = US"220";   /* Default status code */
esc = US"";       /* Default extended status code */
esclen = 0;       /* Length of esc */

if (user_msg)
  {
  int codelen = 3;
  s = user_msg;
  smtp_message_code(&code, &codelen, &s, NULL, TRUE);
  if (codelen > 4)
    {
    esc = code + 4;
    esclen = codelen - 4;
    }
  }
else
  {
  GET_OPTION("smtp_banner");
  if (!(s = expand_string(smtp_banner)))
    {
    log_write(0, f.expand_string_forcedfail ? LOG_MAIN : LOG_MAIN|LOG_PANIC_DIE,
      "Expansion of %q (smtp_banner) failed: %s",
      smtp_banner, expand_string_message);
    /* for force-fail */
  #ifndef DISABLE_TLS
    if (tls_in.on_connect) tls_close(NULL, TLS_SHUTDOWN_WAIT);
  #endif
    return FALSE;
    }
  }

/* Remove any terminating newlines; might as well remove trailing space too */

p = s + Ustrlen(s);
while (p > s && isspace(p[-1])) p--;
s = string_copyn(s, p-s);

/* It seems that CC:Mail is braindead, and assumes that the greeting message
is all contained in a single IP packet. The original code wrote out the
greeting using several calls to fprint/fputc, and on busy servers this could
cause it to be split over more than one packet - which caused CC:Mail to fall
over when it got the second part of the greeting after sending its first
command. Sigh. To try to avoid this, build the complete greeting message
first, and output it in one fell swoop. This gives a better chance of it
ending up as a single packet. */

ss = string_get(256);

p = s;
do       /* At least once, in case we have an empty string */
  {
  int len;
  const uschar * linebreak = Ustrchr(p, '\n');
  ss = string_catn(ss, code, 3);
  if (!linebreak)
    {
    len = Ustrlen(p);
    ss = string_catn(ss, US" ", 1);
    }
  else
    {
    len = linebreak - p;
    ss = string_catn(ss, US"-", 1);
    }
  ss = string_catn(ss, esc, esclen);
  ss = string_catn(ss, p, len);
  ss = string_catn(ss, US"\r\n", 2);
  p += len;
  if (linebreak) p++;
  }
while (*p);

/* Start up TLS if tls_on_connect is set. This is for supporting the legacy
smtps port for use with older style SSL MTAs. */

#ifndef DISABLE_TLS
if (tls_in.on_connect)
  {
  gstring * g = verify_check_host(&tls_early_banner_hosts) == OK ? ss : NULL;

  if (tls_server_start(&user_msg, g) != OK)
    return smtp_log_tls_fail(user_msg);
  cmd_list[CL_TLAU].is_mail_cmd = TRUE;
  }
#endif

#ifndef DISABLE_PIPE_CONNECT
fl.pipe_connect_acceptable = sender_host_address
		    && verify_check_host(&pipe_connect_advertise_hosts) == OK;
#endif

if (gstring_length(ss) == 0)			/* banner already sent */
  {
  if (f.running_in_test_harness)		/* make visible to testsuite */
    {
    for (int i = 20; i && check_sync(WBR_DATA_OR_EOF); i--) millisleep(5);
    log_write(0, LOG_MAIN, "Ci=%s SMTP peer appears to have %s our banner",
		connection_id, check_sync(WBR_DATA_OR_EOF) ? "NOT SEEN" : "seen");
    }
  }
else						/* not already sent */
  {
  /* Before we write the banner, check that there is no input pending, unless
  this synchronisation check is disabled. */

#ifndef DISABLE_PIPE_CONNECT
  fl.pipe_connect_acceptable =
       sender_host_address
    && verify_check_host(&pipe_connect_advertise_hosts) == OK;

  if (!check_sync(WBR_DATA_ONLY))
    if (fl.pipe_connect_acceptable)
      f.smtp_in_early_pipe_used = TRUE;
    else
#else
  if (!check_sync(WBR_DATA_ONLY))
#endif
      {
      unsigned nchars = 128;
      uschar * buf = receive_getbuf(&nchars);		/* destructive read */

      if (buf)
	log_write(0, LOG_MAIN|LOG_REJECT, "SMTP protocol "
	  "synchronization error (input sent without waiting for greeting): "
	  "rejected connection from %s input=%q", host_and_ident(TRUE),
	  string_printing(string_copyn(buf, nchars)));
      else
	log_write(0, LOG_MAIN|LOG_REJECT, "Error or EOF on input from %s",
	  host_and_ident(TRUE));
      smtp_printf("554 SMTP synchronization error\r\n", SP_NO_MORE);
      return FALSE;
      }

  /* Now output the banner */

    smtp_printf("%Y",
#ifndef DISABLE_PIPE_CONNECT
      fl.pipe_connect_acceptable && pipeline_connect_sends(),
#else
      SP_NO_MORE,
#endif
      ss);
  }

/* Attempt to see if we sent the banner before the last ACK of the 3-way
handshake arrived.  If so we must have managed a TFO. */

#ifdef TCP_FASTOPEN
if (sender_host_address && !f.sender_host_notsocket && !atrn_mode)
  tfo_in_check();
#endif

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

int
synprot_error(int type, int code, uschar *data, uschar *errmess)
{
int yield = -1;

#ifndef DISABLE_EVENT
event_raise(event_action,
  L_smtp_syntax_error ? US"smtp:fail:syntax" : US"smtp:fail:protocol",
  errmess, NULL);
#endif

log_write(type, LOG_MAIN, "SMTP %s error in %q %s %s",
  type == L_smtp_syntax_error ? "syntax" : "protocol",
  string_printing(smtp_cmd_buffer), host_and_ident(TRUE), errmess);

GET_OPTION("smtp_max_synprot_errors");
if (++synprot_error_count > smtp_max_synprot_errors)
  {
  yield = 1;
  log_write(0, LOG_MAIN|LOG_REJECT, "SMTP call from %s dropped: too many "
    "syntax or protocol errors (last command was %q, %Y)",
    host_and_ident(FALSE), string_printing(smtp_cmd_buffer),
    s_connhad_log(NULL)
    );
  }

if (code > 0)
  {
  BOOL more = yield == 1;
  smtp_printf("%d%c%s%s%s\r\n", more, code, more ? '-' : ' ',
    data ? data : US"", data ? US": " : US"", errmess);
  if (more)
    {
    smtp_notquit_exit(US"bad-command-synprot", string_sprintf("%d", code),
		      US"Too many syntax or protocol errors");
    DEBUG(D_any) debug_printf_indent("SMTP(close)>>\n");
#ifndef DISABLE_TLS
    tls_close(NULL, TLS_SHUTDOWN_WAIT);
#endif
    smtp_inout_close();
    }
  }

return yield;
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
smtp_respond(uschar * code, int codelen, BOOL final, uschar * msg)
{
int esclen = 0;
uschar *esc = US"";

if (!final && f.no_multiline_responses) return;

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

if (fl.rcpt_in_progress)
  {
  if (!rcpt_smtp_response)
    rcpt_smtp_response = string_copy(msg);
  else if (fl.rcpt_smtp_response_same &&
           Ustrcmp(rcpt_smtp_response, msg) != 0)
    fl.rcpt_smtp_response_same = FALSE;
  fl.rcpt_in_progress = FALSE;
  }

/* Now output the message, splitting it up into multiple lines if necessary.
We only handle pipelining these responses as far as nonfinal/final groups,
not the whole MAIL/RCPT/DATA response set. */

for (uschar * nl;;)
  if (!(nl = Ustrchr(msg, '\n')))
    {
    smtp_printf("%.3s%c%.*s%s\r\n", !final, code, final ? ' ':'-', esclen, esc, msg);
    return;
    }
  else if (nl[1] == 0 || f.no_multiline_responses)
    {
    smtp_printf("%.3s%c%.*s%.*s\r\n", !final, code, final ? ' ':'-', esclen, esc,
      (int)(nl - msg), msg);
    return;
    }
  else
    {
    smtp_printf("%.3s-%.*s%.*s\r\n", SP_MORE, code, esclen, esc, (int)(nl - msg), msg);
    msg = nl + 1;
    Uskip_whitespace(&msg);
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
  check_valid   if true, verify the response code

Returns:        nothing
*/

void
smtp_message_code(uschar **code, int *codelen, uschar **msg, uschar **log_msg,
  BOOL check_valid)
{
uschar * match;
int len;

if (!msg || !*msg || !regex_match(regex_smtp_code, *msg, -1, &match))
  return;

len = Ustrlen(match);
if (check_valid && (*msg)[0] != (*code)[0])
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "configured error code starts with "
    "incorrect digit (expected %c) in %q", (*code)[0], *msg);
  if (log_msg && *log_msg == *msg)
    *log_msg = string_sprintf("%s %s", *code, *log_msg + len);
  }
else
  {
  *code = *msg;
  *codelen = len;    /* Includes final space */
  }
*msg += len;         /* Chop the code off the message */
return;
}




/*************************************************
*           Handle an ACL failure                *
*************************************************/

/* This function is called when acl_check() fails. As well as calls from within
this module, it is called from receive.c for an ACL after DATA. It sorts out
logging the incident, and sends the error response. A message containing
newlines is turned into a multiline SMTP response, but for logging, only the
first line is used.

There's a table of default permanent failure response codes to use in
globals.c, along with the table of names. VFRY is special. Despite RFC1123 it
defaults disabled in Exim. However, discussion in connection with RFC 821bis
(aka RFC 2821) has concluded that the response should be 252 in the disabled
state, because there are broken clients that try VRFY before RCPT. A 5xx
response should be given only when the address is positively known to be
undeliverable. Sigh. We return 252 if there is no VRFY ACL or it provides
no explicit code, but if there is one we let it know best.
Also, for ETRN, 458 is given on refusal, and for AUTH, 503.

From Exim 4.63, it is possible to override the response code details by
providing a suitable response code string at the start of the message provided
in user_msg. The code's first digit is checked for validity.

Arguments:
  where        where the ACL was called from
  rc           the failure code
  user_msg     a message that can be included in an SMTP response
  log_msg      a message for logging

Returns:     0 in most cases
             2 if the failure code was FAIL_DROP, in which case the
               SMTP connection should be dropped (this value fits with the
               "done" variable in smtp_setup_msg() below)
*/

int
smtp_handle_acl_fail(int where, int rc, uschar * user_msg, uschar * log_msg)
{
BOOL drop = rc == FAIL_DROP;
int codelen = 3;
uschar *smtp_code;
uschar *lognl;
uschar *sender_info = US"";
uschar *what;

if (drop) rc = FAIL;

/* Set the default SMTP code, and allow a user message to change it. */

smtp_code = rc == FAIL ? acl_wherecodes[where] : US"451";
smtp_message_code(&smtp_code, &codelen, &user_msg, &log_msg,
  where != ACL_WHERE_VRFY);

/* Get info for logging.
We used to have sender_address here; however, there was a bug that was not
updating sender_address after a rewrite during a verify. When this bug was
fixed, sender_address at this point became the rewritten address. I'm not sure
this is what should be logged, so I've changed to logging the unrewritten
address to retain backward compatibility. */

switch (where)
  {
#ifdef WITH_CONTENT_SCAN
  case ACL_WHERE_MIME:		what = US"during MIME ACL checks";	break;
#endif
  case ACL_WHERE_PREDATA:	what = US"DATA";			break;
  case ACL_WHERE_DATA:		what = US"after DATA";			break;
#ifndef DISABLE_PRDR
  case ACL_WHERE_PRDR:		what = US"after DATA PRDR";		break;
#endif
  default:
    {
    uschar * place = smtp_cmd_data ? smtp_cmd_data : US"in \"connect\" ACL";
    int lim = 100;

    if (where == ACL_WHERE_AUTH)	/* avoid logging auth creds */
      {
      uschar * s = smtp_cmd_data;
      Uskip_nonwhite(&s);
      lim = s - smtp_cmd_data;	/* stop after method */
      }
    what = string_sprintf("%s %.*s", acl_wherenames[where], lim, place);
    }
  }
switch (where)
  {
  case ACL_WHERE_RCPT:
  case ACL_WHERE_DATA:
#ifdef WITH_CONTENT_SCAN
  case ACL_WHERE_MIME:
#endif
    sender_info = string_sprintf(" F=<%s>%s%s%s%s",
      sender_address_unrewritten ? sender_address_unrewritten : sender_address,
      sender_host_authenticated ? US" A="                                    : US"",
      sender_host_authenticated ? sender_host_authenticated                  : US"",
      sender_host_authenticated && authenticated_id ? US":"                  : US"",
      sender_host_authenticated && authenticated_id ? authenticated_id       : US""
      );
  break;
  }

/* If there's been a sender verification failure with a specific message, and
we have not sent a response about it yet, do so now, as a preliminary line for
failures, but not defers. However, always log it for defer, and log it for fail
unless the sender_verify_fail log selector has been turned off. */

if (sender_verified_failed &&
    !testflag(sender_verified_failed, af_sverify_told))
  {
  BOOL save_rcpt_in_progress = fl.rcpt_in_progress;
  fl.rcpt_in_progress = FALSE;  /* So as not to treat these as the error */

  setflag(sender_verified_failed, af_sverify_told);

  if (rc != FAIL || LOGGING(sender_verify_fail))
    log_write(0, LOG_MAIN|LOG_REJECT, "%s sender verify %s for <%s>%s",
      host_and_ident(TRUE),
      ((sender_verified_failed->special_action & 255) == DEFER)? "defer":"fail",
      sender_verified_failed->address,
      (sender_verified_failed->message == NULL)? US"" :
      string_sprintf(": %s", sender_verified_failed->message));

  if (rc == FAIL && sender_verified_failed->user_message)
    smtp_respond(smtp_code, codelen, SR_NOT_FINAL, string_sprintf(
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

  fl.rcpt_in_progress = save_rcpt_in_progress;
  }

/* Sort out text for logging */

log_msg = log_msg ? string_sprintf(": %s", log_msg) : US"";
if ((lognl = Ustrchr(log_msg, '\n'))) *lognl = 0;

/* Send permanent failure response to the command, but the code used isn't
always a 5xx one - see comments at the start of this function. If the original
rc was FAIL_DROP we drop the connection and yield 2. */

if (rc == FAIL)
  smtp_respond(smtp_code, codelen, SR_FINAL,
    user_msg ? user_msg : US"Administrative prohibition");

/* Send temporary failure response to the command. Don't give any details,
unless acl_temp_details is set. This is TRUE for a callout defer, a "defer"
verb, and for a header verify when smtp_return_error_details is set.

This conditional logic is all somewhat of a mess because of the odd
interactions between temp_details and return_error_details. One day it should
be re-implemented in a tidier fashion. */

else
  if (f.acl_temp_details && user_msg)
    {
    if (  smtp_return_error_details
       && sender_verified_failed
       && sender_verified_failed->message
       )
      smtp_respond(smtp_code, codelen, SR_NOT_FINAL, sender_verified_failed->message);

    smtp_respond(smtp_code, codelen, SR_FINAL, user_msg);
    }
  else
    smtp_respond(smtp_code, codelen, SR_FINAL,
      US"Temporary local problem - please try later");

smtp_fflush(SFF_UNCORK);

/* Log the incident to the logs that are specified by log_reject_target
(default main, reject). This can be empty to suppress logging of rejections. If
the connection is not forcibly to be dropped, return 0. Otherwise, log why it
is closing if required and return 2.  */

if (log_reject_target)
  log_write(where == ACL_WHERE_CONNECT ? L_connection_reject : 0,
    log_reject_target, "%s%s%#Y%s%#Y%#Y %srejected %s%s",
    LOGGING(dnssec) && sender_host_dnssec ? US" DS" : US"",
    host_and_ident(TRUE),
    add_tls_info_for_log(NULL),
    sender_info,
    add_spf_info_for_log(NULL),
    add_dmarc_info_for_log(NULL),
    rc == FAIL ? US"" : US"temporarily ",
    what, log_msg);

if (!drop) return 0;

log_close_event(US"by DROP in ACL");

/* Run the not-quit ACL, but without any custom messages. This should not be a
problem, because we get here only if some other ACL has issued "drop", and
in that case, *its* custom messages will have been used above. */

smtp_notquit_exit(US"acl-drop", NULL, NULL);

/* An overenthusiastic fail2ban/iptables implimentation has been seen to result
in the TCP conn staying open, and retrying, despite this process exiting. A
malicious client could possibly do the same, tying up server netowrking
resources. Close the socket explicitly to try to avoid that (there's a note in
the Linux socket(7) manpage, SO_LINGER para, to the effect that exit() without
close() results in the socket always lingering). */

(void) poll_one_fd(smtp_in_fd, POLLIN, 200);
DEBUG(D_any) debug_printf_indent("SMTP(close)>>\n");
smtp_inout_close();

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
may re-enter this function, there is a recursion check.

Arguments:
  reason          What $smtp_notquit_reason will be set to in the ACL;
                    if NULL, the ACL is not run
  code            The error code to return as part of the response
  defaultrespond  The default message if there's no user_msg

Returns:          Nothing
*/

void
smtp_notquit_exit(const uschar * reason, uschar * code,
  const uschar * defaultrespond, ...)
{
uschar * user_msg = NULL, * log_msg = NULL;

/* When a bad-command-excess is seen in the CHUNKING sub-handler, it only
reports as EOF to the toplevel command loop - which handles EOF for the
traditional DATA mode and calls here because the line dropped. Maybe we
should complexify that reporting value?  For now just ignore the second call
we get when the line goes on to drop when CHUNKING. */

if (smtp_notquit_reason)
  {
#ifdef notdef
  log_write(0, LOG_PANIC,
    "smtp_notquit_exit() called more than once (%s, prev: %s)",
    reason, smtp_notquit_reason);
#endif
  return;
  }
smtp_notquit_reason = reason;

/* Call the not-QUIT ACL, if there is one, unless no reason is given. */

GET_OPTION("acl_smtp_notquit");
if (acl_smtp_notquit && reason)
  if (acl_check(ACL_WHERE_NOTQUIT, NULL, acl_smtp_notquit, &user_msg,
		      &log_msg) == ERROR)
    log_write(0, LOG_MAIN|LOG_PANIC, "ACL for not-QUIT returned ERROR: %s",
      log_msg);

/* Write an SMTP response if we are expected to give one. As the default
responses are all internal, they should be reasonable size. */

if (code && defaultrespond)
  {
  if (user_msg)
    smtp_respond(code, 3, SR_FINAL, user_msg);
  else
    {
    gstring * g;
    va_list ap;

    va_start(ap, defaultrespond);
    g = string_vformat(NULL, SVFMT_EXTEND|SVFMT_REBUFFER, CCS defaultrespond, ap);
    va_end(ap);
    smtp_printf("%s %Y\r\n", SP_NO_MORE, code, g);
    }
  smtp_fflush(SFF_UNCORK);
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

HDEBUG(D_receive) debug_printf("verifying EHLO/HELO argument %q\n",
  sender_helo_name);

if (sender_helo_name == NULL)
  {
  HDEBUG(D_receive) debug_printf("no EHLO/HELO command was issued\n");
  }

/* Deal with the case of -bs without an IP address */

else if (sender_host_address == NULL)
  {
  HDEBUG(D_receive) debug_printf("no client IP address: assume success\n");
  f.helo_verified = TRUE;
  }

/* Deal with the more common case when there is a sending IP address */

else if (sender_helo_name[0] == '[')
  {
  f.helo_verified = Ustrncmp(sender_helo_name+1, sender_host_address,
    Ustrlen(sender_host_address)) == 0;

#if HAVE_IPV6
  if (!f.helo_verified)
    {
    if (strncmpic(sender_host_address, US"::ffff:", 7) == 0)
      f.helo_verified = Ustrncmp(sender_helo_name + 1,
        sender_host_address + 7, Ustrlen(sender_host_address) - 7) == 0;
    }
#endif

  HDEBUG(D_receive)
    { if (f.helo_verified) debug_printf("matched host address\n"); }
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
    if ((f.helo_verified = strcmpic(sender_host_name, sender_helo_name) == 0))
      {
      sender_helo_dnssec = sender_host_dnssec;
      HDEBUG(D_receive) debug_printf("matched host name\n");
      }
    else
      {
      uschar **aliases = sender_host_aliases;
      while (*aliases)
        if ((f.helo_verified = strcmpic(*aliases++, sender_helo_name) == 0))
	  {
	  sender_helo_dnssec = sender_host_dnssec;
	  break;
	  }

      HDEBUG(D_receive) if (f.helo_verified)
          debug_printf("matched alias %s\n", *(--aliases));
      }

  /* Final attempt: try a forward lookup of the helo name */

  if (!f.helo_verified)
    {
    int rc;
    host_item h =
      {.name = sender_helo_name, .address = NULL, .mx = MX_NONE, .next = NULL};
    dnssec_domains d =
      {.request = US"*", .require = US""};

    HDEBUG(D_receive) debug_printf("getting IP address for %s\n",
      sender_helo_name);
    rc = host_find_bydns(&h, NULL, HOST_FIND_BY_A | HOST_FIND_BY_AAAA,
			  NULL, NULL, NULL, &d, NULL, NULL);
    if (rc == HOST_FOUND || rc == HOST_FOUND_LOCAL)
      for (host_item * hh = &h; hh; hh = hh->next)
        if (Ustrcmp(hh->address, sender_host_address) == 0)
          {
          f.helo_verified = TRUE;
	  if (h.dnssec_used == DS_YES) sender_helo_dnssec = TRUE;
          HDEBUG(D_receive)
            debug_printf("IP address for %s matches calling address\n"
	      "Forward DNS security status: %sverified\n",
              sender_helo_name, sender_helo_dnssec ? "" : "un");
          break;
          }
    }
  }

if (!f.helo_verified) f.helo_verify_failed = TRUE;  /* We've tried ... */
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
smtp_user_msg(uschar * code, uschar * user_msg)
{
int len = 3;
smtp_message_code(&code, &len, &user_msg, NULL, TRUE);
smtp_respond(code, len, SR_FINAL, user_msg);
}



static int
smtp_in_auth(auth_instance *au, uschar ** smtp_resp, uschar ** errmsg)
{
const uschar *set_id = NULL;
int rc;

/* Set up globals for error messages */

authenticator_name = au->drinst.name;
driver_srcfile = au->drinst.srcfile;
driver_srcline = au->drinst.srcline;

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

for (int i = 0; i < AUTH_VARS; i++) auth_vars[i] = NULL;
expand_nmax = 0;
expand_nlength[0] = 0;   /* $0 contains nothing */

  {
  auth_info * ai = au->drinst.info;
  rc = (ai->servercode)(au, smtp_cmd_data);
  }
if (au->set_id) set_id = expand_string(au->set_id);
expand_nmax = -1;        /* Reset numeric variables */
for (int i = 0; i < AUTH_VARS; i++) auth_vars[i] = NULL;   /* Reset $auth<n> */
driver_srcfile = authenticator_name = NULL; driver_srcline = 0;

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
      if (set_id) authenticated_id = string_copy_perm(set_id, TRUE);
      sender_host_authenticated = au->drinst.name;
      sender_host_auth_pubname  = au->public_name;
      authentication_failed = FALSE;
      authenticated_fail_id = NULL;   /* Impossible to already be set? */

      received_protocol =
	(sender_host_address ? protocols : protocols_local)
	  [
	  tls_in.on_connect && LOGGING(tls_on_connect)
	  ? ponconn + (pextend + pauthed)/2
	  : pnormal + pextend + pauthed + (tls_in.active.sock >= 0 ? pcrpted:0)
	  ];
      *smtp_resp = *errmsg = US"235 Authentication succeeded";
      authenticated_by = au;
      break;
      }

    /* Authentication succeeded, but we failed to expand the set_id string.
    Treat this as a temporary error. */

    auth_defer_msg = expand_string_message;
    /* Fall through */

  case DEFER:
    if (set_id) authenticated_fail_id = string_copy_perm(set_id, TRUE);
    *smtp_resp = string_sprintf("435 Unable to authenticate at present%s",
      auth_defer_user_msg);
    *errmsg = string_sprintf("435 Unable to authenticate at present%s: %s",
      set_id, auth_defer_msg);
    break;

  case BAD64:
    *smtp_resp = *errmsg = US"501 Invalid base64 data";
    break;

  case CANCELLED:
    *smtp_resp = *errmsg = US"501 Authentication cancelled";
    break;

  case UNEXPECTED:
    *smtp_resp = *errmsg = US"553 Initial data not expected";
    break;

  case FAIL:
    if (set_id) authenticated_fail_id = string_copy_perm(set_id, TRUE);
    *smtp_resp = US"535 Incorrect authentication data";
    *errmsg = string_sprintf("535 Incorrect authentication data%s", set_id);
    break;

  default:
    if (set_id) authenticated_fail_id = string_copy_perm(set_id, TRUE);
    *smtp_resp = US"435 Internal error";
    *errmsg = string_sprintf("435 Internal error%s: return %d from authentication "
      "check", set_id, rc);
    break;
  }

return rc;
}





static int
qualify_recipient(uschar ** recipient, uschar * smtp_cmd_data, uschar * tag)
{
if (f.allow_unqualified_recipient || strcmpic(*recipient, US"postmaster") == 0)
  {
  int rd = Ustrlen(recipient) + 1;
  DEBUG(D_receive) debug_printf("unqualified address %s accepted\n",
    *recipient);
  /* deconst ok as *recipient was not const */
  *recipient = US rewrite_address_qualify(*recipient, TRUE);
  return rd;
  }
smtp_printf("501 %s: recipient address must contain a domain\r\n", SP_NO_MORE,
  smtp_cmd_data);
log_write(L_smtp_syntax_error,
  LOG_MAIN|LOG_REJECT, "unqualified %s rejected: <%s> %s%s",
  tag, *recipient, host_and_ident(TRUE), host_lookup_msg);
return 0;
}




static void
smtp_quit_handler(uschar ** user_msgp, uschar ** log_msgp)
{
HAD(SCH_QUIT);
f.smtp_in_quit = TRUE;
incomplete_transaction_log(US"QUIT");
GET_OPTION("acl_smtp_quit");
if (  acl_smtp_quit
   && acl_check(ACL_WHERE_QUIT, NULL, acl_smtp_quit, user_msgp, log_msgp)
	== ERROR)
    log_write(0, LOG_MAIN|LOG_PANIC, "ACL for QUIT returned ERROR: %s",
      *log_msgp);

#ifdef EXIM_TCP_CORK
if (smtp_out_fd >= 0)
  (void) setsockopt(smtp_out_fd, IPPROTO_TCP, EXIM_TCP_CORK,
		    US &on, sizeof(on));
#endif

if (*user_msgp)
  smtp_respond(US"221", 3, SR_FINAL, *user_msgp);
else
  smtp_printf("221 %s closing connection\r\n", SP_MORE, smtp_active_hostname);

#ifdef SERVERSIDE_CLOSE_NOWAIT
# ifndef DISABLE_TLS
tls_close(NULL, TLS_SHUTDOWN_NOWAIT);
# endif

log_close_event(US"by QUIT");
#else

# ifndef DISABLE_TLS
tls_close(NULL, TLS_SHUTDOWN_WAIT);
# endif

log_close_event(US"by QUIT");

# ifdef EXIM_TCP_CORK
/* If we corked and there is no pending input, trigger transmit of the
ack-of-QUIT since that could be the peer's wakeup to close the TCP connection.
*/

if (  smtp_out_fd > 0 && tls_in.active.sock < 0
   && wouldblock_reading(WBR_DATA_OR_EOF))
  {
  smtp_fflush(SFF_UNCORK);
  (void) poll_one_fd(smtp_in_fd, POLLIN, 200);
  }
# else

/* Pause, hoping client will FIN first so that they get the TIME_WAIT.
The socket should become readble (though with no data) */

(void) poll_one_fd(smtp_in_fd, POLLIN, 200);

# endif	/*!EXIM_TCP_CORK*/
#endif	/*!SERVERSIDE_CLOSE_NOWAIT*/
}


static void
smtp_rset_handler(void)
{
HAD(SCH_RSET);
incomplete_transaction_log(US"RSET");
smtp_printf("250 Reset OK\r\n", SP_NO_MORE);
cmd_list[CL_RSET].is_mail_cmd = FALSE;
if (chunking_state > CHUNKING_OFFERED)
  chunking_state = CHUNKING_OFFERED;
}


#ifndef DISABLE_WELLKNOWN
static int
smtp_wellknown_handler(void)
{
if (verify_check_host(&wellknown_advertise_hosts) != FAIL)
  {
  GET_OPTION("acl_smtp_wellknown");
  if (acl_smtp_wellknown)
    {
    uschar * user_msg = NULL, * log_msg;
    int rc;

    if ((rc = acl_check(ACL_WHERE_WELLKNOWN, NULL, acl_smtp_wellknown,
		&user_msg, &log_msg)) != OK)
      return smtp_handle_acl_fail(ACL_WHERE_WELLKNOWN, rc, user_msg, log_msg);
    else if (!wellknown_response)
      return smtp_handle_acl_fail(ACL_WHERE_WELLKNOWN, ERROR, user_msg, log_msg);
    smtp_user_msg(US"250", wellknown_response);
    return 0;
    }
  }

smtp_printf("554 not permitted\r\n", SP_NO_MORE);
log_write(0, LOG_MAIN|LOG_REJECT, "rejected %q from %s",
	      smtp_cmd_buffer, sender_helo_name, host_and_ident(FALSE));
return 0;
}
#endif


static int
expand_mailmax(const uschar * s)
{
if (!(s = expand_string(s)))
  log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand smtp_accept_max_per_connection");
return *s ? Uatoi(s) : 0;
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
          < 0 lost connection, or synprot error
*/

int
smtp_setup_msg(void)
{
int done = 0;
BOOL toomany = FALSE, discarded = FALSE, last_was_rej_mail = FALSE,
    last_was_rcpt = FALSE;
rmark reset_point = store_mark();

DEBUG(D_receive) debug_printf("smtp_setup_msg entered\n");

/* Reset for start of new message. We allow one RSET not to be counted as a
nonmail command, for those MTAs that insist on sending it between every
message. Ditto for EHLO/HELO and for STARTTLS, to allow for going in and out of
TLS between messages (an Exim client may do this if it has messages queued up
for the host). Note: we do NOT reset AUTH at this point. */

reset_point = smtp_reset(reset_point);
message_ended = END_NOTSTARTED;

chunking_state = f.chunking_offered ? CHUNKING_OFFERED : CHUNKING_NOT_OFFERED;

cmd_list[CL_RSET].is_mail_cmd = TRUE;
cmd_list[CL_HELO].is_mail_cmd = TRUE;
cmd_list[CL_EHLO].is_mail_cmd = TRUE;
#ifndef DISABLE_TLS
cmd_list[CL_STLS].is_mail_cmd = TRUE;
#endif

if (lwr_receive_getc && !atrn_mode)
  {
  /* This should have already happened, but if we've gotten confused,
  force a reset here. */
  DEBUG(D_receive) debug_printf("WARNING: smtp_setup_msg had to restore receive functions to lowers\n");
  bdat_pop_receive_functions();
  }

/* Set the local signal handler for SIGTERM - it tries to end off tidily */

had_command_sigterm = 0;
os_non_restarting_signal(SIGTERM, command_sigterm_handler);

/* Batched SMTP is handled in a different function. */

if (smtp_batched_input) return smtp_setup_batch_msg();

#ifdef TCP_QUICKACK
if (smtp_in_fd >= 0)	/* Avoid pure-ACKs while in cmd pingpong phase */
  (void) setsockopt(smtp_in_fd, IPPROTO_TCP, TCP_QUICKACK,
	  US &off, sizeof(off));
#endif

/* Deal with SMTP commands. This loop is exited by setting done to a POSITIVE
value. The values are 2 larger than the required yield of the function. */

while (done <= 0)
  {
  const uschar ** argv;
  uschar * etrn_command, * etrn_serialize_key, * errmess;
  uschar * log_msg, * smtp_code;
  uschar * user_msg = NULL, * recipient = NULL, * hello = NULL;
  uschar * s, * ss;
  BOOL was_rej_mail = FALSE, was_rcpt = FALSE;
  void (*oldsignal)(int);
  pid_t pid;
  int start, end, sender_domain, recipient_domain;
  int rc, c, dsn_flags;
  uschar * orcpt = NULL;
  gstring * g;

#ifdef AUTH_TLS
  /* Check once per STARTTLS or SSL-on-connect for a TLS AUTH */
  if (  tls_in.active.sock >= 0
     && tls_in.peercert
     && tls_in.certificate_verified
     && cmd_list[CL_TLAU].is_mail_cmd
     )
    {
    cmd_list[CL_TLAU].is_mail_cmd = FALSE;

    for (auth_instance * au = auths; au; au = au->drinst.next)
      if (strcmpic(US"tls", au->drinst.driver_name) == 0)
	{
	GET_OPTION("acl_smtp_auth");
	if (  acl_smtp_auth
	   && (rc = acl_check(ACL_WHERE_AUTH, NULL, acl_smtp_auth,
		      &user_msg, &log_msg)) != OK
	   )
	  done = smtp_handle_acl_fail(ACL_WHERE_AUTH, rc, user_msg, log_msg);
	else
	  {
	  smtp_cmd_data = NULL;

	  if (smtp_in_auth(au, &s, &ss) == OK)
	    { DEBUG(D_auth) debug_printf("tls auth succeeded\n"); }
	  else
	    {
	    DEBUG(D_auth) debug_printf("tls auth not succeeded\n");
#ifndef DISABLE_EVENT
	     {
	      uschar * save_name = sender_host_authenticated, * logmsg;
	      sender_host_authenticated = au->drinst.name;
	      if ((logmsg = event_raise(event_action, US"auth:fail", s, NULL)))
		log_write(0, LOG_MAIN, "%s", logmsg);
	      sender_host_authenticated = save_name;
	     }
#endif
	    }
	  }
	break;
	}
    }
#endif

  switch(smtp_read_command(
#ifndef DISABLE_PIPE_CONNECT
	  !fl.pipe_connect_acceptable,
#else
	  TRUE,
#endif
	  GETC_BUFFER_UNLIMITED))
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
      cmd_list[CL_AUTH].is_mail_cmd = FALSE;

      if (!fl.auth_advertised && !f.allow_auth_unadvertised)
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

      GET_OPTION("acl_smtp_auth");
      if (  acl_smtp_auth
	 && (rc = acl_check(ACL_WHERE_AUTH, NULL, acl_smtp_auth,
		    &user_msg, &log_msg)) != OK
	 )
	{
	done = smtp_handle_acl_fail(ACL_WHERE_AUTH, rc, user_msg, log_msg);
	break;
	}

      /* Find the name of the requested authentication mechanism. */

      s = smtp_cmd_data;
      for (; (c = *smtp_cmd_data) && !isspace(c); smtp_cmd_data++)
	if (!isalnum(c) && c != '-' && c != '_')
	  {
	  done = synprot_error(L_smtp_syntax_error, 501, NULL,
	    US"invalid character in authentication mechanism name");
	  goto COMMAND_LOOP;
	  }

      /* If not at the end of the line, we must be at white space. Terminate the
      name and move the pointer on to any data that may be present. */

      if (*smtp_cmd_data)
	{
	*smtp_cmd_data++ = '\0';
	Uskip_whitespace(&smtp_cmd_data);
	}

      /* Search for an authentication mechanism which is configured for use
      as a server and which has been advertised (unless, sigh, allow_auth_
      unadvertised is set). */

	{
	auth_instance * au;
	uschar * smtp_resp, * errmsg;

	for (au = auths; au; au = au->drinst.next)
	  if (strcmpic(s, au->public_name) == 0 && au->server &&
	      (au->advertised || f.allow_auth_unadvertised))
	    break;

	if (au)
	  {
	  int rc = smtp_in_auth(au, &smtp_resp, &errmsg);

	  smtp_printf("%s\r\n", SP_NO_MORE, smtp_resp);
	  if (rc != OK)
	    {
	    uschar * logmsg = NULL;
#ifndef DISABLE_EVENT
	     {uschar * save_name = sender_host_authenticated;
	      sender_host_authenticated = au->drinst.name;
	      logmsg = event_raise(event_action, US"auth:fail", smtp_resp, NULL);
	      sender_host_authenticated = save_name;
	     }
#endif
	    if (logmsg)
	      log_write(0, LOG_MAIN|LOG_REJECT, "%s", logmsg);
	    else
	      log_write(0, LOG_MAIN|LOG_REJECT, "%s authenticator failed for %s: %s",
		au->drinst.name, host_and_ident(TRUE), errmsg);
	    }
	  }
	else
	  done = synprot_error(L_smtp_protocol_error, 504, NULL,
	    string_sprintf("%s authentication mechanism not supported", s));
	}

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
      fl.esmtp = FALSE;
      goto HELO_EHLO;

    case EHLO_CMD:
      HAD(SCH_EHLO);
      hello = US"EHLO";
      fl.esmtp = TRUE;

    HELO_EHLO:      /* Common code for HELO and EHLO */
      cmd_list[CL_HELO].is_mail_cmd = FALSE;
      cmd_list[CL_EHLO].is_mail_cmd = FALSE;

      /* Reject the HELO if its argument was invalid or non-existent. A
      successful check causes the argument to be saved in malloc store. */

      if (!check_helo(smtp_cmd_data))
	{
	smtp_printf("501 Syntactically invalid %s argument(s)\r\n", SP_NO_MORE, hello);

	log_write(0, LOG_MAIN|LOG_REJECT, "rejected %s from %s: syntactically "
	  "invalid argument(s): %s", hello, host_and_ident(FALSE),
	  *smtp_cmd_argument == 0 ? US"(no argument given)" :
			     string_printing(smtp_cmd_argument));

	GET_OPTION("smtp_max_synprot_errors");
	if (++synprot_error_count > smtp_max_synprot_errors)
	  {
	  log_write(0, LOG_MAIN|LOG_REJECT, "SMTP call from %s dropped: too many "
	    "syntax or protocol errors (last command was %q, %Y)",
	    host_and_ident(FALSE), string_printing(smtp_cmd_buffer),
	    s_connhad_log(NULL)
	    );
	  done = 1;
	  }

	break;
	}

      /* If sender_host_unknown is true, we have got here via the -bs interface,
      not called from inetd. Otherwise, we are running an IP connection and the
      host address will be set. If the helo name is the primary name of this
      host and we haven't done a reverse lookup, force one now. If helo_verify_required
      is set, ensure that the HELO name matches the actual host. If helo_verify
      is set, do the same check, but softly. */

      if (!f.sender_host_unknown)
	{
	BOOL old_helo_verified = f.helo_verified;
	uschar * p = smtp_cmd_data;

	while (*p && !isspace(*p)) { *p = tolower(*p); p++; }
	*p = '\0';

	/* Force a reverse lookup if HELO quoted something in helo_lookup_domains
	because otherwise the log can be confusing. */

	if (  !sender_host_name
	   && match_isinlist(sender_helo_name, CUSS &helo_lookup_domains, 0,
		&domainlist_anchor, NULL, MCL_DOMAIN, TRUE, NULL) == OK)
	  (void)host_name_lookup();

	/* Rebuild the fullhost info to include the HELO name (and the real name
	if it was looked up.) */

	host_build_sender_fullhost();  /* Rebuild */
	set_process_info("handling%s incoming connection from %s",
	  tls_in.active.sock >= 0 ? " TLS" : "", host_and_ident(FALSE));

	/* Verify if configured. This doesn't give much security, but it does
	make some people happy to be able to do it. If helo_verify_required is set,
	(host matches helo_verify_hosts) failure forces rejection. If helo_verify
	is set (host matches helo_try_verify_hosts), it does not. This is perhaps
	now obsolescent, since the verification can now be requested selectively
	at ACL time. */

	f.helo_verified = f.helo_verify_failed = sender_helo_dnssec = FALSE;
	if (fl.helo_verify_required || fl.helo_verify)
	  {
	  BOOL tempfail = !smtp_verify_helo();
	  if (!f.helo_verified)
	    {
	    if (fl.helo_verify_required)
	      {
	      smtp_printf("%d %s argument does not match calling host\r\n", SP_NO_MORE,
		tempfail? 451 : 550, hello);
	      log_write(0, LOG_MAIN|LOG_REJECT, "%srejected \"%s %s\" from %s",
		tempfail? "temporarily " : "",
		hello, sender_helo_name, host_and_ident(FALSE));
	      f.helo_verified = old_helo_verified;
	      break;                   /* End of HELO/EHLO processing */
	      }
	    HDEBUG(D_all) debug_printf("%s verification failed but host is in "
	      "helo_try_verify_hosts\n", hello);
	    }
	  }
	}

      /* For any misc-module having a connection-init routine, call it. */
      
      {
      const uschar * errstr = NULL;
      if (misc_mod_conn_init(sender_helo_name, sender_host_address, &errstr)
	  != OK)
	{
	DEBUG(D_receive)
	  debug_printf("A module conn-init routine failed: %s\n", errstr);
	done = 1;
	break;
	}
      }

      /* Apply an ACL check if one is defined; afterwards, recheck
      synchronization in case the client started sending in a delay. */

      GET_OPTION("acl_smtp_helo");
      if (acl_smtp_helo)
	if ((rc = acl_check(ACL_WHERE_HELO, NULL, acl_smtp_helo,
		  &user_msg, &log_msg)) != OK)
	  {
	  done = smtp_handle_acl_fail(ACL_WHERE_HELO, rc, user_msg, log_msg);
	  sender_helo_name = NULL;
	  host_build_sender_fullhost();  /* Rebuild */
	  break;
	  }
#ifndef DISABLE_PIPE_CONNECT
	else if (!fl.pipe_connect_acceptable && !check_sync(WBR_DATA_OR_EOF))
#else
	else if (!check_sync(WBR_DATA_OR_EOF))
#endif
	  goto SYNC_FAILURE;

      /* Generate an OK reply. The default string includes the ident if present,
      and also the IP address if present. Reflecting back the ident is intended
      as a deterrent to mail forgers. For maximum efficiency, and also because
      some broken systems expect each response to be in a single packet, arrange
      that the entire reply is sent in one write(). */

      fl.auth_advertised = FALSE;
      f.smtp_in_pipelining_advertised = FALSE;
#ifndef DISABLE_TLS
      fl.tls_advertised = FALSE;
#endif
      fl.dsn_advertised = FALSE;
#ifdef SUPPORT_I18N
      fl.smtputf8_advertised = FALSE;
#endif

      /* Expand the per-connection message count limit option */
      smtp_mailcmd_max = expand_mailmax(smtp_accept_max_per_connection);

      smtp_code = US"250 ";        /* Default response code plus space*/
      if (!user_msg)
	{
	/* sender_host_name below will be tainted, so save on copy when we hit it */
	g = string_get_tainted(24, GET_TAINTED);
	g = string_fmt_append(g, "%.3s %s Hello %s%s%s",
	  smtp_code,
	  smtp_active_hostname,
	  sender_ident ? sender_ident : US"",
	  sender_ident ? US" at " : US"",
	  sender_host_name ? sender_host_name : sender_helo_name);

	if (sender_host_address)
	  g = string_fmt_append(g, " [%s]", sender_host_address);
	}

      /* A user-supplied EHLO greeting may not contain more than one line. Note
      that the code returned by smtp_message_code() includes the terminating
      whitespace character. */

      else
	{
	char * t;
	int codelen = 4;
	smtp_message_code(&smtp_code, &codelen, &user_msg, NULL, TRUE);
	s = string_sprintf("%.*s%s", codelen, smtp_code, user_msg);
	if ((t= strpbrk(CS s, "\r\n")) != NULL)
	  {
	  log_write(0, LOG_MAIN|LOG_PANIC, "EHLO/HELO response must not contain "
	    "newlines: message truncated: %s", string_printing(s));
	  *t = '\0';
	  }
	g = string_cat(NULL, s);
	}

      g = string_catn(g, US"\r\n", 2);

      /* If we received EHLO, we must create a multiline response which includes
      the functions supported. */

      if (fl.esmtp)
	{
	g->s[3] = '-';	/* overwrite the space after the SMTP response code */

	/* I'm not entirely happy with this, as an MTA is supposed to check
	that it has enough room to accept a message of maximum size before
	it sends this. However, there seems little point in not sending it.
	The actual size check happens later at MAIL FROM time. By postponing it
	till then, VRFY and EXPN can be used after EHLO when space is short. */

	if (thismessage_size_limit > 0)
	  g = string_fmt_append(g, "%.3s-SIZE %d\r\n", smtp_code,
	    thismessage_size_limit);
	else
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-SIZE\r\n", 7);
	  }

#ifndef DISABLE_ESMTP_LIMITS
	if (  (smtp_mailcmd_max > 0 || recipients_max_expanded > 0)
	   && verify_check_host(&limits_advertise_hosts) == OK)
	  {
	  g = string_fmt_append(g, "%.3s-LIMITS", smtp_code);
	  if (smtp_mailcmd_max > 0)
	    g = string_fmt_append(g, " MAILMAX=%d", smtp_mailcmd_max);
	  if (recipients_max_expanded > 0)
	    g = string_fmt_append(g, " RCPTMAX=%d", recipients_max_expanded);
	  g = string_catn(g, US"\r\n", 2);
	  }
#endif

	/* Exim does not do protocol conversion or data conversion. It is 8-bit
	clean; if it has an 8-bit character in its hand, it just sends it. It
	cannot therefore specify 8BITMIME and remain consistent with the RFCs.
	However, some users want this option simply in order to stop MUAs
	mangling messages that contain top-bit-set characters. It is therefore
	provided as an option. */

	if (accept_8bitmime)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-8BITMIME\r\n", 11);
	  }

	/* Advertise DSN support if configured to do so. */
	if (verify_check_host(&dsn_advertise_hosts) != FAIL)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-DSN\r\n", 6);
	  fl.dsn_advertised = TRUE;
	  }

	/* Advertise ATRN/ETRN/VRFY/EXPN if there's are ACL checking whether a
	host is permitted to issue them; a check is made when any host actually
	tries. */

	GET_OPTION("acl_smtp_atrn");
	if (acl_smtp_atrn && !atrn_mode)
	  {
	  const uschar * s = expand_string(acl_smtp_atrn);
	  if (s && *s)
	    {
	    g = string_catn(g, smtp_code, 3);
	    g = string_catn(g, US"-ATRN\r\n", 7);
	    }
	  }
	GET_OPTION("acl_smtp_etrn");
	if (acl_smtp_etrn)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-ETRN\r\n", 7);
	  }
	GET_OPTION("acl_smtp_vrfy");
	if (acl_smtp_vrfy)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-VRFY\r\n", 7);
	  }
	GET_OPTION("acl_smtp_expn");
	if (acl_smtp_expn)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-EXPN\r\n", 7);
	  }

	/* Exim is quite happy with pipelining, so let the other end know that
	it is safe to use it, unless advertising is disabled. */

	if (  f.pipelining_enable
	   && verify_check_host(&pipelining_advertise_hosts) == OK)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-PIPELINING\r\n", 13);
	  sync_cmd_limit = NON_SYNC_CMD_PIPELINING;
	  f.smtp_in_pipelining_advertised = TRUE;

#ifndef DISABLE_PIPE_CONNECT
	  if (fl.pipe_connect_acceptable)
	    {
	    f.smtp_in_early_pipe_advertised = TRUE;
	    g = string_catn(g, smtp_code, 3);
	    g = string_catn(g, US"-" EARLY_PIPE_FEATURE_NAME "\r\n", EARLY_PIPE_FEATURE_LEN+3);
	    }
#endif
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
#ifdef AUTH_TLS
	   && !sender_host_authenticated
#endif
	   && verify_check_host(&auth_advertise_hosts) == OK
	   )
	  {
	  BOOL first = TRUE;
	  for (auth_instance * au = auths; au; au = au->drinst.next)
	    {
	    au->advertised = FALSE;
	    if (au->server)
	      {
	      DEBUG(D_auth+D_expand) debug_printf_indent(
		"Evaluating advertise_condition for %s %s authenticator\n",
		au->drinst.name, au->public_name);
	      if (  !au->advertise_condition
		 || expand_check_condition(au->advertise_condition,
					  au->drinst.name, US"authenticator")
		 )
		{
		int saveptr;
		if (first)
		  {
		  g = string_catn(g, smtp_code, 3);
		  g = string_catn(g, US"-AUTH", 5);
		  first = FALSE;
		  fl.auth_advertised = TRUE;
		  }
		saveptr = gstring_length(g);
		g = string_catn(g, US" ", 1);
		g = string_cat(g, au->public_name);
		while (++saveptr < g->ptr) g->s[saveptr] = toupper(g->s[saveptr]);
		au->advertised = TRUE;
		}
	      }
	    }

	  if (!first) g = string_catn(g, US"\r\n", 2);
	  }

	/* RFC 3030 CHUNKING */

	if (verify_check_host(&chunking_advertise_hosts) != FAIL)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-CHUNKING\r\n", 11);
	  f.chunking_offered = TRUE;
	  chunking_state = CHUNKING_OFFERED;
	  }

#ifndef DISABLE_TLS
	/* Advertise TLS (Transport Level Security) aka SSL (Secure Socket Layer)
	if it has been included in the binary, and the host matches
	tls_advertise_hosts. We must *not* advertise if we are already in a
	secure connection. */

	if (tls_in.active.sock < 0 &&
	    verify_check_host(&tls_advertise_hosts) != FAIL)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-STARTTLS\r\n", 11);
	  fl.tls_advertised = TRUE;
	  }
#endif
#ifdef EXPERIMENTAL_XCLIENT
	if (proxy_session || verify_check_host(&hosts_xclient) != FAIL)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = xclient_smtp_advertise_str(g);
	  }
#endif
#ifndef DISABLE_PRDR
	/* Per Recipient Data Response, draft by Eric A. Hall extending RFC */
	if (prdr_enable)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-PRDR\r\n", 7);
	  }
#endif

#ifdef SUPPORT_I18N
	if (  accept_8bitmime
	   && verify_check_host(&smtputf8_advertise_hosts) != FAIL)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-SMTPUTF8\r\n", 11);
	  fl.smtputf8_advertised = TRUE;
	  }
#endif
#ifndef DISABLE_WELLKNOWN
	if (verify_check_host(&wellknown_advertise_hosts) != FAIL)
	  {
	  g = string_catn(g, smtp_code, 3);
	  g = string_catn(g, US"-WELLKNOWN\r\n", 12);
	  }
#endif

	/* Finish off the multiline reply with one that is always available. */

	g = string_catn(g, smtp_code, 3);
	g = string_catn(g, US" HELP\r\n", 7);
	}

#ifndef DISABLE_PIPE_CONNECT
      /* Before sending the response, if not already determined and there
      was an early-banner or TLS-on-connect, recheck for the client using
      early-pipe by further input being available. */

      if (  !f.smtp_in_early_pipe_used && !fl.helo_seen
	 && fl.pipe_connect_acceptable && !wouldblock_reading(WBR_DATA_OR_EOF))
	f.smtp_in_early_pipe_used = TRUE;
#endif
      /* Terminate the string (for debug), write it, and note that HELO/EHLO
      has been seen. If further command input is waiting, just buffer the
      write. */

      if (smtp_out_fd >= 0)
        {
	smtp_printf("%Y",
		  wouldblock_reading(WBR_DATA_OR_EOF) ? SP_NO_MORE : SP_MORE,
		  g);
	fl.helo_seen = TRUE;
        }

      /* Reset the protocol and the state, abandoning any previous message. */
      received_protocol =
	(sender_host_address ? protocols : protocols_local)
	  [
	  tls_in.on_connect && LOGGING(tls_on_connect)
	  ? ponconn + (pextend + (sender_host_authenticated ? pauthed : 0))/2
	  :   (fl.esmtp
	      ? pextend + (sender_host_authenticated ? pauthed : 0)
	      : pnormal)
	    + (tls_in.active.sock >= 0 ? pcrpted : 0)
	  ];
      cancel_cutthrough_connection(TRUE, US"sent EHLO response");
      reset_point = smtp_reset(reset_point);
      toomany = FALSE;
      break;   /* HELO/EHLO */

#ifndef DISABLE_WELLKNOWN
    case WELLKNOWN_CMD:
      HAD(SCH_WELLKNOWN);
      smtp_mailcmd_count++;
      smtp_wellknown_handler();
      break;
#endif

#ifdef EXPERIMENTAL_XCLIENT
    case XCLIENT_CMD:
      {
      BOOL fatal = fl.helo_seen;
      uschar * errmsg;
      int resp;

      HAD(SCH_XCLIENT);
      smtp_mailcmd_count++;

      if ((errmsg = xclient_smtp_command(smtp_cmd_data, &resp, &fatal)))
	if (fatal)
	  done = synprot_error(L_smtp_syntax_error, resp, NULL, errmsg);
	else
	  {
	  smtp_printf("%d %s\r\n", SP_NO_MORE, resp, errmsg);
	  log_write(0, LOG_MAIN|LOG_REJECT, "rejected XCLIENT from %s: %s",
	    host_and_ident(FALSE), errmsg);
	  }
      else
	{
	fl.helo_seen = FALSE;			/* Require another EHLO */
	smtp_code = string_sprintf("%d", resp);

	/*XXX unclear in spec. if this needs to be an ESMTP banner,
	nor whether we get the original client's HELO after (or a proxy fake).
	We require that we do; the following HELO/EHLO handling will set
	sender_helo_name as normal. */

	smtp_printf("%s XCLIENT success\r\n", SP_NO_MORE, smtp_code);
	}
      break; /* XCLIENT */
      }
#endif


    /* The MAIL command requires an address as an operand. All we do
    here is to parse it for syntactic correctness. The form "<>" is
    a special case which converts into an empty string. The start/end
    pointers in the original are not used further for this address, as
    it is the canonical extracted address which is all that is kept. */

    case MAIL_CMD:
      HAD(SCH_MAIL);
      smtp_mailcmd_count++;              /* Count for limit and ratelimit */
      message_start();
      was_rej_mail = TRUE;               /* Reset if accepted */
      env_mail_type_t * mail_args;       /* Sanity check & validate args */

      if (!fl.helo_seen)
	if (  fl.helo_verify_required
	   || verify_check_host(&hosts_require_helo) == OK)
	  {
	  log_write(0, LOG_MAIN|LOG_REJECT, "rejected MAIL from %s: no "
	    "HELO/EHLO given", host_and_ident(FALSE));
	  done = synprot_error(L_smtp_protocol_error, 503, NULL,
		      US"HELO or EHLO required");
	  break;
	  }
	else if (smtp_mailcmd_max < 0)
	  smtp_mailcmd_max = expand_mailmax(smtp_accept_max_per_connection);

      if (sender_address)
	{
	done = synprot_error(L_smtp_protocol_error, 503, NULL,
	  US"sender already given");
	break;
	}

      if (!*smtp_cmd_data)
	{
	done = synprot_error(L_smtp_protocol_error, 501, NULL,
	  US"MAIL must have an address operand");
	break;
	}

      /* Check to see if the limit for messages per connection would be
      exceeded by accepting further messages. */

      if (smtp_mailcmd_max > 0 && smtp_mailcmd_count > smtp_mailcmd_max)
	{
	smtp_printf("421 too many messages in this connection\r\n", SP_NO_MORE);
	log_write(0, LOG_MAIN|LOG_REJECT, "rejected MAIL command %s: too many "
	  "messages in one connection", host_and_ident(TRUE));
	break;
	}

      /* Reset for start of message - even if this is going to fail, we
      obviously need to throw away any previous data. */

      cancel_cutthrough_connection(TRUE, US"MAIL received");
      reset_point = smtp_reset(reset_point);
      toomany = FALSE;
      sender_data = recipient_data = NULL;

      /* Loop, checking for ESMTP additions to the MAIL FROM command. */

      if (fl.esmtp) for(;;)
	{
	uschar * name, * value;
	BOOL arg_error = FALSE;

	if (!extract_option(&name, &value)) break;

	for (mail_args = env_mail_type_list;
	     mail_args->value != ENV_MAIL_OPT_NULL;
	     mail_args++
	    )
	  if (strcmpic(name, mail_args->name) == 0)
	    break;
	if (mail_args->need_value && strcmpic(value, US"") == 0)
	  break;

	switch(mail_args->value)
	  {
	  /* Handle SIZE= by reading the value. We don't do the check till
	  later, in order to be able to log the sender address on failure. */
	  case ENV_MAIL_OPT_SIZE:
	    {
	    const uschar * s_end;
	    unsigned long int size = Ustrtoul(value, &s_end, 10);
	    if (!*s_end)
	      {
	      if ((size == ULONG_MAX && errno == ERANGE) || size > INT_MAX)
		size = INT_MAX;
	      message_size = (int)size;
	      }
	    else
	      arg_error = TRUE;
	    break;
	    }

	  /* If this session was initiated with EHLO and accept_8bitmime is set,
	  Exim will have indicated that it supports the BODY=8BITMIME option. In
	  fact, it does not support this according to the RFCs, in that it does
	  not take any special action for forwarding messages containing 8-bit
	  characters. That is why accept_8bitmime is not the default setting,
	  but some sites want the action that is provided. We recognize both
	  "8BITMIME" and "7BIT" as body types, but take no action. */
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
	  will have caused "DSN" to be given in the EHLO response). The code
	  itself is included only if configured in at build time. */

	  case ENV_MAIL_OPT_RET:
	    if (fl.dsn_advertised)
	      {
	      /* Check if RET has already been set */
	      if (dsn_ret > 0)
		{
		done = synprot_error(L_smtp_syntax_error, 501, NULL,
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
		done = synprot_error(L_smtp_syntax_error, 501, NULL,
		  US"Value for RET is invalid");
		goto COMMAND_LOOP;
		}
	      }
	    break;
	  case ENV_MAIL_OPT_ENVID:
	    if (fl.dsn_advertised)
	      {
	      /* Check if the dsn envid has been already set */
	      if (dsn_envid)
		{
		done = synprot_error(L_smtp_syntax_error, 501, NULL,
		  US"ENVID can be specified once only");
		goto COMMAND_LOOP;
		}
	      dsn_envid = string_copy(value);
	      DEBUG(D_receive) debug_printf("DSN_ENVID: %s\n", dsn_envid);
	      }
	    break;

	  /* Handle the AUTH extension. If the value given is not "<>" and
	  either the ACL says "yes" or there is no ACL but the sending host is
	  authenticated, we set it up as the authenticated sender. However, if
	  the authenticator set a condition to be tested, we ignore AUTH on MAIL
	  unless the condition is met. The value of AUTH is an xtext, which
	  means that +, = and cntrl chars are coded in hex; however "<>" is
	  unaffected by this coding. */
	  case ENV_MAIL_OPT_AUTH:
	    if (Ustrcmp(value, "<>") != 0)
	      {
	      int rc;
	      const uschar * ignore_msg;

	      if (xtextdecode(value, &authenticated_sender) < 0)
		{
		/* Put back terminator overrides for error message */
		value[-1] = '=';
		name[-1] = ' ';
		done = synprot_error(L_smtp_syntax_error, 501, NULL,
		  US"invalid data for AUTH");
		goto COMMAND_LOOP;
		}
	      GET_OPTION("acl_smtp_mailauth");
	      if (!acl_smtp_mailauth)
		{
		ignore_msg = US"client not authenticated";
		rc = sender_host_authenticated ? OK : FAIL;
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
			  authenticated_by->drinst.name, US"authenticator"))
		    break;     /* Accept the AUTH */

		  ignore_msg = US"server_mail_auth_condition failed";
		  if (authenticated_id != NULL)
		    ignore_msg = string_sprintf("%s: authenticated ID=%q",
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

#ifdef SUPPORT_I18N
	  case ENV_MAIL_OPT_UTF8:
	    if (!fl.smtputf8_advertised)
	      {
	      done = synprot_error(L_smtp_syntax_error, 501, NULL,
		US"SMTPUTF8 used when not advertised");
	      goto COMMAND_LOOP;
	      }

	    DEBUG(D_receive) debug_printf("smtputf8 requested\n");
	    message_smtputf8 = allow_utf8_domains = TRUE;
	    if (Ustrncmp(received_protocol, US"utf8", 4) != 0)
	      {
	      int old_pool = store_pool;
	      store_pool = POOL_PERM;
	      received_protocol = string_sprintf("utf8%s", received_protocol);
	      store_pool = old_pool;
	      }
	    break;
#endif

	  /* No valid option. Stick back the terminator characters and break
	  the loop.  Do the name-terminator second as extract_option sets
	  value==name when it found no equal-sign.
	  An error for a malformed address will occur. */
	  case ENV_MAIL_OPT_NULL:
	    value[-1] = '=';
	    name[-1] = ' ';
	    arg_error = TRUE;
	    break;

	  default:  assert(0);
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
	/* deconst ok as smtp_cmd_data was not const */
	? US rewrite_one(smtp_cmd_data, rewrite_smtp, NULL, FALSE, US"",
		      global_rewrite_rules)
	: smtp_cmd_data;

      raw_sender =
	parse_extract_address(raw_sender, &errmess, &start, &end, &sender_domain,
	  TRUE);

      if (!raw_sender)
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
	smtp_printf("552 Message size exceeds maximum permitted\r\n", SP_NO_MORE);
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
	   smtp_check_spool_space && message_size >= 0
	      ? message_size + 5000 : 0))
	{
	smtp_printf("452 Space shortage, please try later\r\n", SP_NO_MORE);
	sender_address = NULL;
	break;
	}

      /* If sender_address is unqualified, reject it, unless this is a locally
      generated message, or the sending host or net is permitted to send
      unqualified addresses - typically local machines behaving as MUAs -
      in which case just qualify the address. The flag is set above at the start
      of the SMTP connection. */

      if (!sender_domain && *sender_address)
	if (f.allow_unqualified_sender)
	  {
	  sender_domain = Ustrlen(sender_address) + 1;
	  /* deconst ok as sender_address was not const */
	  sender_address = US rewrite_address_qualify(sender_address, FALSE);
	  DEBUG(D_receive) debug_printf("unqualified address %s accepted\n",
	    raw_sender);
	  }
	else
	  {
	  smtp_printf("501 %s: sender address must contain a domain\r\n", SP_NO_MORE,
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

      /* Apply an ACL check if one is defined, before responding. Afterwards,
      when pipelining is not advertised, do another sync check in case the ACL
      delayed and the client started sending in the meantime. */

      GET_OPTION("acl_smtp_mail");
      if (acl_smtp_mail)
	{
	rc = acl_check(ACL_WHERE_MAIL, NULL, acl_smtp_mail, &user_msg, &log_msg);
	if (rc == OK && !f.smtp_in_pipelining_advertised && !check_sync(WBR_DATA_OR_EOF))
	  goto SYNC_FAILURE;
	}
      else
	rc = OK;

      if (rc == OK || rc == DISCARD)
	{
	BOOL more = pipeline_response();

	if (!user_msg)
	  smtp_printf("%s%s%s", more, US"250 OK",
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
	f.recipients_discarded = (rc == DISCARD);
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
      /* We got really to many recipients. A check against configured
      limits is done later */
      if (rcpt_count < 0 || rcpt_count >= INT_MAX/2)
        log_write_die(0, LOG_MAIN, "Too many recipients: %d", rcpt_count);
      rcpt_count++;
      was_rcpt = fl.rcpt_in_progress = TRUE;

      /* There must be a sender address; if the sender was rejected and
      pipelining was advertised, we assume the client was pipelining, and do not
      count this as a protocol error. Reset was_rej_mail so that further RCPTs
      get the same treatment. */

      if (!sender_address)
	{
	if (f.smtp_in_pipelining_advertised && last_was_rej_mail)
	  {
	  smtp_printf("503 sender not yet given\r\n", SP_NO_MORE);
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

      if (!smtp_cmd_data[0])
	{
	done = synprot_error(L_smtp_syntax_error, 501, NULL,
	  US"RCPT must have an address operand");
	rcpt_fail_count++;
	break;
	}

      /* Set the DSN flags orcpt and dsn_flags from the session*/
      orcpt = NULL;
      dsn_flags = 0;

      if (fl.esmtp) for(;;)
	{
	uschar *name, *value;

	if (!extract_option(&name, &value))
	  break;

	if (fl.dsn_advertised && strcmpic(name, US"ORCPT") == 0)
	  {
	  /* Check whether orcpt has been already set */
	  if (orcpt)
	    {
	    done = synprot_error(L_smtp_syntax_error, 501, NULL,
	      US"ORCPT can be specified once only");
	    goto COMMAND_LOOP;
	    }
	  orcpt = string_copy(value);
	  DEBUG(D_receive) debug_printf("DSN orcpt: %s\n", orcpt);
	  }

	else if (fl.dsn_advertised && strcmpic(name, US"NOTIFY") == 0)
	  {
	  /* Check if the notify flags have been already set */
	  if (dsn_flags > 0)
	    {
	    done = synprot_error(L_smtp_syntax_error, 501, NULL,
		US"NOTIFY can be specified once only");
	    goto COMMAND_LOOP;
	    }
	  if (strcmpic(value, US"NEVER") == 0)
	    dsn_flags |= rf_notify_never;
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
		dsn_flags |= rf_notify_success;
		}
	      else if (strcmpic(p, US"FAILURE") == 0)
		{
		DEBUG(D_receive) debug_printf("DSN: Setting notify failure\n");
		dsn_flags |= rf_notify_failure;
		}
	      else if (strcmpic(p, US"DELAY") == 0)
		{
		DEBUG(D_receive) debug_printf("DSN: Setting notify delay\n");
		dsn_flags |= rf_notify_delay;
		}
	      else
		{
		/* Catch any strange values */
		done = synprot_error(L_smtp_syntax_error, 501, NULL,
		  US"Invalid value for NOTIFY parameter");
		goto COMMAND_LOOP;
		}
	      p = pp;
	      }
	      DEBUG(D_receive) debug_printf("DSN Flags: %x\n", dsn_flags);
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

      recipient = rewrite_existflags & rewrite_smtp
	/* deconst ok as smtp_cmd_data was not const */
	? US rewrite_one(smtp_cmd_data, rewrite_smtp, NULL, FALSE, US"",
	    global_rewrite_rules)
	: smtp_cmd_data;

      if (!(recipient = parse_extract_address(recipient, &errmess, &start, &end,
	&recipient_domain, FALSE)))
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

      if (!recipient_domain)
	if (!(recipient_domain = qualify_recipient(&recipient, smtp_cmd_data,
				    US"recipient")))
	  {
	  rcpt_fail_count++;
	  break;
	  }

      /* Check maximum allowed */

      if (  rcpt_count+1 < 0
         || rcpt_count > recipients_max_expanded && recipients_max_expanded > 0)
	{
	if (recipients_max_reject)
	  {
	  rcpt_fail_count++;
	  smtp_printf("552 too many recipients\r\n", SP_NO_MORE);
	  if (!toomany)
	    log_write(0, LOG_MAIN|LOG_REJECT, "too many recipients: message "
	      "rejected: sender=<%s> %s", sender_address, host_and_ident(TRUE));
	  }
	else
	  {
	  rcpt_defer_count++;
	  smtp_printf("452 too many recipients\r\n", SP_NO_MORE);
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

      if (f.recipients_discarded)
	rc = DISCARD;
      else
	{
	GET_OPTION("acl_smtp_rcpt");
	if (  (rc = acl_check(ACL_WHERE_RCPT, recipient, acl_smtp_rcpt, &user_msg,
		      &log_msg)) == OK
	   && !f.smtp_in_pipelining_advertised && !check_sync(WBR_DATA_ONLY))
	  goto SYNC_FAILURE;
	}

      /* The ACL was happy */

      if (rc == OK)
	{
	BOOL more = pipeline_response();

	if (user_msg)
	  smtp_user_msg(US"250", user_msg);
	else
	  smtp_printf("250 Accepted\r\n", more);
	receive_add_recipient(recipient, -1);

	/* Set the dsn flags in the recipients_list */
	recipients_list[recipients_count-1].orcpt = orcpt;
	recipients_list[recipients_count-1].dsn_flags = dsn_flags;

	/* DEBUG(D_receive) debug_printf("DSN: orcpt: %s  flags: %d\n",
	  recipients_list[recipients_count-1].orcpt,
	  recipients_list[recipients_count-1].dsn_flags); */
	}

      /* The recipient was discarded */

      else if (rc == DISCARD)
	{
	if (user_msg)
	  smtp_user_msg(US"250", user_msg);
	else
	  smtp_printf("250 Accepted\r\n", SP_NO_MORE);
	rcpt_fail_count++;
	discarded = TRUE;
	log_write(0, LOG_MAIN|LOG_REJECT, "%s F=<%s> RCPT %s: "
	  "discarded by %s ACL%s%s", host_and_ident(TRUE),
	  sender_address_unrewritten ? sender_address_unrewritten : sender_address,
	  smtp_cmd_argument, f.recipients_discarded ? "MAIL" : "RCPT",
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

    case BDAT_CMD:
      {
      int n;

      HAD(SCH_BDAT);
      if (chunking_state != CHUNKING_OFFERED)
	{
	done = synprot_error(L_smtp_protocol_error, 503, NULL,
	  US"BDAT command used when CHUNKING not advertised");
	break;
	}

      /* grab size, endmarker */

      if (sscanf(CS smtp_cmd_data, "%u %n", &chunking_datasize, &n) < 1)
	{
	done = synprot_error(L_smtp_protocol_error, 501, NULL,
	  US"missing size for BDAT command");
	break;
	}
      chunking_state = strcmpic(smtp_cmd_data+n, US"LAST") == 0
	? CHUNKING_LAST : CHUNKING_ACTIVE;
      chunking_data_left = chunking_datasize;
      DEBUG(D_receive) debug_printf("chunking state '%s', %d bytes\n",
			chunking_states[chunking_state], chunking_data_left);

      f.bdat_readers_wanted = TRUE; /* FIXME: redundant vs chunking_state? */
      f.dot_ends = FALSE;

      goto DATA_BDAT;
      }

    case DATA_CMD:
      HAD(SCH_DATA);
      f.dot_ends = TRUE;
      f.bdat_readers_wanted = FALSE;

    DATA_BDAT:		/* Common code for DATA and BDAT */
#ifndef DISABLE_PIPE_CONNECT
      fl.pipe_connect_acceptable = FALSE;
#endif
      if (!discarded && recipients_count <= 0)
	{
	if (fl.rcpt_smtp_response_same && rcpt_smtp_response)
	  {
	  uschar *code = US"503";
	  int len = Ustrlen(rcpt_smtp_response);
	  smtp_respond(code, 3, SR_NOT_FINAL, US"All RCPT commands were rejected with "
	    "this error:");
	  /* Responses from smtp_printf() will have \r\n on the end */
	  if (len > 2 && rcpt_smtp_response[len-2] == '\r')
	    rcpt_smtp_response[len-2] = 0;
	  smtp_respond(code, 3, SR_NOT_FINAL, rcpt_smtp_response);
	  }
	if (f.smtp_in_pipelining_advertised && last_was_rcpt)
	  smtp_printf("503 Valid RCPT command must precede %s\r\n", SP_NO_MORE,
	    smtp_names[smtp_connection_had[SMTP_HBUFF_PREV(smtp_ch_index)]]);
	else
	  done = synprot_error(L_smtp_protocol_error, 503, NULL,
	    smtp_connection_had[SMTP_HBUFF_PREV(smtp_ch_index)] == SCH_DATA
	    ? US"valid RCPT command must precede DATA"
	    : US"valid RCPT command must precede BDAT");

	if (chunking_state > CHUNKING_OFFERED)
	  {
	  bdat_push_receive_functions();
	  bdat_flush_data();
	  }
	break;
	}

      if (toomany && recipients_max_reject)
	{
	sender_address = NULL;  /* This will allow a new MAIL without RSET */
	sender_address_unrewritten = NULL;
	smtp_printf("554 Too many recipients\r\n", SP_NO_MORE);

	if (chunking_state > CHUNKING_OFFERED)
	  {
	  bdat_push_receive_functions();
	  bdat_flush_data();
	  }
	break;
	}

      if (chunking_state > CHUNKING_OFFERED)
	rc = OK;	/* There is no predata ACL or go-ahead output for BDAT */
      else
	{
	/* If there is a predata-ACL, re-check the synchronization afterwards,
	since the ACL may have delayed.  To handle cutthrough delivery enforce a
	dummy call to get the DATA command sent. */

	GET_OPTION("acl_smtp_predata");
	if (!acl_smtp_predata && cutthrough.cctx.sock < 0)
	  rc = OK;
	else
	  {
	  uschar * acl = acl_smtp_predata ? acl_smtp_predata : US"accept";
	  f.enable_dollar_recipients = TRUE;
	  rc = acl_check(ACL_WHERE_PREDATA, NULL, acl, &user_msg,
	    &log_msg);
	  f.enable_dollar_recipients = FALSE;
	  if (rc == OK && !check_sync(WBR_DATA_OR_EOF))
	    goto SYNC_FAILURE;

	  if (rc != OK)
	    {	/* Either the ACL failed the address, or it was deferred. */
	    done = smtp_handle_acl_fail(ACL_WHERE_PREDATA, rc, user_msg, log_msg);
	    break;
	    }
	  }

	if (user_msg)
	  smtp_user_msg(US"354", user_msg);
	else
	  smtp_printf(
	    "354 Enter message, ending with \".\" on a line by itself\r\n", SP_NO_MORE);
	}

      if (f.bdat_readers_wanted)
	bdat_push_receive_functions();

#ifdef TCP_QUICKACK
      /* all ACKs needed to ramp window up for bulk data */
      (void) setsockopt(smtp_in_fd, IPPROTO_TCP, TCP_QUICKACK,
		US &on, sizeof(on));
#endif
      done = 3;
      message_ended = END_NOTENDED;   /* Indicate in middle of data */

      break;


    case VRFY_CMD:
      {
      uschar * address;

      HAD(SCH_VRFY);

      if (!(address = parse_extract_address(smtp_cmd_data, &errmess,
            &start, &end, &recipient_domain, FALSE)))
	{
	smtp_printf("501 %s\r\n", SP_NO_MORE, errmess);
	break;
	}

      if (!recipient_domain)
	if (!(recipient_domain = qualify_recipient(&address, smtp_cmd_data,
				    US"verify")))
	  break;

      GET_OPTION("acl_smtp_vrfy");
      if ((rc = acl_check(ACL_WHERE_VRFY, address, acl_smtp_vrfy,
		    &user_msg, &log_msg)) != OK)
	done = smtp_handle_acl_fail(ACL_WHERE_VRFY, rc, user_msg, log_msg);
      else
	{
	const uschar * s = NULL;
	address_item * addr = deliver_make_addr(address, FALSE);

	switch(verify_address(addr, -1, vopt_is_recipient | vopt_qualify, -1,
	       -1, -1, NULL, NULL, NULL))
	  {
	  case OK:
	    s = string_sprintf("250 <%s> is deliverable", address);
	    break;

	  case DEFER:
	    s = addr->user_message
	      ? string_sprintf("451 <%s> %s", address, addr->user_message)
	      : string_sprintf("451 Cannot resolve <%s> at this time", address);
	    break;

	  case FAIL:
	    s = addr->user_message
	      ? string_sprintf("550 <%s> %s", address, addr->user_message)
	      : string_sprintf("550 <%s> is not deliverable", address);
	    log_write(0, LOG_MAIN, "VRFY failed for %s %s",
	      smtp_cmd_argument, host_and_ident(TRUE));
	    break;
	  }

	smtp_printf("%s\r\n", SP_NO_MORE, s);
	}
      break;
      }


    case EXPN_CMD:
      HAD(SCH_EXPN);
      GET_OPTION("acl_smtp_expn");
      rc = acl_check(ACL_WHERE_EXPN, NULL, acl_smtp_expn, &user_msg, &log_msg);
      if (rc != OK)
	done = smtp_handle_acl_fail(ACL_WHERE_EXPN, rc, user_msg, log_msg);
      else if (smtp_out_fd >= 0)
	{
	BOOL save_log_testing_mode = f.log_testing_mode;
	f.address_test_mode = f.log_testing_mode = TRUE;
	(void) verify_address(deliver_make_addr(smtp_cmd_data, FALSE),
	  smtp_out_fd, vopt_is_recipient | vopt_qualify | vopt_expn, -1, -1, -1,
	  NULL, NULL, NULL);
	f.address_test_mode = FALSE;
	f.log_testing_mode = save_log_testing_mode;    /* true for -bh */
	}
      break;


    #ifndef DISABLE_TLS

    case STARTTLS_CMD:
      HAD(SCH_STARTTLS);
      if (!fl.tls_advertised)
	{
	done = synprot_error(L_smtp_protocol_error, 503, NULL,
	  US"STARTTLS command used when not advertised");
	break;
	}

      /* Apply an ACL check if one is defined */

      GET_OPTION("acl_smtp_starttls");
      if (  acl_smtp_starttls
	 && (rc = acl_check(ACL_WHERE_STARTTLS, NULL, acl_smtp_starttls,
		    &user_msg, &log_msg)) != OK
	 )
	{
	done = smtp_handle_acl_fail(ACL_WHERE_STARTTLS, rc, user_msg, log_msg);
	break;
	}

      /* RFC 2487 is not clear on when this command may be sent, though it
      does state that all information previously obtained from the client
      must be discarded if a TLS session is started. It seems reasonable to
      do an implied RSET when STARTTLS is received. */

      incomplete_transaction_log(US"STARTTLS");
      cancel_cutthrough_connection(TRUE, US"STARTTLS received");
      reset_point = smtp_reset(reset_point);
      toomany = FALSE;
      cmd_list[CL_STLS].is_mail_cmd = FALSE;

      /* There's an attack where more data is read in past the STARTTLS command
      before TLS is negotiated, then assumed to be part of the secure session
      when used afterwards; we use segregated input buffers, so are not
      vulnerable, but we want to note when it happens and, for sheer paranoia,
      ensure that the buffer is "wiped".
      Pipelining sync checks will normally have protected us too, unless
      disabled by configuration. */

      if (receive_hasc())
	{
	DEBUG(D_any)
	  debug_printf("Non-empty input buffer after STARTTLS; naive attack?\n");
	if (tls_in.active.sock < 0)
	  smtp_inend = smtp_inptr = smtp_inbuffer;
	/* and if TLS is already active, tls_server_start() should fail */
	}

      /* There is nothing we value in the input buffer and if TLS is successfully
      negotiated, we won't use this buffer again; if TLS fails, we'll just read
      fresh content into it.  The buffer contains arbitrary content from an
      untrusted remote source; eg: NOOP <shellcode>\r\nSTARTTLS\r\n
      It seems safest to just wipe away the content rather than leave it as a
      target to jump to. */

      memset(smtp_inbuffer, 0, IN_BUFFER_SIZE);

      /* Attempt to start up a TLS session, and if successful, discard all
      knowledge that was obtained previously. At least, that's what the RFC says,
      and that's what happens by default. However, in order to work round YAEB,
      there is an option to remember the esmtp state. Sigh.

      We must allow for an extra EHLO command and an extra AUTH command after
      STARTTLS that don't add to the nonmail command count. */

      s = NULL;
      if ((rc = tls_server_start(&s, NULL)) == OK)
	{
	if (!tls_remember_esmtp)
	  fl.helo_seen = fl.esmtp = fl.auth_advertised = f.smtp_in_pipelining_advertised = FALSE;
	cmd_list[CL_EHLO].is_mail_cmd = TRUE;
	cmd_list[CL_AUTH].is_mail_cmd = TRUE;
	cmd_list[CL_TLAU].is_mail_cmd = TRUE;
	if (sender_helo_name)
	  {
	  sender_helo_name = NULL;
	  host_build_sender_fullhost();  /* Rebuild */
	  set_process_info("handling incoming TLS connection from %s",
	    host_and_ident(FALSE));
	  }
	received_protocol =
	  (sender_host_address ? protocols : protocols_local)
	    [
	    tls_in.on_connect && LOGGING(tls_on_connect)
	    ? ponconn + (pextend + (sender_host_authenticated ? pauthed : 0))/2
	    :   (fl.esmtp
		? pextend + (sender_host_authenticated ? pauthed : 0)
		: pnormal)
	      + (tls_in.active.sock >= 0 ? pcrpted : 0)
	    ];

	sender_host_auth_pubname = sender_host_authenticated = NULL;
	authenticated_id = NULL;
	sync_cmd_limit = NON_SYNC_CMD_NON_PIPELINING;
	DEBUG(D_tls) debug_printf("TLS active\n");
	break;     /* Successful STARTTLS */
	}
      else
	(void) smtp_log_tls_fail(s);

      /* Some local configuration problem was discovered before actually trying
      to do a TLS handshake; give a temporary error. */

      if (rc == DEFER)
	{
	smtp_printf("454 TLS currently unavailable\r\n", SP_NO_MORE);
	break;
	}

      /* Hard failure. Reject everything except QUIT or closed connection. One
      cause for failure is a nested STARTTLS, in which case tls_in.active remains
      set, but we must still reject all incoming commands.  Another is a handshake
      failure - and there may some encrypted data still in the pipe to us, which we
      see as garbage commands. */

      DEBUG(D_tls) debug_printf("TLS failed to start\n");
      while (done <= 0) switch(smtp_read_command(FALSE, GETC_BUFFER_UNLIMITED))
	{
	case EOF_CMD:
	  log_close_event(US"by EOF");
	  smtp_notquit_exit(US"tls-failed", NULL, NULL);
	  done = 2;
	  break;

	/* It is perhaps arguable as to which exit ACL should be called here,
	but as it is probably a situation that almost never arises, it
	probably doesn't matter. We choose to call the real QUIT ACL, which in
	some sense is perhaps "right". */

	case QUIT_CMD:
	  smtp_quit_handler(&user_msg, &log_msg);
	  done = 2;
	  break;

	default:
	  smtp_printf("554 Security failure\r\n", SP_NO_MORE);
	  break;
	}
      tls_close(NULL, TLS_SHUTDOWN_NOWAIT);
      break;
    #endif


    /* The ACL for QUIT is provided for gathering statistical information or
    similar; it does not affect the response code, but it can supply a custom
    message. */

    case QUIT_CMD:
      smtp_quit_handler(&user_msg, &log_msg);
      done = 2;
      break;


    case RSET_CMD:
      smtp_rset_handler();
      cancel_cutthrough_connection(TRUE, US"RSET received");
      reset_point = smtp_reset(reset_point);
      toomany = FALSE;
      break;


    case NOOP_CMD:
      HAD(SCH_NOOP);
      smtp_printf("250 OK\r\n", SP_NO_MORE);
      break;


    /* Show ETRN/EXPN/VRFY if there's an ACL for checking hosts; if actually
    used, a check will be done for permitted hosts. Show STARTTLS only if not
    already in a TLS session and if it would be advertised in the EHLO
    response. */

    case HELP_CMD:
      HAD(SCH_HELP);
      smtp_printf("214-Commands supported:\r\n214", SP_MORE);
      smtp_printf(" AUTH", SP_MORE);
#ifndef DISABLE_TLS
      if (tls_in.active.sock < 0 &&
	  verify_check_host(&tls_advertise_hosts) != FAIL)
	smtp_printf(" STARTTLS", SP_MORE);
#endif
      smtp_printf(" HELO EHLO MAIL RCPT DATA BDAT", SP_MORE);
      smtp_printf(" NOOP QUIT RSET HELP", SP_MORE);
      if (acl_smtp_atrn) smtp_printf(" ATRN", SP_MORE);
      if (acl_smtp_etrn) smtp_printf(" ETRN", SP_MORE);
      if (acl_smtp_expn) smtp_printf(" EXPN", SP_MORE);
      if (acl_smtp_vrfy) smtp_printf(" VRFY", SP_MORE);
#ifndef DISABLE_WELLKNOWN
      if (verify_check_host(&wellknown_advertise_hosts) != FAIL)
	smtp_printf(" WELLKNOWN", SP_MORE);
#endif
#ifdef EXPERIMENTAL_XCLIENT
      if (proxy_session || verify_check_host(&hosts_xclient) != FAIL)
	smtp_printf(" XCLIENT", SP_MORE);
#endif
      smtp_printf("\r\n", SP_NO_MORE);
      break;


    case EOF_CMD:
      {
      uschar * errstr = smtp_ferror()
	? string_sprintf(" (error: %s)", strerror(errno)) : US"";

      incomplete_transaction_log(US"connection lost");
      smtp_notquit_exit(US"connection-lost", US"421",
	US"%s lost input connection", smtp_active_hostname);

      /* Don't log by default unless in the middle of a message, as some mailers
      just drop the call rather than sending QUIT, and it clutters up the logs.
      */

      if (sender_address || recipients_count > 0)
	log_write(L_lost_incoming_connection, LOG_MAIN,
	  "unexpected %s while reading SMTP command from %s%s%s D=%s",
	  f.sender_host_unknown ? "EOF" : "disconnection",
	  f.tcp_in_fastopen_logged
	  ? US""
	  : f.tcp_in_fastopen
	  ? f.tcp_in_fastopen_data ? US"TFO* " : US"TFO "
	  : US"",
	  host_and_ident(FALSE), errstr,
	  string_timesince(&smtp_connection_start)
	  );

      else
	log_write(L_smtp_connection, LOG_MAIN, "%s %slost%s D=%s",
	  smtp_get_connection_info(),
	  f.tcp_in_fastopen && !f.tcp_in_fastopen_logged ? US"TFO " : US"",
	  errstr,
	  string_timesince(&smtp_connection_start)
	  );

      done = 1;
      break;
      }

    case ATRN_CMD:
      HAD(SCH_ATRN);
      done = atrn_handle_provider(&user_msg, &log_msg);	/* Normal: exit() */
      break;						/* Error cases */

    case ETRN_CMD:
      HAD(SCH_ETRN);
      if (sender_address)
	{
	done = synprot_error(L_smtp_protocol_error, 503, NULL,
	  US"ETRN is not permitted inside a transaction");
	break;
	}

      log_write(L_etrn, LOG_MAIN, "ETRN %s received from %s", smtp_cmd_argument,
	host_and_ident(FALSE));

      GET_OPTION("acl_smtp_etrn");
      if ((rc = acl_check(ACL_WHERE_ETRN, NULL, acl_smtp_etrn,
		  &user_msg, &log_msg)) != OK)
	{
	done = smtp_handle_acl_fail(ACL_WHERE_ETRN, rc, user_msg, log_msg);
	break;
	}

      /* Compute the serialization key for this command. We used (all the way
      back to 4.00) to include the given string as part of the key, but this
      opens a security hole for hintsdb types that use a command-string for
      operations. All ETRN with the same command hash are serialized */

      md5 hash;
      uschar *digest = store_get(16, GET_TAINTED);

      md5_start(&hash);
      md5_end(&hash, smtp_cmd_argument, Ustrlen(smtp_cmd_argument), digest);

      etrn_serialize_key = string_sprintf("etrn-" /* don't we have a function doing exactly this? */
          "%02x%02x%02x%02x" "%02x%02x%02x%02x"   /* we have, since 2024-09-xx we can use %.16H */
          "%02x%02x%02x%02x" "%02x%02x%02x%02x",
          digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
          digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);

      /* If a command has been specified for running as a result of ETRN, we
      permit any argument to ETRN. If not, only the # standard form is
      permitted, since that is strictly the only kind of ETRN that can be
      implemented according to the RFC. */

      GET_OPTION("smtp_etrn_command");
      if (smtp_etrn_command)
	{
	uschar * error;
	BOOL rc;
	etrn_command = smtp_etrn_command;
	deliver_domain = smtp_cmd_data;
	rc = transport_set_up_command(&argv, smtp_etrn_command,
			TSUC_EXPAND_ARGS, 0, NULL, US"ETRN processing", &error);
	deliver_domain = NULL;
	if (!rc)
	  {
	  log_write(0, LOG_MAIN|LOG_PANIC, "failed to set up ETRN command: %s",
	    error);
	  smtp_printf("458 Internal failure\r\n", SP_NO_MORE);
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
	argv = CUSS child_exec_exim(CEE_RETURN_ARGV, TRUE, NULL, TRUE,
	  *queue_name ? 4 : 2,
	  US"-R", smtp_cmd_data,
	  US"-MCG", queue_name);
	}

      /* If we are host-testing, don't actually do anything. */

      if (host_checking)
	{
	HDEBUG(D_any)
	  {
	  debug_printf("ETRN command is: %s\n", etrn_command);
	  debug_printf("ETRN command execution skipped\n");
	  }
	if (user_msg == NULL) smtp_printf("250 OK\r\n", SP_NO_MORE);
	  else smtp_user_msg(US"250", user_msg);
	break;
	}


      /* If ETRN queue runs are to be serialized, check the database to
      ensure one isn't already running. */

      if (smtp_etrn_serialize && !enq_start(etrn_serialize_key, 1))
	{
	smtp_printf("458 Already processing %s\r\n", SP_NO_MORE, smtp_cmd_data);
	break;
	}

      /* Fork a child process and run the command. We don't want to have to
      wait for the process at any point, so set SIGCHLD to SIG_IGN before
      forking. It should be set that way anyway for external incoming SMTP,
      but we save and restore to be tidy. If serialization is required, we
      actually run the command in yet another process, so we can wait for it
      to complete and then remove the serialization lock. */

      oldsignal = signal(SIGCHLD, SIG_IGN);

      if ((pid = exim_fork(US"etrn-command")) == 0)
	{
	smtp_input = FALSE;       /* This process is not associated with the */
	smtp_inout_close();	  /* SMTP call any more. */

	signal(SIGCHLD, SIG_DFL);      /* Want to catch child */

	/* If not serializing, do the exec right away. Otherwise, fork down
	into another process. */

	if (  !smtp_etrn_serialize
	   || (pid = exim_fork(US"etrn-serialised-command")) == 0)
	  {
	  DEBUG(D_exec) debug_print_argv(argv);
	  exim_nullstd();                   /* Ensure std{in,out,err} exist */
	  /* argv[0] should be untainted, from child_exec_exim() */
	  execv(CS argv[0], (char *const *)argv);
	  log_write_die(0, LOG_MAIN, "exec of %q (ETRN) failed: %s",
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
	exim_underbar_exit(EXIT_SUCCESS);
	}

      /* Back in the top level SMTP process. Check that we started a subprocess
      and restore the signal state. */

      if (pid < 0)
	{
	log_write(0, LOG_MAIN|LOG_PANIC, "fork of process for ETRN failed: %s",
	  strerror(errno));
	smtp_printf("458 Unable to fork process\r\n", SP_NO_MORE);
	if (smtp_etrn_serialize) enq_end(etrn_serialize_key);
	}
      else
	if (!user_msg)
	  smtp_printf("250 OK\r\n", SP_NO_MORE);
	else
	  smtp_user_msg(US"250", user_msg);

      signal(SIGCHLD, oldsignal);
      break;


    case BADARG_CMD:
      done = synprot_error(L_smtp_syntax_error, 501, NULL,
	US"unexpected argument data");
      break;


    /* This currently happens only for NULLs, but could be extended. */

    case BADCHAR_CMD:
      done = synprot_error(L_smtp_syntax_error, 0, NULL,       /* Just logs */
	US"NUL character(s) present (shown as '?')");
      smtp_printf("501 NUL characters are not allowed in SMTP commands\r\n",
		  SP_NO_MORE);
      break;


    case BADSYN_CMD:
    SYNC_FAILURE:
      {
	unsigned nchars = 150;
	uschar * buf = receive_getbuf(&nchars);		/* destructive read */

	incomplete_transaction_log(US"sync failure");
	if (buf)
	  {
	  buf[nchars] = '\0';
	  log_write(0, LOG_MAIN|LOG_REJECT,
	    "SMTP protocol synchronization error "
	    "(next input sent too soon: pipelining was%s advertised): "
	    "rejected %q %s next input=%q (%u bytes)",
	    f.smtp_in_pipelining_advertised ? "" : " not",
	    smtp_cmd_buffer, host_and_ident(TRUE),
	    string_printing(buf), nchars);
	  }
	else
	  log_write(0, LOG_MAIN|LOG_REJECT, "Error or EOF on input from %s",
	    host_and_ident(TRUE));
	smtp_notquit_exit(US"synchronization-error", US"554",
	  US"SMTP synchronization error");
	done = 1;   /* Pretend eof - drops connection */
	break;
      }


    case TOO_MANY_NONMAIL_CMD:
      s = smtp_cmd_buffer;
      Uskip_nonwhite(&s);
      incomplete_transaction_log(US"too many non-mail commands");
      log_write(0, LOG_MAIN|LOG_REJECT, "SMTP call from %s dropped: too many "
	"nonmail commands (last was \"%.*s\")",  host_and_ident(FALSE),
	(int)(s - smtp_cmd_buffer), smtp_cmd_buffer);
      smtp_notquit_exit(US"bad-commands", US"554", US"Too many nonmail commands");
      done = 1;   /* Pretend eof - drops connection */
      break;

#ifdef SUPPORT_PROXY
    case PROXY_FAIL_IGNORE_CMD:
      smtp_printf("503 Command refused, required Proxy negotiation failed\r\n", SP_NO_MORE);
      break;
#endif

    default:
      GET_OPTION("smtp_max_unknown_commands");
      if (unknown_command_count++ >= smtp_max_unknown_commands)
	{
	log_write(L_smtp_syntax_error, LOG_MAIN,
	  "SMTP syntax error in %q %s %s",
	  string_printing(smtp_cmd_buffer), host_and_ident(TRUE),
	  US"unrecognized command");
	incomplete_transaction_log(US"unrecognized command");
	smtp_notquit_exit(US"bad-commands", US"500",
	  US"Too many unrecognized commands");
	done = 2;
	log_write(0, LOG_MAIN|LOG_REJECT, "SMTP call from %s dropped: too many "
	  "unrecognized commands (last was %q)", host_and_ident(FALSE),
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
  }

done -= 2;	/* Convert yield values */

if (done != 0 && wouldblock_reading(WBR_DATA_ONLY))
  smtp_fflush(SFF_UNCORK);
return done;
}



gstring *
authres_smtpauth(gstring * g)
{
if (!sender_host_authenticated)
  return g;

g = string_append(g, 2, US";\n\tauth=pass (", sender_host_auth_pubname);

if (Ustrcmp(sender_host_auth_pubname, "tls") == 0)
  g = authenticated_id
    ? string_append(g, 2, US") x509.auth=", authenticated_id)
    : string_cat(g, US") reason=x509.auth");
else
  g = authenticated_id
    ? string_append(g, 2, US") smtp.auth=", authenticated_id)
    : string_cat(g, US", no id saved)");

if (authenticated_sender)
  g = string_append(g, 2, US" smtp.mailfrom=", authenticated_sender);
return g;
}



/* vi: aw ai sw=2
*/
/* End of smtp_in.c */
