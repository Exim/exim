/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* A number of functions for driving outgoing SMTP calls. */


#include "exim.h"
#include "transports/smtp.h"



/*************************************************
*           Find an outgoing interface           *
*************************************************/

/* This function is called from the smtp transport and also from the callout
code in verify.c. Its job is to expand a string to get a list of interfaces,
and choose a suitable one (IPv4 or IPv6) for the outgoing address.

Arguments:
  istring    string interface setting, may be NULL, meaning "any", in
               which case the function does nothing
  host_af    AF_INET or AF_INET6 for the outgoing IP address
  addr       the mail address being handled (for setting errors)
  changed    if not NULL, set TRUE if expansion actually changed istring
  interface  point this to the interface
  msg        to add to any error message

Returns:     TRUE on success, FALSE on failure, with error message
               set in addr and transport_return set to PANIC
*/

BOOL
smtp_get_interface(uschar *istring, int host_af, address_item *addr,
  BOOL *changed, uschar **interface, uschar *msg)
{
const uschar * expint;
uschar *iface;
int sep = 0;

if (istring == NULL) return TRUE;

expint = expand_string(istring);
if (expint == NULL)
  {
  if (expand_string_forcedfail) return TRUE;
  addr->transport_return = PANIC;
  addr->message = string_sprintf("failed to expand \"interface\" "
      "option for %s: %s", msg, expand_string_message);
  return FALSE;
  }

if (changed != NULL) *changed = expint != istring;

while (isspace(*expint)) expint++;
if (*expint == 0) return TRUE;

while ((iface = string_nextinlist(&expint, &sep, big_buffer,
          big_buffer_size)) != NULL)
  {
  if (string_is_ip_address(iface, NULL) == 0)
    {
    addr->transport_return = PANIC;
    addr->message = string_sprintf("\"%s\" is not a valid IP "
      "address for the \"interface\" option for %s",
      iface, msg);
    return FALSE;
    }

  if (((Ustrchr(iface, ':') == NULL)? AF_INET:AF_INET6) == host_af)
    break;
  }

if (iface != NULL) *interface = string_copy(iface);
return TRUE;
}



/*************************************************
*           Find an outgoing port                *
*************************************************/

/* This function is called from the smtp transport and also from the callout
code in verify.c. Its job is to find a port number. Note that getservbyname()
produces the number in network byte order.

Arguments:
  rstring     raw (unexpanded) string representation of the port
  addr        the mail address being handled (for setting errors)
  port        stick the port in here
  msg         for adding to error message

Returns:      TRUE on success, FALSE on failure, with error message set
                in addr, and transport_return set to PANIC
*/

BOOL
smtp_get_port(uschar *rstring, address_item *addr, int *port, uschar *msg)
{
uschar *pstring = expand_string(rstring);

if (pstring == NULL)
  {
  addr->transport_return = PANIC;
  addr->message = string_sprintf("failed to expand \"%s\" (\"port\" option) "
    "for %s: %s", rstring, msg, expand_string_message);
  return FALSE;
  }

if (isdigit(*pstring))
  {
  uschar *end;
  *port = Ustrtol(pstring, &end, 0);
  if (end != pstring + Ustrlen(pstring))
    {
    addr->transport_return = PANIC;
    addr->message = string_sprintf("invalid port number for %s: %s", msg,
      pstring);
    return FALSE;
    }
  }

else
  {
  struct servent *smtp_service = getservbyname(CS pstring, "tcp");
  if (smtp_service == NULL)
    {
    addr->transport_return = PANIC;
    addr->message = string_sprintf("TCP port \"%s\" is not defined for %s",
      pstring, msg);
    return FALSE;
    }
  *port = ntohs(smtp_service->s_port);
  }

return TRUE;
}




int
smtp_sock_connect(host_item * host, int host_af, int port, uschar * interface,
  transport_instance * tb, int timeout)
{
smtp_transport_options_block * ob =
  (smtp_transport_options_block *)tb->options_block;
const uschar * dscp = ob->dscp;
int dscp_value;
int dscp_level;
int dscp_option;
int sock;
int on = 1;
int save_errno = 0;

#ifdef EXPERIMENTAL_EVENT
deliver_host_address = host->address;
deliver_host_port = port;
if (event_raise(tb->event_action, US"tcp:connect", NULL)) return -1;
#endif

if ((sock = ip_socket(SOCK_STREAM, host_af)) < 0) return -1;

/* Set TCP_NODELAY; Exim does its own buffering. */

setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (uschar *)(&on), sizeof(on));

/* Set DSCP value, if we can. For now, if we fail to set the value, we don't
bomb out, just log it and continue in default traffic class. */

if (dscp && dscp_lookup(dscp, host_af, &dscp_level, &dscp_option, &dscp_value))
  {
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf("DSCP \"%s\"=%x ", dscp, dscp_value);
  if (setsockopt(sock, dscp_level, dscp_option, &dscp_value, sizeof(dscp_value)) < 0)
    HDEBUG(D_transport|D_acl|D_v)
      debug_printf("failed to set DSCP: %s ", strerror(errno));
  /* If the kernel supports IPv4 and IPv6 on an IPv6 socket, we need to set the
  option for both; ignore failures here */
  if (host_af == AF_INET6 &&
      dscp_lookup(dscp, AF_INET, &dscp_level, &dscp_option, &dscp_value))
    (void) setsockopt(sock, dscp_level, dscp_option, &dscp_value, sizeof(dscp_value));
  }

/* Bind to a specific interface if requested. Caller must ensure the interface
is the same type (IPv4 or IPv6) as the outgoing address. */

if (interface && ip_bind(sock, host_af, interface, 0) < 0)
  {
  save_errno = errno;
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf("unable to bind outgoing SMTP call to %s: %s", interface,
    strerror(errno));
  }

/* Connect to the remote host, and add keepalive to the socket before returning
it, if requested. */

else if (ip_connect(sock, host_af, host->address, port, timeout) < 0)
  save_errno = errno;

/* Either bind() or connect() failed */

if (save_errno != 0)
  {
  HDEBUG(D_transport|D_acl|D_v)
    {
    debug_printf("failed: %s", CUstrerror(save_errno));
    if (save_errno == ETIMEDOUT)
      debug_printf(" (timeout=%s)", readconf_printtime(timeout));
    debug_printf("\n");
    }
  (void)close(sock);
  errno = save_errno;
  return -1;
  }

/* Both bind() and connect() succeeded */

else
  {
  union sockaddr_46 interface_sock;
  EXIM_SOCKLEN_T size = sizeof(interface_sock);
  HDEBUG(D_transport|D_acl|D_v) debug_printf("connected\n");
  if (getsockname(sock, (struct sockaddr *)(&interface_sock), &size) == 0)
    sending_ip_address = host_ntoa(-1, &interface_sock, NULL, &sending_port);
  else
    {
    log_write(0, LOG_MAIN | ((errno == ECONNRESET)? 0 : LOG_PANIC),
      "getsockname() failed: %s", strerror(errno));
    close(sock);
    return -1;
    }
  if (ob->keepalive) ip_keepalive(sock, host->address, TRUE);
  return sock;
  }
}

/*************************************************
*           Connect to remote host               *
*************************************************/

/* Create a socket, and connect it to a remote host. IPv6 addresses are
detected by checking for a colon in the address. AF_INET6 is defined even on
non-IPv6 systems, to enable the code to be less messy. However, on such systems
host->address will always be an IPv4 address.

The port field in the host item is used if it is set (usually router from SRV
records or elsewhere). In other cases, the default passed as an argument is
used, and the host item is updated with its value.

Arguments:
  host        host item containing name and address (and sometimes port)
  host_af     AF_INET or AF_INET6
  port        default remote port to connect to, in host byte order, for those
                hosts whose port setting is PORT_NONE
  interface   outgoing interface address or NULL
  timeout     timeout value or 0
  tb          transport

Returns:      connected socket number, or -1 with errno set
*/

int
smtp_connect(host_item *host, int host_af, int port, uschar *interface,
  int timeout, transport_instance * tb)
{
#ifdef EXPERIMENTAL_SOCKS
smtp_transport_options_block * ob =
  (smtp_transport_options_block *)tb->options_block;
#endif

if (host->port != PORT_NONE)
  {
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf("Transport port=%d replaced by host-specific port=%d\n", port,
      host->port);
  port = host->port;
  }
else host->port = port;    /* Set the port actually used */

HDEBUG(D_transport|D_acl|D_v)
  {
  uschar * s = US" ";
  if (interface) s = string_sprintf(" from %s ", interface);
#ifdef EXPERIMENTAL_SOCKS
  if (ob->socks_proxy) s = string_sprintf("%svia proxy ", s);
#endif
  debug_printf("Connecting to %s [%s]:%d%s... ",
    host->name, host->address, port, s);
  }

/* Create and connect the socket */

#ifdef EXPERIMENTAL_SOCKS
if (ob->socks_proxy)
  return socks_sock_connect(host, host_af, port, interface, tb, timeout);
#endif

return smtp_sock_connect(host, host_af, port, interface, tb, timeout);
}


/*************************************************
*        Flush outgoing command buffer           *
*************************************************/

/* This function is called only from smtp_write_command() below. It flushes
the buffer of outgoing commands. There is more than one in the buffer only when
pipelining.

Argument:
  outblock   the SMTP output block

Returns:     TRUE if OK, FALSE on error, with errno set
*/

static BOOL
flush_buffer(smtp_outblock *outblock)
{
int rc;

#ifdef SUPPORT_TLS
if (tls_out.active == outblock->sock)
  rc = tls_write(FALSE, outblock->buffer, outblock->ptr - outblock->buffer);
else
#endif

rc = send(outblock->sock, outblock->buffer, outblock->ptr - outblock->buffer, 0);
if (rc <= 0)
  {
  HDEBUG(D_transport|D_acl) debug_printf("send failed: %s\n", strerror(errno));
  return FALSE;
  }

outblock->ptr = outblock->buffer;
outblock->cmd_count = 0;
return TRUE;
}



/*************************************************
*             Write SMTP command                 *
*************************************************/

/* The formatted command is left in big_buffer so that it can be reflected in
any error message.

Arguments:
  outblock   contains buffer for pipelining, and socket
  noflush    if TRUE, save the command in the output buffer, for pipelining
  format     a format, starting with one of
             of HELO, MAIL FROM, RCPT TO, DATA, ".", or QUIT.
  ...        data for the format

Returns:     0 if command added to pipelining buffer, with nothing transmitted
            +n if n commands transmitted (may still have buffered the new one)
            -1 on error, with errno set
*/

int
smtp_write_command(smtp_outblock *outblock, BOOL noflush, const char *format, ...)
{
int count;
int rc = 0;
va_list ap;

va_start(ap, format);
if (!string_vformat(big_buffer, big_buffer_size, CS format, ap))
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "overlong write_command in outgoing "
    "SMTP");
va_end(ap);
count = Ustrlen(big_buffer);

if (count > outblock->buffersize)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "overlong write_command in outgoing "
    "SMTP");

if (count > outblock->buffersize - (outblock->ptr - outblock->buffer))
  {
  rc = outblock->cmd_count;                 /* flush resets */
  if (!flush_buffer(outblock)) return -1;
  }

Ustrncpy(CS outblock->ptr, big_buffer, count);
outblock->ptr += count;
outblock->cmd_count++;
count -= 2;
big_buffer[count] = 0;     /* remove \r\n for error message */

/* We want to hide the actual data sent in AUTH transactions from reflections
and logs. While authenticating, a flag is set in the outblock to enable this.
The AUTH command itself gets any data flattened. Other lines are flattened
completely. */

if (outblock->authenticating)
  {
  uschar *p = big_buffer;
  if (Ustrncmp(big_buffer, "AUTH ", 5) == 0)
    {
    p += 5;
    while (isspace(*p)) p++;
    while (!isspace(*p)) p++;
    while (isspace(*p)) p++;
    }
  while (*p != 0) *p++ = '*';
  }

HDEBUG(D_transport|D_acl|D_v) debug_printf("  SMTP>> %s\n", big_buffer);

if (!noflush)
  {
  rc += outblock->cmd_count;                /* flush resets */
  if (!flush_buffer(outblock)) return -1;
  }

return rc;
}



/*************************************************
*          Read one line of SMTP response        *
*************************************************/

/* This function reads one line of SMTP response from the server host. This may
not be a complete response - it could be just part of a multiline response. We
have to use a buffer for incoming packets, because when pipelining or using
LMTP, there may well be more than one response in a single packet. This
function is called only from the one that follows.

Arguments:
  inblock   the SMTP input block (contains holding buffer, socket, etc.)
  buffer    where to put the line
  size      space available for the line
  timeout   the timeout to use when reading a packet

Returns:    length of a line that has been put in the buffer
            -1 otherwise, with errno set
*/

static int
read_response_line(smtp_inblock *inblock, uschar *buffer, int size, int timeout)
{
uschar *p = buffer;
uschar *ptr = inblock->ptr;
uschar *ptrend = inblock->ptrend;
int sock = inblock->sock;

/* Loop for reading multiple packets or reading another packet after emptying
a previously-read one. */

for (;;)
  {
  int rc;

  /* If there is data in the input buffer left over from last time, copy
  characters from it until the end of a line, at which point we can return,
  having removed any whitespace (which will include CR) at the end of the line.
  The rules for SMTP say that lines end in CRLF, but there are have been cases
  of hosts using just LF, and other MTAs are reported to handle this, so we
  just look for LF. If we run out of characters before the end of a line,
  carry on to read the next incoming packet. */

  while (ptr < ptrend)
    {
    int c = *ptr++;
    if (c == '\n')
      {
      while (p > buffer && isspace(p[-1])) p--;
      *p = 0;
      inblock->ptr = ptr;
      return p - buffer;
      }
    *p++ = c;
    if (--size < 4)
      {
      *p = 0;                     /* Leave malformed line for error message */
      errno = ERRNO_SMTPFORMAT;
      return -1;
      }
    }

  /* Need to read a new input packet. */

  rc = ip_recv(sock, inblock->buffer, inblock->buffersize, timeout);
  if (rc <= 0) break;

  /* Another block of data has been successfully read. Set up the pointers
  and let the loop continue. */

  ptrend = inblock->ptrend = inblock->buffer + rc;
  ptr = inblock->buffer;
  DEBUG(D_transport|D_acl) debug_printf("read response data: size=%d\n", rc);
  }

/* Get here if there has been some kind of recv() error; errno is set, but we
ensure that the result buffer is empty before returning. */

*buffer = 0;
return -1;
}





/*************************************************
*              Read SMTP response                *
*************************************************/

/* This function reads an SMTP response with a timeout, and returns the
response in the given buffer, as a string. A multiline response will contain
newline characters between the lines. The function also analyzes the first
digit of the reply code and returns FALSE if it is not acceptable. FALSE is
also returned after a reading error. In this case buffer[0] will be zero, and
the error code will be in errno.

Arguments:
  inblock   the SMTP input block (contains holding buffer, socket, etc.)
  buffer    where to put the response
  size      the size of the buffer
  okdigit   the expected first digit of the response
  timeout   the timeout to use

Returns:    TRUE if a valid, non-error response was received; else FALSE
*/

BOOL
smtp_read_response(smtp_inblock *inblock, uschar *buffer, int size, int okdigit,
   int timeout)
{
uschar *ptr = buffer;
int count;

errno = 0;  /* Ensure errno starts out zero */

/* This is a loop to read and concatentate the lines that make up a multi-line
response. */

for (;;)
  {
  if ((count = read_response_line(inblock, ptr, size, timeout)) < 0)
    return FALSE;

  HDEBUG(D_transport|D_acl|D_v)
    debug_printf("  %s %s\n", (ptr == buffer)? "SMTP<<" : "      ", ptr);

  /* Check the format of the response: it must start with three digits; if
  these are followed by a space or end of line, the response is complete. If
  they are followed by '-' this is a multi-line response and we must look for
  another line until the final line is reached. The only use made of multi-line
  responses is to pass them back as error messages. We therefore just
  concatenate them all within the buffer, which should be large enough to
  accept any reasonable number of lines. */

  if (count < 3 ||
     !isdigit(ptr[0]) ||
     !isdigit(ptr[1]) ||
     !isdigit(ptr[2]) ||
     (ptr[3] != '-' && ptr[3] != ' ' && ptr[3] != 0))
    {
    errno = ERRNO_SMTPFORMAT;    /* format error */
    return FALSE;
    }

  /* If the line we have just read is a terminal line, line, we are done.
  Otherwise more data has to be read. */

  if (ptr[3] != '-') break;

  /* Move the reading pointer upwards in the buffer and insert \n between the
  components of a multiline response. Space is left for this by read_response_
  line(). */

  ptr += count;
  *ptr++ = '\n';
  size -= count + 1;
  }

/* Return a value that depends on the SMTP return code. On some systems a
non-zero value of errno has been seen at this point, so ensure it is zero,
because the caller of this function looks at errno when FALSE is returned, to
distinguish between an unexpected return code and other errors such as
timeouts, lost connections, etc. */

errno = 0;
return buffer[0] == okdigit;
}

/* End of smtp_out.c */
/* vi: aw ai sw=2
*/
