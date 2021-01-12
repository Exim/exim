/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"


/****************************************************************
*	Decode and split the argument of an AUTH command	*
****************************************************************/

/* If data was supplied on the AUTH command, decode it, and split it up into
multiple items at binary zeros. The strings are put into $auth1, $auth2, etc,
up to a maximum. To retain backwards compatibility, they are also put int $1,
$2, etc. If the data consists of the string "=" it indicates a single, empty
string. */

int
auth_read_input(const uschar * data)
{
if (Ustrcmp(data, "=") == 0)
  {
  auth_vars[0] = expand_nstring[++expand_nmax] = US"";
  expand_nlength[expand_nmax] = 0;
  }
else
  {
  uschar * clear, * end;
  int len;

  if ((len = b64decode(data, &clear)) < 0) return BAD64;
  DEBUG(D_auth) debug_printf("auth input decode:");
  for (end = clear + len; clear < end && expand_nmax < EXPAND_MAXN; )
    {
    DEBUG(D_auth) debug_printf(" '%s'", clear);
    if (expand_nmax < AUTH_VARS) auth_vars[expand_nmax] = clear;
    expand_nstring[++expand_nmax] = clear;
    while (*clear != 0) clear++;
    expand_nlength[expand_nmax] = clear++ - expand_nstring[expand_nmax];
    }
  DEBUG(D_auth) debug_printf("\n");
  }
return OK;
}




/*************************************************
*      Issue a challenge and get a response      *
*************************************************/

/* This function is used by authentication drivers to b64-encode and
output a challenge to the SMTP client, and read the response line.

Arguments:
   aptr       set to point to the response (which is in big_buffer)
   challenge  the challenge data (unencoded, may be binary)
   challen    the length of the challenge data, in bytes

Returns:      OK on success
              BAD64 if response too large for buffer
              CANCELLED if response is "*"
*/

int
auth_get_data(uschar ** aptr, const uschar * challenge, int challen)
{
int c;
int p = 0;
smtp_printf("334 %s\r\n", FALSE, b64encode(challenge, challen));
while ((c = receive_getc(GETC_BUFFER_UNLIMITED)) != '\n' && c != EOF)
  {
  if (p >= big_buffer_size - 1) return BAD64;
  big_buffer[p++] = c;
  }
if (p > 0 && big_buffer[p-1] == '\r') p--;
big_buffer[p] = 0;
DEBUG(D_receive) debug_printf("SMTP<< %s\n", big_buffer);
if (Ustrcmp(big_buffer, "*") == 0) return CANCELLED;
*aptr = big_buffer;
return OK;
}



int
auth_prompt(const uschar * challenge)
{
int rc, len;
uschar * resp, * clear, * end;

if ((rc = auth_get_data(&resp, challenge, Ustrlen(challenge))) != OK)
  return rc;
if ((len = b64decode(resp, &clear)) < 0)
  return BAD64;
end = clear + len;

/* This loop must run at least once, in case the length is zero */
do
  {
  if (expand_nmax < AUTH_VARS) auth_vars[expand_nmax] = clear;
  expand_nstring[++expand_nmax] = clear;
  while (*clear != 0) clear++;
  expand_nlength[expand_nmax] = clear++ - expand_nstring[expand_nmax];
  }
while (clear < end && expand_nmax < EXPAND_MAXN);
return OK;
}


/***********************************************
*	Send an AUTH-negotiation item		*
************************************************/

/* Expand and send one client auth item and read the response.
Include the AUTH command and method if tagged as "first".  Use the given buffer
for receiving the b6-encoded reply; decode it it return it in the string arg.

Return:
  OK          success
  FAIL_SEND   error after writing a command; errno is set
  FAIL        failed after reading a response;
              either errno is set (for timeouts, I/O failures) or
              the buffer contains the SMTP response line
  CANCELLED   the client cancelled authentication (often "fail" in expansion)
              the buffer may contain a message; if not, *buffer = 0
  ERROR       local problem (typically expansion error); message in buffer
  DEFER       more items expected
*/

int
auth_client_item(void * sx, auth_instance * ablock, const uschar ** inout,
  unsigned flags, int timeout, uschar * buffer, int buffsize)
{
int len, clear_len;
uschar * ss, * clear;

ss = US expand_cstring(*inout);
if (ss == *inout) ss = string_copy(ss);

/* Forced expansion failure is not an error; authentication is abandoned. On
all but the first string, we have to abandon the authentication attempt by
sending a line containing "*". Save the failed expansion string, because it
is in big_buffer, and that gets used by the sending function. */

if (!ss)
  {
  if (!(flags & AUTH_ITEM_FIRST))
    {
    if (smtp_write_command(sx, SCMD_FLUSH, "*\r\n") >= 0)
      (void) smtp_read_response(sx, US buffer, buffsize, '2', timeout);
    }
  if (f.expand_string_forcedfail)
    {
    *buffer = 0;       /* No message */
    return CANCELLED;
    }
  string_format(buffer, buffsize, "expansion of \"%s\" failed in %s "
    "authenticator: %s", *inout, ablock->name, expand_string_message);
  return ERROR;
  }

len = Ustrlen(ss);

/* The character ^ is used as an escape for a binary zero character, which is
needed for the PLAIN mechanism. It must be doubled if really needed.

The parsing ambiguity of ^^^ is taken as ^^ -> ^ ; ^ -> NUL - and there is
no way to get a leading ^ after a NUL.  We would need to intro new syntax to
support that (probably preferring to take a more-standard exim list as a source
and concat the elements with intervening NULs.  Either a magic marker on the
source string for client_send, or a new option). */

for (int i = 0; i < len; i++)
  if (ss[i] == '^')
    if (ss[i+1] != '^')
      ss[i] = 0;
    else
      if (--len > i+1) memmove(ss + i + 1, ss + i + 2, len - i);

/* The first string is attached to the AUTH command; others are sent
unembellished. */

if (flags & AUTH_ITEM_FIRST)
  {
  if (smtp_write_command(sx, SCMD_FLUSH, "AUTH %s%s%s\r\n",
       ablock->public_name, len == 0 ? "" : " ", b64encode(CUS ss, len)) < 0)
    return FAIL_SEND;
  }
else
  if (smtp_write_command(sx, SCMD_FLUSH, "%s\r\n", b64encode(CUS ss, len)) < 0)
    return FAIL_SEND;

/* If we receive a success response from the server, authentication
has succeeded. There may be more data to send, but is there any point
in provoking an error here? */

if (smtp_read_response(sx, buffer, buffsize, '2', timeout))
  {
  *inout = NULL;
  return OK;
  }

/* Not a success response. If errno != 0 there is some kind of transmission
error. Otherwise, check the response code in the buffer. If it starts with
'3', more data is expected. */

if (errno != 0 || buffer[0] != '3') return FAIL;

/* If there is no more data to send, we have to cancel the authentication
exchange and return ERROR. */

if (flags & AUTH_ITEM_LAST)
  {
  if (smtp_write_command(sx, SCMD_FLUSH, "*\r\n") >= 0)
    (void)smtp_read_response(sx, US buffer, buffsize, '2', timeout);
  string_format(buffer, buffsize, "Too few items in client_send in %s "
    "authenticator", ablock->name);
  return ERROR;
  }

/* Now that we know we'll continue, we put the received data into $auth<n>,
if possible. First, decode it: buffer+4 skips over the SMTP status code. */

clear_len = b64decode(buffer+4, &clear);

/* If decoding failed, the default is to terminate the authentication, and
return FAIL, with the SMTP response still in the buffer. However, if client_
ignore_invalid_base64 is set, we ignore the error, and put an empty string
into $auth<n>. */

if (clear_len < 0)
  {
  uschar *save_bad = string_copy(buffer);
  if (!(flags & AUTH_ITEM_IGN64))
    {
    if (smtp_write_command(sx, SCMD_FLUSH, "*\r\n") >= 0)
      (void)smtp_read_response(sx, US buffer, buffsize, '2', timeout);
    string_format(buffer, buffsize, "Invalid base64 string in server "
      "response \"%s\"", save_bad);
    return CANCELLED;
    }
  DEBUG(D_auth) debug_printf("bad b64 decode for '%s';"
       " ignoring due to client_ignore_invalid_base64\n", save_bad);
  clear = string_copy(US"");
  clear_len = 0;
  }

*inout = clear;
return DEFER;
}
  
  
/* End of get_data.c */
