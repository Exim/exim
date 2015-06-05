/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* General functions concerned with transportation, and generic options for all
transports. */


#include "exim.h"

#ifdef HAVE_LINUX_SENDFILE
#include <sys/sendfile.h>
#endif

/* Structure for keeping list of addresses that have been added to
Envelope-To:, in order to avoid duplication. */

struct aci {
  struct aci *next;
  address_item *ptr;
  };


/* Static data for write_chunk() */

static uschar *chunk_ptr;           /* chunk pointer */
static uschar *nl_check;            /* string to look for at line start */
static int     nl_check_length;     /* length of same */
static uschar *nl_escape;           /* string to insert */
static int     nl_escape_length;    /* length of same */
static int     nl_partial_match;    /* length matched at chunk end */


/* Generic options for transports, all of which live inside transport_instance
data blocks and which therefore have the opt_public flag set. Note that there
are other options living inside this structure which can be set only from
certain transports. */

optionlist optionlist_transports[] = {
  { "*expand_group",    opt_stringptr|opt_hidden|opt_public,
                 (void *)offsetof(transport_instance, expand_gid) },
  { "*expand_user",     opt_stringptr|opt_hidden|opt_public,
                 (void *)offsetof(transport_instance, expand_uid) },
  { "*headers_rewrite_flags", opt_int|opt_public|opt_hidden,
                 (void *)offsetof(transport_instance, rewrite_existflags) },
  { "*headers_rewrite_rules", opt_void|opt_public|opt_hidden,
                 (void *)offsetof(transport_instance, rewrite_rules) },
  { "*set_group",       opt_bool|opt_hidden|opt_public,
                 (void *)offsetof(transport_instance, gid_set) },
  { "*set_user",        opt_bool|opt_hidden|opt_public,
                 (void *)offsetof(transport_instance, uid_set) },
  { "body_only",        opt_bool|opt_public,
                 (void *)offsetof(transport_instance, body_only) },
  { "current_directory", opt_stringptr|opt_public,
                 (void *)offsetof(transport_instance, current_dir) },
  { "debug_print",      opt_stringptr | opt_public,
                 (void *)offsetof(transport_instance, debug_string) },
  { "delivery_date_add", opt_bool|opt_public,
                 (void *)(offsetof(transport_instance, delivery_date_add)) },
  { "disable_logging",  opt_bool|opt_public,
                 (void *)(offsetof(transport_instance, disable_logging)) },
  { "driver",           opt_stringptr|opt_public,
                 (void *)offsetof(transport_instance, driver_name) },
  { "envelope_to_add",   opt_bool|opt_public,
                 (void *)(offsetof(transport_instance, envelope_to_add)) },
#ifdef EXPERIMENTAL_EVENT
  { "event_action",     opt_stringptr | opt_public,
                 (void *)offsetof(transport_instance, event_action) },
#endif
  { "group",             opt_expand_gid|opt_public,
                 (void *)offsetof(transport_instance, gid) },
  { "headers_add",      opt_stringptr|opt_public|opt_rep_str,
                 (void *)offsetof(transport_instance, add_headers) },
  { "headers_only",     opt_bool|opt_public,
                 (void *)offsetof(transport_instance, headers_only) },
  { "headers_remove",   opt_stringptr|opt_public|opt_rep_str,
                 (void *)offsetof(transport_instance, remove_headers) },
  { "headers_rewrite",  opt_rewrite|opt_public,
                 (void *)offsetof(transport_instance, headers_rewrite) },
  { "home_directory",   opt_stringptr|opt_public,
                 (void *)offsetof(transport_instance, home_dir) },
  { "initgroups",       opt_bool|opt_public,
                 (void *)offsetof(transport_instance, initgroups) },
  { "message_size_limit", opt_stringptr|opt_public,
                 (void *)offsetof(transport_instance, message_size_limit) },
  { "rcpt_include_affixes", opt_bool|opt_public,
                 (void *)offsetof(transport_instance, rcpt_include_affixes) },
  { "retry_use_local_part", opt_bool|opt_public,
                 (void *)offsetof(transport_instance, retry_use_local_part) },
  { "return_path",      opt_stringptr|opt_public,
                 (void *)(offsetof(transport_instance, return_path)) },
  { "return_path_add",   opt_bool|opt_public,
                 (void *)(offsetof(transport_instance, return_path_add)) },
  { "shadow_condition", opt_stringptr|opt_public,
                 (void *)offsetof(transport_instance, shadow_condition) },
  { "shadow_transport", opt_stringptr|opt_public,
                 (void *)offsetof(transport_instance, shadow) },
  { "transport_filter", opt_stringptr|opt_public,
                 (void *)offsetof(transport_instance, filter_command) },
  { "transport_filter_timeout", opt_time|opt_public,
                 (void *)offsetof(transport_instance, filter_timeout) },
  { "user",             opt_expand_uid|opt_public,
                 (void *)offsetof(transport_instance, uid) }
};

int optionlist_transports_size =
  sizeof(optionlist_transports)/sizeof(optionlist);


/*************************************************
*             Initialize transport list           *
*************************************************/

/* Read the transports section of the configuration file, and set up a chain of
transport instances according to its contents. Each transport has generic
options and may also have its own private options. This function is only ever
called when transports == NULL. We use generic code in readconf to do most of
the work. */

void
transport_init(void)
{
transport_instance *t;

readconf_driver_init(US"transport",
  (driver_instance **)(&transports),     /* chain anchor */
  (driver_info *)transports_available,   /* available drivers */
  sizeof(transport_info),                /* size of info block */
  &transport_defaults,                   /* default values for generic options */
  sizeof(transport_instance),            /* size of instance block */
  optionlist_transports,                 /* generic options */
  optionlist_transports_size);

/* Now scan the configured transports and check inconsistencies. A shadow
transport is permitted only for local transports. */

for (t = transports; t != NULL; t = t->next)
  {
  if (!t->info->local)
    {
    if (t->shadow != NULL)
      log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
        "shadow transport not allowed on non-local transport %s", t->name);
    }

  if (t->body_only && t->headers_only)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "%s transport: body_only and headers_only are mutually exclusive",
      t->name);
  }
}



/*************************************************
*             Write block of data                *
*************************************************/

/* Subroutine called by write_chunk() and at the end of the message actually
to write a data block. Also called directly by some transports to write
additional data to the file descriptor (e.g. prefix, suffix).

If a transport wants data transfers to be timed, it sets a non-zero value in
transport_write_timeout. A non-zero transport_write_timeout causes a timer to
be set for each block of data written from here. If time runs out, then write()
fails and provokes an error return. The caller can then inspect sigalrm_seen to
check for a timeout.

On some systems, if a quota is exceeded during the write, the yield is the
number of bytes written rather than an immediate error code. This also happens
on some systems in other cases, for example a pipe that goes away because the
other end's process terminates (Linux). On other systems, (e.g. Solaris 2) you
get the error codes the first time.

The write() function is also interruptible; the Solaris 2.6 man page says:

     If write() is interrupted by a signal before it writes any
     data, it will return -1 with errno set to EINTR.

     If write() is interrupted by a signal after it successfully
     writes some data, it will return the number of bytes written.

To handle these cases, we want to restart the write() to output the remainder
of the data after a non-negative return from write(), except after a timeout.
In the error cases (EDQUOT, EPIPE) no bytes get written the second time, and a
proper error then occurs. In principle, after an interruption, the second
write() could suffer the same fate, but we do not want to continue for
evermore, so stick a maximum repetition count on the loop to act as a
longstop.

Arguments:
  fd        file descriptor to write to
  block     block of bytes to write
  len       number of bytes to write

Returns:    TRUE on success, FALSE on failure (with errno preserved);
              transport_count is incremented by the number of bytes written
*/

BOOL
transport_write_block(int fd, uschar *block, int len)
{
int i, rc, save_errno;
int local_timeout = transport_write_timeout;

/* This loop is for handling incomplete writes and other retries. In most
normal cases, it is only ever executed once. */

for (i = 0; i < 100; i++)
  {
  DEBUG(D_transport)
    debug_printf("writing data block fd=%d size=%d timeout=%d\n",
      fd, len, local_timeout);

  /* This code makes use of alarm() in order to implement the timeout. This
  isn't a very tidy way of doing things. Using non-blocking I/O with select()
  provides a neater approach. However, I don't know how to do this when TLS is
  in use. */

  if (transport_write_timeout <= 0)   /* No timeout wanted */
    {
    #ifdef SUPPORT_TLS
    if (tls_out.active == fd) rc = tls_write(FALSE, block, len); else
    #endif
    rc = write(fd, block, len);
    save_errno = errno;
    }

  /* Timeout wanted. */

  else
    {
    alarm(local_timeout);
    #ifdef SUPPORT_TLS
    if (tls_out.active == fd) rc = tls_write(FALSE, block, len); else
    #endif
    rc = write(fd, block, len);
    save_errno = errno;
    local_timeout = alarm(0);
    if (sigalrm_seen)
      {
      errno = ETIMEDOUT;
      return FALSE;
      }
    }

  /* Hopefully, the most common case is success, so test that first. */

  if (rc == len) { transport_count += len; return TRUE; }

  /* A non-negative return code is an incomplete write. Try again for the rest
  of the block. If we have exactly hit the timeout, give up. */

  if (rc >= 0)
    {
    len -= rc;
    block += rc;
    transport_count += rc;
    DEBUG(D_transport) debug_printf("write incomplete (%d)\n", rc);
    goto CHECK_TIMEOUT;   /* A few lines below */
    }

  /* A negative return code with an EINTR error is another form of
  incomplete write, zero bytes having been written */

  if (save_errno == EINTR)
    {
    DEBUG(D_transport)
      debug_printf("write interrupted before anything written\n");
    goto CHECK_TIMEOUT;   /* A few lines below */
    }

  /* A response of EAGAIN from write() is likely only in the case of writing
  to a FIFO that is not swallowing the data as fast as Exim is writing it. */

  if (save_errno == EAGAIN)
    {
    DEBUG(D_transport)
      debug_printf("write temporarily locked out, waiting 1 sec\n");
    sleep(1);

    /* Before continuing to try another write, check that we haven't run out of
    time. */

    CHECK_TIMEOUT:
    if (transport_write_timeout > 0 && local_timeout <= 0)
      {
      errno = ETIMEDOUT;
      return FALSE;
      }
    continue;
    }

  /* Otherwise there's been an error */

  DEBUG(D_transport) debug_printf("writing error %d: %s\n", save_errno,
    strerror(save_errno));
  errno = save_errno;
  return FALSE;
  }

/* We've tried and tried and tried but still failed */

errno = ERRNO_WRITEINCOMPLETE;
return FALSE;
}




/*************************************************
*             Write formatted string             *
*************************************************/

/* This is called by various transports. It is a convenience function.

Arguments:
  fd          file descriptor
  format      string format
  ...         arguments for format

Returns:      the yield of transport_write_block()
*/

BOOL
transport_write_string(int fd, const char *format, ...)
{
va_list ap;
va_start(ap, format);
if (!string_vformat(big_buffer, big_buffer_size, format, ap))
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "overlong formatted string in transport");
va_end(ap);
return transport_write_block(fd, big_buffer, Ustrlen(big_buffer));
}




/*************************************************
*              Write character chunk             *
*************************************************/

/* Subroutine used by transport_write_message() to scan character chunks for
newlines and act appropriately. The object is to minimise the number of writes.
The output byte stream is buffered up in deliver_out_buffer, which is written
only when it gets full, thus minimizing write operations and TCP packets.

Static data is used to handle the case when the last character of the previous
chunk was NL, or matched part of the data that has to be escaped.

Arguments:
  fd         file descript to write to
  chunk      pointer to data to write
  len        length of data to write
  usr_crlf   TRUE if CR LF is wanted at the end of each line

In addition, the static nl_xxx variables must be set as required.

Returns:     TRUE on success, FALSE on failure (with errno preserved)
*/

static BOOL
write_chunk(int fd, uschar *chunk, int len, BOOL use_crlf)
{
uschar *start = chunk;
uschar *end = chunk + len;
register uschar *ptr;
int mlen = DELIVER_OUT_BUFFER_SIZE - nl_escape_length - 2;

/* The assumption is made that the check string will never stretch over move
than one chunk since the only time there are partial matches is when copying
the body in large buffers. There is always enough room in the buffer for an
escape string, since the loop below ensures this for each character it
processes, and it won't have stuck in the escape string if it left a partial
match. */

if (nl_partial_match >= 0)
  {
  if (nl_check_length > 0 && len >= nl_check_length &&
      Ustrncmp(start, nl_check + nl_partial_match,
        nl_check_length - nl_partial_match) == 0)
    {
    Ustrncpy(chunk_ptr, nl_escape, nl_escape_length);
    chunk_ptr += nl_escape_length;
    start += nl_check_length - nl_partial_match;
    }

  /* The partial match was a false one. Insert the characters carried over
  from the previous chunk. */

  else if (nl_partial_match > 0)
    {
    Ustrncpy(chunk_ptr, nl_check, nl_partial_match);
    chunk_ptr += nl_partial_match;
    }

  nl_partial_match = -1;
  }

/* Now process the characters in the chunk. Whenever we hit a newline we check
for possible escaping. The code for the non-NL route should be as fast as
possible. */

for (ptr = start; ptr < end; ptr++)
  {
  register int ch;

  /* Flush the buffer if it has reached the threshold - we want to leave enough
  room for the next uschar, plus a possible extra CR for an LF, plus the escape
  string. */

  if (chunk_ptr - deliver_out_buffer > mlen)
    {
    if (!transport_write_block(fd, deliver_out_buffer,
          chunk_ptr - deliver_out_buffer))
      return FALSE;
    chunk_ptr = deliver_out_buffer;
    }

  if ((ch = *ptr) == '\n')
    {
    int left = end - ptr - 1;  /* count of chars left after NL */

    /* Insert CR before NL if required */

    if (use_crlf) *chunk_ptr++ = '\r';
    *chunk_ptr++ = '\n';
    transport_newlines++;

    /* The check_string test (formerly "from hack") replaces the specific
    string at the start of a line with an escape string (e.g. "From " becomes
    ">From " or "." becomes "..". It is a case-sensitive test. The length
    check above ensures there is always enough room to insert this string. */

    if (nl_check_length > 0)
      {
      if (left >= nl_check_length &&
          Ustrncmp(ptr+1, nl_check, nl_check_length) == 0)
        {
        Ustrncpy(chunk_ptr, nl_escape, nl_escape_length);
        chunk_ptr += nl_escape_length;
        ptr += nl_check_length;
        }

      /* Handle the case when there isn't enough left to match the whole
      check string, but there may be a partial match. We remember how many
      characters matched, and finish processing this chunk. */

      else if (left <= 0) nl_partial_match = 0;

      else if (Ustrncmp(ptr+1, nl_check, left) == 0)
        {
        nl_partial_match = left;
        ptr = end;
        }
      }
    }

  /* Not a NL character */

  else *chunk_ptr++ = ch;
  }

return TRUE;
}




/*************************************************
*        Generate address for RCPT TO            *
*************************************************/

/* This function puts together an address for RCPT to, using the caseful
version of the local part and the caseful version of the domain. If there is no
prefix or suffix, or if affixes are to be retained, we can just use the
original address. Otherwise, if there is a prefix but no suffix we can use a
pointer into the original address. If there is a suffix, however, we have to
build a new string.

Arguments:
  addr              the address item
  include_affixes   TRUE if affixes are to be included

Returns:            a string
*/

uschar *
transport_rcpt_address(address_item *addr, BOOL include_affixes)
{
uschar *at;
int plen, slen;

if (include_affixes)
  {
  setflag(addr, af_include_affixes);  /* Affects logged => line */
  return addr->address;
  }

if (addr->suffix == NULL)
  {
  if (addr->prefix == NULL) return addr->address;
  return addr->address + Ustrlen(addr->prefix);
  }

at = Ustrrchr(addr->address, '@');
plen = (addr->prefix == NULL)? 0 : Ustrlen(addr->prefix);
slen = Ustrlen(addr->suffix);

return string_sprintf("%.*s@%s", (at - addr->address - plen - slen),
   addr->address + plen, at + 1);
}


/*************************************************
*  Output Envelope-To: address & scan duplicates *
*************************************************/

/* This function is called from internal_transport_write_message() below, when
generating an Envelope-To: header line. It checks for duplicates of the given
address and its ancestors. When one is found, this function calls itself
recursively, to output the envelope address of the duplicate.

We want to avoid duplication in the list, which can arise for example when
A->B,C and then both B and C alias to D. This can also happen when there are
unseen drivers in use. So a list of addresses that have been output is kept in
the plist variable.

It is also possible to have loops in the address ancestry/duplication graph,
for example if there are two top level addresses A and B and we have A->B,C and
B->A. To break the loop, we use a list of processed addresses in the dlist
variable.

After handling duplication, this function outputs the progenitor of the given
address.

Arguments:
  p         the address we are interested in
  pplist    address of anchor of the list of addresses not to output
  pdlist    address of anchor of the list of processed addresses
  first     TRUE if this is the first address; set it FALSE afterwards
  fd        the file descriptor to write to
  use_crlf  to be passed on to write_chunk()

Returns:    FALSE if writing failed
*/

static BOOL
write_env_to(address_item *p, struct aci **pplist, struct aci **pdlist,
  BOOL *first, int fd, BOOL use_crlf)
{
address_item *pp;
struct aci *ppp;

/* Do nothing if we have already handled this address. If not, remember it
so that we don't handle it again. */

for (ppp = *pdlist; ppp != NULL; ppp = ppp->next)
  { if (p == ppp->ptr) return TRUE; }

ppp = store_get(sizeof(struct aci));
ppp->next = *pdlist;
*pdlist = ppp;
ppp->ptr = p;

/* Now scan up the ancestry, checking for duplicates at each generation. */

for (pp = p;; pp = pp->parent)
  {
  address_item *dup;
  for (dup = addr_duplicate; dup != NULL; dup = dup->next)
    {
    if (dup->dupof != pp) continue;   /* Not a dup of our address */
    if (!write_env_to(dup, pplist, pdlist, first, fd, use_crlf)) return FALSE;
    }
  if (pp->parent == NULL) break;
  }

/* Check to see if we have already output the progenitor. */

for (ppp = *pplist; ppp != NULL; ppp = ppp->next)
  { if (pp == ppp->ptr) break; }
if (ppp != NULL) return TRUE;

/* Remember what we have output, and output it. */

ppp = store_get(sizeof(struct aci));
ppp->next = *pplist;
*pplist = ppp;
ppp->ptr = pp;

if (!(*first) && !write_chunk(fd, US",\n ", 3, use_crlf)) return FALSE;
*first = FALSE;
return write_chunk(fd, pp->address, Ustrlen(pp->address), use_crlf);
}




/* Add/remove/rewwrite headers, and send them plus the empty-line sparator.

Globals:
  header_list

Arguments:
  addr                  (chain of) addresses (for extra headers), or NULL;
                          only the first address is used
  fd                    file descriptor to write the message to
  sendfn		function for output
  use_crlf		turn NL into CR LF
  rewrite_rules         chain of header rewriting rules
  rewrite_existflags    flags for the rewriting rules

Returns:                TRUE on success; FALSE on failure.
*/
BOOL
transport_headers_send(address_item *addr, int fd, uschar *add_headers, uschar *remove_headers,
  BOOL (*sendfn)(int fd, uschar * s, int len, BOOL use_crlf),
  BOOL use_crlf, rewrite_rule *rewrite_rules, int rewrite_existflags)
{
header_line *h;

/* Then the message's headers. Don't write any that are flagged as "old";
that means they were rewritten, or are a record of envelope rewriting, or
were removed (e.g. Bcc). If remove_headers is not null, skip any headers that
match any entries therein.  It is a colon-sep list; expand the items
separately and squash any empty ones.
Then check addr->prop.remove_headers too, provided that addr is not NULL. */

for (h = header_list; h != NULL; h = h->next) if (h->type != htype_old)
  {
  int i;
  const uschar *list = remove_headers;

  BOOL include_header = TRUE;

  for (i = 0; i < 2; i++)    /* For remove_headers && addr->prop.remove_headers */
    {
    if (list)
      {
      int sep = ':';         /* This is specified as a colon-separated list */
      uschar *s, *ss;
      while ((s = string_nextinlist(&list, &sep, NULL, 0)))
	{
	int len;

	if (i == 0)
	  if (!(s = expand_string(s)) && !expand_string_forcedfail)
	    {
	    errno = ERRNO_CHHEADER_FAIL;
	    return FALSE;
	    }
	len = Ustrlen(s);
	if (strncmpic(h->text, s, len) != 0) continue;
	ss = h->text + len;
	while (*ss == ' ' || *ss == '\t') ss++;
	if (*ss == ':') break;
	}
      if (s != NULL) { include_header = FALSE; break; }
      }
    if (addr != NULL) list = addr->prop.remove_headers;
    }

  /* If this header is to be output, try to rewrite it if there are rewriting
  rules. */

  if (include_header)
    {
    if (rewrite_rules)
      {
      void *reset_point = store_get(0);
      header_line *hh;

      if ((hh = rewrite_header(h, NULL, NULL, rewrite_rules, rewrite_existflags, FALSE)))
	{
	if (!sendfn(fd, hh->text, hh->slen, use_crlf)) return FALSE;
	store_reset(reset_point);
	continue;     /* With the next header line */
	}
      }

    /* Either no rewriting rules, or it didn't get rewritten */

    if (!sendfn(fd, h->text, h->slen, use_crlf)) return FALSE;
    }

  /* Header removed */

  else
    {
    DEBUG(D_transport) debug_printf("removed header line:\n%s---\n", h->text);
    }
  }

/* Add on any address-specific headers. If there are multiple addresses,
they will all have the same headers in order to be batched. The headers
are chained in reverse order of adding (so several addresses from the
same alias might share some of them) but we want to output them in the
opposite order. This is a bit tedious, but there shouldn't be very many
of them. We just walk the list twice, reversing the pointers each time,
but on the second time, write out the items.

Headers added to an address by a router are guaranteed to end with a newline.
*/

if (addr)
  {
  int i;
  header_line *hprev = addr->prop.extra_headers;
  header_line *hnext;
  for (i = 0; i < 2; i++)
    {
    for (h = hprev, hprev = NULL; h != NULL; h = hnext)
      {
      hnext = h->next;
      h->next = hprev;
      hprev = h;
      if (i == 1)
	{
	if (!sendfn(fd, h->text, h->slen, use_crlf)) return FALSE;
	DEBUG(D_transport)
	  debug_printf("added header line(s):\n%s---\n", h->text);
	}
      }
    }
  }

/* If a string containing additional headers exists it is a newline-sep
list.  Expand each item and write out the result.  This is done last so that
if it (deliberately or accidentally) isn't in header format, it won't mess
up any other headers. An empty string or a forced expansion failure are
noops. An added header string from a transport may not end with a newline;
add one if it does not. */

if (add_headers)
  {
  int sep = '\n';
  uschar * s;

  while ((s = string_nextinlist(CUSS &add_headers, &sep, NULL, 0)))
    if (!(s = expand_string(s)))
      {
      if (!expand_string_forcedfail)
	{ errno = ERRNO_CHHEADER_FAIL; return FALSE; }
      }
    else
      {
      int len = Ustrlen(s);
      if (len > 0)
	{
	if (!sendfn(fd, s, len, use_crlf)) return FALSE;
	if (s[len-1] != '\n' && !sendfn(fd, US"\n", 1, use_crlf))
	  return FALSE;
	DEBUG(D_transport)
	  {
	  debug_printf("added header line:\n%s", s);
	  if (s[len-1] != '\n') debug_printf("\n");
	  debug_printf("---\n");
	  }
	}
      }
  }

/* Separate headers from body with a blank line */

return sendfn(fd, US"\n", 1, use_crlf);
}


/*************************************************
*                Write the message               *
*************************************************/

/* This function writes the message to the given file descriptor. The headers
are in the in-store data structure, and the rest of the message is in the open
file descriptor deliver_datafile. Make sure we start it at the beginning.

. If add_return_path is TRUE, a "return-path:" header is added to the message,
  containing the envelope sender's address.

. If add_envelope_to is TRUE, a "envelope-to:" header is added to the message,
  giving the top-level envelope address that caused this delivery to happen.

. If add_delivery_date is TRUE, a "delivery-date:" header is added to the
  message. It gives the time and date that delivery took place.

. If check_string is not null, the start of each line is checked for that
  string. If it is found, it is replaced by escape_string. This used to be
  the "from hack" for files, and "smtp_dots" for escaping SMTP dots.

. If use_crlf is true, newlines are turned into CRLF (SMTP output).

The yield is TRUE if all went well, and FALSE if not. Exit *immediately* after
any writing or reading error, leaving the code in errno intact. Error exits
can include timeouts for certain transports, which are requested by setting
transport_write_timeout non-zero.

Arguments:
  addr                  (chain of) addresses (for extra headers), or NULL;
                          only the first address is used
  fd                    file descriptor to write the message to
  options               bit-wise options:
    add_return_path       if TRUE, add a "return-path" header
    add_envelope_to       if TRUE, add a "envelope-to" header
    add_delivery_date     if TRUE, add a "delivery-date" header
    use_crlf              if TRUE, turn NL into CR LF
    end_dot               if TRUE, send a terminating "." line at the end
    no_headers            if TRUE, omit the headers
    no_body               if TRUE, omit the body
  size_limit            if > 0, this is a limit to the size of message written;
                          it is used when returning messages to their senders,
                          and is approximate rather than exact, owing to chunk
                          buffering
  add_headers           a string containing one or more headers to add; it is
                          expanded, and must be in correct RFC 822 format as
                          it is transmitted verbatim; NULL => no additions,
                          and so does empty string or forced expansion fail
  remove_headers        a colon-separated list of headers to remove, or NULL
  check_string          a string to check for at the start of lines, or NULL
  escape_string         a string to insert in front of any check string
  rewrite_rules         chain of header rewriting rules
  rewrite_existflags    flags for the rewriting rules

Returns:                TRUE on success; FALSE (with errno) on failure.
                        In addition, the global variable transport_count
                        is incremented by the number of bytes written.
*/

static BOOL
internal_transport_write_message(address_item *addr, int fd, int options,
  int size_limit, uschar *add_headers, uschar *remove_headers, uschar *check_string,
  uschar *escape_string, rewrite_rule *rewrite_rules, int rewrite_existflags)
{
int written = 0;
int len;
BOOL use_crlf  = (options & topt_use_crlf)  != 0;

/* Initialize pointer in output buffer. */

chunk_ptr = deliver_out_buffer;

/* Set up the data for start-of-line data checking and escaping */

nl_partial_match = -1;
if (check_string != NULL && escape_string != NULL)
  {
  nl_check = check_string;
  nl_check_length = Ustrlen(nl_check);
  nl_escape = escape_string;
  nl_escape_length = Ustrlen(nl_escape);
  }
else nl_check_length = nl_escape_length = 0;

/* Whether the escaping mechanism is applied to headers or not is controlled by
an option (set for SMTP, not otherwise). Negate the length if not wanted till
after the headers. */

if ((options & topt_escape_headers) == 0) nl_check_length = -nl_check_length;

/* Write the headers if required, including any that have to be added. If there
are header rewriting rules, apply them. */

if ((options & topt_no_headers) == 0)
  {
  /* Add return-path: if requested. */

  if ((options & topt_add_return_path) != 0)
    {
    uschar buffer[ADDRESS_MAXLENGTH + 20];
    sprintf(CS buffer, "Return-path: <%.*s>\n", ADDRESS_MAXLENGTH,
      return_path);
    if (!write_chunk(fd, buffer, Ustrlen(buffer), use_crlf)) return FALSE;
    }

  /* Add envelope-to: if requested */

  if ((options & topt_add_envelope_to) != 0)
    {
    BOOL first = TRUE;
    address_item *p;
    struct aci *plist = NULL;
    struct aci *dlist = NULL;
    void *reset_point = store_get(0);

    if (!write_chunk(fd, US"Envelope-to: ", 13, use_crlf)) return FALSE;

    /* Pick up from all the addresses. The plist and dlist variables are
    anchors for lists of addresses already handled; they have to be defined at
    this level becuase write_env_to() calls itself recursively. */

    for (p = addr; p != NULL; p = p->next)
      {
      if (!write_env_to(p, &plist, &dlist, &first, fd, use_crlf)) return FALSE;
      }

    /* Add a final newline and reset the store used for tracking duplicates */

    if (!write_chunk(fd, US"\n", 1, use_crlf)) return FALSE;
    store_reset(reset_point);
    }

  /* Add delivery-date: if requested. */

  if ((options & topt_add_delivery_date) != 0)
    {
    uschar buffer[100];
    sprintf(CS buffer, "Delivery-date: %s\n", tod_stamp(tod_full));
    if (!write_chunk(fd, buffer, Ustrlen(buffer), use_crlf)) return FALSE;
    }

  /* Then the message's headers. Don't write any that are flagged as "old";
  that means they were rewritten, or are a record of envelope rewriting, or
  were removed (e.g. Bcc). If remove_headers is not null, skip any headers that
  match any entries therein. Then check addr->prop.remove_headers too, provided that
  addr is not NULL. */
  if (!transport_headers_send(addr, fd, add_headers, remove_headers, &write_chunk,
	use_crlf, rewrite_rules, rewrite_existflags))
    return FALSE;
  }

/* If the body is required, ensure that the data for check strings (formerly
the "from hack") is enabled by negating the length if necessary. (It will be
negative in cases where it isn't to apply to the headers). Then ensure the body
is positioned at the start of its file (following the message id), then write
it, applying the size limit if required. */

if ((options & topt_no_body) == 0)
  {
  nl_check_length = abs(nl_check_length);
  nl_partial_match = 0;
  lseek(deliver_datafile, SPOOL_DATA_START_OFFSET, SEEK_SET);
  while ((len = read(deliver_datafile, deliver_in_buffer,
           DELIVER_IN_BUFFER_SIZE)) > 0)
    {
    if (!write_chunk(fd, deliver_in_buffer, len, use_crlf)) return FALSE;
    if (size_limit > 0)
      {
      written += len;
      if (written > size_limit)
        {
        len = 0;    /* Pretend EOF */
        break;
        }
      }
    }

  /* A read error on the body will have left len == -1 and errno set. */

  if (len != 0) return FALSE;
  }

/* Finished with the check string */

nl_check_length = nl_escape_length = 0;

/* If requested, add a terminating "." line (SMTP output). */

if ((options & topt_end_dot) != 0 && !write_chunk(fd, US".\n", 2, use_crlf))
  return FALSE;

/* Write out any remaining data in the buffer before returning. */

return (len = chunk_ptr - deliver_out_buffer) <= 0 ||
  transport_write_block(fd, deliver_out_buffer, len);
}


#ifndef DISABLE_DKIM

/***************************************************************************************************
*    External interface to write the message, while signing it with DKIM and/or Domainkeys         *
***************************************************************************************************/

/* This function is a wrapper around transport_write_message().
   It is only called from the smtp transport if DKIM or Domainkeys support
   is compiled in.  The function sets up a replacement fd into a -K file,
   then calls the normal function. This way, the exact bits that exim would
   have put "on the wire" will end up in the file (except for TLS
   encapsulation, which is the very very last thing). When we are done
   signing the file, send the signed message down the original fd (or TLS fd).

Arguments:
  as for internal_transport_write_message() above, with additional arguments:
   uschar *dkim_private_key  DKIM: The private key to use (filename or
				    plain data)
   uschar *dkim_domain       DKIM: The domain to use
   uschar *dkim_selector     DKIM: The selector to use.
   uschar *dkim_canon        DKIM: The canonalization scheme to use,
				    "simple" or "relaxed"
   uschar *dkim_strict       DKIM: What to do if signing fails:
				  1/true  => throw error
				  0/false => send anyway
   uschar *dkim_sign_headers DKIM: List of headers that should be included
				    in signature generation

Returns:       TRUE on success; FALSE (with errno) for any failure
*/

BOOL
dkim_transport_write_message(address_item *addr, int fd, int options,
  int size_limit, uschar *add_headers, uschar *remove_headers,
  uschar *check_string, uschar *escape_string, rewrite_rule *rewrite_rules,
  int rewrite_existflags, uschar *dkim_private_key, uschar *dkim_domain,
  uschar *dkim_selector, uschar *dkim_canon, uschar *dkim_strict, uschar *dkim_sign_headers
  )
{
int dkim_fd;
int save_errno = 0;
BOOL rc;
uschar dkim_spool_name[256];
char sbuf[2048];
int sread = 0;
int wwritten = 0;
uschar *dkim_signature = NULL;

/* If we can't sign, just call the original function. */

if (!(dkim_private_key && dkim_domain && dkim_selector))
  return transport_write_message(addr, fd, options,
	    size_limit, add_headers, remove_headers,
	    check_string, escape_string, rewrite_rules,
	    rewrite_existflags);

(void)string_format(dkim_spool_name, 256, "%s/input/%s/%s-%d-K",
	spool_directory, message_subdir, message_id, (int)getpid());

if ((dkim_fd = Uopen(dkim_spool_name, O_RDWR|O_CREAT|O_TRUNC, SPOOL_MODE)) < 0)
  {
  /* Can't create spool file. Ugh. */
  rc = FALSE;
  save_errno = errno;
  goto CLEANUP;
  }

/* Call original function to write the -K file */

rc = transport_write_message(addr, dkim_fd, options,
  size_limit, add_headers, remove_headers,
  check_string, escape_string, rewrite_rules,
  rewrite_existflags);

/* Save error state. We must clean up before returning. */
if (!rc)
  {
  save_errno = errno;
  goto CLEANUP;
  }

if (dkim_private_key && dkim_domain && dkim_selector)
  {
  /* Rewind file and feed it to the goats^W DKIM lib */
  lseek(dkim_fd, 0, SEEK_SET);
  dkim_signature = dkim_exim_sign(dkim_fd,
				  dkim_private_key,
				  dkim_domain,
				  dkim_selector,
				  dkim_canon,
				  dkim_sign_headers);
  if (!dkim_signature)
    {
    if (dkim_strict)
      {
      uschar *dkim_strict_result = expand_string(dkim_strict);
      if (dkim_strict_result)
	if ( (strcmpic(dkim_strict,US"1") == 0) ||
	     (strcmpic(dkim_strict,US"true") == 0) ) 
	  {
	  /* Set errno to something halfway meaningful */
	  save_errno = EACCES;
	  log_write(0, LOG_MAIN, "DKIM: message could not be signed,"
	    " and dkim_strict is set. Deferring message delivery.");
	  rc = FALSE;
	  goto CLEANUP;
	  }
      }
    }
  else
    {
    int siglen = Ustrlen(dkim_signature);
    while(siglen > 0)
      {
#ifdef SUPPORT_TLS
      wwritten = tls_out.active == fd
	? tls_write(FALSE, dkim_signature, siglen)
	: write(fd, dkim_signature, siglen);
#else
      wwritten = write(fd, dkim_signature, siglen);
#endif
      if (wwritten == -1)
        {
	/* error, bail out */
	save_errno = errno;
	rc = FALSE;
	goto CLEANUP;
	}
      siglen -= wwritten;
      dkim_signature += wwritten;
      }
    }
  }

#ifdef HAVE_LINUX_SENDFILE
/* We can use sendfile() to shove the file contents
   to the socket. However only if we don't use TLS,
   as then there's another layer of indirection
   before the data finally hits the socket. */
if (tls_out.active != fd)
  {
  off_t size = lseek(dkim_fd, 0, SEEK_END); /* Fetch file size */
  ssize_t copied = 0;
  off_t offset = 0;

  /* Rewind file */
  lseek(dkim_fd, 0, SEEK_SET);

  while(copied >= 0 && offset < size)
    copied = sendfile(fd, dkim_fd, &offset, size - offset);
  if (copied < 0)
    {
    save_errno = errno;
    rc = FALSE;
    }
  }
else

#endif

  {
  /* Rewind file */
  lseek(dkim_fd, 0, SEEK_SET);

  /* Send file down the original fd */
  while((sread = read(dkim_fd, sbuf, 2048)) > 0)
    {
    char *p = sbuf;
    /* write the chunk */

    while (sread)
      {
#ifdef SUPPORT_TLS
      wwritten = tls_out.active == fd
	? tls_write(FALSE, US p, sread)
	: write(fd, p, sread);
#else
      wwritten = write(fd, p, sread);
#endif
      if (wwritten == -1)
	{
	/* error, bail out */
	save_errno = errno;
	rc = FALSE;
	goto CLEANUP;
	}
      p += wwritten;
      sread -= wwritten;
      }
    }

  if (sread == -1)
    {
    save_errno = errno;
    rc = FALSE;
    }
  }

CLEANUP:
/* unlink -K file */
(void)close(dkim_fd);
Uunlink(dkim_spool_name);
errno = save_errno;
return rc;
}

#endif



/*************************************************
*    External interface to write the message     *
*************************************************/

/* If there is no filtering required, call the internal function above to do
the real work, passing over all the arguments from this function. Otherwise,
set up a filtering process, fork another process to call the internal function
to write to the filter, and in this process just suck from the filter and write
down the given fd. At the end, tidy up the pipes and the processes.

Arguments:     as for internal_transport_write_message() above

Returns:       TRUE on success; FALSE (with errno) for any failure
               transport_count is incremented by the number of bytes written
*/

BOOL
transport_write_message(address_item *addr, int fd, int options,
  int size_limit, uschar *add_headers, uschar *remove_headers,
  uschar *check_string, uschar *escape_string, rewrite_rule *rewrite_rules,
  int rewrite_existflags)
{
BOOL use_crlf;
BOOL last_filter_was_NL = TRUE;
int rc, len, yield, fd_read, fd_write, save_errno;
int pfd[2];
pid_t filter_pid, write_pid;

transport_filter_timed_out = FALSE;

/* If there is no filter command set up, call the internal function that does
the actual work, passing it the incoming fd, and return its result. */

if (transport_filter_argv == NULL)
  return internal_transport_write_message(addr, fd, options, size_limit,
    add_headers, remove_headers, check_string, escape_string,
    rewrite_rules, rewrite_existflags);

/* Otherwise the message must be written to a filter process and read back
before being written to the incoming fd. First set up the special processing to
be done during the copying. */

use_crlf  = (options & topt_use_crlf) != 0;
nl_partial_match = -1;

if (check_string != NULL && escape_string != NULL)
  {
  nl_check = check_string;
  nl_check_length = Ustrlen(nl_check);
  nl_escape = escape_string;
  nl_escape_length = Ustrlen(nl_escape);
  }
else nl_check_length = nl_escape_length = 0;

/* Start up a subprocess to run the command. Ensure that our main fd will
be closed when the subprocess execs, but remove the flag afterwards.
(Otherwise, if this is a TCP/IP socket, it can't get passed on to another
process to deliver another message.) We get back stdin/stdout file descriptors.
If the process creation failed, give an error return. */

fd_read = -1;
fd_write = -1;
save_errno = 0;
yield = FALSE;
write_pid = (pid_t)(-1);

(void)fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
filter_pid = child_open(USS transport_filter_argv, NULL, 077,
 &fd_write, &fd_read, FALSE);
(void)fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) & ~FD_CLOEXEC);
if (filter_pid < 0) goto TIDY_UP;      /* errno set */

DEBUG(D_transport)
  debug_printf("process %d running as transport filter: write=%d read=%d\n",
    (int)filter_pid, fd_write, fd_read);

/* Fork subprocess to write the message to the filter, and return the result
via a(nother) pipe. While writing to the filter, we do not do the CRLF,
smtp dots, or check string processing. */

if (pipe(pfd) != 0) goto TIDY_UP;      /* errno set */
if ((write_pid = fork()) == 0)
  {
  BOOL rc;
  (void)close(fd_read);
  (void)close(pfd[pipe_read]);
  nl_check_length = nl_escape_length = 0;
  rc = internal_transport_write_message(addr, fd_write,
    (options & ~(topt_use_crlf | topt_end_dot)),
    size_limit, add_headers, remove_headers, NULL, NULL,
    rewrite_rules, rewrite_existflags);
  save_errno = errno;
  if (  write(pfd[pipe_write], (void *)&rc, sizeof(BOOL))
        != sizeof(BOOL)
     || write(pfd[pipe_write], (void *)&save_errno, sizeof(int))
        != sizeof(int)
     || write(pfd[pipe_write], (void *)&(addr->more_errno), sizeof(int))
        != sizeof(int)
     )
    rc = FALSE;	/* compiler quietening */
  _exit(0);
  }
save_errno = errno;

/* Parent process: close our copy of the writing subprocess' pipes. */

(void)close(pfd[pipe_write]);
(void)close(fd_write);
fd_write = -1;

/* Writing process creation failed */

if (write_pid < 0)
  {
  errno = save_errno;    /* restore */
  goto TIDY_UP;
  }

/* When testing, let the subprocess get going */

if (running_in_test_harness) millisleep(250);

DEBUG(D_transport)
  debug_printf("process %d writing to transport filter\n", (int)write_pid);

/* Copy the message from the filter to the output fd. A read error leaves len
== -1 and errno set. We need to apply a timeout to the read, to cope with
the case when the filter gets stuck, but it can be quite a long one. The
default is 5m, but this is now configurable. */

DEBUG(D_transport) debug_printf("copying from the filter\n");

/* Copy the output of the filter, remembering if the last character was NL. If
no data is returned, that counts as "ended with NL" (default setting of the
variable is TRUE). */

chunk_ptr = deliver_out_buffer;

for (;;)
  {
  sigalrm_seen = FALSE;
  alarm(transport_filter_timeout);
  len = read(fd_read, deliver_in_buffer, DELIVER_IN_BUFFER_SIZE);
  alarm(0);
  if (sigalrm_seen)
    {
    errno = ETIMEDOUT;
    transport_filter_timed_out = TRUE;
    goto TIDY_UP;
    }

  /* If the read was successful, write the block down the original fd,
  remembering whether it ends in \n or not. */

  if (len > 0)
    {
    if (!write_chunk(fd, deliver_in_buffer, len, use_crlf)) goto TIDY_UP;
    last_filter_was_NL = (deliver_in_buffer[len-1] == '\n');
    }

  /* Otherwise, break the loop. If we have hit EOF, set yield = TRUE. */

  else
    {
    if (len == 0) yield = TRUE;
    break;
    }
  }

/* Tidying up code. If yield = FALSE there has been an error and errno is set
to something. Ensure the pipes are all closed and the processes are removed. If
there has been an error, kill the processes before waiting for them, just to be
sure. Also apply a paranoia timeout. */

TIDY_UP:
save_errno = errno;

(void)close(fd_read);
if (fd_write > 0) (void)close(fd_write);

if (!yield)
  {
  if (filter_pid > 0) kill(filter_pid, SIGKILL);
  if (write_pid > 0)  kill(write_pid, SIGKILL);
  }

/* Wait for the filter process to complete. */

DEBUG(D_transport) debug_printf("waiting for filter process\n");
if (filter_pid > 0 && (rc = child_close(filter_pid, 30)) != 0 && yield)
  {
  yield = FALSE;
  save_errno = ERRNO_FILTER_FAIL;
  addr->more_errno = rc;
  DEBUG(D_transport) debug_printf("filter process returned %d\n", rc);
  }

/* Wait for the writing process to complete. If it ends successfully,
read the results from its pipe, provided we haven't already had a filter
process failure. */

DEBUG(D_transport) debug_printf("waiting for writing process\n");
if (write_pid > 0)
  {
  rc = child_close(write_pid, 30);
  if (yield)
    {
    if (rc == 0)
      {
      BOOL ok;
      int dummy = read(pfd[pipe_read], (void *)&ok, sizeof(BOOL));
      if (!ok)
        {
        dummy = read(pfd[pipe_read], (void *)&save_errno, sizeof(int));
        dummy = read(pfd[pipe_read], (void *)&(addr->more_errno), sizeof(int));
        yield = FALSE;
        }
      }
    else
      {
      yield = FALSE;
      save_errno = ERRNO_FILTER_FAIL;
      addr->more_errno = rc;
      DEBUG(D_transport) debug_printf("writing process returned %d\n", rc);
      }
    }
  }
(void)close(pfd[pipe_read]);

/* If there have been no problems we can now add the terminating "." if this is
SMTP output, turning off escaping beforehand. If the last character from the
filter was not NL, insert a NL to make the SMTP protocol work. */

if (yield)
  {
  nl_check_length = nl_escape_length = 0;
  if ((options & topt_end_dot) != 0 && (last_filter_was_NL?
        !write_chunk(fd, US".\n", 2, use_crlf) :
        !write_chunk(fd, US"\n.\n", 3, use_crlf)))
    {
    yield = FALSE;
    }

  /* Write out any remaining data in the buffer. */

  else
    {
    yield = (len = chunk_ptr - deliver_out_buffer) <= 0 ||
      transport_write_block(fd, deliver_out_buffer, len);
    }
  }
else errno = save_errno;      /* From some earlier error */

DEBUG(D_transport)
  {
  debug_printf("end of filtering transport writing: yield=%d\n", yield);
  if (!yield)
    debug_printf("errno=%d more_errno=%d\n", errno, addr->more_errno);
  }

return yield;
}





/*************************************************
*            Update waiting database             *
*************************************************/

/* This is called when an address is deferred by remote transports that are
capable of sending more than one message over one connection. A database is
maintained for each transport, keeping track of which messages are waiting for
which hosts. The transport can then consult this when eventually a successful
delivery happens, and if it finds that another message is waiting for the same
host, it can fire up a new process to deal with it using the same connection.

The database records are keyed by host name. They can get full if there are
lots of messages waiting, and so there is a continuation mechanism for them.

Each record contains a list of message ids, packed end to end without any
zeros. Each one is MESSAGE_ID_LENGTH bytes long. The count field says how many
in this record, and the sequence field says if there are any other records for
this host. If the sequence field is 0, there are none. If it is 1, then another
record with the name <hostname>:0 exists; if it is 2, then two other records
with sequence numbers 0 and 1 exist, and so on.

Currently, an exhaustive search of all continuation records has to be done to
determine whether to add a message id to a given record. This shouldn't be
too bad except in extreme cases. I can't figure out a *simple* way of doing
better.

Old records should eventually get swept up by the exim_tidydb utility.

Arguments:
  hostlist  list of hosts that this message could be sent to
  tpname    name of the transport

Returns:    nothing
*/

void
transport_update_waiting(host_item *hostlist, uschar *tpname)
{
uschar buffer[256];
const uschar *prevname = US"";
host_item *host;
open_db dbblock;
open_db *dbm_file;

DEBUG(D_transport) debug_printf("updating wait-%s database\n", tpname);

/* Open the database for this transport */

sprintf(CS buffer, "wait-%.200s", tpname);
dbm_file = dbfn_open(buffer, O_RDWR, &dbblock, TRUE);
if (dbm_file == NULL) return;

/* Scan the list of hosts for which this message is waiting, and ensure
that the message id is in each host record. */

for (host = hostlist; host!= NULL; host = host->next)
  {
  BOOL already = FALSE;
  dbdata_wait *host_record;
  uschar *s;
  int i, host_length;

  /* Skip if this is the same host as we just processed; otherwise remember
  the name for next time. */

  if (Ustrcmp(prevname, host->name) == 0) continue;
  prevname = host->name;

  /* Look up the host record; if there isn't one, make an empty one. */

  host_record = dbfn_read(dbm_file, host->name);
  if (host_record == NULL)
    {
    host_record = store_get(sizeof(dbdata_wait) + MESSAGE_ID_LENGTH);
    host_record->count = host_record->sequence = 0;
    }

  /* Compute the current length */

  host_length = host_record->count * MESSAGE_ID_LENGTH;

  /* Search the record to see if the current message is already in it. */

  for (s = host_record->text; s < host_record->text + host_length;
       s += MESSAGE_ID_LENGTH)
    {
    if (Ustrncmp(s, message_id, MESSAGE_ID_LENGTH) == 0)
      { already = TRUE; break; }
    }

  /* If we haven't found this message in the main record, search any
  continuation records that exist. */

  for (i = host_record->sequence - 1; i >= 0 && !already; i--)
    {
    dbdata_wait *cont;
    sprintf(CS buffer, "%.200s:%d", host->name, i);
    cont = dbfn_read(dbm_file, buffer);
    if (cont != NULL)
      {
      int clen = cont->count * MESSAGE_ID_LENGTH;
      for (s = cont->text; s < cont->text + clen; s += MESSAGE_ID_LENGTH)
        {
        if (Ustrncmp(s, message_id, MESSAGE_ID_LENGTH) == 0)
          { already = TRUE; break; }
        }
      }
    }

  /* If this message is already in a record, no need to update. */

  if (already)
    {
    DEBUG(D_transport) debug_printf("already listed for %s\n", host->name);
    continue;
    }


  /* If this record is full, write it out with a new name constructed
  from the sequence number, increase the sequence number, and empty
  the record. */

  if (host_record->count >= WAIT_NAME_MAX)
    {
    sprintf(CS buffer, "%.200s:%d", host->name, host_record->sequence);
    dbfn_write(dbm_file, buffer, host_record, sizeof(dbdata_wait) + host_length);
    host_record->sequence++;
    host_record->count = 0;
    host_length = 0;
    }

  /* If this record is not full, increase the size of the record to
  allow for one new message id. */

  else
    {
    dbdata_wait *newr =
      store_get(sizeof(dbdata_wait) + host_length + MESSAGE_ID_LENGTH);
    memcpy(newr, host_record, sizeof(dbdata_wait) + host_length);
    host_record = newr;
    }

  /* Now add the new name on the end */

  memcpy(host_record->text + host_length, message_id, MESSAGE_ID_LENGTH);
  host_record->count++;
  host_length += MESSAGE_ID_LENGTH;

  /* Update the database */

  dbfn_write(dbm_file, host->name, host_record, sizeof(dbdata_wait) + host_length);
  DEBUG(D_transport) debug_printf("added to list for %s\n", host->name);
  }

/* All now done */

dbfn_close(dbm_file);
}




/*************************************************
*         Test for waiting messages              *
*************************************************/

/* This function is called by a remote transport which uses the previous
function to remember which messages are waiting for which remote hosts. It's
called after a successful delivery and its job is to check whether there is
another message waiting for the same host. However, it doesn't do this if the
current continue sequence is greater than the maximum supplied as an argument,
or greater than the global connection_max_messages, which, if set, overrides.

Arguments:
  transport_name     name of the transport
  hostname           name of the host
  local_message_max  maximum number of messages down one connection
                       as set by the caller transport
  new_message_id     set to the message id of a waiting message
  more               set TRUE if there are yet more messages waiting
  oicf_func          function to call to validate if it is ok to send
                     to this message_id from the current instance.
  oicf_data          opaque data for oicf_func

Returns:             TRUE if new_message_id set; FALSE otherwise
*/

typedef struct msgq_s
{
    uschar  message_id [MESSAGE_ID_LENGTH + 1];
    BOOL    bKeep;
} msgq_t;

BOOL
transport_check_waiting(const uschar *transport_name, const uschar *hostname,
  int local_message_max, uschar *new_message_id, BOOL *more, oicf oicf_func, void *oicf_data)
{
dbdata_wait *host_record;
int host_length;
open_db dbblock;
open_db *dbm_file;
uschar buffer[256];

msgq_t      *msgq = NULL;
int         msgq_count = 0;
int         msgq_actual = 0;
int         i;
BOOL        bFound = FALSE;
uschar      spool_dir [PATH_MAX];
uschar      spool_file [PATH_MAX];
struct stat statbuf;
BOOL        bContinuation = FALSE;

*more = FALSE;

DEBUG(D_transport)
  {
  debug_printf("transport_check_waiting entered\n");
  debug_printf("  sequence=%d local_max=%d global_max=%d\n",
    continue_sequence, local_message_max, connection_max_messages);
  }

/* Do nothing if we have hit the maximum number that can be send down one
connection. */

if (connection_max_messages >= 0) local_message_max = connection_max_messages;
if (local_message_max > 0 && continue_sequence >= local_message_max)
  {
  DEBUG(D_transport)
    debug_printf("max messages for one connection reached: returning\n");
  return FALSE;
  }

/* Open the waiting information database. */

sprintf(CS buffer, "wait-%.200s", transport_name);
dbm_file = dbfn_open(buffer, O_RDWR, &dbblock, TRUE);
if (dbm_file == NULL) return FALSE;

/* See if there is a record for this host; if not, there's nothing to do. */

host_record = dbfn_read(dbm_file, hostname);
if (host_record == NULL)
  {
  dbfn_close(dbm_file);
  DEBUG(D_transport) debug_printf("no messages waiting for %s\n", hostname);
  return FALSE;
  }

/* If the data in the record looks corrupt, just log something and
don't try to use it. */

if (host_record->count > WAIT_NAME_MAX)
  {
  dbfn_close(dbm_file);
  log_write(0, LOG_MAIN|LOG_PANIC, "smtp-wait database entry for %s has bad "
    "count=%d (max=%d)", hostname, host_record->count, WAIT_NAME_MAX);
  return FALSE;
  }

/* Scan the message ids in the record from the end towards the beginning,
until one is found for which a spool file actually exists. If the record gets
emptied, delete it and continue with any continuation records that may exist.
*/

/* For Bug 1141, I refactored this major portion of the routine, it is risky
but the 1 off will remain without it.  This code now allows me to SKIP over
a message I do not want to send out on this run.  */

sprintf(CS spool_dir, "%s/input/", spool_directory);

host_length = host_record->count * MESSAGE_ID_LENGTH;

while (1)
  {
  /* create an array to read entire message queue into memory for processing  */

  msgq = (msgq_t*) malloc(sizeof(msgq_t) * host_record->count);
  msgq_count = host_record->count;
  msgq_actual = msgq_count;

  for (i = 0; i < host_record->count; ++i)
    {
    msgq[i].bKeep = TRUE;

    Ustrncpy(msgq[i].message_id, host_record->text + (i * MESSAGE_ID_LENGTH),
      MESSAGE_ID_LENGTH);
    msgq[i].message_id[MESSAGE_ID_LENGTH] = 0;
    }

  /* first thing remove current message id if it exists */

  for (i = 0; i < msgq_count; ++i)
    if (Ustrcmp(msgq[i].message_id, message_id) == 0)
      {
      msgq[i].bKeep = FALSE;
      break;
      }

  /* now find the next acceptable message_id */

  bFound = FALSE;

  for (i = msgq_count - 1; i >= 0; --i) if (msgq[i].bKeep)
    {
    if (split_spool_directory)
	sprintf(CS spool_file, "%s%c/%s-D",
		      spool_dir, new_message_id[5], msgq[i].message_id);
    else
	sprintf(CS spool_file, "%s%s-D", spool_dir, msgq[i].message_id);

    if (Ustat(spool_file, &statbuf) != 0)
      msgq[i].bKeep = FALSE;
    else if (!oicf_func || oicf_func(msgq[i].message_id, oicf_data))
      {
      Ustrcpy(new_message_id, msgq[i].message_id);
      msgq[i].bKeep = FALSE;
      bFound = TRUE;
      break;
      }
    }

  /* re-count */
  for (msgq_actual = 0, i = 0; i < msgq_count; ++i)
    if (msgq[i].bKeep)
      msgq_actual++;

  /* reassemble the host record, based on removed message ids, from in
   * memory queue.
   */

  if (msgq_actual <= 0)
    {
    host_length = 0;
    host_record->count = 0;
    }
  else
    {
    host_length = msgq_actual * MESSAGE_ID_LENGTH;
    host_record->count = msgq_actual;

    if (msgq_actual < msgq_count)
      {
      int new_count;
      for (new_count = 0, i = 0; i < msgq_count; ++i)
	if (msgq[i].bKeep)
	  Ustrncpy(&host_record->text[new_count++ * MESSAGE_ID_LENGTH],
	    msgq[i].message_id, MESSAGE_ID_LENGTH);

      host_record->text[new_count * MESSAGE_ID_LENGTH] = 0;
      }
    }

/* Jeremy: check for a continuation record, this code I do not know how to
test but the code should work */

  bContinuation = FALSE;

  while (host_length <= 0)
    {
    int i;
    dbdata_wait * newr = NULL;

    /* Search for a continuation */

    for (i = host_record->sequence - 1; i >= 0 && !newr; i--)
      {
      sprintf(CS buffer, "%.200s:%d", hostname, i);
      newr = dbfn_read(dbm_file, buffer);
      }

    /* If no continuation, delete the current and break the loop */

    if (!newr)
      {
      dbfn_delete(dbm_file, hostname);
      break;
      }

    /* Else replace the current with the continuation */

    dbfn_delete(dbm_file, buffer);
    host_record = newr;
    host_length = host_record->count * MESSAGE_ID_LENGTH;

    bContinuation = TRUE;
    }

  if (bFound)
    break;

  /* If host_length <= 0 we have emptied a record and not found a good message,
  and there are no continuation records. Otherwise there is a continuation
  record to process. */

  if (host_length <= 0)
    {
    dbfn_close(dbm_file);
    DEBUG(D_transport) debug_printf("waiting messages already delivered\n");
    return FALSE;
    }

  /* we were not able to find an acceptable message, nor was there a
   * continuation record.  So bug out, outer logic will clean this up.
   */

  if (!bContinuation)
    {
    Ustrcpy (new_message_id, message_id); 
    dbfn_close(dbm_file);
    return FALSE;
    }
  }		/* we need to process a continuation record */

/* clean up in memory queue */
if (msgq)
  {
  free (msgq);
  msgq = NULL;
  msgq_count = 0;
  msgq_actual = 0;
  }

/* Control gets here when an existing message has been encountered; its
id is in new_message_id, and host_length is the revised length of the
host record. If it is zero, the record has been removed. Update the
record if required, close the database, and return TRUE. */

if (host_length > 0)
  {
  uschar  msg [MESSAGE_ID_LENGTH + 1];
  int i;

  host_record->count = host_length/MESSAGE_ID_LENGTH;

  /* rebuild the host_record->text */

  for (i = 0; i < host_record->count; ++i)
    {
    Ustrncpy(msg, host_record->text + (i*MESSAGE_ID_LENGTH), MESSAGE_ID_LENGTH);
    msg[MESSAGE_ID_LENGTH] = 0;
    }

  dbfn_write(dbm_file, hostname, host_record, (int)sizeof(dbdata_wait) + host_length);
  *more = TRUE;
  }

dbfn_close(dbm_file);
return TRUE;
}

/*************************************************
*    Deliver waiting message down same socket    *
*************************************************/

/* Fork a new exim process to deliver the message, and do a re-exec, both to
get a clean delivery process, and to regain root privilege in cases where it
has been given away.

Arguments:
  transport_name  to pass to the new process
  hostname        ditto
  hostaddress     ditto
  id              the new message to process
  socket_fd       the connected socket

Returns:          FALSE if fork fails; TRUE otherwise
*/

BOOL
transport_pass_socket(const uschar *transport_name, const uschar *hostname,
  const uschar *hostaddress, uschar *id, int socket_fd)
{
pid_t pid;
int status;

DEBUG(D_transport) debug_printf("transport_pass_socket entered\n");

if ((pid = fork()) == 0)
  {
  int i = 16;
  const uschar **argv;

  /* Disconnect entirely from the parent process. If we are running in the
  test harness, wait for a bit to allow the previous process time to finish,
  write the log, etc., so that the output is always in the same order for
  automatic comparison. */

  if ((pid = fork()) != 0) _exit(EXIT_SUCCESS);
  if (running_in_test_harness) sleep(1);

  /* Set up the calling arguments; use the standard function for the basics,
  but we have a number of extras that may be added. */

  argv = CUSS child_exec_exim(CEE_RETURN_ARGV, TRUE, &i, FALSE, 0);

  /* Call with the dsn flag */
  if (smtp_use_dsn) argv[i++] = US"-MCD";

  if (smtp_authenticated) argv[i++] = US"-MCA";

  #ifdef SUPPORT_TLS
  if (tls_offered) argv[i++] = US"-MCT";
  #endif

  if (smtp_use_size) argv[i++] = US"-MCS";
  if (smtp_use_pipelining) argv[i++] = US"-MCP";

  if (queue_run_pid != (pid_t)0)
    {
    argv[i++] = US"-MCQ";
    argv[i++] = string_sprintf("%d", queue_run_pid);
    argv[i++] = string_sprintf("%d", queue_run_pipe);
    }

  argv[i++] = US"-MC";
  argv[i++] = US transport_name;
  argv[i++] = US hostname;
  argv[i++] = US hostaddress;
  argv[i++] = string_sprintf("%d", continue_sequence + 1);
  argv[i++] = id;
  argv[i++] = NULL;

  /* Arrange for the channel to be on stdin. */

  if (socket_fd != 0)
    {
    (void)dup2(socket_fd, 0);
    (void)close(socket_fd);
    }

  DEBUG(D_exec) debug_print_argv(argv);
  exim_nullstd();                          /* Ensure std{out,err} exist */
  execv(CS argv[0], (char *const *)argv);

  DEBUG(D_any) debug_printf("execv failed: %s\n", strerror(errno));
  _exit(errno);         /* Note: must be _exit(), NOT exit() */
  }

/* If the process creation succeeded, wait for the first-level child, which
immediately exits, leaving the second level process entirely disconnected from
this one. */

if (pid > 0)
  {
  int rc;
  while ((rc = wait(&status)) != pid && (rc >= 0 || errno != ECHILD));
  DEBUG(D_transport) debug_printf("transport_pass_socket succeeded\n");
  return TRUE;
  }
else
  {
  DEBUG(D_transport) debug_printf("transport_pass_socket failed to fork: %s\n",
    strerror(errno));
  return FALSE;
  }
}



/*************************************************
*          Set up direct (non-shell) command     *
*************************************************/

/* This function is called when a command line is to be parsed and executed
directly, without the use of /bin/sh. It is called by the pipe transport,
the queryprogram router, and also from the main delivery code when setting up a
transport filter process. The code for ETRN also makes use of this; in that
case, no addresses are passed.

Arguments:
  argvptr            pointer to anchor for argv vector
  cmd                points to the command string (modified IN PLACE)
  expand_arguments   true if expansion is to occur
  expand_failed      error value to set if expansion fails; not relevant if
                     addr == NULL
  addr               chain of addresses, or NULL
  etext              text for use in error messages
  errptr             where to put error message if addr is NULL;
                     otherwise it is put in the first address

Returns:             TRUE if all went well; otherwise an error will be
                     set in the first address and FALSE returned
*/

BOOL
transport_set_up_command(const uschar ***argvptr, uschar *cmd,
  BOOL expand_arguments, int expand_failed, address_item *addr,
  uschar *etext, uschar **errptr)
{
address_item *ad;
const uschar **argv;
uschar *s, *ss;
int address_count = 0;
int argcount = 0;
int i, max_args;

/* Get store in which to build an argument list. Count the number of addresses
supplied, and allow for that many arguments, plus an additional 60, which
should be enough for anybody. Multiple addresses happen only when the local
delivery batch option is set. */

for (ad = addr; ad != NULL; ad = ad->next) address_count++;
max_args = address_count + 60;
*argvptr = argv = store_get((max_args+1)*sizeof(uschar *));

/* Split the command up into arguments terminated by white space. Lose
trailing space at the start and end. Double-quoted arguments can contain \\ and
\" escapes and so can be handled by the standard function; single-quoted
arguments are verbatim. Copy each argument into a new string. */

s = cmd;
while (isspace(*s)) s++;

while (*s != 0 && argcount < max_args)
  {
  if (*s == '\'')
    {
    ss = s + 1;
    while (*ss != 0 && *ss != '\'') ss++;
    argv[argcount++] = ss = store_get(ss - s++);
    while (*s != 0 && *s != '\'') *ss++ = *s++;
    if (*s != 0) s++;
    *ss++ = 0;
    }
  else argv[argcount++] = string_copy(string_dequote(CUSS &s));
  while (isspace(*s)) s++;
  }

argv[argcount] = (uschar *)0;

/* If *s != 0 we have run out of argument slots. */

if (*s != 0)
  {
  uschar *msg = string_sprintf("Too many arguments in command \"%s\" in "
    "%s", cmd, etext);
  if (addr != NULL)
    {
    addr->transport_return = FAIL;
    addr->message = msg;
    }
  else *errptr = msg;
  return FALSE;
  }

/* Expand each individual argument if required. Expansion happens for pipes set
up in filter files and with directly-supplied commands. It does not happen if
the pipe comes from a traditional .forward file. A failing expansion is a big
disaster if the command came from Exim's configuration; if it came from a user
it is just a normal failure. The expand_failed value is used as the error value
to cater for these two cases.

An argument consisting just of the text "$pipe_addresses" is treated specially.
It is not passed to the general expansion function. Instead, it is replaced by
a number of arguments, one for each address. This avoids problems with shell
metacharacters and spaces in addresses.

If the parent of the top address has an original part of "system-filter", this
pipe was set up by the system filter, and we can permit the expansion of
$recipients. */

DEBUG(D_transport)
  {
  debug_printf("direct command:\n");
  for (i = 0; argv[i] != (uschar *)0; i++)
    debug_printf("  argv[%d] = %s\n", i, string_printing(argv[i]));
  }

if (expand_arguments)
  {
  BOOL allow_dollar_recipients = addr != NULL &&
    addr->parent != NULL &&
    Ustrcmp(addr->parent->address, "system-filter") == 0;

  for (i = 0; argv[i] != (uschar *)0; i++)
    {

    /* Handle special fudge for passing an address list */

    if (addr != NULL &&
        (Ustrcmp(argv[i], "$pipe_addresses") == 0 ||
         Ustrcmp(argv[i], "${pipe_addresses}") == 0))
      {
      int additional;

      if (argcount + address_count - 1 > max_args)
        {
        addr->transport_return = FAIL;
        addr->message = string_sprintf("Too many arguments to command \"%s\" "
          "in %s", cmd, etext);
        return FALSE;
        }

      additional = address_count - 1;
      if (additional > 0)
        memmove(argv + i + 1 + additional, argv + i + 1,
          (argcount - i)*sizeof(uschar *));

      for (ad = addr; ad != NULL; ad = ad->next) {
          argv[i++] = ad->address;
          argcount++;
      }

      /* Subtract one since we replace $pipe_addresses */
      argcount--;
      i--;
      }

      /* Handle special case of $address_pipe when af_force_command is set */

    else if (addr != NULL && testflag(addr,af_force_command) &&
        (Ustrcmp(argv[i], "$address_pipe") == 0 ||
         Ustrcmp(argv[i], "${address_pipe}") == 0))
      {
      int address_pipe_i;
      int address_pipe_argcount = 0;
      int address_pipe_max_args;
      uschar **address_pipe_argv;

      /* We can never have more then the argv we will be loading into */
      address_pipe_max_args = max_args - argcount + 1;

      DEBUG(D_transport)
        debug_printf("address_pipe_max_args=%d\n", address_pipe_max_args);

      /* We allocate an additional for (uschar *)0 */
      address_pipe_argv = store_get((address_pipe_max_args+1)*sizeof(uschar *));

      /* +1 because addr->local_part[0] == '|' since af_force_command is set */
      s = expand_string(addr->local_part + 1);

      if (s == NULL || *s == '\0')
        {
        addr->transport_return = FAIL;
        addr->message = string_sprintf("Expansion of \"%s\" "
           "from command \"%s\" in %s failed: %s",
           (addr->local_part + 1), cmd, etext, expand_string_message);
        return FALSE;
        }

      while (isspace(*s)) s++; /* strip leading space */

      while (*s != 0 && address_pipe_argcount < address_pipe_max_args)
        {
        if (*s == '\'')
          {
          ss = s + 1;
          while (*ss != 0 && *ss != '\'') ss++;
          address_pipe_argv[address_pipe_argcount++] = ss = store_get(ss - s++);
          while (*s != 0 && *s != '\'') *ss++ = *s++;
          if (*s != 0) s++;
          *ss++ = 0;
          }
        else address_pipe_argv[address_pipe_argcount++] =
	      string_copy(string_dequote(CUSS &s));
        while (isspace(*s)) s++; /* strip space after arg */
        }

      address_pipe_argv[address_pipe_argcount] = (uschar *)0;

      /* If *s != 0 we have run out of argument slots. */
      if (*s != 0)
        {
        uschar *msg = string_sprintf("Too many arguments in $address_pipe "
          "\"%s\" in %s", addr->local_part + 1, etext);
        if (addr != NULL)
          {
          addr->transport_return = FAIL;
          addr->message = msg;
          }
        else *errptr = msg;
        return FALSE;
        }

      /* address_pipe_argcount - 1
       * because we are replacing $address_pipe in the argument list
       * with the first thing it expands to */
      if (argcount + address_pipe_argcount - 1 > max_args)
        {
        addr->transport_return = FAIL;
        addr->message = string_sprintf("Too many arguments to command "
          "\"%s\" after expanding $address_pipe in %s", cmd, etext);
        return FALSE;
        }

      /* If we are not just able to replace the slot that contained
       * $address_pipe (address_pipe_argcount == 1)
       * We have to move the existing argv by address_pipe_argcount - 1
       * Visually if address_pipe_argcount == 2:
       * [argv 0][argv 1][argv 2($address_pipe)][argv 3][0]
       * [argv 0][argv 1][ap_arg0][ap_arg1][old argv 3][0]
       */
      if (address_pipe_argcount > 1)
        memmove(
          /* current position + additonal args */
          argv + i + address_pipe_argcount,
          /* current position + 1 (for the (uschar *)0 at the end) */
          argv + i + 1,
          /* -1 for the (uschar *)0 at the end)*/
          (argcount - i)*sizeof(uschar *)
        );

      /* Now we fill in the slots we just moved argv out of
       * [argv 0][argv 1][argv 2=pipeargv[0]][argv 3=pipeargv[1]][old argv 3][0]
       */
      for (address_pipe_i = 0;
           address_pipe_argv[address_pipe_i] != (uschar *)0;
           address_pipe_i++)
        {
        argv[i++] = address_pipe_argv[address_pipe_i];
        argcount++;
        }

      /* Subtract one since we replace $address_pipe */
      argcount--;
      i--;
      }

    /* Handle normal expansion string */

    else
      {
      const uschar *expanded_arg;
      enable_dollar_recipients = allow_dollar_recipients;
      expanded_arg = expand_cstring(argv[i]);
      enable_dollar_recipients = FALSE;

      if (expanded_arg == NULL)
        {
        uschar *msg = string_sprintf("Expansion of \"%s\" "
          "from command \"%s\" in %s failed: %s",
          argv[i], cmd, etext, expand_string_message);
        if (addr != NULL)
          {
          addr->transport_return = expand_failed;
          addr->message = msg;
          }
        else *errptr = msg;
        return FALSE;
        }
      argv[i] = expanded_arg;
      }
    }

  DEBUG(D_transport)
    {
    debug_printf("direct command after expansion:\n");
    for (i = 0; argv[i] != (uschar *)0; i++)
      debug_printf("  argv[%d] = %s\n", i, string_printing(argv[i]));
    }
  }

return TRUE;
}

/* vi: aw ai sw=2
*/
/* End of transport.c */
