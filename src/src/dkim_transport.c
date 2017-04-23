/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2016 */
/* See the file NOTICE for conditions of use and distribution. */

/* Transport shim for dkim signing */

#ifndef DISABLE_DKIM


#include "exim.h"

#ifdef HAVE_LINUX_SENDFILE
#include <sys/sendfile.h>
#endif


static BOOL
dkt_sign_fail(struct ob_dkim * dkim, int * errp)
{
if (dkim->dkim_strict)
  {
  uschar * dkim_strict_result = expand_string(dkim->dkim_strict);

  if (dkim_strict_result)
    if ( (strcmpic(dkim->dkim_strict, US"1") == 0) ||
	 (strcmpic(dkim->dkim_strict, US"true") == 0) )
      {
      /* Set errno to something halfway meaningful */
      *errp = EACCES;
      log_write(0, LOG_MAIN, "DKIM: message could not be signed,"
	" and dkim_strict is set. Deferring message delivery.");
      return FALSE;
      }
  }
return TRUE;
}

static BOOL
dkt_send_file(int out_fd, int in_fd, off_t off, size_t size)
{
DEBUG(D_transport) debug_printf("send file fd=%d size=%d\n", out_fd, size - off);

/*XXX should implement timeout, like transport_write_block_fd() ? */

/* Rewind file */
lseek(in_fd, off, SEEK_SET);

#ifdef HAVE_LINUX_SENDFILE
/* We can use sendfile() to shove the file contents
   to the socket. However only if we don't use TLS,
   as then there's another layer of indirection
   before the data finally hits the socket. */
if (tls_out.active != out_fd)
  {
  ssize_t copied = 0;

  while(copied >= 0 && off < size)
    copied = sendfile(tctx->u.fd, dkim_fd, &off, size - off);
  if (copied < 0)
    return FALSE;
  }
else

#endif

  {
  int sread, wwritten;

  /* Send file down the original fd */
  while((sread = read(in_fd, deliver_out_buffer, DELIVER_OUT_BUFFER_SIZE)) >0)
    {
    uschar * p = deliver_out_buffer;
    /* write the chunk */

    while (sread)
      {
#ifdef SUPPORT_TLS
      wwritten = tls_out.active == out_fd
	? tls_write(FALSE, p, sread)
	: write(out_fd, CS p, sread);
#else
      wwritten = write(out_fd, CS p, sread);
#endif
      if (wwritten == -1)
	return FALSE;
      p += wwritten;
      sread -= wwritten;
      }
    }

  if (sread == -1)
    return FALSE;
  }

return TRUE;
}




/* This function is a wrapper around transport_write_message().
   It is only called from the smtp transport if DKIM or Domainkeys support
   is active and no transport filter is to be used.

Arguments:
  As for transport_write_message() in transort.c, with additional arguments
  for DKIM.

Returns:       TRUE on success; FALSE (with errno) for any failure
*/

static BOOL
dkt_direct(transport_ctx * tctx, struct ob_dkim * dkim,
  const uschar ** err)
{
int save_fd = tctx->u.fd;
int save_options = tctx->options;
uschar * hdrs, * dkim_signature;
int siglen, hsize;
const uschar * errstr;
BOOL rc;

DEBUG(D_transport) debug_printf("dkim signing direct-mode\n");

/* Get headers in string for signing and transmission */

tctx->u.msg = NULL;
tctx->options = tctx->options & ~(topt_end_dot | topt_use_bdat)
  | topt_output_string | topt_no_body;

rc = transport_write_message(tctx, 0);
hdrs = tctx->u.msg;
hdrs[hsize = tctx->msg_ptr] = '\0';

tctx->u.fd = save_fd;
tctx->options = save_options;
if (!rc) return FALSE;

/* Get signatures for headers plus spool data file */

dkim->dot_stuffed = !!(save_options & topt_end_dot);

if ((dkim_signature = dkim_exim_sign(deliver_datafile, SPOOL_DATA_START_OFFSET,
				    hdrs, dkim, &errstr)))
  siglen = Ustrlen(dkim_signature);
else if (!(rc = dkt_sign_fail(dkim, &errno)))
  {
  *err = errstr;
  return FALSE;
  }

/* Write the signature and headers into the deliver-out-buffer.  This should
mean they go out in the same packet as the MAIL, RCPT and (first) BDAT commands
(transport_write_message() sizes the BDAT for the buffered amount) - for short
messages, the BDAT LAST command.  We want no CRLF or dotstuffing expansion */

tctx->options &= ~topt_use_crlf;
transport_write_reset(0);
if (  !write_chunk(tctx, dkim_signature, siglen)
   || !write_chunk(tctx, hdrs, hsize))
  return FALSE;

tctx->options = save_options | topt_no_headers | topt_continuation;

if (!(transport_write_message(tctx, 0)))
  return FALSE;

tctx->options = save_options;
return TRUE;
}


/* This function is a wrapper around transport_write_message().
   It is only called from the smtp transport if DKIM or Domainkeys support
   is active and a transport filter is to be used.  The function sets up a
   replacement fd into a -K file, then calls the normal function. This way, the
   exact bits that exim would have put "on the wire" will end up in the file
   (except for TLS encapsulation, which is the very very last thing). When we
   are done signing the file, send the signed message down the original fd (or
   TLS fd).

Arguments:
  As for transport_write_message() in transort.c, with additional arguments
  for DKIM.

Returns:       TRUE on success; FALSE (with errno) for any failure
*/

static BOOL
dkt_via_kfile(transport_ctx * tctx, struct ob_dkim * dkim, const uschar ** err)
{
int dkim_fd;
int save_errno = 0;
BOOL rc;
uschar * dkim_spool_name, * dkim_signature;
int sread = 0, wwritten = 0, siglen, options;
off_t k_file_size;
const uschar * errstr;

dkim_spool_name = spool_fname(US"input", message_subdir, message_id,
		    string_sprintf("-%d-K", (int)getpid()));

DEBUG(D_transport) debug_printf("dkim signing via file %s\n", dkim_spool_name);

if ((dkim_fd = Uopen(dkim_spool_name, O_RDWR|O_CREAT|O_TRUNC, SPOOL_MODE)) < 0)
  {
  /* Can't create spool file. Ugh. */
  rc = FALSE;
  save_errno = errno;
  *err = string_sprintf("dkim spoolfile create: %s", strerror(errno));
  goto CLEANUP;
  }

/* Call transport utility function to write the -K file; does the CRLF expansion
(but, in the CHUNKING case, neither dot-stuffing nor dot-termination). */

  {
  int save_fd = tctx->u.fd;
  tctx->u.fd = dkim_fd;
  options = tctx->options;
  tctx->options &= ~topt_use_bdat;

  rc = transport_write_message(tctx, 0);

  tctx->u.fd = save_fd;
  tctx->options = options;
  }

/* Save error state. We must clean up before returning. */
if (!rc)
  {
  save_errno = errno;
  goto CLEANUP;
  }

/* Feed the file to the goats^W DKIM lib */

dkim->dot_stuffed = !!(options & topt_end_dot);
if ((dkim_signature = dkim_exim_sign(dkim_fd, 0, NULL, dkim, &errstr)))
  siglen = Ustrlen(dkim_signature);
else if (!(rc = dkt_sign_fail(dkim, &save_errno)))
  {
  *err = errstr;
  goto CLEANUP;
  }

#ifndef HAVE_LINUX_SENDFILE
if (options & topt_use_bdat)
#endif
  k_file_size = lseek(dkim_fd, 0, SEEK_END); /* Fetch file size */

if (options & topt_use_bdat)
  {
  /* On big messages output a precursor chunk to get any pipelined
  MAIL & RCPT commands flushed, then reap the responses so we can
  error out on RCPT rejects before sending megabytes. */

  if (siglen + k_file_size > DELIVER_OUT_BUFFER_SIZE && siglen > 0)
    {
    if (  tctx->chunk_cb(tctx, siglen, 0) != OK
       || !transport_write_block(tctx, dkim_signature, siglen, FALSE)
       || tctx->chunk_cb(tctx, 0, tc_reap_prev) != OK
       )
      goto err;
    siglen = 0;
    }

  /* Send the BDAT command for the entire message, as a single LAST-marked
  chunk. */

  if (tctx->chunk_cb(tctx, siglen + k_file_size, tc_chunk_last) != OK)
    goto err;
  }

if(siglen > 0 && !transport_write_block(tctx, dkim_signature, siglen, TRUE))
  goto err;

if (!dkt_send_file(tctx->u.fd, dkim_fd, 0, k_file_size))
  {
  save_errno = errno;
  rc = FALSE;
  }

CLEANUP:
  /* unlink -K file */
  (void)close(dkim_fd);
  Uunlink(dkim_spool_name);
  errno = save_errno;
  return rc;

err:
  save_errno = errno;
  rc = FALSE;
  goto CLEANUP;
}



/***************************************************************************************************
*    External interface to write the message, while signing it with DKIM and/or Domainkeys         *
***************************************************************************************************/

/* This function is a wrapper around transport_write_message().
   It is only called from the smtp transport if DKIM or Domainkeys support
   is compiled in.

Arguments:
  As for transport_write_message() in transort.c, with additional arguments
  for DKIM.

Returns:       TRUE on success; FALSE (with errno) for any failure
*/

BOOL
dkim_transport_write_message(transport_ctx * tctx,
  struct ob_dkim * dkim, const uschar ** err)
{
/* If we can't sign, just call the original function. */

if (!(dkim->dkim_private_key && dkim->dkim_domain && dkim->dkim_selector))
  return transport_write_message(tctx, 0);

/* If there is no filter command set up, construct the message and calculate
a dkim signature of it, send the signature and a reconstructed message. This
avoids using a temprary file. */

if (  !transport_filter_argv
   || !*transport_filter_argv
   || !**transport_filter_argv
   )
  return dkt_direct(tctx, dkim, err);

/* Use the transport path to write a file, calculate a dkim signature,
send the signature and then send the file. */

return dkt_via_kfile(tctx, dkim, err);
}

#endif	/* whole file */

/* vi: aw ai sw=2
*/
/* End of dkim_transport.c */
