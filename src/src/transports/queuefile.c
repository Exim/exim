/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Andrew Colin Kissa <andrew@topdog.za.net> 2016 */
/* Copyright (c) University of Cambridge 2016 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "queuefile.h"

/* Options specific to the appendfile transport. They must be in alphabetic
order (note that "_" comes before the lower case letters). Some of them are
stored in the publicly visible instance block - these are flagged with the
opt_public flag. */

optionlist queuefile_transport_options[] = {
  { "directory", opt_stringptr,
    (void *)offsetof(queuefile_transport_options_block, dirname) },
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int queuefile_transport_options_count =
  sizeof(queuefile_transport_options) / sizeof(optionlist);

/* Default private options block for the appendfile transport. */

queuefile_transport_options_block queuefile_transport_option_defaults = {
  NULL,           /* dirname */
};

/*************************************************
*          Initialization entry point            *
*************************************************/

void queuefile_transport_init(transport_instance *tblock)
{
queuefile_transport_options_block *ob =
  (queuefile_transport_options_block *) tblock->options_block;

if (!ob->dirname)
  log_write(0, LOG_PANIC_DIE | LOG_CONFIG,
    "directory must be set for the %s transport", tblock->name);
}

/* This function will copy from a file to another

Arguments:
  to_fd        FILE to write to (the destination queue file)
  from_fd      FILE to read from (the spool queue file)

Returns:       TRUE if all went well, FALSE otherwise
*/

static BOOL
copy_spool_file (FILE *to_fd, FILE *from_fd)
{
int i, j;
uschar buffer[16384];

rewind(from_fd);

do
  if ((j = fread(buffer, 1, sizeof(buffer), from_fd)) > 0)
    if ((i = fwrite(buffer, j, 1, to_fd)) != 1)
      return FALSE;
while (j > 0);
return TRUE;
}

/* This function performs the actual copying of the header
and data files to the destination directory

Arguments:
  tb		the transport block
  addr          address_item being processed
  sdfd          int Source directory fd
  ddfd          int Destination directory fd
  link_file     BOOL use linkat instead of data copy
  srcfd		fd for data file, or -1 for header file

Returns:       TRUE if all went well, FALSE otherwise
*/

static BOOL
copy_spool_files(transport_instance * tb, address_item * addr,
  int sdfd, int ddfd, BOOL link_file, int srcfd)
{
BOOL is_hdr_file = srcfd < 0;
uschar * suffix = srcfd < 0 ? US"H" : US"D";
int dstfd;
FILE * dst_file, * src_file;
uschar * filename = string_sprintf("%s-%s", message_id, suffix);
uschar * srcpath = spool_fname(US"input", message_subdir, message_id, suffix);
uschar * dstpath = string_sprintf("%s/%s-%s",
  ((queuefile_transport_options_block *) tb->options_block)->dirname,
  message_id, suffix);

if (link_file)
  {
  DEBUG(D_transport) debug_printf("%s transport, linking %s => %s\n",
    tb->name, srcpath, dstpath);

  return linkat(sdfd, CCS filename, ddfd, CCS filename, 0) >= 0;
  }

/* use data copy */

DEBUG(D_transport) debug_printf("%s transport, copying %s => %s\n",
  tb->name, srcpath, dstpath);

if ((dstfd =
  openat(ddfd, CCS filename, O_RDWR|O_CREAT|O_EXCL, SPOOL_MODE)) < 0)
  {
  addr->transport_return = DEFER;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport opening file: %s "
    "failed with error: %s", tb->name, dstpath, strerror(errno));
  return FALSE;
  }

fchmod(dstfd, SPOOL_MODE);

if (!(dst_file = fdopen(dstfd, "wb")))
  {
  addr->transport_return = DEFER;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport opening file fd: %s "
    "failed with error: %s", tb->name, dstpath, strerror(errno));
  (void) close(dstfd);
  return FALSE;
  }

if (is_hdr_file)
  if ((srcfd = openat(sdfd, CCS filename, O_RDONLY)) < 0)
    {
    addr->basic_errno = errno;
    addr->message = string_sprintf("%s transport opening file: %s "
      "failed with error: %s", tb->name, srcpath, strerror(errno));
    goto bad;
    }

if (!(src_file = fdopen(srcfd, "rb")))
  {
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport opening file fd: "
    "%s failed with error: %s", tb->name, srcpath, strerror(errno));
  if (is_hdr_file) (void) close(srcfd);
  goto bad;
  }

if (!copy_spool_file(dst_file, src_file))
  {
  addr->message = string_sprintf("%s transport creating file: "
    "%s failed with error: %s", tb->name, dstpath, strerror(errno));
  if (is_hdr_file) (void) fclose(src_file);
  goto bad;
  }

if (is_hdr_file) (void) fclose(src_file);
(void) fclose(dst_file);

return TRUE;

bad:
  addr->transport_return = DEFER;
  (void) fclose(dst_file);
  return FALSE;
}

/*************************************************
*              Main entry point                  *
*************************************************/

/* This transport always returns FALSE, indicating that the status in
the first address is the status for all addresses in a batch. */

BOOL
queuefile_transport_entry(transport_instance * tblock, address_item * addr)
{
queuefile_transport_options_block * ob =
  (queuefile_transport_options_block *) tblock->options_block;
BOOL can_link;
uschar * sourcedir = spool_dname(US"input", message_subdir);
uschar * s;
struct stat dstatbuf, sstatbuf;
int ddfd = -1, sdfd = -1;

DEBUG(D_transport)
  debug_printf("%s transport entered\n", tblock->name);

#ifndef O_DIRECTORY
# define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
# define O_NOFOLLOW 0
#endif

if (ob->dirname[0] != '/')
  {
  addr->transport_return = PANIC;
  addr->message = string_sprintf("%s transport directory: "
    "%s is not absolute", tblock->name, ob->dirname);
  return FALSE;
  }

/* Open the source and destination directories and check if they are
on the same filesystem, so we can hard-link files rather than copying. */

if (  (s = ob->dirname,
       (ddfd = Uopen(s, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0)) < 0)
   || (s = sourcedir,
       (sdfd = Uopen(sourcedir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0)) < 0)
   )
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport accessing directory: %s "
    "failed with error: %s", tblock->name, s, strerror(errno));
  if (ddfd >= 0) (void) close(ddfd);
  return FALSE;
  }

if (  (s = ob->dirname, fstat(ddfd, &dstatbuf) < 0)
   || (s = sourcedir,   fstat(sdfd, &sstatbuf) < 0)
   )
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport fstat on directory fd: "
    "%s failed with error: %s", tblock->name, s, strerror(errno));
  goto RETURN;
  }
can_link = (dstatbuf.st_dev == sstatbuf.st_dev);

if (dont_deliver)
  {
  DEBUG(D_transport)
    debug_printf("*** delivery by %s transport bypassed by -N option\n",
      tblock->name);
  addr->transport_return = OK;
  goto RETURN;
  }

/* Link or copy the header and data spool files */

DEBUG(D_transport)
  debug_printf("%s transport, copying header file\n", tblock->name);

if (!copy_spool_files(tblock, addr, sdfd, ddfd, can_link, -1))
  goto RETURN;

DEBUG(D_transport)
  debug_printf("%s transport, copying data file\n", tblock->name);

if (!copy_spool_files(tblock, addr, sdfd, ddfd, can_link, deliver_datafile))
  {
  DEBUG(D_transport)
    debug_printf("%s transport, copying data file failed, "
      "unlinking the header file\n", tblock->name);
  Uunlink(string_sprintf("%s/%s-H", ob->dirname, message_id));
  goto RETURN;
  }

DEBUG(D_transport)
  debug_printf("%s transport succeeded\n", tblock->name);

addr->transport_return = OK;

RETURN:
if (ddfd >= 0) (void) close(ddfd);
if (sdfd >= 0) (void) close(sdfd);

/* A return of FALSE means that if there was an error, a common error was
put in the first address of a batch. */
return FALSE;
}
