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
  (queuefile_transport_options_block *)(tblock->options_block);

if (ob->dirname == NULL)
  log_write(0, LOG_PANIC_DIE | LOG_CONFIG,
    "directory must be set for the %s transport", tblock->name);
}

/* This function will copy from a file to another

Arguments:
  to_fd        FILE to write to (the destination queue file)
  from_fd      FILE to read from (the spool queue file)

Returns:       TRUE if all went well, FALSE otherwise
*/

static BOOL copy_spool_file (FILE *to_fd, FILE *from_fd)
{
int i, j;
uschar buffer[16384];

rewind(from_fd);

do
  {
    j = fread(buffer, 1, sizeof(buffer), from_fd);
    if (j > 0)
      {
      i = fwrite(buffer, j, 1, to_fd);
      if (i != 1)
        return FALSE;
      }
  }
while (j > 0);
return TRUE;
}

/* This function performs the actual copying of the header
and data files to the destination directory

Arguments:
  tname         uschar the transport name
  addr          address_item being processed
  sdfd          int Source directory fd
  ddfd          int Destination directory fd
  suffix        uschar file suffix
  dirname       uschar Destination directory
  link_file     BOOL use linkat instead of data copy
  is_data_file  BOOL the file is a data file not a header file
  dst_file      FILE to write to
  src_file      FILE to read from

Returns:       TRUE if all went well, FALSE otherwise
*/

static BOOL copy_spool_files(uschar *tname, address_item *addr,
  int sdfd, int ddfd, uschar *suffix, uschar *dirname, BOOL link_file,
  BOOL is_data_file, FILE *dst_file, FILE *src_file)
{
int dstfd, srcfd;
/*
uschar message_subdir[2];
message_subdir[1] = '\0';
message_subdir[0] = split_spool_directory? message_id[5] : 0;
*/
uschar *filename = string_sprintf("%s-%s", message_id, suffix);
/*
uschar *srcpath = string_sprintf("%s/%s/%s/%s-%s", spool_directory,
    US"input", message_subdir, message_id, suffix);
*/
uschar *srcpath = spool_fname(US"input", message_subdir, message_id, suffix);
uschar *dstpath = string_sprintf("%s/%s-%s", dirname, message_id, suffix);

if (link_file)
  {
  /* use linkat */
  DEBUG(D_transport)
    debug_printf("%s transport, linking %s => %s\n", tname,
      srcpath, dstpath);
  if (linkat(sdfd, CCS filename, ddfd, CCS filename, 0) < 0)
    return FALSE;
  return TRUE;
  }
else
  {
  /* use data copy */
  DEBUG(D_transport)
    debug_printf("%s transport, copying %s => %s\n", tname,
      srcpath, dstpath);
  if ((dstfd =
    openat(ddfd, CCS filename, O_RDWR|O_CREAT|O_EXCL, SPOOL_MODE)) < 0)
    {
    addr->transport_return = DEFER;
    addr->basic_errno = errno;
    addr->message = string_sprintf("%s transport opening file: %s "
      "failed with error: %s", tname, dstpath, strerror(errno));
    return FALSE;
    }

  fchmod(dstfd, SPOOL_MODE);

  if ((dst_file = fdopen(dstfd, "wb")) < 0)
    {
    addr->transport_return = DEFER;
    addr->basic_errno = errno;
    addr->message = string_sprintf("%s transport opening file fd: %s "
      "failed with error: %s", tname, dstpath, strerror(errno));
    (void)close(dstfd);
    return FALSE;
    }

  if (is_data_file)
    srcfd = deliver_datafile;
  else
    {
    if ((srcfd = openat(sdfd, CCS filename, O_RDONLY)) < 0)
      {
      addr->transport_return = DEFER;
      addr->basic_errno = errno;
      addr->message = string_sprintf("%s transport opening file: %s "
        "failed with error: %s", tname, srcpath, strerror(errno));
      return FALSE;
      }
    }

  if ((src_file = fdopen(srcfd, "rb")) < 0)
    {
    addr->transport_return = DEFER;
    addr->basic_errno = errno;
    addr->message = string_sprintf("%s transport opening file fd: "
      "%s failed with error: %s", tname, srcpath, strerror(errno));
    if (!is_data_file) (void)close(srcfd);
    return FALSE;
    }

  if (!copy_spool_file(dst_file, src_file))
    {
    addr->transport_return = DEFER;
    addr->message = string_sprintf("%s transport creating file: "
      "%s failed with error: %s", tname, dstpath, strerror(errno));
    return FALSE;
    }

  if (!is_data_file)
    {
    (void)fclose(src_file);
    src_file = NULL;
    }

  (void)fclose(dst_file);
  dst_file = NULL;

  } /* end data copy */

return TRUE;
}

/*************************************************
*              Main entry point                  *
*************************************************/

/* This transport always returns FALSE, indicating that the status in
the first address is the status for all addresses in a batch. */

BOOL queuefile_transport_entry(transport_instance *tblock,
  address_item *addr)
{
BOOL link_file;
BOOL is_data_file;
uschar *sourcedir;
struct stat dstatbuf;
struct stat sstatbuf;
FILE *dst_file = NULL;
FILE *src_file = NULL;
/* uschar message_subdir[2]; */
int ddfd, sdfd, dfd_oflags;
queuefile_transport_options_block *ob =
  (queuefile_transport_options_block *)(tblock->options_block);

DEBUG(D_transport)
  debug_printf("%s transport entered\n", tblock->name);

# ifndef O_DIRECTORY
#  define O_DIRECTORY 0
# endif

dfd_oflags = O_RDONLY|O_DIRECTORY;
#ifdef O_NOFOLLOW
dfd_oflags |= O_NOFOLLOW;
#endif

if (ob->dirname[0] != '/')
  {
  addr->transport_return = PANIC;
  addr->message = string_sprintf("%s transport directory: "
    "%s is not absolute", tblock->name, ob->dirname);
  return FALSE;
  }

if ((ddfd = Uopen(ob->dirname, dfd_oflags, 0)) < 0)
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport accessing directory: %s "
    "failed with error: %s", tblock->name, ob->dirname, strerror(errno));
  return FALSE;
  }


if ((fstat(ddfd, &dstatbuf)) < 0)
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport fstat on directory fd: "
    "%s failed with error: %s", tblock->name, ob->dirname, strerror(errno));
  goto RETURN;
  }

sourcedir = spool_dname(US"input", message_subdir);
/*
message_subdir[1] = '\0';
message_subdir[0] = split_spool_directory? message_id[5] : 0;
sourcedir = string_sprintf("%s/%s/%s", spool_directory,
  US"input", message_subdir);
*/

if ((sdfd = Uopen(sourcedir, dfd_oflags, 0)) < 0)
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport accessing directory: %s "
    "failed with error: %s", tblock->name, sourcedir, strerror(errno));
  goto RETURN;
  }

if ((fstat(sdfd, &sstatbuf)) < 0)
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport fstat on directory fd: "
    "%s failed with error: %s", tblock->name, sourcedir, strerror(errno));
  goto RETURN;
  }

if (dont_deliver)
  {
  DEBUG(D_transport)
    debug_printf("*** delivery by %s transport bypassed by -N option\n",
      tblock->name);
  addr->transport_return = OK;
  goto RETURN;
  }

/* process the header file */
DEBUG(D_transport)
  debug_printf("%s transport, copying header file\n", tblock->name);

is_data_file = FALSE;
link_file = (dstatbuf.st_dev == sstatbuf.st_dev);

if ((copy_spool_files(tblock->name, addr, sdfd, ddfd, US"H", ob->dirname,
  link_file, is_data_file, dst_file, src_file)) == FALSE)
  goto RETURN;

/* process the data file */
DEBUG(D_transport)
  debug_printf("%s transport, copying data file\n", tblock->name);

is_data_file = TRUE;

if ((copy_spool_files(tblock->name, addr, sdfd, ddfd, US"D", ob->dirname,
  link_file, is_data_file, dst_file, src_file)) == FALSE)
  {
  DEBUG(D_transport)
    debug_printf("%s transport, copying data file failed, "
      "unlinking the header file\n", tblock->name);
  Uunlink(string_sprintf("%s/%s-H", ob->dirname, message_id));
  goto RETURN;
  }

(void)close(ddfd);
(void)close(sdfd);

DEBUG(D_transport)
  debug_printf("%s transport succeeded\n", tblock->name);

addr->transport_return = OK;

RETURN:
if (dst_file) (void)fclose(dst_file);
if (src_file && !is_data_file) (void)fclose(src_file);
if (ddfd) (void)close(ddfd);
if (sdfd) (void)close(sdfd);

/* A return of FALSE means that if there was an error, a common error was
put in the first address of a batch. */
return FALSE;
}
