/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 1995 - 2024 */
/* Copyright (c) Andrew Colin Kissa <andrew@topdog.za.net> 2016 */
/* Copyright (c) University of Cambridge 2016 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */



#include "../exim.h"

#ifdef EXPERIMENTAL_QUEUEFILE	/* whole file */
#include "queuefile.h"

#ifndef EXIM_HAVE_OPENAT
# error queuefile transport reqires openat() support
#endif

/* Options specific to the appendfile transport. They must be in alphabetic
order (note that "_" comes before the lower case letters). Some of them are
stored in the publicly visible instance block - these are flagged with the
opt_public flag. */

optionlist queuefile_transport_options[] = {
  { "directory", opt_stringptr,
    OPT_OFF(queuefile_transport_options_block, dirname) },
};


/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int queuefile_transport_options_count =
  sizeof(queuefile_transport_options) / sizeof(optionlist);


#ifdef MACRO_PREDEF

/* Dummy values */
queuefile_transport_options_block queuefile_transport_option_defaults = {0};
void queuefile_transport_init(driver_instance *tblock) {}
BOOL queuefile_transport_entry(transport_instance *tblock, address_item *addr) {return FALSE;}

#else   /*!MACRO_PREDEF*/



/* Default private options block for the appendfile transport. */

queuefile_transport_options_block queuefile_transport_option_defaults = {
  NULL,           /* dirname */
};

/*************************************************
*          Initialization entry point            *
*************************************************/

void queuefile_transport_init(driver_instance * t)
{
queuefile_transport_options_block * ob = t->options_block;

if (!ob->dirname)
  log_write_die(0, LOG_CONFIG,
    "directory must be set for the %s transport", t->name);
}

/* This function will copy from a file to another

Arguments:
  dst        fd to write to (the destination queue file)
  src        fd to read from (the spool queue file)

Returns:       TRUE if all went well, FALSE otherwise with errno set
*/

static BOOL
copy_spool_file(int dst, int src)
{
int i, j;
uschar buffer[16384];

if (lseek(src, 0, SEEK_SET) != 0)
  return FALSE;

do
  if ((j = read(src, buffer, sizeof(buffer))) > 0)
    for (uschar * s = buffer; (i = write(dst, s, j)) != j; s += i, j -= i)
      if (i < 0)
	return FALSE;
  else if (j < 0)
    return FALSE;
while (j > 0);
return TRUE;
}

/* This function performs the actual copying of the header
and data files to the destination directory

Arguments:
  tb		the transport block
  addr          address_item being processed
  dstpath	destination directory name
  sdfd          int Source directory fd
  ddfd          int Destination directory fd
  link_file     BOOL use linkat instead of data copy
  srcfd		fd for data file, or -1 for header file

Returns:       TRUE if all went well, FALSE otherwise
*/

static BOOL
copy_spool_files(transport_instance * tb, address_item * addr,
  const uschar * dstpath, int sdfd, int ddfd, BOOL link_file, int srcfd)
{
const uschar * trname = tb->drinst.name;
BOOL is_hdr_file = srcfd < 0;
const uschar * suffix = srcfd < 0 ? US"H" : US"D";
int dstfd;
const uschar * filename = string_sprintf("%s-%s", message_id, suffix);
const uschar * srcpath = spool_fname(US"input", message_subdir, message_id, suffix);
const uschar * s, * op;

dstpath = string_sprintf("%s/%s-%s", dstpath, message_id, suffix);

if (link_file)
  {
  DEBUG(D_transport) debug_printf("%s transport, linking %s => %s\n",
    trname, srcpath, dstpath);

  if (linkat(sdfd, CCS filename, ddfd, CCS filename, 0) >= 0)
    return TRUE;

  op = US"linking";
  s = dstpath;
  }
else					/* use data copy */
  {
  DEBUG(D_transport) debug_printf("%s transport, copying %s => %s\n",
    trname, srcpath, dstpath);

  if (  (s = dstpath,
	 (dstfd = exim_openat4(ddfd, CCS filename, O_RDWR|O_CREAT|O_EXCL, SPOOL_MODE))
	 < 0
	)
     ||    is_hdr_file
	&& (s = srcpath, (srcfd = exim_openat(sdfd, CCS filename, O_RDONLY)) < 0)
     )
    op = US"opening";

  else
    if (s = dstpath, fchmod(dstfd, SPOOL_MODE) != 0)
      op = US"setting perms on";
    else
      if (!copy_spool_file(dstfd, srcfd))
	op = US"creating";
      else
	return TRUE;
  }

addr->basic_errno = errno;
addr->message = string_sprintf("%s transport %s file: %s failed with error: %s",
  trname, op, s, strerror(errno));
addr->transport_return = DEFER;
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
queuefile_transport_options_block * ob = tblock->drinst.options_block;
const uschar * trname = tblock->drinst.name;
BOOL can_link;
uschar * sourcedir = spool_dname(US"input", message_subdir);
uschar * s, * dstdir;
struct stat dstatbuf, sstatbuf;
int ddfd = -1, sdfd = -1;

DEBUG(D_transport)
  debug_printf("%s transport entered\n", trname);

#ifndef O_DIRECTORY
# define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
# define O_NOFOLLOW 0
#endif

GET_OPTION("directory");
if (!(dstdir = expand_string(ob->dirname)))
  {
  addr->message = string_sprintf("%s transport: failed to expand dirname option",
    trname);
  addr->transport_return = DEFER;
  return FALSE;
  }
if (*dstdir != '/')
  {
  addr->transport_return = PANIC;
  addr->message = string_sprintf("%s transport directory: "
    "%s is not absolute", trname, dstdir);
  return FALSE;
  }

/* Open the source and destination directories and check if they are
on the same filesystem, so we can hard-link files rather than copying. */

if (  (s = dstdir,
       (ddfd = Uopen(s, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0)) < 0)
   || (s = sourcedir,
       (sdfd = Uopen(sourcedir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0)) < 0)
   )
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport accessing directory: %s "
    "failed with error: %s", trname, s, strerror(errno));
  if (ddfd >= 0) (void) close(ddfd);
  return FALSE;
  }

if (  (s = dstdir,    fstat(ddfd, &dstatbuf) < 0)
   || (s = sourcedir, fstat(sdfd, &sstatbuf) < 0)
   )
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport fstat on directory fd: "
    "%s failed with error: %s", trname, s, strerror(errno));
  goto RETURN;
  }
can_link = (dstatbuf.st_dev == sstatbuf.st_dev);

if (f.dont_deliver)
  {
  DEBUG(D_transport)
    debug_printf("*** delivery by %s transport bypassed by -N option\n",
      trname);
  addr->transport_return = OK;
  goto RETURN;
  }

/* Link or copy the header and data spool files */

DEBUG(D_transport)
  debug_printf("%s transport, copying header file\n", trname);

if (!copy_spool_files(tblock, addr, dstdir, sdfd, ddfd, can_link, -1))
  goto RETURN;

DEBUG(D_transport)
  debug_printf("%s transport, copying data file\n", trname);

if (!copy_spool_files(tblock, addr, dstdir, sdfd, ddfd, can_link,
	deliver_datafile))
  {
  DEBUG(D_transport)
    debug_printf("%s transport, copying data file failed, "
      "unlinking the header file\n", trname);
  Uunlink(string_sprintf("%s/%s-H", dstdir, message_id));
  goto RETURN;
  }

DEBUG(D_transport)
  debug_printf("%s transport succeeded\n", trname);

addr->transport_return = OK;

RETURN:
if (ddfd >= 0) (void) close(ddfd);
if (sdfd >= 0) (void) close(sdfd);

/* A return of FALSE means that if there was an error, a common error was
put in the first address of a batch. */
return FALSE;
}




# ifdef DYNLOOKUP
#  define queuefile_transport_info _transport_info
# endif

transport_info queuefile_transport_info = {
.drinfo = {
  .driver_name =	US"queuefile",
  .options =		queuefile_transport_options,
  .options_count =	&queuefile_transport_options_count,
  .options_block =	&queuefile_transport_option_defaults,
  .options_len =	sizeof(queuefile_transport_options_block),
  .init =		queuefile_transport_init,
# ifdef DYNLOOKUP
  .dyn_magic =		TRANSPORT_MAGIC,
# endif
  },
.code =		queuefile_transport_entry,
.tidyup =	NULL,
.closedown =	NULL,
.local =	TRUE
};

#endif /*!MACRO_PREDEF*/
#endif /*EXPERIMENTAL_QUEUEFILE*/
