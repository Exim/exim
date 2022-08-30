/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* The idea for this code came from Matthew Byng-Maddick, but his original has
been heavily reworked a lot for Exim 4 (and it now uses stat() (more precisely:
lstat()) rather than a directory scan). */


#include "../exim.h"
#include "lf_functions.h"

#if !defined USE_AT_FILE \
 && !defined NO_AT_FILE \
 && ( defined O_PATH && defined O_DIRECTORY ) \
 && ( _XOPEN_SOURCE >= 700 || _POSIX_C_SOURCE >= 200809L \
      || defined _ATFILE_SOURCE )
#define USE_AT_FILE
#endif

#ifdef USE_AT_FILE
/* Have fstatat() */
typedef struct {
  int dir_fd;
} ds_handle;
#endif


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. We open the directory to test
whether it exists and whether it is searchable. However, we don't need to keep
it open, because the "search" can be done by a call to lstat() rather than
actually scanning through the list of files. */

static void *
dsearch_open(const uschar * dirname, uschar ** errmsg)
{
if (is_tainted(dirname))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "Tainted dirname '%s'", dirname);
  errno = EACCES;
  *errmsg = string_open_failed("%s for directory search", dirname);
  return NULL;
  }
#ifdef USE_AT_FILE
int dir_fd = open(dirname, O_PATH|O_DIRECTORY);
if (dir_fd<0)
  {
  *errmsg = string_open_failed("%s for directory search", dirname);
  return NULL;
  }
ds_handle *h = malloc(sizeof (ds_handle));
h->dir_fd = dir_fd;
return h;
#else
if (f.running_in_test_harness)
  /* Dereferencing (void*)(-1) will intentionally cause an immediate abort on
   * most modern architectures. However we only use this return statement
   * during regression testing, as it has "undefined behaviour" according to
   * ISO-9899, and in theory could misbehave on exotic architectures even
   * during normal operation; in particular (void*)(-1)==NULL is allowable.
   */
  return (void*)(-1);
static char ignored_handle[1];
return ignored_handle;
#endif
}

/*************************************************
*             Check entry point                  *
*************************************************/

/* The handle will always be (void *)(-1), but don't try casting it to an
integer as this gives warnings on 64-bit systems. */

static BOOL
dsearch_check(void * UNUSED(handle), const uschar * filename, int modemask,
  uid_t * owners, gid_t * owngroups, uschar ** errmsg)
{
if (*filename == '/')
  return lf_check_file(-1, filename, S_IFDIR, modemask, owners, owngroups,
    "dsearch", errmsg) == 0;
*errmsg = string_sprintf("dirname '%s' for dsearch is not absolute", filename);
return FALSE;
}


/*************************************************
*              Find entry point                  *
*************************************************/

#define FILTER_BY(TYPE) BIT( S_I##TYPE / (S_IFMT&-S_IFMT) )   /* X&-X gives the bottom bit of X */

/* See local README for interface description. We use lstat() or fstatat()
instead of reading the directory, as it is hopefully faster to let the OS do
the scanning for us. */

static int
dsearch_find(
  #ifdef USE_AT_FILE
  void * handle,
  #else
  void * UNUSED(handle),
  #endif
  const uschar * dirname, const uschar * keystring, int length,
  uschar ** result, uschar ** errmsg, uint * do_cache, const uschar * opts)
{
struct stat statbuf;
int save_errno;
unsigned filter_by_type = 0;
int exclude_dotdotdot = 0;
int ret_full = 0;
int follow_symlink = 0;
int ignore_key = 0;
#ifdef USE_AT_FILE
ds_handle *h = handle;
int statat_flags = 0;
#else
const uschar *filename;
#endif
int stat_result;

if (Ustrchr(keystring, '/') != 0)
  {
  *errmsg = string_sprintf("key for dsearch lookup contains a slash: %s",
    keystring);
  return DEFER;
  }

if (opts)
  {
  int sep = ',';
  uschar * ele;

  while ((ele = string_nextinlist(&opts, &sep, NULL, 0)))
    if (Ustrcmp(ele, "ret=full") == 0)
      ret_full = 1;
    else if (Ustrncmp(ele, "filter=", 7) == 0)
      {
      ele += 7;
	   if (Ustrcmp(ele, "file") == 0)    filter_by_type |= FILTER_BY(FREG);
      else if (Ustrcmp(ele, "dir") == 0)     filter_by_type |= FILTER_BY(FDIR);
      else if (Ustrcmp(ele, "subdir") == 0)  filter_by_type |= FILTER_BY(FDIR), exclude_dotdotdot = 1;    /* dir but not "." or ".." */
      else if (Ustrcmp(ele, "pipe") == 0
	    || Ustrcmp(ele, "fifo") == 0)    filter_by_type |= FILTER_BY(FIFO);
      else if (Ustrcmp(ele, "socket") == 0)  filter_by_type |= FILTER_BY(FSOCK);
      else if (Ustrcmp(ele, "link") == 0
	    || Ustrcmp(ele, "symlink") == 0) filter_by_type |= FILTER_BY(FLNK);
      else if (Ustrcmp(ele, "bdev") == 0)    filter_by_type |= FILTER_BY(FBLK);
      else if (Ustrcmp(ele, "cdev") == 0)    filter_by_type |= FILTER_BY(FCHR);
      else
	{
	*errmsg = string_sprintf("unknown filter option for dsearch lookup: %s", ele);
	return DEFER;
	}
      }
    else if (Ustrcmp(ele, "follow") == 0)
      follow_symlink = 1;
    else if (Ustrcmp(ele, "checkpath") == 0)
      ignore_key = follow_symlink = ret_full = 1;
    else if (Ustrcmp(ele, "ignorekey") == 0)
      ignore_key = 1;
    else
      {
      *errmsg = string_sprintf("unknown option for dsearch lookup: %s", ele);
      return DEFER;
      }
  }

if (ignore_key)
  keystring = "";
else if (keystring == NULL || keystring[0] == 0) /* in case lstat treats "/dir/" the same as "/dir/." */
  return FAIL;

/* exclude "." and ".." when {filter=subdir} included */
if (exclude_dotdotdot
    &&  keystring[0] == '.'
    && (keystring[1] == 0
     || keystring[1] == '.' && keystring[2] == 0))
  return FAIL;

#ifdef USE_AT_FILE
if (!follow_symlink) statat_flags |= AT_SYMLINK_NOFOLLOW;
if (ignore_key)      statat_flags |= AT_EMPTY_PATH;
stat_result = fstatat(h->dir_fd, CCS keystring, &statbuf, statat_flags);
#else
filename = ignore_key ? dirname
		      : string_sprintf("%s/%s", dirname, keystring);
if (follow_symlink)
  stat_result = Ustat(filename, &statbuf);
else
  stat_result = Ulstat(filename, &statbuf);
#endif
if (stat_result >= 0
   && ( !filter_by_type
      || filter_by_type & BIT((statbuf.st_mode & S_IFMT) / (S_IFMT&-S_IFMT))))
  {
  if (ret_full)
    #ifdef USE_AT_FILE
    keystring = string_sprintf("%s/%s", dirname, keystring);
    #else
    keystring = filename;
    #endif

  /* Since the filename exists in the filesystem, we can return a
  non-tainted result. */
  *result = string_copy_taint(keystring, GET_UNTAINTED);
  return OK;
  }

if (errno == ENOENT || errno == 0) return FAIL;

save_errno = errno;
*errmsg = string_sprintf("%s/%s: lstat: %s", dirname, keystring, strerror(errno));
errno = save_errno;
return DEFER;
}


/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

#ifdef USE_AT_FILE
static void
dsearch_close(void *handle)
{
ds_handle *h = handle;
close(h->dir_fd);   /* ignore error */
free(h);
}
#else
static void
dsearch_close(void * UNUSED(handle))
{
}
#endif


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

gstring *
dsearch_version_report(gstring * g)
{
#ifdef DYNLOOKUP
g = string_fmt_append(g, "Library version: dsearch: Exim version %s\n", EXIM_VERSION_STR);
#endif
return g;
}


static lookup_info _lookup_info = {
  .name = US"dsearch",			/* lookup name */
  .type = lookup_absfile,		/* uses absolute file name */
  .open = dsearch_open,			/* open function */
  .check = dsearch_check,		/* check function */
  .find = dsearch_find,			/* find function */
  .close = dsearch_close,		/* close function */
  .tidy = NULL,				/* no tidy function */
  .quote = NULL,			/* no quoting function */
  .version_report = dsearch_version_report /* version reporting */
};

#ifdef DYNLOOKUP
#define dsearch_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info dsearch_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/dsearch.c */
