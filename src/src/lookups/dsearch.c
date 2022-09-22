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

/* See local README for interface description. We checks that the proposed
directory is untainted and absolute. On systems where fstatat is supported, we
also opens the directory in O_PATH mode, meaning that fstatat does not have to
re-parse the entire path when it subsequently checks for the existence of a
file within it. */

static void *
dsearch_open(const uschar * dirname, uschar ** errmsg)
{
if (*dirname != '/')
  {
  *errmsg = string_sprintf("dirname '%s' for dsearch is not absolute", dirname);
  return NULL;
  }
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
ds_handle *h = store_get(sizeof (ds_handle), GET_UNTAINTED);
h->dir_fd = dir_fd;
DEBUG(D_lookup) debug_printf_indent("  dsearch_open: dirname=%s -> fd=%d h=%p\n", dirname, dir_fd, h);
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

#ifdef USE_AT_FILE
static BOOL
dsearch_check(void * handle, const uschar * UNUSED(dirname), int modemask,
  uid_t * owners, gid_t * owngroups, uschar ** errmsg)
{
ds_handle *h = handle;
BOOL r = lf_check_file(h->dir_fd, NULL, S_IFDIR, modemask, owners, owngroups,
  "dsearch", errmsg) == 0;
DEBUG(D_lookup) debug_printf_indent("  dsearch_check: h=%p fd=%d -> %d\n", h, h->dir_fd, r);
return r;
}
#else
static BOOL
dsearch_check(void * UNUSED(handle), const uschar * dirname, int modemask,
  uid_t * owners, gid_t * owngroups, uschar ** errmsg)
{
BOOL r = lf_check_file(-1, dirname, S_IFDIR, modemask, owners, owngroups,
  "dsearch", errmsg) == 0;
DEBUG(D_lookup) debug_printf_indent("  dsearch_check: dirname=%s -> %d\n", dirname, r);
return r;
}
#endif


/*************************************************
*              Find entry point                  *
*************************************************/

/* See local README for interface description. We use a single lstat() or
stat() or fstatat() syscall, instead of reading the directory (which takes at
least 3 syscalls). */

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
ifmt_set_t filter_by_type = 0;
int allowdots = 0;
enum {
  RET_KEY,  /* return the key */
  RET_DIR,  /* return the dir without the key */
  RET_FULL  /* return the path comprising both combined */
} ret_mode = RET_KEY;
int follow_symlink = 0;
int ignore_key = 0;
#ifdef USE_AT_FILE
ds_handle *h = handle;
int statat_flags = 0;
#endif
const uschar *full_path;
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
    if (Ustrncmp(ele, "ret=", 4) == 0)
      {
      ele += 4;
      if (Ustrcmp(ele, "full") == 0)
	ret_mode = RET_FULL;
      else if (Ustrcmp(ele, "dir") == 0)
	ret_mode = RET_DIR;
      #if 0
      /* NOTE ret=key is excluded from opts by special-case code in by search_find() */
      else if (Ustrcmp(ele, "key") == 0)
	ret_mode = RET_KEY;
      #endif
      else
	{
	*errmsg = string_sprintf("unknown parameter for dsearch lookup: %s", ele-=4);
	return DEFER;
	}
      }
    else if (Ustrncmp(ele, "filter=", 7) == 0)
      {
      ele += 7;
      ifmt_set_t m = S_IFMTset_from_name(ele);
      if (m)
        {
	filter_by_type |= m;
/* XXX issue immediate deprecation warning */
#ifndef NO_DIR_IMPLIES_ALLOWDOTS
        /* allow "." or ".." when "dir" rather than "subdir" */
        if (m == S_IFMT_to_set(S_IFDIR) && ele[0] == 'd')
          allowdots = 1;
#endif
        }
      else if (Ustrcmp(ele, "allowdots") == 0)
        allowdots = 1;    /* allow "." or ".." */
      else
	{
	*errmsg = string_sprintf("unknown parameter for dsearch lookup: %s", ele-=7);
	return DEFER;
	}
      }
    else if (Ustrcmp(ele, "follow") == 0)
      follow_symlink = 1;
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

DEBUG(D_lookup) debug_printf_indent("  dsearch_find: %s%sfilter_set=%04jx ret=%s key=%s\n",
  follow_symlink ? "follow, " : "",
  allowdots ? "filter=allowdots, " : "",
  (uintmax_t) filter_by_type,
  ret_mode == RET_FULL ? "full" : ret_mode == RET_DIR ? "dir" : "key",
  keystring);

/* exclude "." and ".." when {filter=subdir} included */
if (! allowdots
    &&  keystring[0] == '.'
    && (keystring[1] == 0
     || keystring[1] == '.' && keystring[2] == 0))
  return FAIL;

#ifdef USE_AT_FILE
if (!follow_symlink) statat_flags |= AT_SYMLINK_NOFOLLOW;
if (ignore_key)      statat_flags |= AT_EMPTY_PATH;
stat_result = fstatat(h->dir_fd, CCS keystring, &statbuf, statat_flags);
#else
full_path = ignore_key ? dirname
		       : string_sprintf("%s/%s", dirname, keystring);
if (follow_symlink)
  stat_result = Ustat(full_path, &statbuf);
else
  stat_result = Ulstat(full_path, &statbuf);
#endif
if (stat_result >= 0)
  {
  if (!filter_by_type
	|| filter_by_type & S_IFMT_to_set(statbuf.st_mode))
    {
    switch (ret_mode)
      {
      default:
      case RET_KEY:
	full_path = keystring;
	break;
      case RET_DIR:
	full_path = dirname;
	break;
      case RET_FULL:
	#ifdef USE_AT_FILE
	full_path = string_sprintf("%s/%s", dirname, keystring);
	#else
	full_path = full_path;
	#endif
	break;
      }

    /* Since the filename exists in the filesystem, we can return a
    non-tainted result. */
    full_path =
    *result = string_copy_taint(full_path, GET_UNTAINTED);
    DEBUG(D_lookup) debug_printf_indent("  dsearch_find: res=%s", full_path);
    return OK;
    }
  *errmsg = string_sprintf("%s/%s is of unexpected type %s",
    dirname, keystring, S_IFMT_to_long_name(statbuf.st_mode));
  errno = ERRNO_MISMATCH;
  return DEFER;
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
DEBUG(D_lookup) debug_printf_indent("  dsearch_close: h=%p fd=%d\n", h, h->dir_fd);
close(h->dir_fd);   /* ignore error */
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
