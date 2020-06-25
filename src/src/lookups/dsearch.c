/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */

/* The idea for this code came from Matthew Byng-Maddick, but his original has
been heavily reworked a lot for Exim 4 (and it now uses stat() (more precisely:
lstat()) rather than a directory scan). */


#include "../exim.h"
#include "lf_functions.h"



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
DIR * dp = exim_opendir(dirname);
if (!dp)
  {
  int save_errno = errno;
  *errmsg = string_open_failed(errno, "%s for directory search", dirname);
  errno = save_errno;
  return NULL;
  }
closedir(dp);
return (void *)(-1);
}


/*************************************************
*             Check entry point                  *
*************************************************/

/* The handle will always be (void *)(-1), but don't try casting it to an
integer as this gives warnings on 64-bit systems. */

static BOOL
dsearch_check(void * handle, const uschar * filename, int modemask,
  uid_t * owners, gid_t * owngroups, uschar ** errmsg)
{
handle = handle;
if (*filename == '/')
  return lf_check_file(-1, filename, S_IFDIR, modemask, owners, owngroups,
    "dsearch", errmsg) == 0;
*errmsg = string_sprintf("dirname '%s' for dsearch is not absolute", filename);
return FALSE;
}


/*************************************************
*              Find entry point                  *
*************************************************/

#define RET_FULL	BIT(0)
#define FILTER_TYPE	BIT(1)
#define FILTER_ALL	BIT(1)
#define FILTER_FILE	BIT(2)
#define FILTER_DIR	BIT(3)
#define FILTER_SUBDIR	BIT(4)

/* See local README for interface description. We use lstat() instead of
scanning the directory, as it is hopefully faster to let the OS do the scanning
for us. */

static int
dsearch_find(void * handle, const uschar * dirname, const uschar * keystring,
  int length, uschar ** result, uschar ** errmsg, uint * do_cache,
  const uschar * opts)
{
struct stat statbuf;
int save_errno;
uschar * filename;
unsigned flags = 0;

handle = handle;  /* Keep picky compilers happy */
length = length;
do_cache = do_cache;

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
      flags |= RET_FULL;
    else if (Ustrncmp(ele, "filter=", 7) == 0)
      {
      ele += 7;
      if (Ustrcmp(ele, "file") == 0)
	flags |= FILTER_TYPE | FILTER_FILE;
      else if (Ustrcmp(ele, "dir") == 0)
	flags |= FILTER_TYPE | FILTER_DIR;
      else if (Ustrcmp(ele, "subdir") == 0)
	flags |= FILTER_TYPE | FILTER_SUBDIR;	/* like dir but not "." or ".." */
      }
  }

filename = string_sprintf("%s/%s", dirname, keystring);
if (  Ulstat(filename, &statbuf) >= 0
   && (  !(flags & FILTER_TYPE)
      || (flags & FILTER_FILE && S_ISREG(statbuf.st_mode))
      || (  flags & (FILTER_DIR | FILTER_SUBDIR)
       	 && S_ISDIR(statbuf.st_mode)
	 && (  flags & FILTER_DIR
	    || keystring[0] != '.'
	    || keystring[1] && keystring[1] != '.'
   )  )  )  )
  {
  /* Since the filename exists in the filesystem, we can return a
  non-tainted result. */
  *result = string_copy_taint(flags & RET_FULL ? filename : keystring, FALSE);
  return OK;
  }

if (errno == ENOENT || errno == 0) return FAIL;

save_errno = errno;
*errmsg = string_sprintf("%s: lstat: %s", filename, strerror(errno));
errno = save_errno;
return DEFER;
}


/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

void
static dsearch_close(void *handle)
{
handle = handle;   /* Avoid compiler warning */
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
dsearch_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: dsearch: Exim version %s\n", EXIM_VERSION_STR);
#endif
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
  .version_report = dsearch_version_report         /* version reporting */
};

#ifdef DYNLOOKUP
#define dsearch_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info dsearch_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/dsearch.c */
