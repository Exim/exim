/* $Cambridge: exim/src/src/lookups/dsearch.c,v 1.6 2009/11/16 19:50:38 nm4 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* The idea for this code came from Matthew Byng-Maddick, but his original has
been heavily reworked a lot for Exim 4 (and it now uses stat() (more precisely:
lstat()) rather than a directory scan). */


#include "../exim.h"
#include "lf_functions.h"
#include "dsearch.h"



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. We open the directory to test
whether it exists and whether it is searchable. However, we don't need to keep
it open, because the "search" can be done by a call to lstat() rather than
actually scanning through the list of files. */

void *
dsearch_open(uschar *dirname, uschar **errmsg)
{
DIR *dp = opendir(CS dirname);
if (dp == NULL)
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

BOOL
dsearch_check(void *handle, uschar *filename, int modemask, uid_t *owners,
  gid_t *owngroups, uschar **errmsg)
{
handle = handle;
return lf_check_file(-1, filename, S_IFDIR, modemask, owners, owngroups,
  "dsearch", errmsg) == 0;
}


/*************************************************
*              Find entry point                  *
*************************************************/

/* See local README for interface description. We use lstat() instead of
scanning the directory, as it is hopefully faster to let the OS do the scanning
for us. */

int
dsearch_find(void *handle, uschar *dirname, uschar *keystring, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
struct stat statbuf;
int save_errno;
uschar filename[PATH_MAX];

handle = handle;  /* Keep picky compilers happy */
length = length;
do_cache = do_cache;

if (Ustrchr(keystring, '/') != 0)
  {
  *errmsg = string_sprintf("key for dsearch lookup contains a slash: %s",
    keystring);
  return DEFER;
  }

if (!string_format(filename, sizeof(filename), "%s/%s", dirname, keystring))
  {
  *errmsg = US"path name too long";
  return DEFER;
  }

if (Ulstat(filename, &statbuf) >= 0)
  {
  *result = string_copy(keystring);
  return OK;
  }

if (errno == ENOENT) return FAIL;

save_errno = errno;
*errmsg = string_sprintf("%s: lstat failed", filename);
errno = save_errno;
return DEFER;
}


/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

void
dsearch_close(void *handle)
{
handle = handle;   /* Avoid compiler warning */
}

/* End of lookups/dsearch.c */
