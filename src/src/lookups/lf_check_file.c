/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */


#include "../exim.h"
#include "lf_functions.h"

const uschar * S_IF_longnames[] = {
    #ifdef S_IFBLK
    [S_IFMT_to_index(S_IFBLK)]  = CUS "block device",
    #endif
    #ifdef S_IFCHR
    [S_IFMT_to_index(S_IFCHR)]  = CUS "serial device",
    #endif
    #ifdef S_IFLNK
    [S_IFMT_to_index(S_IFLNK)]  = CUS "symbolic link",
    #endif
    #ifdef S_IFIFO
    [S_IFMT_to_index(S_IFIFO)]  = CUS "named pipe",
    #endif
    #ifdef S_IFSOCK
    [S_IFMT_to_index(S_IFSOCK)] = CUS "local socket",
    #endif
    [S_IFMT_to_index(S_IFDIR)]  = CUS "directory",
    [S_IFMT_to_index(S_IFREG)]  = CUS "regular file"
};
const uschar * S_IF_names[] = {
    #ifdef S_IFBLK
    [S_IFMT_to_index(S_IFBLK)]  = CUS "bdev",
    #endif
    #ifdef S_IFCHR
    [S_IFMT_to_index(S_IFCHR)]  = CUS "cdev",
    #endif
    #ifdef S_IFLNK
    [S_IFMT_to_index(S_IFLNK)]  = CUS "link",
    #endif
    #ifdef S_IFIFO
    [S_IFMT_to_index(S_IFIFO)]  = CUS "fifo",
    #endif
    #ifdef S_IFSOCK
    [S_IFMT_to_index(S_IFSOCK)] = CUS "sock",
    #endif
    [S_IFMT_to_index(S_IFDIR)]  = CUS "dir",
    [S_IFMT_to_index(S_IFREG)]  = CUS "file"
};
const uschar * S_IF_ucnames[] = {
    #ifdef S_IFBLK
    [S_IFMT_to_index(S_IFBLK)]  = CUS "BDEV",
    #endif
    #ifdef S_IFCHR
    [S_IFMT_to_index(S_IFCHR)]  = CUS "CDEV",
    #endif
    #ifdef S_IFLNK
    [S_IFMT_to_index(S_IFLNK)]  = CUS "LINK",
    #endif
    #ifdef S_IFIFO
    [S_IFMT_to_index(S_IFIFO)]  = CUS "FIFO",
    #endif
    #ifdef S_IFSOCK
    [S_IFMT_to_index(S_IFSOCK)] = CUS "SOCK",
    #endif
    [S_IFMT_to_index(S_IFDIR)]  = CUS "DIR",
    [S_IFMT_to_index(S_IFREG)]  = CUS "FILE"
};
const size_t num_S_IF_names = nelem(S_IF_names);

static const struct {
  const uschar *name;
  int index;
} ni_map[] = {
  /* sorted in descending order of likelihood */
  { CUS "file",    S_IFMT_to_index(S_IFREG) },
  { CUS "dir",     S_IFMT_to_index(S_IFDIR) },
  { CUS "subdir",  S_IFMT_to_index(S_IFDIR) },
  #ifdef S_IFLNK
  { CUS "symlink", S_IFMT_to_index(S_IFLNK) },
  { CUS "link",    S_IFMT_to_index(S_IFLNK) },
  #endif
  #ifdef S_IFIFO
  { CUS "fifo",    S_IFMT_to_index(S_IFIFO) },
  { CUS "pipe",    S_IFMT_to_index(S_IFIFO) },
  #endif
  #ifdef S_IFSOCK
  { CUS "socket",  S_IFMT_to_index(S_IFSOCK) },
  { CUS "sock",    S_IFMT_to_index(S_IFSOCK) },
  #endif
  #ifdef S_IFCHR
  { CUS "cdev",    S_IFMT_to_index(S_IFCHR) },
  { CUS "tty",     S_IFMT_to_index(S_IFCHR) },
  #endif
  #ifdef S_IFBLK
  { CUS "bdev",    S_IFMT_to_index(S_IFBLK) },
  #endif
  { CUS "reg",     S_IFMT_to_index(S_IFREG) }
};
static const size_t num_ni_map = nelem(ni_map);

ifmt_set_t
S_IFMTset_from_name(const uschar *name)
{
for (int i=0 ; i < num_ni_map ; ++i)
  if (Ustrcmp(ni_map[i].name, name) == 0)
    return 1UL << ni_map[i].index;
return 0;
}

const uschar *
S_IFMTix_to_long_name(int index)
{
if (index < 0 || index >= num_S_IF_names)
  return NULL; /* invalid file type */
return S_IF_longnames[index];
}

/*************************************************
*         Check a file's credentials             *
*************************************************/

/* fstat can normally be expected to work on an open file, but there are some
NFS states where it may not.

Arguments:
  fd         an open file descriptor or -1
  filename   a file name if fd is -1
  s_type     type of file (S_IFREG or S_IFDIR)
  modemask   a mask specifying mode bits that must *not* be set
  owners     NULL or a list of of allowable uids, count in the first item
  owngroups  NULL or a list of allowable gids, count in the first item
  type       name of lookup type for putting in error message
  errmsg     where to put an error message

Returns:     -1 stat() or fstat() failed
              0 OK
             +1 something didn't match

Side effect: sets errno to ERRNO_BADUGID, ERRNO_NOTREGULAR or ERRNO_BADMODE for
             bad uid/gid, not a regular file, or bad mode; otherwise leaves it
             to what fstat set it to.
*/

int
lf_check_file(int fd, const uschar * filename, int s_type, int modemask,
  uid_t * owners, gid_t * owngroups, const char * type, uschar ** errmsg)
{
struct stat statbuf;

if ((fd  < 0 ? Ustat(filename, &statbuf) : fstat(fd, &statbuf)) != 0)
  {
  int save_errno = errno;
  *errmsg = string_sprintf("%s: stat failed", filename);
  errno = save_errno;
  return -1;
  }

if ((statbuf.st_mode & S_IFMT) != s_type)
  {
  const uschar *t = S_IFMT_to_long_name(s_type);
  if (t)
    {
    *errmsg = string_sprintf("%s is not a %s (%s lookup)",
      filename, t, type);
    errno = s_type == S_IFDIR ? ERRNO_NOTDIRECTORY :
	 /* s_type != S_IFREG ? ERRNO_MISMATCH : */ /* TODO - decide whether to use this? */
				ERRNO_NOTREGULAR;
    }
  else
    {
    *errmsg = string_sprintf("%s is not a type#%d name (%s lookup)",
      filename, S_IFMT_to_index(s_type), type);
    errno = ERRNO_BADMODE;
    }
  return +1;
  }

if ((statbuf.st_mode & modemask) != 0)
  {
  *errmsg = string_sprintf("%s (%s lookup): file mode %.4o should not contain "
    "%.4o", filename, type,  statbuf.st_mode & 07777,
    statbuf.st_mode & modemask);
  errno = ERRNO_BADMODE;
  return +1;
  }

if (owners)
  {
  BOOL uid_ok = FALSE;
  for (int i = 1; i <= (int)owners[0]; i++)
    if (owners[i] == statbuf.st_uid) { uid_ok = TRUE; break; }
  if (!uid_ok)
    {
    *errmsg = string_sprintf("%s (%s lookup): file has wrong owner", filename,
      type);
    errno = ERRNO_BADUGID;
    return +1;
    }
  }

if (owngroups)
  {
  BOOL gid_ok = FALSE;
  for (int i = 1; i <= (int)owngroups[0]; i++)
    if (owngroups[i] == statbuf.st_gid) { gid_ok = TRUE; break; }
  if (!gid_ok)
    {
    *errmsg = string_sprintf("%s (%s lookup): file has wrong group", filename,
      type);
    errno = ERRNO_BADUGID;
    return +1;
    }
  }

return 0;
}

/* End of lf_check_file.c */
