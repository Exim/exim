/* $Cambridge: exim/src/src/lookups/passwd.c,v 1.4 2007/01/08 10:50:19 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2007 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "passwd.h"



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */

void *
passwd_open(uschar *filename, uschar **errmsg)
{
filename = filename;     /* Keep picky compilers happy */
errmsg = errmsg;
return (void *)(-1);     /* Just return something non-null */
}




/*************************************************
*         Find entry point for passwd           *
*************************************************/

/* See local README for interface description */

int
passwd_find(void *handle, uschar *filename, uschar *keystring, int length,
  uschar **result, uschar **errmsg, BOOL *do_cache)
{
struct passwd *pw;

handle = handle;         /* Keep picky compilers happy */
filename = filename;
length = length;
errmsg = errmsg;
do_cache = do_cache;

if (!route_finduser(keystring, &pw, NULL)) return FAIL;
*result = string_sprintf("*:%d:%d:%s:%s:%s", (int)pw->pw_uid, (int)pw->pw_gid,
  pw->pw_gecos, pw->pw_dir, pw->pw_shell);
return OK;
}

/* End of lookups/passwd.c */
