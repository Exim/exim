/* $Cambridge: exim/src/src/transports/tf_maildir.h,v 1.2 2005/01/04 10:00:45 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2005 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header file for the functions that are used to support the use of
maildirsize files for quota handling in maildir directories. */

extern int  maildir_compute_size(uschar *, int *, time_t *, const pcre *,
              const pcre *, BOOL);
extern BOOL maildir_ensure_directories(uschar *, address_item *, BOOL, int);
extern int  maildir_ensure_sizefile(uschar *,
              appendfile_transport_options_block *, const pcre *, const pcre *,
              int *, int *);
extern void maildir_record_length(int, int);

/* End of tf_maildir.h */
