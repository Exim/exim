/* $Cambridge: exim/src/src/dbfunctions.h,v 1.2 2005/01/04 10:00:42 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2005 */
/* See the file NOTICE for conditions of use and distribution. */


/* Functions for reading/writing exim database files */

void     dbfn_close(open_db *);
int      dbfn_delete(open_db *, uschar *);
open_db *dbfn_open(uschar *, int, open_db *, BOOL);
void    *dbfn_read_with_length(open_db *, uschar *, int *);
uschar  *dbfn_scan(open_db *, BOOL, EXIM_CURSOR **);
int      dbfn_write(open_db *, uschar *, void *, int);

/* Macro for the common call to read without wanting to know the length. */

#define  dbfn_read(a, b) dbfn_read_with_length(a, b, NULL)

/* Berkeley DB uses a callback function to pass back error details. */

#if defined(USE_DB) && defined(DB_VERSION_STRING)
void     dbfn_bdb_error_callback(const char *, char *);
#endif

/* End of dbfunctions.h */
