/* $Cambridge: exim/src/src/lookups/cdb.h,v 1.1 2004/10/07 13:10:01 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * $Id: cdb.h,v 1.2.2.1 1998/05/29 16:21:36 cvs Exp $
 *
 * Exim - CDB database lookup module
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Copyright (c) 1998 Nigel Metheringham, Planet Online Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 *
 * This code implements Dan Bernstein's Constant DataBase (cdb) spec.
 * Information, the spec and sample code for cdb can be obtained from
 *      http://www.pobox.com/~djb/cdb.html
 *
 * This implementation borrows some code from Dan Bernstein's
 * implementation (which has no license restrictions applied to it).
 * This (read-only) implementation is completely contained within
 * cdb.[ch] it does *not* link against an external cdb library.
 *
 *
 * There are 2 varients included within this code.  One uses MMAP and
 * should give better performance especially for multiple lookups on a
 * modern machine.  The other is the default implementation which is
 * used in the case where the MMAP fails or if MMAP was not compiled
 * in.  this implementation is the same as the original reference cdb
 * implementation.
 *
 */


/* Functions for reading exim cdb files */

extern void *cdb_open(uschar *, uschar **);
extern BOOL  cdb_check(void *, uschar *, int, uid_t *, gid_t *, uschar **);
extern int   cdb_find(void *, uschar *, uschar *, int, uschar **, uschar **,
               BOOL *);
extern void  cdb_close(void *);

/* End of cdb.h */
