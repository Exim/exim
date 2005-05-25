/* $Cambridge: exim/src/src/lookups/spf.h,v 1.1 2005/05/25 20:07:55 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * Exim - SPF lookup module using libspf2
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Copyright (c) 2005 Chris Webb, Arachsys Internet Services Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
*/



extern void *spf_open(uschar *, uschar **);
extern void spf_close(void *);
extern int spf_find(void *, uschar *, uschar *, int, uschar **, uschar **,
                    BOOL *);

