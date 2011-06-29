/*************************************************
*                  Exim Monitor                  *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

#include "mytypes.h"
#include "macros.h"
#include <string.h>
#include <stdlib.h>

extern uschar *version_string;
extern uschar *version_date;

void
version_init(void)
{
int i = 0;
uschar today[20];

version_string = US"2.06";

Ustrcpy(today, __DATE__);
if (today[4] == ' ') i = 1;
today[3] = today[6] = '-';

version_date = (uschar *)malloc(32);
version_date[0] = 0;
Ustrncat(version_date, today+4+i, 3-i);
Ustrncat(version_date, today, 4);
Ustrncat(version_date, today+7, 4);
Ustrcat(version_date, " ");
Ustrcat(version_date, __TIME__);
}

/* End of em_version.c */
