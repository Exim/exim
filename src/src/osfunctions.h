/* $Cambridge: exim/src/src/osfunctions.h,v 1.2 2005/01/04 10:00:42 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2005 */
/* See the file NOTICE for conditions of use and distribution. */

/* Prototypes for os-specific functions. For utilities, we don't need the one
that uses a type that isn't defined for them. */

#ifndef COMPILE_UTILITY
extern ip_address_item *os_common_find_running_interfaces(void);
#endif

extern int     os_getloadavg(void);
extern void    os_restarting_signal(int, void (*)(int));
extern void    os_non_restarting_signal(int, void (*)(int));
extern char   *os_strexit(int);     /* char to match os_strsignal */
extern char   *os_strsignal(int);   /* char to match strsignal in some OS */

/* End of osfunctions.h */
