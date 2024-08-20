/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2016 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Prototypes for os-specific functions. For utilities, we don't need the one
that uses a type that isn't defined for them. */

#ifndef COMPILE_UTILITY
extern ip_address_item *os_common_find_running_interfaces(void);
#endif

/* If these exist as a macro, then they're overridden away from us and we
rely upon the system headers to provide prototype declarations for us.
Notably, strsignal() is not in the Single Unix Specification (v3) and
predicting constness is awkward. */

#ifndef os_getloadavg
extern int           os_getloadavg(void);
#endif
#ifndef os_restarting_signal
extern void          os_restarting_signal(int, void (*)(int));
#endif
#ifndef os_non_restarting_signal
extern void          os_non_restarting_signal(int, void (*)(int));
#endif
#ifndef os_strexit
extern const char   *os_strexit(int);     /* char to match os_strsignal */
#endif
#ifndef os_strsignal
extern const char   *os_strsignal(int);   /* char to match strsignal in some OS */
#endif
#ifndef os_unsetenv
extern int           os_unsetenv(const uschar *);
#endif
#ifndef os_getcwd
extern uschar       *os_getcwd(uschar *, size_t);
#endif

#ifndef EXIM_HAVE_STRCHRNUL
extern char * strchrnul(const char *, int);
#endif

/* End of osfunctions.h */
