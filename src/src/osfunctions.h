/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2016 */
/* Copyright (c) The Exim Maintainers 2019 */
/* See the file NOTICE for conditions of use and distribution. */

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

#ifdef OS_PIPE_RW_EINTR
 extern ssize_t os_pipe_read(int fd, void * buf, size_t count);
 extern ssize_t os_pipe_write(int fd, void * buf, size_t count);
 extern ssize_t os_pipe_writev(int fd, const struct iovec * iov, int iovcnt);
#else
# define os_pipe_read(fd, buf, count) read(fd, buf, count)
# define os_pipe_write(fd, buf, count) write(fd, buf, count)
# define os_pipe_writev(fd, buf, count) writev(fd, buf, count)
#endif

/* End of osfunctions.h */
