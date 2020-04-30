/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */


/* This header file contains type definitions and macros that I use as
"standard" in the code of Exim and its utilities. Make it idempotent because
local_scan.h includes it and exim.h includes them both (to get this earlier). */

#ifndef MYTYPES_H
#define MYTYPES_H

# include <string.h>

#ifndef FALSE
# define FALSE         0
#endif

#ifndef TRUE
# define TRUE          1
#endif

#ifndef TRUE_UNSET
# define TRUE_UNSET    2
#endif


/* If gcc is being used to compile Exim, we can use its facility for checking
the arguments of printf-like functions. This is done by a macro. */

#if defined(__GNUC__) || defined(__clang__)
# define PRINTF_FUNCTION(A,B)	__attribute__((format(printf,A,B)))
# define ARG_UNUSED		__attribute__((__unused__))
# define WARN_UNUSED_RESULT	__attribute__((__warn_unused_result__))
# define ALLOC			__attribute__((malloc))
# define ALLOC_SIZE(A)		__attribute__((alloc_size(A)))
# define NORETURN		__attribute__((noreturn))
#else
# define PRINTF_FUNCTION(A,B)
# define ARG_UNUSED		/**/
# define WARN_UNUSED_RESULT	/**/
# define ALLOC			/**/
# define ALLOC_SIZE(A)		/**/
# define NORETURN		/**/
#endif

#ifdef WANT_DEEPER_PRINTF_CHECKS
# define ALMOST_PRINTF(A, B) PRINTF_FUNCTION(A, B)
#else
# define ALMOST_PRINTF(A, B)
#endif


/* Some operating systems (naughtily, imo) include a definition for "uchar" in
the standard header files, so we use "uschar". Solaris has u_char in
sys/types.h. This is just a typing convenience, of course. */

typedef unsigned char uschar;
typedef unsigned BOOL;
/* We also have SIGNAL_BOOL, which requires signal.h be included, so is defined
elsewhere */


/* These macros save typing for the casting that is needed to cope with the
mess that is "char" in ISO/ANSI C. Having now been bitten enough times by
systems where "char" is actually signed, I've converted Exim to use entirely
unsigned chars, except in a few special places such as arguments that are
almost always literal strings. */

#define CS   (char *)
#define CCS  (const char *)
#define CSS  (char **)
#define US   (unsigned char *)
#define CUS  (const unsigned char *)
#define USS  (unsigned char **)
#define CUSS (const unsigned char **)
#define CCSS (const char **)

/* The C library string functions expect "char *" arguments. Use macros to
avoid having to write a cast each time. We do this for string and file
functions that are called quite often; for other calls to external libraries
(which are on the whole special-purpose) we just use individual casts. */

#define Uatoi(s)           atoi(CCS(s))
#define Uatol(s)           atol(CCS(s))
#define Uchdir(s)          chdir(CCS(s))
#define Uchmod(s,n)        chmod(CCS(s),n)
#define Ufgets(b,n,f)      fgets(CS(b),n,f)
#define Ufopen(s,t)        exim_fopen(CCS(s),CCS(t))
#define Ulink(s,t)         link(CCS(s),CCS(t))
#define Ulstat(s,t)        lstat(CCS(s),t)

#ifdef O_BINARY							/* This is for Cygwin,  */
# define Uopen(s,n,m)       exim_open(CCS(s),(n)|O_BINARY,m)	/* where all files must */
# define Uopen2(s,n)        exim_open2(CCS(s),(n)|O_BINARY)
#else								/* be opened as binary  */
# define Uopen(s,n,m)       exim_open(CCS(s),n,m)		/* to avoid problems    */
# define Uopen2(s,n)        exim_open2(CCS(s),n)	
#endif								/* with CRLF endings.   */
#define Uread(f,b,l)       read(f,CS(b),l)
#define Urename(s,t)       rename(CCS(s),CCS(t))
#define Ustat(s,t)         stat(CCS(s),t)
#define Ustrchr(s,n)       US strchr(CCS(s),n)
#define CUstrchr(s,n)      CUS strchr(CCS(s),n)
#define CUstrerror(n)      CUS strerror(n)
#define Ustrcmp(s,t)       strcmp(CCS(s),CCS(t))
#define Ustrcpy_nt(s,t)    strcpy(CS s, CCS t)		/* no taint check */
#define Ustrcspn(s,t)      strcspn(CCS(s),CCS(t))
#define Ustrftime(s,m,f,t) strftime(CS(s),m,f,t)
#define Ustrlen(s)         (int)strlen(CCS(s))
#define Ustrncmp(s,t,n)    strncmp(CCS(s),CCS(t),n)
#define Ustrncpy_nt(s,t,n) strncpy(CS s, CCS t, n)	/* no taint check */
#define Ustrpbrk(s,t)      strpbrk(CCS(s),CCS(t))
#define Ustrrchr(s,n)      US strrchr(CCS(s),n)
#define CUstrrchr(s,n)     CUS strrchr(CCS(s),n)
#define Ustrspn(s,t)       strspn(CCS(s),CCS(t))
#define Ustrstr(s,t)       US strstr(CCS(s),CCS(t))
#define CUstrstr(s,t)      CUS strstr(CCS(s),CCS(t))
#define Ustrtod(s,t)       strtod(CCS(s),CSS(t))
#define Ustrtol(s,t,b)     strtol(CCS(s),CSS(t),b)
#define Ustrtoul(s,t,b)    strtoul(CCS(s),CSS(t),b)
#define Uunlink(s)         unlink(CCS(s))

#if defined(EM_VERSION_C) || defined(LOCAL_SCAN) || defined(DLFUNC_IMPL)
# define Ustrcat(s,t)       strcat(CS(s), CCS(t))
# define Ustrcpy(s,t)       strcpy(CS(s), CCS(t))
# define Ustrncat(s,t,n)    strncat(CS(s), CCS(t), n)
# define Ustrncpy(s,t,n)    strncpy(CS(s), CCS(t), n)
#else
# define Ustrcat(s,t)       __Ustrcat(s, CUS(t), __FUNCTION__, __LINE__)
# define Ustrcpy(s,t)       __Ustrcpy(s, CUS(t), __FUNCTION__, __LINE__)
# define Ustrncat(s,t,n)    __Ustrncat(s, CUS(t), n, __FUNCTION__, __LINE__)
# define Ustrncpy(s,t,n)    __Ustrncpy(s, CUS(t), n, __FUNCTION__, __LINE__)
#endif

#endif
/* End of mytypes.h */
