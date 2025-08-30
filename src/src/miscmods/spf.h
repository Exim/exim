/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* SPF support.
   Copyright (c) The Exim Maintainers 2016 - 2025
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004
   License: GPL
   SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifdef EXPERIMENTAL_SPF_PERL
# define EXIM_HAVE_SPF EXPERIMENTAL_SPF_PERL

#elif defined(SUPPORT_SPF)
# define EXIM_HAVE_SPF SUPPORT_SPF

/* Yes, we do have ns_type. spf.h redefines it if we don't set this. Doh */
# if !defined(HAVE_NS_TYPE) && defined(NS_INADDRSZ)
#  define HAVE_NS_TYPE
# endif
# include <spf2/spf.h>
# include <spf2/spf_dns_resolv.h>
# include <spf2/spf_dns_cache.h>

#endif


#ifdef EXIM_HAVE_SPF

typedef struct spf_result_id {
  uschar *name;
  int    value;
} spf_result_id;

# define SPF_PROCESS_NORMAL  0
# define SPF_PROCESS_GUESS   1
# define SPF_PROCESS_FALLBACK    2

#endif
