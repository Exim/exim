/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Heiko Schlittermann 2016
 * hs@schlittermann.de
 * Copyright (c) The Exim Maintainers 2022
 * See the file NOTICE for conditions of use and distribution.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "exim.h"

extern char **environ;

/* The cleanup_environment() function is used during the startup phase
of the Exim process, right after reading the configurations main
part, before any expansions take place. It retains the environment
variables we trust (via the keep_environment option) and allows to
set additional variables (via add_environment).

Returns:    TRUE if successful
            FALSE otherwise
*/

BOOL
cleanup_environment()
{
if (!keep_environment || !*keep_environment)
  {
  /* From: https://github.com/dovecot/core/blob/master/src/lib/env-util.c#L55
  Try to clear the environment.
  a) environ = NULL crashes on OS X.
  b) *environ = NULL doesn't work on FreeBSD 7.0.
  c) environ = emptyenv doesn't work on Haiku OS
  d) environ = calloc() should work everywhere */

  if (environ) *environ = NULL;

  }
else if (Ustrcmp(keep_environment, "*") != 0)
  {
  rmark reset_point = store_mark();
  unsigned deb = debug_selector;
  BOOL hc = host_checking;
  debug_selector = 0;			/* quieten this clearout */
  host_checking = FALSE;

  if (environ) for (uschar ** p = USS environ; *p; /* see below */)
    {
    /* It's considered broken if we do not find the '=', according to
    Florian Weimer. For now we ignore such strings. unsetenv() would complain,
    getenv() would complain. */
    uschar * eqp = Ustrchr(*p, '=');

    if (eqp)
      {
      uschar * name = string_copyn(*p, eqp - *p);

      if (match_isinlist(name, CUSS &keep_environment,
          0, NULL, NULL, MCL_NOEXPAND, FALSE, NULL) == OK)
	p++;			/* next */
      else if (os_unsetenv(name) == 0)
	p = USS environ;	/* RESTART from the beginning */
      else
	{ debug_selector = deb; host_checking = hc; return FALSE; }
      }
    }
  debug_selector = deb;
  host_checking = hc;
  store_reset(reset_point);
  }
DEBUG(D_expand)
  {
  debug_printf("environment after trimming:\n");
  if (environ) for (uschar ** p = USS environ; *p; p++)
    debug_printf(" %s\n", *p);
  }
if (add_environment)
  {
  int sep = 0;
  const uschar * envlist = add_environment;
  int old_pool = store_pool;
  store_pool = POOL_PERM;		/* Need perm memory for any created env vars */

  for (const uschar * p; p = string_nextinlist(&envlist, &sep, NULL, 0); )
    {
    DEBUG(D_expand) debug_printf("adding %s\n", p);
    putenv(CS p);
    }
  store_pool = old_pool;
  }
#ifndef DISABLE_TLS
tls_clean_env();
#endif

return TRUE;
}
