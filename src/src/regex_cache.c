/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * Copyright (c) The Exim Maintainers 2022 - 2023
 * License: GPL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Caching layers for compiled REs.  There is a local layer in the process,
implemented as a tree for inserts and lookup.  This cache is inherited from
the daemon, for the process tree deriving from there - but not by re-exec'd
proceses or commandline submission processes.

If the process has to compile, and is not the daemon or a re-exec'd exim,
it notifies the use of the RE to the daemon via a unix-domain socket.
This is a fire-and-forget send with no response, hence cheap from the point-of
view of the sender.  I have not measured the overall comms costs.  The
daemon also compiles the RE, and caches the result.

A second layer would be possible by asking the daemon via the notifier socket
(for a result from its cache, or a compile if it must).  The comms overhead
is significant, not only for the channel but also for de/serialisation of
the compiled object.  This makes it untenable for the primary use-case, the
transport process which has been re-exec'd to gain privs - and therefore does not
have the daemon-maintained cache.  Using shared-memory might reduce that cost
(the attach time for the memory segment will matter); the implimentation
would require suitable R/W locks.
*/

#include "exim.h"

typedef struct re_req {
  uschar	notifier_reqtype;
  BOOL		caseless;
  uschar	re[1];		/* extensible */
} re_req;

static tree_node * regex_cache = NULL;
static tree_node * regex_caseless_cache = NULL;

#define REGEX_CACHESIZE_LIMIT 1000

/******************************************************************************/

static void
regex_to_daemon(const uschar * key, BOOL caseless)
{
int klen = Ustrlen(key) + 1;
int rlen = sizeof(re_req) + klen;
re_req * req;
int fd, old_pool = store_pool;

DEBUG(D_expand|D_lists)
  debug_printf_indent("sending RE '%s' to daemon\n", key);

store_pool = POOL_MAIN;
  req = store_get(rlen, key);	/* maybe need a size limit */
store_pool = old_pool;;
req->notifier_reqtype = NOTIFY_REGEX;
req->caseless = caseless;
memcpy(req->re, key, klen);

if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) >= 0)
  {
  struct sockaddr_un sa_un = {.sun_family = AF_UNIX};
  ssize_t len = daemon_notifier_sockname(&sa_un);

  if (sendto(fd, req, rlen, 0, (struct sockaddr *)&sa_un, (socklen_t)len) < 0)
    DEBUG(D_queue_run)
      debug_printf("%s: sendto %s\n", __FUNCTION__, strerror(errno));
  close(fd);
  }
else DEBUG(D_queue_run) debug_printf(" socket: %s\n", strerror(errno));
}


static const pcre2_code *
regex_from_cache(const uschar * key, BOOL caseless)
{
tree_node * node  =
  tree_search(caseless ? regex_caseless_cache : regex_cache, key);
DEBUG(D_expand|D_lists)
  debug_printf_indent("compiled %sRE '%s' %sfound in local cache\n",
		      caseless ? "caseless " : "", key, node ? "" : "not ");

return node ? node->data.ptr : NULL;
}


static void
regex_to_cache(const uschar * key, BOOL caseless, const pcre2_code * cre)
{

/* we are called with STORE_PERM */
tree_node * node = store_get(sizeof(tree_node) + Ustrlen(key) + 1, key);
Ustrcpy(node->name, key);
node->data.ptr = (void *)cre;

if (!tree_insertnode(caseless ? &regex_caseless_cache : &regex_cache, node))
  { DEBUG(D_expand|D_lists) debug_printf_indent("duplicate key!\n"); }
else DEBUG(D_expand|D_lists)
  debug_printf_indent("compiled RE '%s' saved in local cache\n", key);

/* Additionally, if not re-execed and not the daemon, tell the daemon of the RE
so it can add to the cache */

if (f.daemon_scion && !f.daemon_listen)
  regex_to_daemon(key, caseless);

return;
}

/******************************************************************************/

/*************************************************
*  Compile regular expression and panic on fail  *
*************************************************/

/* This function is called when failure to compile a regular expression leads
to a panic exit. In other cases, pcre_compile() is called directly. In many
cases where this function is used, the results of the compilation are to be
placed in long-lived store, so we temporarily reset the store management
functions that PCRE uses if the use_malloc flag is set.

Argument:
  pattern     the pattern to compile
  flags
   caseless    caseless matching is required
   cacheable   use (writeback) cache
  use_malloc  TRUE if compile into malloc store

Returns:      pointer to the compiled pattern
*/

const pcre2_code *
regex_must_compile(const uschar * pattern, mcs_flags flags, BOOL use_malloc)
{
BOOL caseless = !!(flags & MCS_CASELESS);
size_t offset;
const pcre2_code * yield;
int old_pool = store_pool, err;

/* Optionall, check the cache and return if found */

if (  flags & MCS_CACHEABLE
   && (yield = regex_from_cache(pattern, caseless)))
  return yield;

store_pool = POOL_PERM;

if (!(yield = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
  caseless ? PCRE_COPT|PCRE2_CASELESS : PCRE_COPT,
  &err, &offset, use_malloc ? pcre_mlc_cmp_ctx : pcre_gen_cmp_ctx)))
  {
  uschar errbuf[128];
  pcre2_get_error_message(err, errbuf, sizeof(errbuf));
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "regular expression error: "
    "%s at offset %ld while compiling %s", errbuf, (long)offset, pattern);
  }

if (use_malloc)
  {
  /*pcre2_general_context_free(gctx);*/
  }

if (flags & MCS_CACHEABLE)
  regex_to_cache(pattern, caseless, yield);

store_pool = old_pool;
return yield;
}




/* Wrapper for pcre2_compile() and error-message handling.

Arguments:	pattern		regex to compile
		flags
		 caseless	flag for match variant
		 cacheable	use (writeback) cache
		errstr		on error, filled in with error message
		cctx		compile-context for pcre2

Return:		NULL on error, with errstr set. Otherwise, the compiled RE object
*/

const pcre2_code *
regex_compile(const uschar * pattern, mcs_flags flags, uschar ** errstr,
  pcre2_compile_context * cctx)
{
const uschar * key = pattern;
BOOL caseless = !!(flags & MCS_CASELESS);
int err;
PCRE2_SIZE offset;
const pcre2_code * yield;
int old_pool = store_pool;

/* Optionally, check the cache and return if found */

if (  flags & MCS_CACHEABLE
   && (yield = regex_from_cache(key, caseless)))
  return yield;

DEBUG(D_expand|D_lists) debug_printf_indent("compiling %sRE '%s'\n",
				caseless ? "caseless " : "", pattern);

store_pool = POOL_PERM;
if (!(yield = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
		caseless ? PCRE_COPT|PCRE2_CASELESS : PCRE_COPT,
		&err, &offset, cctx)))
  {
  uschar errbuf[128];
  pcre2_get_error_message(err, errbuf, sizeof(errbuf));
  store_pool = old_pool;
  *errstr = string_sprintf("regular expression error in "
	    "\"%s\": %s at offset %ld", pattern, errbuf, (long)offset);
  }
else if (flags & MCS_CACHEABLE)
  regex_to_cache(key, caseless, yield);
store_pool = old_pool;

return yield;
}



/* Handle a regex notify arriving at the daemon.  We get sent the original RE;
compile it (again) and write to the cache.  Later forked procs will be able to
read from the cache, unless they re-execed.  Therefore, those latter never bother
sending us a notification. */

void
regex_at_daemon(const uschar * reqbuf)
{
const re_req * req = (const re_req *)reqbuf;
uschar * errstr;
const pcre2_code * cre = NULL;

if (regex_cachesize >= REGEX_CACHESIZE_LIMIT)
  errstr = US"regex cache size limit reached";
else if ((cre = regex_compile(req->re,
	    req->caseless ? MCS_CASELESS | MCS_CACHEABLE : MCS_CACHEABLE,
	    &errstr, pcre_gen_cmp_ctx)))
  regex_cachesize++;

DEBUG(D_any) if (!cre) debug_printf("%s\n", errstr);
return;
}
