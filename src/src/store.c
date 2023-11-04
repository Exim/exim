/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim maintainers 2019 - 2023 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Exim gets and frees all its store through these functions. In the original
implementation there was a lot of mallocing and freeing of small bits of store.
The philosophy has now changed to a scheme which includes the concept of
"stacking pools" of store. For the short-lived processes, there isn't any real
need to do any garbage collection, but the stack concept allows quick resetting
in places where this seems sensible.

Obviously the long-running processes (the daemon, the queue runner, and eximon)
must take care not to eat store.

The following different types of store are recognized:

. Long-lived, large blocks: This is implemented by retaining the original
  malloc/free functions, and it used for permanent working buffers and for
  getting blocks to cut up for the other types.

. Long-lived, small blocks: This is used for blocks that have to survive until
  the process exits. It is implemented as a stacking pool (POOL_PERM). This is
  functionally the same as store_malloc(), except that the store can't be
  freed, but I expect it to be more efficient for handling small blocks.

. Short-lived, short blocks: Most of the dynamic store falls into this
  category. It is implemented as a stacking pool (POOL_MAIN) which is reset
  after accepting a message when multiple messages are received by a single
  process. Resetting happens at some other times as well, usually fairly
  locally after some specific processing that needs working store.

. There is a separate pool (POOL_SEARCH) that is used only for lookup storage.
  This means it can be freed when search_tidyup() is called to close down all
  the lookup caching.

- There is another pool (POOL_MESSAGE) used for medium-lifetime objects; within
  a single message transaction but needed for longer than the use of the main
  pool permits.  Currently this means only receive-time DKIM information.

- There is a dedicated pool for configuration data read from the config file(s).
  Once complete, it is made readonly.

- There are pools for each active combination of lookup-quoting, dynamically created.

. Orthogonal to the four main pool types, there are two classes of memory: untainted
  and tainted.  The latter is used for values derived from untrusted input, and
  the string-expansion mechanism refuses to operate on such values (obviously,
  it can expand an untainted value to return a tainted result).  The classes
  are implemented by duplicating the four pool types.  Pool resets are requested
  against the nontainted sibling and apply to both siblings.

  Only memory blocks requested for tainted use are regarded as tainted; anything
  else (including stack auto variables) is untainted.  Care is needed when coding
  to not copy untrusted data into untainted memory, as downstream taint-checks
  would be avoided.

  Intermediate layers (eg. the string functions) can test for taint, and use this
  for ensurinng that results have proper state.  For example the
  string_vformat_trc() routing supporting the string_sprintf() interface will
  recopy a string being built into a tainted allocation if it meets a %s for a
  tainted argument.  Any intermediate-layer function that (can) return a new
  allocation should behave this way; returning a tainted result if any tainted
  content is used.  Intermediate-layer functions (eg. Ustrncpy) that modify
  existing allocations fail if tainted data is written into an untainted area.
  Users of functions that modify existing allocations should check if a tainted
  source and an untainted destination is used, and fail instead (sprintf() being
  the classic case).
*/


#include "exim.h"
/* keep config.h before memcheck.h, for NVALGRIND */
#include "config.h"

#include <sys/mman.h>
#include "memcheck.h"


/* We need to know how to align blocks of data for general use. I'm not sure
how to get an alignment factor in general. In the current world, a value of 8
is probably right, and this is sizeof(double) on some systems and sizeof(void
*) on others, so take the larger of those. Since everything in this expression
is a constant, the compiler should optimize it to a simple constant wherever it
appears (I checked that gcc does do this). */

#define alignment \
  (sizeof(void *) > sizeof(double) ? sizeof(void *) : sizeof(double))

/* store_reset() will not free the following block if the last used block has
less than this much left in it. */

#define STOREPOOL_MIN_SIZE 256

/* Structure describing the beginning of each big block. */

typedef struct storeblock {
  struct storeblock *next;
  size_t length;
} storeblock;

/* Pool descriptor struct */

typedef struct pooldesc {
  storeblock *	chainbase;		/* list of blocks in pool */
  storeblock *	current_block;		/* top block, still with free space */
  void *	next_yield;		/* next allocation point */
  int		yield_length;		/* remaining space in current block */
  unsigned	store_block_order;	/* log2(size) block allocation size */

  /* This variable is set by store_get() to its yield, and by store_reset() to
  NULL. This enables string_cat() to optimize its store handling for very long
  strings. That's why the variable is global. */

  void *	store_last_get;

  /* These are purely for stats-gathering */

  int		nbytes;
  int		maxbytes;
  int		nblocks;
  int		maxblocks;
  unsigned	maxorder;
} pooldesc;

/* Enhanced pool descriptor for quoted pools */

typedef struct quoted_pooldesc {
  pooldesc			pool;
  unsigned			quoter;
  struct quoted_pooldesc *	next;
} quoted_pooldesc;

/* Just in case we find ourselves on a system where the structure above has a
length that is not a multiple of the alignment, set up a macro for the padded
length. */

#define ALIGNED_SIZEOF_STOREBLOCK \
  (((sizeof(storeblock) + alignment - 1) / alignment) * alignment)

/* Size of block to get from malloc to carve up into smaller ones. This
must be a multiple of the alignment. We assume that 4096 is going to be
suitably aligned.  Double the size per-pool for every malloc, to mitigate
certain denial-of-service attacks.  Don't bother to decrease on block frees.
We waste average half the current alloc size per pool.  This could be several
hundred kB now, vs. 4kB with a constant-size block size.  But the search time
for is_tainted(), linear in the number of blocks for the pool, is O(n log n)
rather than O(n^2).
A test of 2000 RCPTs and just accept ACL had 370kB in 21 blocks before,
504kB in 6 blocks now, for the untainted-main (largest) pool.
Builds for restricted-memory system can disable the expansion by
defining RESTRICTED_MEMORY */
/*XXX should we allow any for malloc's own overhead?  But how much? */

/* #define RESTRICTED_MEMORY */
#define STORE_BLOCK_SIZE(order) ((1U << (order)) - ALIGNED_SIZEOF_STOREBLOCK)

/* Variables holding data for the local pools of store. The current pool number
is held in store_pool, which is global so that it can be changed from outside.
Setting the initial length values to -1 forces a malloc for the first call,
even if the length is zero (which is used for getting a point to reset to). */

int store_pool = POOL_MAIN;

pooldesc paired_pools[N_PAIRED_POOLS];
quoted_pooldesc * quoted_pools = NULL;

static int n_nonpool_blocks;	/* current number of direct store_malloc() blocks */
static int max_nonpool_blocks;
static int max_pool_malloc;	/* max value for pool_malloc */
static int max_nonpool_malloc;	/* max value for nonpool_malloc */

/* pool_malloc holds the amount of memory used by the store pools; this goes up
and down as store is reset or released. nonpool_malloc is the total got by
malloc from other calls; this doesn't go down because it is just freed by
pointer. */

static int pool_malloc;
static int nonpool_malloc;


#ifndef COMPILE_UTILITY
static const uschar * pooluse[N_PAIRED_POOLS] = {
[POOL_MAIN] =		US"main",
[POOL_PERM] =		US"perm",
[POOL_CONFIG] =		US"config",
[POOL_SEARCH] =		US"search",
[POOL_MESSAGE] =	US"message",
[POOL_TAINT_MAIN] =	US"main",
[POOL_TAINT_PERM] =	US"perm",
[POOL_TAINT_CONFIG] =	US"config",
[POOL_TAINT_SEARCH] =	US"search",
[POOL_TAINT_MESSAGE] =	US"message",
};
static const uschar * poolclass[N_PAIRED_POOLS] = {
[POOL_MAIN] =		US"untainted",
[POOL_PERM] =		US"untainted",
[POOL_CONFIG] =		US"untainted",
[POOL_SEARCH] =		US"untainted",
[POOL_MESSAGE] =	US"untainted",
[POOL_TAINT_MAIN] =	US"tainted",
[POOL_TAINT_PERM] =	US"tainted",
[POOL_TAINT_CONFIG] =	US"tainted",
[POOL_TAINT_SEARCH] =	US"tainted",
[POOL_TAINT_MESSAGE] =	US"tainted",
};
#endif


static void * internal_store_malloc(size_t, const char *, int);
static void   internal_store_free(void *, const char *, int linenumber);

/******************************************************************************/

static void
pool_init(pooldesc * pp)
{
memset(pp, 0, sizeof(*pp));
pp->yield_length = -1;
pp->store_block_order = 12; /* log2(allocation_size) ie. 4kB */
}

/* Initialisation, for things fragile with parameter channges when using
static initialisers. */

void
store_init(void)
{
for (pooldesc * pp = paired_pools; pp < paired_pools + N_PAIRED_POOLS; pp++)
  pool_init(pp);
}

/******************************************************************************/
/* Locating elements given memory pointer */

static BOOL
is_pointer_in_block(const storeblock * b, const void * p)
{
uschar * bc = US b + ALIGNED_SIZEOF_STOREBLOCK;
return US p >= bc && US p < bc + b->length;
}

static pooldesc *
pool_current_for_pointer(const void * p)
{
storeblock * b;

for (quoted_pooldesc * qp = quoted_pools; qp; qp = qp->next)
  if ((b = qp->pool.current_block) && is_pointer_in_block(b, p))
    return &qp->pool;

for (pooldesc * pp = paired_pools; pp < paired_pools + N_PAIRED_POOLS; pp++)
  if ((b = pp->current_block) && is_pointer_in_block(b, p))
    return pp;
return NULL;
}

static pooldesc *
pool_for_pointer(const void * p, const char * func, int linenumber)
{
pooldesc * pp;
storeblock * b;

if ((pp = pool_current_for_pointer(p))) return pp;

for (quoted_pooldesc * qp = quoted_pools; qp; qp = qp->next)
  for (b = qp->pool.chainbase; b; b = b->next)
    if (is_pointer_in_block(b, p)) return &qp->pool;

for (pp = paired_pools; pp < paired_pools + N_PAIRED_POOLS; pp++)
  for (b = pp->chainbase; b; b = b->next)
    if (is_pointer_in_block(b, p)) return pp;

#ifndef COMPILE_UTILITY
stackdump();
#endif
log_write(0, LOG_MAIN|LOG_PANIC_DIE,
  "bad memory reference; pool not found, at %s %d", func, linenumber);
return NULL;
}

/******************************************************************************/
/* Test if a pointer refers to tainted memory.

Slower version check, for use when platform intermixes malloc and mmap area
addresses. Test against the current-block of all tainted pools first, then all
blocks of all tainted pools.

Return: TRUE iff tainted
*/

BOOL
is_tainted_fn(const void * p)
{
storeblock * b;

if (p == GET_UNTAINTED) return FALSE;
if (p == GET_TAINTED) return TRUE;

for (pooldesc * pp = paired_pools + POOL_TAINT_BASE;
     pp < paired_pools + N_PAIRED_POOLS; pp++)
  if ((b = pp->current_block))
    if (is_pointer_in_block(b, p)) return TRUE;

for (quoted_pooldesc * qp = quoted_pools; qp; qp = qp->next)
  if (b = qp->pool.current_block)
    if (is_pointer_in_block(b, p)) return TRUE;

for (pooldesc * pp = paired_pools + POOL_TAINT_BASE;
     pp < paired_pools + N_PAIRED_POOLS; pp++)
  for (b = pp->chainbase; b; b = b->next)
    if (is_pointer_in_block(b, p)) return TRUE;

for (quoted_pooldesc * qp = quoted_pools; qp; qp = qp->next)
  for (b = qp->pool.chainbase; b; b = b->next)
    if (is_pointer_in_block(b, p)) return TRUE;

return FALSE;
}


void
die_tainted(const uschar * msg, const uschar * func, int line)
{
log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Taint mismatch, %s: %s %d\n",
	msg, func, line);
}


#ifndef COMPILE_UTILITY
/* Return the pool for the given quoter, or null */

static pooldesc *
pool_for_quoter(unsigned quoter)
{
for (quoted_pooldesc * qp = quoted_pools; qp; qp = qp->next)
  if (qp->quoter == quoter)
    return &qp->pool;
return NULL;
}

/* Allocate/init a new quoted-pool and return the pool */

static pooldesc *
quoted_pool_new(unsigned quoter)
{
// debug_printf("allocating quoted-pool\n");
quoted_pooldesc * qp = store_get_perm(sizeof(quoted_pooldesc), GET_UNTAINTED);

pool_init(&qp->pool);
qp->quoter = quoter;
qp->next = quoted_pools;
quoted_pools = qp;
return &qp->pool;
}
#endif


/******************************************************************************/
void
store_writeprotect(int pool)
{
#if !defined(COMPILE_UTILITY) && !defined(MISSING_POSIX_MEMALIGN)
for (storeblock * b =  paired_pools[pool].chainbase; b; b = b->next)
  if (mprotect(b, ALIGNED_SIZEOF_STOREBLOCK + b->length, PROT_READ) != 0)
    DEBUG(D_any) debug_printf("config block mprotect: (%d) %s\n", errno, strerror(errno));
#endif
}

/******************************************************************************/

static void *
pool_get(pooldesc * pp, int size, BOOL align_mem, const char * func, int linenumber)
{
/* Ensure we've been asked to allocate memory.
A negative size is a sign of a security problem.
A zero size might be also suspect, but our internal usage deliberately
does this to return a current watermark value for a later release of
allocated store. */

if (size < 0 || size >= INT_MAX/2)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
            "bad memory allocation requested (%d bytes) from %s %d",
            size, func, linenumber);

/* Round up the size to a multiple of the alignment. Although this looks a
messy statement, because "alignment" is a constant expression, the compiler can
do a reasonable job of optimizing, especially if the value of "alignment" is a
power of two. I checked this with -O2, and gcc did very well, compiling it to 4
instructions on a Sparc (alignment = 8). */

if (size % alignment != 0) size += alignment - (size % alignment);

/* If there isn't room in the current block, get a new one. The minimum
size is STORE_BLOCK_SIZE, and we would expect this to be the norm, since
these functions are mostly called for small amounts of store. */

if (size > pp->yield_length)
  {
  int length = MAX(
	  STORE_BLOCK_SIZE(pp->store_block_order) - ALIGNED_SIZEOF_STOREBLOCK,
	  size);
  int mlength = length + ALIGNED_SIZEOF_STOREBLOCK;
  storeblock * newblock;

  /* Sometimes store_reset() may leave a block for us; check if we can use it */

  if (  (newblock = pp->current_block)
     && (newblock = newblock->next)
     && newblock->length < length
     )
    {
    /* Give up on this block, because it's too small */
    pp->nblocks--;
    internal_store_free(newblock, func, linenumber);
    newblock = NULL;
    }

  /* If there was no free block, get a new one */

  if (!newblock)
    {
    if ((pp->nbytes += mlength) > pp->maxbytes)
      pp->maxbytes = pp->nbytes;
    if ((pool_malloc += mlength) > max_pool_malloc)	/* Used in pools */
      max_pool_malloc = pool_malloc;
    nonpool_malloc -= mlength;			/* Exclude from overall total */
    if (++pp->nblocks > pp->maxblocks)
      pp->maxblocks = pp->nblocks;

#ifndef MISSING_POSIX_MEMALIGN
    if (align_mem)
      {
      long pgsize = sysconf(_SC_PAGESIZE);
      int err = posix_memalign((void **)&newblock,
				pgsize, (mlength + pgsize - 1) & ~(pgsize - 1));
      if (err)
	log_write(0, LOG_MAIN|LOG_PANIC_DIE,
	  "failed to alloc (using posix_memalign) %d bytes of memory: '%s'"
	  "called from line %d in %s",
	  size, strerror(err), linenumber, func);
      }
    else
#endif
      newblock = internal_store_malloc(mlength, func, linenumber);
    newblock->next = NULL;
    newblock->length = length;
#ifndef RESTRICTED_MEMORY
    if (pp->store_block_order++ > pp->maxorder)
      pp->maxorder = pp->store_block_order;
#endif

    if (! pp->chainbase)
       pp->chainbase = newblock;
    else
      pp->current_block->next = newblock;
    }

  pp->current_block = newblock;
  pp->yield_length = newblock->length;
  pp->next_yield =
    (void *)(CS pp->current_block + ALIGNED_SIZEOF_STOREBLOCK);
  (void) VALGRIND_MAKE_MEM_NOACCESS(pp->next_yield, pp->yield_length);
  }

/* There's (now) enough room in the current block; the yield is the next
pointer. */

pp->store_last_get = pp->next_yield;

(void) VALGRIND_MAKE_MEM_UNDEFINED(pp->store_last_get, size);
/* Update next pointer and number of bytes left in the current block. */

pp->next_yield = (void *)(CS pp->next_yield + size);
pp->yield_length -= size;
return pp->store_last_get;
}

/*************************************************
*       Get a block from the current pool        *
*************************************************/

/* Running out of store is a total disaster. This function is called via the
macro store_get(). The current store_pool is used, adjusting for taint.
If the protoype is quoted, use a quoted-pool.
Return a block of store within the current big block of the pool, getting a new
one if necessary. The address is saved in store_last_get for the pool.

Arguments:
  size        amount wanted, bytes
  proto_mem   class: get store conformant to this
		Special values: 0 forces untainted, 1 forces tainted
  func        function from which called
  linenumber  line number in source file

Returns:      pointer to store (panic on malloc failure)
*/

void *
store_get_3(int size, const void * proto_mem, const char * func, int linenumber)
{
#ifndef COMPILE_UTILITY
int quoter = quoter_for_address(proto_mem);
#endif
pooldesc * pp;
void * yield;

#ifndef COMPILE_UTILITY
if (!is_real_quoter(quoter))
#endif
  {
  BOOL tainted = is_tainted(proto_mem);
  int pool = tainted ? store_pool + POOL_TAINT_BASE : store_pool;
  pp = paired_pools + pool;
  yield = pool_get(pp, size, (pool == POOL_CONFIG), func, linenumber);

  /* Cut out the debugging stuff for utilities, but stop picky compilers from
  giving warnings. */

#ifndef COMPILE_UTILITY
  DEBUG(D_memory)
    debug_printf("---%d Get %6p %5d %-14s %4d\n", pool,
      pp->store_last_get, size, func, linenumber);
#endif
  }
#ifndef COMPILE_UTILITY
else
  {
  DEBUG(D_memory)
    debug_printf("allocating quoted-block for quoter %u (from %s %d)\n",
      quoter, func, linenumber);
  if (!(pp = pool_for_quoter(quoter))) pp = quoted_pool_new(quoter);
  yield = pool_get(pp, size, FALSE, func, linenumber);
  DEBUG(D_memory)
    debug_printf("---QQ Get %6p %5d %-14s %4d\n",
      pp->store_last_get, size, func, linenumber);
  }
#endif
return yield;
}



/*************************************************
*       Get a block from the PERM pool           *
*************************************************/

/* This is just a convenience function, useful when just a single block is to
be obtained.

Arguments:
  size        amount wanted
  proto_mem   class: get store conformant to this
  func        function from which called
  linenumber  line number in source file

Returns:      pointer to store (panic on malloc failure)
*/

void *
store_get_perm_3(int size, const void * proto_mem, const char * func, int linenumber)
{
void * yield;
int old_pool = store_pool;
store_pool = POOL_PERM;
yield = store_get_3(size, proto_mem, func, linenumber);
store_pool = old_pool;
return yield;
}


#ifndef COMPILE_UTILITY
/*************************************************
*  Get a block annotated as being lookup-quoted  *
*************************************************/

/* Allocate from pool a pool consistent with the proto_mem augmented by the
requested quoter type.

XXX currently not handling mark/release

Args:	size		number of bytes to allocate
	quoter		id for the quoting type
	func		caller, for debug
	linenumber	caller, for debug

Return:	allocated memory block
*/

static void *
store_force_get_quoted(int size, unsigned quoter,
  const char * func, int linenumber)
{
pooldesc * pp = pool_for_quoter(quoter);
void * yield;

DEBUG(D_memory)
  debug_printf("allocating quoted-block for quoter %u (from %s %d)\n", quoter, func, linenumber);

if (!pp) pp = quoted_pool_new(quoter);
yield = pool_get(pp, size, FALSE, func, linenumber);

DEBUG(D_memory)
  debug_printf("---QQ Get %6p %5d %-14s %4d\n",
    pp->store_last_get, size, func, linenumber);

return yield;
}

/* Maybe get memory for the specified quoter, but only if the
prototype memory is tainted. Otherwise, get plain memory.
*/
void *
store_get_quoted_3(int size, const void * proto_mem, unsigned quoter,
  const char * func, int linenumber)
{
// debug_printf("store_get_quoted_3: quoter %u\n", quoter);
return is_tainted(proto_mem)
  ? store_force_get_quoted(size, quoter, func, linenumber)
  : store_get_3(size, proto_mem, func, linenumber);
}

/* Return quoter for given address, or -1 if not in a quoted-pool. */
int
quoter_for_address(const void * p)
{
for (quoted_pooldesc * qp = quoted_pools; qp; qp = qp->next)
  {
  pooldesc * pp = &qp->pool;
  storeblock * b;

  if (b = pp->current_block)
    if (is_pointer_in_block(b, p))
      return qp->quoter;

  for (b = pp->chainbase; b; b = b->next)
    if (is_pointer_in_block(b, p))
      return qp->quoter;
  }
return -1;
}

/* Return TRUE iff the given address is quoted for the given type.
There is extra complexity to handle lookup providers with multiple
find variants but shared quote functions. */
BOOL
is_quoted_like(const void * p, unsigned quoter)
{
int pq = quoter_for_address(p);
BOOL y =
  is_real_quoter(pq) && lookup_list[pq]->quote == lookup_list[quoter]->quote;
/* debug_printf("is_quoted(%p, %u): %c\n", p, quoter, y?'T':'F'); */
return y;
}

/* Return TRUE if the quoter value indicates an actual quoter */
BOOL
is_real_quoter(int quoter)
{
return quoter >= 0;
}

/* Return TRUE if the "new" data requires that the "old" data
be recopied to new-class memory.  We order the classes as

  2: tainted, not quoted
  1: quoted (which is also tainted)
  0: untainted

If the "new" is higher-order than the "old", they are not compatible
and a copy is needed.  If both are quoted, but the quoters differ,
not compatible.  Otherwise they are compatible.
*/
BOOL
is_incompatible_fn(const void * old, const void * new)
{
int oq, nq;
unsigned oi, ni;

ni = is_real_quoter(nq = quoter_for_address(new)) ? 1 : is_tainted(new) ? 2 : 0;
oi = is_real_quoter(oq = quoter_for_address(old)) ? 1 : is_tainted(old) ? 2 : 0;
return ni > oi || ni == oi && nq != oq;
}

#endif	/*!COMPILE_UTILITY*/

/*************************************************
*      Extend a block if it is at the top        *
*************************************************/

/* While reading strings of unknown length, it is often the case that the
string is being read into the block at the top of the stack. If it needs to be
extended, it is more efficient just to extend within the top block rather than
allocate a new block and then have to copy the data. This function is provided
for the use of string_cat(), but of course can be used elsewhere too.
The block itself is not expanded; only the top allocation from it.

Arguments:
  ptr        pointer to store block
  oldsize    current size of the block, as requested by user
  newsize    new size required
  func       function from which called
  linenumber line number in source file

Returns:     TRUE if the block is at the top of the stack and has been
             extended; FALSE if it isn't at the top of the stack, or cannot
             be extended

XXX needs extension for quoted-tracking.  This assumes that the global store_pool
is the one to alloc from, which breaks with separated pools.
*/

BOOL
store_extend_3(void * ptr, int oldsize, int newsize,
   const char * func, int linenumber)
{
pooldesc * pp = pool_for_pointer(ptr, func, linenumber);
int inc = newsize - oldsize;
int rounded_oldsize = oldsize;

if (oldsize < 0 || newsize < oldsize || newsize >= INT_MAX/2)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
            "bad memory extension requested (%d -> %d bytes) at %s %d",
            oldsize, newsize, func, linenumber);

if (rounded_oldsize % alignment != 0)
  rounded_oldsize += alignment - (rounded_oldsize % alignment);

if (CS ptr + rounded_oldsize != CS (pp->next_yield) ||
    inc > pp->yield_length + rounded_oldsize - oldsize)
  return FALSE;

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifndef COMPILE_UTILITY
DEBUG(D_memory)
  {
  quoted_pooldesc * qp;
  for (qp = quoted_pools; qp; qp = qp->next)
    if (pp == &qp->pool)
      {
      debug_printf("---Q%d Ext %6p %5d %-14s %4d\n",
	(int)(qp - quoted_pools),
	ptr, newsize, func, linenumber);
      break;
      }
  if (!qp)
    debug_printf("---%d Ext %6p %5d %-14s %4d\n",
      (int)(pp - paired_pools),
      ptr, newsize, func, linenumber);
  }
#endif  /* COMPILE_UTILITY */

if (newsize % alignment != 0) newsize += alignment - (newsize % alignment);
pp->next_yield = CS ptr + newsize;
pp->yield_length -= newsize - rounded_oldsize;
(void) VALGRIND_MAKE_MEM_UNDEFINED(ptr + oldsize, inc);
return TRUE;
}




static BOOL
is_pwr2_size(int len)
{
unsigned x = len;
return (x & (x - 1)) == 0;
}


/*************************************************
*    Back up to a previous point on the stack    *
*************************************************/

/* This function resets the next pointer, freeing any subsequent whole blocks
that are now unused. Call with a cookie obtained from store_mark() only; do
not call with a pointer returned by store_get().  Both the untainted and tainted
pools corresposding to store_pool are reset.

Quoted pools are not handled.

Arguments:
  ptr         place to back up to
  pool	      pool holding the pointer
  func        function from which called
  linenumber  line number in source file

Returns:      nothing
*/

static void
internal_store_reset(void * ptr, int pool, const char *func, int linenumber)
{
storeblock * bb;
pooldesc * pp = paired_pools + pool;
storeblock * b = pp->current_block;
char * bc = CS b + ALIGNED_SIZEOF_STOREBLOCK;
int newlength, count;
#ifndef COMPILE_UTILITY
int oldmalloc = pool_malloc;
#endif

if (!b) return;	/* exim_dumpdb gets this, becuse it has never used tainted mem */

/* Last store operation was not a get */

pp->store_last_get = NULL;

/* See if the place is in the current block - as it often will be. Otherwise,
search for the block in which it lies. */

if (CS ptr < bc || CS ptr > bc + b->length)
  {
  for (b =  pp->chainbase; b; b = b->next)
    {
    bc = CS b + ALIGNED_SIZEOF_STOREBLOCK;
    if (CS ptr >= bc && CS ptr <= bc + b->length) break;
    }
  if (!b)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "internal error: store_reset(%p) "
      "failed: pool=%d %-14s %4d", ptr, pool, func, linenumber);
  }

/* Back up, rounding to the alignment if necessary. When testing, flatten
the released memory. */

newlength = bc + b->length - CS ptr;
#ifndef COMPILE_UTILITY
if (debug_store)
  {
  assert_no_variables(ptr, newlength, func, linenumber);
  if (f.running_in_test_harness)
    {
    (void) VALGRIND_MAKE_MEM_DEFINED(ptr, newlength);
    memset(ptr, 0xF0, newlength);
    }
  }
#endif
(void) VALGRIND_MAKE_MEM_NOACCESS(ptr, newlength);
pp->next_yield = CS ptr + (newlength % alignment);
count = pp->yield_length;
count = (pp->yield_length = newlength - (newlength % alignment)) - count;
pp->current_block = b;

/* Free any subsequent block. Do NOT free the first
successor, if our current block has less than 256 bytes left. This should
prevent us from flapping memory. However, keep this block only when it has
a power-of-two size so probably is not a custom inflated one. */

if (  pp->yield_length < STOREPOOL_MIN_SIZE
   && b->next
   && is_pwr2_size(b->next->length + ALIGNED_SIZEOF_STOREBLOCK))
  {
  b = b->next;
#ifndef COMPILE_UTILITY
  if (debug_store)
    assert_no_variables(b, b->length + ALIGNED_SIZEOF_STOREBLOCK,
			func, linenumber);
#endif
  (void) VALGRIND_MAKE_MEM_NOACCESS(CS b + ALIGNED_SIZEOF_STOREBLOCK,
		b->length - ALIGNED_SIZEOF_STOREBLOCK);
  }

bb = b->next;
if (pool != POOL_CONFIG)
  b->next = NULL;

while ((b = bb))
  {
  int siz = b->length + ALIGNED_SIZEOF_STOREBLOCK;

#ifndef COMPILE_UTILITY
  if (debug_store)
    assert_no_variables(b, b->length + ALIGNED_SIZEOF_STOREBLOCK,
			func, linenumber);
#endif
  bb = bb->next;
  pp->nbytes -= siz;
  pool_malloc -= siz;
  pp->nblocks--;
  if (pool != POOL_CONFIG)
    internal_store_free(b, func, linenumber);

#ifndef RESTRICTED_MEMORY
  if (pp->store_block_order > 13) pp->store_block_order--;
#endif
  }

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifndef COMPILE_UTILITY
DEBUG(D_memory)
  debug_printf("---%d Rst %6p %5d %-14s %4d\tpool %d\n", pool, ptr,
    count + oldmalloc - pool_malloc,
    func, linenumber, pool_malloc);
#endif  /* COMPILE_UTILITY */
}


/* Back up the pool pair, untainted and tainted, of the store_pool setting.
Quoted pools are not handled.
*/

rmark
store_reset_3(rmark r, const char * func, int linenumber)
{
void ** ptr = r;

if (store_pool >= POOL_TAINT_BASE)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "store_reset called for pool %d: %s %d\n", store_pool, func, linenumber);
if (!r)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "store_reset called with bad mark: %s %d\n", func, linenumber);

internal_store_reset(*ptr, store_pool + POOL_TAINT_BASE, func, linenumber);
internal_store_reset(ptr,  store_pool,		   func, linenumber);
return NULL;
}


/**************/

/* Free tail-end unused allocation.  This lets us allocate a big chunk
early, for cases when we only discover later how much was really needed.

Can be called with a value from store_get(), or an offset after such.  Only
the tainted or untainted pool that serviced the store_get() will be affected.

This is mostly a cut-down version of internal_store_reset().
XXX needs rationalising
*/

void
store_release_above_3(void * ptr, const char * func, int linenumber)
{
pooldesc * pp;

/* Search all pools' "current" blocks.  If it isn't one of those,
ignore it (it usually will be). */

if ((pp = pool_current_for_pointer(ptr)))
  {
  storeblock * b = pp->current_block;
  int count, newlength;

  /* Last store operation was not a get */

  pp->store_last_get = NULL;

  /* Back up, rounding to the alignment if necessary. When testing, flatten
  the released memory. */

  newlength = (CS b + ALIGNED_SIZEOF_STOREBLOCK) + b->length - CS ptr;
#ifndef COMPILE_UTILITY
  if (debug_store)
    {
    assert_no_variables(ptr, newlength, func, linenumber);
    if (f.running_in_test_harness)
      {
      (void) VALGRIND_MAKE_MEM_DEFINED(ptr, newlength);
      memset(ptr, 0xF0, newlength);
      }
    }
#endif
  (void) VALGRIND_MAKE_MEM_NOACCESS(ptr, newlength);
  pp->next_yield = CS ptr + (newlength % alignment);
  count = pp->yield_length;
  count = (pp->yield_length = newlength - (newlength % alignment)) - count;

  /* Cut out the debugging stuff for utilities, but stop picky compilers from
  giving warnings. */

#ifndef COMPILE_UTILITY
  DEBUG(D_memory)
    {
    quoted_pooldesc * qp;
    for (qp = quoted_pools; qp; qp = qp->next)
      if (pp == &qp->pool)
	debug_printf("---Q%d Rel %6p %5d %-14s %4d\tpool %d\n",
	  (int)(qp - quoted_pools),
	  ptr, count, func, linenumber, pool_malloc);
    if (!qp)
      debug_printf("---%d Rel %6p %5d %-14s %4d\tpool %d\n",
	(int)(pp - paired_pools), ptr, count,
	func, linenumber, pool_malloc);
    }
#endif
  return;
  }
#ifndef COMPILE_UTILITY
DEBUG(D_memory)
  debug_printf("non-last memory release try: %s %d\n", func, linenumber);
#endif
}



rmark
store_mark_3(const char * func, int linenumber)
{
void ** p;

#ifndef COMPILE_UTILITY
DEBUG(D_memory)
  debug_printf("---%d Mrk                    %-14s %4d\tpool %d\n",
    store_pool, func, linenumber, pool_malloc);
#endif  /* COMPILE_UTILITY */

if (store_pool >= POOL_TAINT_BASE)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "store_mark called for pool %d: %s %d\n", store_pool, func, linenumber);

/* Stash a mark for the tainted-twin release, in the untainted twin. Return
a cookie (actually the address in the untainted pool) to the caller.
Reset uses the cookie to recover the t-mark, winds back the tainted pool with it
and winds back the untainted pool with the cookie. */

p = store_get_3(sizeof(void *), GET_UNTAINTED, func, linenumber);
*p = store_get_3(0, GET_TAINTED, func, linenumber);
return p;
}




/************************************************
*             Release store                     *
************************************************/

/* This function checks that the pointer it is given is the first thing in a
block, and if so, releases that block.

Arguments:
  block       block of store to consider
  pp	      pool containing the block
  func        function from which called
  linenumber  line number in source file

Returns:      nothing
*/

static void
store_release_3(void * block, pooldesc * pp, const char * func, int linenumber)
{
/* It will never be the first block, so no need to check that. */

for (storeblock * b =  pp->chainbase; b; b = b->next)
  {
  storeblock * bb = b->next;
  if (bb && CS block == CS bb + ALIGNED_SIZEOF_STOREBLOCK)
    {
    int siz = bb->length + ALIGNED_SIZEOF_STOREBLOCK;
    b->next = bb->next;
    pp->nbytes -= siz;
    pool_malloc -= siz;
    pp->nblocks--;

    /* Cut out the debugging stuff for utilities, but stop picky compilers
    from giving warnings. */

#ifndef COMPILE_UTILITY
    DEBUG(D_memory)
      debug_printf("-Release %6p %-20s %4d %d\n", (void *)bb, func,
	linenumber, pool_malloc);

    if (f.running_in_test_harness)
      memset(bb, 0xF0, bb->length+ALIGNED_SIZEOF_STOREBLOCK);
#endif  /* COMPILE_UTILITY */

    internal_store_free(bb, func, linenumber);
    return;
    }
  }
}


/************************************************
*             Move store                        *
************************************************/

/* Allocate a new block big enough to expend to the given size and
copy the current data into it.  Free the old one if possible.

This function is specifically provided for use when reading very
long strings, e.g. header lines. When the string gets longer than a
complete block, it gets copied to a new block. It is helpful to free
the old block iff the previous copy of the string is at its start,
and therefore the only thing in it. Otherwise, for very long strings,
dead store can pile up somewhat disastrously. This function checks that
the pointer it is given is the first thing in a block, and that nothing
has been allocated since. If so, releases that block.

Arguments:
  oldblock
  newsize	requested size
  len		current size

Returns:	new location of data
*/

void *
store_newblock_3(void * oldblock, int newsize, int len,
  const char * func, int linenumber)
{
pooldesc * pp = pool_for_pointer(oldblock, func, linenumber);
BOOL release_ok = !is_tainted(oldblock) && pp->store_last_get == oldblock;		/*XXX why tainted not handled? */
uschar * newblock;

if (len < 0 || len > newsize)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
            "bad memory extension requested (%d -> %d bytes) at %s %d",
            len, newsize, func, linenumber);

newblock = store_get(newsize, oldblock);
memcpy(newblock, oldblock, len);
if (release_ok) store_release_3(oldblock, pp, func, linenumber);
return (void *)newblock;
}




/*************************************************
*                Malloc store                    *
*************************************************/

/* Running out of store is a total disaster for exim. Some malloc functions
do not run happily on very small sizes, nor do they document this fact. This
function is called via the macro store_malloc().

Arguments:
  size        amount of store wanted
  func        function from which called
  line	      line number in source file

Returns:      pointer to gotten store (panic on failure)
*/

static void *
internal_store_malloc(size_t size, const char *func, int line)
{
void * yield;

/* Check specifically for a possibly result of conversion from
a negative int, to the (unsigned, wider) size_t */

if (size >= INT_MAX/2)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "bad internal_store_malloc request (" SIZE_T_FMT " bytes) from %s %d",
    size, func, line);

size += sizeof(size_t);	/* space to store the size, used under debug */
if (size < 16) size = 16;

if (!(yield = malloc(size)))
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to malloc " SIZE_T_FMT " bytes of memory: "
    "called from line %d in %s", size, line, func);

#ifndef COMPILE_UTILITY
DEBUG(D_any) *(size_t *)yield = size;
#endif
yield = US yield + sizeof(size_t);

if ((nonpool_malloc += size) > max_nonpool_malloc)
  max_nonpool_malloc = nonpool_malloc;

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifndef COMPILE_UTILITY
/* If running in test harness, spend time making sure all the new store
is not filled with zeros so as to catch problems. */

if (f.running_in_test_harness)
  memset(yield, 0xF0, size - sizeof(size_t));
DEBUG(D_memory) debug_printf("--Malloc %6p %5lu bytes\t%-20s %4d\tpool %5d  nonpool %5d\n",
  yield, size, func, line, pool_malloc, nonpool_malloc);
#endif  /* COMPILE_UTILITY */

return yield;
}

void *
store_malloc_3(size_t size, const char *func, int linenumber)
{
if (n_nonpool_blocks++ > max_nonpool_blocks)
  max_nonpool_blocks = n_nonpool_blocks;
return internal_store_malloc(size, func, linenumber);
}


/************************************************
*             Free store                        *
************************************************/

/* This function is called by the macro store_free().

Arguments:
  block       block of store to free
  func        function from which called
  linenumber  line number in source file

Returns:      nothing
*/

static void
internal_store_free(void * block, const char * func, int linenumber)
{
uschar * p = US block - sizeof(size_t);
#ifndef COMPILE_UTILITY
DEBUG(D_any) nonpool_malloc -= *(size_t *)p;
DEBUG(D_memory) debug_printf("----Free %6p %5ld bytes\t%-20s %4d\n",
		    block, *(size_t *)p, func, linenumber);
#endif
free(p);
}

void
store_free_3(void * block, const char * func, int linenumber)
{
n_nonpool_blocks--;
internal_store_free(block, func, linenumber);
}

/******************************************************************************/
/* Stats output on process exit */
void
store_exit(void)
{
#ifndef COMPILE_UTILITY
DEBUG(D_memory)
 {
 int i;
 debug_printf("----Exit nonpool max: %3d kB in %d blocks\n",
  (max_nonpool_malloc+1023)/1024, max_nonpool_blocks);
 debug_printf("----Exit npools  max: %3d kB\n", max_pool_malloc/1024);

 for (i = 0; i < N_PAIRED_POOLS; i++)
   {
   pooldesc * pp = paired_pools + i;
   debug_printf("----Exit  pool %2d max: %3d kB in %d blocks at order %u\t%s %s\n",
    i, (pp->maxbytes+1023)/1024, pp->maxblocks, pp->maxorder,
    poolclass[i], pooluse[i]);
   }
 i = 0;
 for (quoted_pooldesc * qp = quoted_pools; qp; i++, qp = qp->next)
   {
   pooldesc * pp = &qp->pool;
   debug_printf("----Exit  pool Q%d max: %3d kB in %d blocks at order %u\ttainted quoted:%s\n",
    i, (pp->maxbytes+1023)/1024, pp->maxblocks, pp->maxorder, lookup_list[qp->quoter]->name);
   }
 }
#endif
}


/******************************************************************************/
/* Per-message pool management */

static rmark   message_reset_point    = NULL;

void
message_start(void)
{
int oldpool = store_pool;
store_pool = POOL_MESSAGE;
if (!message_reset_point) message_reset_point = store_mark();
store_pool = oldpool;
}

void
message_tidyup(void)
{
int oldpool;
if (!message_reset_point) return;
oldpool = store_pool;
store_pool = POOL_MESSAGE;
message_reset_point = store_reset(message_reset_point);
store_pool = oldpool;
}

/******************************************************************************/
/* Debug analysis of address */

#ifndef COMPILE_UTILITY
void
debug_print_taint(const void * p)
{
int q = quoter_for_address(p);
if (!is_tainted(p)) return;
debug_printf("(tainted");
if (is_real_quoter(q)) debug_printf(", quoted:%s", lookup_list[q]->name);
debug_printf(")\n");
}
#endif

/* End of store.c */
