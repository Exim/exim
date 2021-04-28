/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim maintainers 2019 - 2020 */
/* See the file NOTICE for conditions of use and distribution. */

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

. Orthogonal to the three pool types, there are two classes of memory: untainted
  and tainted.  The latter is used for values derived from untrusted input, and
  the string-expansion mechanism refuses to operate on such values (obviously,
  it can expand an untainted value to return a tainted result).  The classes
  are implemented by duplicating the three pool types.  Pool resets are requested
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

/* Just in case we find ourselves on a system where the structure above has a
length that is not a multiple of the alignment, set up a macro for the padded
length. */

#define ALIGNED_SIZEOF_STOREBLOCK \
  (((sizeof(storeblock) + alignment - 1) / alignment) * alignment)

/* Size of block to get from malloc to carve up into smaller ones. This
must be a multiple of the alignment. We assume that 8192 is going to be
suitably aligned. */

#define STORE_BLOCK_SIZE (8192 - ALIGNED_SIZEOF_STOREBLOCK)

/* Variables holding data for the local pools of store. The current pool number
is held in store_pool, which is global so that it can be changed from outside.
Setting the initial length values to -1 forces a malloc for the first call,
even if the length is zero (which is used for getting a point to reset to). */

int store_pool = POOL_MAIN;

#define NPOOLS 6
static storeblock *chainbase[NPOOLS];
static storeblock *current_block[NPOOLS];
static void *next_yield[NPOOLS];
static int yield_length[NPOOLS] = { -1, -1, -1,  -1, -1, -1 };

/* pool_malloc holds the amount of memory used by the store pools; this goes up
and down as store is reset or released. nonpool_malloc is the total got by
malloc from other calls; this doesn't go down because it is just freed by
pointer. */

static int pool_malloc;
static int nonpool_malloc;

/* This variable is set by store_get() to its yield, and by store_reset() to
NULL. This enables string_cat() to optimize its store handling for very long
strings. That's why the variable is global. */

void *store_last_get[NPOOLS];

/* These are purely for stats-gathering */

static int nbytes[NPOOLS];	/* current bytes allocated */
static int maxbytes[NPOOLS];	/* max number reached */
static int nblocks[NPOOLS];	/* current number of blocks allocated */
static int maxblocks[NPOOLS];
static int n_nonpool_blocks;	/* current number of direct store_malloc() blocks */
static int max_nonpool_blocks;
static int max_pool_malloc;	/* max value for pool_malloc */
static int max_nonpool_malloc;	/* max value for nonpool_malloc */


#ifndef COMPILE_UTILITY
static const uschar * pooluse[NPOOLS] = {
[POOL_MAIN] =		US"main",
[POOL_PERM] =		US"perm",
[POOL_SEARCH] =		US"search",
[POOL_TAINT_MAIN] =	US"main",
[POOL_TAINT_PERM] =	US"perm",
[POOL_TAINT_SEARCH] =	US"search",
};
static const uschar * poolclass[NPOOLS] = {
[POOL_MAIN] =		US"untainted",
[POOL_PERM] =		US"untainted",
[POOL_SEARCH] =		US"untainted",
[POOL_TAINT_MAIN] =	US"tainted",
[POOL_TAINT_PERM] =	US"tainted",
[POOL_TAINT_SEARCH] =	US"tainted",
};
#endif


static void * internal_store_malloc(int, const char *, int);
static void   internal_store_free(void *, const char *, int linenumber);

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

for (int pool = POOL_TAINT_BASE; pool < nelem(chainbase); pool++)
  if ((b = current_block[pool]))
    {
    uschar * bc = US b + ALIGNED_SIZEOF_STOREBLOCK;
    if (US p >= bc && US p < bc + b->length) return TRUE;
    }

for (int pool = POOL_TAINT_BASE; pool < nelem(chainbase); pool++)
  for (b = chainbase[pool]; b; b = b->next)
    {
    uschar * bc = US b + ALIGNED_SIZEOF_STOREBLOCK;
    if (US p >= bc && US p < bc + b->length) return TRUE;
    }
return FALSE;
}


void
die_tainted(const uschar * msg, const uschar * func, int line)
{
log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Taint mismatch, %s: %s %d\n",
	msg, func, line);
}



/*************************************************
*       Get a block from the current pool        *
*************************************************/

/* Running out of store is a total disaster. This function is called via the
macro store_get(). It passes back a block of store within the current big
block, getting a new one if necessary. The address is saved in
store_last_was_get.

Arguments:
  size        amount wanted, bytes
  tainted     class: set to true for untrusted data (eg. from smtp input)
  func        function from which called
  linenumber  line number in source file

Returns:      pointer to store (panic on malloc failure)
*/

void *
store_get_3(int size, BOOL tainted, const char *func, int linenumber)
{
int pool = tainted ? store_pool + POOL_TAINT_BASE : store_pool;

/* Ensure we've been asked to allocate memory.
A negative size is a sign of a security problem.
A zero size might be also suspect, but our internal usage deliberately
does this to return a current watermark value for a later release of
allocated store. */

if (size < 0 || size >= INT_MAX/2)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
            "bad memory allocation requested (%d bytes) at %s %d",
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

if (size > yield_length[pool])
  {
  int length = size <= STORE_BLOCK_SIZE ? STORE_BLOCK_SIZE : size;
  int mlength = length + ALIGNED_SIZEOF_STOREBLOCK;
  storeblock * newblock;

  /* Sometimes store_reset() may leave a block for us; check if we can use it */

  if (  (newblock = current_block[pool])
     && (newblock = newblock->next)
     && newblock->length < length
     )
    {
    /* Give up on this block, because it's too small */
    nblocks[pool]--;
    internal_store_free(newblock, func, linenumber);
    newblock = NULL;
    }

  /* If there was no free block, get a new one */

  if (!newblock)
    {
    if ((nbytes[pool] += mlength) > maxbytes[pool])
      maxbytes[pool] = nbytes[pool];
    if ((pool_malloc += mlength) > max_pool_malloc)	/* Used in pools */
      max_pool_malloc = pool_malloc;
    nonpool_malloc -= mlength;			/* Exclude from overall total */
    if (++nblocks[pool] > maxblocks[pool])
      maxblocks[pool] = nblocks[pool];

    newblock = internal_store_malloc(mlength, func, linenumber);
    newblock->next = NULL;
    newblock->length = length;

    if (!chainbase[pool])
      chainbase[pool] = newblock;
    else
      current_block[pool]->next = newblock;
    }

  current_block[pool] = newblock;
  yield_length[pool] = newblock->length;
  next_yield[pool] =
    (void *)(CS current_block[pool] + ALIGNED_SIZEOF_STOREBLOCK);
  (void) VALGRIND_MAKE_MEM_NOACCESS(next_yield[pool], yield_length[pool]);
  }

/* There's (now) enough room in the current block; the yield is the next
pointer. */

store_last_get[pool] = next_yield[pool];

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifdef COMPILE_UTILITY
func = func;
linenumber = linenumber;
#else
DEBUG(D_memory)
  debug_printf("---%d Get %6p %5d %-14s %4d\n", pool,
    store_last_get[pool], size, func, linenumber);
#endif  /* COMPILE_UTILITY */

(void) VALGRIND_MAKE_MEM_UNDEFINED(store_last_get[pool], size);
/* Update next pointer and number of bytes left in the current block. */

next_yield[pool] = (void *)(CS next_yield[pool] + size);
yield_length[pool] -= size;
return store_last_get[pool];
}



/*************************************************
*       Get a block from the PERM pool           *
*************************************************/

/* This is just a convenience function, useful when just a single block is to
be obtained.

Arguments:
  size        amount wanted
  func        function from which called
  linenumber  line number in source file

Returns:      pointer to store (panic on malloc failure)
*/

void *
store_get_perm_3(int size, BOOL tainted, const char *func, int linenumber)
{
void *yield;
int old_pool = store_pool;
store_pool = POOL_PERM;
yield = store_get_3(size, tainted, func, linenumber);
store_pool = old_pool;
return yield;
}



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
*/

BOOL
store_extend_3(void *ptr, BOOL tainted, int oldsize, int newsize,
   const char *func, int linenumber)
{
int pool = tainted ? store_pool + POOL_TAINT_BASE : store_pool;
int inc = newsize - oldsize;
int rounded_oldsize = oldsize;

if (oldsize < 0 || newsize < oldsize || newsize >= INT_MAX/2)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
            "bad memory extension requested (%d -> %d bytes) at %s %d",
            oldsize, newsize, func, linenumber);

/* Check that the block being extended was already of the required taint status;
refuse to extend if not. */

if (is_tainted(ptr) != tainted)
  return FALSE;

if (rounded_oldsize % alignment != 0)
  rounded_oldsize += alignment - (rounded_oldsize % alignment);

if (CS ptr + rounded_oldsize != CS (next_yield[pool]) ||
    inc > yield_length[pool] + rounded_oldsize - oldsize)
  return FALSE;

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifdef COMPILE_UTILITY
func = func;
linenumber = linenumber;
#else
DEBUG(D_memory)
  debug_printf("---%d Ext %6p %5d %-14s %4d\n", pool, ptr, newsize,
    func, linenumber);
#endif  /* COMPILE_UTILITY */

if (newsize % alignment != 0) newsize += alignment - (newsize % alignment);
next_yield[pool] = CS ptr + newsize;
yield_length[pool] -= newsize - rounded_oldsize;
(void) VALGRIND_MAKE_MEM_UNDEFINED(ptr + oldsize, inc);
return TRUE;
}




/*************************************************
*    Back up to a previous point on the stack    *
*************************************************/

/* This function resets the next pointer, freeing any subsequent whole blocks
that are now unused. Call with a cookie obtained from store_mark() only; do
not call with a pointer returned by store_get().  Both the untainted and tainted
pools corresposding to store_pool are reset.

Arguments:
  r           place to back up to
  func        function from which called
  linenumber  line number in source file

Returns:      nothing
*/

static void
internal_store_reset(void * ptr, int pool, const char *func, int linenumber)
{
storeblock * bb;
storeblock * b = current_block[pool];
char * bc = CS b + ALIGNED_SIZEOF_STOREBLOCK;
int newlength, count;
#ifndef COMPILE_UTILITY
int oldmalloc = pool_malloc;
#endif

/* Last store operation was not a get */

store_last_get[pool] = NULL;

/* See if the place is in the current block - as it often will be. Otherwise,
search for the block in which it lies. */

if (CS ptr < bc || CS ptr > bc + b->length)
  {
  for (b = chainbase[pool]; b; b = b->next)
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
next_yield[pool] = CS ptr + (newlength % alignment);
count = yield_length[pool];
count = (yield_length[pool] = newlength - (newlength % alignment)) - count;
current_block[pool] = b;

/* Free any subsequent block. Do NOT free the first
successor, if our current block has less than 256 bytes left. This should
prevent us from flapping memory. However, keep this block only when it has
the default size. */

if (  yield_length[pool] < STOREPOOL_MIN_SIZE
   && b->next
   && b->next->length == STORE_BLOCK_SIZE)
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
  nbytes[pool] -= siz;
  pool_malloc -= siz;
  nblocks[pool]--;
  internal_store_free(b, func, linenumber);
  }

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifdef COMPILE_UTILITY
func = func;
linenumber = linenumber;
#else
DEBUG(D_memory)
  debug_printf("---%d Rst %6p %5d %-14s %4d %d\n", pool, ptr,
    count + oldmalloc - pool_malloc,
    func, linenumber, pool_malloc);
#endif  /* COMPILE_UTILITY */
}


rmark
store_reset_3(rmark r, int pool, const char *func, int linenumber)
{
void ** ptr = r;

if (pool >= POOL_TAINT_BASE)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "store_reset called for pool %d: %s %d\n", pool, func, linenumber);
if (!r)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "store_reset called with bad mark: %s %d\n", func, linenumber);

internal_store_reset(*ptr, pool + POOL_TAINT_BASE, func, linenumber);
internal_store_reset(ptr,  pool,		   func, linenumber);
return NULL;
}



/* Free tail-end unused allocation.  This lets us allocate a big chunk
early, for cases when we only discover later how much was really needed.

Can be called with a value from store_get(), or an offset after such.  Only
the tainted or untainted pool that serviced the store_get() will be affected.

This is mostly a cut-down version of internal_store_reset().
XXX needs rationalising
*/

void
store_release_above_3(void *ptr, const char *func, int linenumber)
{
/* Search all pools' "current" blocks.  If it isn't one of those,
ignore it (it usually will be). */

for (int pool = 0; pool < nelem(current_block); pool++)
  {
  storeblock * b = current_block[pool];
  char * bc;
  int count, newlength;

  if (!b)
    continue;

  bc = CS b + ALIGNED_SIZEOF_STOREBLOCK;
  if (CS ptr < bc || CS ptr > bc + b->length)
    continue;

  /* Last store operation was not a get */

  store_last_get[pool] = NULL;

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
  next_yield[pool] = CS ptr + (newlength % alignment);
  count = yield_length[pool];
  count = (yield_length[pool] = newlength - (newlength % alignment)) - count;

  /* Cut out the debugging stuff for utilities, but stop picky compilers from
  giving warnings. */

#ifdef COMPILE_UTILITY
  func = func;
  linenumber = linenumber;
#else
  DEBUG(D_memory)
    debug_printf("---%d Rel %6p %5d %-14s %4d %d\n", pool, ptr, count,
      func, linenumber, pool_malloc);
#endif
  return;
  }
#ifndef COMPILE_UTILITY
DEBUG(D_memory)
  debug_printf("non-last memory release try: %s %d\n", func, linenumber);
#endif
}



rmark
store_mark_3(const char *func, int linenumber)
{
void ** p;

if (store_pool >= POOL_TAINT_BASE)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "store_mark called for pool %d: %s %d\n", store_pool, func, linenumber);

/* Stash a mark for the tainted-twin release, in the untainted twin. Return
a cookie (actually the address in the untainted pool) to the caller.
Reset uses the cookie to recover the t-mark, winds back the tainted pool with it
and winds back the untainted pool with the cookie. */

p = store_get_3(sizeof(void *), FALSE, func, linenumber);
*p = store_get_3(0, TRUE, func, linenumber);
return p;
}




/************************************************
*             Release store                     *
************************************************/

/* This function checks that the pointer it is given is the first thing in a
block, and if so, releases that block.

Arguments:
  block       block of store to consider
  func        function from which called
  linenumber  line number in source file

Returns:      nothing
*/

static void
store_release_3(void * block, int pool, const char * func, int linenumber)
{
/* It will never be the first block, so no need to check that. */

for (storeblock * b = chainbase[pool]; b; b = b->next)
  {
  storeblock * bb = b->next;
  if (bb && CS block == CS bb + ALIGNED_SIZEOF_STOREBLOCK)
    {
    int siz = bb->length + ALIGNED_SIZEOF_STOREBLOCK;
    b->next = bb->next;
    nbytes[pool] -= siz;
    pool_malloc -= siz;
    nblocks[pool]--;

    /* Cut out the debugging stuff for utilities, but stop picky compilers
    from giving warnings. */

#ifdef COMPILE_UTILITY
    func = func;
    linenumber = linenumber;
#else
    DEBUG(D_memory)
      debug_printf("-Release %6p %-20s %4d %d\n", (void *)bb, func,
	linenumber, pool_malloc);

    if (f.running_in_test_harness)
      memset(bb, 0xF0, bb->length+ALIGNED_SIZEOF_STOREBLOCK);
#endif  /* COMPILE_UTILITY */

    free(bb);
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
  block
  newsize
  len

Returns:	new location of data
*/

void *
store_newblock_3(void * block, BOOL tainted, int newsize, int len,
  const char * func, int linenumber)
{
int pool = tainted ? store_pool + POOL_TAINT_BASE : store_pool;
BOOL release_ok = !tainted && store_last_get[pool] == block;
uschar * newtext;

#if !defined(MACRO_PREDEF) && !defined(COMPILE_UTILITY)
if (is_tainted(block) != tainted)
  die_tainted(US"store_newblock", CUS func, linenumber);
#endif

if (len < 0 || len > newsize)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
            "bad memory extension requested (%d -> %d bytes) at %s %d",
            len, newsize, func, linenumber);

newtext = store_get(newsize, tainted);
memcpy(newtext, block, len);
if (release_ok) store_release_3(block, pool, func, linenumber);
return (void *)newtext;
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
internal_store_malloc(int size, const char *func, int line)
{
void * yield;

if (size < 0 || size >= INT_MAX/2)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
            "bad memory allocation requested (%d bytes) at %s %d",
            size, func, line);

if (size < 16) size = 16;

if (!(yield = malloc((size_t)size)))
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to malloc %d bytes of memory: "
    "called from line %d in %s", size, line, func);

if ((nonpool_malloc += size) > max_nonpool_malloc)
  max_nonpool_malloc = nonpool_malloc;

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifdef COMPILE_UTILITY
func = func; line = line;
#else

/* If running in test harness, spend time making sure all the new store
is not filled with zeros so as to catch problems. */

if (f.running_in_test_harness)
  memset(yield, 0xF0, (size_t)size);
DEBUG(D_memory) debug_printf("--Malloc %6p %5d bytes\t%-14s %4d\tpool %5d  nonpool %5d\n",
  yield, size, func, line, pool_malloc, nonpool_malloc);
#endif  /* COMPILE_UTILITY */

return yield;
}

void *
store_malloc_3(int size, const char *func, int linenumber)
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
#ifdef COMPILE_UTILITY
func = func;
linenumber = linenumber;
#else
DEBUG(D_memory)
  debug_printf("----Free %6p %-20s %4d\n", block, func, linenumber);
#endif  /* COMPILE_UTILITY */
free(block);
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
 debug_printf("----Exit nonpool max: %3d kB in %d blocks\n",
  (max_nonpool_malloc+1023)/1024, max_nonpool_blocks);
 debug_printf("----Exit npools  max: %3d kB\n", max_pool_malloc/1024);
 for (int i = 0; i < NPOOLS; i++)
  debug_printf("----Exit  pool %d max: %3d kB in %d blocks\t%s %s\n",
    i, maxbytes[i]/1024, maxblocks[i], poolclass[i], pooluse[i]);
 }
#endif
}

/* End of store.c */
