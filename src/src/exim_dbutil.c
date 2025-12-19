/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2025 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */


/* This single source file is used to compile three utility programs for
maintaining Exim hints databases.

  exim_dumpdb     dumps out the contents
  exim_fixdb      patches the database (really for Exim maintenance/testing)
  exim_tidydb     removed obsolete data

In all cases, the first argument is the name of the spool directory. The second
argument is the name of the database file. The available names are:

  callout:	callout verification cache
  misc:		miscellaneous hints data
  ratelimit:	record for ACL "ratelimit" condition
  retry:	etry delivery information
  seen:		imestamp records for ACL "seen" condition
  tls:		TLS session resumption cache
  wait-<t>:	message waiting information; <t> is a transport name

There are a number of common subroutines, followed by three main programs,
whose inclusion is controlled by -D on the compilation command. */


#include <libgen.h>
#include "exim.h"
#include "hintsdb.h"


/* Identifiers for the different database types. */

enum dbtype { type_retry = 1, type_wait, type_misc, type_callout,
	      type_ratelimit, type_tls, type_seen, type_dbm
};

/* This is used by our cut-down dbfn_open(). */

uschar * spool_directory = NULL;
const uschar * lockfile_name = NULL;

BOOL dbmdb = FALSE;
BOOL keyonly = FALSE;
BOOL utc = FALSE;


/******************************************************************************/
	/* dummies needed by Solaris build */
void
millisleep(int msec)
{}
uschar *
readconf_printtime(int t)
{ return NULL; }
const uschar * expand_string_2(const uschar * string, BOOL * textonly_p)
{ return NULL; }
const uschar * parse_find_address_end_gen(const uschar * s, BOOL b)
{return NULL; }

struct global_flags	f;
unsigned int		log_selector[1];
uschar *		queue_name;
BOOL			split_spool_directory;


/******************************************************************************/


/*************************************************
*              SIGALRM handler                   *
*************************************************/

SIGNAL_BOOL sigalrm_seen;

void
sigalrm_handler(int sig)
{
sigalrm_seen = 1;
}



/*************************************************
*        Output usage message and exit           *
*************************************************/

static void
usage(const uschar * name, const uschar * options)
{
uschar * s = store_get(Ustrlen(options), options), * t = s;

if (Ustrchr(options, 'L'))
  printf("Usage: exim_%s -L <database-path>\n\n", name);

/* drop the L from options */
do { if (*options != 'L') *t++ = *options; } while (*options++);

printf("Usage: exim_%s%s  <spool-directory> <database-name>\n", name, s);
printf("  <database-name> = retry | misc | wait-<transport-name> | callout | ratelimit | tls | seen\n");
exit(EXIT_FAILURE);
}



/*******************
*   Debug output   *
*******************/

unsigned int debug_selector = 0;	/* set -1 for debugging */

void
debug_printf(const char * fmt, ...)
{
va_list ap;
va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
}
void
debug_printf_indent(const char * fmt, ...)
{
va_list ap;
va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
}

/*************************************************
*           Sort out the command arguments       *
*************************************************/

/* This function checks that there are exactly 2 arguments, and checks the
second of them to be sure it is a known database name. */

static int
check_args(int argc, uschar **argv, const uschar * name, const uschar * options)
{
if (dbmdb && argc - optind == 1) return type_dbm;

if (argc - optind == 2)
  {
  const uschar * aname = argv[optind + 1];
  if (Ustrcmp(aname, "retry") == 0)	return type_retry;
  if (Ustrcmp(aname, "misc") == 0)	return type_misc;
  if (Ustrncmp(aname, "wait-", 5) == 0)	return type_wait;
  if (Ustrcmp(aname, "callout") == 0)	return type_callout;
  if (Ustrcmp(aname, "ratelimit") == 0)	return type_ratelimit;
  if (Ustrcmp(aname, "tls") == 0)	return type_tls;
  if (Ustrcmp(aname, "seen") == 0)	return type_seen;
  }
usage(name, options);
return -1;              /* Never obeyed */
}


FUNC_MAYBE_UNUSED
static void
options(int argc, uschar * argv[], uschar * name, const uschar * opts)
{
int opt;

opterr = 0;
while ((opt = getopt(argc, (char * const *)argv, CCS opts)) != -1)
  switch (opt)
  {
  case 'L':	dbmdb = TRUE; break;
  case 'k':	keyonly = TRUE; break;
  case 'z':	utc = TRUE; break;
  default:	usage(name, US" [-kLz]");
  }
}




/*************************************************
*         Handle attempts to write the log       *
*************************************************/

/* The message gets written to stderr when log_write() is called from a
utility. The message always gets '\n' added on the end of it. These calls come
from modules such as store.c when things go drastically wrong (e.g. malloc()
failing). In normal use they won't get obeyed.

Arguments:
  selector  not relevant when running a utility
  flags     not relevant when running a utility
  format    a printf() format
  ...       arguments for format

Returns:    nothing
*/

void
log_write(unsigned int selector, int flags, const char *format, ...)
{
va_list ap;
va_start(ap, format);
vfprintf(stderr, format, ap);
fprintf(stderr, "\n");
va_end(ap);
}

void
log_write_die(unsigned int selector, int flags, const char *format, ...)
{
va_list ap;
va_start(ap, format);
vfprintf(stderr, format, ap);
fprintf(stderr, "\n");
va_end(ap);
exit(EXIT_FAILURE);
}



/*************************************************
*        Format a time value for printing        *
*************************************************/

static uschar time_buffer[sizeof("09-xxx-1999 hh:mm:ss  ")];

uschar *
print_time(time_t t)
{
const struct tm * tmstr = utc ? gmtime(&t) : localtime(&t);
Ustrftime(time_buffer, sizeof(time_buffer), "%d-%b-%Y %H:%M:%S", tmstr);
return time_buffer;
}



/*************************************************
*        Format a cache value for printing       *
*************************************************/

uschar *
print_cache(int value)
{
return value == ccache_accept ? US"accept" :
       value == ccache_reject ? US"reject" :
       US"unknown";
}


#ifdef EXIM_FIXDB
/*************************************************
*                Read time value                 *
*************************************************/

static time_t
read_time(uschar *s)
{
int field = 0;
int value;
time_t now = time(NULL);
struct tm *tm = localtime(&now);

tm->tm_sec = 0;
tm->tm_isdst = -1;

for (uschar * t = s + Ustrlen(s) - 1; t >= s; t--)
  {
  if (*t == ':') continue;
  if (!isdigit((uschar)*t)) return -1;

  value = *t - '0';
  if (--t >= s)
    {
    if (!isdigit((uschar)*t)) return -1;
    value = value + (*t - '0')*10;
    }

  switch (field++)
    {
    case 0: tm->tm_min = value; break;
    case 1: tm->tm_hour = value; break;
    case 2: tm->tm_mday = value; break;
    case 3: tm->tm_mon = value - 1; break;
    case 4: tm->tm_year = (value < 90)? value + 100 : value; break;
    default: return -1;
    }
  }

return mktime(tm);
}
#endif  /* EXIM_FIXDB */



/*************************************************
*       Open and lock a database file            *
*************************************************/

/* This is a cut-down version from the function in dbfn.h that Exim itself
uses. We assume the database exists, and therefore give up if we cannot open
the lock file.

Arguments:
  name     The single-component name of one of Exim's database files.
  flags    O_RDONLY or O_RDWR, O_CREAT
  dbblock  Points to an open_db block to be filled in.
  lof      Unused.
  panic	   Unused

Returns:   NULL if the open failed, or the locking failed.
           On success, dbblock is returned. This contains the dbm pointer and
           the fd of the locked lock file.
*/

open_db *
dbfn_open(const uschar * name, int flags, open_db * dbblock,
  BOOL lof, BOOL panic)
{
int rc;
struct flock lock_data;
uschar * dname, * filename;

/* The first thing to do is to open a separate file on which to lock. This
ensures that Exim has exclusive use of the database before it even tries to
open it. If there is a database, there should be a lock file in existence;
if no lockfile and a create fails, we assume it was the spooldir perms (and
we have no write perms) and there is no database - and error out.  We open the
lockfile using the r/w mode requested for the DB, users lacking permission
for the DB access mode will error out here. */

if (dbmdb)
  {
  filename = string_sprintf("%s.lockfile", name);
  dname = Ustrchr(name, '/')		/* path has dirs */
    ? US dirname(CS string_copy(name))
    : US ".";
  }
else
  {
  dname = string_sprintf("%s/db", spool_directory);
  filename = string_sprintf("%s/%s.lockfile", dname, name);
  }

dbblock->readonly = (flags & O_ACCMODE) == O_RDONLY;
dbblock->lockfd = -1;
if (exim_lockfile_needed())
  {
  if ((dbblock->lockfd = Uopen(filename, dbmdb ? flags | O_CREAT : flags,
			      0600)) < 0)
    {
    printf("** Failed to open database lock file %s: %s\n", filename,
      strerror(errno));
    return NULL;
    }
  lockfile_name = string_copy(filename);

  /* Now we must get a lock on the opened lock file; do this with a blocking
  lock that times out. */

  lock_data.l_type = dbblock->readonly ? F_RDLCK : F_WRLCK;
  lock_data.l_whence = lock_data.l_start = lock_data.l_len = 0;

  sigalrm_seen = FALSE;
  os_non_restarting_signal(SIGALRM, sigalrm_handler);
  ALARM(EXIMDB_LOCK_TIMEOUT);
  rc = fcntl(dbblock->lockfd, F_SETLKW, &lock_data);
  ALARM_CLR(0);

  if (sigalrm_seen) errno = ETIMEDOUT;
  if (rc < 0)
    {
    printf("** Failed to get %s lock for %s: %s",
      dbblock->readonly ? "read" : "write",
      filename,
      errno == ETIMEDOUT ? "timed out" : strerror(errno));
    (void)close(dbblock->lockfd);
    unlink(CS filename);
    return NULL;
    }

  /* At this point we have an opened and locked separate lock file, that is,
  exclusive access to the database, so we can go ahead and open it. */
  }

/* Drop the ".lockfile" off the name */
*Ustrrchr(filename, '.') = '\0';

if (!(dbblock->dbptr = dbblock->readonly && !exim_lockfile_needed()
		      ? exim_dbopen_multi(filename, dname, flags, 0)
		      : exim_dbopen(filename, dname, flags, 0)))
  {
  printf("** Failed to open hintsdb file %s for %s: %s%s\n", filename,
    dbblock->readonly ? "reading" : "writing", strerror(errno),
#ifdef USE_DB
    " (or Berkeley DB error while opening)"
#else
    ""
#endif
    );
  if (dbblock->lockfd >= 0) (void)close(dbblock->lockfd);
  unlink(CCS lockfile_name);
  return NULL;
  }

return dbblock;
}




/*************************************************
*         Unlock and close a database file       *
*************************************************/

/* Closing a file automatically unlocks it, so after closing the database, just
close the lock file if there was one.

Argument: a pointer to an open database block
Returns:  nothing
*/

void
dbfn_close(open_db * dbp)
{
if (dbp->readonly && !exim_lockfile_needed())
  exim_dbclose_multi(dbp->dbptr);
else
  exim_dbclose(dbp->dbptr);

if (dbp->lockfd >= 0)
  { (void) close(dbp->lockfd); dbp->lockfd = -1; }
unlink(CCS lockfile_name);
lockfile_name = NULL;
}




/*************************************************
*             Read from database file            *
*************************************************/

/* Passing back the pointer unchanged is useless, because there is no guarantee
of alignment. Since all the records used by Exim need to be properly aligned to
pick out the timestamps, etc., do the copying centrally here.

Arguments:
  dbblock   a pointer to an open database block
  key       the key of the record to be read
  length    where to put the length (or NULL if length not wanted). Includes overhead.

Returns: a pointer to the retrieved record, or
         NULL if the record is not found or bad
*/

void *
dbfn_read_with_length(open_db * dbblock, const uschar * key, int * length)
{
void * yield;
EXIM_DATUM key_datum, result_datum;
int klen = Ustrlen(key) + 1;
uschar * key_copy = store_get(klen, key);
unsigned dlen;
BOOL tainted;

memcpy(key_copy, key, klen);

exim_datum_init(&key_datum);         /* Some DBM libraries require the datum */
exim_datum_init(&result_datum);      /* to be cleared before use. */
exim_datum_data_set(&key_datum, key_copy);
exim_datum_size_set(&key_datum, klen);

if (!exim_dbget(dbblock->dbptr, &key_datum, &result_datum))
  return NULL;

dlen = exim_datum_size_get(&result_datum);
DEBUG(D_hints_lookup) debug_printf_indent("dbfn_read: size %u return\n", dlen);
if (length) *length = dlen;

/* Hintsdb uses store the taint of the payload of the value in the value.
For non-hints uses we have no provenance, so assume untainted */

if (dbmdb)
  tainted = FALSE;
else
  {
  dbdata_generic * gp = (dbdata_generic *) exim_datum_data_get(&result_datum);
  if (dlen < sizeof(dbdata_generic))
    {
    DEBUG(D_hints_lookup)
      debug_printf_indent("dbfn_read: bad record size %u\n", dlen);
    return NULL;
    }
  if (gp->version != HINTS_VERSION)
    {
    DEBUG(D_hints_lookup)
      debug_printf_indent("dbfn_read: bad record version %u; deleting\n",
			    gp->version);
    return NULL;
    }

  tainted = gp->tainted;
  }

yield = store_get(dlen, tainted ? GET_TAINTED : GET_UNTAINTED);
memcpy(yield, exim_datum_data_get(&result_datum), dlen);
exim_datum_free(&result_datum);		/* Some DBM libs require freeing */

return yield;
}



#if defined(EXIM_TIDYDB) || defined(EXIM_FIXDB)

/*************************************************
*             Write to database file             *
*************************************************/

/*
Arguments:
  dbblock   a pointer to an open database block
  key       the key of the record to be written
  ptr       a pointer to the record to be written
  length    the length of the record to be written

Returns:    the yield of the underlying dbm or db "write" function. If this
            is dbm, the value is zero for OK.
*/

int
dbfn_write(open_db * dbblock, const uschar * key, void * ptr, int length)
{
EXIM_DATUM key_datum, value_datum;
int klen = Ustrlen(key) + 1;
uschar * key_copy = store_get(klen, key);

memcpy(key_copy, key, klen);

exim_datum_init(&key_datum);         /* Some DBM libraries require the datum */
exim_datum_init(&value_datum);       /* to be cleared before use. */
exim_datum_data_set(&key_datum, key_copy);
exim_datum_size_set(&key_datum, klen);
exim_datum_data_set(&value_datum, ptr);
exim_datum_size_set(&value_datum, length);
return exim_dbput(dbblock->dbptr, &key_datum, &value_datum);
}



/*************************************************
*           Delete record from database file     *
*************************************************/

/*
Arguments:
  dbblock    a pointer to an open database block
  key        the key of the record to be deleted

Returns: the yield of the underlying dbm or db "delete" function.
*/

int
dbfn_delete(open_db *dbblock, const uschar *key)
{
int klen = Ustrlen(key) + 1;
uschar * key_copy = store_get(klen, key);
EXIM_DATUM key_datum;

memcpy(key_copy, key, klen);
exim_datum_init(&key_datum);         /* Some DBM libraries require clearing */
exim_datum_data_set(&key_datum, key_copy);
exim_datum_size_set(&key_datum, klen);
return exim_dbdel(dbblock->dbptr, &key_datum);
}

#endif  /* EXIM_TIDYDB || EXIM_FIXDB */



#if defined(EXIM_DUMPDB) || defined(EXIM_TIDYDB)
/*************************************************
*         Scan the keys of a database file       *
*************************************************/

/*
Arguments:
  dbblock  a pointer to an open database block
  start    TRUE if starting a new scan
           FALSE if continuing with the current scan
  cursor   a pointer to a pointer to a cursor anchor, for those dbm libraries
           that use the notion of a cursor

Returns:   the next *key* (nul-terminated) from the file, or
           NULL if there are no more
*/

uschar *
dbfn_scan(open_db *dbblock, BOOL start, EXIM_CURSOR **cursor)
{
EXIM_DATUM key_datum, value_datum;
uschar *yield;

/* Some dbm require an initialization */

if (start) *cursor = exim_dbcreate_cursor(dbblock->dbptr);

exim_datum_init(&key_datum);         /* Some DBM libraries require the datum */
exim_datum_init(&value_datum);       /* to be cleared before use. */

yield = exim_dbscan(dbblock->dbptr, &key_datum, &value_datum, start, *cursor)
  ? US exim_datum_data_get(&key_datum) : NULL;

/* Some dbm require a termination */

if (!yield) exim_dbdelete_cursor(*cursor);
return yield;
}
#endif  /* EXIM_DUMPDB || EXIM_TIDYDB */



#ifdef EXIM_DUMPDB
/*************************************************
*           The exim_dumpdb main program         *
*************************************************/

int
main(int argc, char ** cargv)
{
int dbdata_type = 0, yield = 0;
open_db dbblock;
open_db * dbm;
EXIM_CURSOR * cursor;
uschar ** argv = USS cargv;
const uschar * file;
uschar keybuffer[1024];

store_init();
options(argc, argv, US"dumpdb", US"kLz");

/* Check the arguments, and open the database */

dbdata_type = check_args(argc, argv, US"dumpdb", US" [-kLz]");
argc -= optind; argv += optind;

if (dbmdb)
  file = argv[0];
else
  {
  spool_directory = argv[0];
  file = argv[1];
  }

if (!(dbm = dbfn_open(file, O_RDONLY, &dbblock, FALSE, TRUE)))
  exit(EXIT_FAILURE);

/* Scan the file, formatting the information for each entry. Note
that data is returned in a malloc'ed block, in order that it be
correctly aligned. */

for (uschar * key = dbfn_scan(dbm, TRUE, &cursor);
     key;
     key = dbfn_scan(dbm, FALSE, &cursor))
  {
  dbdata_retry *retry;
  dbdata_wait *wait;
  dbdata_callout_cache *callout;
  dbdata_ratelimit *ratelimit;
  dbdata_ratelimit_unique *rate_unique;
  dbdata_tls_session *session;
  dbdata_seen *seen;
  int count_bad = 0;
  int length;
  uschar *t;
  uschar name[MESSAGE_ID_LENGTH + 1];
  void *value;
  rmark reset_point = store_mark();

  /* Keep a copy of the key separate, as in some DBM's the pointer is into data
  which might change. */

  if (Ustrlen(key) > sizeof(keybuffer) - 1)
    {
    printf("**** Overlong key encountered: %s\n", key);
    return 1;
    }
  Ustrcpy(keybuffer, key);

  if (keyonly)
    printf("  %s\n", keybuffer);
  else if (!(value = dbfn_read_with_length(dbm, keybuffer, &length)))
    fprintf(stderr, "**** Entry \"%s\" was in the key scan, but the record "
                    "was not found in the file - something is wrong!\n",
      CS keybuffer);
  else
    /* Note: don't use print_time more than once in one statement, since
    it uses a single buffer. */

    switch(dbdata_type)
      {
      case type_retry:
	retry = (dbdata_retry *)value;
	printf("  %s %d %d %s\n%s  ", keybuffer, retry->basic_errno,
	  retry->more_errno, retry->text,
	  print_time(retry->first_failed));
	printf("%s  ", print_time(retry->last_try));
	printf("%s %s\n", print_time(retry->next_try),
	  retry->expired ? "*" : "");
	break;

      case type_wait:
	wait = (dbdata_wait *)value;
	printf("%s ", keybuffer);
	t = wait->text;
	name[MESSAGE_ID_LENGTH] = 0;

    /* Leave corrupt records alone */
	if (wait->count > WAIT_NAME_MAX)
	  {
	  fprintf(stderr,
	    "**** Data for %s corrupted\n  count=%d=0x%x max=%d\n",
	    CS keybuffer, wait->count, wait->count, WAIT_NAME_MAX);
	  wait->count = WAIT_NAME_MAX;
	  yield = count_bad = 1;
	  }
	for (int i = 1; i <= wait->count; i++)
	  {
	  Ustrncpy(name, t, MESSAGE_ID_LENGTH);
	  if (count_bad && name[0] == 0) break;
	  if (Ustrlen(name) != MESSAGE_ID_LENGTH ||
	      Ustrspn(name, "0123456789"
			    "abcdefghijklmnopqrstuvwxyz"
			    "ABCDEFGHIJKLMNOPQRSTUVWXYZ-") != MESSAGE_ID_LENGTH)
	    {
	    fprintf(stderr,
	      "**** Data for %s corrupted: bad character in message id\n",
	      CS keybuffer);
	    for (int j = 0; j < MESSAGE_ID_LENGTH; j++)
	      fprintf(stderr, "%02x ", name[j]);
	    fprintf(stderr, "\n");
	    yield = 1;
	    break;
	    }
	  printf("%s ", name);
	  t += MESSAGE_ID_LENGTH;
	  }
	putchar('\n');
	break;

      case type_misc:
	{
	dbdata_generic * recp = (dbdata_generic *)value;
	uschar * dp = US (recp + 1);
	int dlen = length = sizeof(dbdata_generic);

	printf("%s %s\n", print_time(recp->time_stamp), keybuffer);
	if (  Ustrncmp(keybuffer, "etrn-", 5) == 0
	   || Ustrncmp(keybuffer, "tpt-serialize-", 14) == 0
	   || Ustrncmp(keybuffer, "host-serialize-", 15) == 0
	   )
	  printf("serialize %.*s: %d running\n",
		  (int)(Ustrchr(keybuffer, '-') - keybuffer), keybuffer,
		  ((dbdata_serialize *)recp)->count);
	else
	  {
	  uschar * s = keybuffer + Ustrlen(keybuffer) - 5;
#ifndef DISABLE_PIPE_CONNECT
	  if (s > keybuffer && Ustrcmp(s, ".EHLO") == 0)
	    {
	    ehlo_resp_precis * erp = &((dbdata_ehlo_resp *)recp)->data;

	    printf("helo/ehlo %.*s clr %04x/%04x cry %04x/%04x",
		    (int)(s - keybuffer), keybuffer,
		    erp->cleartext_features, erp->cleartext_auths,
		    erp->crypted_features,   erp->crypted_auths);

	    if (sizeof(*erp) > 4 * sizeof(unsigned short))
	      printf(" lim %05d/%05d/%05d",
		erp->limit_mail, erp->limit_rcpt, erp->limit_rcptdom);
	    putchar('\n');
	    }
	  else
#endif
	    printf("%s\n", string_sprintf("%.*q\n", dlen, dp));
	  }
	break;
	}

      case type_callout:
	callout = (dbdata_callout_cache *)value;

	/* New-style address record */

	if (length == sizeof(dbdata_callout_cache_address))
	  {
	  printf("%s %s callout=%s\n",
	    print_time(callout->gen.time_stamp),
	    keybuffer,
	    print_cache(callout->result));
	  }

	/* New-style domain record */

	else if (length == sizeof(dbdata_callout_cache))
	  {
	  printf("%s %s callout=%s postmaster=%s",
	    print_time(callout->gen.time_stamp),
	    keybuffer,
	    print_cache(callout->result),
	    print_cache(callout->postmaster_result));
	  if (callout->postmaster_result != ccache_unknown)
	    printf(" (%s)", print_time(callout->postmaster_stamp));
	  printf(" random=%s", print_cache(callout->random_result));
	  if (callout->random_result != ccache_unknown)
	    printf(" (%s)", print_time(callout->random_stamp));
	  printf("\n");
	  }

	break;

      case type_ratelimit:
	if (Ustrstr(key, "/unique/") != NULL && length >= sizeof(*rate_unique))
	  {
	  ratelimit = (dbdata_ratelimit *)value;
	  rate_unique = (dbdata_ratelimit_unique *)value;
	  printf("%s.%06d rate: %10.3f epoch: %s size: %u key: %s\n",
	    print_time(ratelimit->gen.time_stamp),
	    ratelimit->time_usec, ratelimit->rate,
	    print_time(rate_unique->bloom_epoch), rate_unique->bloom_size,
	    keybuffer);
	  }
	else
	  {
	  ratelimit = (dbdata_ratelimit *)value;
	  printf("%s.%06d rate: %10.3f key: %s\n",
	    print_time(ratelimit->gen.time_stamp),
	    ratelimit->time_usec, ratelimit->rate,
	    keybuffer);
	  }
	break;

      case type_tls:
	session = (dbdata_tls_session *)value;
	printf("  %s %.*s\n", keybuffer, length, session->session);
	break;

      case type_seen:
	seen = (dbdata_seen *)value;
	printf("%s\t%s\n", keybuffer, print_time(seen->gen.time_stamp));
	break;

      case type_dbm:
	printf("%s\t%.*s\n", keybuffer, length, CS value);
      }
  store_reset(reset_point);
  }

dbfn_close(dbm);
return yield;
}

#endif  /* EXIM_DUMPDB */




#ifdef EXIM_FIXDB
/*************************************************
*           The exim_fixdb main program          *
*************************************************/

/* In order not to hold the database lock any longer than is necessary, each
operation on the database uses a separate open/close call. This is expensive,
but then using this utility is not expected to be very common. Its main use is
to provide a way of patching up hints databases in order to run tests.

Syntax of commands:

(1) <record name>
    This causes the data from the given record to be displayed, or "not found"
    to be output. Note that in the retry database, destination names are
    preceded by R: or T: for router or transport retry info.

(2) <record name> d
    This causes the given record to be deleted or "not found" to be output.

(3) <record name> <field number> <value>
    This sets the given value into the given field, identified by a number
    which is output by the display command. Not all types of record can
    be changed.

(4) q
    This exits from exim_fixdb.

If the record name is omitted from (2) or (3), the previously used record name
is re-used. */


int
main(int argc, char **cargv)
{
int dbdata_type;
uschar **argv = USS cargv;
uschar buffer[256];
uschar name[256];
const uschar * file;
rmark reset_point;

store_init();
options(argc, argv, US"fixdb", US"Lz");
*name = '\0';  /* No name set */

/* Sort out the database type, verify what we are working on and then process
user requests */

dbdata_type = check_args(argc, argv, US"fixdb", US" [-Lz]");
argc -= optind; argv += optind;

if (dbmdb)
  {
  file = argv[0];
  printf("Modifying Exim dbm database %s\n", file);
  }
else
  {
  spool_directory = argv[0];
  file = argv[1];
  printf("Modifying Exim hints database %s/db/%s\n", spool_directory, file);
  }

for(; (reset_point = store_mark()); store_reset(reset_point))
  {
  open_db dbblock;
  open_db *dbm;
  void *record;
  dbdata_retry *retry;
  dbdata_wait *wait;
  dbdata_callout_cache *callout;
  dbdata_ratelimit *ratelimit;
  dbdata_ratelimit_unique *rate_unique;
  dbdata_tls_session *session;
  int oldlength, newlength;
  uschar * t, field[256], value[256];

  printf("> ");
  if (Ufgets(buffer, 256, stdin) == NULL) break;

  buffer[Ustrlen(buffer)-1] = 0;
  field[0] = value[0] = 0;

  /* If the buffer contains just one digit, or just consists of "d", use the
  previous name for an update. */

  if ((isdigit((uschar)buffer[0]) && (buffer[1] == ' ' || buffer[1] == '\0'))
       || Ustrcmp(buffer, "d") == 0)
    {
    if (!*name)
      {
      printf("No previous record name is set\n");
      continue;
      }
    (void)sscanf(CS buffer, "%s %s", field, value);
    }
  else
    {
    *name = '\0';
    (void)sscanf(CS buffer, "%s %s %s", name, field, value);
    }

  /* Handle an update request */

  if (*field)
    {
    int verify = 1;

    if (!(dbm = dbfn_open(file, O_RDWR|O_CREAT, &dbblock, FALSE, TRUE)))
      continue;

    if (Ustrcmp(field, "d") == 0)
      {
      if (*value)
	printf("unexpected value after \"d\"\n");
      else
	printf("%s\n", dbfn_delete(dbm, name) < 0 ?  "not found" : "deleted");
      dbfn_close(dbm);
      continue;
      }

    else if (dbdata_type == type_dbm || isdigit((uschar)field[0]))
      {
      if (!*value)
        {
        printf("value missing\n");
        dbfn_close(dbm);
        continue;
        }
      else if (!(record = dbfn_read_with_length(dbm, name, &oldlength)))
	printf("not found\n");
      else
	{
	int fieldno = Uatoi(field);
	time_t tt;
	/*int length = 0;      Stops compiler warning */

	newlength = oldlength;
	switch(dbdata_type)
	  {
	  case type_retry:
	    retry = (dbdata_retry *)record;
	    /* length = sizeof(dbdata_retry) + Ustrlen(retry->text); */

	    switch(fieldno)
	      {
	      case 0: retry->basic_errno = Uatoi(value);
		      break;
	      case 1: retry->more_errno = Uatoi(value);
		      break;
	      case 2: if ((tt = read_time(value)) > 0) retry->first_failed = tt;
		      else printf("bad time value\n");
		      break;
	      case 3: if ((tt = read_time(value)) > 0) retry->last_try = tt;
		      else printf("bad time value\n");
		      break;
	      case 4: if ((tt = read_time(value)) > 0) retry->next_try = tt;
		      else printf("bad time value\n");
		      break;
	      case 5: if (Ustrcmp(value, "yes") == 0) retry->expired = TRUE;
		      else if (Ustrcmp(value, "no") == 0) retry->expired = FALSE;
		      else printf("\"yes\" or \"no\" expected=n");
		      break;
	      default: printf("unknown field number\n");
		       verify = 0;
		       break;
	      }
	    break;

	  case type_wait:
	    printf("Can't change contents of wait database record\n");
	    break;

	  case type_misc:
	    printf("Can't change contents of misc database record\n");
	    break;

	  case type_callout:
	    callout = (dbdata_callout_cache *)record;
	    /* length = sizeof(dbdata_callout_cache); */
	    switch(fieldno)
	      {
	      case 0: callout->result = Uatoi(value);
		      break;
	      case 1: callout->postmaster_result = Uatoi(value);
		      break;
	      case 2: callout->random_result = Uatoi(value);
		      break;
	      default: printf("unknown field number\n");
		       verify = 0;
		       break;
	      }
	      break;

	  case type_ratelimit:
	    ratelimit = (dbdata_ratelimit *)record;
	    switch(fieldno)
	      {
	      case 0: if ((tt = read_time(value)) > 0)
			ratelimit->gen.time_stamp = tt;
		      else
			printf("bad time value\n");
		      break;
	      case 1: ratelimit->time_usec = Uatoi(value);
		      break;
	      case 2: ratelimit->rate = Ustrtod(value, NULL);
		      break;
	      case 3: if (Ustrstr(name, "/unique/") != NULL
			  && oldlength >= sizeof(dbdata_ratelimit_unique))
			{
			rate_unique = (dbdata_ratelimit_unique *)record;
			if ((tt = read_time(value)) > 0) rate_unique->bloom_epoch = tt;
			  else printf("bad time value\n");
			break;
			}
		      /* else fall through */
	      case 4:
	      case 5: if (Ustrstr(name, "/unique/") != NULL
			  && oldlength >= sizeof(dbdata_ratelimit_unique))
			{
			/* see acl.c */
			BOOL seen;
			unsigned hash, hinc;
			uschar md5sum[16];
			md5 md5info;
			md5_start(&md5info);
			md5_end(&md5info, value, Ustrlen(value), md5sum);
			hash = md5sum[0] <<  0 | md5sum[1] <<  8
			     | md5sum[2] << 16 | md5sum[3] << 24;
			hinc = md5sum[4] <<  0 | md5sum[5] <<  8
			     | md5sum[6] << 16 | md5sum[7] << 24;
			rate_unique = (dbdata_ratelimit_unique *)record;
			seen = TRUE;
			for (unsigned n = 0; n < 8; n++, hash += hinc)
			  {
			  int bit = 1 << (hash % 8);
			  int byte = (hash / 8) % rate_unique->bloom_size;
			  if ((rate_unique->bloom[byte] & bit) == 0)
			    {
			    seen = FALSE;
			    if (fieldno == 5) rate_unique->bloom[byte] |= bit;
			    }
			  }
			printf("%s %s\n",
			  seen ? "seen" : fieldno == 5 ? "added" : "unseen", value);
			break;
			}
		      /* else fall through */
	      default: printf("unknown field number\n");
		       verify = 0;
		       break;
	      }
	    break;

	  case type_tls:
	    printf("Can't change contents of tls database record\n");
	    break;

	  case type_dbm:
	    record = value;
	    newlength = Ustrlen(value);
	    break;
	  }

	if (dbdata_type != type_dbm)
	  {
	  dbdata_generic * p = (dbdata_generic *)record;
	  p->time_stamp = time(NULL);
	  p->tainted = FALSE;
	  }

	dbfn_write(dbm, name, record, newlength);
	}
      }

    else
      {
      printf("field number or d expected\n");
      verify = 0;
      }

    dbfn_close(dbm);
    if (!verify) continue;
    }

  /* The "name" q causes an exit */

  else if (Ustrcmp(name, "q") == 0) return 0;

  /* Handle a read request, or verify after an update. */

  if (!(dbm = dbfn_open(file, O_RDONLY, &dbblock, FALSE, TRUE)))
    continue;

  if (!(record = dbfn_read_with_length(dbm, name, &oldlength)))
    {
    printf("record %s not found\n", name);
    *name = '\0';
    }
  else
    {
    int count_bad = 0;

    if (dbdata_type != type_dbm)
      printf("%s\n", CS print_time(((dbdata_generic *)record)->time_stamp));

    switch(dbdata_type)
      {
      case type_retry:
	retry = (dbdata_retry *)record;
	printf("0 error number: %d %s\n", retry->basic_errno, retry->text);
	printf("1 extra data:   %d\n", retry->more_errno);
	printf("2 first failed: %s\n", print_time(retry->first_failed));
	printf("3 last try:     %s\n", print_time(retry->last_try));
	printf("4 next try:     %s\n", print_time(retry->next_try));
	printf("5 expired:      %s\n", retry->expired ? "yes" : "no");
	break;

      case type_wait:
	wait = (dbdata_wait *)record;
	t = wait->text;
	printf("Sequence: %d\n", wait->sequence);
	if (wait->count > WAIT_NAME_MAX)
	  {
	  printf("**** Data corrupted: count=%d=0x%x max=%d ****\n", wait->count,
	    wait->count, WAIT_NAME_MAX);
	  wait->count = WAIT_NAME_MAX;
	  count_bad = 1;
	  }
	for (int i = 1; i <= wait->count; i++)
	  {
	  Ustrncpy(value, t, MESSAGE_ID_LENGTH);
	  value[MESSAGE_ID_LENGTH] = 0;
	  if (count_bad && value[0] == 0) break;
	  if (Ustrlen(value) != MESSAGE_ID_LENGTH ||
	      Ustrspn(value, "0123456789"
			    "abcdefghijklmnopqrstuvwxyz"
			    "ABCDEFGHIJKLMNOPQRSTUVWXYZ-") != MESSAGE_ID_LENGTH)
	    {
	    printf("\n**** Data corrupted: bad character in message id ****\n");
	    for (int j = 0; j < MESSAGE_ID_LENGTH; j++)
	      printf("%02x ", value[j]);
	    printf("\n");
	    break;
	    }
	  printf("%s ", value);
	  t += MESSAGE_ID_LENGTH;
	  }
	printf("\n");
	break;

      case type_misc:
	break;

      case type_callout:
	callout = (dbdata_callout_cache *)record;
	printf("0 callout:    %s (%d)\n", print_cache(callout->result),
	    callout->result);
	if (oldlength > sizeof(dbdata_callout_cache_address))
	  {
	  printf("1 postmaster: %s (%d)\n", print_cache(callout->postmaster_result),
	      callout->postmaster_result);
	  printf("2 random:     %s (%d)\n", print_cache(callout->random_result),
	      callout->random_result);
	  }
	break;

      case type_ratelimit:
	ratelimit = (dbdata_ratelimit *)record;
	printf("0 time stamp:  %s\n", print_time(ratelimit->gen.time_stamp));
	printf("1 fract. time: .%06d\n", ratelimit->time_usec);
	printf("2 sender rate: % .3f\n", ratelimit->rate);
	if (Ustrstr(name, "/unique/") != NULL
	 && oldlength >= sizeof(dbdata_ratelimit_unique))
	 {
	 rate_unique = (dbdata_ratelimit_unique *)record;
	 printf("3 filter epoch: %s\n", print_time(rate_unique->bloom_epoch));
	 printf("4 test filter membership\n");
	 printf("5 add element to filter\n");
	 }
	break;

      case type_tls:
	session = (dbdata_tls_session *)record;
	printf("0 time stamp:  %s\n", print_time(session->gen.time_stamp));
	printf("1 session: .%s\n", session->session);
	break;

      case type_dbm:
	printf("0 value:  %.*s\n", oldlength, CS record);
      }
    }

  /* The database is closed after each request */

  dbfn_close(dbm);
  }

printf("\n");
return 0;
}

#endif  /* EXIM_FIXDB */



#ifdef EXIM_TIDYDB
/*************************************************
*           The exim_tidydb main program         *
*************************************************/


/* Utility program to tidy the contents of an exim database file. There is one
option:

   -t <time>  expiry time for old records - default 30 days

For backwards compatibility, an -f option is recognized and ignored. (It used
to request a "full" tidy. This version always does the whole job.) */


typedef struct key_item {
  struct key_item *next;
  uschar key[1];
} key_item;


int
main(int argc, char **cargv)
{
struct stat statbuf;
int maxkeep = 30 * 24 * 60 * 60;
int dbdata_type, i, oldest, path_len;
key_item *keychain = NULL;
rmark reset_point;
open_db dbblock;
open_db *dbm;
EXIM_CURSOR *cursor;
uschar **argv = USS cargv;
uschar buffer[256];
uschar *key;

store_init();

/* Scan the options */

for (i = 1; i < argc; i++)
  {
  if (argv[i][0] != '-') break;
  if (Ustrcmp(argv[i], "-f") == 0) continue;
  if (Ustrcmp(argv[i], "-t") == 0)
    {
    uschar *s;
    s = argv[++i];
    maxkeep = 0;
    while (*s != 0)
      {
      int value, count;
      if (!isdigit(*s)) usage(US"tidydb", US" [-t <time>]");
      (void)sscanf(CS s, "%d%n", &value, &count);
      s += count;
      switch (*s)
        {
        case 'w': value *= 7;
        case 'd': value *= 24;
        case 'h': value *= 60;
        case 'm': value *= 60;
        case 's': s++;
        break;
        default: usage(US"tidydb", US" [-t <time>]");
        }
      maxkeep += value;
      }
    }
  else usage(US"tidydb", US" [-t <time>]");
  }

/* Adjust argument values and process arguments */

argc -= --i;
argv += i;

dbdata_type = check_args(argc, argv, US"tidydb", US" [-t <time>]");

/* Compute the oldest keep time, verify what we are doing, and open the
database */

oldest = time(NULL) - maxkeep;
printf("Tidying Exim hints database %s/db/%s\n", argv[1], argv[2]);

spool_directory = argv[1];
if (!(dbm = dbfn_open(argv[2], O_RDWR|O_CREAT, &dbblock, FALSE, TRUE)))
  exit(EXIT_FAILURE);

/* Prepare for building file names */

sprintf(CS buffer, "%s/input/", argv[1]);
path_len = Ustrlen(buffer);


/* It appears, by experiment, that it is a bad idea to make changes
to the file while scanning it. Pity the man page doesn't warn you about that.
Therefore, we scan and build a list of all the keys. Then we use that to
read the records and possibly update them. */

for (key = dbfn_scan(dbm, TRUE, &cursor);
     key;
     key = dbfn_scan(dbm, FALSE, &cursor))
  {
  key_item * k = store_get(sizeof(key_item) + Ustrlen(key), key);
  k->next = keychain;
  keychain = k;
  Ustrcpy(k->key, key);
  }

/* Now scan the collected keys and operate on the records, resetting
the store each time round. */

for (; keychain && (reset_point = store_mark()); store_reset(reset_point))
  {
  dbdata_generic * value;
  int size = 0;

  key = keychain->key;
  keychain = keychain->next;
  value = dbfn_read_with_length(dbm, key, &size);

  /* A continuation record may have been deleted or renamed already, so
  non-existence is not serious. Also, for a back-version record we get
  a null value - so attempt a delete. */

  if (!value)
    {
    if (size)
      {
      printf(" deleted %s (bad record version)\n", key);
      dbfn_delete(dbm, key);
      }
    continue;
    }

  /* Delete if too old */

  if (value->time_stamp < oldest)
    {
    printf("deleted %s (too old)\n", key);
    dbfn_delete(dbm, key);
    continue;
    }

  /* Do database-specific tidying for wait databases, and message-
  specific tidying for the retry database. */

  if (dbdata_type == type_wait)
    {
    dbdata_wait *wait = (dbdata_wait *)value;
    BOOL update = FALSE;

    /* Leave corrupt records alone */

    if (wait->gen.time_stamp > time(NULL))
      {
      printf("**** Data for '%s' corrupted\n  time in future: %s\n",
        key, print_time(wait->gen.time_stamp));
      continue;
      }
    if (wait->count > WAIT_NAME_MAX)
      {
      printf("**** Data for '%s' corrupted\n  count=%d=0x%x max=%d\n",
        key, wait->count, wait->count, WAIT_NAME_MAX);
      continue;
      }
    if (wait->sequence > WAIT_CONT_MAX)
      {
      printf("**** Data for '%s' corrupted\n  sequence=%d=0x%x max=%d\n",
        key, wait->sequence, wait->sequence, WAIT_CONT_MAX);
      continue;
      }

    /* Record over 1 year old; just remove it */

    if (wait->gen.time_stamp < time(NULL) - 365*24*60*60)
      {
      dbfn_delete(dbm, key);
      printf("deleted %s (too old)\n", key);
      continue;
      }

    /* Loop for renamed continuation records. For each message id,
    check to see if the message exists, and if not, remove its entry
    from the record. Because of the possibility of split input directories,
    we must look in both possible places for a -D file. */

    for (;;)
      {
      int length = wait->count * MESSAGE_ID_LENGTH;

      for (int offset = length - MESSAGE_ID_LENGTH;
           offset >= 0; offset -= MESSAGE_ID_LENGTH)
        {
        Ustrncpy(buffer+path_len, wait->text + offset, MESSAGE_ID_LENGTH);
        sprintf(CS(buffer+path_len + MESSAGE_ID_LENGTH), "-D");

        if (Ustat(buffer, &statbuf) != 0)
          {
          buffer[path_len] = wait->text[offset+5];
          buffer[path_len+1] = '/';
          Ustrncpy(buffer+path_len+2, wait->text + offset, MESSAGE_ID_LENGTH);
          sprintf(CS(buffer+path_len+2 + MESSAGE_ID_LENGTH), "-D");

          if (Ustat(buffer, &statbuf) != 0)
            {
            int left = length - offset - MESSAGE_ID_LENGTH;
            if (left > 0) Ustrncpy(wait->text + offset,
              wait->text + offset + MESSAGE_ID_LENGTH, left);
            wait->count--;
            length -= MESSAGE_ID_LENGTH;
            update = TRUE;
            }
          }
        }

      /* If record is empty and the main record, either delete it or rename
      the next continuation, repeating if that is also empty. */

      if (wait->count == 0 && Ustrchr(key, ':') == NULL)
        {
        while (wait->count == 0 && wait->sequence > 0)
          {
          uschar newkey[256];
          dbdata_generic *newvalue;
          sprintf(CS newkey, "%s:%d", key, wait->sequence - 1);
          newvalue = dbfn_read_with_length(dbm, newkey, NULL);
          if (newvalue != NULL)
            {
            value = newvalue;
            wait = (dbdata_wait *)newvalue;
            dbfn_delete(dbm, newkey);
            printf("renamed %s\n", newkey);
            update = TRUE;
            }
          else wait->sequence--;
          }

        /* If we have ended up with an empty main record, delete it
        and break the loop. Otherwise the new record will be scanned. */

        if (wait->count == 0 && wait->sequence == 0)
          {
          dbfn_delete(dbm, key);
          printf("deleted %s (empty)\n", key);
          update = FALSE;
          break;
          }
        }

      /* If not an empty main record, break the loop */

      else break;
      }

    /* Re-write the record if required */

    if (update)
      {
      printf("updated %s\n", key);
      wait->gen.time_stamp = time(NULL);
      /* leave the taint marker unchanged */
      dbfn_write(dbm, key, wait, sizeof(dbdata_wait) +
        wait->count * MESSAGE_ID_LENGTH);
      }
    }

  /* If a retry record's key ends with a message-id, check that that message
  still exists; if not, remove this record. */

  else if (dbdata_type == type_retry)
    {
    uschar *id;
    int len = Ustrlen(key);

    if (len < MESSAGE_ID_LENGTH + 1) continue;
    id = key + len - MESSAGE_ID_LENGTH - 1;
    if (*id++ != ':') continue;

    for (i = 0; i < MESSAGE_ID_LENGTH; i++)
      if (i == 6 || i == 13)
        { if (id[i] != '-') break; }
      else
        { if (!isalnum(id[i])) break; }
    if (i < MESSAGE_ID_LENGTH) continue;

    Ustrncpy(buffer + path_len, id, MESSAGE_ID_LENGTH);
    sprintf(CS(buffer + path_len + MESSAGE_ID_LENGTH), "-D");

    if (Ustat(buffer, &statbuf) != 0)
      {
      sprintf(CS(buffer + path_len), "%c/%s-D", id[5], id);
      if (Ustat(buffer, &statbuf) != 0)
        {
        dbfn_delete(dbm, key);
        printf("deleted %s (no message)\n", key);
        }
      }
    }
  }

dbfn_close(dbm);
printf("Tidying complete\n");
return 0;
}

#endif  /* EXIM_TIDYDB */

/* End of exim_dbutil.c */
/* vi: aw ai sw=2
*/
