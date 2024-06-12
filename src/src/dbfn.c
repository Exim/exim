/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */


#include "exim.h"

/* We have buffers holding path names for database files.
PATH_MAX could be used here, but would be wasting memory, as we deal
with database files like $spooldirectory/db/<name> */
#define PATHLEN 256


/* Functions for accessing Exim's hints database, which consists of a number of
different DBM files. This module does not contain code for reading DBM files
for (e.g.) alias expansion. That is all contained within the general search
functions. As Exim now has support for several DBM interfaces, all the relevant
functions are called as inlinable functions from an included file.

All the data in Exim's database is in the nature of *hints*. Therefore it
doesn't matter if it gets destroyed by accident. These functions are not
supposed to implement a "safe" database.

Keys are passed in as C strings, and the terminating zero *is* used when
building the dbm files. This just makes life easier when scanning the files
sequentially.

Synchronization is required on the database files, and this is achieved by
means of locking on independent lock files. (Earlier attempts to lock on the
DBM files themselves were never completely successful.) Since callers may in
general want to do more than one read or write while holding the lock, there
are separate open and close functions. However, the calling modules should
arrange to hold the locks for the bare minimum of time.

API:
  dbfn_open
  dbfn_close
  dbfn_read_with_length
  dbfn_read_enforce_length
  dbfn_write
  dbfn_delete
  dbfn_scan				unused; ifdeffout out

Users:
  ACL ratelimit & seen conditions
  delivery retry handling
  delivery serialization
  TLS session resumption
  peer capability cache
  callout & quota cache
*/



/*************************************************
*          Open and lock a database file         *
*************************************************/

/* Ensure the directory for the DB is present */

static inline void
db_dir_make(BOOL panic)
{
(void) directory_make(spool_directory, US"db", EXIMDB_DIRECTORY_MODE, panic);
}


/* Lock a file to protect the DB.  Return TRUE for success */

static inline BOOL
lockfile_take(open_db * dbblock, const uschar * filename, BOOL rdonly, BOOL panic)
{
flock_t lock_data;
int rc, * fdp = &dbblock->lockfd;

priv_drop_temp(exim_uid, exim_gid);
if ((*fdp = Uopen(filename, O_RDWR, EXIMDB_LOCKFILE_MODE)) < 0)
  {
  db_dir_make(panic);
  *fdp = Uopen(filename, O_RDWR|O_CREAT, EXIMDB_LOCKFILE_MODE);
  }
priv_restore();

if (*fdp < 0)
  {
  log_write(0, LOG_MAIN, "%s",
    string_open_failed("database lock file %s", filename));
  errno = 0;      /* Indicates locking failure */
  return FALSE;
  }

/* Now we must get a lock on the opened lock file; do this with a blocking
lock that times out. */

lock_data.l_type = rdonly ? F_RDLCK : F_WRLCK;
lock_data.l_whence = lock_data.l_start = lock_data.l_len = 0;

DEBUG(D_hints_lookup|D_retry|D_route|D_deliver)
  debug_printf_indent("locking %s\n", filename);

sigalrm_seen = FALSE;
ALARM(EXIMDB_LOCK_TIMEOUT);
rc = fcntl(*fdp, F_SETLKW, &lock_data);
ALARM_CLR(0);

if (sigalrm_seen) errno = ETIMEDOUT;
if (rc < 0)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "Failed to get %s lock for %s: %s",
    rdonly ? "read" : "write", filename,
    errno == ETIMEDOUT ? "timed out" : strerror(errno));
  (void)close(*fdp); *fdp = -1;
  errno = 0;       /* Indicates locking failure */
  return FALSE;
  }

DEBUG(D_hints_lookup) debug_printf_indent("locked  %s\n", filename);
return TRUE;
}

/* Used for accessing Exim's hints databases.

Arguments:
  name     The single-component name of one of Exim's database files.
  flags    Either O_RDONLY or O_RDWR, indicating the type of open required;
             O_RDWR implies "create if necessary"
  dbblock  Points to an open_db block to be filled in.
  lof      If TRUE, write to the log for actual open failures (locking failures
           are always logged).
  panic	   If TRUE, panic on failure to create the db directory

Returns:   NULL if the open failed, or the locking failed. After locking
           failures, errno is zero.

           On success, dbblock is returned. This contains the dbm pointer and
           the fd of the locked lock file.
*/

open_db *
dbfn_open(const uschar * name, int flags, open_db * dbblock,
  BOOL lof, BOOL panic)
{
int rc, save_errno;
flock_t lock_data;
uschar dirname[PATHLEN], filename[PATHLEN];

DEBUG(D_hints_lookup) acl_level++;

/* The first thing to do is to open a separate file on which to lock. This
ensures that Exim has exclusive use of the database before it even tries to
open it. Early versions tried to lock on the open database itself, but that
gave rise to mysterious problems from time to time - it was suspected that some
DB libraries "do things" on their open() calls which break the interlocking.
The lock file is never written to, but we open it for writing so we can get a
write lock if required. If it does not exist, we create it. This is done
separately so we know when we have done it, because when running as root we
need to change the ownership - see the bottom of this function. We also try to
make the directory as well, just in case. We won't be doing this many times
unnecessarily, because usually the lock file will be there. If the directory
exists, there is no error. */

snprintf(CS dirname, sizeof(dirname), "%s/db", spool_directory);
snprintf(CS filename, sizeof(filename), "%s/%s.lockfile", dirname, name);

dbblock->lockfd = -1;
if (!exim_lockfile_needed())
  db_dir_make(panic);
else
  {
  if (!lockfile_take(dbblock, filename, flags == O_RDONLY, panic))
    {
    DEBUG(D_hints_lookup) acl_level--;
    return NULL;
    }
  }

/* At this point we have an opened and locked separate lock file, that is,
exclusive access to the database, so we can go ahead and open it. If we are
expected to create it, don't do so at first, again so that we can detect
whether we need to change its ownership (see comments about the lock file
above.) There have been regular reports of crashes while opening hints
databases - often this is caused by non-matching db.h and the library. To make
it easy to pin this down, there are now debug statements on either side of the
open call. */

flags &= O_RDONLY | O_RDWR;
snprintf(CS filename, sizeof(filename), "%s/%s", dirname, name);

priv_drop_temp(exim_uid, exim_gid);
dbblock->dbptr = exim_dbopen(filename, dirname, flags, EXIMDB_MODE);
if (!dbblock->dbptr && errno == ENOENT && flags == O_RDWR)
  {
  DEBUG(D_hints_lookup)
    debug_printf_indent("%s appears not to exist: trying to create\n", filename);
  dbblock->dbptr = exim_dbopen(filename, dirname, flags|O_CREAT, EXIMDB_MODE);
  }
save_errno = errno;
priv_restore();

/* If the open has failed, return NULL, leaving errno set. If lof is TRUE,
log the event - also for debugging - but debug only if the file just doesn't
exist. */

if (!dbblock->dbptr)
  {
  errno = save_errno;
  if (lof && save_errno != ENOENT)
    log_write(0, LOG_MAIN, "%s", string_open_failed("DB file %s",
        filename));
  else
    DEBUG(D_hints_lookup)
      debug_printf_indent("%s\n", CS string_open_failed("DB file %s",
          filename));
  (void)close(dbblock->lockfd);
  dbblock->lockfd = -1;
  errno = save_errno;
  DEBUG(D_hints_lookup) acl_level--;
  return NULL;
  }

DEBUG(D_hints_lookup)
  debug_printf_indent("opened hints database %s: flags=%s\n", filename,
    flags == O_RDONLY ? "O_RDONLY"
    : flags == O_RDWR ? "O_RDWR"
    : "??");

/* Pass back the block containing the opened database handle and the open fd
for the lock. */

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
dbfn_close(open_db *dbblock)
{
int * fdp = &dbblock->lockfd;

exim_dbclose(dbblock->dbptr);
if (*fdp >= 0) (void)close(*fdp);
DEBUG(D_hints_lookup)
  {
  debug_printf_indent("closed hints database%s\n",
		      *fdp < 0 ? "" : " and lockfile");
  acl_level--;
  }
*fdp = -1;
}




/*************************************************
*             Read from database file            *
*************************************************/

/* Passing back the pointer unchanged is useless, because there is
no guarantee of alignment. Since all the records used by Exim need
to be properly aligned to pick out the timestamps, etc., we might as
well do the copying centrally here.

Most calls don't need the length, so there is a macro called dbfn_read which
has two arguments; it calls this function adding NULL as the third.

Arguments:
  dbblock   a pointer to an open database block
  key       the key of the record to be read
  length    a pointer to an int into which to return the length, if not NULL

Returns: a pointer to the retrieved record, or
         NULL if the record is not found
*/

void *
dbfn_read_with_length(open_db * dbblock, const uschar * key, int * length)
{
void * yield;
EXIM_DATUM key_datum, result_datum;
int klen = Ustrlen(key) + 1;
uschar * key_copy = store_get(klen, key);
unsigned dlen;

memcpy(key_copy, key, klen);

DEBUG(D_hints_lookup) debug_printf_indent("dbfn_read: key=%s\n", key);

exim_datum_init(&key_datum);         /* Some DBM libraries require the datum */
exim_datum_init(&result_datum);      /* to be cleared before use. */
exim_datum_data_set(&key_datum, key_copy);
exim_datum_size_set(&key_datum, klen);

if (!exim_dbget(dbblock->dbptr, &key_datum, &result_datum))
  {
  DEBUG(D_hints_lookup) debug_printf_indent("dbfn_read: null return\n");
  return NULL;
  }

/* Assume the data store could have been tainted.  Properly, we should
store the taint status with the data. */

dlen = exim_datum_size_get(&result_datum);
yield = store_get(dlen, GET_TAINTED);
memcpy(yield, exim_datum_data_get(&result_datum), dlen);
DEBUG(D_hints_lookup) debug_printf_indent("dbfn_read: size %u return\n", dlen);
if (length) *length = dlen;

exim_datum_free(&result_datum);    /* Some DBM libs require freeing */
return yield;
}


/* Read a record.  If the length is not as expected then delete it, write
an error log line, delete the record and return NULL.
Use this for fixed-size records (so not retry or wait records).

Arguments:
  dbblock   a pointer to an open database block
  key       the key of the record to be read
  length    the expected record length

Returns: a pointer to the retrieved record, or
         NULL if the record is not found/bad
*/

void *
dbfn_read_enforce_length(open_db * dbblock, const uschar * key, size_t length)
{
int rlen;
void * yield = dbfn_read_with_length(dbblock, key, &rlen);

if (yield)
  {
  if (rlen == length) return yield;
  log_write(0, LOG_MAIN|LOG_PANIC, "Bad db record size for '%s'", key);
  dbfn_delete(dbblock, key);
  }
return NULL;
}


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
dbfn_write(open_db *dbblock, const uschar *key, void *ptr, int length)
{
EXIM_DATUM key_datum, value_datum;
dbdata_generic *gptr = (dbdata_generic *)ptr;
int klen = Ustrlen(key) + 1;
uschar * key_copy = store_get(klen, key);

memcpy(key_copy, key, klen);
gptr->time_stamp = time(NULL);

DEBUG(D_hints_lookup)
  debug_printf_indent("dbfn_write: key=%s datalen %d\n", key, length);

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

DEBUG(D_hints_lookup) debug_printf_indent("dbfn_delete: key=%s\n", key);

memcpy(key_copy, key, klen);
exim_datum_init(&key_datum);         /* Some DBM libraries require clearing */
exim_datum_data_set(&key_datum, key_copy);
exim_datum_size_set(&key_datum, klen);
return exim_dbdel(dbblock->dbptr, &key_datum);
}



#ifdef notdef
/* XXX This appears to be unused.  There's a separate implementation
in dbutils.c for dumpdb and fixdb, using the same underlying support.
*/

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

Returns:   the next record from the file, or
           NULL if there are no more
*/

uschar *
dbfn_scan(open_db *dbblock, BOOL start, EXIM_CURSOR **cursor)
{
EXIM_DATUM key_datum, value_datum;
uschar *yield;

DEBUG(D_hints_lookup) debug_printf_indent("dbfn_scan\n");

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
#endif



/*************************************************
**************************************************
*             Stand-alone test program           *
**************************************************
*************************************************/

#ifdef STAND_ALONE

int
main(int argc, char **cargv)
{
open_db dbblock[8];
int max_db = sizeof(dbblock)/sizeof(open_db);
int current = -1;
int showtime = 0;
int i;
dbdata_wait *dbwait = NULL;
uschar **argv = USS cargv;
uschar buffer[256];
uschar structbuffer[1024];

if (argc != 2)
  {
  printf("Usage: test_dbfn directory\n");
  printf("The subdirectory called \"db\" in the given directory is used for\n");
  printf("the files used in this test program.\n");
  return 1;
  }

/* Initialize */

spool_directory = argv[1];
debug_selector = D_all - D_memory;
debug_file = stderr;
big_buffer = malloc(big_buffer_size);

for (i = 0; i < max_db; i++) dbblock[i].dbptr = NULL;

printf("\nExim's db functions tester: interface type is %s\n", EXIM_DBTYPE);
printf("DBM library: ");

#ifdef DB_VERSION_STRING
printf("Berkeley DB: %s\n", DB_VERSION_STRING);
#elif defined(BTREEVERSION) && defined(HASHVERSION)
  #ifdef USE_DB
  printf("probably Berkeley DB version 1.8x (native mode)\n");
  #else
  printf("probably Berkeley DB version 1.8x (compatibility mode)\n");
  #endif
#elif defined(_DBM_RDONLY) || defined(dbm_dirfno)
printf("probably ndbm\n");
#elif defined(USE_TDB)
printf("using tdb\n");
#else
  #ifdef USE_GDBM
  printf("probably GDBM (native mode)\n");
  #else
  printf("probably GDBM (compatibility mode)\n");
  #endif
#endif

/* Test the functions */

printf("\nTest the functions\n> ");

while (Ufgets(buffer, 256, stdin) != NULL)
  {
  int len = Ustrlen(buffer);
  int count = 1;
  clock_t start = 1;
  clock_t stop = 0;
  uschar *cmd = buffer;
  while (len > 0 && isspace((uschar)buffer[len-1])) len--;
  buffer[len] = 0;

  if (isdigit((uschar)*cmd))
    {
    count = Uatoi(cmd);
    while (isdigit((uschar)*cmd)) cmd++;
    Uskip_whitespace(&cmd);
    }

  if (Ustrncmp(cmd, "open", 4) == 0)
    {
    int i;
    open_db *odb;
    uschar *s = cmd + 4;
    Uskip_whitespace(&s);

    for (i = 0; i < max_db; i++)
      if (dbblock[i].dbptr == NULL) break;

    if (i >= max_db)
      {
      printf("Too many open databases\n> ");
      continue;
      }

    start = clock();
    odb = dbfn_open(s, O_RDWR, dbblock + i, TRUE, TRUE);
    stop = clock();

    if (odb)
      {
      current = i;
      printf("opened %d\n", current);
      }
    /* Other error cases will have written messages */
    else if (errno == ENOENT)
      {
      printf("open failed: %s%s\n", strerror(errno),
        #ifdef USE_DB
        " (or other Berkeley DB error)"
        #else
        ""
        #endif
        );
      }
    }

  else if (Ustrncmp(cmd, "write", 5) == 0)
    {
    int rc = 0;
    uschar * key = cmd + 5, * data;

    if (current < 0)
      {
      printf("No current database\n");
      continue;
      }

    Uskip_whitespace(&key);
    data = key;
    Uskip_nonwhite(&data);
    *data++ = '\0';
    Uskip_whitespace(&data);

    dbwait = (dbdata_wait *)(&structbuffer);
    Ustrcpy(dbwait->text, data);

    start = clock();
    while (count-- > 0)
      rc = dbfn_write(dbblock + current, key, dbwait,
        Ustrlen(data) + sizeof(dbdata_wait));
    stop = clock();
    if (rc != 0) printf("Failed: %s\n", strerror(errno));
    }

  else if (Ustrncmp(cmd, "read", 4) == 0)
    {
    uschar * key = cmd + 4;
    if (current < 0)
      {
      printf("No current database\n");
      continue;
      }
    Uskip_whitespace(&key);
    start = clock();
    while (count-- > 0)
      dbwait = (dbdata_wait *)dbfn_read_with_length(dbblock+ current, key, NULL);
    stop = clock();
    printf("%s\n", (dbwait == NULL)? "<not found>" : CS dbwait->text);
    }

  else if (Ustrncmp(cmd, "delete", 6) == 0)
    {
    uschar * key = cmd + 6;
    if (current < 0)
      {
      printf("No current database\n");
      continue;
      }
    Uskip_whitespace(&key);
    dbfn_delete(dbblock + current, key);
    }

  else if (Ustrncmp(cmd, "scan", 4) == 0)
    {
    EXIM_CURSOR *cursor;
    BOOL startflag = TRUE;
    uschar *key;
    uschar keybuffer[256];
    if (current < 0)
      {
      printf("No current database\n");
      continue;
      }
    start = clock();
    while ((key = dbfn_scan(dbblock + current, startflag, &cursor)) != NULL)
      {
      startflag = FALSE;
      Ustrcpy(keybuffer, key);
      dbwait = (dbdata_wait *)dbfn_read_with_length(dbblock + current,
        keybuffer, NULL);
      printf("%s: %s\n", keybuffer, dbwait->text);
      }
    stop = clock();
    printf("End of scan\n");
    }

  else if (Ustrncmp(cmd, "close", 5) == 0)
    {
    uschar * s = cmd + 5;
    Uskip_whitespace(&s);
    i = Uatoi(s);
    if (i >= max_db || dbblock[i].dbptr == NULL) printf("Not open\n"); else
      {
      start = clock();
      dbfn_close(dbblock + i);
      stop = clock();
      dbblock[i].dbptr = NULL;
      if (i == current) current = -1;
      }
    }

  else if (Ustrncmp(cmd, "file", 4) == 0)
    {
    uschar * s = cmd + 4;
    Uskip_whitespace(&s);
    i = Uatoi(s);
    if (i >= max_db || dbblock[i].dbptr == NULL) printf("Not open\n");
      else current = i;
    }

  else if (Ustrncmp(cmd, "time", 4) == 0)
    {
    showtime = ~showtime;
    printf("Timing %s\n", showtime? "on" : "off");
    }

  else if (Ustrcmp(cmd, "q") == 0 || Ustrncmp(cmd, "quit", 4) == 0) break;

  else if (Ustrncmp(cmd, "help", 4) == 0)
    {
    printf("close  [<number>]              close file [<number>]\n");
    printf("delete <key>                   remove record from current file\n");
    printf("file   <number>                make file <number> current\n");
    printf("open   <name>                  open db file\n");
    printf("q[uit]                         exit program\n");
    printf("read   <key>                   read record from current file\n");
    printf("scan                           scan current file\n");
    printf("time                           time display on/off\n");
    printf("write  <key> <rest-of-line>    write record to current file\n");
    }

  else printf("Eh?\n");

  if (showtime && stop >= start)
    printf("start=%d stop=%d difference=%d\n", (int)start, (int)stop,
     (int)(stop - start));

  printf("> ");
  }

for (i = 0; i < max_db; i++)
  {
  if (dbblock[i].dbptr != NULL)
    {
    printf("\nClosing %d", i);
    dbfn_close(dbblock + i);
    }
  }

printf("\n");
return 0;
}

#endif

/* End of dbfn.c */
/* vi: aw ai sw=2
*/
