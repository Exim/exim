/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for writing log files. The code for maintaining datestamped
log files was originally contributed by Tony Sheen. */


#include "exim.h"

#define LOG_NAME_SIZE 256
#define MAX_SYSLOG_LEN 870

#define LOG_MODE_FILE   1
#define LOG_MODE_SYSLOG 2

enum { lt_main, lt_reject, lt_panic, lt_debug };

static uschar *log_names[] = { US"main", US"reject", US"panic", US"debug" };



/*************************************************
*           Local static variables               *
*************************************************/

static uschar mainlog_name[LOG_NAME_SIZE];
static uschar rejectlog_name[LOG_NAME_SIZE];
static uschar debuglog_name[LOG_NAME_SIZE];

static uschar *mainlog_datestamp = NULL;
static uschar *rejectlog_datestamp = NULL;

static int    mainlogfd = -1;
static int    rejectlogfd = -1;
static ino_t  mainlog_inode = 0;
static ino_t  rejectlog_inode = 0;

static uschar *panic_save_buffer = NULL;
static BOOL   panic_recurseflag = FALSE;

static BOOL   syslog_open = FALSE;
static BOOL   path_inspected = FALSE;
static int    logging_mode = LOG_MODE_FILE;
static uschar *file_path = US"";




/*************************************************
*              Write to syslog                   *
*************************************************/

/* The given string is split into sections according to length, or at embedded
newlines, and syslogged as a numbered sequence if it is overlong or if there is
more than one line. However, if we are running in the test harness, do not do
anything. (The test harness doesn't use syslog - for obvious reasons - but we
can get here if there is a failure to open the panic log.)

Arguments:
  priority       syslog priority
  s              the string to be written

Returns:         nothing
*/

static void
write_syslog(int priority, uschar *s)
{
int len, pass;
int linecount = 0;

if (running_in_test_harness) return;

if (!syslog_timestamp) s += log_timezone? 26 : 20;

len = Ustrlen(s);

#ifndef NO_OPENLOG
if (!syslog_open)
  {
  #ifdef SYSLOG_LOG_PID
  openlog(CS syslog_processname, LOG_PID|LOG_CONS, syslog_facility);
  #else
  openlog(CS syslog_processname, LOG_CONS, syslog_facility);
  #endif
  syslog_open = TRUE;
  }
#endif

/* First do a scan through the message in order to determine how many lines
it is going to end up as. Then rescan to output it. */

for (pass = 0; pass < 2; pass++)
  {
  int i;
  int tlen;
  uschar *ss = s;
  for (i = 1, tlen = len; tlen > 0; i++)
    {
    int plen = tlen;
    uschar *nlptr = Ustrchr(ss, '\n');
    if (nlptr != NULL) plen = nlptr - ss;
    #ifndef SYSLOG_LONG_LINES
    if (plen > MAX_SYSLOG_LEN) plen = MAX_SYSLOG_LEN;
    #endif
    tlen -= plen;
    if (ss[plen] == '\n') tlen--;    /* chars left */

    if (pass == 0) linecount++; else
      {
      if (linecount == 1)
        syslog(priority, "%.*s", plen, ss);
      else
        syslog(priority, "[%d%c%d] %.*s", i,
          (ss[plen] == '\n' && tlen != 0)? '\\' : '/',
          linecount, plen, ss);
      }
    ss += plen;
    if (*ss == '\n') ss++;
    }
  }
}



/*************************************************
*             Die tidily                         *
*************************************************/

/* This is called when Exim is dying as a result of something going wrong in
the logging, or after a log call with LOG_PANIC_DIE set. Optionally write a
message to debug_file or a stderr file, if they exist. Then, if in the middle
of accepting a message, throw it away tidily by calling receive_bomb_out();
this will attempt to send an SMTP response if appropriate. Passing NULL as the
first argument stops it trying to run the NOTQUIT ACL (which might try further
logging and thus cause problems). Otherwise, try to close down an outstanding
SMTP call tidily.

Arguments:
  s1         Error message to write to debug_file and/or stderr and syslog
  s2         Error message for any SMTP call that is in progress
Returns:     The function does not return
*/

static void
die(uschar *s1, uschar *s2)
{
if (s1 != NULL)
  {
  write_syslog(LOG_CRIT, s1);
  if (debug_file != NULL) debug_printf("%s\n", s1);
  if (log_stderr != NULL && log_stderr != debug_file)
    fprintf(log_stderr, "%s\n", s1);
  }
if (receive_call_bombout) receive_bomb_out(NULL, s2);  /* does not return */
if (smtp_input) smtp_closedown(s2);
exim_exit(EXIT_FAILURE);
}



/*************************************************
*             Create a log file                  *
*************************************************/

/* This function is called to create and open a log file. It may be called in a
subprocess when the original process is root.

Arguments:
  name         the file name

The file name has been build in a working buffer, so it is permissible to
overwrite it temporarily if it is necessary to create the directory.

Returns:       a file descriptor, or < 0 on failure (errno set)
*/

int
log_create(uschar *name)
{
int fd = Uopen(name, O_CREAT|O_APPEND|O_WRONLY, LOG_MODE);

/* If creation failed, attempt to build a log directory in case that is the
problem. */

if (fd < 0 && errno == ENOENT)
  {
  BOOL created;
  uschar *lastslash = Ustrrchr(name, '/');
  *lastslash = 0;
  created = directory_make(NULL, name, LOG_DIRECTORY_MODE, FALSE);
  DEBUG(D_any) debug_printf("%s log directory %s\n",
    created? "created" : "failed to create", name);
  *lastslash = '/';
  if (created) fd = Uopen(name, O_CREAT|O_APPEND|O_WRONLY, LOG_MODE);
  }

return fd;
}



/*************************************************
*     Create a log file as the exim user         *
*************************************************/

/* This function is called when we are root to spawn an exim:exim subprocess
in which we can create a log file. It must be signal-safe since it is called
by the usr1_handler().

Arguments:
  name         the file name

Returns:       a file descriptor, or < 0 on failure (errno set)
*/

int
log_create_as_exim(uschar *name)
{
pid_t pid = fork();
int status = 1;
int fd = -1;

/* In the subprocess, change uid/gid and do the creation. Return 0 from the
subprocess on success. If we don't check for setuid failures, then the file
can be created as root, so vulnerabilities which cause setuid to fail mean
that the Exim user can use symlinks to cause a file to be opened/created as
root. We always open for append, so can't nuke existing content but it would
still be Rather Bad. */

if (pid == 0)
  {
  if (setgid(exim_gid) < 0)
    die(US"exim: setgid for log-file creation failed, aborting",
      US"Unexpected log failure, please try later");
  if (setuid(exim_uid) < 0)
    die(US"exim: setuid for log-file creation failed, aborting",
      US"Unexpected log failure, please try later");
  _exit((log_create(name) < 0)? 1 : 0);
  }

/* If we created a subprocess, wait for it. If it succeeded, try the open. */

while (pid > 0 && waitpid(pid, &status, 0) != pid);
if (status == 0) fd = Uopen(name, O_APPEND|O_WRONLY, LOG_MODE);

/* If we failed to create a subprocess, we are in a bad way. We return
with fd still < 0, and errno set, letting the caller handle the error. */

return fd;
}




/*************************************************
*                Open a log file                 *
*************************************************/

/* This function opens one of a number of logs, creating the log directory if
it does not exist. This may be called recursively on failure, in order to open
the panic log.

The directory is in the static variable file_path. This is static so that it
the work of sorting out the path is done just once per Exim process.

Exim is normally configured to avoid running as root wherever possible, the log
files must be owned by the non-privileged exim user. To ensure this, first try
an open without O_CREAT - most of the time this will succeed. If it fails, try
to create the file; if running as root, this must be done in a subprocess to
avoid races.

Arguments:
  fd         where to return the resulting file descriptor
  type       lt_main, lt_reject, lt_panic, or lt_debug
  tag        optional tag to include in the name (only hooked up for debug)

Returns:   nothing
*/

static void
open_log(int *fd, int type, uschar *tag)
{
uid_t euid;
BOOL ok, ok2;
uschar buffer[LOG_NAME_SIZE];

/* The names of the log files are controlled by file_path. The panic log is
written to the same directory as the main and reject logs, but its name does
not have a datestamp. The use of datestamps is indicated by %D/%M in file_path.
When opening the panic log, if %D or %M is present, we remove the datestamp
from the generated name; if it is at the start, remove a following
non-alphanumeric character as well; otherwise, remove a preceding
non-alphanumeric character. This is definitely kludgy, but it sort of does what
people want, I hope. */

ok = string_format(buffer, sizeof(buffer), CS file_path, log_names[type]);

/* Save the name of the mainlog for rollover processing. Without a datestamp,
it gets statted to see if it has been cycled. With a datestamp, the datestamp
will be compared. The static slot for saving it is the same size as buffer,
and the text has been checked above to fit, so this use of strcpy() is OK. */

if (type == lt_main)
  {
  Ustrcpy(mainlog_name, buffer);
  mainlog_datestamp = mainlog_name + string_datestamp_offset;
  }

/* Ditto for the reject log */

else if (type == lt_reject)
  {
  Ustrcpy(rejectlog_name, buffer);
  rejectlog_datestamp = rejectlog_name + string_datestamp_offset;
  }

/* and deal with the debug log (which keeps the datestamp, but does not
update it) */

else if (type == lt_debug)
  {
  Ustrcpy(debuglog_name, buffer);
  if (tag)
    {
    /* this won't change the offset of the datestamp */
    ok2 = string_format(buffer, sizeof(buffer), "%s%s",
      debuglog_name, tag);
    if (ok2)
      Ustrcpy(debuglog_name, buffer);
    }
  }

/* Remove any datestamp if this is the panic log. This is rare, so there's no
need to optimize getting the datestamp length. We remove one non-alphanumeric
char afterwards if at the start, otherwise one before. */

else if (string_datestamp_offset >= 0)
  {
  uschar *from = buffer + string_datestamp_offset;
  uschar *to = from + string_datestamp_length;
  if (from == buffer || from[-1] == '/')
    {
    if (!isalnum(*to)) to++;
    }
  else
    {
    if (!isalnum(from[-1])) from--;
    }

  /* This strcpy is ok, because we know that to is a substring of from. */

  Ustrcpy(from, to);
  }

/* If the file name is too long, it is an unrecoverable disaster */

if (!ok)
  {
  die(US"exim: log file path too long: aborting",
      US"Logging failure; please try later");
  }

/* We now have the file name. Try to open an existing file. After a successful
open, arrange for automatic closure on exec(), and then return. */

*fd = Uopen(buffer, O_APPEND|O_WRONLY, LOG_MODE);

if (*fd >= 0)
  {
  (void)fcntl(*fd, F_SETFD, fcntl(*fd, F_GETFD) | FD_CLOEXEC);
  return;
  }

/* Open was not successful: try creating the file. If this is a root process,
we must do the creating in a subprocess set to exim:exim in order to ensure
that the file is created with the right ownership. Otherwise, there can be a
race if another Exim process is trying to write to the log at the same time.
The use of SIGUSR1 by the exiwhat utility can provoke a lot of simultaneous
writing. */

euid = geteuid();

/* If we are already running as the Exim user (even if that user is root),
we can go ahead and create in the current process. */

if (euid == exim_uid) *fd = log_create(buffer);

/* Otherwise, if we are root, do the creation in an exim:exim subprocess. If we
are neither exim nor root, creation is not attempted. */

else if (euid == root_uid) *fd = log_create_as_exim(buffer);

/* If we now have an open file, set the close-on-exec flag and return. */

if (*fd >= 0)
  {
  (void)fcntl(*fd, F_SETFD, fcntl(*fd, F_GETFD) | FD_CLOEXEC);
  return;
  }

/* Creation failed. There are some circumstances in which we get here when
the effective uid is not root or exim, which is the problem. (For example, a
non-setuid binary with log_arguments set, called in certain ways.) Rather than
just bombing out, force the log to stderr and carry on if stderr is available.
*/

if (euid != root_uid && euid != exim_uid && log_stderr != NULL)
  {
  *fd = fileno(log_stderr);
  return;
  }

/* Otherwise this is a disaster. This call is deliberately ONLY to the panic
log. If possible, save a copy of the original line that was being logged. If we
are recursing (can't open the panic log either), the pointer will already be
set. */

if (panic_save_buffer == NULL)
  {
  panic_save_buffer = (uschar *)malloc(LOG_BUFFER_SIZE);
  if (panic_save_buffer != NULL)
    memcpy(panic_save_buffer, log_buffer, LOG_BUFFER_SIZE);
  }

log_write(0, LOG_PANIC_DIE, "Cannot open %s log file \"%s\": %s: "
  "euid=%d egid=%d", log_names[type], buffer, strerror(errno), euid, getegid());
/* Never returns */
}



/*************************************************
*     Add configuration file info to log line    *
*************************************************/

/* This is put in a function because it's needed twice (once for debugging,
once for real).

Arguments:
  ptr         pointer to the end of the line we are building
  flags       log flags

Returns:      updated pointer
*/

static uschar *
log_config_info(uschar *ptr, int flags)
{
Ustrcpy(ptr, "Exim configuration error");
ptr += 24;

if ((flags & (LOG_CONFIG_FOR & ~LOG_CONFIG)) != 0)
  {
  Ustrcpy(ptr, " for ");
  return ptr + 5;
  }

if ((flags & (LOG_CONFIG_IN & ~LOG_CONFIG)) != 0)
  {
  sprintf(CS ptr, " in line %d of %s", config_lineno, config_filename);
  while (*ptr) ptr++;
  }

Ustrcpy(ptr, ":\n  ");
return ptr + 4;
}


/*************************************************
*           A write() operation failed           *
*************************************************/

/* This function is called when write() fails on anything other than the panic
log, which can happen if a disk gets full or a file gets too large or whatever.
We try to save the relevant message in the panic_save buffer before crashing
out.

The potential invoker should probably not call us for EINTR -1 writes.  But
otherwise, short writes are bad as we don't do non-blocking writes to fds
subject to flow control.  (If we do, that's new and the logic of this should
be reconsidered).

Arguments:
  name      the name of the log being written
  length    the string length being written
  rc        the return value from write()

Returns:    does not return
*/

static void
log_write_failed(uschar *name, int length, int rc)
{
int save_errno = errno;

if (panic_save_buffer == NULL)
  {
  panic_save_buffer = (uschar *)malloc(LOG_BUFFER_SIZE);
  if (panic_save_buffer != NULL)
    memcpy(panic_save_buffer, log_buffer, LOG_BUFFER_SIZE);
  }

log_write(0, LOG_PANIC_DIE, "failed to write to %s: length=%d result=%d "
  "errno=%d (%s)", name, length, rc, save_errno,
  (save_errno == 0)? "write incomplete" : strerror(save_errno));
/* Never returns */
}



/*************************************************
*     Write to an fd, retrying after signals     *
*************************************************/

/* Basic write to fd for logs, handling EINTR.

Arguments:
  fd        the fd to write to
  buf       the string to write
  length    the string length being written

Returns:
  length actually written, persisting an errno from write()
*/
ssize_t
write_to_fd_buf(int fd, const uschar *buf, size_t length)
{
ssize_t wrote;
size_t total_written = 0;
const uschar *p = buf;
size_t left = length;

while (1)
  {
  wrote = write(fd, p, left);
  if (wrote == (ssize_t)-1)
    {
    if (errno == EINTR) continue;
    return wrote;
    }
  total_written += wrote;
  if (wrote == left)
    break;
  else
    {
    p += wrote;
    left -= wrote;
    }
  }
return total_written;
}



static void
set_file_path(void)
{
int sep = ':';              /* Fixed separator - outside use */
uschar *t;
const uschar *tt = US LOG_FILE_PATH;
while ((t = string_nextinlist(&tt, &sep, log_buffer, LOG_BUFFER_SIZE)))
  {
  if (Ustrcmp(t, "syslog") == 0 || t[0] == 0) continue;
  file_path = string_copy(t);
  break;
  }
}



/*************************************************
*            Write message to log file           *
*************************************************/

/* Exim can be configured to log to local files, or use syslog, or both. This
is controlled by the setting of log_file_path. The following cases are
recognized:

  log_file_path = ""               write files in the spool/log directory
  log_file_path = "xxx"            write files in the xxx directory
  log_file_path = "syslog"         write to syslog
  log_file_path = "syslog : xxx"   write to syslog and to files (any order)

The message always gets '\n' added on the end of it, since more than one
process may be writing to the log at once and we don't want intermingling to
happen in the middle of lines. To be absolutely sure of this we write the data
into a private buffer and then put it out in a single write() call.

The flags determine which log(s) the message is written to, or for syslogging,
which priority to use, and in the case of the panic log, whether the process
should die afterwards.

The variable really_exim is TRUE only when exim is running in privileged state
(i.e. not with a changed configuration or with testing options such as -brw).
If it is not, don't try to write to the log because permission will probably be
denied.

Avoid actually writing to the logs when exim is called with -bv or -bt to
test an address, but take other actions, such as panicing.

In Exim proper, the buffer for building the message is got at start-up, so that
nothing gets done if it can't be got. However, some functions that are also
used in utilities occasionally obey log_write calls in error situations, and it
is simplest to put a single malloc() here rather than put one in each utility.
Malloc is used directly because the store functions may call log_write().

If a message_id exists, we include it after the timestamp.

Arguments:
  selector  write to main log or LOG_INFO only if this value is zero, or if
              its bit is set in log_write_selector
  flags     each bit indicates some independent action:
              LOG_SENDER      add raw sender to the message
              LOG_RECIPIENTS  add raw recipients list to message
              LOG_CONFIG      add "Exim configuration error"
              LOG_CONFIG_FOR  add " for " instead of ":\n  "
              LOG_CONFIG_IN   add " in line x[ of file y]"
              LOG_MAIN        write to main log or syslog LOG_INFO
              LOG_REJECT      write to reject log or syslog LOG_NOTICE
              LOG_PANIC       write to panic log or syslog LOG_ALERT
              LOG_PANIC_DIE   write to panic log or LOG_ALERT and then crash
  format    a printf() format
  ...       arguments for format

Returns:    nothing
*/

void
log_write(unsigned int selector, int flags, const char *format, ...)
{
uschar *ptr;
int length;
int paniclogfd;
ssize_t written_len;
va_list ap;

/* If panic_recurseflag is set, we have failed to open the panic log. This is
the ultimate disaster. First try to write the message to a debug file and/or
stderr and also to syslog. If panic_save_buffer is not NULL, it contains the
original log line that caused the problem. Afterwards, expire. */

if (panic_recurseflag)
  {
  uschar *extra = (panic_save_buffer == NULL)? US"" : panic_save_buffer;
  if (debug_file != NULL) debug_printf("%s%s", extra, log_buffer);
  if (log_stderr != NULL && log_stderr != debug_file)
    fprintf(log_stderr, "%s%s", extra, log_buffer);
  if (*extra != 0) write_syslog(LOG_CRIT, extra);
  write_syslog(LOG_CRIT, log_buffer);
  die(US"exim: could not open panic log - aborting: see message(s) above",
    US"Unexpected log failure, please try later");
  }

/* Ensure we have a buffer (see comment above); this should never be obeyed
when running Exim proper, only when running utilities. */

if (log_buffer == NULL)
  {
  log_buffer = (uschar *)malloc(LOG_BUFFER_SIZE);
  if (log_buffer == NULL)
    {
    fprintf(stderr, "exim: failed to get store for log buffer\n");
    exim_exit(EXIT_FAILURE);
    }
  }

/* If we haven't already done so, inspect the setting of log_file_path to
determine whether to log to files and/or to syslog. Bits in logging_mode
control this, and for file logging, the path must end up in file_path. This
variable must be in permanent store because it may be required again later in
the process. */

if (!path_inspected)
  {
  BOOL multiple = FALSE;
  int old_pool = store_pool;

  store_pool = POOL_PERM;

  /* If nothing has been set, don't waste effort... the default values for the
  statics are file_path="" and logging_mode = LOG_MODE_FILE. */

  if (*log_file_path)
    {
    int sep = ':';              /* Fixed separator - outside use */
    uschar *s;
    const uschar *ss = log_file_path;
    logging_mode = 0;
    while ((s = string_nextinlist(&ss, &sep, log_buffer, LOG_BUFFER_SIZE)))
      {
      if (Ustrcmp(s, "syslog") == 0)
        logging_mode |= LOG_MODE_SYSLOG;
      else if ((logging_mode & LOG_MODE_FILE) != 0) multiple = TRUE;
      else
        {
        logging_mode |= LOG_MODE_FILE;

        /* If a non-empty path is given, use it */

        if (*s)
          file_path = string_copy(s);

        /* If the path is empty, we want to use the first non-empty, non-
        syslog item in LOG_FILE_PATH, if there is one, since the value of
        log_file_path may have been set at runtime. If there is no such item,
        use the ultimate default in the spool directory. */

        else
	  set_file_path();  /* Empty item in log_file_path */
        }    /* First non-syslog item in log_file_path */
      }      /* Scan of log_file_path */
    }

  /* If no modes have been selected, it is a major disaster */

  if (logging_mode == 0)
    die(US"Neither syslog nor file logging set in log_file_path",
        US"Unexpected logging failure");

  /* Set up the ultimate default if necessary. Then revert to the old store
  pool, and record that we've sorted out the path. */

  if ((logging_mode & LOG_MODE_FILE) != 0 && file_path[0] == 0)
    file_path = string_sprintf("%s/log/%%slog", spool_directory);
  store_pool = old_pool;
  path_inspected = TRUE;

  /* If more than one file path was given, log a complaint. This recursive call
  should work since we have now set up the routing. */

  if (multiple)
    log_write(0, LOG_MAIN|LOG_PANIC,
      "More than one path given in log_file_path: using %s", file_path);
  }

/* If debugging, show all log entries, but don't show headers. Do it all
in one go so that it doesn't get split when multi-processing. */

DEBUG(D_any|D_v)
  {
  int i;
  ptr = log_buffer;

  Ustrcpy(ptr, "LOG:");
  ptr += 4;

  /* Show the options that were passed into the call. These are those whose
  flag values do not have the 0x80000000 bit in them. Note that this
  automatically exclude the "all" setting. */

  for (i = 0; i < log_options_count; i++)
    {
    unsigned int bit = log_options[i].bit;
    if ((bit & 0x80000000) != 0) continue;
    if ((selector & bit) != 0)
      {
      *ptr++ = ' ';
      Ustrcpy(ptr, log_options[i].name);
      while (*ptr) ptr++;
      }
    }

  sprintf(CS ptr, "%s%s%s%s\n  ",
    ((flags & LOG_MAIN) != 0)?    " MAIN"   : "",
    ((flags & LOG_PANIC) != 0)?   " PANIC"  : "",
    ((flags & LOG_PANIC_DIE) == LOG_PANIC_DIE)? " DIE" : "",
    ((flags & LOG_REJECT) != 0)?  " REJECT" : "");

  while(*ptr) ptr++;
  if ((flags & LOG_CONFIG) != 0) ptr = log_config_info(ptr, flags);

  va_start(ap, format);
  if (!string_vformat(ptr, LOG_BUFFER_SIZE - (ptr-log_buffer)-1, format, ap))
    Ustrcpy(ptr, "**** log string overflowed log buffer ****");
  va_end(ap);

  while(*ptr) ptr++;
  Ustrcat(ptr, "\n");
  debug_printf("%s", log_buffer);
  }

/* If no log file is specified, we are in a mess. */

if ((flags & (LOG_MAIN|LOG_PANIC|LOG_REJECT)) == 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "log_write called with no log "
    "flags set");

/* There are some weird circumstances in which logging is disabled. */

if (disable_logging)
  {
  DEBUG(D_any) debug_printf("log writing disabled\n");
  return;
  }

/* Handle disabled reject log */

if (!write_rejectlog) flags &= ~LOG_REJECT;

/* Create the main message in the log buffer. Do not include the message id
when called by a utility. */

ptr = log_buffer;
sprintf(CS ptr, "%s ", tod_stamp(tod_log));
while(*ptr) ptr++;

if ((log_extra_selector & LX_pid) != 0)
  {
  sprintf(CS ptr, "[%d] ", (int)getpid());
  while (*ptr) ptr++;
  }

if (really_exim && message_id[0] != 0)
  {
  sprintf(CS ptr, "%s ", message_id);
  while(*ptr) ptr++;
  }

if ((flags & LOG_CONFIG) != 0) ptr = log_config_info(ptr, flags);

va_start(ap, format);
if (!string_vformat(ptr, LOG_BUFFER_SIZE - (ptr-log_buffer)-1, format, ap))
  Ustrcpy(ptr, "**** log string overflowed log buffer ****\n");
while(*ptr) ptr++;
va_end(ap);

/* Add the raw, unrewritten, sender to the message if required. This is done
this way because it kind of fits with LOG_RECIPIENTS. */

if ((flags & LOG_SENDER) != 0 &&
    ptr < log_buffer + LOG_BUFFER_SIZE - 10 - Ustrlen(raw_sender))
  {
  sprintf(CS ptr, " from <%s>", raw_sender);
  while (*ptr) ptr++;
  }

/* Add list of recipients to the message if required; the raw list,
before rewriting, was saved in raw_recipients. There may be none, if an ACL
discarded them all. */

if ((flags & LOG_RECIPIENTS) != 0 && ptr < log_buffer + LOG_BUFFER_SIZE - 6 &&
     raw_recipients_count > 0)
  {
  int i;
  sprintf(CS ptr, " for");
  while (*ptr) ptr++;
  for (i = 0; i < raw_recipients_count; i++)
    {
    uschar *s = raw_recipients[i];
    if (log_buffer + LOG_BUFFER_SIZE - ptr < Ustrlen(s) + 3) break;
    sprintf(CS ptr, " %s", s);
    while (*ptr) ptr++;
    }
  }

sprintf(CS  ptr, "\n");
while(*ptr) ptr++;
length = ptr - log_buffer;

/* Handle loggable errors when running a utility, or when address testing.
Write to log_stderr unless debugging (when it will already have been written),
or unless there is no log_stderr (expn called from daemon, for example). */

if (!really_exim || log_testing_mode)
  {
  if (debug_selector == 0 && log_stderr != NULL &&
      (selector == 0 || (selector & log_write_selector) != 0))
    {
    if (host_checking)
      fprintf(log_stderr, "LOG: %s", CS(log_buffer + 20));  /* no timestamp */
    else
      fprintf(log_stderr, "%s", CS log_buffer);
    }
  if ((flags & LOG_PANIC_DIE) == LOG_PANIC_DIE) exim_exit(EXIT_FAILURE);
  return;
  }

/* Handle the main log. We know that either syslog or file logging (or both) is
set up. A real file gets left open during reception or delivery once it has
been opened, but we don't want to keep on writing to it for too long after it
has been renamed. Therefore, do a stat() and see if the inode has changed, and
if so, re-open. */

if ((flags & LOG_MAIN) != 0 &&
    (selector == 0 || (selector & log_write_selector) != 0))
  {
  if ((logging_mode & LOG_MODE_SYSLOG) != 0 &&
      (syslog_duplication || (flags & (LOG_REJECT|LOG_PANIC)) == 0))
    write_syslog(LOG_INFO, log_buffer);

  if ((logging_mode & LOG_MODE_FILE) != 0)
    {
    struct stat statbuf;

    /* Check for a change to the mainlog file name when datestamping is in
    operation. This happens at midnight, at which point we want to roll over
    the file. Closing it has the desired effect. */

    if (mainlog_datestamp != NULL)
      {
      uschar *nowstamp = tod_stamp(string_datestamp_type);
      if (Ustrncmp (mainlog_datestamp, nowstamp, Ustrlen(nowstamp)) != 0)
        {
        (void)close(mainlogfd);       /* Close the file */
        mainlogfd = -1;               /* Clear the file descriptor */
        mainlog_inode = 0;            /* Unset the inode */
        mainlog_datestamp = NULL;     /* Clear the datestamp */
        }
      }

    /* Otherwise, we want to check whether the file has been renamed by a
    cycling script. This could be "if else", but for safety's sake, leave it as
    "if" so that renaming the log starts a new file even when datestamping is
    happening. */

    if (mainlogfd >= 0)
      {
      if (Ustat(mainlog_name, &statbuf) < 0 || statbuf.st_ino != mainlog_inode)
        {
        (void)close(mainlogfd);
        mainlogfd = -1;
        mainlog_inode = 0;
        }
      }

    /* If the log is closed, open it. Then write the line. */

    if (mainlogfd < 0)
      {
      open_log(&mainlogfd, lt_main, NULL);     /* No return on error */
      if (fstat(mainlogfd, &statbuf) >= 0) mainlog_inode = statbuf.st_ino;
      }

    /* Failing to write to the log is disastrous */

    written_len = write_to_fd_buf(mainlogfd, log_buffer, length);
    if (written_len != length)
      {
      log_write_failed(US"main log", length, written_len);
      /* That function does not return */
      }
    }
  }

/* Handle the log for rejected messages. This can be globally disabled, in
which case the flags are altered above. If there are any header lines (i.e. if
the rejection is happening after the DATA phase), log the recipients and the
headers. */

if ((flags & LOG_REJECT) != 0)
  {
  header_line *h;

  if (header_list != NULL && (log_extra_selector & LX_rejected_header) != 0)
    {
    if (recipients_count > 0)
      {
      int i;

      /* List the sender */

      string_format(ptr, LOG_BUFFER_SIZE - (ptr-log_buffer),
        "Envelope-from: <%s>\n", sender_address);
      while (*ptr) ptr++;

      /* List up to 5 recipients */

      string_format(ptr, LOG_BUFFER_SIZE - (ptr-log_buffer),
        "Envelope-to: <%s>\n", recipients_list[0].address);
      while (*ptr) ptr++;

      for (i = 1; i < recipients_count && i < 5; i++)
        {
        string_format(ptr, LOG_BUFFER_SIZE - (ptr-log_buffer), "    <%s>\n",
          recipients_list[i].address);
        while (*ptr) ptr++;
        }

      if (i < recipients_count)
        {
        (void)string_format(ptr, LOG_BUFFER_SIZE - (ptr-log_buffer),
          "    ...\n");
        while (*ptr) ptr++;
        }
      }

    /* A header with a NULL text is an unfilled in Received: header */

    for (h = header_list; h != NULL; h = h->next)
      {
      BOOL fitted;
      if (h->text == NULL) continue;
      fitted = string_format(ptr, LOG_BUFFER_SIZE - (ptr-log_buffer),
        "%c %s", h->type, h->text);
      while(*ptr) ptr++;
      if (!fitted)         /* Buffer is full; truncate */
        {
        ptr -= 100;        /* For message and separator */
        if (ptr[-1] == '\n') ptr--;
        Ustrcpy(ptr, "\n*** truncated ***\n");
        while (*ptr) ptr++;
        break;
        }
      }

    length = ptr - log_buffer;
    }

  /* Write to syslog or to a log file */

  if ((logging_mode & LOG_MODE_SYSLOG) != 0 &&
      (syslog_duplication || (flags & LOG_PANIC) == 0))
    write_syslog(LOG_NOTICE, log_buffer);

  /* Check for a change to the rejectlog file name when datestamping is in
  operation. This happens at midnight, at which point we want to roll over
  the file. Closing it has the desired effect. */

  if ((logging_mode & LOG_MODE_FILE) != 0)
    {
    struct stat statbuf;

    if (rejectlog_datestamp != NULL)
      {
      uschar *nowstamp = tod_stamp(string_datestamp_type);
      if (Ustrncmp (rejectlog_datestamp, nowstamp, Ustrlen(nowstamp)) != 0)
        {
        (void)close(rejectlogfd);       /* Close the file */
        rejectlogfd = -1;               /* Clear the file descriptor */
        rejectlog_inode = 0;            /* Unset the inode */
        rejectlog_datestamp = NULL;     /* Clear the datestamp */
        }
      }

    /* Otherwise, we want to check whether the file has been renamed by a
    cycling script. This could be "if else", but for safety's sake, leave it as
    "if" so that renaming the log starts a new file even when datestamping is
    happening. */

    if (rejectlogfd >= 0)
      {
      if (Ustat(rejectlog_name, &statbuf) < 0 ||
           statbuf.st_ino != rejectlog_inode)
        {
        (void)close(rejectlogfd);
        rejectlogfd = -1;
        rejectlog_inode = 0;
        }
      }

    /* Open the file if necessary, and write the data */

    if (rejectlogfd < 0)
      {
      open_log(&rejectlogfd, lt_reject, NULL); /* No return on error */
      if (fstat(rejectlogfd, &statbuf) >= 0) rejectlog_inode = statbuf.st_ino;
      }

    written_len = write_to_fd_buf(rejectlogfd, log_buffer, length);
    if (written_len != length)
      {
      log_write_failed(US"reject log", length, written_len);
      /* That function does not return */
      }
    }
  }


/* Handle the panic log, which is not kept open like the others. If it fails to
open, there will be a recursive call to log_write(). We detect this above and
attempt to write to the system log as a last-ditch try at telling somebody. In
all cases except mua_wrapper, try to write to log_stderr. */

if ((flags & LOG_PANIC) != 0)
  {
  if (log_stderr != NULL && log_stderr != debug_file && !mua_wrapper)
    fprintf(log_stderr, "%s", CS log_buffer);

  if ((logging_mode & LOG_MODE_SYSLOG) != 0)
    {
    write_syslog(LOG_ALERT, log_buffer);
    }

  /* If this panic logging was caused by a failure to open the main log,
  the original log line is in panic_save_buffer. Make an attempt to write it. */

  if ((logging_mode & LOG_MODE_FILE) != 0)
    {
    panic_recurseflag = TRUE;
    open_log(&paniclogfd, lt_panic, NULL);  /* Won't return on failure */
    panic_recurseflag = FALSE;

    if (panic_save_buffer != NULL)
      {
      int i = write(paniclogfd, panic_save_buffer, Ustrlen(panic_save_buffer));
      i = i;	/* compiler quietening */
      }

    written_len = write_to_fd_buf(paniclogfd, log_buffer, length);
    if (written_len != length)
      {
      int save_errno = errno;
      write_syslog(LOG_CRIT, log_buffer);
      sprintf(CS log_buffer, "write failed on panic log: length=%d result=%d "
        "errno=%d (%s)", length, (int)written_len, save_errno, strerror(save_errno));
      write_syslog(LOG_CRIT, log_buffer);
      flags |= LOG_PANIC_DIE;
      }

    (void)close(paniclogfd);
    }

  /* Give up if the DIE flag is set */

  if ((flags & LOG_PANIC_DIE) != LOG_PANIC)
    die(NULL, US"Unexpected failure, please try later");
  }
}



/*************************************************
*            Close any open log files            *
*************************************************/

void
log_close_all(void)
{
if (mainlogfd >= 0)
  { (void)close(mainlogfd); mainlogfd = -1; }
if (rejectlogfd >= 0)
  { (void)close(rejectlogfd); rejectlogfd = -1; }
closelog();
syslog_open = FALSE;
}



/*************************************************
*         Decode bit settings for log/debug      *
*************************************************/

/* This function decodes a string containing bit settings in the form of +name
and/or -name sequences, and sets/unsets bits in a bit string accordingly. It
also recognizes a numeric setting of the form =<number>, but this is not
intended for user use. It's an easy way for Exim to pass the debug settings
when it is re-exec'ed.

The log options are held in two unsigned ints (because there became too many
for one). The top bit in the table means "put in 2nd selector". This does not
yet apply to debug options, so the "=" facility sets only the first selector.

The "all" selector, which must be equal to 0xffffffff, is recognized specially.
It sets all the bits in both selectors. However, there is a facility for then
unsetting certain bits, because we want to turn off "memory" in the debug case.

The action taken for bad values varies depending upon why we're here.
For log messages, or if the debugging is triggered from config, then we write
to the log on the way out.  For debug setting triggered from the command-line,
we treat it as an unknown option: error message to stderr and die.

Arguments:
  selector1      address of the first bit string
  selector2      address of the second bit string, or NULL
  notall1        bits to exclude from "all" for selector1
  notall2        bits to exclude from "all" for selector2
  string         the configured string
  options        the table of option names
  count          size of table
  which          "log" or "debug"
  flags          DEBUG_FROM_CONFIG

Returns:         nothing on success - bomb out on failure
*/

void
decode_bits(unsigned int *selector1, unsigned int *selector2, int notall1,
  int notall2, uschar *string, bit_table *options, int count, uschar *which,
  int flags)
{
uschar *errmsg;
if (string == NULL) return;

if (*string == '=')
  {
  char *end;    /* Not uschar */
  *selector1 = strtoul(CS string+1, &end, 0);
  if (*end == 0) return;
  errmsg = string_sprintf("malformed numeric %s_selector setting: %s", which,
    string);
  goto ERROR_RETURN;
  }

/* Handle symbolic setting */

else for(;;)
  {
  BOOL adding;
  uschar *s;
  int len;
  bit_table *start, *end;

  while (isspace(*string)) string++;
  if (*string == 0) return;

  if (*string != '+' && *string != '-')
    {
    errmsg = string_sprintf("malformed %s_selector setting: "
      "+ or - expected but found \"%s\"", which, string);
    goto ERROR_RETURN;
    }

  adding = *string++ == '+';
  s = string;
  while (isalnum(*string) || *string == '_') string++;
  len = string - s;

  start = options;
  end = options + count;

  while (start < end)
    {
    bit_table *middle = start + (end - start)/2;
    int c = Ustrncmp(s, middle->name, len);
    if (c == 0)
      {
      if (middle->name[len] != 0) c = -1; else
        {
        unsigned int bit = middle->bit;
        unsigned int *selector;

        /* The value with all bits set means "force all bits in both selectors"
        in the case where two are being handled. However, the top bit in the
        second selector is never set. When setting, some bits can be excluded.
        */

        if (bit == 0xffffffff)
          {
          if (adding)
            {
            *selector1 = 0xffffffff ^ notall1;
            if (selector2 != NULL) *selector2 = 0x7fffffff ^ notall2;
            }
          else
            {
            *selector1 = 0;
            if (selector2 != NULL) *selector2 = 0;
            }
          }

        /* Otherwise, the 0x80000000 bit means "this value, without the top
        bit, belongs in the second selector". */

        else
          {
          if ((bit & 0x80000000) != 0)
            {
            selector = selector2;
            bit &= 0x7fffffff;
            }
          else selector = selector1;
          if (adding) *selector |= bit; else *selector &= ~bit;
          }
        break;  /* Out of loop to match selector name */
        }
      }
    if (c < 0) end = middle; else start = middle + 1;
    }  /* Loop to match selector name */

  if (start >= end)
    {
    errmsg = string_sprintf("unknown %s_selector setting: %c%.*s", which,
      adding? '+' : '-', len, s);
    goto ERROR_RETURN;
    }
  }    /* Loop for selector names */

/* Handle disasters */

ERROR_RETURN:
if (Ustrcmp(which, "debug") == 0)
  {
  if (flags & DEBUG_FROM_CONFIG)
    {
    log_write(0, LOG_CONFIG|LOG_PANIC, "%s", errmsg);
    return;
    }
  fprintf(stderr, "exim: %s\n", errmsg);
  exit(EXIT_FAILURE);
  }
else log_write(0, LOG_CONFIG|LOG_PANIC_DIE, "%s", errmsg);
}



/*************************************************
*        Activate a debug logfile (late)         *
*************************************************/

/* Normally, debugging is activated from the command-line; it may be useful
within the configuration to activate debugging later, based on certain
conditions.  If debugging is already in progress, we return early, no action
taken (besides debug-logging that we wanted debug-logging).

Failures in options are not fatal but will result in paniclog entries for the
misconfiguration.

The first use of this is in ACL logic, "control = debug/tag=foo/opts=+expand"
which can be combined with conditions, etc, to activate extra logging only
for certain sources. The second use is inetd wait mode debug preservation. */

void
debug_logging_activate(uschar *tag_name, uschar *opts)
{
int fd = -1;

if (debug_file)
  {
  debug_printf("DEBUGGING ACTIVATED FROM WITHIN CONFIG.\n"
      "DEBUG: Tag=\"%s\" Opts=\"%s\"\n", tag_name, opts ? opts : US"");
  return;
  }

if (tag_name != NULL && (Ustrchr(tag_name, '/') != NULL))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "debug tag may not contain a '/' in: %s",
      tag_name);
  return;
  }

debug_selector = D_default;
if (opts)
  {
  decode_bits(&debug_selector, NULL, D_memory, 0, opts,
      debug_options, debug_options_count, US"debug", DEBUG_FROM_CONFIG);
  }

/* When activating from a transport process we may never have logged at all
resulting in certain setup not having been done.  Hack this for now so we
do not segfault; note that nondefault log locations will not work */

if (!*file_path) set_file_path();

open_log(&fd, lt_debug, tag_name);

if (fd != -1)
  debug_file = fdopen(fd, "w");
else
  log_write(0, LOG_MAIN|LOG_PANIC, "unable to open debug log");
}


/* End of log.c */
