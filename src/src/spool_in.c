/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2023 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Functions for reading spool files. When compiling for a utility (eximon),
not all are needed, and some functionality can be cut out. */


#include "exim.h"



#ifndef COMPILE_UTILITY
/*************************************************
*           Open and lock data file              *
*************************************************/

/* The data file is the one that is used for locking, because the header file
can get replaced during delivery because of header rewriting. The file has
to opened with write access so that we can get an exclusive lock, but in
fact it won't be written to. Just in case there's a major disaster (e.g.
overwriting some other file descriptor with the value of this one), open it
with append.

As called by deliver_message() (at least) we are operating as root.

Argument: the id of the message
Returns:  fd if file successfully opened and locked, else -1

Side effect: message_subdir is set for the (possibly split) spool directory
*/

int
spool_open_datafile(const uschar * id)
{
struct stat statbuf;
flock_t lock_data;
int fd;

/* If split_spool_directory is set (handled by set_subdir_str()), first look for
the file in the appropriate sub-directory of the input directory. If it is not
found there, try the input directory itself, to pick up leftovers from before
the splitting. If split_ spool_directory is not set, first look in the main
input directory. If it is not found there, try the split sub-directory, in case
it is left over from a splitting state. */

for (int i = 0; i < 2; i++)
  {
  uschar * fname;
  int save_errno;

  set_subdir_str(message_subdir, id, i);
  fname = spool_fname(US"input", message_subdir, id, US"-D");
  DEBUG(D_deliver) debug_printf_indent("Trying spool file %s\n", fname);

  /* We protect against symlink attacks both in not propagating the
  file-descriptor to other processes as we exec, and also ensuring that we
  don't even open symlinks.
  No -D file inside the spool area should be a symlink.  */

  if ((fd = Uopen(fname,
		  EXIM_CLOEXEC | EXIM_NOFOLLOW | O_RDWR | O_APPEND, 0)) >= 0)
    break;
  save_errno = errno;
  if (errno == ENOENT)
    {
    if (i == 0) continue;
    if (!f.queue_running)
      log_write(0, LOG_MAIN, "Spool%s%s file %s-D not found",
	*queue_name ? US" Q=" : US"",
	*queue_name ? queue_name : US"",
	id);
    else DEBUG(D_deliver)
      debug_printf("Spool%s%s file %s-D not found\n",
	*queue_name ? US" Q=" : US"",
	*queue_name ? queue_name : US"",
	id);
    }
  else
    log_write(0, LOG_MAIN, "Spool error for %s: %s", fname, strerror(errno));
  errno = save_errno;
  return -1;
  }

/* File is open and message_subdir is set. Set the close-on-exec flag, and lock
the file. We lock only the first line of the file (containing the message ID)
because this apparently is needed for running Exim under Cygwin. If the entire
file is locked in one process, a sub-process cannot access it, even when passed
an open file descriptor (at least, I think that's the Cygwin story). On real
Unix systems it doesn't make any difference as long as Exim is consistent in
what it locks. */

#ifndef O_CLOEXEC
(void)fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

lock_data.l_type = F_WRLCK;
lock_data.l_whence = SEEK_SET;
lock_data.l_start = 0;
lock_data.l_len = spool_data_start_offset(id);

if (fcntl(fd, F_SETLK, &lock_data) < 0)
  {
  log_write(L_skip_delivery, LOG_MAIN,
      "Spool file for %s is locked (another process is handling this message)",
      id);
  (void)close(fd);
  errno = 0;
  return -1;
  }

/* Get the size of the data; don't include the leading filename line
in the count, but add one for the newline before the data. */

if (fstat(fd, &statbuf) == 0)
  {
  message_body_size = statbuf.st_size - spool_data_start_offset(id);
  message_size = message_body_size + 1;
  }

return fd;
}
#endif  /* COMPILE_UTILITY */



/*************************************************
*    Read non-recipients tree from spool file    *
*************************************************/

/* The tree of non-recipients is written to the spool file in a form that
makes it easy to read back into a tree. The format is as follows:

   . Each node is preceded by two letter(Y/N) indicating whether it has left
     or right children. There's one space after the two flags, before the name.

   . The left subtree (if any) then follows, then the right subtree (if any).

This function is entered with the next input line in the buffer. Note we must
save the right flag before recursing with the same buffer.

Once the tree is read, we re-construct the balance fields by scanning the tree.
I forgot to write them out originally, and the compatible fix is to do it this
way. This initial local recursing function does the necessary.

Arguments:
  node      tree node

Returns:    maximum depth below the node, including the node itself
*/

static int
count_below(tree_node *node)
{
int nleft, nright;
if (node == NULL) return 0;
nleft = count_below(node->left);
nright = count_below(node->right);
node->balance = (nleft > nright)? 1 : ((nright > nleft)? 2 : 0);
return 1 + ((nleft > nright)? nleft : nright);
}

/* This is the real function...

Arguments:
  connect      pointer to the root of the tree
  f            FILE to read data from
  buffer       contains next input line; further lines read into it
  buffer_size  size of the buffer

Returns:       FALSE on format error
*/

static BOOL
read_nonrecipients_tree(tree_node **connect, FILE *f, uschar *buffer,
  int buffer_size)
{
tree_node *node;
int n = Ustrlen(buffer);
BOOL right = buffer[1] == 'Y';

if (n < 5) return FALSE;    /* malformed line */
buffer[n-1] = 0;            /* Remove \n */
node = store_get(sizeof(tree_node) + n - 3, GET_TAINTED);	/* rcpt names tainted */
*connect = node;
Ustrcpy(node->name, buffer + 3);
node->data.ptr = NULL;

if (buffer[0] == 'Y')
  {
  if (Ufgets(buffer, buffer_size, f) == NULL ||
    !read_nonrecipients_tree(&node->left, f, buffer, buffer_size))
      return FALSE;
  }
else node->left = NULL;

if (right)
  {
  if (Ufgets(buffer, buffer_size, f) == NULL ||
    !read_nonrecipients_tree(&node->right, f, buffer, buffer_size))
      return FALSE;
  }
else node->right = NULL;

(void) count_below(*connect);
return TRUE;
}




/* Reset all the global variables to their default values. However, there is
one exception. DO NOT change the default value of dont_deliver, because it may
be forced by an external setting. */

void
spool_clear_header_globals(void)
{
acl_var_c = acl_var_m = NULL;
authenticated_id = NULL;
authenticated_sender = NULL;
f.allow_unqualified_recipient = FALSE;
f.allow_unqualified_sender = FALSE;
body_linecount = 0;
body_zerocount = 0;
f.deliver_firsttime = FALSE;
f.deliver_freeze = FALSE;
deliver_frozen_at = 0;
f.deliver_manual_thaw = FALSE;
/* f.dont_deliver must NOT be reset */
header_list = header_last = NULL;
host_lookup_deferred = FALSE;
host_lookup_failed = FALSE;
interface_address = NULL;
interface_port = 0;
f.local_error_message = FALSE;
#ifdef HAVE_LOCAL_SCAN
local_scan_data = NULL;
#endif
max_received_linelength = 0;
message_linecount = 0;
received_protocol = NULL;
received_count = 0;
recipients_list = NULL;
sender_address = NULL;
sender_fullhost = NULL;
sender_helo_name = NULL;
sender_host_address = NULL;
sender_host_name = NULL;
sender_host_port = 0;
sender_host_authenticated = sender_host_auth_pubname = NULL;
sender_ident = NULL;
f.sender_local = FALSE;
f.sender_set_untrusted = FALSE;
smtp_active_hostname = primary_hostname;
#ifndef COMPILE_UTILITY
f.spool_file_wireformat = FALSE;
#endif
tree_nonrecipients = NULL;

#ifdef EXPERIMENTAL_BRIGHTMAIL
bmi_run = 0;
bmi_verdicts = NULL;
#endif

#ifndef DISABLE_DKIM
dkim_signers = NULL;
f.dkim_disable_verify = FALSE;
dkim_collect_input = 0;
#endif

#ifndef DISABLE_TLS
tls_in.certificate_verified = FALSE;
# ifdef SUPPORT_DANE
tls_in.dane_verified = FALSE;
# endif
tls_in.ver = tls_in.cipher = NULL;
# ifndef COMPILE_UTILITY	/* tls support fns not built in */
tls_free_cert(&tls_in.ourcert);
tls_free_cert(&tls_in.peercert);
# endif
tls_in.peerdn = NULL;
tls_in.sni = NULL;
tls_in.ocsp = OCSP_NOT_REQ;
#endif

#ifdef WITH_CONTENT_SCAN
spam_bar = NULL;
spam_score = NULL;
spam_score_int = NULL;
#endif

#if defined(SUPPORT_I18N) && !defined(COMPILE_UTILITY)
message_smtputf8 = FALSE;
message_utf8_downconvert = 0;
#endif

#ifndef COMPILE_UTILITY
debuglog_name[0] = '\0';
#endif
dsn_ret = 0;
dsn_envid = NULL;
}

static void *
fgets_big_buffer(FILE *fp)
{
int len = 0;

big_buffer[0] = 0;
if (Ufgets(big_buffer, big_buffer_size, fp) == NULL) return NULL;

while ((len = Ustrlen(big_buffer)) == big_buffer_size-1
      && big_buffer[len-1] != '\n')
  {
  uschar *newbuffer;
  int newsize;

  if (big_buffer_size >= BIG_BUFFER_SIZE * 4) return NULL;
  newsize = big_buffer_size * 2;
  newbuffer = store_get_perm(newsize, FALSE);
  memcpy(newbuffer, big_buffer, len);

  big_buffer = newbuffer;
  big_buffer_size = newsize;
  if (Ufgets(big_buffer + len, big_buffer_size - len, fp) == NULL) return NULL;
  }

if (len <= 0 || big_buffer[len-1] != '\n') return NULL;
return big_buffer;
}



/*************************************************
*             Read spool header file             *
*************************************************/

/* This function reads a spool header file and places the data into the
appropriate global variables. The header portion is always read, but header
structures are built only if read_headers is set true. It isn't, for example,
while generating -bp output.

It may be possible for blocks of nulls (binary zeroes) to get written on the
end of a file if there is a system crash during writing. It was observed on an
earlier version of Exim that omitted to fsync() the files - this is thought to
have been the cause of that incident, but in any case, this code must be robust
against such an event, and if such a file is encountered, it must be treated as
malformed.

As called from deliver_message() (at least) we are running as root.

Arguments:
  name          name of the header file, including the -H
  read_headers  TRUE if in-store header structures are to be built
  subdir_set    TRUE is message_subdir is already set

Returns:        spool_read_OK        success
                spool_read_notopen   open failed
                spool_read_enverror  error in the envelope portion
                spool_read_hdrerror  error in the header portion
*/

int
spool_read_header(uschar *name, BOOL read_headers, BOOL subdir_set)
{
FILE * fp = NULL;
int n;
int rcount = 0;
long int uid, gid;
BOOL inheader = FALSE;
const uschar * where;

/* Reset all the global variables to their default values. However, there is
one exception. DO NOT change the default value of dont_deliver, because it may
be forced by an external setting. */

spool_clear_header_globals();

/* Generate the full name and open the file. If message_subdir is already
set, just look in the given directory. Otherwise, look in both the split
and unsplit directories, as for the data file above. */

for (int n = 0; n < 2; n++)
  {
  if (!subdir_set)
    set_subdir_str(message_subdir, name, n);

  if ((fp = Ufopen(spool_fname(US"input", message_subdir, name, US""), "rb")))
    break;
  if (n != 0 || subdir_set || errno != ENOENT)
    return spool_read_notopen;
  }

errno = 0;

#ifndef COMPILE_UTILITY
DEBUG(D_deliver) debug_printf_indent("reading spool file %s\n", name);
#endif  /* COMPILE_UTILITY */

/* The first line of a spool file contains the message id followed by -H (i.e.
the file name), in order to make the file self-identifying. */

where = US"first line read";
if (Ufgets(big_buffer, big_buffer_size, fp) == NULL) goto SPOOL_READ_ERROR;
where = US"first line length";
if (  (  Ustrlen(big_buffer) != MESSAGE_ID_LENGTH + 3
      && Ustrlen(big_buffer) != MESSAGE_ID_LENGTH_OLD + 3
      )
   || (  Ustrncmp(big_buffer, name, MESSAGE_ID_LENGTH + 2) != 0
      && Ustrncmp(big_buffer, name, MESSAGE_ID_LENGTH_OLD + 2) != 0
   )  )
  goto SPOOL_FORMAT_ERROR;

/* The next three lines in the header file are in a fixed format. The first
contains the login, uid, and gid of the user who caused the file to be written.
There are known cases where a negative gid is used, so we allow for both
negative uids and gids. The second contains the mail address of the message's
sender, enclosed in <>. The third contains the time the message was received,
and the number of warning messages for delivery delays that have been sent. */

where = US"2nd line read";
if (Ufgets(big_buffer, big_buffer_size, fp) == NULL) goto SPOOL_READ_ERROR;

 {
  uschar *p = big_buffer + Ustrlen(big_buffer);
  while (p > big_buffer && isspace(p[-1])) p--;
  *p = 0;
  where = US"2nd line fmt 1";
  if (!isdigit(p[-1])) goto SPOOL_FORMAT_ERROR;
  while (p > big_buffer && (isdigit(p[-1]) || '-' == p[-1])) p--;
  gid = Uatoi(p);
  where = US"2nd line fmt 2";
  if (p <= big_buffer || *(--p) != ' ') goto SPOOL_FORMAT_ERROR;
  *p = 0;
  if (!isdigit(p[-1])) goto SPOOL_FORMAT_ERROR;
  while (p > big_buffer && (isdigit(p[-1]) || '-' == p[-1])) p--;
  uid = Uatoi(p);
  where = US"2nd line fmt 3";
  if (p <= big_buffer || *(--p) != ' ') goto SPOOL_FORMAT_ERROR;
  *p = 0;
 }

originator_login = string_copy(big_buffer);
originator_uid = (uid_t)uid;
originator_gid = (gid_t)gid;

where = US"envelope from";
if (Ufgets(big_buffer, big_buffer_size, fp) == NULL) goto SPOOL_READ_ERROR;
n = Ustrlen(big_buffer);
if (n < 3 || big_buffer[0] != '<' || big_buffer[n-2] != '>')
  goto SPOOL_FORMAT_ERROR;

sender_address = store_get(n-2, GET_TAINTED);
Ustrncpy(sender_address, big_buffer+1, n-3);
sender_address[n-3] = 0;

where = US"time";
if (Ufgets(big_buffer, big_buffer_size, fp) == NULL) goto SPOOL_READ_ERROR;
if (sscanf(CS big_buffer, TIME_T_FMT " %d", &received_time.tv_sec, &warning_count) != 2)
  goto SPOOL_FORMAT_ERROR;
received_time.tv_usec = 0;
received_time_complete = received_time;


message_age = time(NULL) - received_time.tv_sec;
#ifndef COMPILE_UTILITY
if (f.running_in_test_harness)
  message_age = test_harness_fudged_queue_time(message_age);
#endif

#ifndef COMPILE_UTILITY
DEBUG(D_deliver) debug_printf_indent("user=%s uid=%ld gid=%ld sender=%s\n",
  originator_login, (long int)originator_uid, (long int)originator_gid,
  sender_address);
#endif

/* Now there may be a number of optional lines, each starting with "-". If you
add a new setting here, make sure you set the default above.

Because there are now quite a number of different possibilities, we use a
switch on the first character to avoid too many failing tests. Thanks to Nico
Erfurth for the patch that implemented this. I have made it even more efficient
by not re-scanning the first two characters.

To allow new versions of Exim that add additional flags to interwork with older
versions that do not understand them, just ignore any lines starting with "-"
that we don't recognize. Otherwise it wouldn't be possible to back off a new
version that left new-style flags written on the spool.

If the line starts with "--" the content of the variable is tainted.
If the line start "--(<lookuptype>)" it is also quoted for the given <lookuptype>.
*/

for (;;)
  {
  const void * proto_mem;
  uschar * var;
  const uschar * p;

  if (fgets_big_buffer(fp) == NULL) goto SPOOL_READ_ERROR;
  if (big_buffer[0] != '-') break;
  big_buffer[Ustrlen(big_buffer)-1] = 0;

  proto_mem = big_buffer[1] == '-' ? GET_TAINTED : GET_UNTAINTED;
  var =  big_buffer + (proto_mem == GET_UNTAINTED ? 1 : 2);
  if (*var == '(')				/* marker for quoted value */
    {
    uschar * s;
    for (s = ++var; *s != ')'; ) s++;
#ifndef COMPILE_UTILITY
      {
      int idx;
      if ((idx = search_findtype(var, s - var)) < 0)
	{
	DEBUG(D_any)
	  debug_printf("Unrecognised quoter %.*s\n", (int)(s - var), var+1);
	where = NULL;
	goto SPOOL_FORMAT_ERROR;
	}
      proto_mem = store_get_quoted(1, GET_TAINTED, idx);
      }
#endif  /* COMPILE_UTILITY */
    var = s + 1;
    }
  p = var + 1;

  switch(*var)
    {
    case 'a':

    /* Nowadays we use "-aclc" and "-aclm" for the different types of ACL
    variable, because Exim allows any number of them, with arbitrary names.
    The line in the spool file is "-acl[cm] <name> <length>". The name excludes
    the c or m. */

    if (Ustrncmp(p, "clc ", 4) == 0 ||
        Ustrncmp(p, "clm ", 4) == 0)
      {
      uschar *name, *endptr;
      int count;
      tree_node *node;
      endptr = Ustrchr(var + 5, ' ');
      where = US"-aclXn";
      if (!endptr) goto SPOOL_FORMAT_ERROR;
      name = string_sprintf("%c%.*s", var[3],
        (int)(endptr - var - 5), var + 5);
      if (sscanf(CS endptr, " %d", &count) != 1) goto SPOOL_FORMAT_ERROR;
      node = acl_var_create(name);
      node->data.ptr = store_get(count + 1, proto_mem);
      if (fread(node->data.ptr, 1, count+1, fp) < count) goto SPOOL_READ_ERROR;
      ((uschar*)node->data.ptr)[count] = 0;
      }

    else if (Ustrcmp(p, "llow_unqualified_recipient") == 0)
      f.allow_unqualified_recipient = TRUE;
    else if (Ustrcmp(p, "llow_unqualified_sender") == 0)
      f.allow_unqualified_sender = TRUE;

    else if (Ustrncmp(p, "uth_id", 6) == 0)
      authenticated_id = string_copy_taint(var + 8, proto_mem);
    else if (Ustrncmp(p, "uth_sender", 10) == 0)
      authenticated_sender = string_copy_taint(var + 12, proto_mem);
    else if (Ustrncmp(p, "ctive_hostname", 14) == 0)
      smtp_active_hostname = string_copy_taint(var + 16, proto_mem);

    /* For long-term backward compatibility, we recognize "-acl", which was
    used before the number of ACL variables changed from 10 to 20. This was
    before the subsequent change to an arbitrary number of named variables.
    This code is retained so that upgrades from very old versions can still
    handle old-format spool files. The value given after "-acl" is a number
    that is 0-9 for connection variables, and 10-19 for message variables. */

    else if (Ustrncmp(p, "cl ", 3) == 0)
      {
      unsigned index, count;
      uschar name[20];   /* Need plenty of space for %u format */
      tree_node * node;
      where = US"-acl (old)";
      if (  sscanf(CS var + 4, "%u %u", &index, &count) != 2
	 || index >= 20
	 || count > 16384	/* arbitrary limit on variable size */
         )
        goto SPOOL_FORMAT_ERROR;
      if (index < 10)
        (void) string_format(name, sizeof(name), "%c%u", 'c', index);
      else
        (void) string_format(name, sizeof(name), "%c%u", 'm', index - 10);
      node = acl_var_create(name);
      node->data.ptr = store_get(count + 1, proto_mem);
      /* We sanity-checked the count, so disable the Coverity error */
      /* coverity[tainted_data] */
      if (fread(node->data.ptr, 1, count+1, fp) < count) goto SPOOL_READ_ERROR;
      (US node->data.ptr)[count] = '\0';
      }
    break;

    case 'b':
    if (Ustrncmp(p, "ody_linecount", 13) == 0)
      body_linecount = Uatoi(var + 14);
    else if (Ustrncmp(p, "ody_zerocount", 13) == 0)
      body_zerocount = Uatoi(var + 14);
#ifdef EXPERIMENTAL_BRIGHTMAIL
    else if (Ustrncmp(p, "mi_verdicts ", 12) == 0)
      bmi_verdicts = string_copy_taint(var + 13, proto_mem);
#endif
    break;

    case 'd':
    if (Ustrcmp(p, "eliver_firsttime") == 0)
      f.deliver_firsttime = TRUE;
    else if (Ustrncmp(p, "sn_ret", 6) == 0)
      dsn_ret= atoi(CS var + 7);
    else if (Ustrncmp(p, "sn_envid", 8) == 0)
      dsn_envid = string_copy_taint(var + 10, proto_mem);
#ifndef COMPILE_UTILITY
    else if (Ustrncmp(p, "ebug_selector ", 14) == 0)
      debug_selector = strtol(CS var + 15, NULL, 0);
    else if (Ustrncmp(p, "ebuglog_name ", 13) == 0)
      debug_logging_from_spool(var + 14);
#endif
    break;

    case 'f':
    if (Ustrncmp(p, "rozen", 5) == 0)
      {
      f.deliver_freeze = TRUE;
      if (sscanf(CS var+6, TIME_T_FMT, &deliver_frozen_at) != 1)
	goto SPOOL_READ_ERROR;
      }
    break;

    case 'h':
    if (Ustrcmp(p, "ost_lookup_deferred") == 0)
      host_lookup_deferred = TRUE;
    else if (Ustrcmp(p, "ost_lookup_failed") == 0)
      host_lookup_failed = TRUE;
    else if (Ustrncmp(p, "ost_auth_pubname", 16) == 0)
      sender_host_auth_pubname = string_copy_taint(var + 18, proto_mem);
    else if (Ustrncmp(p, "ost_auth", 8) == 0)
      sender_host_authenticated = string_copy_taint(var + 10, proto_mem);
    else if (Ustrncmp(p, "ost_name", 8) == 0)
      sender_host_name = string_copy_taint(var + 10, proto_mem);
    else if (Ustrncmp(p, "elo_name", 8) == 0)
      sender_helo_name = string_copy_taint(var + 10, proto_mem);

    /* We now record the port number after the address, separated by a
    dot. For compatibility during upgrading, do nothing if there
    isn't a value (it gets left at zero). */

    else if (Ustrncmp(p, "ost_address", 11) == 0)
      {
      sender_host_port = host_address_extract_port(var + 13);
      sender_host_address = string_copy_taint(var + 13, proto_mem);
      }
    break;

    case 'i':
    if (Ustrncmp(p, "nterface_address", 16) == 0)
      {
      interface_port = host_address_extract_port(var + 18);
      interface_address = string_copy_taint(var + 18, proto_mem);
      }
    else if (Ustrncmp(p, "dent", 4) == 0)
      sender_ident = string_copy_taint(var + 6, proto_mem);
    break;

    case 'l':
    if (Ustrcmp(p, "ocal") == 0)
      f.sender_local = TRUE;
    else if (Ustrcmp(var, "localerror") == 0)
      f.local_error_message = TRUE;
#ifdef HAVE_LOCAL_SCAN
    else if (Ustrncmp(p, "ocal_scan ", 10) == 0)
      local_scan_data = string_copy_taint(var + 11, proto_mem);
#endif
    break;

    case 'm':
    if (Ustrcmp(p, "anual_thaw") == 0)
      f.deliver_manual_thaw = TRUE;
    else if (Ustrncmp(p, "ax_received_linelength", 22) == 0)
      max_received_linelength = Uatoi(var + 23);
    break;

    case 'N':
    if (*p == 0) f.dont_deliver = TRUE;   /* -N */
    break;

    case 'r':
    if (Ustrncmp(p, "eceived_protocol", 16) == 0)
      received_protocol = string_copy_taint(var + 18, proto_mem);
    else if (Ustrncmp(p, "eceived_time_usec", 17) == 0)
      {
      unsigned usec;
      if (sscanf(CS var + 20, "%u", &usec) == 1)
	{
	received_time.tv_usec = usec;
	if (!received_time_complete.tv_sec) received_time_complete.tv_usec = usec;
	}
      }
    else if (Ustrncmp(p, "eceived_time_complete", 21) == 0)
      {
      unsigned sec, usec;
      if (sscanf(CS var + 23, "%u.%u", &sec, &usec) == 2)
	{
	received_time_complete.tv_sec = sec;
	received_time_complete.tv_usec = usec;
	}
      }
    break;

    case 's':
    if (Ustrncmp(p, "ender_set_untrusted", 19) == 0)
      f.sender_set_untrusted = TRUE;
#ifdef WITH_CONTENT_SCAN
    else if (Ustrncmp(p, "pam_bar ", 8) == 0)
      spam_bar = string_copy_taint(var + 9, proto_mem);
    else if (Ustrncmp(p, "pam_score ", 10) == 0)
      spam_score = string_copy_taint(var + 11, proto_mem);
    else if (Ustrncmp(p, "pam_score_int ", 14) == 0)
      spam_score_int = string_copy_taint(var + 15, proto_mem);
#endif
#ifndef COMPILE_UTILITY
    else if (Ustrncmp(p, "pool_file_wireformat", 20) == 0)
      f.spool_file_wireformat = TRUE;
#endif
#if defined(SUPPORT_I18N) && !defined(COMPILE_UTILITY)
    else if (Ustrncmp(p, "mtputf8", 7) == 0)
      message_smtputf8 = TRUE;
#endif
    break;

#ifndef DISABLE_TLS
    case 't':
    if (Ustrncmp(p, "ls_", 3) == 0)
      {
      const uschar * q = p + 3;
      if (Ustrncmp(q, "certificate_verified", 20) == 0)
	tls_in.certificate_verified = TRUE;
      else if (Ustrncmp(q, "cipher", 6) == 0)
	tls_in.cipher = string_copy_taint(q+7, proto_mem);
# ifndef COMPILE_UTILITY	/* tls support fns not built in */
      else if (Ustrncmp(q, "ourcert", 7) == 0)
	(void) tls_import_cert(q+8, &tls_in.ourcert);
      else if (Ustrncmp(q, "peercert", 8) == 0)
	(void) tls_import_cert(q+9, &tls_in.peercert);
# endif
      else if (Ustrncmp(q, "peerdn", 6) == 0)
	tls_in.peerdn = string_unprinting(string_copy_taint(q+7, proto_mem));
      else if (Ustrncmp(q, "sni", 3) == 0)
	tls_in.sni = string_unprinting(string_copy_taint(q+4, proto_mem));
      else if (Ustrncmp(q, "ocsp", 4) == 0)
	tls_in.ocsp = q[5] - '0';
# ifndef DISABLE_TLS_RESUME
      else if (Ustrncmp(q, "resumption", 10) == 0)
	tls_in.resumption = q[11] - 'A';
# endif
      else if (Ustrncmp(q, "ver", 3) == 0)
	tls_in.ver = string_copy_taint(q+4, proto_mem);
      }
    break;
#endif

#if defined(SUPPORT_I18N) && !defined(COMPILE_UTILITY)
    case 'u':
    if (Ustrncmp(p, "tf8_downcvt", 11) == 0)
      message_utf8_downconvert = 1;
    else if (Ustrncmp(p, "tf8_optdowncvt", 15) == 0)
      message_utf8_downconvert = -1;
    break;
#endif

    default:    /* Present because some compilers complain if all */
    break;      /* possibilities are not covered. */
    }
  }

/* Build sender_fullhost if required */

#ifndef COMPILE_UTILITY
host_build_sender_fullhost();
#endif  /* COMPILE_UTILITY */

#ifndef COMPILE_UTILITY
DEBUG(D_deliver)
  debug_printf_indent("sender_local=%d ident=%s\n", f.sender_local,
    sender_ident ? sender_ident : US"unset");
#endif  /* COMPILE_UTILITY */

/* We now have the tree of addresses NOT to deliver to, or a line
containing "XX", indicating no tree. */

where = US"nondeliver";
if (Ustrncmp(big_buffer, "XX\n", 3) != 0 &&
  !read_nonrecipients_tree(&tree_nonrecipients, fp, big_buffer, big_buffer_size))
    goto SPOOL_FORMAT_ERROR;

#ifndef COMPILE_UTILITY
DEBUG(D_deliver) debug_print_tree("Non-recipients", tree_nonrecipients);
#endif  /* COMPILE_UTILITY */

/* After reading the tree, the next line has not yet been read into the
buffer. It contains the count of recipients which follow on separate lines.
Apply an arbitrary sanity check.*/

where = US"rcpt cnt";
if (Ufgets(big_buffer, big_buffer_size, fp) == NULL) goto SPOOL_READ_ERROR;
if (sscanf(CS big_buffer, "%d", &rcount) != 1 || rcount > 16384)
  goto SPOOL_FORMAT_ERROR;

#ifndef COMPILE_UTILITY
DEBUG(D_deliver) debug_printf_indent("recipients_count=%d\n", rcount);
#endif  /* COMPILE_UTILITY */

recipients_list_max = rcount;
recipients_list = store_get(rcount * sizeof(recipient_item), GET_UNTAINTED);

/* We sanitised the count and know we have enough memory, so disable
the Coverity error on recipients_count */
/* coverity[tainted_data] */

where = US"recipient";
for (recipients_count = 0; recipients_count < rcount; recipients_count++)
  {
  int nn;
  int pno = -1;
  int dsn_flags = 0;
  uschar *orcpt = NULL;
  uschar *errors_to = NULL;
  uschar *p;

  if (fgets_big_buffer(fp) == NULL) goto SPOOL_READ_ERROR;
  nn = Ustrlen(big_buffer);
  if (nn < 2) goto SPOOL_FORMAT_ERROR;

  /* Remove the newline; this terminates the address if there is no additional
  data on the line. */

  p = big_buffer + nn - 1;
  *p-- = 0;

  /* Look back from the end of the line for digits and special terminators.
  Since an address must end with a domain, we can tell that extra data is
  present by the presence of the terminator, which is always some character
  that cannot exist in a domain. (If I'd thought of the need for additional
  data early on, I'd have put it at the start, with the address at the end. As
  it is, we have to operate backwards. Addresses are permitted to contain
  spaces, you see.)

  This code has to cope with various versions of this data that have evolved
  over time. In all cases, the line might just contain an address, with no
  additional data. Otherwise, the possibilities are as follows:

  Exim 3 type:       <address><space><digits>,<digits>,<digits>

    The second set of digits is the parent number for one_time addresses. The
    other values were remnants of earlier experiments that were abandoned.

  Exim 4 first type: <address><space><digits>

    The digits are the parent number for one_time addresses.

  Exim 4 new type:   <address><space><data>#<type bits>

    The type bits indicate what the contents of the data are.

    Bit 01 indicates that, reading from right to left, the data
      ends with <errors_to address><space><len>,<pno> where pno is
      the parent number for one_time addresses, and len is the length
      of the errors_to address (zero meaning none).

    Bit 02 indicates that, again reading from right to left, the data continues
     with orcpt len(orcpt),dsn_flags
   */

  while (isdigit(*p)) p--;

  /* Handle Exim 3 spool files */

  if (*p == ',')
    {
    int dummy;
#if !defined (COMPILE_UTILITY)
    DEBUG(D_deliver) debug_printf_indent("**** SPOOL_IN - Exim 3 spool file\n");
#endif
    while (isdigit(*(--p)) || *p == ',');
    if (*p == ' ')
      {
      *p++ = 0;
      (void)sscanf(CS p, "%d,%d", &dummy, &pno);
      }
    }

  /* Handle early Exim 4 spool files */

  else if (*p == ' ')
    {
#if !defined (COMPILE_UTILITY)
    DEBUG(D_deliver) debug_printf_indent("**** SPOOL_IN - early Exim 4 spool file\n");
#endif
    *p++ = 0;
    (void)sscanf(CS p, "%d", &pno);
    }

  /* Handle current format Exim 4 spool files */

  else if (*p == '#')
    {
    int flags;

#if !defined (COMPILE_UTILITY)
    DEBUG(D_deliver) debug_printf_indent("**** SPOOL_IN - Exim standard format spoolfile\n");
#endif

    (void)sscanf(CS p+1, "%d", &flags);

    if (flags & 0x01)      /* one_time data exists */
      {
      int len;
      while (isdigit(*(--p)) || *p == ',' || *p == '-');
      (void)sscanf(CS p+1, "%d,%d", &len, &pno);
      *p = 0;
      if (len > 0)
        {
        p -= len;
        errors_to = string_copy_taint(p, GET_TAINTED);
        }
      }

    *--p = 0;   /* Terminate address */
    if (flags & 0x02)      /* one_time data exists */
      {
      int len;
      while (isdigit(*(--p)) || *p == ',' || *p == '-');
      (void)sscanf(CS p+1, "%d,%d", &len, &dsn_flags);
      *p = 0;
      if (len > 0)
        {
        p -= len;
        orcpt = string_copy_taint(p, GET_TAINTED);
        }
      }

    *--p = 0;   /* Terminate address */
    }
#if !defined(COMPILE_UTILITY)
  else
    { DEBUG(D_deliver) debug_printf_indent("**** SPOOL_IN - No additional fields\n"); }

  if (orcpt || dsn_flags)
    DEBUG(D_deliver) debug_printf_indent("**** SPOOL_IN - address: <%s> orcpt: <%s> dsn_flags: 0x%x\n",
      big_buffer, orcpt, dsn_flags);
  if (errors_to)
    DEBUG(D_deliver) debug_printf_indent("**** SPOOL_IN - address: <%s> errorsto: <%s>\n",
      big_buffer, errors_to);
#endif

  recipients_list[recipients_count].address = string_copy_taint(big_buffer, GET_TAINTED);
  recipients_list[recipients_count].pno = pno;
  recipients_list[recipients_count].errors_to = errors_to;
  recipients_list[recipients_count].orcpt = orcpt;
  recipients_list[recipients_count].dsn_flags = dsn_flags;
  }

/* The remainder of the spool header file contains the headers for the message,
separated off from the previous data by a blank line. Each header is preceded
by a count of its length and either a certain letter (for various identified
headers), space (for a miscellaneous live header) or an asterisk (for a header
that has been rewritten). Count the Received: headers. We read the headers
always, in order to check on the format of the file, but only create a header
list if requested to do so. */

inheader = TRUE;
where = US"headers";
if (Ufgets(big_buffer, big_buffer_size, fp) == NULL) goto SPOOL_READ_ERROR;
if (big_buffer[0] != '\n') goto SPOOL_FORMAT_ERROR;

while ((n = fgetc(fp)) != EOF)
  {
  header_line * h;
  uschar flag[4];
  int i;

  if (!isdigit(n)) goto SPOOL_FORMAT_ERROR;
  if(ungetc(n, fp) == EOF  ||  fscanf(fp, "%d%c ", &n, flag) == EOF)
    goto SPOOL_READ_ERROR;
  if (flag[0] != '*') message_size += n;  /* Omit non-transmitted headers */

  if (read_headers)
    {
    h = store_get(sizeof(header_line), GET_UNTAINTED);
    h->next = NULL;
    h->type = flag[0];
    h->slen = n;
    h->text = store_get(n+1, GET_TAINTED);

    if (h->type == htype_received) received_count++;

    if (header_list) header_last->next = h;
    else header_list = h;
    header_last = h;

    for (i = 0; i < n; i++)
      {
      int c = fgetc(fp);
      if (c == 0 || c == EOF) goto SPOOL_FORMAT_ERROR;
      if (c == '\n' && h->type != htype_old) message_linecount++;
      h->text[i] = c;
      }
    h->text[i] = 0;
    }

  /* Not requiring header data, just skip through the bytes */

  else for (i = 0; i < n; i++)
    {
    int c = fgetc(fp);
    if (c == 0 || c == EOF) goto SPOOL_FORMAT_ERROR;
    }
  }

/* We have successfully read the data in the header file. Update the message
line count by adding the body linecount to the header linecount. Close the file
and give a positive response. */

#ifndef COMPILE_UTILITY
DEBUG(D_deliver) debug_printf_indent("body_linecount=%d message_linecount=%d\n",
  body_linecount, message_linecount);
#endif  /* COMPILE_UTILITY */

message_linecount += body_linecount;

fclose(fp);
return spool_read_OK;


/* There was an error reading the spool or there was missing data,
or there was a format error. A "read error" with no errno means an
unexpected EOF, which we treat as a format error. */

SPOOL_READ_ERROR:
if (errno != 0)
  {
  n = errno;

#ifndef COMPILE_UTILITY
  DEBUG(D_any) debug_printf("Error while reading spool file %s\n", name);
#endif  /* COMPILE_UTILITY */

  fclose(fp);
  errno = n;
  return inheader ? spool_read_hdrerror : spool_read_enverror;
  }

SPOOL_FORMAT_ERROR:

#ifndef COMPILE_UTILITY
DEBUG(D_any) debug_printf("Format error in spool file %s%s%s\n", name,
  where ? ": " : "", where ? where : US"");
#endif  /* COMPILE_UTILITY */

fclose(fp);
errno = ERRNO_SPOOLFORMAT;
return inheader? spool_read_hdrerror : spool_read_enverror;
}


#ifndef COMPILE_UTILITY
/* Read out just the (envelope) sender string from the spool -H file.
Remove the <> wrap and return it in allocated store.  Return NULL on error.

We assume that message_subdir is already set.
*/

uschar *
spool_sender_from_msgid(const uschar * id)
{
FILE * fp;
int n;
uschar * yield = NULL;

if (!(fp = Ufopen(spool_fname(US"input", message_subdir, id, US"-H"), "rb")))
  return NULL;

DEBUG(D_deliver) debug_printf_indent("reading spool file %s-H\n", id);

/* Skip the line with the copy of the filename, then the line with login/uid/gid.
Read the next line, which should be the envelope sender.
Do basic validation on that. */

if (  Ufgets(big_buffer, big_buffer_size, fp) != NULL
   && Ufgets(big_buffer, big_buffer_size, fp) != NULL
   && Ufgets(big_buffer, big_buffer_size, fp) != NULL
   && (n = Ustrlen(big_buffer)) >= 3
   && big_buffer[0] == '<' && big_buffer[n-2] == '>'
   )
  {
  yield = store_get(n-2, GET_TAINTED);
  Ustrncpy(yield, big_buffer+1, n-3);
  yield[n-3] = 0;
  }
fclose(fp);
return yield;
}
#endif  /* COMPILE_UTILITY */

/* vi: aw ai sw=2
*/
/* End of spool_in.c */
