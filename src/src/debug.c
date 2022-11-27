/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2015 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-only */


#include "exim.h"

static uschar  debug_buffer[2048];
static uschar *debug_ptr = debug_buffer;
static int     debug_prefix_length = 0;

static unsigned pretrigger_writeoff;
static unsigned pretrigger_readoff;


const uschar * rc_names[] = {		/* Mostly for debug output */
  [OK] =		US"OK",
  [DEFER] =		US"DEFER",
  [FAIL] =		US"FAIL",
  [ERROR] =		US"ERROR",
  [FAIL_FORCED] =	US"FAIL_FORCED",
  [DECLINE] =		US"DECLINE",
  [PASS] =		US"PASS",
  [DISCARD] =		US"DISCARD",
  [SKIP] =		US"SKIP",
  [REROUTED] =		US"REROUTED",
  [PANIC] =		US"PANIC",
  [BAD64] =		US"BAD64",
  [UNEXPECTED] =	US"UNEXPECTED",
  [CANCELLED] =		US"CANCELLED",
  [FAIL_SEND] =		US"FAIL_SEND",
  [FAIL_DROP] =		US"FAIL_DROP",
  [DANE] =		US"DANE",
};

const uschar * dns_rc_names[] = {
  [DNS_SUCCEED] =	US"DNS_SUCCEED",
  [DNS_NOMATCH] =	US"DNS_NOMATCH",
  [DNS_NODATA] =	US"DNS_NODATA",
  [DNS_AGAIN] =		US"DNS_AGAIN",
  [DNS_FAIL] =		US"DNS_FAIL",
};


/*************************************************
*               Print tree                       *
*************************************************/

/* Recursive tree-printing subroutine. It uses a static vector of uschar to
hold the line-drawing characters that need to be printed on every line as it
moves down the page. This function is used only in debugging circumstances. The
output is done via debug_printf(). */

#define TREE_PRINTLINESIZE 132   /* line size for printing */
static uschar tree_printline[TREE_PRINTLINESIZE];

/* Internal recursive subroutine.

Arguments:
  p          tree node
  pos        amount of indenting & vertical bars to print
  barswitch  if TRUE print | at the pos value

Returns:     nothing
*/

static void
tree_printsub(tree_node * p, int pos, int barswitch)
{
if (p->right) tree_printsub(p->right, pos+2, 1);
for (int i = 0; i <= pos-1; i++) debug_printf_indent(" %c", tree_printline[i]);
debug_printf_indent(" -->%s [%d]\n", p->name, p->balance);
tree_printline[pos] = barswitch ? '|' : ' ';
if (p->left)
  {
  tree_printline[pos+2] = '|';
  tree_printsub(p->left, pos+2, 0);
  }
}

/* The external function, with just a tree node argument. */

void
debug_print_tree(const char * title, tree_node * p)
{
debug_printf_indent("%s:\n", title);
for (int i = 0; i < TREE_PRINTLINESIZE; i++) tree_printline[i] = ' ';
if (!p) debug_printf_indent(" Empty Tree\n"); else tree_printsub(p, 0, 0);
debug_printf_indent("---- End of tree ----\n");
}



/*************************************************
*          Print an argv vector                  *
*************************************************/

/* Called when about to obey execv().

Argument:    the argv vector
Returns:     nothing
*/

void
debug_print_argv(const uschar ** argv)
{
debug_printf("exec");
while (*argv) debug_printf(" %.256s", *argv++);
debug_printf("\n");
}



/*************************************************
*      Expand and print debugging string         *
*************************************************/

/* The string is expanded and written as debugging output. If
expansion fails, a message is written instead.

Argument:    the string
Returns:     nothing
*/

void
debug_print_string(uschar *debug_string)
{
if (!debug_string) return;
HDEBUG(D_any|D_v)
  {
  uschar *s = expand_string(debug_string);
  if (!s)
    debug_printf("failed to expand debug_output \"%s\": %s\n", debug_string,
      expand_string_message);
  else if (s[0] != 0)
    debug_printf("%s%s", s, (s[Ustrlen(s)-1] == '\n')? "" : "\n");
  }
}



/*************************************************
*      Print current uids and gids               *
*************************************************/

/*
Argument:   an introductory string
Returns:    nothing
*/

void
debug_print_ids(uschar *s)
{
debug_printf("%s uid=%ld gid=%ld euid=%ld egid=%ld\n", s,
  (long int)getuid(), (long int)getgid(), (long int)geteuid(),
  (long int)getegid());
}

/************************************************/

/* Give a string for a return-code */

const uschar *
rc_to_string(int rc)
{
return rc < 0 || rc >= nelem(rc_names) ? US"?" : rc_names[rc];
}





/*************************************************
*           Print debugging message              *
*************************************************/

/* There are two entries, one for use when being called directly from a
function with a variable argument list, one for prepending an indent.

If debug_pid is nonzero, print the pid at the start of each line. This is for
tidier output when running parallel remote deliveries with debugging turned on.
Must do the whole thing with a single printf and flush, as otherwise output may
get interleaved. Since some calls to debug_printf() don't end with newline,
we save up the text until we do get the newline.
Take care to not disturb errno. */


/* Debug printf indented by ACL nest depth */
void
debug_printf_indent(const char * format, ...)
{
va_list ap;
va_start(ap, format);
debug_vprintf(acl_level + expand_level, format, ap);
va_end(ap);
}

void
debug_printf(const char *format, ...)
{
va_list ap;
va_start(ap, format);
debug_vprintf(0, format, ap);
va_end(ap);
}

void
debug_vprintf(int indent, const char *format, va_list ap)
{
int save_errno = errno;

if (!debug_file) return;

/* Various things can be inserted at the start of a line. Don't use the
tod_stamp() function for the timestamp, because that will overwrite the
timestamp buffer, which may contain something useful. (This was a bug fix: the
+memory debugging with +timestamp did cause a problem.) */

if (debug_ptr == debug_buffer)
  {
  DEBUG(D_timestamp)
    {
    struct timeval now;
    time_t tmp;
    struct tm * t;

    gettimeofday(&now, NULL);
    tmp = now.tv_sec;
    t = f.timestamps_utc ? gmtime(&tmp) : localtime(&tmp);
    debug_ptr += sprintf(CS debug_ptr,
      LOGGING(millisec) ? "%02d:%02d:%02d.%03d " : "%02d:%02d:%02d ",
      t->tm_hour, t->tm_min, t->tm_sec, (int)(now.tv_usec/1000));
    }

  DEBUG(D_pid)
    debug_ptr += sprintf(CS debug_ptr, "%5d ", (int)getpid());

  /* Set up prefix if outputting for host checking and not debugging */

  if (host_checking && debug_selector == 0)
    {
    Ustrcpy(debug_ptr, US">>> ");
    debug_ptr += 4;
    }

  debug_prefix_length = debug_ptr - debug_buffer;
  }

if (indent > 0)
  {
  for (int i = indent >> 2; i > 0; i--)
    DEBUG(D_noutf8)
      {
      Ustrcpy(debug_ptr, US"   !");
      debug_ptr += 4;	/* 3 spaces + shriek */
      debug_prefix_length += 4;
      }
    else
      {
      Ustrcpy(debug_ptr, US"   " UTF8_VERT_2DASH);
      debug_ptr += 6;	/* 3 spaces + 3 UTF-8 octets */
      debug_prefix_length += 6;
      }

  Ustrncpy(debug_ptr, US"   ", indent &= 3);
  debug_ptr += indent;
  debug_prefix_length += indent;
  }

/* Use the lengthchecked formatting routine to ensure that the buffer
does not overflow. Ensure there's space for a newline at the end.
However, use taint-unchecked routines for writing into the buffer
so that we can write tainted info into the static debug_buffer -
we trust that we will never expand the results. */

  {
  gstring gs = { .size = (int)sizeof(debug_buffer) - 1,
		.ptr = debug_ptr - debug_buffer,
		.s = debug_buffer };
  if (!string_vformat(&gs, SVFMT_TAINT_NOCHK, format, ap))
    {
    uschar * s = US"**** debug string too long - truncated ****\n";
    uschar * p = gs.s + gs.ptr;
    int maxlen = gs.size - Ustrlen(s) - 2;
    if (p > gs.s + maxlen) p = gs.s + maxlen;
    if (p > gs.s && p[-1] != '\n') *p++ = '\n';
    Ustrcpy(p, s);
    while(*debug_ptr) debug_ptr++;
    }
  else
    {
    string_from_gstring(&gs);
    debug_ptr = gs.s + gs.ptr;
    }
  }

/* Output the line if it is complete. If we added any prefix data and there
are internal newlines, make sure the prefix is on the continuation lines,
as long as there is room in the buffer. We want to do just a single fprintf()
so as to avoid interleaving. */

if (debug_ptr[-1] == '\n')
  {
  if (debug_prefix_length > 0)
    {
    uschar *p = debug_buffer;
    int left = sizeof(debug_buffer) - (debug_ptr - debug_buffer) - 1;
    while ((p = Ustrchr(p, '\n') + 1) != debug_ptr &&
           left >= debug_prefix_length)
      {
      int len = debug_ptr - p;
      memmove(p + debug_prefix_length, p, len + 1);
      memmove(p, debug_buffer, debug_prefix_length);
      debug_ptr += debug_prefix_length;
      left -= debug_prefix_length;
      }
    }

  if (debug_pretrigger_buf)
    {
    int needed = Ustrlen(debug_buffer)+1, avail;
    char c;

    if (needed > debug_pretrigger_bsize)
      needed = debug_pretrigger_bsize;
    if ((avail = pretrigger_readoff - pretrigger_writeoff) <= 0)
      avail += debug_pretrigger_bsize;

    /* We have a pretrigger set up, trigger not yet hit. Copy the line(s) to the
    pretrig buffer, dropping earlier lines if needed but truncating this line if
    the pbuf is maxed out.  In the PTB the lines are NOT nul-terminated. */

    while (avail < needed)
      do
	{
	avail++;
        c = debug_pretrigger_buf[pretrigger_readoff];
	if (++pretrigger_readoff >= debug_pretrigger_bsize) pretrigger_readoff = 0;
	}
      while (c && c != '\n' && pretrigger_readoff != pretrigger_writeoff);

    needed--;
    for (int i = 0; needed; i++, needed--)
      {
      debug_pretrigger_buf[pretrigger_writeoff] = debug_buffer[i];
      if (++pretrigger_writeoff >= debug_pretrigger_bsize) pretrigger_writeoff = 0;
      }
    }
  else
    {
    fprintf(debug_file, "%s", CS debug_buffer);
    fflush(debug_file);
    }
  debug_ptr = debug_buffer;
  debug_prefix_length = 0;
  }
errno = save_errno;
}



/* Output the details of a socket */

void
debug_print_socket(int fd)
{
struct stat s;
if (fstat(fd, &s) == 0 && (s.st_mode & S_IFMT) == S_IFSOCK)
  {
  gstring * g = NULL;
  int val;
  socklen_t vlen = sizeof(val);
  struct sockaddr_storage a;
  socklen_t alen = sizeof(a);
  struct sockaddr_in * sinp = (struct sockaddr_in *)&a;
  struct sockaddr_in6 * sin6p = (struct sockaddr_in6 *)&a;
  struct sockaddr_un * sunp = (struct sockaddr_un *)&a;

  if (getsockname(fd, (struct sockaddr*)&a, &alen) == 0)
    switch (a.ss_family)
      {
      case AF_INET:
	g = string_cat(g, US"domain AF_INET");
	g = string_fmt_append(g, " lcl [%s]:%u",
	  inet_ntoa(sinp->sin_addr), ntohs(sinp->sin_port));
	alen = sizeof(*sinp);
	if (getpeername(fd, (struct sockaddr *)sinp, &alen) == 0)
	  g = string_fmt_append(g, " rmt [%s]:%u",
	    inet_ntoa(sinp->sin_addr), ntohs(sinp->sin_port));
	break;
      case AF_INET6:
	{
	uschar buf[46];
	g = string_cat(g, US"domain AF_INET6");
	g = string_fmt_append(g, " lcl [%s]:%u",
	  inet_ntop(AF_INET6, &sin6p->sin6_addr, CS buf, sizeof(buf)),
	  ntohs(sin6p->sin6_port));
	alen = sizeof(*sin6p);
	if (getpeername(fd, (struct sockaddr *)sin6p, &alen) == 0)
	  g = string_fmt_append(g, " rmt [%s]:%u",
	    inet_ntop(AF_INET6, &sin6p->sin6_addr, CS buf, sizeof(buf)),
	    ntohs(sin6p->sin6_port));
	break;
	}
      case AF_UNIX:
        g = string_cat(g, US"domain AF_UNIX");
        if (alen > sizeof(sa_family_t)) /* not unix(7) "unnamed socket" */
          g = string_fmt_append(g, " lcl %s%s",
            sunp->sun_path[0] ? US"" : US"@",
            sunp->sun_path[0] ? sunp->sun_path : sunp->sun_path+1);
        alen = sizeof(*sunp);
        if (getpeername(fd, (struct sockaddr *)sunp, &alen) == 0)
          g = string_fmt_append(g, " rmt %s%s",
            sunp->sun_path[0] ? US"" : US"@",
            sunp->sun_path[0] ? sunp->sun_path : sunp->sun_path+1);
        break;
      default:
	g = string_fmt_append(g, "domain %u", sinp->sin_family);
	break;
      }
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &val, &vlen) == 0)
    switch (val)
      {
      case SOCK_STREAM:	g = string_cat(g, US" type SOCK_STREAM"); break;
      case SOCK_DGRAM:	g = string_cat(g, US" type SOCK_DGRAM"); break;
      default:	g = string_fmt_append(g, " type %d", val); break;
      }
#ifdef SO_PROTOCOL
  if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &val, &vlen) == 0)
    {
    struct protoent * p = getprotobynumber(val);
    g = p
      ? string_fmt_append(g, " proto %s", p->p_name)
      : string_fmt_append(g, " proto %d", val);
    }
#endif
  debug_printf_indent(" socket: %s\n", string_from_gstring(g));
  }
else
  debug_printf_indent(" fd st_mode 0%o\n", s.st_mode);
}


/**************************************************************/
/* Pretrigger handling for debug.  The debug_printf implementation
diverts output to a circular buffer if the buffer is set up.
The routines here set up the buffer, and unload it to file (and release it).
What ends up in the buffer is subject to the usual debug_selector. */

void
debug_pretrigger_setup(const uschar * size_string)
{
long size = Ustrtol(size_string, NULL, 0);
if (size > 0)
  {
  unsigned bufsize = MIN(size, 16384);

  dtrigger_selector |= BIT(DTi_pretrigger);
  if (debug_pretrigger_buf) store_free(debug_pretrigger_buf);
  debug_pretrigger_buf = store_malloc((size_t)(debug_pretrigger_bsize = bufsize));
  pretrigger_readoff = pretrigger_writeoff = 0;
  }
}

void
debug_trigger_fire(void)
{
int nbytes;

if (!debug_pretrigger_buf) return;

if (debug_file && (nbytes = pretrigger_writeoff - pretrigger_readoff) != 0)
  if (nbytes > 0)
    fwrite(debug_pretrigger_buf + pretrigger_readoff, 1, nbytes, debug_file);
  else
    {
    fwrite(debug_pretrigger_buf + pretrigger_readoff, 1,
      debug_pretrigger_bsize - pretrigger_readoff, debug_file);
    fwrite(debug_pretrigger_buf, 1, pretrigger_writeoff, debug_file);
    }

debug_pretrigger_discard();
}

void
debug_pretrigger_discard(void)
{
if (debug_pretrigger_buf) store_free(debug_pretrigger_buf);
debug_pretrigger_buf = NULL;
dtrigger_selector = 0;
}


/* End of debug.c */
