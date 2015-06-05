/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */


#include "exim.h"

static uschar  debug_buffer[2048];
static uschar *debug_ptr = debug_buffer;
static int     debug_prefix_length = 0;



/*************************************************
*               Print tree                       *
*************************************************/

/* Recursive tree-printing subroutine. It uses a static vector of uschar to
hold the line-drawing characters that need to be printed on every line as it
moves down the page. This function is used only in debugging circumstances. The
output is done via debug_printf(). */

#define tree_printlinesize 132   /* line size for printing */
static uschar tree_printline[tree_printlinesize];

/* Internal recursive subroutine.

Arguments:
  p          tree node
  pos        amount of indenting & vertical bars to pring
  barswitch  if TRUE print | at the pos value

Returns:     nothing
*/

static void
tree_printsub(tree_node *p, int pos, int barswitch)
{
int i;
if (p->right != NULL) tree_printsub(p->right, pos+2, 1);
for (i = 0; i <= pos-1; i++) debug_printf("%c", tree_printline[i]);
debug_printf("-->%s [%d]\n", p->name, p->balance);
tree_printline[pos] = barswitch? '|' : ' ';
if (p->left != NULL)
  {
  tree_printline[pos+2] = '|';
  tree_printsub(p->left, pos+2, 0);
  }
}

/* The external function, with just a tree node argument. */

void
debug_print_tree(tree_node *p)
{
int i;
for (i = 0; i < tree_printlinesize; i++) tree_printline[i] = ' ';
if (p == NULL) debug_printf("Empty Tree\n"); else tree_printsub(p, 0, 0);
debug_printf("---- End of tree ----\n");
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
while (*argv != NULL) debug_printf(" %.256s", *argv++);
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
if (debug_string == NULL) return;
HDEBUG(D_any|D_v)
  {
  uschar *s = expand_string(debug_string);
  if (s == NULL)
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




/*************************************************
*           Print debugging message              *
*************************************************/

/* There are two entries, one for use when being called directly from a
function with a variable argument list.

If debug_pid is nonzero, print the pid at the start of each line. This is for
tidier output when running parallel remote deliveries with debugging turned on.
Must do the whole thing with a single printf and flush, as otherwise output may
get interleaved. Since some calls to debug_printf() don't end with newline,
we save up the text until we do get the newline. */

void
debug_printf(const char *format, ...)
{
va_list ap;
va_start(ap, format);
debug_vprintf(format, ap);
va_end(ap);
}

void
debug_vprintf(const char *format, va_list ap)
{
if (debug_file == NULL) return;

/* Various things can be inserted at the start of a line. Don't use the
tod_stamp() function for the timestamp, because that will overwrite the
timestamp buffer, which may contain something useful. (This was a bug fix: the
+memory debugging with +timestamp did cause a problem.) */

if (debug_ptr == debug_buffer)
  {
  DEBUG(D_timestamp)
    {
    time_t now = time(NULL);
    struct tm *t = timestamps_utc? gmtime(&now) : localtime(&now);
    (void) sprintf(CS debug_ptr, "%02d:%02d:%02d ", t->tm_hour, t->tm_min,
      t->tm_sec);
    while(*debug_ptr != 0) debug_ptr++;
    }

  DEBUG(D_pid)
    {
    sprintf(CS debug_ptr, "%5d ", (int)getpid());
    while(*debug_ptr != 0) debug_ptr++;
    }

  /* Set up prefix if outputting for host checking and not debugging */

  if (host_checking && debug_selector == 0)
    {
    Ustrcpy(debug_ptr, ">>> ");
    debug_ptr += 4;
    }

  debug_prefix_length = debug_ptr - debug_buffer;
  }

/* Use the checked formatting routine to ensure that the buffer
does not overflow. Ensure there's space for a newline at the end. */

if (!string_vformat(debug_ptr,
     sizeof(debug_buffer) - (debug_ptr - debug_buffer) - 1, format, ap))
  {
  uschar *s = US"**** debug string too long - truncated ****\n";
  uschar *p = debug_buffer + Ustrlen(debug_buffer);
  int maxlen = sizeof(debug_buffer) - Ustrlen(s) - 3;
  if (p > debug_buffer + maxlen) p = debug_buffer + maxlen;
  if (p > debug_buffer && p[-1] != '\n') *p++ = '\n';
  Ustrcpy(p, s);
  }

while(*debug_ptr != 0) debug_ptr++;

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

  fprintf(debug_file, "%s", CS debug_buffer);
  fflush(debug_file);
  debug_ptr = debug_buffer;
  debug_prefix_length = 0;
  }
}

/* End of debug.c */
