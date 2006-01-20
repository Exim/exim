/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2006 */
/* Written by Philip Hazel. */

/* This module contains code for reading the input. */

#include "xfpt.h"



/*************************************************
*            Static variables                    *
*************************************************/

static uschar *next_line = NULL;



/*************************************************
*             Process macro line                 *
*************************************************/

/* This is the place where macro arguments are substituted. In a section
delimited by .eacharg/.endeach, the variable macro_argbase is set to the first
of the relative arguments. This function is also called from para.c in order to
handle inline macro calls.

Arguments:
  p         the macro input line
  b         where to put the result

Returns:    nothing
*/

void
read_process_macroline(uschar *p, uschar *b)
{
int optend = 0;

while (*p != 0)
  {
  int i;
  int argn = 0;
  argstr *argbase, *arg;

  /* If we are including an optional substring, when we get to the terminator,
  just skip it. */

  if (*p == optend)
    {
    optend = 0;
    p++;
    continue;
    }

  /* Until we hit a dollar, just copy verbatim */

  if (*p != '$') { *b++ = *p++; continue; }

  /* If the character after $ is another $, insert a literal $. */

  if (p[1] == '$') { p++; *b++ = *p++; continue; }

  /* If the character after $ is +, we are dealing with arguments
  relative to macro_arg0 in a ".eacharg" section. Otherwise, we are dealing
  with an absolute argument number. */

  if (p[1] == '+')
    {
    p++;
    if (macro_argbase == NULL)       /* Not in a .eacharg section */
      {
      error(18);
      *b++ = '+';
      *b++ = *p++;
      continue;
      }
    argbase = macro_argbase;
    }
  else argbase = macrocurrent->args;

  /* $= introduces an optional substring */

  if (p[1] == '=')
    {
    p++;
    if (!isdigit(p[1]))
      {
      error(17, p[1], "$=");
      *b++ = '$';
      *b++ = *p++;
      continue;
      }
    while (isdigit(*(++p))) argn = argn * 10 + *p - '0';

    optend = *p++;

    arg = argbase;
    for (i = 1; i < argn; i++)
      {
      if (arg == NULL) break;
      arg = arg->next;
      }

    if (arg == NULL || arg->string[0] == 0)
      {
      while (*p != 0 && *p != optend) p++;
      if (*p == optend) p++;
      }

    continue;
    }

  /* Not '=' after $; this is an argument substitution */

  if (!isdigit(p[1]))
    {
    error(17, p[1], "$");
    *b++ = *p++;
    continue;
    }

  while (isdigit(*(++p))) argn = argn * 10 + *p - '0';

  /* Handle $0 - currently no meaning */

  if (argn == 0)
    {
    continue;
    }

  /* Seek an argument in this invocation */

  arg = argbase;
  for (i = 1; i < argn; i++)
    {
    if (arg == NULL) break;
    arg = arg->next;
    }

  /* If not found, seek a default argument for an absolute substitution, but
  not for a relative one. */

  if (arg == NULL && argbase == macrocurrent->args)
    {
    arg = macrocurrent->macro->args;
    for (i = 1; i < argn; i++)
      {
      if (arg == NULL) break;
      arg = arg->next;
      }
    }

  /* If we have found an argument, substitute it. */

  if (arg != NULL) b += sprintf(CS b, "%s", arg->string);
  }

*b = 0;
}


/*************************************************
*     Get the next line from the current file    *
*************************************************/

/* There may be a stack of included files. This function makes them look like a
single source of input.

Arguments:
  buffer        where to read
  size          size of buffer

Returns:        buffer pointer or NULL
*/

static uschar *
read_nextfileline(uschar *buffer, int size)
{
if (istack == NULL) return NULL;
if (Ufgets(buffer, size, istack->file) == NULL)
  {
  istackstr *prev = istack->prev;
  fclose(istack->file);
  free(istack);
  istack = prev;
  return (istack == NULL)? NULL : read_nextfileline(buffer, size);
  }

istack->linenumber++;
return buffer;
}



/*************************************************
*         Get the next line of input             *
*************************************************/

/* There may be a saved line already in the buffer, following the reading of a
paragraph. Otherwise, take the next line from one of three sources, in order:

  (1) If popto is not negative, get an appropropriate line off the stack.
  (2) If we are in a macro, get the next macro line.
  (3) Read a new line from a file and handle any continuations.

Arguments:  none
Returns:    pointer to the next line or NULL
*/

uschar *
read_nextline(void)
{
int len;
uschar *p, *q;

/* Handle a dot line that terminated a paragraph */

if (next_line != NULL)
  {
  uschar *yield = next_line;
  next_line = NULL;
  return yield;
  }

/* Handle a line off the stack */

if (popto == 0)
  {
  pushstr *ps = pushed;
  if (ps == NULL) error(12); else
    {
    popto = -1;
    (void)sprintf(CS inbuffer, "%s\n", ps->string);
    pushed = ps->next;
    free(ps);
    return inbuffer;
    }
  }

/* Handle a line off the stack when there is a matching line at the top or
below for the given letter. When we reach the matching line, stop popping. The
value of popto is set greater than zero only when it is known that there's a
matching line. */

if (popto > 0)
  {
  pushstr *ps = pushed;
  if (ps->letter == popto) popto = -1;
  (void)sprintf(CS inbuffer, "%s\n", ps->string);
  pushed = ps->next;
  free(ps);
  return inbuffer;
  }

/* Handle the next macro line. */

while (macrocurrent != NULL)
  {
  if (macrocurrent->nextline == NULL)
    {
    macroexe *temp = macrocurrent;
    macrocurrent = macrocurrent->prev;
    free(temp);
    }
  else
    {
    read_process_macroline(macrocurrent->nextline->string, inbuffer);
    macrocurrent->nextline = macrocurrent->nextline->next;
    return inbuffer;
    }
  }

/* Get a line from an input file */

if (read_nextfileline(inbuffer, INBUFFSIZE) == NULL) return NULL;

q = inbuffer;
len = Ustrlen(q);

for (;;)
  {
  p = q + len;
  while (p > q && isspace(p[-1])) p--;

  if (p - q < 3 || Ustrncmp(p - 3, "&&&", 3) != 0) break;

  q = p - 3;
  *q = 0;

  if (read_nextfileline(q, INBUFFSIZE - (q - inbuffer)) == NULL) break;

  p = q;
  while (*p == ' ' || *p == '\t') p++;
  len = Ustrlen(p);
  if (p > q) memmove(q, p, len + 1);
  }

return inbuffer;
}



/*************************************************
*        Complete the reading of a paragraph     *
*************************************************/

/* This function is called after a line has been identified as the start of a
paragraph. We need to read the rest so that flags can be matched across the
entire paragraph. The whole is copied into the paragraph buffer. Directives
that are encountered in the paragraph are processed, with the exception of
.literal, which terminates it. We leave a .literal directive in the input
buffer and set next_line to point to it, so that it is processed later.

Arguments:  the first line
Returns:    the paragraph
*/


uschar *
read_paragraph(uschar *p)
{
uschar *q = parabuffer;
int length = Ustrlen(p);

memcpy(q, p, length);
q += length;

for (;;)
  {
  uschar *s;

  if ((p = read_nextline()) == NULL) break;

  if (Ustrncmp(p, ".literal ", 9) == 0)
    {
    next_line = p;
    break;
    }

  else if (*p == '.')
    {
    dot_process(p);
    continue;
    }

  /* End paragraph on encountering a completely blank line */

  for (s = p;  *s == ' ' || *s == '\t'; s++);
  if (*s == '\n') break;

  length = Ustrlen(p);
  memcpy(q, p, length);
  q += length;
  }

*q = 0;
return parabuffer;
}

/* End of read.c */
