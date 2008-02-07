/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2008 */
/* Written by Philip Hazel. */

/* This module contains code for processing a paragraph by looking for flag
characters and also dealing with literals that must be escaped. */

#include "xfpt.h"


/*************************************************
*         Process an inline macro call           *
*************************************************/

/* This function is called when we encounter & followed by a name and an
opening parenthesis. This signifies an inline macro call.

Arguments:
  p         points to the start of the macro name
  q         points to the opening parenthesis

Returns:    updated value for p to continue processing
*/

static uschar *
para_macro_process(uschar *p, uschar *q)
{
int length = q - p;
argstr **pp;
macrodef *md;
macroexe *me;

for (md = macrolist; md != NULL; md = md->next)
  {
  if (length == md->namelength && Ustrncmp(p, md->name, length) == 0) break;
  }

if (md == NULL)
  {
  error(23, length, p);
  (void)fprintf(outfile, "&");
  return p;
  }

/* Set up the macro and its arguments on the input stack, just as we do for a
macro called as a directive, though the arguments are comma-separated here. */

me = misc_malloc(sizeof(macroexe));
me->prev = macrocurrent;
macrocurrent = me;
me->macro = md;
me->nextline = md->lines;
from_type[++from_type_ptr] = FROM_MACRO;

me->args = NULL;
pp = &(me->args);

while (isspace(*(++q)));
while (*q != 0 && *q != ')')
  {
  argstr *as = misc_malloc(sizeof(argstr));
  as->next = NULL;
  *pp = as;
  pp = &(as->next);
  as->string = misc_readitem(q, US",)", &length, NULL, 0);
  q += length;
  if (*q == ',') while (isspace(*(++q)));
  }

if (*q != ')')
  {
  error(24, p);
  (void)fprintf(outfile, "&");
  return p;
  }

/* Bump the count indicating that we are in an inline macro, and then process
the lines of the macro. It's a count rather than a flag, because the macro data
may also reference inline macros. Each line is processed and output, but
without the terminating newline. */

para_inline_macro++;

for (;;)
  {
  uschar buffer[INBUFFSIZE];

  read_process_macroline(macrocurrent->nextline->string, buffer);

  /* A directive such as .eacharg can skip to the end of the macro if there
  is no .endeach. Detect this by looking for a change of macrocurrent value,
  because there may be an enclosing macro. */

  if (*buffer == '.')
    {
    dot_process(buffer);
    if (macrocurrent != me) break;
    }

  /* Process a data line */

  else
    {
    uschar *qq = buffer + Ustrlen(buffer);
    while (qq > buffer && isspace(qq[-1])) qq--;
    *qq = 0;
    para_process(buffer);
    }

  /* Advance to the next macro line, exiting the loop when we hit the
  end of the macro. */

  macrocurrent->nextline = macrocurrent->nextline->next;
  if (macrocurrent->nextline == NULL)
    {
    macroexe *temp = macrocurrent;
    macrocurrent = macrocurrent->prev;
    free(temp);
    from_type_ptr--;
    break;
    }
  }

/* Unstack one level of inline macro, and return the position to carry on
from in the original input. */

para_inline_macro--;
return q + 1;
}




/*************************************************
*        Check a flag string for literal         *
*************************************************/

/* This function is called to scan flag replacement strings to check for
<literal> and <literal/> so that we can avoid messing with single quotes in
literal text.

Arguments:
  s           the flag string
  b           a boolean that is set TRUE, FALSE, or left alone

Returns:      nothing
*/

static void
check_literal(uschar *s, BOOL *b)
{
while (*s != 0)
  {
  s = Ustrchr(s, '<');
  if (s == NULL) return;

  if (Ustrncmp(s, "<literal", 8) == 0 && (s[8] == '>' || isspace(s[8])))
    *b = TRUE;
  else if (Ustrncmp(s, "</literal", 9) == 0 && (s[9] == '>' || isspace(s[9])))
    *b = FALSE;

  while (*s != 0 && *s != '>')
    {
    if (*s == '"' || *s == '\'')
      {
      int t = *s++;
      while (*s != 0 && *s != t) s++;
      if (*s == 0) return;
      }
    s++;
    }

  if (*s++ == 0) return;
  }
}



/*************************************************
*             Process a paragraph                *
*************************************************/

/* This is used both for a complete paragraph that may consist of many lines,
and for literal layout lines that nevertheless need to be scanned for flags.
However, it is not used for literal text.

Argument:  the text to be processed
Returns:   nothing
*/

void
para_process(uschar *p)
{
flagstr *f;
flagstr *fstack[FLAGSTACKSIZE];
int fstackcount = 0;
BOOL inliteraltext = FALSE;

while (*p != 0)
  {
  int c, i;

  /* Check for the closing flag sequence for any outstanding flag pairs. If we
  find one that isn't at the top of the stack, there's a nesting error. */

  for (i = fstackcount - 1; i >= 0; i--)
    {
    f = fstack[i];
    if (Ustrncmp(f->flag2, p, f->length2) == 0)
      {
      int j;
      for (j = i + 1; j < fstackcount; j++)
        error(8, fstack[j]->flag2, f->flag2);
      fstackcount = i;
      (void)fprintf(outfile, "%s", CS f->rep2);
      check_literal(f->rep2, &inliteraltext);
      p += f->length2;
      i = fstackcount;   /* Reset in case another follows immediately */
      continue;
      }
    }

  /* We may be at the end of string if we've just passed a closing flag
  sequence. */

  if (*p == 0) break;

  /* Otherwise, scan character by character. Angle brackets are escaped,
  single quotes are mapped except in literal text, and then everything other
  than ampersand is treated literally. */

  c = *p++;
  if (c == '<')  { (void)fprintf(outfile, "&lt;"); continue; }
  if (c == '>')  { (void)fprintf(outfile, "&gt;"); continue; }

  if (!inliteraltext)
    {
    if (c == '`')
      {
      (void)fprintf(outfile, "&#x2018;");
      continue;
      }

    if (c == '\'')
      {
      (void)fprintf(outfile, "&#x2019;");
      continue;
      }
    }

  if (c != '&')  { (void)fputc(c, outfile); continue; }

  /* Ampersand must be followed by something. */

  if (*p == 0 || *p == '\n')
    {
    error(25);
    continue;
    }

  /* Handle all the fancy stuff that starts with ampersand. First, all the
  cases where a letter is next. */

  if (isalpha(*p))
    {
    int entlen;
    uschar *q = p + 1;
    while (isalnum(*q) || *q == '.') q++;

    /* Check for an inline macro call; handle out-of line as the code is
    non-trivial. */

    if (*q == '(')
      {
      p = para_macro_process(p, q);
      continue;
      }

    /* Otherwise, if it is not XML entity reference syntax there's an error. We
    support some special entities that start with "&xfpt." for inserting local
    data. We also allow local entities to be defined. If we don't recognize an
    entity name, it is passed through untouched, assuming it is a defined XML
    entity. */

    entlen = q - p;

    if (*q != ';')
      {
      error (3, entlen, p);
      (void)fprintf(outfile, "&");
      continue;
      }

    /* This special provides support for the .revision directive. */

    if (Ustrncmp(p, "xfpt.rev", entlen) == 0)
      {
      if (revision != NULL && *revision != 0)
        (void)fprintf(outfile, " revisionflag=\"%s\"", revision);
      }

    /* Search for a locally defined entitity */

    else
      {
      tree_node *t;
      *q = 0;
      t = tree_search(entities, p);
      *q = ';';
      if (t != NULL)
        (void)fprintf(outfile, "%s", CS t->data);
      else
        (void)fprintf(outfile, "&%.*s;", entlen, p);
      }

    if (*q == ';') q++;
    p = q;
    continue;
    }

  /* Ampersand followed by # might be an XML numerical entity. If not, we fall
  through in case it's a flag. */

  if (*p == '#')
    {
    uschar *q = p + 1;
    if (isdigit(*q))
      {
      for (q++; isdigit(*q); q++);
      if (*q == ';')
        {
        (void)fprintf(outfile, "&%.*s", q - p, p);
        p = q;
        continue;
        }
      }

    else if (*q == 'x')
      {
      for (q++; isxdigit(*q); q++);
      if (*q == ';')
        {
        (void)fprintf(outfile, "&%.*s", q - p, p);
        p = q;
        continue;
        }
      }
    }

  /* If not an XML entity, search out defined flag sequences */

  for (f = flaglist; f != NULL; f = f->next)
    { if (Ustrncmp(p, f->flag1, f->length1) == 0) break; }

  if (f == NULL)
    {
    error(6, *p);
    (void)fprintf(outfile, "&amp;");
    continue;
    }

  /* If the flag is part of a pair, put it onto a stack. Then write out the
  replacement for the first flag, and move past the flag characters. */

  if (f->length2 != 0) fstack[fstackcount++] = f;
  (void)fprintf(outfile, "%s", CS f->rep1);
  check_literal(f->rep1, &inliteraltext);
  p += f->length1;
  }

/* If there is anything left on the stack at the end of the string, there is a
missing flag partner. */

while (fstackcount > 0)
  {
  f = fstack[--fstackcount];
  error(7, f->flag2);
  }
}


/* End of para.c */
