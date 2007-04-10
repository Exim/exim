/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2007 */
/* Written by Philip Hazel. */

/* This module contains code for processing a line that starts with a dot. */

#include "xfpt.h"



/*************************************************
*               Static variables                 *
*************************************************/

static uschar *circumflexes =
  US"^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^";
static uschar *spaces =
  US"                                                                         ";
static uschar *thisdir = NULL;



/*************************************************
*        Read a single number argument           *
*************************************************/

/* Several directives take just a single number as an argument.

Argument:   pointer in the input line
Returns:    the number, or -1 on error
*/

static int
readnumber(uschar *p)
{
int n = 0;
if (!isdigit(*p)) { error(11, thisdir); return -1; }
while (isdigit(*p)) n = n * 10 + *p++ - '0';
while (isspace(*p)) p++;
if (*p != 0) { error(11, thisdir); return -1; }
return n;
}



/*************************************************
*               Skip macro lines                 *
*************************************************/

/* This function skips to the end of the current macro or to the given
terminator line. It is called only when we know we are in a macro. The current
macro line is the conditional directive.

Arguments:
  s         the conditional directive
  t         the terminator directive
Returns:    nothing
*/

static void
skipto(uschar *s, uschar *t)
{
int nest = -1;
int slength = Ustrlen(s);
int tlength = Ustrlen(t);
BOOL done = macrocurrent->nextline == NULL;
while (!done)
  {
  uschar *p = macrocurrent->nextline->string;
  done = Ustrncmp(p, t, tlength) == 0 &&
         (p[tlength] == 0 || isspace(p[tlength])) &&
         nest-- <= 0;
  if (Ustrncmp(p, s, slength) == 0 && (p[slength] == 0 || isspace(p[slength])))
    nest++;
  macrocurrent->nextline = macrocurrent->nextline->next;
  if (macrocurrent->nextline == NULL)
    {
    macroexe *temp = macrocurrent;
    macrocurrent = macrocurrent->prev;
    free(temp);
    break;
    }
  }
}



/*************************************************
*               Handle .arg                      *
*************************************************/

/* The .arg directive is permitted only within a macro. It must be followed by
a positive or negative number. For a positive number, if an argument of that
number was given to the macro and is not an empty string, nothing happens.
Otherwise, the macro's input is skipped, either to .endarg or to the end of the
macro. For a negative number, the test is reversed: nothing happens if that
argument was not given or is empty.

Argument:   a single argument string
Returns:    nothing
*/

static void
do_arg(uschar *p)
{
BOOL mustexist = TRUE;
argstr *arg;
int i, argn;

if (macrocurrent == NULL) { error(15, US".arg"); return; }

if (*p == '-')
  {
  mustexist = FALSE;
  p++;
  }

argn = readnumber(p);
if (argn < 0) return;

arg = macrocurrent->args;
for (i = 1; arg != NULL && i < argn; i++) arg = arg->next;

if (mustexist != (arg != NULL && arg->string[0] != 0))
  skipto(US".arg", US".endarg");
}



/*************************************************
*               Handle .eacharg                  *
*************************************************/

/* This may be followed by a number to specify which argument to start at. The
lines between this and ".endeach" are repeated for each argument.

Argument:   a single argument string
Returns:    nothing
*/

static void
do_eacharg(uschar *p)
{
argstr *arg;
int argn, i;

if (macrocurrent == NULL) { error(15, US".eacharg"); return; }

argn = (*p == 0)? 1 : readnumber(p);
if (argn < 0) return;

arg = macrocurrent->args;
for (i = 1; arg != NULL && i < argn; i++) arg = arg->next;

/* If we did not find the starting argument, skip. Otherwise, set up the
substitution for relative arguments, and remember where to come back to. */

if (arg == NULL) skipto(US"eacharg", US".endeach"); else
  {
  macro_argbase = arg;
  macro_starteach = macrocurrent->nextline;
  }
}



/*************************************************
*             Handle .echo                       *
*************************************************/

/* This directive provides a debugging and commenting facility.

Argument:   a single argument string
Returns:    nothing
*/

static void
do_echo(uschar *p)
{
(void)fprintf(stderr, "%s\n", p);
}



/*************************************************
*             Handle .endarg                     *
*************************************************/

/* We only hit this as a stand-alone directive when the argument exists and the
previous lines have been obeyed. There is nothing to do.

Argument:   the rest of the line
Returns:    nothing
*/

static void
do_endarg(uschar *p)
{
if (macrocurrent == NULL) { error(15, US".endarg"); return; }
if (*p != 0) error(19, ".endarg", p, 8, spaces, Ustrlen(p), circumflexes);
}



/*************************************************
*              Handle .endeach                   *
*************************************************/

/* This marks the end of an ".eacharg" section of lines. Advance the relative
argument base pointer by the given number (default 1). If there are still some
arguments left, repeat the section.

Argument:   a single argument string
Returns:    nothing
*/

static void
do_endeach(uschar *p)
{
int count;

if (macrocurrent == NULL) { error(15, US".endeach"); return; }

count = (*p == 0)? 1 : readnumber(p);
if (count < 0) return;

while (count-- > 0 && macro_argbase != NULL)
  macro_argbase = macro_argbase->next;

if (macro_argbase == NULL) macro_starteach = NULL;
  else macrocurrent->nextline = macro_starteach;
}




/*************************************************
*           Handle .endinliteral                 *
*************************************************/

/* We only hit this as a stand-alone directive when in a literal section and
the previous lines have been obeyed. There is nothing to do.

Argument:   the rest of the line
Returns:    nothing
*/

static void
do_endinliteral(uschar *p)
{
if (macrocurrent == NULL) { error(15, US".endinliteral"); return; }
if (*p != 0) error(19, ".endinliteral", p, 8, spaces, Ustrlen(p), circumflexes);
}



/*************************************************
*               Handle .flag                     *
*************************************************/

/* The .flag directive defines either a single flag (starting with &) or a pair
of flags, the first of which must start with &. We put the data into a block
that's added to the flaglist chain. We have to cope with all these (example)
possibilities:

  .flag &+ "stuff"
  .flag &" "stuff"
  .flag &" "& "stuff1" "stuff2"

Argument:   the rest of the command line
Returns:    nothing
*/

static void
do_flag(uschar *p)
{
uschar *pp, *q;
int length, term;
flagstr *f, **ff;

f = misc_malloc(sizeof(flagstr));

/* Check that the flag starts with & and then get a copy of the rest of it. */

if (*p++ != '&') { error(9); return; }

for (pp = p; *pp != 0 && !isspace(*pp); pp++);
length = pp - p;
if (length == 0) { error(10); return; }

f->length1 = length;
f->flag1 = misc_copystring(p, length);

/* Now look backwards from the end of the line and find the last quoted string
that is there. */

q = pp + Ustrlen(pp);
if (*(--q) != '\"' && *q != '\'') { error(11, thisdir); return; }

term = *q;
while (--q > pp)
  {
  if (*q == term) { if (q[-1] == term) q--; else break; }
  }

if (q <= pp) { error(11, thisdir); return; }

/* If there's nothing between pp and q, we have the definition of a single,
non-paired flag. */

while (isspace(*pp)) pp++;
if (pp == q)
  {
  f->rep1 = misc_readstring(q, NULL, NULL, 0);
  f->length2 = 0;
  f->flag2 = f->rep2 = NULL;
  }

/* Otherwise, we are dealing with a pair of flags. */

else
  {
  f->rep2 = misc_readstring(q, NULL, NULL, 0);
  p = pp;
  while (*pp != 0 && !isspace(*pp)) pp++;
  length = pp - p;
  if (length == 0) { error(10); return; }
  f->length2 = length;
  f->flag2 = misc_copystring(p, length);
  while (isspace(*pp)) pp++;
  if (*pp != '\"' && *pp != '\'') { error(11, thisdir); return; }
  f->rep1 = misc_readstring(pp, &length, NULL, 0);
  if (pp + length >= q) { error(11, thisdir); return; }
  }

/* Successfully defined the flag(s). Attach the block to the chain. The order
is not defined, except that the longer (initial) flag comes first. */

ff = &flaglist;
while (*ff != NULL && f->length1 < (*ff)->length1) ff = &((*ff)->next);
f->next = *ff;
*ff = f;
}


/*************************************************
*               Handle .include                  *
*************************************************/

/* We set up a stack of included files so that the input is treated as one big
file.

Argument:   a single argument string
Returns:    nothing
*/

static void
do_include(uschar *p)
{
istackstr *ist;

ist = misc_malloc(sizeof(istackstr));
ist->prev = istack;
istack = ist;
ist->linenumber = 0;

if (Ustrchr(p, '/') != NULL) Ustrcpy(ist->filename, p);
  else sprintf(CS ist->filename, "%s/%s", xfpt_share, p);

ist->file = Ufopen(ist->filename, "rb");
if (ist->file == NULL) error(0, ist->filename, strerror(errno));  /* Hard */
}



/*************************************************
*             Handle .inliteral                  *
*************************************************/

/* The .inliteral directive is permitted only within a macro. If we are
handling the appropriate kind of literal text, nothing happens. Otherwise, the
macro's input is skipped, either to .endinliteral or to the end of the macro.

Argument:   a single argument string
Returns:    nothing
*/

static void
do_inliteral(uschar *p)
{
int state = -1;
if (macrocurrent == NULL) { error(15, US".inliteral"); return; }
if (Ustrcmp(p, "layout") == 0) state = LITERAL_LAYOUT;
else if (Ustrcmp(p, "text") == 0) state = LITERAL_TEXT;
else if (Ustrcmp(p, "off") == 0) state = LITERAL_OFF;
else if (Ustrcmp(p, "xml") == 0) state = LITERAL_XML;
else error(5, p);
if (literal_state != state) skipto(US"inliteral", US".endinliteral");
}




/*************************************************
*                Handle .literal                 *
*************************************************/

/*
Argument:   a single argument string
Returns:    nothing
*/

static void
do_literal(uschar *p)
{
if (Ustrcmp(p, "layout") == 0) literal_state = LITERAL_LAYOUT;
else if (Ustrcmp(p, "text") == 0) literal_state = LITERAL_TEXT;
else if (Ustrcmp(p, "off") == 0) literal_state = LITERAL_OFF;
else if (Ustrcmp(p, "xml") == 0) literal_state = LITERAL_XML;
else error(5, p);
}


/*************************************************
*               Handle .macro                    *
*************************************************/

/* We set up a macro definition, whose contents are all the following lines,
uninterpreted, until we reach .endmacro.

Argument:   the rest of the .macro line
Returns:    nothing
*/

static void
do_macro(uschar *p)
{
int length;
int nest = 0;
argstr **pp;
macrodef *md = misc_malloc(sizeof(macrodef));

md->name = misc_readitem(p, NULL, &length, NULL, 0);
md->namelength = Ustrlen(md->name);
p += length;

if (length == 0)
  {
  error(14);
  return;
  }

md->lines = md->args = NULL;
md->next = macrolist;
macrolist = md;

pp = &(md->args);
while (*p != 0)
  {
  argstr *as = misc_malloc(sizeof(argstr));
  as->next = NULL;
  *pp = as;
  pp = &(as->next);
  as->string = misc_readitem(p, NULL, &length, NULL, 0);
  p += length;
  }

pp = &(md->lines);
for (;;)
  {
  argstr *as;
  uschar *line = read_nextline();
  if (line == NULL) { error(13, ".endmacro"); return; }

  if (Ustrncmp(line, ".macro ", 7) == 0) nest++;
  else if (Ustrncmp(line, ".endmacro", 9) == 0)
    {
    if (isspace(line[9]) || line[9] == '\n')
    if (--nest < 0) break;
    }

  as = misc_malloc(sizeof(argstr));
  as->next = NULL;
  *pp = as;
  pp = &(as->next);
  as->string = misc_copystring(line, Ustrlen(line));
  }

/* If there aren't any replacement lines, fake up a comment so that there's
always something for a macro to generate. */

if (md->lines == NULL)
  {
  md->lines = misc_malloc(sizeof(argstr));
  md->lines->next = NULL;
  md->lines->string = misc_copystring(US". Dummy line\n", 13);
  }
}



/*************************************************
*               Handle .nonl                     *
*************************************************/

/* Output the argument as normal text, but without a newline on the end.

Argument:   the rest of the line
Returns:    nothing
*/

static void
do_nonl(uschar *p)
{
para_process(p);
}


/*************************************************
*               Handle .pop                      *
*************************************************/

/* This may optionally be followed by an upper case letter identifier. This
causes a search down the stack for an item with that letter. If one is found,
we arrange for the stack to pop back to it. If not, nothing happens. If no
letter is specified, arrange to pop just one item.

Argument:   a single argument string
Returns:    nothing
*/

static void
do_pop(uschar *p)
{
pushstr *ps;

if (*p == 0)
  {
  popto = 0;
  return;
  }

if (!isupper(*p) || p[1] != 0) { error(11, thisdir); return; }

for (ps = pushed; ps != NULL; ps = ps->next)
  { if (ps->letter == *p) break; }

if (ps != NULL) popto = *p;
}



/*************************************************
*               Handle .push                     *
*************************************************/

/* This directive pushes the rest of the line onto a stack. If the first thing
on the line is a single upper case letter followed by space, we set that as the
stack marker letter. Following that we either have a quoted item, or the rest
of the line unquoted.

Argument:   the rest of the line
Returns:    nothing
*/

static void
do_push(uschar *p)
{
int length;
int letter = 0;
pushstr *ps;
uschar *porig = p;
uschar buffer[INBUFFSIZE];

if (isupper(*p) && (p[1] == 0 || isspace(p[1])))
  {
  letter = *p++;
  while (isspace(*p)) p++;
  }

if (*p == '"')
  {
  uschar *s = misc_readitem(p, NULL, &length, buffer, INBUFFSIZE);
  p += length;
  while (isspace(*p)) p++;
  if (*p != 0) error(19, ".push", porig, p - porig + 6, spaces, Ustrlen(p),
    circumflexes);
  p = s;
  }

length = Ustrlen(p);
ps = misc_malloc(sizeof(pushstr) + length);
ps->letter = letter;
memcpy(ps->string, p, length);
ps->string[length] = 0;
ps->next = pushed;
pushed = ps;
}




/*************************************************
*                 Handle .revision               *
*************************************************/

/* Set or unset a text for <revisionflag= in many elements. If the text if
"off", treat it as empty.

Arguments:  a single argument string
Returns:    nothing
*/

static void
do_revision(uschar *p)
{
if (revision != NULL)
  {
  free(revision);
  revision = NULL;
  }

if (*p != 0 && Ustrcmp(p, "off") != 0)
  {
  revision = misc_malloc(Ustrlen(p) + 1);
  Ustrcpy(revision, p);
  }
}




/*************************************************
*               Handle .set                      *
*************************************************/

/* Set the value of a locally-defined entity.

Arguments:  the rest of the command line
Returns:    nothing
*/

static void
do_set(uschar *p)
{
int length;
tree_node *t;
uschar *porig = p;
uschar buffer[INBUFFSIZE];
uschar *name = misc_readitem(p, NULL, &length, buffer, INBUFFSIZE);

p += length;
while (isspace(*p)) p++;

t = misc_malloc(sizeof(tree_node) + Ustrlen(name));
Ustrcpy(t->name, name);

t->data = misc_readitem(p, NULL, &length, NULL, 0);

p += length;
while (isspace(*p)) p++;
if (*p != 0) error(19, ".set", porig, p - porig + 5, spaces, Ustrlen(p),
  circumflexes);

if (!tree_insertnode(&entities, t)) error(21, name);
}



/*************************************************
*             Table of directives                *
*************************************************/

/* Quite a few directives have a single argument that can either be quoted, or
just the rest of the line. These are flagged up so that the code to read that
argument can be central. Only those directives that control macro behaviour are
permitted in macros that are called inline. */

typedef struct dirstr {
  uschar *name;
  int length;
  void (*function)(uschar *);
  BOOL onearg;
  BOOL okinline;
} dirstr;


static dirstr dirs[] = {
  { US".arg",           4, do_arg,           TRUE,  TRUE },
  { US".eacharg",       8, do_eacharg,       TRUE,  TRUE },
  { US".echo",          5, do_echo,          TRUE, FALSE },
  { US".endarg",        7, do_endarg,       FALSE,  TRUE },
  { US".endeach",       8, do_endeach,       TRUE,  TRUE },
  { US".endinliteral", 13, do_endinliteral, FALSE,  TRUE },
  { US".flag",          5, do_flag,         FALSE, FALSE },
  { US".include",       8, do_include,       TRUE, FALSE },
  { US".inliteral",    10, do_inliteral,     TRUE,  TRUE },
  { US".literal",       8, do_literal,       TRUE, FALSE },
  { US".macro",         6, do_macro,        FALSE, FALSE },
  { US".nonl",          5, do_nonl,          TRUE, FALSE },
  { US".pop",           4, do_pop,           TRUE, FALSE },
  { US".push",          5, do_push,         FALSE, FALSE },
  { US".revision",      9, do_revision,      TRUE, FALSE },
  { US".set",           4, do_set,          FALSE, FALSE },
};

static int cmdcount = sizeof(dirs)/sizeof(dirstr);


/*************************************************
*         Process a line starting with a dot     *
*************************************************/

/* There are a small number of built-in commands, but many more may be defined
as macros. When we are in literal text or literal xml states, unknown lines
starting with dot are treated as data.

Argument:  the line to be processed
Returns:   nothing
*/

void
dot_process(uschar *p)
{
macrodef *md;
macroexe *me;
argstr **pp;
int top, bot, length;

thisdir = p;  /* Save for error messages */

misc_detrail(p);

if (p[1] == 0 || isspace(p[1])) return;       /* Comment */

/* Seek a built-in directive by binary chop. */

bot = 0;
top = cmdcount;

while (top > bot)
  {
  int c;
  int mid = (top + bot)/2;
  dirstr *dir = dirs + mid;

  length = dir->length;
  c = Ustrncmp(p, dir->name, length);

  /* Found a built-in directive; if it takes a single argument, read it here
  to avoid repeating the code in the individual directive functions. If there
  is text after the argument, give a warning. */

  if (c == 0 && (p[length] == 0 || isspace(p[length])))
    {
    uschar buffer[INBUFFSIZE];
    p += length;
    while (isspace(*p)) p++;

    if (dir->onearg)
      {
      int alength;
      uschar *s = misc_readitem(p, NULL, &alength, buffer, INBUFFSIZE);
      if (p[alength] != 0)
        error(19, dir->name, p, alength + length + 1, spaces,
          Ustrlen(p) - alength, circumflexes);
      p = s;
      }

    /* If we are in an inline macro, only certain directives are permitted */

    if (para_inline_macro == 0 || dir->okinline) (dir->function)(p);
      else error(22, dir->name);

    return;              /* Dealt with this directive line */
    }

  /* No match; do the chop and continue */

  if (c < 0) top = mid; else bot = mid + 1;
  }

/* If we can't match a built-in directive, we normally seek a macro. However,
this is not permitted if we are already expanding an inline macro call. */

if (para_inline_macro > 0)
  {
  error(22, p);
  return;
  }

for (md = macrolist; md != NULL; md = md->next)
  {
  length = md->namelength;
  if (Ustrncmp(p+1, md->name, length) == 0 &&
      (p[length+1] == 0 || isspace(p[length+1])))
    {
    p += length + 1;
    break;
    }
  }

/* Could not find a macro. In literal text and xml states, treat as data. Note
that the newline has been removed. */

if (md == NULL)
  {
  switch(literal_state)
    {
    case LITERAL_TEXT:
    case LITERAL_XML:
    fprintf(outfile, "%s\n", CS p);
    break;

    default:
    error(2, p);
    break;
    }
  return;
  }

/* Found a macro */

me = misc_malloc(sizeof(macroexe));
me->prev = macrocurrent;
macrocurrent = me;
me->macro = md;
me->nextline = md->lines;

me->args = NULL;
pp = &(me->args);

while (isspace(*p)) p++;
while (*p != 0)
  {
  argstr *as = misc_malloc(sizeof(argstr));
  as->next = NULL;
  *pp = as;
  pp = &(as->next);
  as->string = misc_readitem(p, NULL, &length, NULL, 0);
  p += length;
  }
}

/* End of dot.c */
