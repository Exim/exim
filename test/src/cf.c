/************************************************
*                  PH-Compare                   *
************************************************/

/* A program to compare two files line by line.

History:

It was originally written in C, but the C under
Panos is still a shambles (1986). Translated therefore
to BCPL -- this explains some of the odd style.

Modified to run on Archimedes, August 1987.
Modified to run under MSDOS, March 1989.
Modified to run under CINTERP interpreter, July 1989.
Modified to run under Unix, October 1989.

Translated back into C, March 1990! */

/* Copyright (c) 1986, 1987, 1989, 1990, 1994, 2001 by Philip Hazel */

/* Previously modified: October 1994*/
/* Last modified: September 2001 - a long-lived bug fixed! */


#include <stdio.h>
#include <errno.h>

#ifdef __STDC__
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#endif

#ifndef intptr_t
# define intptr_t long long int
#endif

/* ----- parameters ----- */

#define version            8
#define defaultstore  100000     /* default recovery buffer size */
#define minstore         500     /* minimum recovery buffer size */
#define SHOWMAX		  20	 /* maximum number of diff lines to display */

/* ----- misc defines ----- */

#define FALSE 0
#define TRUE  1

#ifdef __STDC__
#define pvoid     void
#else
#define pvoid
#endif

#define EqString(s, t)   (strcmp(s, t) == 0)

/* ----- line structure ----- */

typedef struct line {
  struct line *next;
  int  number;
  char text[999999];
} line;


/* ----- global variables ----- */

FILE *f_one;           /* files */
FILE *f_two;
FILE *f_out;

int lines_one = 0;            /* line counts */
int lines_two = 0;
int return_code = 0;
int eof_one = FALSE;          /* eof flags */
int eof_two = FALSE;
int exact = FALSE;            /* TRUE => no strip spaces */
int echo = TRUE;              /* TRUE => show mismatched lines */
int sync_count = 3;           /* resync count */
int storesize = defaultstore; /* size of each buffer */

char *name_one = NULL;        /* file names */
char *name_two = NULL;
char *to_name = NULL;

char *bufbase_one;            /* start buffer */
char *bufbase_two;
char *bufnext_one;            /* next free byte */
char *bufnext_two;
char *buftop_one;             /* end buffer */
char *buftop_two;

line *rootline_one;           /* mis-match point */
line *rootline_two;
line *lastline_one;           /* last in store */
line *lastline_two;
line *pline_one;              /* working line */
line *pline_two;


/*************************************************
*             Help Information                   *
*************************************************/

void givehelp(pvoid)
{
printf("PH's CMP v%d\n", version);
printf("Keywords:\n");
printf("       <file>    ) files to compare\n");
printf("       <file>    ) no keywords used\n");
printf("-to    <file>      output destination\n");
printf("-exact             include trailing spaces & match tabs\n");
printf("-noecho            don't echo differences (just give line numbers)\n");
printf("-s, -sync  <n>     set re-sync count, default 3\n");
printf("-buffer <n>        buffer size (for each file) default 100000\n");
printf("-id                give program version id\n");
printf("-h, -help          give this help\n");
printf("\nExamples:\n");
printf("cmp old.f77 new.f77\n");
printf("cmp first second -noecho -sync 1\n");
printf("cmp large1 large2 -buffer 200000 -noecho -to diffs\n");
}



/************************************************
*               Errors -- all serious           *
************************************************/

void moan(code, text)
int code;
char *text;
{
fprintf(stderr, "\n** ");
switch (code)
  {
  case 1:
  fprintf(stderr, "Unable to open file \"%s\"", text);
  if (errno)
    {
    fprintf(stderr, " - ");
    perror(NULL);
    }
  else fprintf(stderr, "\n");
  break;

  case 2:
  fprintf(stderr, "Buffer overflow for file \"%s\"\n", text);
  break;

  case 3:
  fprintf(stderr, "Two file names must be given\n");
  break;

  default:
  fprintf(stderr, "Unknown error %d\n", code);
  break;
  }

fprintf(stderr, "** CMP abandoned\n");
exit(99);
}



/*************************************************
*         Write line identification              *
*************************************************/

void write_id(n1, n2, c, name, p1, p2)
int n1, n2, c;
char *name, *p1, *p2;
{
if (n2 < 0) n2 = -n2;
n2 -= 1;
fprintf(f_out, "%cine", c);
if (n1 == n2) fprintf(f_out, " %d of \"%s\"%s", n1, name, p1);
  else fprintf(f_out, "s %d-%d of \"%s\"%s", n1, n2, name, p2);
}


/*************************************************
*           Write sequence of lines              *
*************************************************/

void write_lines(s, t)
line *s, *t;
{
while (s != t)
  {
  char *p = s->text;
  while (*p != '\n') fputc(*p++, f_out);
  fputc('\n', f_out);
  s = s->next;
  }
}



/*************************************************
*           Write separator rule                 *
*************************************************/

void rule(s, l)
int s, l;
{
while (l-- > 0) fprintf(f_out, "%c", s);
fprintf(f_out, "\n");
}



/*************************************************
*          Write message on re-sync or eof       *
*************************************************/

void write_message(tline_one, tline_two)
line *tline_one, *tline_two;
{
int s1 = rootline_one->number;
int t1 = tline_one->number;
int s2 = rootline_two->number;
int t2 = tline_two->number;
if (echo) rule('=', 15);

if (s1 == t1)
  {
  write_id(s2, t2, 'L', name_two, " occurs ", " occur ");
  if (s1 < 0) fprintf(f_out, "at the end");
    else fprintf(f_out, "before line %d", s1);
  fprintf(f_out, " of \"%s\".\n", name_one);
  if (echo)
    {
    rule('-', 10);
    write_lines(rootline_two, tline_two);
    }
  }

else if (s2 == t2)
  {
  write_id(s1, t1, 'L', name_one, " occurs ", " occur ");
  if (s2 < 0) fprintf(f_out, "at the end");
    else fprintf(f_out, "before line %d", s2);
  fprintf(f_out, " of \"%s\".\n", name_two);
  if (echo)
    {
    rule('-', 10);
    write_lines(rootline_one, tline_one);
    }
  }

else if (t1 < 0 && t2 < 0)
  {
  fprintf(f_out, "From line %d of \"%s\" and line %d of \"%s\" ",
    rootline_one->number, name_one, rootline_two->number, name_two);
  fprintf(f_out, "the files are different.\n");
  if (echo)
    {
    rule('-', 10);
    if (-t1-s1 < SHOWMAX+1) write_lines(rootline_one, tline_one);
      else fprintf(f_out, "... <more than %d lines> ...\n", SHOWMAX);
    rule('-', 10);
    if (-t2-s2 < SHOWMAX+1) write_lines(rootline_two, tline_two);
      else fprintf(f_out, "... <more than %d lines> ...\n", SHOWMAX);
    }
  }

else
  {
  write_id(s1, t1, 'L', name_one, " does ", " do ");
  fprintf(f_out, "not match ");
  write_id(s2, t2, 'l', name_two, ".\n", ".\n");
  if (echo)
    {
    rule('-', 10);
    write_lines(rootline_one, tline_one);
    rule('-', 10);
    write_lines(rootline_two, tline_two);
    }
  }
}




/*************************************************
*           Advance to next line in store        *
*************************************************/

/* A separate procedure exists for each file, for
simplicity and efficiency. */

int nextline_one(pvoid)
{
if (pline_one == NULL || pline_one->next == NULL) return FALSE;
pline_one = pline_one->next;
return TRUE;
}

int nextline_two(pvoid)
{
if (pline_two == NULL || pline_two->next == NULL) return FALSE;
pline_two = pline_two->next;
return TRUE;
}


/*************************************************
*             Read a line into store             *
*************************************************/

/* A separate procedure exists for each file, for
simplicity and efficiency. */

void readline_one(pvoid)
{
int count = 0;
int c = fgetc(f_one);
line *nextline = (line *)bufnext_one;

bufnext_one = nextline->text;
if (bufnext_one >= buftop_one) moan(2, name_one);

nextline->next = NULL;

lines_one ++;
if (c == EOF)
  {
  eof_one = TRUE;
  nextline->number = -lines_one;
  }
else
  {
  nextline->number = lines_one;
  for (;;)
    {
    if (c == EOF) c = '\n';
    if (c == '\n')
      {
      if (!exact)
        while (bufnext_one > nextline->text)
          { if (bufnext_one[-1] == ' ') bufnext_one--; else break; }
      *(bufnext_one++) = '\n';
      if (bufnext_one >= buftop_one) moan(2, name_one);
      break;
      }
    if (c == '\t' && !exact)
      do { *(bufnext_one++) = ' '; count++; } while ((count & 7) != 0);
    else { *(bufnext_one++) = c; count++; }
    if (bufnext_one >= buftop_one) moan(2, name_one);
    c = fgetc(f_one);
    }
  }

if (lastline_one != NULL) lastline_one->next = nextline;
lastline_one = nextline;
pline_one = nextline;

bufnext_one = (char *) (((intptr_t)bufnext_one+ sizeof (intptr_t) - 1)  & (-(sizeof (intptr_t))));
}



void readline_two(pvoid)
{
int count = 0;
int c = fgetc(f_two);
line *nextline = (line *)bufnext_two;

bufnext_two = nextline->text;
if (bufnext_two >= buftop_two) moan(2, name_two);

nextline->next = NULL;

lines_two ++;
if (c == EOF)
  {
  eof_two = TRUE;
  nextline->number = -lines_two;
  }
else
  {
  nextline->number = lines_two;
  for (;;)
    {
    if (c == EOF) c = '\n';
    if (c == '\n')
      {
      if (!exact)
        while (bufnext_two > nextline->text)
          { if (bufnext_two[-1] == ' ') bufnext_two--; else break; }
      *(bufnext_two++) = '\n';
      if (bufnext_two >= buftop_two) moan(2, name_two);
      break;
      }
    if (c == '\t' && !exact)
      do { *(bufnext_two++) = ' '; count++; } while ((count & 7) != 0);
    else { *(bufnext_two++) = c; count++; }
    if (bufnext_two >= buftop_two) moan(2, name_two);
    c = fgetc(f_two);
    }
  }

if (lastline_two != NULL) lastline_two->next = nextline;
lastline_two = nextline;
pline_two = nextline;

bufnext_two = (char *) (((intptr_t)bufnext_two+ sizeof (intptr_t) - 1)  & (-(sizeof (intptr_t))));
}



/**************************************************
*              Compare two lines                  *
**************************************************/

int compare_lines(a, b)
line *a, *b;
{
int n1 = a->number;
int n2 = b->number;
char *s = a->text;
char *t = b->text;

if (n1 < 0  &&  n2 < 0) return TRUE;
if (n1 < 0  ||  n2 < 0) return FALSE;

while (*s == *t)
  {
  if (*s == '\n') return TRUE;
  s++; t++;
  }

return FALSE;
}


/*************************************************
*             Re-synchronizing code              *
*************************************************/

int resync(pvoid)
{
int i;
int matched = TRUE;
line *tline_one = pline_one;
line *tline_two = pline_two;

if (eof_one || eof_two) matched = FALSE; else
  {
  for (i = 1; i < sync_count; i++)
    {
    if (!nextline_one()) readline_one();
    if (!nextline_two()) readline_two();
    if (!compare_lines(pline_one, pline_two)) { matched = FALSE; break; }
    if (eof_one || eof_two) { matched = FALSE; break; }
    }
  }

if (matched) write_message(tline_one, tline_two); else
  {
  pline_one = tline_one;
  pline_two = tline_two;
  }

return matched;
}



/*************************************************
*                 Main compare code              *
*************************************************/

void compare(pvoid)
{
int matched = TRUE;

/* Big main loop - exit by return or unmatched at eof */

while (matched)
  {
  /* First minor loop, while in step */

  while (matched && !eof_one && !eof_two)
    {
    /* Advance or read next lines */

    if (!nextline_one())
      {
      bufnext_one = bufbase_one;
      lastline_one = NULL;
      readline_one();
      }

    if (!nextline_two())
      {
      bufnext_two = bufbase_two;
      lastline_two = NULL;
      readline_two();
      }

    /* Compare and check for end of file */

    matched = compare_lines(pline_one, pline_two);

    } /* End first minor loop */

  if (matched) return;    /* successful end of file */

  /* There has been a mis-match */

  return_code++;
  rootline_one = pline_one;   /* Fail point */
  rootline_two = pline_two;

  /* Second minor loop, trying to regain sync */

  while (!eof_one || !eof_two)
    {
    /* Advance one and scan all of two */

    if (!eof_one)
      {
      line *zline = pline_two;
      if (!nextline_one()) readline_one();
      pline_two = rootline_two;
      for (;;)
        {
        if (compare_lines(pline_one, pline_two))
          {
          matched = resync();
          if (matched) break;
          }
        if (pline_two == zline) break;
        pline_two = pline_two->next;
        }
      if (matched) break;
      }

    /* Advance two and scan all of one */

    if (!eof_two)
      {
      line *zline = pline_one;
      if (!nextline_two()) readline_two();
      pline_one = rootline_one;
      for (;;)
        {
        if (compare_lines(pline_one, pline_two))
          {
          matched = resync();
          if (matched) break;
          }
        if (pline_one == zline) break;
        pline_one = pline_one->next;
        }
      if (matched) break;
      }

    } /* End second minor loop */

  } /* End of major loop */

write_message(lastline_one, lastline_two);
}




/*************************************************
*                   Entry Point                  *
*************************************************/

int main(argc, argv)
int argc;
char **argv;
{
int argp = 1;
int arg_id = FALSE;
int arg_help = FALSE;

f_out = stdout;

/* Scan argument strings */

while (argp < argc)
  {
  char  *arg = argv[argp];
  char **lv_name = (name_one == NULL)? &name_one:&name_two;  /* default for positional */
  int   *lv_value = NULL;
  int    value = TRUE;

  if (arg[0] == '-')
    {                            /* keyed argument */
    if (EqString(arg,"-help") || EqString(arg, "-h"))
      { arg_help = TRUE; value = FALSE; }
    else if (EqString(arg, "-id"))
      { arg_id = TRUE; value = FALSE; }
    else if (EqString(arg, "-exact"))
      { exact = TRUE; value = FALSE; }
    else if (EqString(arg, "-noecho"))
      { echo = FALSE; value = FALSE; }
    else if (EqString(arg, "-to")) lv_name = &to_name;
    else if (EqString(arg, "-sync") || EqString(arg, "-s"))
       lv_value = &sync_count;
    else if (EqString(arg, "-buffer")) lv_value = &storesize;
    else { printf("Unknown keyword %s\n", arg); exit(99); }

    if (++argp >= argc && value)
      { printf("Value for keyword %s missing\n", arg); exit(99); }
    }

  /* Deal with keys that take values */

  if (value)
    {
    if (lv_value == &sync_count || lv_value == &storesize)
      {
      int ch;
      int i = 0;
      char *argval = argv[argp++];
      *lv_value = 0;
      while ((ch = argval[i++]) != 0)
        {
        if ('0' <= ch && ch <= '9') *lv_value = 10*(*lv_value) + ch - '0'; else
          {
          printf("Number expected after \"%s\" but \"%s\" read\n",
            arg, argval);
          exit(99);
          }
        }
      }

    else if (*lv_name != NULL)
      {
      printf("Keyword expected but \"%s\" read", arg);
      printf(" - use \"cmp -h\" for help\n");
      exit(99);
      }
    else *lv_name = argv[argp++];
    }
  }

/* Deal with help and id */

if (arg_id && !arg_help)
  {
  printf("PH's CMP v%d\n", version);
  exit(0);
  }

if (arg_help)
  {
  givehelp();
  exit(0);
  }

/* Deal with file names */

if (name_one == NULL || name_two == NULL) moan(3, "");

if (to_name != NULL)
  {
  f_out = fopen(to_name, "w");
  if (f_out == NULL) moan(1, to_name);
  }

/* Further general initialization */

if (storesize < minstore) storesize = defaultstore;
f_one = fopen(name_one, "r");
if (f_one == NULL) moan(1, name_one);
f_two = fopen(name_two, "r");
if (f_two == NULL) moan(1, name_two);

bufbase_one = (char *)malloc(storesize);
buftop_one = bufbase_one + storesize;
bufbase_two = (char *)malloc(storesize);
buftop_two = bufbase_two + storesize;

/* Do the job */

compare();

/* Final messages */

if (return_code == 0)
  fprintf(f_out, "\"%s\" and \"%s\" are identical.\n", name_one, name_two);
else
  {
  if (echo) rule('=', 15);
  fprintf(f_out, "%d difference", return_code);
  if (return_code != 1) fprintf(f_out, "s");
  fprintf(f_out, " found.\n");

  lines_one -= 1;
  fprintf(f_out, "\"%s\" contains %d line", name_one, lines_one);
  if (lines_one != 1) fprintf(f_out, "s");

  lines_two -= 1;
  fprintf(f_out, "; \"%s\" contains %d line", name_two, lines_two);
  if (lines_two != 1) fprintf(f_out, "s");
  fprintf(f_out, ".\n");
  }

free(bufbase_one);
free(bufbase_two);

fclose(f_one);
fclose(f_two);
if (f_out != stdout) fclose(f_out);

return return_code;
}

/* End of PH-Compare. */
