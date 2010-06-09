/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2008 */
/* Written by Philip Hazel. */

/* Error handling routines */

#include "xfpt.h"


/* Error codes */

#define ec_noerror   0
#define ec_warning   1
#define ec_serious   2
#define ec_failed    3
#define ec_disaster  4


/*************************************************
*             Static variables                   *
*************************************************/

static int  error_count = 0;
static int  warning_count = 0;
static BOOL suppress_warnings = FALSE;



/*************************************************
*            Texts and return codes              *
*************************************************/

typedef struct {
  char ec;
  const char *text;
} error_struct;


static error_struct error_data[] = {

/* 0-4 */
{ ec_disaster, "failed to open %s: %s" },
{ ec_disaster, "malloc failed: requested %d bytes" },
{ ec_serious,  "unknown directive line: %s" },
{ ec_serious,  "missing semicolon after \"&%.*s\"" },
{ ec_serious,  "unexpected character \"%c\" after \"&#\"" },
/* 5-9 */
{ ec_serious,  "\"layout\", \"text\", \"xml\", or \"off\" expected, but \"%s\" found" },
{ ec_serious,  "unknown flag \"&%c\"" },
{ ec_serious,  "missing closing flag %s" },
{ ec_serious,  "flag nesting error: \"%s\" expected before \"%s\"" },
{ ec_serious,  "a flag must begin with \"&\"" },
/* 10-14 */
{ ec_serious,  "a flag must contain more than just \"&\"" },
{ ec_serious,  "malformed directive\n   %s" },
{ ec_serious,  "line stack is empty" },
{ ec_serious,  "missing %s at end of file" },
{ ec_serious,  "a macro must be given a name" },
/* 15-19 */
{ ec_serious,  "%s is permitted only inside a macro" },
{ ec_serious,  "unexpected %s" },
{ ec_serious,  "bad macro argument substitution: \"%c\" follows \"%s\"" },
{ ec_serious,  "relative macro argument not in \"eacharg\" section" },
{ ec_warning,  "extra characters at end of directive\n"
               "   %s %s\n   %.*s%.*s" },
/* 20-24 */
{ ec_disaster, "string too long for internal buffer (%d > %d)" },
{ ec_serious,  "entity \"%s\" has already been defined" },
{ ec_serious,  "\"%s\" is not permitted in an inline macro call" },
{ ec_serious,  "unknown macro \"%.*s\" in inline macro call" },
{ ec_serious,  "missing closing parenthesis in inline macro call:\n   %s" },
/* 25-29 */
{ ec_serious,  "ampersand found at end of line or string - ignored" },
{ ec_serious,  "\"begin\" or \"end\" expected, but \"%s\" found" },
{ ec_serious,  "\".nest begin\" too deeply nested" },
{ ec_serious,  "\".nest end\" incorrectly nested" }
};

#define error_maxerror 28



/*************************************************
*              Error message generator           *
*************************************************/

/* This function output an error or warning message, and may abandon the
process if the error is sufficiently serious, or if there have been too many
less serious errors. If there are too many warnings, subsequent ones are
suppressed.

Arguments:
  n           error number
  ...         arguments to fill into message

Returns:      nothing, but some errors do not return
*/

void
error(int n, ...)
{
int ec, i;
macroexe *me;
istackstr *fe;
va_list ap;
va_start(ap, n);

if (n > error_maxerror)
  {
  (void)fprintf(stderr, "** Unknown error number %d\n", n);
  ec = ec_disaster;
  }
else
  {
  ec = error_data[n].ec;
  if (ec == ec_warning)
    {
    if (suppress_warnings) return;
    (void)fprintf(stderr, "** Warning: ");
    }
  else if (ec > ec_warning)
    (void)fprintf(stderr, "** Error: ");
  (void)vfprintf(stderr, error_data[n].text, ap);
  (void)fprintf(stderr, "\n");
  }

va_end(ap);

me = macrocurrent;
fe = istack;

for (i = from_type_ptr; i >= 0; i--)
  {
  if (from_type[i] == FROM_MACRO)
    {
    (void)fprintf(stderr, "   Processing macro %s\n", me->macro->name);
    me = me->prev;
    }
  else
    {
    if (fe != NULL)
      {
      (void)fprintf(stderr, "   Detected near line %d of %s\n",
        fe->linenumber, fe->filename);
      fe = fe->prev;
      }
    else
      {
      (void)fprintf(stderr, "   Detected near end of file\n");
      }
    }
  }

if (ec == ec_warning)
  {
  warning_count++;
  if (warning_count > 40)
    {
    (void)fprintf(stderr, "** Too many warnings - subsequent ones suppressed\n");
    suppress_warnings = TRUE;
    }
  }

else if (ec > ec_warning)
  {
  return_code = EXIT_FAILURE;
  error_count++;
  if (error_count > 40)
    {
    (void)fprintf(stderr, "** Too many errors\n");
    ec = ec_failed;
    }
  }

if (ec >= ec_failed)
  {
  (void)fprintf(stderr, "** xfpt abandoned\n");
  exit(EXIT_FAILURE);
  }

(void)fprintf(stderr, "\n");   /* blank before next output */
}

/* End of error.c */
