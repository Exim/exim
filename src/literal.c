/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2006 */
/* Written by Philip Hazel. */

/* This module contains code for processing lines of literal text. */

#include "xfpt.h"



/*************************************************
*         Process a line of literal text         *
*************************************************/

/* All we need to do is make sure that any & < and > characters are correctly
escaped.

Argument:   the line to be processed
Returns:    nothing
*/

void
literal_process(uschar *p)
{
while (*p != 0)
  {
  int c = *p++;
  if (c == '&')      (void)fprintf(outfile, "&amp;");
  else if (c == '<') (void)fprintf(outfile, "&lt;");
  else if (c == '>') (void)fprintf(outfile, "&gt;");
  else (void)fputc(c, outfile);
  }
}


/* End of literal.c */
