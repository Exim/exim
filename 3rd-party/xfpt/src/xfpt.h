/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2008 */

/* Written by Philip Hazel. I wrote this because I found AsciiDoc to be to slow
for large documents, and also to have too many quirks and gotchas. */


#ifndef INCLUDED_xfpt_H
#define INCLUDED_xfpt_H

/* General header file for all modules */

#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>


/* These are some parameters that specify sizes of things in the code. They
must appear before including the local headers. */


/* These values do not necessarily have to appear before including the local
headers, but they might as well be together with those above. */

#define INBUFFSIZE          1024
#define PARABUFFSIZE       10000
#define FLAGSTACKSIZE         40
#define MAXNEST                3
#define FROM_TYPE_STACKSIZE   20


/* Type of current input */

enum { FROM_FILE, FROM_MACRO };


/* Nested block indicators for read_paragraph() */

enum { NEST_NO, NEST_BEGIN, NEST_END };


/* The literal states */

enum { LITERAL_OFF, LITERAL_LAYOUT, LITERAL_TEXT, LITERAL_XML };


/* More header files for xfpt */

#include "mytypes.h"
#include "structs.h"
#include "globals.h"
#include "functions.h"

#endif   /* INCLUDED_xfpt_H */

/* End of xfpt.h */
