/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2006 */
/* Written by Philip Hazel. */

/* This module contains a number of miscellaneous small utility functions. */


#include "xfpt.h"



/*************************************************
*              Detrail a line                    *
*************************************************/

/* This removes all white space, including newlines, at the end of a string.

Argument:   the string
Returns:    nothing
*/

void
misc_detrail(uschar *p)
{
uschar *q = p + Ustrlen(p);
while (q > p && isspace(q[-1])) q--;
*q = 0;
}


/*************************************************
*               Malloc with check                *
*************************************************/

/* The program dies if the memory is not available.

Argument:    size required
Returns:     pointer
*/

void *
misc_malloc(int size)
{
void *yield = malloc(size);
if (yield == NULL) error(1, size);   /* Fatal error */
return yield;
}


/*************************************************
*        Copy a string into malloc memory        *
*************************************************/

/*
Arguments:
  p            pointer to start
  length       length

Returns:       pointer to the copied string
*/

uschar *
misc_copystring(uschar *p, int length)
{
uschar *yield = misc_malloc(length + 1);
memcpy(yield, p, length);
yield[length] = 0;
return yield;
}




/*************************************************
*              Read string in quotes             *
*************************************************/

/* Enter pointing to the opening quote, either single or double. Use
quote-doubling to include the quote. The string is copied into a given buffer
or to heap memory.

Arguments:
  p           points to the opening quote
  lptr        if non-NULL, where to return number of characters consumed,
                including the quotes
  buffer      NULL => get heap memory, else pointer to buffer
  blength     size of buffer

Returns:      pointer to the copied string
*/

uschar *
misc_readstring(uschar *p, int *lptr, uschar *buffer, int blength)
{
int term = *p;
int length;
uschar *pp, *yield;

for (pp = p + 1;; pp++)
  {
  if (*pp == 0) break;
  if (*pp == term) { if (pp[1] != term) break; pp++; }
  }

length = pp - p;   /* stringlength, over-estimate if any doubled */
if (lptr != NULL) *lptr = length + 1;

if (buffer == NULL)
  {
  yield = pp = misc_malloc(length + 1);
  }
else
  {
  if (length + 1 > blength) error(20, length + 1, blength);  /* Hard */
  yield = pp = buffer;
  }

for (++p;; p++)
  {
  if (*p == 0) break;
  if (*p == term) { if (p[1] != term) break; p++; }
  *pp++ = *p;
  }

*pp = 0;

return yield;
}



/*************************************************
*        Read a possibly quoted item             *
*************************************************/

/* If the item is not in quotes, it is terminated by one of a list of
terminators, or alternatively, by white space. The number of characters
consumed includes any trailing spaces, but not a terminator character.

Arguments:
  p           pointer to the first significant character in the input
  term        if non-NULL, contains the possible terminators
  lptr        if non-NULL, where to return the number of characters consumed
  buffer      NULL => get heap memory, else pointer to buffer
  blength     size of buffer

Returns:      pointer to the string, in heap memory
*/

uschar *
misc_readitem(uschar *p, uschar *term, int *lptr, uschar *buffer, int blength)
{
uschar *yield;
int length;

if (*p == '\"' || *p == '\'')
  {
  yield = misc_readstring(p, &length, buffer, blength);
  p += length;
  }

else
  {
  uschar *pp = p;
  if (term == NULL)
    while (*p != 0 && !isspace(*p)) p++;
  else
    while (Ustrchr(term, *p) == NULL) p++;   /* NB zero will match */

  length = p - pp;
  if (buffer == NULL)
    {
    yield = misc_malloc(length + 1);
    }
  else
    {
    if (length + 1 > blength) error(20, length + 1, blength);  /* Hard */
    yield = buffer;
    }
  memcpy(yield, pp, length);
  yield[length] = 0;
  }

while (isspace(*p))
  {
  p++;
  length++;
  }

if (lptr != NULL) *lptr = length;
return yield;
}


/* End of misc.c */
