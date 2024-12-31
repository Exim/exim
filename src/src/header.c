/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2023 */
/* Copyright (c) University of Cambridge 1995 - 2016 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */


#include "exim.h"


/*************************************************
*         Test a header for matching name        *
*************************************************/

/* This function tests the name of a header. It is made into a function because
it isn't just a string comparison: spaces and tabs are permitted between the
name and the colon. The h->text field should nowadays never be NULL, but check
it just in case.

Arguments:
  h         points to the header
  name      the name to test
  len       the length of the name
  notdel    if TRUE, force FALSE for deleted headers

Returns:    TRUE or FALSE
*/

BOOL
header_testname(const header_line * h, const uschar * name, int len,
  BOOL notdel)
{
uschar *tt;
if (h->type == '*' && notdel) return FALSE;
if (!h->text || strncmpic(h->text, name, len) != 0) return FALSE;
tt = h->text + len;
while (*tt == ' ' || *tt == '\t') tt++;
return *tt == ':';
}

/* This is a copy of the function above, only that it is possible to pass
   only the beginning of a header name. It simply does a front-anchored
   substring match. Arguments and Return codes are the same as for
   header_testname() above. */

BOOL
header_testname_incomplete(const header_line * h, const uschar * name,
    int len, BOOL notdel)
{
if (h->type == '*' && notdel) return FALSE;
if (!h->text || strncmpic(h->text, name, len) != 0) return FALSE;
return TRUE;
}


/*************************************************
*         Add new header backend function        *
*************************************************/

/* The header_last variable points to the last header during message reception
and delivery; otherwise it is NULL. We add new headers only when header_last is
not NULL. The function may get called sometimes when it is NULL (e.g. during
address verification where rewriting options exist). When called from a filter,
there may be multiple header lines in a single string.

This is an internal static function that is the common back end to the external
functions defined below. The general interface allows the header to be inserted
before or after a given occurrence of a given header.

(a) if "name" is NULL, the header is added at the end of all the existing
    headers if "after" is true, or at the start if it is false. The "topnot"
    flag is not used.

(b) If "name" is not NULL, the first existing header with that name is sought.
    If "after" is false, the new header is added before it. If "after" is true,
    a check is made for adjacent headers with the same name, and the new header
    is added after the last of them. If a header of the given name is not
    found, the new header is added first if "topnot" is true, and at the bottom
    otherwise.

Arguments:
  after     TRUE for "after", FALSE for "before"
  name      name if adding at a specific header, else NULL
  topnot    TRUE to add at top if no header found
  type      Exim header type character (htype_something)
  format    sprintf format
  ap        va_list value for format arguments

Returns:    pointer to header struct (last one, if multiple added)
*/

static header_line *
header_add_backend(BOOL after, uschar *name, BOOL topnot, int type,
  const char *format, va_list ap)
{
header_line *h, *new = NULL;
header_line **hptr;

uschar * p, * q, * buf;
gstring gs;

if (!header_last) return NULL;

gs.s = buf = store_get(HEADER_ADD_BUFFER_SIZE, GET_UNTAINTED);
gs.size = HEADER_ADD_BUFFER_SIZE;
gs.ptr = 0;

if (!string_vformat(&gs, SVFMT_REBUFFER, format, ap))
  log_write_die(0, LOG_MAIN, "string too long in header_add: "
    "%.100Y ...", &gs);

if (gs.s != buf) store_release_above(buf);
gstring_release_unused(&gs);
string_from_gstring(&gs);

/* Find where to insert this header */

if (!name)
  if (after)
    {
    hptr = &header_last->next;
    h = NULL;
    }
  else
    {
    hptr = &header_list;

    /* header_list->text can be NULL if we get here between when the new
    received header is allocated and when it is actually filled in. We want
    that header to be first, so skip it for now. */

    if (!header_list->text)
      hptr = &header_list->next;
    h = *hptr;
    }

else
  {
  int len = Ustrlen(name);

  /* Find the first non-deleted header with the correct name. */

  for (hptr = &header_list; (h = *hptr); hptr = &h->next)
    if (header_testname(h, name, len, TRUE))
      break;

  /* Handle the case where no header is found. To insert at the bottom, nothing
  needs to be done. */

  if (!h)
    {
    if (topnot)
      {
      hptr = &header_list;
      h = header_list;
      }
    }

  /* Handle the case where a header is found. Check for more if "after" is
  true. In this case, we want to include deleted headers in the block. */

  else if (after)
    for (;;)
      {
      if (!h->next || !header_testname(h, name, len, FALSE)) break;
      hptr = &h->next;
      h = h->next;
      }
  }

/* Loop for multiple header lines, taking care about continuations. At this
point, we have hptr pointing to the link field that will point to the new
header, and h containing the following header, or NULL. */

for (p = q = gs.s; *p; p = q)
  {
  for (;;)
    {
    q = Ustrchr(q, '\n');
    if (!q) q = p + Ustrlen(p);
    if (*(++q) != ' ' && *q != '\t') break;
    }

  new = store_get(sizeof(header_line), GET_UNTAINTED);
  new->text = string_copyn(p, q - p);
  new->slen = q - p;
  new->type = type;
  new->next = h;

  *hptr = new;
  hptr = &new->next;

  if (!h) header_last = new;
  }
return new;
}


/*************************************************
*      Add new header anywhere in the chain      *
*************************************************/

/* This is an external interface to header_add_backend().

Arguments:
  after     TRUE for "after", FALSE for "before"
  name      name if adding at a specific header, else NULL
  topnot    TRUE to add at top if no header found
  type      Exim header type character (htype_something)
  format    sprintf format
  ...       format arguments

Returns:    pointer to header struct added
*/

header_line *
header_add_at_position_internal(BOOL after, uschar *name, BOOL topnot, int type,
  const char *format, ...)
{
header_line * h;
va_list ap;
va_start(ap, format);
h = header_add_backend(after, name, topnot, type, format, ap);
va_end(ap);
return h;
}


/* Documented external i/f for local_scan */
void
header_add_at_position(BOOL after, uschar *name, BOOL topnot, int type,
  const char *format, ...)
{
va_list ap;
va_start(ap, format);
(void) header_add_backend(after, name, topnot, type, format, ap);
va_end(ap);
}

/*************************************************
*            Add new header on end of chain      *
*************************************************/

/* This is now a convenience interface to header_add_backend().

Arguments:
  type      Exim header type character
  format    sprintf format
  ...       arguments for the format

Returns:    nothing
*/

void
header_add(int type, const char *format, ...)
{
va_list ap;
va_start(ap, format);
(void) header_add_backend(TRUE, NULL, FALSE, type, format, ap);
va_end(ap);
}



/*************************************************
*        Remove (mark as old) a header           *
*************************************************/

/* This function is used by the filter code; it is also exported in the
local_scan() API. If no header is found, the function does nothing.

Arguments:
  occ           the occurrence number for multiply-defined headers
                  <= 0 means "all"; deleted headers are not counted
  name          the header name

Returns:        nothing
*/

void
header_remove(int occ, const uschar *name)
{
int hcount = 0;
int len = Ustrlen(name);
for (header_line * h = header_list; h; h = h->next)
  if (header_testname(h, name, len, TRUE) && (occ <= 0 || ++hcount == occ))
    {
    h->type = htype_old;
    if (occ > 0) return;
    }
}



/*************************************************
*          Check the name of a header            *
*************************************************/

/* This function scans a table of header field names that Exim recognizes, and
returns the identification of a match. If "resent" is true, the header is known
to start with "resent-". In that case, the function matches only those fields
that are allowed to appear with resent- in front of them.

Arguments:
  h             points to the header line
  is_resent     TRUE if the name starts "Resent-"

Returns:        One of the htype_ enum values, identifying the header
*/

int
header_checkname(header_line *h, BOOL is_resent)
{
uschar *text = h->text;
header_name *bot = header_names;
header_name *top = header_names + header_names_size;

if (is_resent) text += 7;

while (bot < top)
  {
  header_name *mid = bot + (top - bot)/2;
  int c = strncmpic(text, mid->name, mid->len);

  if (c == 0)
    {
    uschar * s = text + mid->len;
    if (Uskip_whitespace(&s) == ':')
      return (!is_resent || mid->allow_resent)? mid->htype : htype_other;
    c = 1;
    }

  if (c > 0) bot = mid + 1; else top = mid;
  }

return htype_other;
}


/*************************************************
*       Scan a header for certain strings        *
*************************************************/

/* This function is used for the "personal" test. It scans a particular header
line for any one of a number of strings, matched caselessly either as plain
strings, or as regular expressions. If the header line contains a list of
addresses, each match is applied only to the operative part of each address in
the header, and non-regular expressions must be exact matches.

The patterns can be provided either as a chain of string_item structures, or
inline in the argument list, or both. If there is more than one header of the
same name, they are all searched.

Arguments:
  name           header name, including the trailing colon
  has_addresses  TRUE if the header contains a list of addresses
  cond           value to return if the header contains any of the strings
  strings        points to a chain of string_item blocks
  count          number of inline strings
  ...            the inline strings

Returns:         cond if the header exists and contains one of the strings;
                   otherwise !cond
*/


/* First we have a local subroutine to handle a single pattern */

static BOOL
one_pattern_match(uschar * name, int slen, BOOL has_addresses, uschar * pattern)
{
BOOL yield = FALSE;
const pcre2_code *re = NULL;

/* If the pattern is a regex, compile it. Bomb out if compiling fails; these
patterns are all constructed internally and should be valid. */

if (*pattern == '^') re = regex_must_compile(pattern, MCS_CASELESS, FALSE);

/* Scan for the required header(s) and scan each one */

for (header_line * h = header_list; !yield && h; h = h->next)
  {
  if (h->type == htype_old || slen > h->slen ||
      strncmpic(name, h->text, slen) != 0)
    continue;

  /* If the header is a list of addresses, extract each one in turn, and scan
  it. A non-regex scan must be an exact match for the address. */

  if (has_addresses)
    {
    uschar *s = h->text + slen;

    while (!yield && *s)
      {
      uschar *error, *next;
      uschar *e = parse_find_address_end(s, FALSE);
      int terminator = *e;
      int start, end, domain;

      /* Temporarily terminate the string at the address end while extracting
      the operative address within. */

      *e = 0;
      next = parse_extract_address(s, &error, &start, &end, &domain, FALSE);
      *e = terminator;

      /* Move on, ready for the next address */

      s = e;
      if (*s == ',') s++;

      /* If there is some kind of syntax error, just give up on this header
      line. */

      if (!next) break;

      /* Otherwise, test for the pattern; a non-regex must be an exact match */

      yield = re
	? regex_match(re, next, -1, NULL)
        : (strcmpic(next, pattern) == 0);
      }
    }

  /* For headers that are not lists of addresses, scan the entire header line,
  and just require "contains" for non-regex patterns. */

  else
    {
    yield = re
      ? regex_match(re, h->text, h->slen, NULL)
      : (strstric(h->text, pattern, FALSE) != NULL);
    }
  }

return yield;
}


/* The externally visible interface */

BOOL
header_match(uschar * name, BOOL has_addresses, BOOL cond, string_item * strings,
  int count, ...)
{
va_list ap;
int slen = Ustrlen(name);

for (string_item * s = strings; s; s = s->next)
  if (one_pattern_match(name, slen, has_addresses, s->text))
    return cond;

va_start(ap, count);
for (int i = 0; i < count; i++)
  if (one_pattern_match(name, slen, has_addresses, va_arg(ap, uschar *)))
    {
    va_end(ap);
    return cond;
    }
va_end(ap);

return !cond;
}



/* Wrap and truncate a string for use as a header.
Convert either the sequence "\n" or a real newline into newline plus indent.
If that still takes us past the column limit, look for the last space
and split there too.
Limit to the given max total char count.

Return: string or NULL */

uschar *
wrap_header(const uschar * s, unsigned cols, unsigned maxchars,
  const uschar * indent, unsigned indent_cols)
{
gstring * g = NULL;

if (maxchars == 0) maxchars = INT_MAX;
if (cols == 0) cols = INT_MAX;

if (s && *s)
  {
  int sleft = Ustrlen(s);
  for(unsigned llen = 0; ; llen = indent_cols)
    {
    const uschar * t;
    unsigned ltail = 0, glen;

    if ((t = Ustrchr(s, '\\')) && t[1] == 'n')
      ltail = 2;
    else if ((t = Ustrchr(s, '\n')))
      ltail = 1;
    else
      t = s + sleft;

    if ((llen + t - s) > cols)		/* more than a linesworth of s */
      {					/* look backward for whitespace */
      for (const uschar * u = s + cols - llen; u > s + 10; --u) if (isspace(*u))
	{
	llen = u - s;
	while (u > s+1 && isspace(u[-1])) --u;	/* find start of whitespace */
	g = string_catn(g, s, u - s);
	s += ++llen;				/* skip the space */
	while (*s && isspace(*s))		/* and any trailing */
	  s++, llen++;
	goto LDONE;
	}
					/* no whitespace */
      if (llen < cols)
	{					/* just linebreak at 80 */
	llen = cols - llen;
	g = string_catn(g, s, llen);
	s += llen;
	}
      else
        llen = 0;
      LDONE: ;
      }
    else				/* rest of s fits in line */
      {
      llen = t - s;
      g = string_catn(g, s, llen);
      s = t + ltail;
      }

    if (!*s)
      break;				/* no trailing linebreak */
    if ((glen = gstring_length(g)) >= maxchars)
      {
      gstring_trim(g, glen - maxchars);
      break;				/* no trailing linebreak */
      }
    sleft -= llen;
    g = string_catn(g, US"\n", 1);
    g = string_catn(g, indent, 1);
    }
  }
gstring_release_unused(g);
return string_from_gstring(g);
}


/* End of header.c */
