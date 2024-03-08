/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2023 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Miscellaneous string-handling functions. Some are not required for
utilities and tests, and are cut out by the COMPILE_UTILITY macro. */


#include "exim.h"
#include <assert.h>


#ifndef COMPILE_UTILITY
/*************************************************
*            Test for IP address                 *
*************************************************/

/* This used just to be a regular expression, but with IPv6 things are a bit
more complicated. If the address contains a colon, it is assumed to be a v6
address (assuming HAVE_IPV6 is set). If a mask is permitted and one is present,
and maskptr is not NULL, its offset is placed there.

Arguments:
  s         a string
  maskptr   NULL if no mask is permitted to follow
            otherwise, points to an int where the offset of '/' is placed
            if there is no / followed by trailing digits, *maskptr is set 0
  errp      NULL if no diagnostic information is required, and if the netmask
            length should not be checked. Otherwise it is set pointing to a short
            descriptive text.

Returns:    0 if the string is not a textual representation of an IP address
            4 if it is an IPv4 address
            6 if it is an IPv6 address

The legacy string_is_ip_address() function follows below.
*/

int
string_is_ip_addressX(const uschar * ip_addr, int * maskptr, const uschar ** errp)
{
uschar * slash, * percent, * endp = NULL;
long int mask = 0;
const uschar * addr = NULL;
int af;
union { /* we do not need this, but inet_pton() needs a place for storage */
  struct in_addr sa4;
  struct in6_addr sa6;
} sa;

/* If there is a slash, but we didn't request a (optional) netmask,
we return failure, as we do if the mask isn't a pure numerical value,
or if it is negative. The actual length is checked later, once we know
the address family. */

if (slash = Ustrchr(ip_addr, '/'))
  {
  uschar * rest;

  if (!maskptr)
    {
    if (errp) *errp = US"netmask found, but not requested";
    return 0;
    }

  mask = Ustrtol(slash+1, &rest, 10);
  if (*rest || mask < 0)
    {
    if (errp) *errp = US"netmask not numeric or <0";
    return 0;
    }

  *maskptr = slash - ip_addr;	/* offset of the slash */
  endp = slash;
  }
else if (maskptr)
  *maskptr = 0;			/* no slash found */

/* The interface-ID suffix (%<id>) is optional (for IPv6). If it
exists, we check it syntactically. Later, if we know the address
family is IPv4, we might reject it.
The interface-ID is mutually exclusive with the netmask, to the
best of my knowledge. */

if (percent = Ustrchr(ip_addr, '%'))
  {
  if (slash)
    {
    if (errp) *errp = US"interface-ID and netmask are mutually exclusive";
    return 0;
    }
  for (uschar *p = percent+1; *p; p++)
    if (!isalnum(*p) && !ispunct(*p))
      {
      if (errp) *errp = US"interface-ID must match [[:alnum:][:punct:]]";
      return 0;
      }
  endp = percent;
  }

/* inet_pton() can't parse netmasks and interface IDs, so work on a shortened copy
allocated on the current stack */

if (endp)
  {
  ptrdiff_t l = endp - ip_addr;
  if (l > 255)
    {
    if (errp) *errp = US"rudiculous long ip address string";
    return 0;
    }
  addr = string_copyn(ip_addr, l);
  }
else
  addr = ip_addr;

af = Ustrchr(addr, ':') ? AF_INET6 : AF_INET;
if (!inet_pton(af, CCS addr, &sa))
  {
  if (errp) *errp = af == AF_INET6 ? US"IP address string not parsable as IPv6"
				   : US"IP address string not parsable IPv4";
  return 0;
  }

/* we do not check the values of the mask here, as
this is done on the callers side (but I don't understand why), so
actually I'd like to do it here, but it breaks at least testcase 0002 */

switch (af)
  {
  case AF_INET6:
      if (errp && mask > 128)
	{
	*errp = US"IPv6 netmask value must not be >128";
	return 0;
	}
      return 6;
  case AF_INET:
      if (percent)
	{
	if (errp) *errp = US"IPv4 address string must not have an interface-ID";
	return 0;
	}
      if (errp && mask > 32)
	{
	*errp = US"IPv4 netmask value must not be >32";
	return 0;
	}
      return 4;
  default:
      if (errp) *errp = US"unknown address family (should not happen)";
      return 0;
  }
}


int
string_is_ip_address(const uschar * ip_addr, int * maskptr)
{
return string_is_ip_addressX(ip_addr, maskptr, NULL);
}

#endif  /* COMPILE_UTILITY */


/*************************************************
*              Format message size               *
*************************************************/

/* Convert a message size in bytes to printing form, rounding
according to the magnitude of the number. A value of zero causes
a string of spaces to be returned.

Arguments:
  size        the message size in bytes
  buffer      where to put the answer

Returns:      pointer to the buffer
              a string of exactly 5 characters is normally returned
*/

uschar *
string_format_size(int size, uschar *buffer)
{
if (size == 0) Ustrcpy(buffer, US"     ");
else if (size < 1024) sprintf(CS buffer, "%5d", size);
else if (size < 10*1024)
  sprintf(CS buffer, "%4.1fK", (double)size / 1024.0);
else if (size < 1024*1024)
  sprintf(CS buffer, "%4dK", (size + 512)/1024);
else if (size < 10*1024*1024)
  sprintf(CS buffer, "%4.1fM", (double)size / (1024.0 * 1024.0));
else
  sprintf(CS buffer, "%4dM", (size + 512 * 1024)/(1024*1024));
return buffer;
}



#ifndef COMPILE_UTILITY
/*************************************************
*       Convert a number to base 62 format       *
*************************************************/

/* Convert a long integer into an ASCII base 62 string. For Cygwin the value of
BASE_62 is actually 36. Always return exactly 6 characters plus a NUL, in a
static area.  This is enough for a 32b input, for 62  (for 64b we would want 11+nul);
but with 36 we lose half the input range of a 32b input.

Argument: a long integer
Returns:  pointer to base 62 string
*/

uschar *
string_base62_32(unsigned long int value)
{
static uschar yield[7];
uschar * p = yield + sizeof(yield) - 1;
*p = 0;
while (p > yield)
  {
  *--p = base62_chars[value % BASE_62];
  value /= BASE_62;
  }
return yield;
}

uschar *
string_base62_64(unsigned long int value)
{
static uschar yield[12];
uschar * p = yield + sizeof(yield) - 1;
*p = '\0';
while (p > yield)
  if (value)
    {
    *--p = base62_chars[value % BASE_62];
    value /= BASE_62;
    }
  else
    *--p = '0';
return yield;
}
#endif  /* COMPILE_UTILITY */



/*************************************************
*          Interpret escape sequence             *
*************************************************/

/* This function is called from several places where escape sequences are to be
interpreted in strings.

Arguments:
  pp       points a pointer to the initiating "\" in the string;
           the pointer gets updated to point to the final character
           If the backslash is the last character in the string, it
           is not interpreted.
Returns:   the value of the character escape
*/

int
string_interpret_escape(const uschar **pp)
{
#ifdef COMPILE_UTILITY
const uschar *hex_digits= CUS"0123456789abcdef";
#endif
int ch;
const uschar *p = *pp;
ch = *(++p);
if (ch == '\0') return **pp;
if (isdigit(ch) && ch != '8' && ch != '9')
  {
  ch -= '0';
  if (isdigit(p[1]) && p[1] != '8' && p[1] != '9')
    {
    ch = ch * 8 + *(++p) - '0';
    if (isdigit(p[1]) && p[1] != '8' && p[1] != '9')
      ch = ch * 8 + *(++p) - '0';
    }
  }
else switch(ch)
  {
  case 'b':  ch = '\b'; break;
  case 'f':  ch = '\f'; break;
  case 'n':  ch = '\n'; break;
  case 'r':  ch = '\r'; break;
  case 't':  ch = '\t'; break;
  case 'v':  ch = '\v'; break;
  case 'x':
  ch = 0;
  if (isxdigit(p[1]))
    {
    ch = ch * 16 +
      Ustrchr(hex_digits, tolower(*(++p))) - hex_digits;
    if (isxdigit(p[1])) ch = ch * 16 +
      Ustrchr(hex_digits, tolower(*(++p))) - hex_digits;
    }
  break;
  }
*pp = p;
return ch;
}



#ifndef COMPILE_UTILITY
/*************************************************
*          Ensure string is printable            *
*************************************************/

/* This function is called for critical strings. It checks for any
non-printing characters, and if any are found, it makes a new copy
of the string with suitable escape sequences. It is most often called by the
macro string_printing(), which sets flags to 0.

Arguments:
  s             the input string
  flags		Bit 0: convert tabs.  Bit 1: convert spaces.

Returns:        string with non-printers encoded as printing sequences
*/

const uschar *
string_printing2(const uschar *s, int flags)
{
int nonprintcount = 0;
int length = 0;
const uschar *t = s;
uschar *ss, *tt;

while (*t)
  {
  int c = *t++;
  if (  !mac_isprint(c)
     || flags & SP_TAB && c == '\t'
     || flags & SP_SPACE && c == ' '
     ) nonprintcount++;
  length++;
  }

if (nonprintcount == 0) return s;

/* Get a new block of store guaranteed big enough to hold the
expanded string. */

tt = ss = store_get(length + nonprintcount * 3 + 1, s);

/* Copy everything, escaping non printers. */

for (t = s; *t; )
  {
  int c = *t;
  if (  mac_isprint(c)
     && (!(flags & SP_TAB) || c != '\t')
     && (!(flags & SP_SPACE) || c != ' ')
     )
    *tt++ = *t++;
  else
    {
    *tt++ = '\\';
    switch (*t)
      {
      case '\n': *tt++ = 'n'; break;
      case '\r': *tt++ = 'r'; break;
      case '\b': *tt++ = 'b'; break;
      case '\v': *tt++ = 'v'; break;
      case '\f': *tt++ = 'f'; break;
      case '\t': *tt++ = 't'; break;
      default: sprintf(CS tt, "%03o", *t); tt += 3; break;
      }
    t++;
    }
  }
*tt = 0;
return ss;
}
#endif  /* COMPILE_UTILITY */

/*************************************************
*        Undo printing escapes in string         *
*************************************************/

/* This function is the reverse of string_printing2.  It searches for
backslash characters and if any are found, it makes a new copy of the
string with escape sequences parsed.  Otherwise it returns the original
string.

Arguments:
  s             the input string

Returns:        string with printing escapes parsed back
*/

uschar *
string_unprinting(uschar *s)
{
uschar *p, *q, *r, *ss;
int len, off;

p = Ustrchr(s, '\\');
if (!p) return s;

len = Ustrlen(s) + 1;
ss = store_get(len, s);

q = ss;
off = p - s;
if (off)
  {
  memcpy(q, s, off);
  q += off;
  }

while (*p)
  {
  if (*p == '\\')
    {
    *q++ = string_interpret_escape((const uschar **)&p);
    p++;
    }
  else
    {
    r = Ustrchr(p, '\\');
    if (!r)
      {
      off = Ustrlen(p);
      memcpy(q, p, off);
      p += off;
      q += off;
      break;
      }
    else
      {
      off = r - p;
      memcpy(q, p, off);
      q += off;
      p = r;
      }
    }
  }
*q = '\0';

return ss;
}




#if (defined(HAVE_LOCAL_SCAN) || defined(EXPAND_DLFUNC)) \
	&& !defined(MACRO_PREDEF) && !defined(COMPILE_UTILITY)
/*************************************************
*            Copy and save string                *
*************************************************/

/*
Argument: string to copy
Returns:  copy of string in new store with the same taint status
*/

uschar *
string_copy_function(const uschar * s)
{
return string_copy_taint(s, s);
}

/* As above, but explicitly specifying the result taint status
*/

uschar *
string_copy_taint_function(const uschar * s, const void * proto_mem)
{
return string_copy_taint(s, proto_mem);
}



/*************************************************
*       Copy and save string, given length       *
*************************************************/

/* It is assumed the data contains no zeros. A zero is added
onto the end.

Arguments:
  s         string to copy
  n         number of characters

Returns:    copy of string in new store
*/

uschar *
string_copyn_function(const uschar * s, int n)
{
return string_copyn(s, n);
}
#endif


/*************************************************
*     Copy and save string in malloc'd store     *
*************************************************/

/* This function assumes that memcpy() is faster than strcpy().

Argument: string to copy
Returns:  copy of string in new store
*/

uschar *
string_copy_malloc(const uschar * s)
{
int len = Ustrlen(s) + 1;
uschar * ss = store_malloc(len);
memcpy(ss, s, len);
return ss;
}



/*************************************************
*    Copy string if long, inserting newlines     *
*************************************************/

/* If the given string is longer than 75 characters, it is copied, and within
the copy, certain space characters are converted into newlines.

Argument:  pointer to the string
Returns:   pointer to the possibly altered string
*/

uschar *
string_split_message(uschar * msg)
{
uschar *s, *ss;

if (!msg || Ustrlen(msg) <= 75) return msg;
s = ss = msg = string_copy(msg);

for (;;)
  {
  int i = 0;
  while (i < 75 && *ss && *ss != '\n') ss++, i++;
  if (!*ss) break;
  if (*ss == '\n')
    s = ++ss;
  else
    {
    uschar * t = ss + 1;
    uschar * tt = NULL;
    while (--t > s + 35)
      {
      if (*t == ' ')
        {
        if (t[-1] == ':') { tt = t; break; }
        if (!tt) tt = t;
        }
      }

    if (!tt)          /* Can't split behind - try ahead */
      {
      t = ss + 1;
      while (*t)
        {
        if (*t == ' ' || *t == '\n')
          { tt = t; break; }
        t++;
        }
      }

    if (!tt) break;   /* Can't find anywhere to split */
    *tt = '\n';
    s = ss = tt+1;
    }
  }

return msg;
}



/*************************************************
*   Copy returned DNS domain name, de-escaping   *
*************************************************/

/* If a domain name contains top-bit characters, some resolvers return
the fully qualified name with those characters turned into escapes. The
convention is a backslash followed by _decimal_ digits. We convert these
back into the original binary values. This will be relevant when
allow_utf8_domains is set true and UTF-8 characters are used in domain
names. Backslash can also be used to escape other characters, though we
shouldn't come across them in domain names.

Argument:   the domain name string
Returns:    copy of string in new store, de-escaped
*/

uschar *
string_copy_dnsdomain(uschar * s)
{
uschar * yield;
uschar * ss = yield = store_get(Ustrlen(s) + 1, GET_TAINTED);	/* always treat as tainted */

while (*s)
  {
  if (*s != '\\')
    *ss++ = *s++;
  else if (isdigit(s[1]))
    {
    *ss++ = (s[1] - '0')*100 + (s[2] - '0')*10 + s[3] - '0';
    s += 4;
    }
  else if (*++s)
    *ss++ = *s++;
  }

*ss = 0;
return yield;
}


#ifndef COMPILE_UTILITY
/*************************************************
*     Copy space-terminated or quoted string     *
*************************************************/

/* This function copies from a string until its end, or until whitespace is
encountered, unless the string begins with a double quote, in which case the
terminating quote is sought, and escaping within the string is done. The length
of a de-quoted string can be no longer than the original, since escaping always
turns n characters into 1 character.

Argument:  pointer to the pointer to the first character, which gets updated
Returns:   the new string
*/

uschar *
string_dequote(const uschar ** sptr)
{
const uschar * s = * sptr;
uschar * t, * yield;

/* First find the end of the string */

if (*s != '\"')
  while (*s && !isspace(*s)) s++;
else
  {
  s++;
  while (*s && *s != '\"')
    {
    if (*s == '\\') (void)string_interpret_escape(&s);
    s++;
    }
  if (*s) s++;
  }

/* Get enough store to copy into */

t = yield = store_get(s - *sptr + 1, *sptr);
s = *sptr;

/* Do the copy */

if (*s != '\"')
  while (*s && !isspace(*s)) *t++ = *s++;
else
  {
  s++;
  while (*s && *s != '\"')
    {
    *t++ = *s == '\\' ? string_interpret_escape(&s) : *s;
    s++;
    }
  if (*s) s++;
  }

/* Update the pointer and return the terminated copy */

*sptr = s;
*t = 0;
return yield;
}
#endif  /* COMPILE_UTILITY */



/*************************************************
*          Format a string and save it           *
*************************************************/

/* The formatting is done by string_vformat, which checks the length of
everything.  Taint is taken from the worst of the arguments.

Arguments:
  format    a printf() format - deliberately char * rather than uschar *
              because it will most usually be a literal string
  func	    caller, for debug
  line	    caller, for debug
  ...       arguments for format

Returns:    pointer to fresh piece of store containing sprintf'ed string
*/

uschar *
string_sprintf_trc(const char * format, const uschar * func, unsigned line, ...)
{
#ifdef COMPILE_UTILITY
uschar buffer[STRING_SPRINTF_BUFFER_SIZE];
gstring gs = { .size = STRING_SPRINTF_BUFFER_SIZE, .ptr = 0, .s = buffer };
gstring * g = &gs;
unsigned flags = 0;
#else
gstring * g = NULL;
unsigned flags = SVFMT_REBUFFER|SVFMT_EXTEND;
#endif

va_list ap;
va_start(ap, line);
g = string_vformat_trc(g, func, line, STRING_SPRINTF_BUFFER_SIZE,
	flags, format, ap);
va_end(ap);

if (!g)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "string_sprintf expansion was longer than %d; format string was (%s)\n"
    " called from %s %d\n",
    STRING_SPRINTF_BUFFER_SIZE, format, func, line);

#ifdef COMPILE_UTILITY
return string_copyn(g->s, g->ptr);
#else
gstring_release_unused(g);
return string_from_gstring(g);
#endif
}



/*************************************************
*         Case-independent strncmp() function    *
*************************************************/

/*
Arguments:
  s         first string
  t         second string
  n         number of characters to compare

Returns:    < 0, = 0, or > 0, according to the comparison
*/

int
strncmpic(const uschar * s, const uschar * t, int n)
{
while (n--)
  {
  int c = tolower(*s++) - tolower(*t++);
  if (c) return c;
  }
return 0;
}


/*************************************************
*         Case-independent strcmp() function     *
*************************************************/

/*
Arguments:
  s         first string
  t         second string

Returns:    < 0, = 0, or > 0, according to the comparison
*/

int
strcmpic(const uschar * s, const uschar * t)
{
while (*s)
  {
  int c = tolower(*s++) - tolower(*t++);
  if (c != 0) return c;
  }
return *t;
}


/*************************************************
*         Case-independent strstr() function     *
*************************************************/

/* The third argument specifies whether whitespace is required
to follow the matched string.

Arguments:
  s              string to search
  t              substring to search for
  space_follows  if TRUE, match only if whitespace follows

Returns:         pointer to substring in string, or NULL if not found
*/

const uschar *
strstric_c(const uschar * s, const uschar * t, BOOL space_follows)
{
const uschar * p = t;
const uschar * yield = NULL;
int cl = tolower(*p);
int cu = toupper(*p);

while (*s)
  {
  if (*s == cl || *s == cu)
    {
    if (!yield) yield = s;
    if (!*++p)
      {
      if (!space_follows || s[1] == ' ' || s[1] == '\n' ) return yield;
      yield = NULL;
      p = t;
      }
    cl = tolower(*p);
    cu = toupper(*p);
    s++;
    }
  else if (yield)
    {
    yield = NULL;
    p = t;
    cl = tolower(*p);
    cu = toupper(*p);
    }
  else s++;
  }
return NULL;
}

uschar *
strstric(uschar * s, uschar * t, BOOL space_follows)
{
return US strstric_c(s, t, space_follows);
}


#ifdef COMPILE_UTILITY
/* Dummy version for this function; it should never be called */
static void
gstring_grow(gstring * g, int count)
{
assert(FALSE);
}
#endif



#ifndef COMPILE_UTILITY
/*************************************************
*       Get next string from separated list      *
*************************************************/

/* Leading and trailing space is removed from each item. The separator in the
list is controlled by the int pointed to by the separator argument as follows:

  If the value is > 0 it is used as the separator. This is typically used for
  sublists such as slash-separated options. The value is always a printing
  character.

    (If the value is actually > UCHAR_MAX there is only one item in the list.
    This is used for some cases when called via functions that sometimes
    plough through lists, and sometimes are given single items.)

  If the value is <= 0, the string is inspected for a leading <x, where x is an
  ispunct() or an iscntrl() character. If found, x is used as the separator. If
  not found:

      (a) if separator == 0, ':' is used
      (b) if separator <0, -separator is used

  In all cases the value of the separator that is used is written back to the
  int so that it is used on subsequent calls as we progress through the list.

A literal ispunct() separator can be represented in an item by doubling, but
there is no way to include an iscntrl() separator as part of the data.

Arguments:
  listptr    points to a pointer to the current start of the list; the
             pointer gets updated to point after the end of the next item
  separator  a pointer to the separator character in an int (see above)
  buffer     where to put a copy of the next string in the list; or
               NULL if the next string is returned in new memory
	     Note that if the list is tainted then a provided buffer must be
	     also (else we trap, with a message referencing the callsite).
	     If we do the allocation, taint is handled there.
  buflen     when buffer is not NULL, the size of buffer; otherwise ignored

  func	     caller, for debug
  line	     caller, for debug

Returns:     pointer to buffer, containing the next substring,
             or NULL if no more substrings
*/

uschar *
string_nextinlist_trc(const uschar ** listptr, int * separator, uschar * buffer,
  int buflen, const uschar * func, int line)
{
int sep = *separator;
const uschar * s = *listptr;
BOOL sep_is_special;

if (!s) return NULL;

/* This allows for a fixed specified separator to be an iscntrl() character,
but at the time of implementation, this is never the case. However, it's best
to be conservative. */

while (isspace(*s) && *s != sep) s++;

/* A change of separator is permitted, so look for a leading '<' followed by an
allowed character. */

if (sep <= 0)
  {
  if (*s == '<' && (ispunct(s[1]) || iscntrl(s[1])))
    {
    sep = s[1];
    if (*++s) ++s;
    while (isspace(*s) && *s != sep) s++;
    }
  else
    sep = sep ? -sep : ':';
  *separator = sep;
  }

/* An empty string has no list elements */

if (!*s) return NULL;

/* Note whether whether or not the separator is an iscntrl() character. */

sep_is_special = iscntrl(sep);

/* Handle the case when a buffer is provided. */
/*XXX need to also deal with qouted-requirements mismatch */

if (buffer)
  {
  int p = 0;
  if (is_tainted(s) && !is_tainted(buffer))
    die_tainted(US"string_nextinlist", func, line);
  for (; *s; s++)
    {
    if (*s == sep && (*(++s) != sep || sep_is_special)) break;
    if (p < buflen - 1) buffer[p++] = *s;
    }
  while (p > 0 && isspace(buffer[p-1])) p--;
  buffer[p] = '\0';
  }

/* Handle the case when a buffer is not provided. */

else
  {
  gstring * g = NULL;

  /* We know that *s != 0 at this point. However, it might be pointing to a
  separator, which could indicate an empty string, or (if an ispunct()
  character) could be doubled to indicate a separator character as data at the
  start of a string. Avoid getting working memory for an empty item. */

  if (*s == sep)
    if (*++s != sep || sep_is_special)
      {
      *listptr = s;
      return string_copy(US"");
      }

  /* Not an empty string; the first character is guaranteed to be a data
  character. */

  for (;;)
    {
    const uschar * ss;
    for (ss = s + 1; *ss && *ss != sep; ) ss++;
    g = string_catn(g, s, ss-s);
    s = ss;
    if (!*s || *++s != sep || sep_is_special) break;
    }

  /* Trim trailing spaces from the returned string */

  /* while (g->ptr > 0 && isspace(g->s[g->ptr-1])) g->ptr--; */
  while (  g->ptr > 0 && isspace(g->s[g->ptr-1])
	&& (g->ptr == 1 || g->s[g->ptr-2] != '\\') )
    g->ptr--;
  buffer = string_from_gstring(g);
  gstring_release_unused_trc(g, CCS func, line);
  }

/* Update the current pointer and return the new string */

*listptr = s;
return buffer;
}


static const uschar *
Ustrnchr(const uschar * s, int c, unsigned * len)
{
unsigned siz = *len;
while (siz)
  {
  if (!*s) return NULL;
  if (*s == c)
    {
    *len = siz;
    return s;
    }
  s++;
  siz--;
  }
return NULL;
}


/************************************************
*	Add element to separated list           *
************************************************/
/* This function is used to build a list, returning an allocated null-terminated
growable string. The given element has any embedded separator characters
doubled.

Despite having the same growable-string interface as string_cat() the list is
always returned null-terminated.

Arguments:
  list	expanding-string for the list that is being built, or NULL
	if this is a new list that has no contents yet
  sep	list separator character
  ele	new element to be appended to the list

Returns:  pointer to the start of the list, changed if copied for expansion.
*/

gstring *
string_append_listele(gstring * list, uschar sep, const uschar * ele)
{
uschar * sp;

if (list && list->ptr)
  list = string_catn(list, &sep, 1);

while((sp = Ustrchr(ele, sep)))
  {
  list = string_catn(list, ele, sp-ele+1);
  list = string_catn(list, &sep, 1);
  ele = sp+1;
  }
list = string_cat(list, ele);
(void) string_from_gstring(list);
return list;
}


gstring *
string_append_listele_n(gstring * list, uschar sep, const uschar * ele,
 unsigned len)
{
const uschar * sp;

if (list && list->ptr)
  list = string_catn(list, &sep, 1);

while((sp = Ustrnchr(ele, sep, &len)))
  {
  list = string_catn(list, ele, sp-ele+1);
  list = string_catn(list, &sep, 1);
  ele = sp+1;
  len--;
  }
list = string_catn(list, ele, len);
(void) string_from_gstring(list);
return list;
}



/* A slightly-bogus listmaker utility; the separator is a string so
can be multiple chars - there is no checking for the element content
containing any of the separator. */

gstring *
string_append2_listele_n(gstring * list, const uschar * sepstr,
 const uschar * ele, unsigned len)
{
if (list && list->ptr)
  list = string_cat(list, sepstr);

list = string_catn(list, ele, len);
(void) string_from_gstring(list);
return list;
}



/************************************************/
/* Add more space to a growable-string.  The caller should check
first if growth is required.  The gstring struct is modified on
return; specifically, the string-base-pointer may have been changed.

Arguments:
  g		the growable-string
  count		amount needed for g->ptr to increase by
*/

static void
gstring_grow(gstring * g, int count)
{
int p = g->ptr;
int oldsize = g->size;

/* Mostly, string_cat() is used to build small strings of a few hundred
characters at most. There are times, however, when the strings are very much
longer (for example, a lookup that returns a vast number of alias addresses).
To try to keep things reasonable, we use increments whose size depends on the
existing length of the string. */

unsigned inc = oldsize < 4096 ? 127 : 1023;

if (g->ptr < 0 || g->ptr > g->size || g->size >= INT_MAX/2)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "internal error in gstring_grow (ptr %d size %d)", g->ptr, g->size);

if (count <= 0) return;

if (count >= INT_MAX/2 - g->ptr)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "internal error in gstring_grow (ptr %d count %d)", g->ptr, count);

g->size = (p + count + inc + 1) & ~inc;		/* one for a NUL */

/* Try to extend an existing allocation. If the result of calling
store_extend() is false, either there isn't room in the current memory block,
or this string is not the top item on the dynamic store stack. We then have
to get a new chunk of store and copy the old string. When building large
strings, it is helpful to call store_release() on the old string, to release
memory blocks that have become empty. (The block will be freed if the string
is at its start.) However, we can do this only if we know that the old string
was the last item on the dynamic memory stack. This is the case if it matches
store_last_get. */

if (!store_extend(g->s, oldsize, g->size))
  g->s = store_newblock(g->s, g->size, p);
}



/*************************************************
*             Add chars to string                *
*************************************************/
/* This function is used when building up strings of unknown length. Room is
always left for a terminating zero to be added to the string that is being
built. This function does not require the string that is being added to be NUL
terminated, because the number of characters to add is given explicitly. It is
sometimes called to extract parts of other strings.

Arguments:
  g	   growable-string that is being built, or NULL if not assigned yet
  s        points to characters to add
  count    count of characters to add; must not exceed the length of s, if s
             is a C string.

Returns:   growable string, changed if copied for expansion.
           Note that a NUL is not added, though space is left for one. This is
           because string_cat() is often called multiple times to build up a
           string - there's no point adding the NUL till the end.
	   NULL is a possible return.

*/
/* coverity[+alloc] */

gstring *
string_catn(gstring * g, const uschar * s, int count)
{
int p;

if (count < 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "internal error in string_catn (count %d)", count);
if (count == 0) return g;

/*debug_printf("string_catn '%.*s'\n", count, s);*/
if (!g)
  {
  unsigned inc = count < 4096 ? 127 : 1023;
  unsigned size = ((count + inc) &  ~inc) + 1;	/* round up requested count */
  g = string_get_tainted(size, s);
  }
else if (!g->s)			/* should not happen */
  {
  g->s = string_copyn(s, count);
  g->ptr = count;
  g->size = count;	/*XXX suboptimal*/
  return g;
  }
else if (is_incompatible(g->s, s))
  {
/* debug_printf("rebuf A\n"); */
  gstring_rebuffer(g, s);
  }

if (g->ptr < 0 || g->ptr > g->size)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "internal error in string_catn (ptr %d size %d)", g->ptr, g->size);

p = g->ptr;
if (count >= g->size - p)
  gstring_grow(g, count);

/* Because we always specify the exact number of characters to copy, we can
use memcpy(), which is likely to be more efficient than strncopy() because the
latter has to check for zero bytes. */

memcpy(g->s + p, s, count);
g->ptr = p + count;
return g;
}


gstring *
string_cat(gstring * g, const uschar * s)
{
return string_catn(g, s, Ustrlen(s));
}



/*************************************************
*        Append strings to another string        *
*************************************************/

/* This function can be used to build a string from many other strings.
It calls string_cat() to do the dirty work.

Arguments:
  g	   growable-string that is being built, or NULL if not yet assigned
  count    the number of strings to append
  ...      "count" uschar* arguments, which must be valid zero-terminated
             C strings

Returns:   growable string, changed if copied for expansion.
           The string is not zero-terminated - see string_cat() above.
*/

__inline__ gstring *
string_append(gstring * g, int count, ...)
{
va_list ap;

va_start(ap, count);
while (count-- > 0)
  {
  uschar * t = va_arg(ap, uschar *);
  g = string_cat(g, t);
  }
va_end(ap);

return g;
}
#endif



/*************************************************
*        Format a string with length checks      *
*************************************************/

/* This function is used to format a string with checking of the length of the
output for all conversions. It protects Exim from absent-mindedness when
calling functions like debug_printf and string_sprintf, and elsewhere. There
are two different entry points to what is actually the same function, depending
on whether the variable length list of data arguments are given explicitly or
as a va_list item.

The formats are the usual printf() ones, with some omissions (never used) and
three additions for strings: %S forces lower case, %T forces upper case, and
%#s or %#S prints nothing for a NULL string. Without the # "NULL" is printed
(useful in debugging). There is also the addition of %D and %M, which insert
the date in the form used for datestamped log files.

Arguments:
  buffer       a buffer in which to put the formatted string
  buflen       the length of the buffer
  format       the format string - deliberately char * and not uschar *
  ... or ap    variable list of supplementary arguments

Returns:       TRUE if the result fitted in the buffer
*/

BOOL
string_format_trc(uschar * buffer, int buflen,
  const uschar * func, unsigned line, const char * format, ...)
{
gstring g = { .size = buflen, .ptr = 0, .s = buffer }, * gp;
va_list ap;
va_start(ap, format);
gp = string_vformat_trc(&g, func, line, STRING_SPRINTF_BUFFER_SIZE,
	0, format, ap);
va_end(ap);
g.s[g.ptr] = '\0';
return !!gp;
}




/* Build or append to a growing-string, sprintf-style.

Arguments:
	g	a growable-string
	func	called-from function name, for debug
	line	called-from file line number, for debug
	limit	maximum string size
	flags	see below
	format	printf-like format string
	ap	variable-args pointer

Flags:
	SVFMT_EXTEND            buffer can be created or exteded as needed
	SVFMT_REBUFFER          buffer can be recopied to tainted mem as needed
	SVFMT_TAINT_NOCHK       do not check inputs for taint

If the "extend" flag is true, the string passed in can be NULL,
empty, or non-empty.  Growing is subject to an overall limit given
by the limit argument.

If the "extend" flag is false, the string passed in may not be NULL,
will not be grown, and is usable in the original place after return.
The return value can be NULL to signify overflow.

Field width:		decimal digits, or *
Precision:		dot, followed by decimal digits or *
Length modifiers:	h  L  l  ll  z
Conversion specifiers:	n d o u x X p f e E g G % c s S T W V Y D M

Returns the possibly-new (if copy for growth or taint-handling was needed)
string, not nul-terminated.
*/

gstring *
string_vformat_trc(gstring * g, const uschar * func, unsigned line,
  unsigned size_limit, unsigned flags, const char * format, va_list ap)
{
enum ltypes { L_NORMAL=1, L_SHORT=2, L_LONG=3, L_LONGLONG=4, L_LONGDOUBLE=5, L_SIZE=6 };

int width, precision, off, lim, need;
const char * fp = format;	/* Deliberately not unsigned */

string_datestamp_offset = -1;	/* Datestamp not inserted */
string_datestamp_length = 0;	/* Datestamp not inserted */
string_datestamp_type = 0;	/* Datestamp not inserted */

#ifdef COMPILE_UTILITY
assert(!(flags & SVFMT_EXTEND));
assert(g);
#else

/* Ensure we have a string, to save on checking later */
if (!g) g = string_get(16);

if (!(flags & SVFMT_TAINT_NOCHK) && is_incompatible(g->s, format))
  {
#ifndef MACRO_PREDEF
  if (!(flags & SVFMT_REBUFFER))
    die_tainted(US"string_vformat", func, line);
#endif
/* debug_printf("rebuf B\n"); */
  gstring_rebuffer(g, format);
  }
#endif	/*!COMPILE_UTILITY*/

lim = g->size - 1;	/* leave one for a nul */
off = g->ptr;		/* remember initial offset in gstring */

/* Scan the format and handle the insertions */

while (*fp)
  {
  int length = L_NORMAL;
  int * nptr;
  int slen;
  const char *null = "NULL";		/* ) These variables */
  const char *item_start, *s;		/* ) are deliberately */
  char newformat[16];			/* ) not unsigned */
  char * gp = CS g->s + g->ptr;		/* ) */

  /* Non-% characters just get copied verbatim */

  if (*fp != '%')
    {
    /* Avoid string_copyn() due to COMPILE_UTILITY */
    if ((need = g->ptr + 1) > lim)
      {
      if (!(flags & SVFMT_EXTEND) || need > size_limit) return NULL;
      gstring_grow(g, 1);
      lim = g->size - 1;
      }
    g->s[g->ptr++] = (uschar) *fp++;
    continue;
    }

  /* Deal with % characters. Pick off the width and precision, for checking
  strings, skipping over the flag and modifier characters. */

  item_start = fp;
  width = precision = -1;

  if (strchr("-+ #0", *(++fp)) != NULL)
    {
    if (*fp == '#') null = "";
    fp++;
    }

  if (isdigit((uschar)*fp))
    {
    width = *fp++ - '0';
    while (isdigit((uschar)*fp)) width = width * 10 + *fp++ - '0';
    }
  else if (*fp == '*')
    {
    width = va_arg(ap, int);
    fp++;
    }

  if (*fp == '.')
    if (*(++fp) == '*')
      {
      precision = va_arg(ap, int);
      fp++;
      }
    else
      for (precision = 0; isdigit((uschar)*fp); fp++)
        precision = precision*10 + *fp - '0';

  /* Skip over 'h', 'L', 'l', 'll' and 'z', remembering the item length */

  if (*fp == 'h')
    { fp++; length = L_SHORT; }
  else if (*fp == 'L')
    { fp++; length = L_LONGDOUBLE; }
  else if (*fp == 'l')
    if (fp[1] == 'l')
      { fp += 2; length = L_LONGLONG; }
    else
      { fp++; length = L_LONG; }
  else if (*fp == 'z')
    { fp++; length = L_SIZE; }

  /* Handle each specific format type. */

  switch (*fp++)
    {
    case 'n':
      nptr = va_arg(ap, int *);
      *nptr = g->ptr - off;
      break;

    case 'd':
    case 'o':
    case 'u':
    case 'x':
    case 'X':
      width = length > L_LONG ? 24 : 12;
      if ((need = g->ptr + width) > lim)
	{
	if (!(flags & SVFMT_EXTEND) || need >= size_limit) return NULL;
	gstring_grow(g, width);
	lim = g->size - 1;
	gp = CS g->s + g->ptr;
	}
      strncpy(newformat, item_start, fp - item_start);
      newformat[fp - item_start] = 0;

      /* Short int is promoted to int when passing through ..., so we must use
      int for va_arg(). */

      switch(length)
	{
	case L_SHORT:
	case L_NORMAL:
	  g->ptr += sprintf(gp, newformat, va_arg(ap, int)); break;
	case L_LONG:
	  g->ptr += sprintf(gp, newformat, va_arg(ap, long int)); break;
	case L_LONGLONG:
	  g->ptr += sprintf(gp, newformat, va_arg(ap, LONGLONG_T)); break;
	case L_SIZE:
	  g->ptr += sprintf(gp, newformat, va_arg(ap, size_t)); break;
	}
      break;

    case 'p':
      {
      void * ptr;
      if ((need = g->ptr + 24) > lim)
	{
	if (!(flags & SVFMT_EXTEND || need >= size_limit)) return NULL;
	gstring_grow(g, 24);
	lim = g->size - 1;
	gp = CS g->s + g->ptr;
	}
      /* sprintf() saying "(nil)" for a null pointer seems unreliable.
      Handle it explicitly. */
      if ((ptr = va_arg(ap, void *)))
	{
	strncpy(newformat, item_start, fp - item_start);
	newformat[fp - item_start] = 0;
	g->ptr += sprintf(gp, newformat, ptr);
	}
      else
	g->ptr += sprintf(gp, "(nil)");
      }
    break;

    /* %f format is inherently insecure if the numbers that it may be
    handed are unknown (e.g. 1e300). However, in Exim, %f is used for
    printing load averages, and these are actually stored as integers
    (load average * 1000) so the size of the numbers is constrained.
    It is also used for formatting sending rates, where the simplicity
    of the format prevents overflow. */

    case 'f':
    case 'e':
    case 'E':
    case 'g':
    case 'G':
      if (precision < 0) precision = 6;
      if ((need = g->ptr + precision + 8) > lim)
	{
	if (!(flags & SVFMT_EXTEND || need >= size_limit)) return NULL;
	gstring_grow(g, precision+8);
	lim = g->size - 1;
	gp = CS g->s + g->ptr;
	}
      strncpy(newformat, item_start, fp - item_start);
      newformat[fp-item_start] = 0;
      if (length == L_LONGDOUBLE)
	g->ptr += sprintf(gp, newformat, va_arg(ap, long double));
      else
	g->ptr += sprintf(gp, newformat, va_arg(ap, double));
      break;

    /* String types */

    case '%':
      if ((need = g->ptr + 1) > lim)
	{
	if (!(flags & SVFMT_EXTEND || need >= size_limit)) return NULL;
	gstring_grow(g, 1);
	lim = g->size - 1;
	}
      g->s[g->ptr++] = (uschar) '%';
      break;

    case 'c':
      if ((need = g->ptr + 1) > lim)
	{
	if (!(flags & SVFMT_EXTEND || need >= size_limit)) return NULL;
	gstring_grow(g, 1);
	lim = g->size - 1;
	}
      g->s[g->ptr++] = (uschar) va_arg(ap, int);
      break;

    case 'D':                   /* Insert daily datestamp for log file names */
      s = CS tod_stamp(tod_log_datestamp_daily);
      string_datestamp_offset = g->ptr;		/* Passed back via global */
      string_datestamp_length = Ustrlen(s);	/* Passed back via global */
      string_datestamp_type = tod_log_datestamp_daily;
      slen = string_datestamp_length;
      goto INSERT_STRING;

    case 'M':                   /* Insert monthly datestamp for log file names */
      s = CS tod_stamp(tod_log_datestamp_monthly);
      string_datestamp_offset = g->ptr;		/* Passed back via global */
      string_datestamp_length = Ustrlen(s);	/* Passed back via global */
      string_datestamp_type = tod_log_datestamp_monthly;
      slen = string_datestamp_length;
      goto INSERT_STRING;

    case 'Y':			/* gstring pointer */
      {
      gstring * zg = va_arg(ap, gstring *);
      if (zg) { s = CS zg->s; slen = gstring_length(zg); }
      else    { s = null;     slen = Ustrlen(s); }
      goto INSERT_GSTRING;
      }
#ifndef COMPILE_UTILITY
    case 'V':			/* Maybe convert ascii-art to UTF-8 chars */
      {
      gstring * zg = NULL;
      s = va_arg(ap, char *);
      if (IS_DEBUG(D_noutf8))
	for ( ; *s; s++)
	  zg = string_catn(zg, CUS (*s == 'K' ? "|" : s), 1);
      else
	for ( ; *s; s++) switch (*s)
	  {
	  case '\\': zg = string_catn(zg, US UTF8_UP_RIGHT,	  3); break;
	  case '/':  zg = string_catn(zg, US UTF8_DOWN_RIGHT,	  3); break;
	  case '-':
	  case '_':  zg = string_catn(zg, US UTF8_HORIZ,	  3); break;
	  case '|':  zg = string_catn(zg, US UTF8_VERT,		  3); break;
	  case 'K':  zg = string_catn(zg, US UTF8_VERT_RIGHT,	  3); break;
	  case '<':  zg = string_catn(zg, US UTF8_LEFT_TRIANGLE,  3); break;
	  case '>':  zg = string_catn(zg, US UTF8_RIGHT_TRIANGLE, 3); break;
	  default:   zg = string_catn(zg, CUS s, 1);		      break;
	  }

      if (!zg)
	break;
      s = CS zg->s;
      slen = gstring_length(zg);
      goto INSERT_GSTRING;
      }

    case 'W':			/* Maybe mark up spaces & newlines */
      s = va_arg(ap, char *);
      if (Ustrpbrk(s, " \n") && !IS_DEBUG(D_noutf8))
	{
	gstring * zg = NULL;
	int p = precision;
	for ( ; *s; s++)
	  {
	  /* Take a given precision as applying to the input; expand
	  it for the transformed result */

	  if (p >= 0 && --p < 0) break;
	  switch (*s)
	    {
	    case ' ':
	      zg = string_catn(zg, CUS UTF8_LIGHT_SHADE, 3);
	      if (precision >= 0) precision += 2;
	      break;
	    case '\n':
	      zg = string_catn(zg, CUS UTF8_L_ARROW_HOOK "\n", 4);
	      if (precision >= 0) precision += 3;
	      break;
	    default:
	      zg = string_catn(zg, CUS s, 1);
	      break;
	    }
	  }
	if (zg) { s = CS zg->s; slen = gstring_length(zg); }
	else    { s = null;     slen = Ustrlen(s); }
	}
      else
	{
	if (!s) s = null;
	slen = Ustrlen(s);
	}
      goto INSERT_GSTRING;

#endif
    case 's':
    case 'S':                   /* Forces *lower* case */
    case 'T':                   /* Forces *upper* case */
      s = va_arg(ap, char *);

      if (!s) s = null;
      slen = Ustrlen(s);

    INSERT_GSTRING:		/* Come to from %Y above */

      if (!(flags & SVFMT_TAINT_NOCHK) && is_incompatible(g->s, s))
	if (flags & SVFMT_REBUFFER)
	  {
/* debug_printf("%s %d: untainted workarea, tainted %%s :- rebuffer\n", __FUNCTION__, __LINE__); */
	  gstring_rebuffer(g, s);
	  gp = CS g->s + g->ptr;
	  }
#ifndef MACRO_PREDEF
	else
	  die_tainted(US"string_vformat", func, line);
#endif

    INSERT_STRING:              /* Come to from %D or %M above */

      {
      BOOL truncated = FALSE;

      /* If the width is specified, check that there is a precision
      set; if not, set it to the width to prevent overruns of long
      strings. */

      if (width >= 0)
	{
	if (precision < 0) precision = width;
	}

      /* If a width is not specified and the precision is specified, set
      the width to the precision, or the string length if shorted. */

      else if (precision >= 0)
	width = precision < slen ? precision : slen;

      /* If neither are specified, set them both to the string length. */

      else
	width = precision = slen;

      if ((need = g->ptr + width) >= size_limit || !(flags & SVFMT_EXTEND))
	{
	if (g->ptr == lim) return NULL;
	if (need > lim)
	  {
	  truncated = TRUE;
	  width = precision = lim - g->ptr - 1;
	  if (width < 0) width = 0;
	  if (precision < 0) precision = 0;
	  }
	}
      else if (need > lim)
	{
	gstring_grow(g, width);
	lim = g->size - 1;
	gp = CS g->s + g->ptr;
	}

      g->ptr += sprintf(gp, "%*.*s", width, precision, s);
      if (fp[-1] == 'S')
	while (*gp) { *gp = tolower(*gp); gp++; }
      else if (fp[-1] == 'T')
	while (*gp) { *gp = toupper(*gp); gp++; }

      if (truncated) return NULL;
      break;
      }

    /* Some things are never used in Exim; also catches junk. */

    default:
      strncpy(newformat, item_start, fp - item_start);
      newformat[fp-item_start] = 0;
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "string_format: unsupported type "
	"in \"%s\" in \"%s\"", newformat, format);
      break;
    }
  }

if (g->ptr > g->size)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "string_format internal error: caller %s %d", func, line);
return g;
}



#ifndef COMPILE_UTILITY
/*************************************************
*       Generate an "open failed" message        *
*************************************************/

/* This function creates a message after failure to open a file. It includes a
string supplied as data, adds the strerror() text, and if the failure was
"Permission denied", reads and includes the euid and egid.

Arguments:
  format        a text format string - deliberately not uschar *
  func		caller, for debug
  line		caller, for debug
  ...           arguments for the format string

Returns:        a message, in dynamic store
*/

uschar *
string_open_failed_trc(const uschar * func, unsigned line,
  const char * format, ...)
{
va_list ap;
gstring * g = string_get(1024);

g = string_catn(g, US"failed to open ", 15);

/* Use the checked formatting routine to ensure that the buffer
does not overflow. It should not, since this is called only for internally
specified messages. If it does, the message just gets truncated, and there
doesn't seem much we can do about that. */

va_start(ap, format);
(void) string_vformat_trc(g, func, line, STRING_SPRINTF_BUFFER_SIZE,
	SVFMT_REBUFFER, format, ap);
va_end(ap);

g = string_catn(g, US": ", 2);
g = string_cat(g, US strerror(errno));

if (errno == EACCES)
  {
  int save_errno = errno;
  g = string_fmt_append(g, " (euid=%ld egid=%ld)",
    (long int)geteuid(), (long int)getegid());
  errno = save_errno;
  }
gstring_release_unused(g);
return string_from_gstring(g);
}





/* qsort(3), currently used to sort the environment variables
for -bP environment output, needs a function to compare two pointers to string
pointers. Here it is. */

int
string_compare_by_pointer(const void *a, const void *b)
{
return Ustrcmp(* CUSS a, * CUSS b);
}
#endif /* COMPILE_UTILITY */




/*************************************************
**************************************************
*             Stand-alone test program           *
**************************************************
*************************************************/

#ifdef STAND_ALONE
int main(void)
{
uschar buffer[256];

printf("Testing is_ip_address\n");
store_init();

while (fgets(CS buffer, sizeof(buffer), stdin) != NULL)
  {
  int offset;
  buffer[Ustrlen(buffer) - 1] = 0;
  printf("%d\n", string_is_ip_address(buffer, NULL));
  printf("%d %d %s\n", string_is_ip_address(buffer, &offset), offset, buffer);
  }

printf("Testing string_nextinlist\n");

while (fgets(CS buffer, sizeof(buffer), stdin) != NULL)
  {
  uschar *list = buffer;
  uschar *lp1, *lp2;
  uschar item[256];
  int sep1 = 0;
  int sep2 = 0;

  if (*list == '<')
    {
    sep1 = sep2 = list[1];
    list += 2;
    }

  lp1 = lp2 = list;
  for (;;)
    {
    uschar *item1 = string_nextinlist(&lp1, &sep1, item, sizeof(item));
    uschar *item2 = string_nextinlist(&lp2, &sep2, NULL, 0);

    if (item1 == NULL && item2 == NULL) break;
    if (item == NULL || item2 == NULL || Ustrcmp(item1, item2) != 0)
      {
      printf("***ERROR\nitem1=\"%s\"\nitem2=\"%s\"\n",
        (item1 == NULL)? "NULL" : CS item1,
        (item2 == NULL)? "NULL" : CS item2);
      break;
      }
    else printf("  \"%s\"\n", CS item1);
    }
  }

/* This is a horrible lash-up, but it serves its purpose. */

printf("Testing string_format\n");

while (fgets(CS buffer, sizeof(buffer), stdin) != NULL)
  {
  void *args[3];
  long long llargs[3];
  double dargs[3];
  int dflag = 0;
  int llflag = 0;
  int n = 0;
  int count;
  BOOL countset = FASE;
  uschar format[256];
  uschar outbuf[256];
  uschar *s;
  buffer[Ustrlen(buffer) - 1] = 0;

  s = Ustrchr(buffer, ',');
  if (s == NULL) s = buffer + Ustrlen(buffer);

  Ustrncpy(format, buffer, s - buffer);
  format[s-buffer] = 0;

  if (*s == ',') s++;

  while (*s != 0)
    {
    uschar *ss = s;
    s = Ustrchr(ss, ',');
    if (s == NULL) s = ss + Ustrlen(ss);

    if (isdigit(*ss))
      {
      Ustrncpy(outbuf, ss, s-ss);
      if (Ustrchr(outbuf, '.') != NULL)
        {
        dflag = 1;
        dargs[n++] = Ustrtod(outbuf, NULL);
        }
      else if (Ustrstr(outbuf, "ll") != NULL)
        {
        llflag = 1;
        llargs[n++] = strtoull(CS outbuf, NULL, 10);
        }
      else
        {
        args[n++] = (void *)Uatoi(outbuf);
        }
      }

    else if (Ustrcmp(ss, "*") == 0)
      {
      args[n++] = (void *)(&count);
      countset = TRUE;
      }

    else
      {
      uschar *sss = malloc(s - ss + 1);
      Ustrncpy(sss, ss, s-ss);
      args[n++] = sss;
      }

    if (*s == ',') s++;
    }

  if (!dflag && !llflag)
    printf("%s\n", string_format(outbuf, sizeof(outbuf), CS format,
      args[0], args[1], args[2])? "True" : "False");

  else if (dflag)
    printf("%s\n", string_format(outbuf, sizeof(outbuf), CS format,
      dargs[0], dargs[1], dargs[2])? "True" : "False");

  else printf("%s\n", string_format(outbuf, sizeof(outbuf), CS format,
    llargs[0], llargs[1], llargs[2])? "True" : "False");

  printf("%s\n", CS outbuf);
  if (countset) printf("count=%d\n", count);
  }

return 0;
}
#endif

/* End of string.c */
/* vi: aw ai sw=2
*/
