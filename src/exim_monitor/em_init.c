/*************************************************
*                  Exim monitor                  *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* Copyright (c) The Exim Maintainers 2020 - 2021 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* This module contains code to initialize things from the
environment and the arguments. */


#include "em_hdr.h"



/*************************************************
*            Decode stripchart config            *
*************************************************/

/* First determine how many are requested, then compile the
regular expressions and save the title strings. Note that
stripchart_number is initialized to 1 or 2 to count the always-
present queue stripchart, and the optional size-monitoring
stripchart. */

static void decode_stripchart_config(uschar *s)
{
int i;

/* Loop: first time just counts, second time does the
work. */

for (i = 0; i <= 1; i++)
  {
  int first = 1;
  int count = 0;
  uschar *p = s;

  if (*p == '/') p++;   /* allow optional / at start */

  /* This loops for all the substrings, using the first flag
  to determine whether each is the first or second of the pairs. */

  while (*p)
    {
    uschar *pp;
    /* Handle continuations */
    if (*p == '\n')
      {
      while (*(++p) == ' ' || *p == '\t');
      if (*p == '/') p++;
      }

    /* Find the end of the string and count if first string */

    pp = p;
    while (*p && *p != '/') p++;
    if (first) count++;

    /* Take action on the second time round. */

    if (i != 0)
      {
      uschar buffer[256];
      int indx = count + stripchart_varstart - 1;
      Ustrncpy(buffer, pp, p-pp);
      buffer[p-pp] = 0;
      if (first)
        {
        size_t offset;
        int err;

        if (!(stripchart_regex[indx] =
		pcre2_compile((PCRE2_SPTR)buffer,
		      PCRE2_ZERO_TERMINATED, PCRE_COPT,
		      &err, &offset, NULL)))
          {
	  uschar errbuf[128];
	  pcre2_get_error_message(err, errbuf, sizeof(errbuf));
          printf("regular expression error: %s at offset %ld "
            "while compiling %s\n", errbuf, (long)offset, buffer);
          exit(99);
          }
        }
      else stripchart_title[indx] = string_copy(buffer);
      }

    /* Advance past the delimiter and flip the first/second flag */

    p++;
    first = !first;
    }

  /* On the first pass, we now know the number of stripcharts. Get
  store for holding the pointers to the regular expressions and
  title strings. */

  if (i == 0)
    {
    stripchart_number += count;
    stripchart_regex = (pcre2_code **)store_malloc(stripchart_number * sizeof(pcre2_code *));
    stripchart_title = (uschar **)store_malloc(stripchart_number * sizeof(uschar *));
    }
  }
}


/*************************************************
*                    Initialize                  *
*************************************************/

void init(int argc, uschar **argv)
{
int x;
size_t erroroffset;
uschar *s;

argc = argc;     /* These are currently unused. */
argv = argv;

/* Deal with simple values in the environment. */

if ((s = US getenv("ACTION_OUTPUT")))
  {
  if (Ustrcmp(s, "no") == 0) action_output = FALSE;
  if (Ustrcmp(s, "yes") == 0) action_output = TRUE;
  }

if ((s = US getenv("ACTION_QUEUE_UPDATE")))
  {
  if (Ustrcmp(s, "no") == 0) action_queue_update = FALSE;
  if (Ustrcmp(s, "yes") == 0) action_queue_update = TRUE;
  }

s = US getenv("BODY_MAX");
if (s && (x = Uatoi(s)) != 0) body_max = x;

if ((s = US getenv("EXIM_PATH")))
  exim_path = string_copy(s);

if ((s = US getenv("EXIMON_EXIM_CONFIG")))
  alternate_config = string_copy(s);

if ((s = US getenv("LOG_BUFFER")))
  {
  uschar c[1];
  if (sscanf(CS s, "%d%c", &x, c) > 0)
    {
    if (c[0] == 'K' || c[0] == 'k') x *= 1024;
    if (x < 1024) x = 1024;
    log_buffer_size = x;
    }
  }

s = US getenv("LOG_DEPTH");
if (s && (x = Uatoi(s)) != 0) log_depth = x;

if ((s = US getenv("LOG_FILE_NAME")))
  log_file = string_copy(s);

if ((s = US getenv("LOG_FONT")))
  log_font = string_copy(s);

s = US getenv("LOG_WIDTH");
if (s && (x = Uatoi(s)) != 0) log_width = x;

if ((s = US getenv("MENU_EVENT")))
  menu_event = string_copy(s);

s = US getenv("MIN_HEIGHT");
if (s && (x = Uatoi(s)) > 0) min_height = x;

s = US getenv("MIN_WIDTH");
if (s && (x = Uatoi(s)) > 0) min_width = x;

if ((s = US getenv("QUALIFY_DOMAIN")))
  qualify_domain = string_copy(s);
else
  qualify_domain = US"";  /* Don't want NULL */

s = US getenv("QUEUE_DEPTH");
if (s && (x = Uatoi(s)) != 0) queue_depth = x;

if ((s = US getenv("QUEUE_FONT")))
  queue_font = string_copy(s);

s = US getenv("QUEUE_INTERVAL");
if (s && (x = Uatoi(s)) != 0) queue_update = x;

s = US getenv("QUEUE_MAX_ADDRESSES");
if (s && (x = Uatoi(s)) != 0) queue_max_addresses = x;

s = US getenv("QUEUE_WIDTH");
if (s && (x = Uatoi(s)) != 0) queue_width = x;

if ((s = US getenv("SPOOL_DIRECTORY")))
  spool_directory = string_copy(s);

s = US getenv("START_SMALL");
if (s && Ustrcmp(s, "yes") == 0) start_small = 1;

s = US getenv("TEXT_DEPTH");
if (s && (x = Uatoi(s)) != 0) text_depth = x;

if ((s = US getenv("WINDOW_TITLE")))
  window_title = string_copy(s);

/* Deal with stripchart configuration. First see if we are monitoring
the size of a partition, then deal with log stripcharts in a separate
function */

s = US getenv("SIZE_STRIPCHART");
if (s && *s)
  {
  stripchart_number++;
  stripchart_varstart++;
  size_stripchart = string_copy(s);
  s = US getenv("SIZE_STRIPCHART_NAME");
  if (s != NULL && *s != 0) size_stripchart_name = string_copy(s);
  }

if ((s = US getenv("LOG_STRIPCHARTS")))
  decode_stripchart_config(s);

s = US getenv("STRIPCHART_INTERVAL");
if (s && (x = Uatoi(s)) != 0) stripchart_update = x;

s = US getenv("QUEUE_STRIPCHART_NAME");
queue_stripchart_name = s ? string_copy(s) : US"queue";

/* Compile the regex for matching yyyy-mm-dd at the start of a string. */

yyyymmdd_regex = pcre2_compile((PCRE2_SPTR)"^\\d{4}-\\d\\d-\\d\\d\\s",
  PCRE2_ZERO_TERMINATED, PCRE_COPT, &x, &erroroffset, NULL);
}

/* End of em_init.c */
