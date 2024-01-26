/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * Copyright (c) The Exim Maintainers 2016 - 2023
 * Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003-2015
 * License: GPL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Code for matching regular expressions against headers and body.
 Called from acl.c. */

#include "exim.h"
#ifdef WITH_CONTENT_SCAN
#include <unistd.h>
#include <sys/mman.h>

/* Structure to hold a list of Regular expressions */
typedef struct pcre_list {
  const pcre2_code *	re;
  uschar *		pcre_text;
  struct pcre_list *	next;
} pcre_list;

uschar regex_match_string_buffer[1024];

extern FILE *mime_stream;
extern uschar *mime_current_boundary;


static pcre_list *
compile(const uschar * list, BOOL cacheable, int * cntp)
{
int sep = 0, cnt = 0;
uschar * regex_string;
pcre_list * re_list_head = NULL, * ri;

/* precompile our regexes */
while ((regex_string = string_nextinlist(&list, &sep, NULL, 0)))
  if (strcmpic(regex_string, US"false") != 0 && Ustrcmp(regex_string, "0") != 0)
    {
    /* compile our regular expression */
    uschar * errstr;
    const pcre2_code * re = regex_compile(regex_string,
      cacheable ? MCS_CACHEABLE : MCS_NOFLAGS, &errstr, pcre_gen_cmp_ctx);

    if (!re)
      {
      log_write(0, LOG_MAIN, "regex acl condition warning - %s, skipped", errstr);
      continue;
      }

    ri = store_get(sizeof(pcre_list), GET_UNTAINTED);
    ri->re = re;
    ri->pcre_text = regex_string;
    ri->next = re_list_head;
    re_list_head = ri;
    cnt++;
    }
if (cntp) *cntp = cnt;
return re_list_head;
}

static int
matcher(pcre_list * re_list_head, uschar * linebuffer, int len)
{
pcre2_match_data * md = pcre2_match_data_create(REGEX_VARS + 1, pcre_gen_ctx);

for (pcre_list * ri = re_list_head; ri; ri = ri->next)
  {
  int n;

  /* try matcher on the line */
  if ((n = pcre2_match(ri->re, (PCRE2_SPTR)linebuffer, len, 0, 0, md, pcre_gen_mtc_ctx)) > 0)
    {
    Ustrncpy(regex_match_string_buffer, ri->pcre_text,
	      sizeof(regex_match_string_buffer)-1);
    regex_match_string = regex_match_string_buffer;

    for (int nn = 1; nn < n; nn++)
      {
      PCRE2_SIZE * ovec = pcre2_get_ovector_pointer(md);
      int off = nn * 2;
      int len = ovec[off + 1] - ovec[off];
      regex_vars[nn-1] = string_copyn(linebuffer + ovec[off], len);
      }

    return OK;
    }
  }
/* pcre2_match_data_free(md);	gen ctx needs no free */
return FAIL;
}


/* reset expansion variables */
void
regex_vars_clear(void)
{
regex_match_string = NULL;
for (int i = 0; i < REGEX_VARS; i++) regex_vars[i] = NULL;
}



int
regex(const uschar ** listptr, BOOL cacheable)
{
unsigned long mbox_size;
FILE * mbox_file;
pcre_list * re_list_head;
uschar * linebuffer;
long f_pos = 0;
int ret = FAIL, cnt, lcount = REGEX_LOOPCOUNT_STORE_RESET;
rmark reset_point;

regex_vars_clear();

if (!mime_stream)				/* We are in the DATA ACL */
  {
  if (!(mbox_file = spool_mbox(&mbox_size, NULL, NULL)))
    {						/* error while spooling */
    log_write(0, LOG_MAIN|LOG_PANIC,
	   "regex acl condition: error while creating mbox spool file");
    return DEFER;
    }
  }
else
  {
  if ((f_pos = ftell(mime_stream)) < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
	   "regex acl condition: mime_stream: %s", strerror(errno));
    return DEFER;
    }
  mbox_file = mime_stream;
  }

reset_point = store_mark();
  {
  /* precompile our regexes */
  if ((re_list_head = compile(*listptr, cacheable, &cnt)))
    {
    /* match each line against all regexes */
    linebuffer = store_get(32767, GET_TAINTED);
    while (fgets(CS linebuffer, 32767, mbox_file))
      {
      if (  mime_stream && mime_current_boundary		/* check boundary */
	 && Ustrncmp(linebuffer, "--", 2) == 0
	 && Ustrncmp((linebuffer+2), mime_current_boundary,
		      Ustrlen(mime_current_boundary)) == 0)
	break;						/* found boundary */

      if ((ret = matcher(re_list_head, linebuffer, (int)Ustrlen(linebuffer))) == OK)
	break;

      if ((lcount -= cnt) <= 0)
	{
	store_reset(reset_point); reset_point = store_mark();
	lcount = REGEX_LOOPCOUNT_STORE_RESET;
	}
      }
    }
  }
store_reset(reset_point);

if (!mime_stream)
  (void)fclose(mbox_file);
else
  {
  clearerr(mime_stream);
  if (fseek(mime_stream, f_pos, SEEK_SET) == -1)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
	   "regex acl condition: mime_stream: %s", strerror(errno));
    clearerr(mime_stream);
    }
  }

return ret;
}


int
mime_regex(const uschar **listptr, BOOL cacheable)
{
pcre_list * re_list_head = NULL;
FILE * f;
uschar * mime_subject = NULL;
int mime_subject_len = 0;
int ret = FAIL;
rmark reset_point;

regex_vars_clear();

/* check if the file is already decoded */
if (!mime_decoded_filename)
  {				/* no, decode it first */
  const uschar *empty = US"";
  mime_decode(&empty);
  if (!mime_decoded_filename)
    {				/* decoding failed */
    log_write(0, LOG_MAIN,
       "mime_regex acl condition warning - could not decode MIME part to file");
    return DEFER;
    }
  }

/* open file */
if (!(f = fopen(CS mime_decoded_filename, "rb")))
  {
  log_write(0, LOG_MAIN,
       "mime_regex acl condition warning - can't open '%s' for reading",
       mime_decoded_filename);
  return DEFER;
  }

reset_point = store_mark();
  {
  /* precompile our regexes */
  if ((re_list_head = compile(*listptr, cacheable, NULL)))
    {
    /* get 32k memory, tainted */
    mime_subject = store_get(32767, GET_TAINTED);

    mime_subject_len = fread(mime_subject, 1, 32766, f);

    ret = matcher(re_list_head, mime_subject, mime_subject_len);
    }
  }
store_reset(reset_point);
(void)fclose(f);
return ret;
}

#endif /* WITH_CONTENT_SCAN */
