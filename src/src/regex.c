/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003-2015 */
/* License: GPL */

/* Code for matching regular expressions against headers and body.
 Called from acl.c. */

#include "exim.h"
#ifdef WITH_CONTENT_SCAN
#include <unistd.h>
#include <sys/mman.h>

/* Structure to hold a list of Regular expressions */
typedef struct pcre_list {
  pcre *re;
  uschar *pcre_text;
  struct pcre_list *next;
} pcre_list;

uschar regex_match_string_buffer[1024];

extern FILE *mime_stream;
extern uschar *mime_current_boundary;

int
regex(const uschar **listptr)
{
  int sep = 0;
  const uschar *list = *listptr;
  uschar *regex_string;
  uschar regex_string_buffer[1024];
  unsigned long mbox_size;
  FILE *mbox_file;
  pcre *re;
  pcre_list *re_list_head = NULL;
  pcre_list *re_list_item;
  const char *pcre_error;
  int pcre_erroffset;
  uschar *linebuffer;
  long f_pos = 0;

  /* reset expansion variable */
  regex_match_string = NULL;

  if (mime_stream == NULL) {
    /* We are in the DATA ACL */
    mbox_file = spool_mbox(&mbox_size, NULL);
    if (mbox_file == NULL) {
      /* error while spooling */
      log_write(0, LOG_MAIN|LOG_PANIC,
             "regex acl condition: error while creating mbox spool file");
      return DEFER;
    };
  }
  else {
    f_pos = ftell(mime_stream);
    mbox_file = mime_stream;
  };

  /* precompile our regexes */
  while ((regex_string = string_nextinlist(&list, &sep,
                                           regex_string_buffer,
                                           sizeof(regex_string_buffer))) != NULL) {

    /* parse option */
    if ( (strcmpic(regex_string,US"false") == 0) ||
         (Ustrcmp(regex_string,"0") == 0) ) {
      /* explicitly no matching */
      continue;
    };

    /* compile our regular expression */
    re = pcre_compile( CS regex_string,
                       0,
                       &pcre_error,
                       &pcre_erroffset,
                       NULL );

    if (re == NULL) {
      log_write(0, LOG_MAIN,
           "regex acl condition warning - error in regex '%s': %s at offset %d, skipped.", regex_string, pcre_error, pcre_erroffset);
      continue;
    }
    else {
      re_list_item = store_get(sizeof(pcre_list));
      re_list_item->re = re;
      re_list_item->pcre_text = string_copy(regex_string);
      re_list_item->next = re_list_head;
      re_list_head = re_list_item;
    };
  };

  /* no regexes -> nothing to do */
  if (re_list_head == NULL) {
    return FAIL;
  };

  /* match each line against all regexes */
  linebuffer = store_get(32767);
  while (fgets(CS linebuffer, 32767, mbox_file) != NULL) {
    if ( (mime_stream != NULL) && (mime_current_boundary != NULL) ) {
      /* check boundary */
      if (Ustrncmp(linebuffer,"--",2) == 0) {
        if (Ustrncmp((linebuffer+2),mime_current_boundary,Ustrlen(mime_current_boundary)) == 0)
          /* found boundary */
          break;
      };
    };
    re_list_item = re_list_head;
    do {
      /* try matcher on the line */
      if (pcre_exec(re_list_item->re, NULL, CS linebuffer,
      (int)Ustrlen(linebuffer), 0, 0, NULL, 0) >= 0) {
        Ustrncpy(regex_match_string_buffer, re_list_item->pcre_text, 1023);
        regex_match_string = regex_match_string_buffer;
        if (mime_stream == NULL)
          (void)fclose(mbox_file);
        else {
          clearerr(mime_stream);
          fseek(mime_stream,f_pos,SEEK_SET);
        };
        return OK;
      };
      re_list_item = re_list_item->next;
    } while (re_list_item != NULL);
  };

  if (mime_stream == NULL)
    (void)fclose(mbox_file);
  else {
    clearerr(mime_stream);
    fseek(mime_stream,f_pos,SEEK_SET);
  };

  /* no matches ... */
  return FAIL;
}


int
mime_regex(const uschar **listptr)
{
  int sep = 0;
  const uschar *list = *listptr;
  uschar *regex_string;
  uschar regex_string_buffer[1024];
  pcre *re;
  pcre_list *re_list_head = NULL;
  pcre_list *re_list_item;
  const char *pcre_error;
  int pcre_erroffset;
  FILE *f;
  uschar *mime_subject = NULL;
  int mime_subject_len = 0;

  /* reset expansion variable */
  regex_match_string = NULL;

  /* precompile our regexes */
  while ((regex_string = string_nextinlist(&list, &sep,
                                           regex_string_buffer,
                                           sizeof(regex_string_buffer))) != NULL) {

    /* parse option */
    if ( (strcmpic(regex_string,US"false") == 0) ||
         (Ustrcmp(regex_string,"0") == 0) ) {
      /* explicitly no matching */
      continue;
    };

    /* compile our regular expression */
    re = pcre_compile( CS regex_string,
                       0,
                       &pcre_error,
                       &pcre_erroffset,
                       NULL );

    if (re == NULL) {
      log_write(0, LOG_MAIN,
           "regex acl condition warning - error in regex '%s': %s at offset %d, skipped.", regex_string, pcre_error, pcre_erroffset);
      continue;
    }
    else {
      re_list_item = store_get(sizeof(pcre_list));
      re_list_item->re = re;
      re_list_item->pcre_text = string_copy(regex_string);
      re_list_item->next = re_list_head;
      re_list_head = re_list_item;
    };
  };

  /* no regexes -> nothing to do */
  if (re_list_head == NULL) {
    return FAIL;
  };

  /* check if the file is already decoded */
  if (mime_decoded_filename == NULL) {
    const uschar *empty = US"";
    /* no, decode it first */
    mime_decode(&empty);
    if (mime_decoded_filename == NULL) {
      /* decoding failed */
      log_write(0, LOG_MAIN,
           "mime_regex acl condition warning - could not decode MIME part to file.");
      return DEFER;
    };
  };


  /* open file */
  f = fopen(CS mime_decoded_filename, "rb");
  if (f == NULL) {
    /* open failed */
    log_write(0, LOG_MAIN,
         "mime_regex acl condition warning - can't open '%s' for reading.", mime_decoded_filename);
    return DEFER;
  };

  /* get 32k memory */
  mime_subject = (uschar *)store_get(32767);

  /* read max 32k chars from file */
  mime_subject_len = fread(mime_subject, 1, 32766, f);

  re_list_item = re_list_head;
  do {
    /* try matcher on the mmapped file */
    debug_printf("Matching '%s'\n", re_list_item->pcre_text);
    if (pcre_exec(re_list_item->re, NULL, CS mime_subject,
                  mime_subject_len, 0, 0, NULL, 0) >= 0) {
      Ustrncpy(regex_match_string_buffer, re_list_item->pcre_text, 1023);
      regex_match_string = regex_match_string_buffer;
      (void)fclose(f);
      return OK;
    };
    re_list_item = re_list_item->next;
  } while (re_list_item != NULL);

  (void)fclose(f);

  /* no matches ... */
  return FAIL;
}

#endif /* WITH_CONTENT_SCAN */
