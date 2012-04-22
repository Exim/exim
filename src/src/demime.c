/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003-???? */
/* License: GPL */

/* Code for unpacking MIME containers. Called from acl.c. */

#include "exim.h"
#ifdef WITH_OLD_DEMIME

#include "demime.h"

uschar demime_reason_buffer[1024];
struct file_extension *file_extensions = NULL;

int demime(uschar **listptr) {
  int sep = 0;
  uschar *list = *listptr;
  uschar *option;
  uschar option_buffer[64];
  unsigned long mbox_size;
  FILE *mbox_file;
  uschar defer_error_buffer[1024];
  int demime_rc = 0;

  /* reset found_extension variable */
  found_extension = NULL;

  /* try to find 1st option */
  if ((option = string_nextinlist(&list, &sep,
                                  option_buffer,
                                  sizeof(option_buffer))) != NULL) {

    /* parse 1st option */
    if ( (Ustrcmp(option,"false") == 0) || (Ustrcmp(option,"0") == 0) ) {
      /* explicitly no demimeing */
      return FAIL;
    };
  }
  else {
    /* no options -> no demimeing */
    return FAIL;
  };

  /* make sure the eml mbox file is spooled up */
  mbox_file = spool_mbox(&mbox_size, NULL);

  if (mbox_file == NULL) {
    /* error while spooling */
    log_write(0, LOG_MAIN|LOG_PANIC,
           "demime acl condition: error while creating mbox spool file");
    return DEFER;
  };

  /* call demimer if not already done earlier */
  if (!demime_ok)
    demime_rc = mime_demux(mbox_file, defer_error_buffer);

  (void)fclose(mbox_file);

  if (demime_rc == DEFER) {
    /* temporary failure (DEFER => DEFER) */
    log_write(0, LOG_MAIN,
        "demime acl condition: %s", defer_error_buffer);
    return DEFER;
  };

  /* set demime_ok to avoid unpacking again */
  demime_ok = 1;

  /* check for file extensions, if there */
  while (option != NULL) {
    struct file_extension *this_extension = file_extensions;

    /* Look for the wildcard. If it is found, we always return true.
    The user must then use a custom condition to evaluate demime_errorlevel */
    if (Ustrcmp(option,"*") == 0) {
      found_extension = NULL;
      return OK;
    };

    /* loop thru extension list */
    while (this_extension != NULL) {
      if (strcmpic(option, this_extension->file_extension_string) == 0) {
        /* found one */
        found_extension = this_extension->file_extension_string;
        return OK;
      };
      this_extension = this_extension->next;
    };

    /* grab next extension from option list */
    option = string_nextinlist(&list, &sep,
                               option_buffer,
                               sizeof(option_buffer));
  };

  /* nothing found */
  return FAIL;
}


/*************************************************
* small hex_str -> integer conversion function   *
*************************************************/

/* needed for quoted-printable
*/

unsigned int mime_hstr_i(uschar *cptr) {
  unsigned int i, j = 0;

  while (cptr && *cptr && isxdigit(*cptr)) {
    i = *cptr++ - '0';
    if (9 < i) i -= 7;
    j <<= 4;
    j |= (i & 0x0f);
  }

  return(j);
}


/*************************************************
* decode quoted-printable chars                  *
*************************************************/

/* gets called when we hit a =
   returns: new pointer position
   result code in c:
          -2 - decode error
          -1 - soft line break, no char
           0-255 - char to write
*/

uschar *mime_decode_qp(uschar *qp_p,int *c) {
  uschar hex[] = {0,0,0};
  int nan = 0;
  uschar *initial_pos = qp_p;

  /* advance one char */
  qp_p++;

  REPEAT_FIRST:
  if ( (*qp_p == '\t') || (*qp_p == ' ') || (*qp_p == '\r') )  {
    /* tab or whitespace may follow
       just ignore it, but remember
       that this is not a valid hex
       encoding any more */
    nan = 1;
    qp_p++;
    goto REPEAT_FIRST;
  }
  else if ( (('0' <= *qp_p) && (*qp_p <= '9')) || (('A' <= *qp_p) && (*qp_p <= 'F'))  || (('a' <= *qp_p) && (*qp_p <= 'f')) ) {
    /* this is a valid hex char, if nan is unset */
    if (nan) {
      /* this is illegal */
      *c = -2;
      return initial_pos;
    }
    else {
      hex[0] = *qp_p;
      qp_p++;
    };
  }
  else if (*qp_p == '\n') {
    /* hit soft line break already, continue */
    *c = -1;
    return qp_p;
  }
  else {
    /* illegal char here */
    *c = -2;
    return initial_pos;
  };

  if ( (('0' <= *qp_p) && (*qp_p <= '9')) || (('A' <= *qp_p) && (*qp_p <= 'F')) || (('a' <= *qp_p) && (*qp_p <= 'f')) ) {
    if (hex[0] > 0) {
      hex[1] = *qp_p;
      /* do hex conversion */
      *c = mime_hstr_i(hex);
      qp_p++;
      return qp_p;
    }
    else {
      /* huh ? */
      *c = -2;
      return initial_pos;
    };
  }
  else {
    /* illegal char */
    *c = -2;
    return initial_pos;
  };

}


/*************************************************
* open new dump file                             *
*************************************************/

/* open new dump file
   returns: -2 soft error
            or file #, FILE * in f
*/

int mime_get_dump_file(uschar *extension, FILE **f, uschar *info) {
  uschar file_name[1024];
  int result;
  unsigned int file_nr;
  uschar default_extension[] = ".com";
  uschar *p;

  if (extension == NULL)
    extension = default_extension;

  /* scan the proposed extension.
     if it is longer than 4 chars, or
     contains exotic chars, use the default extension */

/*  if (Ustrlen(extension) > 4) {
    extension = default_extension;
  };
*/

  p = extension+1;

  while (*p != 0) {
    *p = (uschar)tolower((uschar)*p);
    if ( (*p < 97) || (*p > 122) ) {
      extension = default_extension;
      break;
    };
    p++;
  };

  /* find a new file to write to */
  file_nr = 0;
  do {
    struct stat mystat;

    (void)string_format(file_name,1024,"%s/scan/%s/%s-%05u%s",spool_directory,message_id,message_id,file_nr,extension);
    file_nr++;
    if (file_nr >= MIME_SANITY_MAX_DUMP_FILES) {
      /* max parts reached */
      mime_trigger_error(MIME_ERRORLEVEL_TOO_MANY_PARTS);
      break;
    };
    result = stat(CS file_name,&mystat);
  }
  while(result != -1);

  *f = modefopen(file_name,"wb+",SPOOL_MODE);
  if (*f == NULL) {
    /* cannot open new dump file, disk full ? -> soft error */
    (void)string_format(info, 1024,"unable to open dump file");
    return -2;
  };

  return file_nr;
}


/*************************************************
* Find a string in a mime header                 *
*************************************************/

/* Find a string in a mime header, and optionally fill in
   the value associated with it into *value

   returns: 0 - nothing found
            1 - found param
            2 - found param + value
*/

int mime_header_find(uschar *header, uschar *param, uschar **value) {
  uschar *needle;

  needle = strstric(header,param,FALSE);
  if (needle != NULL) {
    if (value != NULL) {
      needle += Ustrlen(param);
      if (*needle == '=') {
        uschar *value_start;
        uschar *value_end;

        value_start = needle + 1;
        value_end = strstric(value_start,US";",FALSE);
        if (value_end != NULL) {
          /* allocate mem for value */
          *value = (uschar *)malloc((value_end - value_start)+1);
          if (*value == NULL)
            return 0;

          Ustrncpy(*value,value_start,(value_end - value_start));
          (*value)[(value_end - value_start)] = '\0';
          return 2;
        };
      };
    };
    return 1;
  };
  return 0;
}


/*************************************************
* Read a line of MIME input                      *
*************************************************/
/* returns status code, one of
   MIME_READ_LINE_EOF 0
   MIME_READ_LINE_OK 1
   MIME_READ_LINE_OVERFLOW 2

   In header mode, the line will be "cooked".
*/

int mime_read_line(FILE *f, int mime_demux_mode, uschar *buffer, long *num_copied) {
  int c = EOF;
  int done = 0;
  int header_value_mode = 0;
  int header_open_brackets = 0;

  *num_copied = 0;

  while(!done) {

    c = fgetc(f);
    if (c == EOF) break;

    /* --------- header mode -------------- */
    if (mime_demux_mode == MIME_DEMUX_MODE_MIME_HEADERS) {

      /* always skip CRs */
      if (c == '\r') continue;

      if (c == '\n') {
        if ((*num_copied) > 0) {
          /* look if next char is '\t' or ' ' */
          c = fgetc(f);
          if (c == EOF) break;
          if ( (c == '\t') || (c == ' ') ) continue;
          (void)ungetc(c,f);
        };
        /* end of the header, terminate with ';' */
        c = ';';
        done = 1;
      };

      /* skip control characters */
      if (c < 32) continue;

      /* skip whitespace + tabs */
      if ( (c == ' ') || (c == '\t') )
        continue;

      if (header_value_mode) {
        /* --------- value mode ----------- */
        /* skip quotes */
        if (c == '"') continue;

        /* leave value mode on ';' */
        if (c == ';') {
          header_value_mode = 0;
        };
        /* -------------------------------- */
      }
      else {
        /* -------- non-value mode -------- */
        if (c == '\\') {
          /* quote next char. can be used
          to escape brackets. */
          c = fgetc(f);
          if (c == EOF) break;
        }
        else if (c == '(') {
          header_open_brackets++;
          continue;
        }
        else if ((c == ')') && header_open_brackets) {
          header_open_brackets--;
          continue;
        }
        else if ( (c == '=') && !header_open_brackets ) {
          /* enter value mode */
          header_value_mode = 1;
        };

        /* skip chars while we are in a comment */
        if (header_open_brackets > 0)
          continue;
        /* -------------------------------- */
      };
    }
    /* ------------------------------------ */
    else {
    /* ----------- non-header mode -------- */
      /* break on '\n' */
      if (c == '\n')
        done = 1;
    /* ------------------------------------ */
    };

    /* copy the char to the buffer */
    buffer[*num_copied] = (uschar)c;
    /* raise counter */
    (*num_copied)++;

    /* break if buffer is full */
    if (*num_copied > MIME_SANITY_MAX_LINE_LENGTH-1) {
      done = 1;
    };
  }

  /* 0-terminate */
  buffer[*num_copied] = '\0';

  if (*num_copied > MIME_SANITY_MAX_LINE_LENGTH-1)
    return MIME_READ_LINE_OVERFLOW;
  else
    if (c == EOF)
      return MIME_READ_LINE_EOF;
    else
      return MIME_READ_LINE_OK;
}


/*************************************************
* Check for a MIME boundary                      *
*************************************************/

/* returns: 0 - no boundary found
            1 - start boundary found
            2 - end boundary found
*/

int mime_check_boundary(uschar *line, struct boundary *boundaries) {
  struct boundary *thisboundary = boundaries;
  uschar workbuf[MIME_SANITY_MAX_LINE_LENGTH+1];
  unsigned int i,j=0;

  /* check for '--' first */
  if (Ustrncmp(line,"--",2) == 0) {

    /* strip tab and space */
    for (i = 2; i < Ustrlen(line); i++) {
      if ((line[i] != ' ') && (line[i] != '\t')) {
        workbuf[j] = line[i];
        j++;
      };
    };
    workbuf[j+1]='\0';

    while(thisboundary != NULL) {
      if (Ustrncmp(workbuf,thisboundary->boundary_string,Ustrlen(thisboundary->boundary_string)) == 0) {
        if (Ustrncmp(&workbuf[Ustrlen(thisboundary->boundary_string)],"--",2) == 0) {
          /* final boundary found */
          return 2;
        };
        return 1;
      };
      thisboundary = thisboundary->next;
    };
  };

  return 0;
}


/*************************************************
* Check for start of a UUENCODE block            *
*************************************************/

/* returns 0 for no hit,
           >0 for hit
*/

int mime_check_uu_start(uschar *line, uschar *uu_file_extension, int *has_tnef) {

  if ( (strncmpic(line,US"begin ",6) == 0)) {
    uschar *uu_filename = &line[6];

    /* skip perms, if present */
    Ustrtoul(&line[6],&uu_filename,10);

    /* advance one char */
    uu_filename++;

    /* This should be the filename.
    Check if winmail.dat is present,
    which indicates TNEF. */
    if (strncmpic(uu_filename,US"winmail.dat",11) == 0) {
      *has_tnef = 1;
    };

    /* reverse to dot if present,
    copy up to 4 chars for the extension */
    if (Ustrrchr(uu_filename,'.') != NULL)
      uu_filename = Ustrrchr(uu_filename,'.');

    return sscanf(CS uu_filename, "%4[.0-9A-Za-z]",CS uu_file_extension);
  }
  else {
    /* nothing found */
    return 0;
  };
}


/*************************************************
* Decode a uu line                               *
*************************************************/

/* returns number of decoded bytes
         -2 for soft errors
*/

int warned_about_uudec_line_sanity_1 = 0;
int warned_about_uudec_line_sanity_2 = 0;
long uu_decode_line(uschar *line, uschar **data, long line_len, uschar *info) {
  uschar *p;
  long num_decoded = 0;
  uschar tmp_c;
  uschar *work;
  int uu_decoded_line_len, uu_encoded_line_len;

  /* allocate memory for data and work buffer */
  *data = (uschar *)malloc(line_len);
  if (*data == NULL) {
    (void)string_format(info, 1024,"unable to allocate %lu bytes",line_len);
    return -2;
  };

  work = (uschar *)malloc(line_len);
  if (work == NULL) {
    (void)string_format(info, 1024,"unable to allocate %lu bytes",line_len);
    return -2;
  };

  memcpy(work,line,line_len);

  /* First char is line length
  This is microsofts way of getting it. Scary. */
  if (work[0] < 32) {
    /* ignore this line */
    return 0;
  }
  else {
    uu_decoded_line_len = uudec[work[0]];
  };

  p = &work[1];

  while (*p > 32) {
    *p = uudec[*p];
    p++;
  };

  uu_encoded_line_len = (p - &work[1]);
  p = &work[1];

  /* check that resulting line length is a multiple of 4 */
  if ( ( uu_encoded_line_len % 4 ) != 0) {
    if (!warned_about_uudec_line_sanity_1) {
      mime_trigger_error(MIME_ERRORLEVEL_UU_MISALIGNED);
      warned_about_uudec_line_sanity_1 = 1;
    };
    return -1;
  };

  /* check that the line length matches */
  if ( ( (((uu_encoded_line_len/4)*3)-2) > uu_decoded_line_len ) || (((uu_encoded_line_len/4)*3) < uu_decoded_line_len) ) {
    if (!warned_about_uudec_line_sanity_2) {
      mime_trigger_error(MIME_ERRORLEVEL_UU_LINE_LENGTH);
      warned_about_uudec_line_sanity_2 = 1;
    };
    return -1;
  };

  while ( ((p - &work[1]) < uu_encoded_line_len) && (num_decoded < uu_decoded_line_len)) {

    /* byte 0 ---------------------- */
    if ((p - &work[1] + 1) >= uu_encoded_line_len) {
      return 0;
    }

    (*data)[num_decoded] = *p;
    (*data)[num_decoded] <<= 2;

    tmp_c = *(p+1);
    tmp_c >>= 4;
    (*data)[num_decoded] |= tmp_c;

    num_decoded++;
    p++;

    /* byte 1 ---------------------- */
    if ((p - &work[1] + 1) >= uu_encoded_line_len) {
      return 0;
    }

    (*data)[num_decoded] = *p;
    (*data)[num_decoded] <<= 4;

    tmp_c = *(p+1);
    tmp_c >>= 2;
    (*data)[num_decoded] |= tmp_c;

    num_decoded++;
    p++;

    /* byte 2 ---------------------- */
    if ((p - &work[1] + 1) >= uu_encoded_line_len) {
      return 0;
    }

    (*data)[num_decoded] = *p;
    (*data)[num_decoded] <<= 6;

    (*data)[num_decoded] |= *(p+1);

    num_decoded++;
    p+=2;

  };

  return uu_decoded_line_len;
}


/*************************************************
* Decode a b64 or qp line                        *
*************************************************/

/* returns number of decoded bytes
         -1 for hard errors
         -2 for soft errors
*/

int warned_about_b64_line_length = 0;
int warned_about_b64_line_sanity = 0;
int warned_about_b64_illegal_char = 0;
int warned_about_qp_line_sanity = 0;
long mime_decode_line(int mime_demux_mode,uschar *line, uschar **data, long max_data_len, uschar *info) {
  uschar *p;
  long num_decoded = 0;
  int offset = 0;
  uschar tmp_c;

  /* allocate memory for data */
  *data = (uschar *)malloc(max_data_len);
  if (*data == NULL) {
    (void)string_format(info, 1024,"unable to allocate %lu bytes",max_data_len);
    return -2;
  };

  if (mime_demux_mode == MIME_DEMUX_MODE_BASE64) {
    /* ---------------------------------------------- */

    /* NULL out trailing '\r' and '\n' chars */
    while (Ustrrchr(line,'\r') != NULL) {
      *(Ustrrchr(line,'\r')) = '\0';
    };
    while (Ustrrchr(line,'\n') != NULL) {
      *(Ustrrchr(line,'\n')) = '\0';
    };

    /* check maximum base 64 line length */
    if (Ustrlen(line) > MIME_SANITY_MAX_B64_LINE_LENGTH ) {
      if (!warned_about_b64_line_length) {
        mime_trigger_error(MIME_ERRORLEVEL_B64_LINE_LENGTH);
        warned_about_b64_line_length = 1;
      };
    };

    p = line;
    offset = 0;
    while (*(p+offset) != '\0') {
      /* hit illegal char ? */
      if (b64[*(p+offset)] == 128) {
        if (!warned_about_b64_illegal_char) {
          mime_trigger_error(MIME_ERRORLEVEL_B64_ILLEGAL_CHAR);
          warned_about_b64_illegal_char = 1;
        };
        offset++;
      }
      else {
        *p = b64[*(p+offset)];
        p++;
      };
    };
    *p = 255;

    /* check that resulting line length is a multiple of 4 */
    if ( ( (p - &line[0]) % 4 ) != 0) {
      if (!warned_about_b64_line_sanity) {
        mime_trigger_error(MIME_ERRORLEVEL_B64_MISALIGNED);
        warned_about_b64_line_sanity = 1;
      };
    };

    /* line is translated, start bit shifting */
    p = line;
    num_decoded = 0;

    while(*p != 255) {

      /* byte 0 ---------------------- */
      if (*(p+1) == 255) {
        break;
      }

      (*data)[num_decoded] = *p;
      (*data)[num_decoded] <<= 2;

      tmp_c = *(p+1);
      tmp_c >>= 4;
      (*data)[num_decoded] |= tmp_c;

      num_decoded++;
      p++;

      /* byte 1 ---------------------- */
      if (*(p+1) == 255) {
        break;
      }

      (*data)[num_decoded] = *p;
      (*data)[num_decoded] <<= 4;

      tmp_c = *(p+1);
      tmp_c >>= 2;
      (*data)[num_decoded] |= tmp_c;

      num_decoded++;
      p++;

      /* byte 2 ---------------------- */
      if (*(p+1) == 255) {
        break;
      }

      (*data)[num_decoded] = *p;
      (*data)[num_decoded] <<= 6;

      (*data)[num_decoded] |= *(p+1);

      num_decoded++;
      p+=2;

    };
    return num_decoded;
    /* ---------------------------------------------- */
  }
  else if (mime_demux_mode == MIME_DEMUX_MODE_QP) {
    /* ---------------------------------------------- */
    p = line;

    while (*p != 0) {
      if (*p == '=') {
        int decode_qp_result;

        p = mime_decode_qp(p,&decode_qp_result);

        if (decode_qp_result == -2) {
          /* Error from decoder. p is unchanged. */
          if (!warned_about_qp_line_sanity) {
            mime_trigger_error(MIME_ERRORLEVEL_QP_ILLEGAL_CHAR);
            warned_about_qp_line_sanity = 1;
          };
          (*data)[num_decoded] = '=';
          num_decoded++;
          p++;
        }
        else if (decode_qp_result == -1) {
          /* End of the line with soft line break.
          Bail out. */
          goto QP_RETURN;
        }
        else if (decode_qp_result >= 0) {
          (*data)[num_decoded] = decode_qp_result;
          num_decoded++;
        };
      }
      else {
        (*data)[num_decoded] = *p;
        num_decoded++;
        p++;
      };
    };
    QP_RETURN:
    return num_decoded;
    /* ---------------------------------------------- */
  };

  return 0;
}



/*************************************************
* Log demime errors and set mime error level     *
*************************************************/

/* This sets the global demime_reason expansion
variable and the demime_errorlevel gauge. */

void mime_trigger_error(int level, uschar *format, ...) {
  char *f;
  va_list ap;

  if( (f = malloc(16384+23)) != NULL ) {
    /* first log the incident */
    sprintf(f,"demime acl condition: ");
    f+=22;
    va_start(ap, format);
    (void)string_vformat(US f, 16383,(char *)format, ap);
    va_end(ap);
    f-=22;
    log_write(0, LOG_MAIN, "%s", f);
    /* then copy to demime_reason_buffer if new
    level is greater than old level */
    if (level > demime_errorlevel) {
      demime_errorlevel = level;
      Ustrcpy(demime_reason_buffer, US f);
      demime_reason = demime_reason_buffer;
    };
    free(f);
  };
}

/*************************************************
* Demultiplex MIME stream.                       *
*************************************************/

/* We can handle BASE64, QUOTED-PRINTABLE, and UUENCODE.
 UUENCODE does not need to have a proper
 transfer-encoding header, we detect it with "begin"

 This function will report human parsable errors in
 *info.

 returns DEFER -> soft error (see *info)
         OK    -> EOF hit, all ok
*/

int mime_demux(FILE *f, uschar *info) {
  int mime_demux_mode = MIME_DEMUX_MODE_MIME_HEADERS;
  int uu_mode = MIME_UU_MODE_OFF;
  FILE *mime_dump_file = NULL;
  FILE *uu_dump_file = NULL;
  uschar *line;
  int mime_read_line_status = MIME_READ_LINE_OK;
  long line_len;
  struct boundary *boundaries = NULL;
  struct mime_part mime_part_p;
  int has_tnef = 0;
  int has_rfc822 = 0;

  /* allocate room for our linebuffer */
  line = (uschar *)malloc(MIME_SANITY_MAX_LINE_LENGTH);
  if (line == NULL) {
    (void)string_format(info, 1024,"unable to allocate %u bytes",MIME_SANITY_MAX_LINE_LENGTH);
    return DEFER;
  };

  /* clear MIME header structure */
  memset(&mime_part_p,0,sizeof(mime_part));

  /* ----------------------- start demux loop --------------------- */
  while (mime_read_line_status == MIME_READ_LINE_OK) {

    /* read a line of input. Depending on the mode we are in,
    the returned format will differ. */
    mime_read_line_status = mime_read_line(f,mime_demux_mode,line,&line_len);

    if (mime_read_line_status == MIME_READ_LINE_OVERFLOW) {
      mime_trigger_error(MIME_ERRORLEVEL_LONG_LINE);
      /* despite the error, continue  .. */
      mime_read_line_status = MIME_READ_LINE_OK;
      continue;
    }
    else if (mime_read_line_status == MIME_READ_LINE_EOF) {
      break;
    };

    if (mime_demux_mode == MIME_DEMUX_MODE_MIME_HEADERS) {
      /* -------------- header mode --------------------- */

      /* Check for an empty line, which is the end of the headers.
       In HEADER mode, the line is returned "cooked", with the
       final '\n' replaced by a ';' */
      if (line_len == 1) {
        int tmp;

        /* We have reached the end of the headers. Start decoding
        with the collected settings. */
        if (mime_part_p.seen_content_transfer_encoding > 1) {
          mime_demux_mode = mime_part_p.seen_content_transfer_encoding;
        }
        else {
          /* default to plain mode if no specific encoding type found */
          mime_demux_mode = MIME_DEMUX_MODE_PLAIN;
        };

        /* open new dump file */
        tmp = mime_get_dump_file(mime_part_p.extension, &mime_dump_file, info);
        if (tmp < 0) {
          return DEFER;
        };

        /* clear out mime_part */
        memset(&mime_part_p,0,sizeof(mime_part));
      }
      else {
        /* Another header to check for file extensions,
        encoding type and boundaries */
        if (strncmpic(US"content-type:",line,Ustrlen("content-type:")) == 0) {
          /* ---------------------------- Content-Type header ------------------------------- */
          uschar *value = line;

          /* check for message/partial MIME type and reject it */
          if (mime_header_find(line,US"message/partial",NULL) > 0)
            mime_trigger_error(MIME_ERRORLEVEL_MESSAGE_PARTIAL);

          /* check for TNEF content type, remember to unpack TNEF later. */
          if (mime_header_find(line,US"application/ms-tnef",NULL) > 0)
            has_tnef = 1;

          /* check for message/rfcxxx attachments */
          if (mime_header_find(line,US"message/rfc822",NULL) > 0)
            has_rfc822 = 1;

          /* find the file extension, but do not fill it in
          it is already set, since content-disposition has
          precedence. */
          if (mime_part_p.extension == NULL) {
            if (mime_header_find(line,US"name",&value) == 2) {
              if (Ustrlen(value) > MIME_SANITY_MAX_FILENAME)
                mime_trigger_error(MIME_ERRORLEVEL_FILENAME_LENGTH);
              mime_part_p.extension = value;
              mime_part_p.extension = Ustrrchr(value,'.');
              if (mime_part_p.extension == NULL) {
                /* file without extension, setting
                NULL will use the default extension later */
                mime_part_p.extension = NULL;
              }
              else {
                struct file_extension *this_extension =
                  (struct file_extension *)malloc(sizeof(file_extension));

                this_extension->file_extension_string =
                  (uschar *)malloc(Ustrlen(mime_part_p.extension)+1);
                Ustrcpy(this_extension->file_extension_string,
                        mime_part_p.extension+1);
                this_extension->next = file_extensions;
                file_extensions = this_extension;
              };
            };
          };

          /* find a boundary and add it to the list, if present */
          value = line;
          if (mime_header_find(line,US"boundary",&value) == 2) {
            struct boundary *thisboundary;

            if (Ustrlen(value) > MIME_SANITY_MAX_BOUNDARY_LENGTH) {
              mime_trigger_error(MIME_ERRORLEVEL_BOUNDARY_LENGTH);
            }
            else {
              thisboundary = (struct boundary*)malloc(sizeof(boundary));
              thisboundary->next = boundaries;
              thisboundary->boundary_string = value;
              boundaries = thisboundary;
            };
          };

          if (mime_part_p.seen_content_type == 0) {
            mime_part_p.seen_content_type = 1;
          }
          else {
            mime_trigger_error(MIME_ERRORLEVEL_DOUBLE_HEADERS);
          };
          /* ---------------------------------------------------------------------------- */
        }
        else if (strncmpic(US"content-transfer-encoding:",line,Ustrlen("content-transfer-encoding:")) == 0) {
          /* ---------------------------- Content-Transfer-Encoding header -------------- */

         if (mime_part_p.seen_content_transfer_encoding == 0) {
            if (mime_header_find(line,US"base64",NULL) > 0) {
              mime_part_p.seen_content_transfer_encoding = MIME_DEMUX_MODE_BASE64;
            }
            else if (mime_header_find(line,US"quoted-printable",NULL) > 0) {
              mime_part_p.seen_content_transfer_encoding = MIME_DEMUX_MODE_QP;
            }
            else {
              mime_part_p.seen_content_transfer_encoding = MIME_DEMUX_MODE_PLAIN;
            };
          }
          else {
            mime_trigger_error(MIME_ERRORLEVEL_DOUBLE_HEADERS);
          };
          /* ---------------------------------------------------------------------------- */
        }
        else if (strncmpic(US"content-disposition:",line,Ustrlen("content-disposition:")) == 0) {
          /* ---------------------------- Content-Disposition header -------------------- */
          uschar *value = line;

          if (mime_part_p.seen_content_disposition == 0) {
            mime_part_p.seen_content_disposition = 1;

            if (mime_header_find(line,US"filename",&value) == 2) {
              if (Ustrlen(value) > MIME_SANITY_MAX_FILENAME)
                mime_trigger_error(MIME_ERRORLEVEL_FILENAME_LENGTH);
              mime_part_p.extension = value;
              mime_part_p.extension = Ustrrchr(value,'.');
              if (mime_part_p.extension == NULL) {
                /* file without extension, setting
                NULL will use the default extension later */
                mime_part_p.extension = NULL;
              }
              else {
                struct file_extension *this_extension =
                  (struct file_extension *)malloc(sizeof(file_extension));

                this_extension->file_extension_string =
                  (uschar *)malloc(Ustrlen(mime_part_p.extension)+1);
                Ustrcpy(this_extension->file_extension_string,
                        mime_part_p.extension+1);
                this_extension->next = file_extensions;
                file_extensions = this_extension;
              };
            };
          }
          else {
            mime_trigger_error(MIME_ERRORLEVEL_DOUBLE_HEADERS);
          };
          /* ---------------------------------------------------------------------------- */
        };
      };    /* End of header checks */
      /* ------------------------------------------------ */
    }
    else {
      /* -------------- non-header mode ----------------- */
      int tmp;

      if (uu_mode == MIME_UU_MODE_OFF) {
        uschar uu_file_extension[5];
        /* We are not currently decoding UUENCODE
        Check for possible UUENCODE start tag. */
        if (mime_check_uu_start(line,uu_file_extension,&has_tnef)) {
          /* possible UUENCODING start detected.
          Set unconfirmed mode first. */
          uu_mode = MIME_UU_MODE_UNCONFIRMED;
          /* open new uu dump file */
          tmp = mime_get_dump_file(uu_file_extension, &uu_dump_file, info);
          if (tmp < 0) {
            free(line);
            return DEFER;
          };
        };
      }
      else {
        uschar *data;
        long data_len = 0;

        if (uu_mode == MIME_UU_MODE_UNCONFIRMED) {
         /* We are in unconfirmed UUENCODE mode. */

         data_len = uu_decode_line(line,&data,line_len,info);

         if (data_len == -2) {
           /* temp error, turn off uudecode mode */
           if (uu_dump_file != NULL) {
            (void)fclose(uu_dump_file); uu_dump_file = NULL;
           };
           uu_mode = MIME_UU_MODE_OFF;
           return DEFER;
         }
         else if (data_len == -1) {
           if (uu_dump_file != NULL) {
            (void)fclose(uu_dump_file); uu_dump_file = NULL;
           };
           uu_mode = MIME_UU_MODE_OFF;
           data_len = 0;
         }
         else if (data_len > 0) {
           /* we have at least decoded a valid byte
           turn on confirmed mode */
           uu_mode = MIME_UU_MODE_CONFIRMED;
         };
        }
        else if (uu_mode == MIME_UU_MODE_CONFIRMED) {
          /* If we are in confirmed UU mode,
          check for single "end" tag on line */
          if ((strncmpic(line,US"end",3) == 0) && (line[3] < 32)) {
            if (uu_dump_file != NULL) {
              (void)fclose(uu_dump_file); uu_dump_file = NULL;
            };
            uu_mode = MIME_UU_MODE_OFF;
          }
          else {
            data_len = uu_decode_line(line,&data,line_len,info);
            if (data_len == -2) {
               /* temp error, turn off uudecode mode */
               if (uu_dump_file != NULL) {
                 (void)fclose(uu_dump_file); uu_dump_file = NULL;
               };
               uu_mode = MIME_UU_MODE_OFF;
               return DEFER;
             }
             else if (data_len == -1) {
               /* skip this line */
               data_len = 0;
             };
          };
        };

        /* write data to dump file, if available */
        if (data_len > 0) {
          if (fwrite(data,1,data_len,uu_dump_file) < data_len) {
            /* short write */
            (void)string_format(info, 1024,"short write on uudecode dump file");
            free(line);
            return DEFER;
          };
        };
      };

      if (mime_demux_mode != MIME_DEMUX_MODE_SCANNING) {
        /* Non-scanning and Non-header mode. That means
        we are currently decoding data to the dump
        file. */

        /* Check for a known boundary. */
        tmp = mime_check_boundary(line,boundaries);
        if (tmp == 1) {
          /* We have hit a known start boundary.
          That will put us back in header mode. */
          mime_demux_mode = MIME_DEMUX_MODE_MIME_HEADERS;
          if (mime_dump_file != NULL) {
            /* if the attachment was a RFC822 message, recurse into it */
            if (has_rfc822) {
              has_rfc822 = 0;
              rewind(mime_dump_file);
              mime_demux(mime_dump_file,info);
            };

            (void)fclose(mime_dump_file); mime_dump_file = NULL;
          };
        }
        else if (tmp == 2) {
          /* We have hit a known end boundary.
          That puts us into scanning mode, which will end when we hit another known start boundary */
          mime_demux_mode = MIME_DEMUX_MODE_SCANNING;
          if (mime_dump_file != NULL) {
            /* if the attachment was a RFC822 message, recurse into it */
            if (has_rfc822) {
              has_rfc822 = 0;
              rewind(mime_dump_file);
              mime_demux(mime_dump_file,info);
            };

            (void)fclose(mime_dump_file); mime_dump_file = NULL;
          };
        }
        else {
          uschar *data;
          long data_len = 0;

          /* decode the line with the appropriate method */
          if (mime_demux_mode == MIME_DEMUX_MODE_PLAIN) {
            /* in plain mode, just dump the line */
            data = line;
            data_len = line_len;
          }
          else if ( (mime_demux_mode == MIME_DEMUX_MODE_QP) || (mime_demux_mode == MIME_DEMUX_MODE_BASE64) ) {
            data_len = mime_decode_line(mime_demux_mode,line,&data,line_len,info);
            if (data_len < 0) {
              /* Error reported from the line decoder. */
              data_len = 0;
            };
          };

          /* write data to dump file */
          if (data_len > 0) {
            if (fwrite(data,1,data_len,mime_dump_file) < data_len) {
              /* short write */
              (void)string_format(info, 1024,"short write on dump file");
              free(line);
              return DEFER;
            };
          };

        };
      }
      else {
        /* Scanning mode. We end up here after a end boundary.
        This will usually be at the end of a message or at
        the end of a MIME container.
        We need to look for another start boundary to get
        back into header mode. */
        if (mime_check_boundary(line,boundaries) == 1) {
          mime_demux_mode = MIME_DEMUX_MODE_MIME_HEADERS;
        };

      };
      /* ------------------------------------------------ */
    };
  };
  /* ----------------------- end demux loop ----------------------- */

  /* close files, they could still be open */
  if (mime_dump_file != NULL)
    (void)fclose(mime_dump_file);
  if (uu_dump_file != NULL)
    (void)fclose(uu_dump_file);

  /* release line buffer */
  free(line);

  /* FIXME: release boundary buffers.
  Not too much of a problem since
  this instance of exim is not resident. */

  if (has_tnef) {
    uschar file_name[1024];
    /* at least one file could be TNEF encoded.
    attempt to send all decoded files thru the TNEF decoder */

    (void)string_format(file_name,1024,"%s/scan/%s",spool_directory,message_id);
    /* Removed FTTB. We need to decide on TNEF inclusion */
    /* mime_unpack_tnef(file_name); */
  };

  return 0;
}

#endif
