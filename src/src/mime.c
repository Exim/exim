/* $Cambridge: exim/src/src/mime.c,v 1.3 2004/12/17 14:52:44 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004 */
/* License: GPL */

#include "exim.h"
#ifdef WITH_CONTENT_SCAN
#include "mime.h"
#include <sys/stat.h>

FILE *mime_stream = NULL;
uschar *mime_current_boundary = NULL;

/*************************************************
* set MIME anomaly level + text                  *
*************************************************/

/* Small wrapper to set the two expandables which
   give info on detected "problems" in MIME
   encodings. Those are defined in mime.h. */

void mime_set_anomaly(int level, char *text) {
  mime_anomaly_level = level;
  mime_anomaly_text = US text;
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

unsigned int mime_qp_hstr_i(uschar *cptr) {
  unsigned int i, j = 0;
  while (cptr && *cptr && isxdigit(*cptr)) {
    i = *cptr++ - '0';
    if (9 < i) i -= 7;
    j <<= 4;
    j |= (i & 0x0f);
  }
  return(j);
}

uschar *mime_decode_qp_char(uschar *qp_p,int *c) {
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
      *c = mime_qp_hstr_i(hex);
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


uschar *mime_parse_line(uschar *buffer, uschar *encoding, int *num_decoded) {
  uschar *data = NULL;

  data = (uschar *)malloc(Ustrlen(buffer)+2);

  if (encoding == NULL) {
    /* no encoding type at all */
    NO_DECODING:
    memcpy(data, buffer, Ustrlen(buffer));
    data[(Ustrlen(buffer))] = 0;
    *num_decoded = Ustrlen(data);
    return data;
  }
  else if (Ustrcmp(encoding,"base64") == 0) {
    uschar *p = buffer;
    int offset = 0;
    
    /* ----- BASE64 ---------------------------------------------------- */
    /* NULL out '\r' and '\n' chars */
    while (Ustrrchr(p,'\r') != NULL) {
      *(Ustrrchr(p,'\r')) = '\0';
    };
    while (Ustrrchr(p,'\n') != NULL) {
      *(Ustrrchr(p,'\n')) = '\0';
    };

    while (*(p+offset) != '\0') {
      /* hit illegal char ? */
      if (mime_b64[*(p+offset)] == 128) {
        mime_set_anomaly(MIME_ANOMALY_BROKEN_BASE64);
        offset++;
      }
      else {
        *p = mime_b64[*(p+offset)];
        p++;
      };
    };
    *p = 255;
   
    /* line is translated, start bit shifting */
    p = buffer;
    *num_decoded = 0;  
    while(*p != 255) {
      uschar tmp_c;
      
      /* byte 0 ---------------------- */
      if (*(p+1) == 255) {
        mime_set_anomaly(MIME_ANOMALY_BROKEN_BASE64);
        break;
      }
      data[(*num_decoded)] = *p;
      data[(*num_decoded)] <<= 2;
      tmp_c = *(p+1);
      tmp_c >>= 4;
      data[(*num_decoded)] |= tmp_c;
      (*num_decoded)++;
      p++;
      /* byte 1 ---------------------- */
      if (*(p+1) == 255) {
        mime_set_anomaly(MIME_ANOMALY_BROKEN_BASE64);
        break;
      }
      data[(*num_decoded)] = *p;
      data[(*num_decoded)] <<= 4;
      tmp_c = *(p+1);
      tmp_c >>= 2;
      data[(*num_decoded)] |= tmp_c;
      (*num_decoded)++;
      p++;
      /* byte 2 ---------------------- */
      if (*(p+1) == 255) {
        mime_set_anomaly(MIME_ANOMALY_BROKEN_BASE64);
        break;
      }
      data[(*num_decoded)] = *p;
      data[(*num_decoded)] <<= 6;
      data[(*num_decoded)] |= *(p+1); 
      (*num_decoded)++;
      p+=2;
      
    };
    return data;
    /* ----------------------------------------------------------------- */
  }
  else if (Ustrcmp(encoding,"quoted-printable") == 0) {
    uschar *p = buffer;

    /* ----- QP -------------------------------------------------------- */
    *num_decoded = 0;
    while (*p != 0) {
      if (*p == '=') {
        int decode_qp_result;
        
        p = mime_decode_qp_char(p,&decode_qp_result);
              
        if (decode_qp_result == -2) {
          /* Error from decoder. p is unchanged. */
          mime_set_anomaly(MIME_ANOMALY_BROKEN_QP);
          data[(*num_decoded)] = '=';
          (*num_decoded)++;
          p++;
        }
        else if (decode_qp_result == -1) {
          break;
        }
        else if (decode_qp_result >= 0) {
          data[(*num_decoded)] = decode_qp_result;
          (*num_decoded)++;
        };
      }
      else {
        data[(*num_decoded)] = *p;
        (*num_decoded)++;
        p++;
      };
    };
    return data;
    /* ----------------------------------------------------------------- */
  }
  /* unknown encoding type, just dump as-is */
  else goto NO_DECODING;
}


FILE *mime_get_decode_file(uschar *pname, uschar *fname) {
  FILE *f = NULL;
  uschar *filename;
  
  filename = (uschar *)malloc(2048);
  
  if ((pname != NULL) && (fname != NULL)) {
    snprintf(CS filename, 2048, "%s/%s", pname, fname);
    f = fopen(CS filename,"w+");
  }
  else if (pname == NULL) {
    f = fopen(CS fname,"w+");
  }
  else if (fname == NULL) {
    int file_nr = 0;
    int result = 0;

    /* must find first free sequential filename */
    do {
      struct stat mystat;
      snprintf(CS filename,2048,"%s/%s-%05u", pname, message_id, file_nr);
      file_nr++;
      /* security break */
      if (file_nr >= 1024)
        break;
      result = stat(CS filename,&mystat);
    }
    while(result != -1);
    f = fopen(CS filename,"w+");
  };
  
  /* set expansion variable */
  mime_decoded_filename = filename;
  
  return f;
}


int mime_decode(uschar **listptr) {
  int sep = 0;
  uschar *list = *listptr;
  uschar *option;
  uschar option_buffer[1024];
  uschar decode_path[1024];
  FILE *decode_file = NULL;
  uschar *buffer = NULL;
  long f_pos = 0;
  unsigned int size_counter = 0;

  if (mime_stream == NULL)
    return FAIL;
  
  f_pos = ftell(mime_stream);
  
  /* build default decode path (will exist since MBOX must be spooled up) */
  snprintf(CS decode_path,1024,"%s/scan/%s",spool_directory,message_id);
  
  /* reserve a line buffer to work in */
  buffer = (uschar *)malloc(MIME_MAX_LINE_LENGTH+1);
  if (buffer == NULL) {
    log_write(0, LOG_PANIC,
                 "decode ACL condition: can't allocate %d bytes of memory.", MIME_MAX_LINE_LENGTH+1);
    return DEFER;
  };
  
  /* try to find 1st option */
  if ((option = string_nextinlist(&list, &sep,
                                  option_buffer,
                                  sizeof(option_buffer))) != NULL) {
    
    /* parse 1st option */
    if ( (Ustrcmp(option,"false") == 0) || (Ustrcmp(option,"0") == 0) ) {
      /* explicitly no decoding */
      return FAIL;
    };
    
    if (Ustrcmp(option,"default") == 0) {
      /* explicit default path + file names */
      goto DEFAULT_PATH;
    };
    
    if (option[0] == '/') {
      struct stat statbuf;

      memset(&statbuf,0,sizeof(statbuf));
      
      /* assume either path or path+file name */
      if ( (stat(CS option, &statbuf) == 0) && S_ISDIR(statbuf.st_mode) )
        /* is directory, use it as decode_path */
        decode_file = mime_get_decode_file(option, NULL);
      else
        /* does not exist or is a file, use as full file name */
        decode_file = mime_get_decode_file(NULL, option);
    }
    else
      /* assume file name only, use default path */
      decode_file = mime_get_decode_file(decode_path, option);
  }
  else
    /* no option? patch default path */
    DEFAULT_PATH: decode_file = mime_get_decode_file(decode_path, NULL);
  
  if (decode_file == NULL)
    return DEFER;
  
  /* read data linewise and dump it to the file,
     while looking for the current boundary */
  while(fgets(CS buffer, MIME_MAX_LINE_LENGTH, mime_stream) != NULL) {
    uschar *decoded_line = NULL;
    int decoded_line_length = 0;
    
    if (mime_current_boundary != NULL) {
      /* boundary line must start with 2 dashes */
      if (Ustrncmp(buffer,"--",2) == 0) {
        if (Ustrncmp((buffer+2),mime_current_boundary,Ustrlen(mime_current_boundary)) == 0)
          break;
      };
    };
  
    decoded_line = mime_parse_line(buffer, mime_content_transfer_encoding, &decoded_line_length);
    /* write line to decode file */
    if (fwrite(decoded_line, 1, decoded_line_length, decode_file) < decoded_line_length) {
      /* error/short write */
      clearerr(mime_stream);
      fseek(mime_stream,f_pos,SEEK_SET);
      return DEFER;
    };
    size_counter += decoded_line_length;
    
    if (size_counter > 1023) { 
      if ((mime_content_size + (size_counter / 1024)) < 65535)
        mime_content_size += (size_counter / 1024);
      else 
        mime_content_size = 65535;
      size_counter = (size_counter % 1024);
    };
    
    free(decoded_line);
  }
  
  fclose(decode_file);
  
  clearerr(mime_stream);
  fseek(mime_stream,f_pos,SEEK_SET);
  
  /* round up remaining size bytes to one k */
  if (size_counter) {
    mime_content_size++;
  };
  
  return OK;
}

int mime_get_header(FILE *f, uschar *header) {
  int c = EOF;
  int done = 0;
  int header_value_mode = 0;
  int header_open_brackets = 0;
  int num_copied = 0;
  
  while(!done) {
    
    c = fgetc(f);
    if (c == EOF) break;
   
    /* always skip CRs */
    if (c == '\r') continue;
    
    if (c == '\n') {
      if (num_copied > 0) {
        /* look if next char is '\t' or ' ' */
        c = fgetc(f);
        if (c == EOF) break;
        if ( (c == '\t') || (c == ' ') ) continue;
        ungetc(c,f);
      };
      /* end of the header, terminate with ';' */
      c = ';';
      done = 1;
    };
  
    /* skip control characters */
    if (c < 32) continue;

    if (header_value_mode) {
      /* --------- value mode ----------- */
      /* skip leading whitespace */
      if ( ((c == '\t') || (c == ' ')) && (header_value_mode == 1) )
        continue;
      
      /* we have hit a non-whitespace char, start copying value data */
      header_value_mode = 2;
      
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
      /* skip whitespace + tabs */
      if ( (c == ' ') || (c == '\t') )
        continue;
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
    
    /* copy the char to the buffer */
    header[num_copied] = (uschar)c;
    /* raise counter */
    num_copied++;
    
    /* break if header buffer is full */
    if (num_copied > MIME_MAX_HEADER_SIZE-1) {
      done = 1;
    };
  };

  if (header[num_copied-1] != ';') {
    header[num_copied-1] = ';';
  };

  /* 0-terminate */
  header[num_copied] = '\0';
  
  /* return 0 for EOF or empty line */
  if ((c == EOF) || (num_copied == 1))
    return 0;
  else
    return 1;
}


int mime_acl_check(FILE *f, struct mime_boundary_context *context, uschar 
                   **user_msgptr, uschar **log_msgptr) {
  int rc = OK;
  uschar *header = NULL;
  struct mime_boundary_context nested_context;

  /* reserve a line buffer to work in */
  header = (uschar *)malloc(MIME_MAX_HEADER_SIZE+1);
  if (header == NULL) {
    log_write(0, LOG_PANIC,
                 "acl_smtp_mime: can't allocate %d bytes of memory.", MIME_MAX_HEADER_SIZE+1);
    return DEFER;
  };

  /* Not actually used at the moment, but will be vital to fixing
   * some RFC 2046 nonconformance later... */
  nested_context.parent = context;

  /* loop through parts */
  while(1) {
  
    /* reset all per-part mime variables */
    mime_anomaly_level     = 0;
    mime_anomaly_text      = NULL;
    mime_boundary          = NULL;
    mime_charset           = NULL;
    mime_decoded_filename  = NULL;
    mime_filename          = NULL;
    mime_content_description = NULL;
    mime_content_disposition = NULL;
    mime_content_id        = NULL;
    mime_content_transfer_encoding = NULL;
    mime_content_type      = NULL;
    mime_is_multipart      = 0;
    mime_content_size      = 0;
  
    /*
    If boundary is null, we assume that *f is positioned on the start of headers (for example,
    at the very beginning of a message.
    If a boundary is given, we must first advance to it to reach the start of the next header
    block.
    */
    
    /* NOTE -- there's an error here -- RFC2046 specifically says to
     * check for outer boundaries.  This code doesn't do that, and
     * I haven't fixed this.
     *
     * (I have moved partway towards adding support, however, by adding 
     * a "parent" field to my new boundary-context structure.)
     */
    if (context != NULL) {
      while(fgets(CS header, MIME_MAX_HEADER_SIZE, f) != NULL) {
        /* boundary line must start with 2 dashes */
        if (Ustrncmp(header,"--",2) == 0) {
          if (Ustrncmp((header+2),context->boundary,Ustrlen(context->boundary)) == 0) {
            /* found boundary */
            if (Ustrncmp((header+2+Ustrlen(context->boundary)),"--",2) == 0) {
              /* END boundary found */
              debug_printf("End boundary found %s\n", context->boundary);
              return rc;
            }
            else {
              debug_printf("Next part with boundary %s\n", context->boundary);
            };
            /* can't use break here */
            goto DECODE_HEADERS;
          }
        };
      }
      /* Hit EOF or read error. Ugh. */
      debug_printf("Hit EOF ...\n");
      return rc;
    };
  
    DECODE_HEADERS:
    /* parse headers, set up expansion variables */
    while(mime_get_header(f,header)) {
      int i;
      /* loop through header list */
      for (i = 0; i < mime_header_list_size; i++) {
        uschar *header_value = NULL;
        int header_value_len = 0;
        
        /* found an interesting header? */
        if (strncmpic(mime_header_list[i].name,header,mime_header_list[i].namelen) == 0) {
          uschar *p = header + mime_header_list[i].namelen;
          /* yes, grab the value (normalize to lower case)
             and copy to its corresponding expansion variable */
          while(*p != ';') {
            *p = tolower(*p);
            p++;
          };
          header_value_len = (p - (header + mime_header_list[i].namelen));
          header_value = (uschar *)malloc(header_value_len+1);
          memset(header_value,0,header_value_len+1);
          p = header + mime_header_list[i].namelen;
          Ustrncpy(header_value, p, header_value_len);
          debug_printf("Found %s MIME header, value is '%s'\n", mime_header_list[i].name, header_value);
          *((uschar **)(mime_header_list[i].value)) = header_value;
          
          /* make p point to the next character after the closing ';' */
          p += (header_value_len+1);
          
          /* grab all param=value tags on the remaining line, check if they are interesting */
          NEXT_PARAM_SEARCH: while (*p != 0) {
            int j;
            for (j = 0; j < mime_parameter_list_size; j++) {
              uschar *param_value = NULL;
              int param_value_len = 0;
              
              /* found an interesting parameter? */
              if (strncmpic(mime_parameter_list[j].name,p,mime_parameter_list[j].namelen) == 0) {
                uschar *q = p + mime_parameter_list[j].namelen;
                /* yes, grab the value and copy to its corresponding expansion variable */
                while(*q != ';') q++;
                param_value_len = (q - (p + mime_parameter_list[j].namelen));
                param_value = (uschar *)malloc(param_value_len+1);
                memset(param_value,0,param_value_len+1);
                q = p + mime_parameter_list[j].namelen;
                Ustrncpy(param_value, q, param_value_len);
                param_value = rfc2047_decode(param_value, TRUE, NULL, 32, &param_value_len, &q);
                debug_printf("Found %s MIME parameter in %s header, value is '%s'\n", mime_parameter_list[j].name, mime_header_list[i].name, param_value);
                *((uschar **)(mime_parameter_list[j].value)) = param_value;
                p += (mime_parameter_list[j].namelen + param_value_len + 1);
                goto NEXT_PARAM_SEARCH;
              };
            }
            /* There is something, but not one of our interesting parameters.
               Advance to the next semicolon */
            while(*p != ';') p++;
            p++;
          };
        };
      };
    };
    
    /* set additional flag variables (easier access) */
    if ( (mime_content_type != NULL) &&
         (Ustrncmp(mime_content_type,"multipart",9) == 0) )
      mime_is_multipart = 1;
    
    /* Make a copy of the boundary pointer.
       Required since mime_boundary is global
       and can be overwritten further down in recursion */
    nested_context.boundary = mime_boundary;
    
    /* raise global counter */
    mime_part_count++;
    
    /* copy current file handle to global variable */
    mime_stream = f;
    mime_current_boundary = context ? context->boundary : 0;

    /* Note the context */
    mime_is_coverletter = !(context && context->context == MBC_ATTACHMENT);
    
    /* call ACL handling function */
    rc = acl_check(ACL_WHERE_MIME, NULL, acl_smtp_mime, user_msgptr, log_msgptr);
    
    mime_stream = NULL;
    mime_current_boundary = NULL;
    
    if (rc != OK) break;
    
    /* If we have a multipart entity and a boundary, go recursive */
    if ( (mime_content_type != NULL) &&
         (nested_context.boundary != NULL) &&
         (Ustrncmp(mime_content_type,"multipart",9) == 0) ) {
      debug_printf("Entering multipart recursion, boundary '%s'\n", nested_context.boundary);

      if (context && context->context == MBC_ATTACHMENT)
        nested_context.context = MBC_ATTACHMENT;
      else if (!Ustrcmp(mime_content_type,"multipart/alternative")
            || !Ustrcmp(mime_content_type,"multipart/related"))
        nested_context.context = MBC_COVERLETTER_ALL;
      else
        nested_context.context = MBC_COVERLETTER_ONESHOT;

      rc = mime_acl_check(f, &nested_context, user_msgptr, log_msgptr);
      if (rc != OK) break;
    }
    else if ( (mime_content_type != NULL) &&
            (Ustrncmp(mime_content_type,"message/rfc822",14) == 0) ) {
      uschar *rfc822name = NULL;
      uschar filename[2048];
      int file_nr = 0;
      int result = 0;
      
      /* must find first free sequential filename */
      do {
        struct stat mystat;
        snprintf(CS filename,2048,"%s/scan/%s/__rfc822_%05u", spool_directory, message_id, file_nr);
        file_nr++;
        /* security break */
        if (file_nr >= 128)
          goto NO_RFC822;
        result = stat(CS filename,&mystat);
      }
      while(result != -1);
      
      rfc822name = filename;
      
      /* decode RFC822 attachment */
      mime_decoded_filename = NULL;
      mime_stream = f;
      mime_current_boundary = context ? context->boundary : NULL;
      mime_decode(&rfc822name);
      mime_stream = NULL;
      mime_current_boundary = NULL;
      if (mime_decoded_filename == NULL) {
        /* decoding failed */
        log_write(0, LOG_MAIN,
             "mime_regex acl condition warning - could not decode RFC822 MIME part to file.");
        return DEFER;
      };
      mime_decoded_filename = NULL;
    };
    
    NO_RFC822:
    /* If the boundary of this instance is NULL, we are finished here */
    if (context == NULL) break;

    if (context->context == MBC_COVERLETTER_ONESHOT)
      context->context = MBC_ATTACHMENT;
  
  };

  return rc;
}

#endif
