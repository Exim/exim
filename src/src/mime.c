/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004 */
/* License: GPL */

#include "exim.h"
#ifdef WITH_CONTENT_SCAN	/* entire file */
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

void
mime_set_anomaly(int level, const char *text)
{
  mime_anomaly_level = level;
  mime_anomaly_text = CUS text;
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

uschar *
mime_decode_qp_char(uschar *qp_p, int *c)
{
uschar *initial_pos = qp_p;

/* advance one char */
qp_p++;

/* Check for two hex digits and decode them */
if (isxdigit(*qp_p) && isxdigit(qp_p[1]))
  {
  /* Do hex conversion */
  *c = (isdigit(*qp_p) ? *qp_p - '0' : toupper(*qp_p) - 'A' + 10) <<4;
  qp_p++;
  *c |= isdigit(*qp_p) ? *qp_p - '0' : toupper(*qp_p) - 'A' + 10;
  return qp_p + 1;
  }

/* tab or whitespace may follow just ignore it if it precedes \n */
while (*qp_p == '\t' || *qp_p == ' ' || *qp_p == '\r')
  qp_p++;

if (*qp_p == '\n')	/* hit soft line break */
  {
  *c = -1;
  return qp_p;
  }

/* illegal char here */
*c = -2;
return initial_pos;
}


/* just dump MIME part without any decoding */
static ssize_t
mime_decode_asis(FILE* in, FILE* out, uschar* boundary)
{
  ssize_t len, size = 0;
  uschar buffer[MIME_MAX_LINE_LENGTH];

  while(fgets(CS buffer, MIME_MAX_LINE_LENGTH, mime_stream) != NULL)
    {
    if (boundary != NULL
       && Ustrncmp(buffer, "--", 2) == 0
       && Ustrncmp((buffer+2), boundary, Ustrlen(boundary)) == 0
       )
      break;

    len = Ustrlen(buffer);
    if (fwrite(buffer, 1, (size_t)len, out) < len)
      return -1;
    size += len;
    } /* while */
  return size;
}


/* decode base64 MIME part */
static ssize_t
mime_decode_base64(FILE* in, FILE* out, uschar* boundary)
{
  uschar ibuf[MIME_MAX_LINE_LENGTH], obuf[MIME_MAX_LINE_LENGTH];
  uschar *ipos, *opos;
  ssize_t len, size = 0;
  int bytestate = 0;

  opos = obuf;

  while (Ufgets(ibuf, MIME_MAX_LINE_LENGTH, in) != NULL)
    {
    if (boundary != NULL
       && Ustrncmp(ibuf, "--", 2) == 0
       && Ustrncmp((ibuf+2), boundary, Ustrlen(boundary)) == 0
       )
      break;

    for (ipos = ibuf ; *ipos != '\r' && *ipos != '\n' && *ipos != 0; ++ipos)
      {
      if (*ipos == '=')			/* skip padding */
        {
        ++bytestate;
        continue;
	}
      if (mime_b64[*ipos] == 128)	/* skip bad characters */
        {
        mime_set_anomaly(MIME_ANOMALY_BROKEN_BASE64);
        continue;
	}

      /* simple state-machine */
      switch((bytestate++) & 3)
        {
        case 0:
          *opos = mime_b64[*ipos] << 2;
           break;
        case 1:
          *opos |= mime_b64[*ipos] >> 4;
          ++opos;
          *opos = mime_b64[*ipos] << 4;
          break;
        case 2:
          *opos |= mime_b64[*ipos] >> 2;
          ++opos;
          *opos = mime_b64[*ipos] << 6;
          break;
        case 3:
          *opos |= mime_b64[*ipos];
          ++opos;
          break;
	} /* switch */
      } /* for */

    /* something to write? */
    len = opos - obuf;
    if (len > 0)
      {
      if (fwrite(obuf, 1, len, out) != len) return -1; /* error */
      size += len;
      /* copy incomplete last byte to start of obuf, where we continue */
      if ((bytestate & 3) != 0)
        *obuf = *opos;
      opos = obuf;
      }
    } /* while */

  /* write out last byte if it was incomplete */
  if (bytestate & 3)
    {
    if (fwrite(obuf, 1, 1, out) != 1) return -1;
    ++size;
    }

  return size;
}


/* decode quoted-printable MIME part */
static ssize_t
mime_decode_qp(FILE* in, FILE* out, uschar* boundary)
{
uschar ibuf[MIME_MAX_LINE_LENGTH], obuf[MIME_MAX_LINE_LENGTH];
uschar *ipos, *opos;
ssize_t len, size = 0;

while (fgets(CS ibuf, MIME_MAX_LINE_LENGTH, in) != NULL)
  {
  if (boundary != NULL
     && Ustrncmp(ibuf, "--", 2) == 0
     && Ustrncmp((ibuf+2), boundary, Ustrlen(boundary)) == 0
     )
    break; /* todo: check for missing boundary */

  ipos = ibuf;
  opos = obuf;

  while (*ipos != 0)
    {
    if (*ipos == '=')
      {
      int decode_qp_result;

      ipos = mime_decode_qp_char(ipos, &decode_qp_result);

      if (decode_qp_result == -2)
	{
	/* Error from decoder. ipos is unchanged. */
	mime_set_anomaly(MIME_ANOMALY_BROKEN_QP);
	*opos = '=';
	++opos;
	++ipos;
	}
      else if (decode_qp_result == -1)
	break;
      else if (decode_qp_result >= 0)
	{
	*opos = decode_qp_result;
	++opos;
	}
      }
    else
      {
      *opos = *ipos;
      ++opos;
      ++ipos;
      }
    }
  /* something to write? */
  len = opos - obuf;
  if (len > 0)
    {
    if (fwrite(obuf, 1, len, out) != len) return -1; /* error */
    size += len;
    }
  }
return size;
}


FILE *
mime_get_decode_file(uschar *pname, uschar *fname)
{
FILE *f = NULL;
uschar *filename;

filename = (uschar *)malloc(2048);

if (pname && fname)
  {
  (void)string_format(filename, 2048, "%s/%s", pname, fname);
  f = modefopen(filename,"wb+",SPOOL_MODE);
  }
else if (!pname)
  f = modefopen(fname,"wb+",SPOOL_MODE);
else if (!fname)
  {
  int file_nr = 0;
  int result = 0;

  /* must find first free sequential filename */
  do
    {
    struct stat mystat;
    (void)string_format(filename, 2048,
      "%s/%s-%05u", pname, message_id, file_nr++);
    /* security break */
    if (file_nr >= 1024)
      break;
    result = stat(CS filename, &mystat);
    } while(result != -1);

  f = modefopen(filename, "wb+", SPOOL_MODE);
  }

/* set expansion variable */
mime_decoded_filename = filename;

return f;
}


int
mime_decode(uschar **listptr)
{
int sep = 0;
uschar *list = *listptr;
uschar *option;
uschar option_buffer[1024];
uschar decode_path[1024];
FILE *decode_file = NULL;
long f_pos = 0;
ssize_t size_counter = 0;
ssize_t (*decode_function)(FILE*, FILE*, uschar*);

if (mime_stream == NULL)
  return FAIL;

f_pos = ftell(mime_stream);

/* build default decode path (will exist since MBOX must be spooled up) */
(void)string_format(decode_path,1024,"%s/scan/%s",spool_directory,message_id);

/* try to find 1st option */
if ((option = string_nextinlist(&list, &sep,
				option_buffer,
				sizeof(option_buffer))) != NULL)
  {
  /* parse 1st option */
  if ( (Ustrcmp(option,"false") == 0) || (Ustrcmp(option,"0") == 0) )
    /* explicitly no decoding */
    return FAIL;

  if (Ustrcmp(option,"default") == 0)
    /* explicit default path + file names */
    goto DEFAULT_PATH;

  if (option[0] == '/')
    {
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
  {
  /* no option? patch default path */
DEFAULT_PATH:
  decode_file = mime_get_decode_file(decode_path, NULL);
  }

if (!decode_file)
  return DEFER;

/* decode according to mime type */
decode_function =
  !mime_content_transfer_encoding
  ? mime_decode_asis	/* no encoding, dump as-is */
  : Ustrcmp(mime_content_transfer_encoding, "base64") == 0
  ? mime_decode_base64
  : Ustrcmp(mime_content_transfer_encoding, "quoted-printable") == 0
  ? mime_decode_qp
  : mime_decode_asis;	/* unknown encoding type, just dump as-is */

size_counter = decode_function(mime_stream, decode_file, mime_current_boundary);

clearerr(mime_stream);
fseek(mime_stream, f_pos, SEEK_SET);

if (fclose(decode_file) != 0 || size_counter < 0)
  return DEFER;

/* round up to the next KiB */
mime_content_size = (size_counter + 1023) / 1024;

return OK;
}

int
mime_get_header(FILE *f, uschar *header)
{
int c = EOF;
int done = 0;
int header_value_mode = 0;
int header_open_brackets = 0;
int num_copied = 0;

while(!done)
  {
  if ((c = fgetc(f)) == EOF) break;

  /* always skip CRs */
  if (c == '\r') continue;

  if (c == '\n')
    {
    if (num_copied > 0)
      {
      /* look if next char is '\t' or ' ' */
      if ((c = fgetc(f)) == EOF) break;
      if ( (c == '\t') || (c == ' ') ) continue;
      (void)ungetc(c,f);
      }
    /* end of the header, terminate with ';' */
    c = ';';
    done = 1;
    }

  /* skip control characters */
  if (c < 32) continue;

  if (header_value_mode)
    {
    /* --------- value mode ----------- */
    /* skip leading whitespace */
    if ( ((c == '\t') || (c == ' ')) && (header_value_mode == 1) )
      continue;

      /* we have hit a non-whitespace char, start copying value data */
      header_value_mode = 2;

      if (c == '"')       /* flip "quoted" mode */
        header_value_mode = header_value_mode==2 ? 3 : 2;

      /* leave value mode on unquoted ';' */
      if (header_value_mode == 2 && c == ';') {
        header_value_mode = 0;
      };
      /* -------------------------------- */
    }
  else
    {
    /* -------- non-value mode -------- */
    /* skip whitespace + tabs */
    if ( (c == ' ') || (c == '\t') )
      continue;
    if (c == '\\')
      {
      /* quote next char. can be used
      to escape brackets. */
      if ((c = fgetc(f)) == EOF) break;
      }
    else if (c == '(')
      {
      header_open_brackets++;
      continue;
      }
    else if ((c == ')') && header_open_brackets)
      {
      header_open_brackets--;
      continue;
      }
    else if ( (c == '=') && !header_open_brackets ) /* enter value mode */
      header_value_mode = 1;

    /* skip chars while we are in a comment */
    if (header_open_brackets > 0)
      continue;
    /* -------------------------------- */
    }

  /* copy the char to the buffer */
  header[num_copied++] = (uschar)c;

  /* break if header buffer is full */
  if (num_copied > MIME_MAX_HEADER_SIZE-1)
    done = 1;
  }

if ((num_copied > 0) && (header[num_copied-1] != ';'))
  header[num_copied-1] = ';';

/* 0-terminate */
header[num_copied] = '\0';

/* return 0 for EOF or empty line */
if ((c == EOF) || (num_copied == 1))
  return 0;
else
  return 1;
}


int
mime_acl_check(uschar *acl, FILE *f, struct mime_boundary_context *context,
                   uschar **user_msgptr, uschar **log_msgptr)
{
int rc = OK;
uschar *header = NULL;
struct mime_boundary_context nested_context;

/* reserve a line buffer to work in */
if (!(header = (uschar *)malloc(MIME_MAX_HEADER_SIZE+1)))
  {
  log_write(0, LOG_PANIC,
       "MIME ACL: can't allocate %d bytes of memory.", MIME_MAX_HEADER_SIZE+1);
  return DEFER;
  }

/* Not actually used at the moment, but will be vital to fixing
 * some RFC 2046 nonconformance later... */
nested_context.parent = context;

/* loop through parts */
while(1)
  {
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
  if (context != NULL)
    {
    while(fgets(CS header, MIME_MAX_HEADER_SIZE, f))
      {
      /* boundary line must start with 2 dashes */
      if (  Ustrncmp(header, "--", 2) == 0
	 && Ustrncmp(header+2, context->boundary, Ustrlen(context->boundary)) == 0)
	{
	/* found boundary */
	if (Ustrncmp((header+2+Ustrlen(context->boundary)), "--", 2) == 0)
	  {
	  /* END boundary found */
	  debug_printf("End boundary found %s\n", context->boundary);
	  return rc;
	  }
	else
	  debug_printf("Next part with boundary %s\n", context->boundary);

	/* can't use break here */
	goto DECODE_HEADERS;
	}
      }
    /* Hit EOF or read error. Ugh. */
    debug_printf("Hit EOF ...\n");
    return rc;
    }

DECODE_HEADERS:
  /* parse headers, set up expansion variables */
  while (mime_get_header(f, header))
    {
    int i;
    /* loop through header list */
    for (i = 0; i < mime_header_list_size; i++)
      if (strncmpic(mime_header_list[i].name,
	    header, mime_header_list[i].namelen) == 0)
	{				/* found an interesting header */
	uschar * header_value;
	int header_value_len;
	uschar * p = header + mime_header_list[i].namelen;

	/* grab the value (normalize to lower case)
	and copy to its corresponding expansion variable */
	while(*p != ';')
	  {
	  *p = tolower(*p);
	  p++;
	  }
	header_value_len = p - (header + mime_header_list[i].namelen);
	p = header + mime_header_list[i].namelen;
	header_value = string_copyn(p, header_value_len);
	debug_printf("Found %s MIME header, value is '%s'\n",
			mime_header_list[i].name, header_value);
	*((uschar **)(mime_header_list[i].value)) = header_value;

	/* make p point to the next character after the closing ';' */
	p += header_value_len+1;

	/* grab all param=value tags on the remaining line,
	check if they are interesting */
NEXT_PARAM_SEARCH:
	while (*p)
	  {
	  mime_parameter * mp;
	  for (mp = mime_parameter_list;
	       mp < &mime_parameter_list[mime_parameter_list_size];
	       mp++)
	    {
	    uschar * param_value = NULL;

	    /* found an interesting parameter? */
	    if (strncmpic(mp->name, p, mp->namelen) == 0)
	      {
	      int size = 0;
	      int ptr = 0;

	      /* yes, grab the value and copy to its corresponding expansion variable */
	      p += mp->namelen;
	      while(*p && *p != ';')		/* ; terminates */
		if (*p == '"')
		  {
		  p++;				/* skip leading " */
		  while(*p && *p != '"')	/* " protects ; */
		    param_value = string_cat(param_value, &size, &ptr, p++, 1);
		  if (*p) p++;			/* skip trailing " */
		  }
		else
		  param_value = string_cat(param_value, &size, &ptr, p++, 1);
	      if (*p) p++;			/* skip trailing ; */

	      if (param_value)
		{
		uschar * dummy;
		param_value[ptr++] = '\0';

		param_value = rfc2047_decode(param_value,
		      check_rfc2047_length, NULL, 32, NULL, &dummy);
		debug_printf("Found %s MIME parameter in %s header, "
		      "value is '%s'\n", mp->name, mime_header_list[i].name,
		      param_value);
		}
	      *mp->value = param_value;
	      goto NEXT_PARAM_SEARCH;
	    }
	  }
	  /* There is something, but not one of our interesting parameters.
	     Advance to the next semicolon */
	  while(*p != ';')
	    {
	    if (*p == '"') while(*++p && *p != '"') ;
	    p++;
	    }
	  p++;
	}
      }
  }

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
  rc = acl_check(ACL_WHERE_MIME, NULL, acl, user_msgptr, log_msgptr);

  mime_stream = NULL;
  mime_current_boundary = NULL;

  if (rc != OK) break;

  /* If we have a multipart entity and a boundary, go recursive */
  if ( (mime_content_type != NULL) &&
       (nested_context.boundary != NULL) &&
       (Ustrncmp(mime_content_type,"multipart",9) == 0) )
    {
    debug_printf("Entering multipart recursion, boundary '%s'\n", nested_context.boundary);

    nested_context.context =
      context && context->context == MBC_ATTACHMENT
      ? MBC_ATTACHMENT
      :    Ustrcmp(mime_content_type,"multipart/alternative") == 0
	|| Ustrcmp(mime_content_type,"multipart/related") == 0
      ? MBC_COVERLETTER_ALL
      : MBC_COVERLETTER_ONESHOT;

    rc = mime_acl_check(acl, f, &nested_context, user_msgptr, log_msgptr);
    if (rc != OK) break;
    }
  else if ( (mime_content_type != NULL) &&
	  (Ustrncmp(mime_content_type,"message/rfc822",14) == 0) )
    {
    uschar *rfc822name = NULL;
    uschar filename[2048];
    int file_nr = 0;
    int result = 0;

    /* must find first free sequential filename */
    do
      {
      struct stat mystat;
      (void)string_format(filename, 2048,
	"%s/scan/%s/__rfc822_%05u", spool_directory, message_id, file_nr++);
      /* security break */
      if (file_nr >= 128)
	goto NO_RFC822;
      result = stat(CS filename,&mystat);
      } while (result != -1);

    rfc822name = filename;

    /* decode RFC822 attachment */
    mime_decoded_filename = NULL;
    mime_stream = f;
    mime_current_boundary = context ? context->boundary : NULL;
    mime_decode(&rfc822name);
    mime_stream = NULL;
    mime_current_boundary = NULL;
    if (!mime_decoded_filename)		/* decoding failed */
      {
      log_write(0, LOG_MAIN,
	   "mime_regex acl condition warning - could not decode RFC822 MIME part to file.");
      return DEFER;
      }
    mime_decoded_filename = NULL;
    }

NO_RFC822:
  /* If the boundary of this instance is NULL, we are finished here */
  if (context == NULL) break;

  if (context->context == MBC_COVERLETTER_ONESHOT)
    context->context = MBC_ATTACHMENT;
  }

return rc;
}

#endif	/*WITH_CONTENT_SCAN*/

/* vi: sw ai sw=2
*/
