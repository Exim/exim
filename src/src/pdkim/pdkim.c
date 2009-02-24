/* $Cambridge: exim/src/src/pdkim/pdkim.c,v 1.1.2.2 2009/02/24 15:57:55 tom Exp $ */
/* pdkim.c */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include "pdkim.h"


/* -------------------------------------------------------------------------- */
/* A bunch of list constants */
char *pdkim_querymethods[] = {
  "dns/txt"
};
char *pdkim_algos[] = {
  "rsa-sha256",
  "rsa-sha1"
};
char *pdkim_canons[] = {
  "simple",
  "relaxed"
};


/* -------------------------------------------------------------------------- */
/* Various debugging functions */
#ifdef PDKIM_DEBUG
void pdkim_quoteprint(FILE *stream, char *data, int len, int lf) {
  int i;
  unsigned char *p = (unsigned char *)data;

  for (i=0;i<len;i++) {
    int c = p[i];
    switch (c) {
      case ' ' : fprintf(stream,"{SP}"); break;
      case '\t': fprintf(stream,"{TB}"); break;
      case '\r': fprintf(stream,"{CR}"); break;
      case '\n': fprintf(stream,"{LF}"); break;
      case '{' : fprintf(stream,"{BO}"); break;
      case '}' : fprintf(stream,"{BC}"); break;
      default:
        if ( (c < 32) || (c > 127) )
          fprintf(stream,"{%02x}",c);
        else
          fputc(c,stream);
      break;
    }
  }
  if (lf)
    fputc('\n',stream);
}
#endif


/* -------------------------------------------------------------------------- */
/* Simple string list implementation for convinience */
pdkim_stringlist *pdkim_append_stringlist(pdkim_stringlist *base, char *str) {
  pdkim_stringlist *new_entry = malloc(sizeof(pdkim_stringlist));
  if (new_entry == NULL) return NULL;
  memset(new_entry,0,sizeof(pdkim_stringlist));
  new_entry->value = malloc(strlen(str)+1);
  if (new_entry->value == NULL) return NULL;
  strcpy(new_entry->value,str);
  if (base != NULL) {
    pdkim_stringlist *last = base;
    while (last->next != NULL) { last = last->next; };
    last->next = new_entry;
    return base;
  }
  else return new_entry;
};


/* -------------------------------------------------------------------------- */
/* A small "growing string" implementation to escape malloc/realloc hell */
pdkim_str *pdkim_strnew (char *cstr) {
  unsigned int len = cstr?strlen(cstr):0;
  pdkim_str *p = malloc(sizeof(pdkim_str));
  if (p == NULL) return NULL;
  memset(p,0,sizeof(pdkim_str));
  p->str = malloc(len+1);
  if (p->str == NULL) {
    free(p);
    return NULL;
  }
  p->allocated=(len+1);
  p->len=len;
  if (cstr) strcpy(p->str,cstr);
  return p;
};
char *pdkim_strcat(pdkim_str *str, char *cstr) {
  return pdkim_strncat(str, cstr, strlen(cstr));
};
char *pdkim_strncat(pdkim_str *str, char *data, int len) {
  if ((str->allocated - str->len) < (len+1)) {
    /* Extend the buffer */
    int num_frags = ((len+1)/PDKIM_STR_ALLOC_FRAG)+1;
    char *n = realloc(str->str,
                      (str->allocated+(num_frags*PDKIM_STR_ALLOC_FRAG)));
    if (n == NULL) return NULL;
    str->str = n;
    str->allocated += (num_frags*PDKIM_STR_ALLOC_FRAG);
  }
  strncpy(&(str->str[str->len]),data,len);
  str->len+=len;
  str->str[str->len] = '\0';
  return str->str;
};
char *pdkim_numcat(pdkim_str *str, unsigned long num) {
  char minibuf[20];
  snprintf(minibuf,20,"%lu",num);
  return pdkim_strcat(str,minibuf);
};
void pdkim_strfree(pdkim_str *str) {
  if (str == NULL) return;
  if (str->str != NULL) free(str->str);
  free(str);
};


/* -------------------------------------------------------------------------- */
/* Matches the name of the passed raw "header" against
   the passed colon-separated "list". Case-insensitive.
   Returns '0' for a match. */
int header_name_match(char *header,
                      char *list) {
  char *hname;
  char *lcopy;
  char *p;
  char *q;
  int rc = PDKIM_FAIL;
  char *hcolon = strchr(header,':');
  if (hcolon == NULL) return rc; /* This isn't a header */
  hname = malloc((hcolon-header)+1);
  if (hname == NULL) return PDKIM_ERR_OOM;
  memset(hname,0,(hcolon-header)+1);
  strncpy(hname,header,(hcolon-header));
  lcopy = malloc(strlen(list)+1);
  if (lcopy == NULL) {
    free(hname);
    return PDKIM_ERR_OOM;
  }
  strcpy(lcopy,list);
  p = lcopy;
  q = strchr(p,':');
  while (q != NULL) {
    *q = '\0';
    if (strcasecmp(p,hname) == 0) {
      rc = PDKIM_OK;
      goto BAIL;
    }
    p = q+1;
    q = strchr(p,':');
  }
  if (strcasecmp(p,hname) == 0) rc = PDKIM_OK;
  BAIL:
  free(hname);
  free(lcopy);
  return rc;
}


/* -------------------------------------------------------------------------- */
/* Performs "relaxed" canonicalization of a header. The returned pointer needs
   to be free()d. */
char *pdkim_relax_header (char *header, int crlf) {
  int past_field_name = 0;
  int seen_wsp = 0;
  char *p = header;
  char *q;
  char *relaxed = malloc(strlen(header));
  if (relaxed == NULL) return NULL;
  q = relaxed;
  while (*p != '\0') {
    int c = *p;
    /* Ignore CR & LF */
    if ( (c == '\r') || (c == '\n') ) {
      p++;
      continue;
    }
    if ( (c == '\t') || (c == ' ') ) {
      c = ' '; /* Turns WSP into SP */
      if (seen_wsp) {
        p++;
        continue;
      }
      else seen_wsp = 1;
    }
    else {
      if ( (!past_field_name) && (c == ':') ) {
        if (seen_wsp) q--;   /* This removes WSP before the colon */
        seen_wsp = 1;        /* This removes WSP after the colon */
        past_field_name = 1;
      }
      else seen_wsp = 0;
    }
    /* Lowercase header name */
    if (!past_field_name) c = tolower(c);
    *q = c;
    p++;
    q++;
  }
  *q = '\0';
  if (crlf) strcat(relaxed,"\r\n");
  return relaxed;
};


/* -------------------------------------------------------------------------- */
int pdkim_update_bodyhash(pdkim_ctx *ctx, char *data, int len) {
  pdkim_signature *sig = ctx->sig;
  /* Cache relaxed version of data */
  char *relaxed_data = NULL;
  int   relaxed_len  = 0;

  /* Traverse all signatures, updating their hashes. */
  while (sig != NULL) {
    /* Defaults to simple canon (no further treatment necessary) */
    char *canon_data = data;
    int   canon_len = len;

    if (sig->canon_body == PDKIM_CANON_RELAXED) {
      /* Relax the line if not done already */
      if (relaxed_data == NULL) {
        int seen_wsp = 0;
        char *p = data;
        int q = 0;
        relaxed_data = malloc(len);
        if (relaxed_data == NULL) return PDKIM_ERR_OOM;
        while (*p != '\0') {
          char c = *p;
          if ( (c == '\t') || (c == ' ') ) {
            c = ' '; /* Turns WSP into SP */
            if (seen_wsp) {
              p++;
              continue;
            }
            else seen_wsp = 1;
          }
          else seen_wsp = 0;
          relaxed_data[q++] = c;
          p++;
        }
        relaxed_data[q] = '\0';
        relaxed_len = q;
      }
      canon_data = relaxed_data;
      canon_len  = relaxed_len;
    }

    /* Make sure we don't exceed the to-be-signed body length */
    if (sig->bodylength &&
        ((sig->signed_body_bytes+(unsigned long)canon_len) > sig->bodylength))
      canon_len = (sig->bodylength - sig->signed_body_bytes);

    if (canon_len > 0) {
      if (sig->algo == PDKIM_ALGO_RSA_SHA1)
        sha1_update(&(sig->sha1_body),(unsigned char *)canon_data,canon_len);
      else
        sha2_update(&(sig->sha2_body),(unsigned char *)canon_data,canon_len);
      sig->signed_body_bytes += canon_len;
#ifdef PDKIM_DEBUG
      if (ctx->debug_stream!=NULL)
        pdkim_quoteprint(ctx->debug_stream,canon_data,canon_len,0);
#endif
    }

    sig = sig->next;
  }

  if (relaxed_data != NULL) free(relaxed_data);
  return PDKIM_OK;
};


/* -------------------------------------------------------------------------- */
int pdkim_finish_bodyhash(pdkim_ctx *ctx) {
  pdkim_signature *sig = ctx->sig;

  /* Traverse all signatures */
  while (sig != NULL) {

#ifdef PDKIM_DEBUG
    if (ctx->debug_stream)
      fprintf(ctx->debug_stream, "PDKIM [%s] Body bytes hashed: %lu\n",
              sig->domain, sig->signed_body_bytes);
#endif

    /* Finish hashes */
    unsigned char bh[32]; /* SHA-256 = 32 Bytes,  SHA-1 = 20 Bytes */
    if (sig->algo == PDKIM_ALGO_RSA_SHA1)
      sha1_finish(&(sig->sha1_body),bh);
    else
      sha2_finish(&(sig->sha2_body),bh);

    /* SIGNING -------------------------------------------------------------- */
    if (ctx->mode == PDKIM_MODE_SIGN) {

      /* Build base64 version of body hash and place it in the sig struct */
      int slen = (sig->algo == PDKIM_ALGO_RSA_SHA1)?20:32;
      int dlen = 0;
      base64_encode(NULL,&dlen,bh,slen); /* Puts needed length in dlen */
      sig->bodyhash = malloc(dlen+1);
      if (sig->bodyhash == NULL) return PDKIM_ERR_OOM;
      if (base64_encode((unsigned char *)sig->bodyhash,&dlen,bh,slen) == 0) {
        sig->bodyhash[dlen] = '\0';
#ifdef PDKIM_DEBUG
        if (ctx->debug_stream)
          fprintf(ctx->debug_stream, "PDKIM [%s] body hash: %s\n",
                  sig->domain, sig->bodyhash);
#endif
        return PDKIM_OK;
      }

      /* If bodylength limit is set, and we have received less bytes
         than the requested amount, effectively remove the limit tag. */
      if (sig->signed_body_bytes < sig->bodylength) sig->bodylength = 0;
    }
    /* VERIFICATION --------------------------------------------------------- */
    else {


    }


    sig = sig->next;
  }

  return PDKIM_OK;
};



/* -------------------------------------------------------------------------- */
/* Callback from pdkim_feed below for processing complete body lines */
int pdkim_bodyline_complete(pdkim_ctx *ctx) {
  char *p = ctx->linebuf;
  int   n = ctx->linebuf_offset;

  /* Ignore extra data if we've seen the end-of-data marker */
  if (ctx->seen_eod) goto BAIL;

  /* We've always got one extra byte to stuff a zero ... */
  ctx->linebuf[(ctx->linebuf_offset)] = '\0';

  if (ctx->input_mode == PDKIM_INPUT_SMTP) {
    /* Terminate on EOD marker */
    if (memcmp(p,".\r\n",3) == 0) {
      ctx->seen_eod = 1;
      goto BAIL;
    }
    /* Unstuff dots */
    if (memcmp(p,"..",2) == 0) {
      p++;
      n--;
    }
  }

  /* Empty lines need to be buffered until we find a non-empty line */
  if (memcmp(p,"\r\n",2) == 0) {
    ctx->num_buffered_crlf++;
    goto BAIL;
  }

  /* At this point, we have a non-empty line, so release the buffered ones. */
  while (ctx->num_buffered_crlf) {
    pdkim_update_bodyhash(ctx,"\r\n",2);
    ctx->num_buffered_crlf--;
  }

  pdkim_update_bodyhash(ctx,p,n);

  BAIL:
  ctx->linebuf_offset = 0;
  return PDKIM_OK;
}


/* -------------------------------------------------------------------------- */
/* Callback from pdkim_feed below for processing complete headers */
int pdkim_header_complete(pdkim_ctx *ctx) {
  pdkim_signature *sig = ctx->sig;

  /* Special case: The last header can have an extra \r appended */
  if ( (ctx->cur_header->len > 1) &&
       (ctx->cur_header->str[(ctx->cur_header->len)-1] == '\r') ) {
    ctx->cur_header->str[(ctx->cur_header->len)-1] = '\0';
    ctx->cur_header->len--;
  }

  /* Traverse all signatures */
  while (sig != NULL) {

    /* SIGNING -------------------------------------------------------------- */
    if (ctx->mode == PDKIM_MODE_SIGN) {
      if (header_name_match(ctx->cur_header->str,
                            sig->sign_headers?sig->sign_headers
                                             :PDKIM_DEFAULT_SIGN_HEADERS) == 0) {
        pdkim_stringlist *list = pdkim_append_stringlist(sig->headers,
                                                         ctx->cur_header->str);
        if (list == NULL) return PDKIM_ERR_OOM;
        sig->headers = list;
      }
    }
    /* VERIFICATION --------------------------------------------------------- */
    else {

    }

    sig = sig->next;
  }
  ctx->cur_header->len = 0; /* Re-use existing pdkim_str */
  return PDKIM_OK;
};



/* -------------------------------------------------------------------------- */
#define HEADER_BUFFER_FRAG_SIZE 256
int pdkim_feed (pdkim_ctx *ctx,
                char *data,
                int   len) {
  int p;
  for (p=0;p<len;p++) {
    char c = data[p];
    if (ctx->past_headers) {
      /* Processing body byte */
      ctx->linebuf[(ctx->linebuf_offset)++] = c;
      if (c == '\n') {
        int rc = pdkim_bodyline_complete(ctx); /* End of line */
        if (rc != PDKIM_OK) return rc;
      }
      if (ctx->linebuf_offset == (PDKIM_MAX_BODY_LINE_LEN-1))
        return PDKIM_ERR_LONG_LINE;
    }
    else {
      /* Processing header byte */
      if (c != '\r') {
        if (c == '\n') {
          if (ctx->seen_lf) {
            int rc = pdkim_header_complete(ctx); /* Seen last header line */
            if (rc != PDKIM_OK) return rc;
            ctx->past_headers = 1;
            ctx->seen_lf = 0;
#ifdef PDKIM_DEBUG
            if (ctx->debug_stream)
              fprintf(ctx->debug_stream,
                "PDKIM >> Hashed body data, canonicalized >>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
#endif
            continue;
          }
          else ctx->seen_lf = 1;
        }
        else if (ctx->seen_lf) {
          if (! ((c == '\t') || (c == ' '))) {
            int rc = pdkim_header_complete(ctx); /* End of header */
            if (rc != PDKIM_OK) return rc;
          }
          ctx->seen_lf = 0;
        }
      }
      if (ctx->cur_header == NULL) {
        ctx->cur_header = pdkim_strnew(NULL);
        if (ctx->cur_header == NULL) return PDKIM_ERR_OOM;
      }
      if (pdkim_strncat(ctx->cur_header,&data[p],1) == NULL)
        return PDKIM_ERR_OOM;
    }
  }
  return PDKIM_OK;
};


/* -------------------------------------------------------------------------- */
pdkim_str *pdkim_create_header(pdkim_ctx *ctx, int final) {

  pdkim_str *hdr = pdkim_strnew("DKIM-Signature: v="PDKIM_SIGNATURE_VERSION);
  if (hdr == NULL) return NULL;
  /* Required and static bits */
  if (
        pdkim_strcat(hdr,"; a=")                                     &&
        pdkim_strcat(hdr,pdkim_algos[ctx->sig->algo])                &&
        pdkim_strcat(hdr,"; q=")                                     &&
        pdkim_strcat(hdr,pdkim_querymethods[ctx->sig->querymethod])  &&
        pdkim_strcat(hdr,"; c=")                                     &&
        pdkim_strcat(hdr,pdkim_canons[ctx->sig->canon_headers])      &&
        pdkim_strcat(hdr,"/")                                        &&
        pdkim_strcat(hdr,pdkim_canons[ctx->sig->canon_body])         &&
        pdkim_strcat(hdr,"; d=")                                     &&
        pdkim_strcat(hdr,ctx->sig->domain)                           &&
        pdkim_strcat(hdr,"; s=")                                     &&
        pdkim_strcat(hdr,ctx->sig->selector)                         &&
        pdkim_strcat(hdr,";\r\n\th=")                                &&
        pdkim_strcat(hdr,ctx->sig->headernames)                      &&
        pdkim_strcat(hdr,"; bh=")                                    &&
        pdkim_strcat(hdr,ctx->sig->bodyhash)                         &&
        pdkim_strcat(hdr,";\r\n\t")
     ) {
    /* Optional bits */
    if (ctx->sig->identity != NULL) {
      if (!( pdkim_strcat(hdr,"i=")                                  &&
             pdkim_strcat(hdr,ctx->sig->identity)                    &&
             pdkim_strcat(hdr,";") ) ) {
        return NULL;
      }
    }
    if (ctx->sig->created > 0) {
      if (!( pdkim_strcat(hdr,"t=")                                  &&
             pdkim_numcat(hdr,ctx->sig->created)                     &&
             pdkim_strcat(hdr,";") ) ) {
        return NULL;
      }
    }
    if (ctx->sig->expires > 0) {
      if (!( pdkim_strcat(hdr,"x=")                                  &&
             pdkim_numcat(hdr,ctx->sig->expires)                     &&
             pdkim_strcat(hdr,";") ) ) {
        return NULL;
      }
    }
    if (ctx->sig->bodylength > 0) {
      if (!( pdkim_strcat(hdr,"l=")                                  &&
             pdkim_numcat(hdr,ctx->sig->bodylength)                  &&
             pdkim_strcat(hdr,";") ) ) {
        return NULL;
      }
    }
    /* Extra linebreak */
    if (hdr->str[(hdr->len)-1] == ';') {
      if (!pdkim_strcat(hdr," \r\n\t")) return NULL;
    }
    /* Preliminary or final version? */
    if (final) {
      if (
            pdkim_strcat(hdr,"b=")                                   &&
            pdkim_strcat(hdr,ctx->sig->sigdata)                      &&
            pdkim_strcat(hdr,";")
         ) return hdr;
    }
    else {
      if (pdkim_strcat(hdr,"b=;")) return hdr;
    }
  }
  return NULL;
}


/* -------------------------------------------------------------------------- */
int pdkim_feed_finish(pdkim_ctx *ctx, char **signature) {

  /* Check if we must still flush a (partial) header. If that is the
     case, the message has no body, and we must compute a body hash
     out of '<CR><LF>' */
  if (ctx->cur_header->len) {
    int rc = pdkim_header_complete(ctx);
    if (rc != PDKIM_OK) return rc;
    pdkim_update_bodyhash(ctx,"\r\n",2);
  }
  else {
    /* For non-smtp input, check if there's an unfinished line in the
       body line buffer. If that is the case, we must add a CRLF to the
       hash to properly terminate the message. */
    if ((ctx->input_mode == PDKIM_INPUT_NORMAL) && ctx->linebuf_offset) {
      pdkim_update_bodyhash(ctx, ctx->linebuf, ctx->linebuf_offset);
      pdkim_update_bodyhash(ctx,"\r\n",2);
    }
#ifdef PDKIM_DEBUG
    if (ctx->debug_stream)
      fprintf(ctx->debug_stream,
        "\nPDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
#endif
  }

  if (pdkim_finish_bodyhash(ctx) != PDKIM_OK) return PDKIM_ERR_OOM;

  /* SIGNING ---------------------------------------------------------------- */
  if (ctx->mode == PDKIM_MODE_SIGN) {
    pdkim_stringlist *p;
    pdkim_str *headernames;
    pdkim_str *hdr;
    char *canon_signature;
    unsigned char headerhash[32];
    char *headerhash_base64;
    char *rsa_sig;
    int sigdata_len = 0;
    sha1_context sha1_headers;
    sha2_context sha2_headers;
    rsa_context rsa;
    if (ctx->sig->algo == PDKIM_ALGO_RSA_SHA1) sha1_starts(&sha1_headers);
    else sha2_starts(&sha2_headers,0);
    /* Run through the accumulated list of to-be-signed headers */
#ifdef PDKIM_DEBUG
    if (ctx->debug_stream)
      fprintf(ctx->debug_stream,
              "PDKIM >> Hashed header data, canonicalized, in sequence >>>>>>>>>>>>>>\n");
#endif
    headernames = pdkim_strnew(NULL);
    p = ctx->sig->headers;
    while (p != NULL) {
      char *rh = p->value;
      /* Collect header names (Note: colon presence is guaranteed here) */
      char *q = strchr(p->value,':');
      if (pdkim_strncat(headernames, p->value,
                        (q-(p->value))+((p->next==NULL)?0:1)) == NULL)
        return PDKIM_ERR_OOM;
      /* Cook the header if using relaxed canon */
      if (ctx->sig->canon_body == PDKIM_CANON_RELAXED) {
        rh = pdkim_relax_header(p->value,1);
        if (rh == NULL) return PDKIM_ERR_OOM;
      }
      /* Feed header to the hash algorithm */
      if (ctx->sig->algo == PDKIM_ALGO_RSA_SHA1)
        sha1_update(&(sha1_headers),(unsigned char *)rh,strlen(rh));
      else
        sha2_update(&(sha2_headers),(unsigned char *)rh,strlen(rh));
#ifdef PDKIM_DEBUG
      if (ctx->debug_stream)
        pdkim_quoteprint(ctx->debug_stream, rh, strlen(rh), 1);
#endif
      p = p->next;
    }

#ifdef PDKIM_DEBUG
    if (ctx->debug_stream)
      fprintf(ctx->debug_stream,
              "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
#endif

    /* Copy headernames to signature struct */
    ctx->sig->headernames = malloc((headernames->len)+1);
    if (ctx->sig->headernames == NULL) return PDKIM_ERR_OOM;
    strcpy(ctx->sig->headernames, headernames->str);
    pdkim_strfree(headernames);

    /* Create signature header with b= omitted */
    hdr = pdkim_create_header(ctx,0);
    if (hdr == NULL) return PDKIM_ERR_OOM;

    /* If necessary, perform relaxed canon */
    canon_signature = hdr->str;
    if (ctx->sig->canon_headers == PDKIM_CANON_RELAXED) {
      canon_signature = pdkim_relax_header(canon_signature,0);
      if (canon_signature == NULL) return PDKIM_ERR_OOM;
    }

#ifdef PDKIM_DEBUG
  if (ctx->debug_stream) {
    fprintf(ctx->debug_stream,
            "PDKIM >> Signed DKIM-Signature header, canonicalized >>>>>>>>>>>>>>>>>\n");
    pdkim_quoteprint(ctx->debug_stream, canon_signature, strlen(canon_signature), 1);
    fprintf(ctx->debug_stream,
            "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
  }
#endif

    /* Feed preliminary signature header to the hash algorithm */
    if (ctx->sig->algo == PDKIM_ALGO_RSA_SHA1) {
      int dlen = 0;
      sha1_update(&(sha1_headers),(unsigned char *)canon_signature,strlen(canon_signature));
      sha1_finish(&(sha1_headers),headerhash);
      base64_encode(NULL,&dlen,headerhash,20);
      headerhash_base64 = malloc(dlen+1);
      if (headerhash == NULL) return PDKIM_ERR_OOM;
      base64_encode((unsigned char *)headerhash_base64,&dlen,headerhash,20);
      headerhash_base64[dlen] = '\0';
#ifdef PDKIM_DEBUG
      if (ctx->debug_stream)
        fprintf(ctx->debug_stream,
          "PDKIM SHA1 header hash: %s\n",headerhash_base64);
#endif
    }
    else {
      int dlen = 0;
      sha2_update(&(sha2_headers),(unsigned char *)canon_signature,strlen(canon_signature));
      sha2_finish(&(sha2_headers),headerhash);
      base64_encode(NULL,&dlen,headerhash,32);
      headerhash_base64 = malloc(dlen+1);
      if (headerhash == NULL) return PDKIM_ERR_OOM;
      base64_encode((unsigned char *)headerhash_base64,&dlen,headerhash,32);
      headerhash_base64[dlen] = '\0';
#ifdef PDKIM_DEBUG
      if (ctx->debug_stream)
        fprintf(ctx->debug_stream,
          "PDKIM SHA256 header hash: %s\n",headerhash_base64);
#endif
    }

    if (rsa_parse_key(&rsa, (unsigned char *)ctx->sig->rsa_privkey,
                      strlen(ctx->sig->rsa_privkey), NULL, 0) != 0) {
      return PDKIM_ERR_RSA_PRIVKEY;
    }

    rsa_sig = malloc(mpi_size(&(rsa.N)));
    if (rsa_sig == NULL) return PDKIM_ERR_OOM;

    if (rsa_pkcs1_sign( &rsa, RSA_PRIVATE,
                        ((ctx->sig->algo == PDKIM_ALGO_RSA_SHA1)?
                           RSA_SHA1
                           :
                           RSA_SHA256
                        ),
                        0, headerhash, (unsigned char *)rsa_sig ) != 0) {
      return PDKIM_ERR_RSA_SIGNING;
    }

    base64_encode(NULL,&sigdata_len,(unsigned char *)rsa_sig,mpi_size(&(rsa.N)));
    ctx->sig->sigdata = malloc(sigdata_len+1);
    if (ctx->sig->sigdata == NULL) return PDKIM_ERR_OOM;
    base64_encode((unsigned char *)ctx->sig->sigdata,
                  &sigdata_len,
                  (unsigned char *)rsa_sig,
                  mpi_size(&(rsa.N)));
    ctx->sig->sigdata[sigdata_len] = '\0';

#ifdef PDKIM_DEBUG
    if (ctx->debug_stream)
      fprintf(ctx->debug_stream,
        "PDKIM RSA-signed hash: %s\n",ctx->sig->sigdata);
#endif

    /* Recreate signature header with b= included */
    pdkim_strfree(hdr);
    hdr = pdkim_create_header(ctx,1);
    if (hdr == NULL) return PDKIM_ERR_OOM;

#ifdef PDKIM_DEBUG
    if (ctx->debug_stream) {
      fprintf(ctx->debug_stream,
              "PDKIM >> Final DKIM-Signature header >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
      pdkim_quoteprint(ctx->debug_stream, hdr->str, hdr->len, 1);
      fprintf(ctx->debug_stream,
              "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    }
#endif

    if (signature != NULL) {
      *signature = hdr->str;
    }

  }


  return PDKIM_OK;
}


/* -------------------------------------------------------------------------- */
pdkim_ctx *pdkim_init_sign(char *domain,
                           char *selector,
                           char *rsa_privkey) {
  pdkim_ctx *ctx;

  if (!domain || !selector || !rsa_privkey) return NULL;

  ctx = malloc(sizeof(pdkim_ctx));
  if (ctx == NULL) return NULL;
  memset(ctx,0,sizeof(pdkim_ctx));
  pdkim_signature *sig = malloc(sizeof(pdkim_signature));
  if (sig == NULL) {
    free(ctx);
    return NULL;
  }
  memset(sig,0,sizeof(pdkim_signature));

  ctx->mode = PDKIM_MODE_SIGN;
  ctx->sig = sig;

  ctx->sig->domain = malloc(strlen(domain)+1);
  ctx->sig->selector = malloc(strlen(selector)+1);
  ctx->sig->rsa_privkey = malloc(strlen(rsa_privkey)+1);

  if (!ctx->sig->domain || !ctx->sig->selector || !ctx->sig->rsa_privkey) {
    pdkim_free_ctx(ctx);
    return NULL;
  }

  strcpy(ctx->sig->domain, domain);
  strcpy(ctx->sig->selector, selector);
  strcpy(ctx->sig->rsa_privkey, rsa_privkey);

  sha1_starts(&(ctx->sig->sha1_body));
  sha2_starts(&(ctx->sig->sha2_body),0);

  return ctx;

};

#ifdef PDKIM_DEBUG
/* -------------------------------------------------------------------------- */
void pdkim_set_debug_stream(pdkim_ctx *ctx,
                            FILE *debug_stream) {
  ctx->debug_stream = debug_stream;
};
#endif

/* -------------------------------------------------------------------------- */
int pdkim_set_optional(pdkim_ctx *ctx,
                       int input_mode,
                       char *sign_headers,
                       char *identity,
                       int canon_headers,
                       int canon_body,
                       unsigned long bodylength,
                       int algo,
                       unsigned long created,
                       unsigned long expires) {

  if (identity != NULL) {
    ctx->sig->identity = malloc(strlen(identity)+1);
    if (!ctx->sig->identity) {
      return PDKIM_ERR_OOM;
    }
    strcpy(ctx->sig->identity, identity);
  }

  if (sign_headers != NULL) {
    ctx->sig->sign_headers = malloc(strlen(sign_headers)+1);
    if (!ctx->sig->sign_headers) {
      return PDKIM_ERR_OOM;
    }
    strcpy(ctx->sig->sign_headers, sign_headers);
  }

  ctx->input_mode = input_mode;
  ctx->sig->canon_headers = canon_headers;
  ctx->sig->canon_body = canon_body;
  ctx->sig->bodylength = bodylength;
  ctx->sig->algo = algo;
  ctx->sig->created = created;
  ctx->sig->expires = expires;

  return PDKIM_OK;
};




/* -------------------------------------------------------------------------- */
void pdkim_free_sig(pdkim_signature *sig) {
  if (sig) {
    pdkim_signature *next = (pdkim_signature *)sig->next;

    pdkim_stringlist *e = sig->headers;
    while(e != NULL) {
      pdkim_stringlist *c = e;
      if (e->value != NULL) free(e->value);
      e = e->next;
      free(c);
    }

    if (sig->sigdata        != NULL) free(sig->sigdata);
    if (sig->bodyhash       != NULL) free(sig->bodyhash);
    if (sig->selector       != NULL) free(sig->selector);
    if (sig->domain         != NULL) free(sig->domain);
    if (sig->identity       != NULL) free(sig->identity);
    if (sig->headernames    != NULL) free(sig->headernames);
    if (sig->copiedheaders  != NULL) free(sig->copiedheaders);
    if (sig->rsa_privkey    != NULL) free(sig->rsa_privkey);
    if (sig->sign_headers   != NULL) free(sig->sign_headers);

    free(sig);
    if (next != NULL) pdkim_free_sig(next);
  }
};


/* -------------------------------------------------------------------------- */
void pdkim_free_ctx(pdkim_ctx *ctx) {
  if (ctx) {
    pdkim_free_sig(ctx->sig);
    pdkim_strfree(ctx->cur_header);
    free(ctx);
  }
};
